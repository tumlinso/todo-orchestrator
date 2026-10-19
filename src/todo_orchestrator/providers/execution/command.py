"""Adapter from exact authored command checks to the durable V02 verifier port.

The provider is supplied by the host. This module never starts a process and
never accepts command text from a worker-facing API.
"""

from __future__ import annotations

from datetime import timezone
import hashlib
import json
import math

from todo_orchestrator.contracts import (
    EvidenceKind,
    EvidenceResult,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Sha256Digest,
    StableId,
    VerificationKind,
)
from todo_orchestrator.contracts.providers import (
    CommandExecutionInspection,
    CommandExecutionRequest,
    CommandInspectionState,
    CommandObservation,
    EffectInspectionRequest,
    VerificationEvidenceFact,
    VerificationInspection,
    VerificationInspectionState,
    VerificationObservation,
    VerificationRequest,
    provider_request_digest,
)


COMMAND_VERIFIER_IDENTITY = ProviderIdentity(StableId("todo-command-adapter-v1"), "1")


def _stable_id(prefix: str, value: str) -> StableId:
    return StableId(f"{prefix}-{hashlib.sha256(value.encode('utf-8')).hexdigest()}")


def _receipt_value(receipt: ProviderReceipt) -> dict[str, object]:
    return {
        "receipt_id": str(receipt.receipt_id),
        "provider_id": str(receipt.provider.provider_id),
        "provider_version": receipt.provider.version,
        "provider_contract_version": receipt.provider.contract_version,
        "correlation_id": str(receipt.correlation_id),
        "request_digest": receipt.request_digest.hex,
        "provenance_ref": str(receipt.provenance_ref),
        "observed_at": receipt.observed_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
    }


class CommandExecutionVerifier:
    """Execute authored command contracts through a trusted external port.

    `adapter_identity` is the verifier recorded by V02. `execution_identity`
    is the provider allowed to interpret the command tool ID and execute the
    exact authored argv in the exact attempt workspace.
    """

    def __init__(self, provider, *, execution_identity: ProviderIdentity,
                 adapter_identity: ProviderIdentity) -> None:
        if not callable(getattr(provider, "execute", None)) or not callable(getattr(provider, "inspect", None)):
            raise TypeError("command execution provider must implement execute and inspect")
        if not isinstance(execution_identity, ProviderIdentity) or not isinstance(adapter_identity, ProviderIdentity):
            raise TypeError("command and adapter identities must be explicit ProviderIdentity values")
        self.provider = provider
        self.execution_identity = execution_identity
        self.adapter_identity = adapter_identity

    def supports(self, contract, required_evidence=()) -> bool:
        return (
            contract is not None
            and contract.kind is VerificationKind.COMMAND
            and all(item.kind in {EvidenceKind.COMMAND_RESULT, EvidenceKind.PROVIDER_RECEIPT}
                    for item in required_evidence)
        )

    def _command_request(self, request: VerificationRequest) -> CommandExecutionRequest:
        contract = request.contract
        if contract is None or contract.kind is not VerificationKind.COMMAND:
            raise ValueError("command execution requires an authored command contract")
        if request.workspace_id is None or request.expected_authority_revision is None:
            raise ValueError("command execution request lacks its selected workspace or authority revision")
        config = contract.config
        return CommandExecutionRequest(
            request.context,
            request.attempt,
            request.operation_id,
            request.idempotency_key,
            request.expected_source,
            request.expected_authority_revision,
            self.execution_identity.provider_id,
            tuple(config["argv"]),
            int(math.ceil(float(config["timeout_seconds"]) * 1000)),
            request.workspace_id,
            config.get("cwd"),
        )

    def _validate_execution_receipt(self, result: ProviderResult, request: CommandExecutionRequest) -> ProviderReceipt:
        receipt = result.receipt
        if (result.provider != self.execution_identity or result.correlation_id != request.operation_id
                or not isinstance(receipt, ProviderReceipt)
                or receipt.provider != self.execution_identity
                or receipt.correlation_id != request.operation_id
                or receipt.request_digest != provider_request_digest(request)
                or receipt.provenance_ref != request.operation_id):
            raise ValueError("command provider receipt does not bind the exact execution")
        return receipt

    def _outer_execution_receipt(self, request: VerificationRequest,
                                 execution_receipt: ProviderReceipt) -> ProviderReceipt:
        material = json.dumps(
            {"operation_id": str(request.operation_id), "request_digest": provider_request_digest(request).hex,
             "execution_receipt": _receipt_value(execution_receipt)},
            sort_keys=True, separators=(",", ":"),
        )
        return ProviderReceipt(
            _stable_id("cmd-verification-receipt", material), self.adapter_identity,
            request.operation_id, provider_request_digest(request), request.operation_id,
            execution_receipt.observed_at,
        )

    @staticmethod
    def _command_digest(observation: CommandObservation, receipt: ProviderReceipt) -> Sha256Digest:
        material = json.dumps(
            {"observation": {
                "operation_id": str(observation.operation_id), "exit_code": observation.exit_code,
                "timed_out": observation.timed_out,
                "started_at": observation.started_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
                "completed_at": observation.completed_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
                "stdout_digest": None if observation.stdout_digest is None else observation.stdout_digest.hex,
                "stderr_digest": None if observation.stderr_digest is None else observation.stderr_digest.hex,
            }, "receipt": _receipt_value(receipt)},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return Sha256Digest(hashlib.sha256(material).hexdigest())

    def _observation(self, request: VerificationRequest, command: CommandObservation,
                     command_receipt: ProviderReceipt) -> VerificationObservation:
        contract = request.contract
        assert contract is not None and contract.kind is VerificationKind.COMMAND
        allowed = tuple(contract.config["expected_exit_codes"])
        if command.timed_out:
            verdict = EvidenceResult.INCONCLUSIVE
        elif command.exit_code in allowed:
            verdict = EvidenceResult.PASS
        else:
            verdict = EvidenceResult.FAIL
        digest = self._command_digest(command, command_receipt)
        facts = tuple(
            VerificationEvidenceFact(item.name, item.kind, item.version, digest)
            for item in request.required_evidence
        )
        return VerificationObservation(
            request.operation_id, verdict, self.adapter_identity.provider_id,
            self.adapter_identity.version, request.expected_source, request.contract_digest,
            request.inputs, (), facts, command, command_receipt,
        )

    def verify(self, request: VerificationRequest) -> ProviderResult[VerificationObservation]:
        if not self.supports(request.contract, request.required_evidence):
            return ProviderResult(
                ProviderStatus.UNAVAILABLE, request.operation_id,
                reason_code=StableId("command_evidence_kind_unsupported"),
            )
        command_request = self._command_request(request)
        try:
            result = self.provider.execute(command_request)
        except Exception:
            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.adapter_identity,
                                  reason_code=StableId("command_provider_exception"))
        if not isinstance(result, ProviderResult):
            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.adapter_identity,
                                  reason_code=StableId("command_provider_untyped_result"))
        if result.status is ProviderStatus.UNAVAILABLE:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.operation_id,
                                  reason_code=StableId("command_provider_unavailable"))
        if result.status is ProviderStatus.UNKNOWN:
            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.adapter_identity,
                                  reason_code=StableId("command_effect_unknown"))
        try:
            execution_receipt = self._validate_execution_receipt(result, command_request)
        except (TypeError, ValueError):
            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.adapter_identity,
                                  reason_code=StableId("command_receipt_mismatch"))
        if result.status is ProviderStatus.OBSERVED_FAILURE:
            outer = self._outer_execution_receipt(request, execution_receipt)
            return ProviderResult(ProviderStatus.OBSERVED_FAILURE, request.operation_id,
                                  self.adapter_identity, receipt=outer,
                                  reason_code=StableId("command_provider_failure"))
        command_observation = result.value
        if (not isinstance(command_observation, CommandObservation)
                or command_observation.operation_id != request.operation_id
                or execution_receipt.observed_at < command_observation.completed_at):
            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.adapter_identity,
                                  reason_code=StableId("command_observation_mismatch"))
        observation = self._observation(request, command_observation, execution_receipt)
        outer = self._outer_execution_receipt(request, execution_receipt)
        return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.operation_id,
                              self.adapter_identity, observation, outer)

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[VerificationInspection]:
        verification_request = request.verification_request
        if verification_request is None or not self.supports(
            verification_request.contract, verification_request.required_evidence,
        ):
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("command_inspection_request_unavailable"))
        command_request = self._command_request(verification_request)
        provider_request = EffectInspectionRequest(
            request.context, request.operation_id, request.idempotency_key,
            provider_request_digest(command_request), request.correlation_id,
        )
        try:
            result = self.provider.inspect(provider_request)
        except Exception:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("command_inspection_unavailable"))
        if not isinstance(result, ProviderResult):
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("command_inspection_untyped"))
        if result.status is ProviderStatus.UNAVAILABLE:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("command_inspection_unavailable"))
        if result.status is ProviderStatus.UNKNOWN:
            return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.adapter_identity,
                                  reason_code=StableId("command_inspection_unknown"))
        try:
            query_receipt = self._validate_inspection_receipt(result, provider_request)
        except (TypeError, ValueError):
            return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.adapter_identity,
                                  reason_code=StableId("command_inspection_receipt_mismatch"))
        value = result.value
        if not isinstance(value, CommandExecutionInspection) or value.operation_id != request.operation_id:
            return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.adapter_identity,
                                  reason_code=StableId("command_inspection_mismatch"))
        if value.state is CommandInspectionState.NOT_STARTED:
            inspection = VerificationInspection(request.operation_id, VerificationInspectionState.NOT_STARTED)
        elif value.state is CommandInspectionState.RUNNING:
            inspection = VerificationInspection(request.operation_id, VerificationInspectionState.RUNNING)
        else:
            execution_receipt = value.original_receipt
            command_observation = value.observation
            if execution_receipt is None:
                return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.adapter_identity,
                                      reason_code=StableId("command_original_receipt_missing"))
            try:
                self._validate_original_execution_receipt(execution_receipt, command_request)
                if (command_observation is None
                        or execution_receipt.observed_at < command_observation.completed_at):
                    raise ValueError("completed command observation and receipt times differ")
            except (TypeError, ValueError):
                return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.adapter_identity,
                                      reason_code=StableId("command_original_receipt_mismatch"))
            observation = self._observation(verification_request, command_observation, execution_receipt)
            original_receipt = self._outer_execution_receipt(verification_request, execution_receipt)
            inspection = VerificationInspection(
                request.operation_id, VerificationInspectionState.COMPLETED,
                observation, original_receipt,
            )
        outer_query_receipt = ProviderReceipt(
            _stable_id("cmd-inspect-receipt", str(query_receipt.receipt_id) + request.correlation_id.__str__()),
            self.adapter_identity, request.correlation_id, provider_request_digest(request),
            request.operation_id, query_receipt.observed_at,
        )
        return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.correlation_id,
                              self.adapter_identity, inspection, outer_query_receipt)

    def _validate_original_execution_receipt(self, receipt: ProviderReceipt,
                                             request: CommandExecutionRequest) -> None:
        if (receipt.provider != self.execution_identity
                or receipt.correlation_id != request.operation_id
                or receipt.request_digest != provider_request_digest(request)
                or receipt.provenance_ref != request.operation_id):
            raise ValueError("original command receipt differs from the exact execution request")

    def validate_observation(self, request: VerificationRequest,
                             observation: VerificationObservation) -> bool:
        """Validate the nested command facts against the selected tool request."""
        try:
            command_request = self._command_request(request)
            command = observation.command_observation
            receipt = observation.command_receipt
            if command is None or receipt is None or command.operation_id != request.operation_id:
                return False
            self._validate_original_execution_receipt(receipt, command_request)
            return receipt.observed_at.astimezone(timezone.utc) >= command.completed_at.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return False

    def _validate_inspection_receipt(self, result: ProviderResult,
                                     request: EffectInspectionRequest) -> ProviderReceipt:
        receipt = result.receipt
        if (result.provider != self.execution_identity or result.correlation_id != request.correlation_id
                or not isinstance(receipt, ProviderReceipt)
                or receipt.provider != self.execution_identity
                or receipt.correlation_id != request.correlation_id
                or receipt.request_digest != provider_request_digest(request)
                or receipt.provenance_ref != request.operation_id):
            raise ValueError("command inspection receipt differs from its exact query")
        return receipt


class RoutedVerificationProvider:
    """Select an explicit verifier by accepted contract kind."""

    def __init__(self, *, fallback=None, fallback_identity: ProviderIdentity | None = None,
                 command: CommandExecutionVerifier | None = None) -> None:
        if fallback is not None and (
            not callable(getattr(fallback, "verify", None))
            or not callable(getattr(fallback, "inspect", None))
        ):
            raise TypeError("fallback verification provider must implement verify and inspect")
        if (fallback is None) != (fallback_identity is None):
            raise ValueError("fallback provider and identity must be supplied together")
        if fallback_identity is not None and not isinstance(fallback_identity, ProviderIdentity):
            raise TypeError("fallback_identity must be a ProviderIdentity")
        if command is not None and not isinstance(command, CommandExecutionVerifier):
            raise TypeError("command must be a CommandExecutionVerifier")
        if fallback is None and command is None:
            raise ValueError("at least one verification provider must be configured")
        self.fallback = fallback
        self.fallback_identity = fallback_identity
        self.command = command

    def identity_for(self, contract) -> ProviderIdentity:
        if contract is not None and contract.kind is VerificationKind.COMMAND:
            if self.command is None:
                raise LookupError("trusted command execution provider is unavailable")
            return self.command.adapter_identity
        if self.fallback is None or self.fallback_identity is None:
            raise LookupError("trusted verification provider is unavailable")
        return self.fallback_identity

    def supports(self, contract, required_evidence=()) -> bool:
        try:
            identity = self.identity_for(contract)
        except LookupError:
            return False
        if contract is not None and contract.kind is VerificationKind.COMMAND:
            return self.command.supports(contract, required_evidence)
        return identity is not None

    def verify(self, request: VerificationRequest):
        if request.contract is not None and request.contract.kind is VerificationKind.COMMAND:
            if self.command is None:
                return ProviderResult(ProviderStatus.UNAVAILABLE, request.operation_id,
                                      reason_code=StableId("command_provider_unavailable"))
            return self.command.verify(request)
        if self.fallback is None:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.operation_id,
                                  reason_code=StableId("verification_provider_unavailable"))
        return self.fallback.verify(request)

    def inspect(self, request: EffectInspectionRequest):
        original = request.verification_request
        if original is not None and original.contract is not None and original.contract.kind is VerificationKind.COMMAND:
            if self.command is None:
                return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                      reason_code=StableId("command_provider_unavailable"))
            return self.command.inspect(request)
        if self.fallback is None:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("verification_provider_unavailable"))
        return self.fallback.inspect(request)

    def validate_observation(self, request: VerificationRequest,
                             observation: VerificationObservation) -> bool:
        if request.contract is not None and request.contract.kind is VerificationKind.COMMAND:
            return self.command is not None and self.command.validate_observation(request, observation)
        validator = getattr(self.fallback, "validate_observation", None)
        return True if not callable(validator) else bool(validator(request, observation))


__all__ = ["COMMAND_VERIFIER_IDENTITY", "CommandExecutionVerifier", "RoutedVerificationProvider"]
