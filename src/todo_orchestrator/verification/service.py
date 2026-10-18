"""Authorized, durable verification operations over injected providers.

Provider calls always happen outside the SQLite writer. An operation is committed
as ``executing`` first; after a restart, that state is inspected and is never
blindly replayed. Verification evidence is historical input-bound evidence only;
this module does not accept work outcomes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from types import MappingProxyType
from typing import Protocol

from todo_orchestrator.contracts import (
    AttemptState,
    EntityKind,
    EntityRef,
    EvidenceInput,
    EvidenceKind,
    EvidenceResult,
    EvidenceRequirement,
    Project,
    Requirement,
    Sha256Digest,
    StableId,
    VerificationContract,
    VerificationKind,
)
from todo_orchestrator.contracts.providers import (
    EffectInspectionRequest,
    ProviderCallContext,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    SourceObservation,
    SourceObservationRequest,
    VerificationEvidenceFact,
    VerificationInspection,
    VerificationInspectionState,
    VerificationObservation,
    VerificationRequest,
    WorkingTreeState,
    provider_request_digest,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    CommandEffect,
    CommandResult,
    ProcessLiveness,
    SourceSafety,
    WorkspaceQualification,
)
from todo_orchestrator.planning import CompiledPlan, decode_accepted_plan

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeniedError,
    RECOVERY_APPLY_ACTION,
    _actor_ref,
    _context_from_row,
    _token_digest,
)
from todo_orchestrator.authority.attempts import (
    AttemptError,
    AttemptNotFoundError,
    _check_observation,
    _attempt_from_row,
    _parse_time,
    _stored_attempt,
    _stored_workspace,
    _workspace_values,
    VERIFICATION_ACTION,
    VERIFICATION_RECONCILE_ACTION,
)
from todo_orchestrator.authority.commands import (
    IdempotencyConflictError,
    MutationContext,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.authority.sqlite import (
    AuthorityError,
    InvalidAuthorityError,
    SQLiteAuthority,
    load_plan_revision_snapshot,
)
from todo_orchestrator.authority.child_store import require_parent_children_resolved
from todo_orchestrator.authority.recovery_approval import RecoveryApproval, _is_recovery_approval


VERIFY_ACTION = VERIFICATION_ACTION
VERIFY_RECONCILE_ACTION = VERIFICATION_RECONCILE_ACTION


class VerificationError(AuthorityError):
    """Base for durable verification service errors."""


class VerificationNotFoundError(VerificationError):
    """The exact requested verification requirement or operation is absent."""


class VerificationDeniedError(VerificationError):
    """The active attempt or its grant does not authorize verification."""


class VerificationProviderUnavailableError(VerificationError):
    """A configured trusted observation or verification provider is unavailable."""


class VerificationObservationMismatchError(VerificationError):
    """A provider response failed operation, source, or receipt binding checks."""


class VerificationStateError(VerificationError):
    """The operation state does not permit the requested transition."""


class SourceObserver(Protocol):
    def observe(self, request: SourceObservationRequest) -> ProviderResult[SourceObservation]: ...


class Verifier(Protocol):
    def verify(self, request: VerificationRequest) -> ProviderResult[VerificationObservation]: ...

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[VerificationInspection]: ...


class VerificationState(str):
    PREPARED = "prepared"
    EXECUTING = "executing"
    OBSERVED = "observed"
    NOT_STARTED = "not_started"
    FINALIZED = "finalized"
    REJECTED = "rejected"
    STALE = "stale"
    UNKNOWN = "unknown"
    FAILED = "failed"


@dataclass(frozen=True)
class VerificationOperationView:
    operation: EntityRef
    attempt: EntityRef
    target: EntityRef
    requirement: EntityRef
    plan_revision_id: StableId
    verifier: ProviderIdentity
    contract_digest: Sha256Digest
    source_digest: Sha256Digest
    inputs: tuple[EvidenceInput, ...]
    request_digest: Sha256Digest
    state: str
    created_at: datetime
    updated_at: datetime
    evidence_id: StableId | None = None
    stale_reason: str | None = None
    observation: Mapping[str, object] | None = None
    provider_receipt: Mapping[str, object] | None = None
    source_receipt: Mapping[str, object] | None = None
    final_source_receipt: Mapping[str, object] | None = None
    inspection: Mapping[str, object] | None = None


@dataclass(frozen=True)
class _Prepare:
    attempt: EntityRef
    target: EntityRef
    requirement: EntityRef
    plan_revision_id: StableId
    operation_id: StableId
    idempotency_key: StableId
    capability_id: StableId
    verifier_id: StableId
    verifier_version: str
    contract_json: str
    contract_digest: Sha256Digest
    source_digest: Sha256Digest
    inputs_json: str
    source_receipt_json: str
    request_json: str
    request_digest: Sha256Digest
    created_at: str
    run: EntityRef | None
    assignment: EntityRef | None

    def __deepcopy__(self, memo):
        return self


@dataclass(frozen=True)
class _Transition:
    action: StableId
    attempt: EntityRef
    target: EntityRef
    operation_id: StableId
    expected_state: str
    state: str
    idempotency_key: StableId
    occurred_at: str
    run: EntityRef | None
    assignment: EntityRef | None
    observation_json: str | None = None
    receipt_json: str | None = None
    final_source_receipt_json: str | None = None
    inspection_json: str | None = None
    evidence_id: StableId | None = None
    stale_reason: str | None = None
    recovery_approval: RecoveryApproval | None = None
    recovery_source_json: str | None = None


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _digest(encoded: str) -> Sha256Digest:
    return Sha256Digest(hashlib.sha256(encoded.encode("utf-8")).hexdigest())


def _id(prefix: str, seed: str) -> StableId:
    return StableId(prefix + "-" + hashlib.sha256(seed.encode("utf-8")).hexdigest())


def _ref_value(ref: EntityRef) -> dict[str, object]:
    return {
        "project_id": str(ref.project_id), "kind": ref.kind.value, "entity_id": str(ref.entity_id),
        "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _input_value(item: EvidenceInput) -> dict[str, str]:
    return {"name": str(item.name), "digest": item.digest.hex}


def _inputs_value(inputs: tuple[EvidenceInput, ...]) -> list[dict[str, str]]:
    return [_input_value(item) for item in sorted(inputs, key=lambda value: str(value.name))]


def _receipt_value(receipt: ProviderReceipt) -> dict[str, object]:
    return {
        "receipt_id": str(receipt.receipt_id),
        "provider": {"provider_id": str(receipt.provider.provider_id), "version": receipt.provider.version,
                     "contract_version": receipt.provider.contract_version},
        "correlation_id": str(receipt.correlation_id), "request_digest": receipt.request_digest.hex,
        "provenance_ref": str(receipt.provenance_ref),
        "observed_at": receipt.observed_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
    }


def _recovery_approval_digest(approval: RecoveryApproval) -> str:
    """Stable audit binding for one sealed recovery approval."""
    observation = approval.host_observation
    host_value: dict[str, object] | None = None
    if observation is not None:
        workspace = observation.workspace
        host_value = {
            "attempt": _ref_value(observation.attempt),
            "observed_state": observation.observed_state.value,
            "lease_id": str(observation.lease_id),
            "lease_expires_at": observation.observed_lease_expires_at.astimezone(
                timezone.utc
            ).isoformat(timespec="microseconds"),
            "workspace_id": str(workspace.workspace_id),
            "repository_id": str(workspace.repository_id),
            "base_ref": str(workspace.common_base.ref),
            "base_digest": workspace.common_base.digest,
            "destination": str(workspace.destination.ref),
            "isolation": workspace.isolation.value,
            "source": observation.source.value,
            "process": observation.process.value,
            "children": observation.children.value,
            "receipt": _receipt_value(observation.receipt),
        }
    return _digest(_json({
        "intent_kind": approval.intent_kind,
        "actor": _ref_value(approval.actor),
        "capability_id": str(approval.capability_id),
        "target": _ref_value(approval.target),
        "attempt": None if approval.attempt is None else _ref_value(approval.attempt),
        "run": None if approval.run is None else _ref_value(approval.run),
        "assignment": None if approval.assignment is None else _ref_value(approval.assignment),
        "operation": None if approval.operation is None else _ref_value(approval.operation),
        "intent_digest": approval.intent_digest.hex,
        "authority_revision": approval.authority_revision,
        "expected_lease_id": None if approval.expected_lease_id is None else str(approval.expected_lease_id),
        "expected_lease_expires_at": None if approval.expected_lease_expires_at is None else
            approval.expected_lease_expires_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
        "expected_source_digest": None if approval.expected_source_digest is None else
            approval.expected_source_digest.hex,
        "host_observation": host_value,
    })).hex


def _source_value(source: SourceObservation) -> dict[str, object]:
    return {
        "repository_id": str(source.repository_id), "source_digest": source.source_digest.hex,
        "base_digest": None if source.base_digest is None else source.base_digest.hex,
        "source_revision": None if source.source_revision is None else str(source.source_revision),
        "working_tree": source.working_tree.value, "inputs": _inputs_value(source.inputs),
        "artifacts": [{"artifact_id": str(item.artifact_id), "available": item.available,
                       "content_digest": None if item.content_digest is None else item.content_digest.hex}
                      for item in source.artifacts],
    }


def _observation_value(observation: VerificationObservation) -> dict[str, object]:
    return {
        "operation_id": str(observation.operation_id), "verdict": observation.verdict.value,
        "verifier_id": str(observation.verifier_id), "verifier_version": observation.verifier_version,
        "source_digest": observation.source_digest.hex, "contract_digest": observation.contract_digest.hex,
        "inputs": _inputs_value(observation.inputs),
        "artifact_ids": [str(item) for item in sorted(observation.artifact_ids, key=str)],
        "evidence_facts": [
            {"name": str(item.name), "kind": item.kind.value, "version": item.version,
             "digest": item.digest.hex,
             "artifact_id": None if item.artifact_id is None else str(item.artifact_id),
             "benchmark_value": item.benchmark_value, "unit": item.unit,
             "sample_count": item.sample_count}
            for item in sorted(observation.evidence_facts, key=lambda value: str(value.name))
        ],
    }


def _contract_digest(contract: VerificationContract) -> Sha256Digest:
    return _digest(_json(contract.to_mapping()))


def _provider_result_receipt(
    result: ProviderResult[object], expected_identity: ProviderIdentity, expected_correlation: StableId,
    expected_digest: Sha256Digest, expected_provenance: StableId,
) -> ProviderReceipt:
    if result.provider != expected_identity or result.correlation_id != expected_correlation:
        raise VerificationObservationMismatchError("provider identity or correlation differs from the request")
    receipt = result.receipt
    if receipt is None or receipt.provider != expected_identity:
        raise VerificationObservationMismatchError("provider response omitted its configured receipt")
    if (receipt.correlation_id != expected_correlation or receipt.request_digest != expected_digest
            or receipt.provenance_ref != expected_provenance):
        raise VerificationObservationMismatchError("provider receipt does not bind the exact request and scope")
    return receipt


def _receipt_time(receipt: ProviderReceipt, *, now: datetime, earliest: datetime | None = None) -> None:
    observed = receipt.observed_at.astimezone(timezone.utc)
    if observed > now:
        raise VerificationObservationMismatchError("provider receipt is from the future")
    if earliest is not None and observed < earliest.astimezone(timezone.utc):
        raise VerificationObservationMismatchError("provider receipt predates its authorized operation")


def _scope_id(target: EntityRef) -> StableId:
    return _id("scope", _json(_ref_value(target)))


def _load_plan(connection: sqlite3.Connection, project: Project, plan_revision_id: StableId) -> CompiledPlan:
    try:
        record = load_plan_revision_snapshot(connection, project, plan_revision_id)
        if record.sequence is None:
            raise InvalidAuthorityError("accepted plan sequence is missing")
        return decode_accepted_plan(record.canonical_json, project, sequence=record.sequence)
    except (InvalidAuthorityError, TypeError, ValueError) as exc:
        raise VerificationError(f"accepted plan snapshot cannot be loaded: {exc}") from exc


def _plan_for_attempt(connection: sqlite3.Connection, project: Project, attempt) -> tuple[StableId, CompiledPlan]:
    if attempt.run is not None:
        row = connection.execute(
            "SELECT plan_revision_id FROM run_schedules WHERE run_id = ?",
            (str(attempt.run.entity_id),),
        ).fetchone()
        if row is None:
            raise VerificationDeniedError("attempt run has no persisted accepted schedule")
        revision = StableId(row[0])
    else:
        row = connection.execute(
            "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise VerificationDeniedError("authority has no accepted plan")
        revision = StableId(row[0])
    return revision, _load_plan(connection, project, revision)


def _load_requirement(plan: CompiledPlan, target: EntityRef, requirement_ref: EntityRef) -> Requirement:
    if not any(item.definition.ref == target for item in plan.work_items):
        raise VerificationDeniedError("attempt work definition is not a member of its accepted plan")
    for item in plan.requirements:
        if item.definition.ref == requirement_ref and item.definition.owner == target:
            if item.definition.kind.value != "check" or item.definition.verification is None:
                raise VerificationDeniedError("requirement has no executable verification contract")
            return item.definition
    raise VerificationNotFoundError("exact requirement version is not in the accepted work definition")


def _attempt_context(connection: sqlite3.Connection, authority: SQLiteAuthority, attempt_ref: EntityRef,
                     now: datetime):
    attempt, row = _stored_attempt(connection, authority.project, attempt_ref)
    if attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE} or attempt.lease is None:
        raise VerificationDeniedError("verification requires a live admitted or active attempt")
    if attempt.lease.expires_at <= now:
        # The service clock check is repeated inside the handler; this quick
        # read-side rejection avoids invoking providers for an expired lease.
        raise VerificationDeniedError("attempt lease has expired")
    workspace = _stored_workspace(connection, authority.project, attempt_ref)
    return attempt, row, workspace


def _request_context(actor: EntityRef, capability_id: StableId, operation_id: StableId,
                     target: EntityRef) -> ProviderCallContext:
    return ProviderCallContext(
        actor.project_id, actor, EntityRef(actor.project_id, EntityKind.CAPABILITY, capability_id),
        _id("vctx", f"{operation_id}:{actor.entity_id}:{actor.incarnation_id}"), _scope_id(target),
    )


def _source_request(context: ProviderCallContext, attempt: EntityRef, target: EntityRef,
                    workspace_id: StableId, contract: VerificationContract, operation_id: StableId,
                    phase: str, expected_source: Sha256Digest | None = None) -> SourceObservationRequest:
    correlation = _id("vsrc", f"{operation_id}:{phase}")
    return SourceObservationRequest(
        context, correlation, expected_source, attempt, workspace_id, target, contract,
    )


def _verification_request_json(request: VerificationRequest) -> str:
    return _json({
        "context": {
            "project_id": str(request.context.project_id), "actor": _ref_value(request.context.actor),
            "capability": _ref_value(request.context.capability),
            "trusted_context_id": str(request.context.trusted_context_id),
            "scope_id": str(request.context.scope_id),
        },
        "attempt": _ref_value(request.attempt), "requirement": _ref_value(request.requirement),
        "operation_id": str(request.operation_id), "idempotency_key": str(request.idempotency_key),
        "verifier_id": str(request.verifier_id), "expected_source": request.expected_source.hex,
        "contract_digest": request.contract_digest.hex, "inputs": _inputs_value(request.inputs),
        "contract": request.contract.to_mapping(), "workspace_id": str(request.workspace_id),
        "verifier_version": request.verifier_version,
        "required_evidence": [
            {"name": str(item.name), "kind": item.kind.value, "version": item.version}
            for item in request.required_evidence
        ],
    })


def _enum_ref(value: Mapping[str, object]) -> EntityRef:
    return EntityRef(
        StableId(str(value["project_id"])), EntityKind(str(value["kind"])), StableId(str(value["entity_id"])),
        None if value["definition_revision_id"] is None else StableId(str(value["definition_revision_id"])),
        None if value["incarnation_id"] is None else StableId(str(value["incarnation_id"])),
    )


def _request_from_json(encoded: str) -> VerificationRequest:
    value = json.loads(encoded)
    context = value["context"]
    return VerificationRequest(
        ProviderCallContext(
            StableId(context["project_id"]), _enum_ref(context["actor"]), _enum_ref(context["capability"]),
            StableId(context["trusted_context_id"]), StableId(context["scope_id"]),
        ),
        _enum_ref(value["attempt"]), _enum_ref(value["requirement"]), StableId(value["operation_id"]),
        StableId(value["idempotency_key"]), StableId(value["verifier_id"]),
        Sha256Digest(value["expected_source"]), Sha256Digest(value["contract_digest"]),
        tuple(EvidenceInput(StableId(item["name"]), Sha256Digest(item["digest"])) for item in value["inputs"]),
        VerificationContract.from_mapping(value["contract"]), StableId(value["workspace_id"]),
        value["verifier_version"], tuple(
            EvidenceRequirement.from_mapping(item) for item in value["required_evidence"]
        ),
    )


def _identity_json(identity: ProviderIdentity) -> dict[str, object]:
    return {"provider_id": str(identity.provider_id), "version": identity.version,
            "contract_version": identity.contract_version}


class _PrepareHandler:
    kind = "todo.verification.prepare"
    command_type = _Prepare

    def __init__(self, service: "VerificationService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Prepare) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            VERIFY_ACTION, command.target, command.run, command.assignment, command.attempt,
        )

    def canonical_payload(self, command: _Prepare) -> dict[str, object]:
        return {
            "attempt": _ref_value(command.attempt), "target": _ref_value(command.target),
            "requirement": _ref_value(command.requirement), "plan_revision_id": str(command.plan_revision_id),
            "operation_id": str(command.operation_id), "idempotency_key": str(command.idempotency_key),
            "capability_id": str(command.capability_id), "verifier_id": str(command.verifier_id),
            "verifier_version": command.verifier_version, "contract_json": command.contract_json,
            "contract_digest": command.contract_digest.hex, "source_digest": command.source_digest.hex,
            "inputs_json": command.inputs_json,
            "request_json": command.request_json, "request_digest": command.request_digest.hex,
            "run": None if command.run is None else _ref_value(command.run),
            "assignment": None if command.assignment is None else _ref_value(command.assignment),
        }

    def apply(self, context: MutationContext, command: _Prepare) -> CommandEffect:
        attempt, _ = _stored_attempt(context._connection, context.project, command.attempt)
        if (attempt.work_item != command.target or attempt.actor != context.actor or attempt.run != command.run
                or attempt.assignment != command.assignment
                or attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE}
                or attempt.lease is None or attempt.lease.expires_at <= self.service._now()):
            raise VerificationDeniedError("verification target, owner, run, assignment, or lease changed")
        if command.target.project_id != context.project.project_id:
            raise VerificationDeniedError("verification target belongs to another project")
        plan = _load_plan(context._connection, context.project, command.plan_revision_id)
        requirement = _load_requirement(plan, command.target, command.requirement)
        if _contract_digest(requirement.verification) != command.contract_digest:
            raise VerificationDeniedError("accepted verification contract changed before preparation")
        current_membership = context._connection.execute(
            "SELECT 1 FROM plan_revision_work_items WHERE plan_revision_id = ? AND work_item_id = ? "
            "AND definition_revision_id = ?",
            (str(command.plan_revision_id), str(command.target.entity_id), str(command.target.definition_revision_id)),
        ).fetchone()
        if current_membership is None:
            raise VerificationDeniedError("work definition is no longer in the selected accepted plan")
        request = _request_from_json(command.request_json)
        if (provider_request_digest(request) != command.request_digest
                or request.operation_id != command.operation_id
                or request.idempotency_key != command.idempotency_key
                or request.attempt != command.attempt or request.requirement != command.requirement
                or request.verifier_id != command.verifier_id
                or request.verifier_version != command.verifier_version
                or request.context.capability.entity_id != command.capability_id
                or request.expected_source != command.source_digest
                or request.contract_digest != command.contract_digest):
            raise VerificationObservationMismatchError("prepared provider request differs from its durable operation fields")
        source_document = json.loads(command.source_receipt_json)
        source = source_document.get("source")
        source_receipt = source_document.get("receipt")
        if (not isinstance(source, dict) or not isinstance(source_receipt, dict)
                or source.get("source_digest") != command.source_digest.hex
                or source.get("inputs") != json.loads(command.inputs_json)):
            raise VerificationObservationMismatchError("prepared source identity does not match the typed request")
        workspace = _stored_workspace(context._connection, context.project, command.attempt)
        if (source.get("repository_id") != str(workspace.repository_id)
                or source.get("base_digest") != workspace.common_base.digest):
            raise VerificationObservationMismatchError("prepared source does not match the persisted attempt workspace")
        try:
            receipt_provider = source_receipt["provider"]
            expected_source_request = _source_request(
                request.context, request.attempt, command.target, request.workspace_id,
                request.contract, command.operation_id, "before",
            )
            if (receipt_provider["provider_id"] != str(self.service.source_identity.provider_id)
                    or receipt_provider["version"] != self.service.source_identity.version
                    or receipt_provider["contract_version"] != self.service.source_identity.contract_version
                    or source_receipt["correlation_id"] != str(expected_source_request.correlation_id)
                    or source_receipt["request_digest"] != provider_request_digest(expected_source_request).hex
                    or source_receipt["provenance_ref"] != str(request.workspace_id)):
                raise ValueError("source receipt identity mismatch")
            _receipt_time(ProviderReceipt(
                StableId(source_receipt["receipt_id"]), self.service.source_identity,
                StableId(source_receipt["correlation_id"]), Sha256Digest(source_receipt["request_digest"]),
                StableId(source_receipt["provenance_ref"]), datetime.fromisoformat(source_receipt["observed_at"]),
            ), now=datetime.fromisoformat(command.created_at),
                earliest=datetime.fromisoformat(command.created_at) - self.service.max_source_age)
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationObservationMismatchError("prepared source receipt is invalid") from exc
        now = self.service._now()
        context.execute(
            "INSERT INTO external_operations(operation_id, kind, idempotency_key, request_digest, state, "
            "created_at, updated_at, attempt_id, external_ref, receipt_digest) "
            "VALUES (?, 'verification', ?, ?, 'prepared', ?, ?, ?, ?, NULL)",
            (str(command.operation_id), str(command.idempotency_key), command.request_digest.hex,
             command.created_at, command.created_at, str(command.attempt.entity_id), str(command.verifier_id)),
        )
        context.execute(
            "INSERT INTO verification_attempts(operation_id, attempt_id, work_item_id, definition_revision_id, "
            "requirement_id, requirement_definition_revision_id, plan_revision_id, verifier_id, verifier_version, "
            "contract_json, contract_digest, source_digest, inputs_json, source_receipt_json, request_json, "
            "request_digest, state, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?)",
            (str(command.operation_id), str(command.attempt.entity_id), str(command.target.entity_id),
             str(command.target.definition_revision_id), str(command.requirement.entity_id),
             str(command.requirement.definition_revision_id), str(command.plan_revision_id),
             str(command.verifier_id), command.verifier_version, command.contract_json,
             command.contract_digest.hex, command.source_digest.hex, command.inputs_json,
             command.source_receipt_json, command.request_json, command.request_digest.hex,
             command.created_at, command.created_at),
        )
        return CommandEffect(
            True, {"operation_id": str(command.operation_id), "state": "prepared"},
            "todo.verification.prepared",
            {"operation_id": str(command.operation_id), "attempt_id": str(command.attempt.entity_id),
             "requirement_id": str(command.requirement.entity_id), "request_digest": command.request_digest.hex,
             "source_digest": command.source_digest.hex, "verifier_id": str(command.verifier_id)},
        )


class _TransitionHandler:
    kind = "todo.verification.transition"
    command_type = _Transition

    def __init__(self, service: "VerificationService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Transition) -> AuthorizationRequirement:
        return AuthorizationRequirement(command.action, command.target, command.run,
                                        command.assignment, command.attempt)

    def canonical_payload(self, command: _Transition) -> dict[str, object]:
        inspection = None
        if command.inspection_json is not None:
            try:
                inspection = json.loads(command.inspection_json)
                if isinstance(inspection, dict):
                    if command.recovery_approval is None:
                        inspection.pop("receipt", None)
            except (TypeError, ValueError):
                inspection = command.inspection_json
        payload = {
            "action": str(command.action), "attempt": _ref_value(command.attempt),
            "target": _ref_value(command.target), "operation_id": str(command.operation_id),
            "expected_state": command.expected_state, "state": command.state,
            "idempotency_key": str(command.idempotency_key),
            "run": None if command.run is None else _ref_value(command.run),
            "assignment": None if command.assignment is None else _ref_value(command.assignment),
            "observation_json": command.observation_json, "receipt_json": command.receipt_json,
            # These receipts are observations attached to a stable operation
            # or reconciliation intent. Their provider timestamps may differ
            # across concurrent read-only observation attempts; the durable
            # first writer remains authoritative.
            "inspection": inspection,
            "evidence_id": None if command.evidence_id is None else str(command.evidence_id),
            "stale_reason": command.stale_reason,
        }
        if command.recovery_approval is not None:
            payload["recovery_approval_digest"] = _recovery_approval_digest(command.recovery_approval)
            payload["recovery_intent_kind"] = command.recovery_approval.intent_kind
            payload["recovery_intent_digest"] = command.recovery_approval.intent_digest.hex
        if command.recovery_source_json is not None:
            payload["recovery_source_digest"] = _digest(command.recovery_source_json).hex
        if command.recovery_approval is not None and command.inspection_json is not None:
            payload["recovery_inspection_digest"] = _digest(command.inspection_json).hex
        return payload

    def apply(self, context: MutationContext, command: _Transition) -> CommandEffect:
        row = context._connection.execute(
            "SELECT v.*, o.idempotency_key AS external_idempotency_key, o.request_digest AS external_digest "
            "FROM verification_attempts AS v JOIN external_operations AS o USING(operation_id) "
            "WHERE v.operation_id = ?",
            (str(command.operation_id),),
        ).fetchone()
        if row is None:
            raise VerificationNotFoundError("verification operation does not exist")
        attempt, _ = _stored_attempt(context._connection, context.project, command.attempt)
        recovery = command.action == RECOVERY_APPLY_ACTION
        if (attempt.work_item != command.target
                or (attempt.actor != context.actor and not recovery) or attempt.run != command.run
                or attempt.assignment != command.assignment or row["attempt_id"] != str(command.attempt.entity_id)
                or row["work_item_id"] != str(command.target.entity_id)
                or row["definition_revision_id"] != str(command.target.definition_revision_id)):
            raise VerificationDeniedError("verification operation is not bound to this active attempt context")
        if recovery:
            self.service._validate_recovery_transition(context, command, attempt, row)
        elif command.recovery_approval is not None:
            raise VerificationDeniedError("recovery approval cannot authorize an ordinary verification transition")
        if row["state"] != command.expected_state:
            raise VerificationStateError(
                f"verification operation is {row['state']}, expected {command.expected_state}"
            )
        retry_reinspection = (
            recovery and command.recovery_approval is not None
            and command.recovery_approval.intent_kind == "retry_original_operation"
            and command.expected_state in {VerificationState.EXECUTING, VerificationState.UNKNOWN}
            and command.state == VerificationState.EXECUTING
        )
        if (command.state not in _ALLOWED_TRANSITIONS.get(command.expected_state, frozenset())
                and not retry_reinspection):
            raise VerificationStateError(f"unsupported verification transition {command.expected_state} -> {command.state}")
        now = self.service._now()
        live = attempt.state in {AttemptState.ADMITTED, AttemptState.ACTIVE}
        if command.state in {
            VerificationState.EXECUTING, VerificationState.OBSERVED, VerificationState.UNKNOWN,
            VerificationState.NOT_STARTED, VerificationState.FINALIZED, VerificationState.REJECTED,
            VerificationState.STALE, VerificationState.FAILED,
        } and (not live or attempt.lease is None or attempt.lease.expires_at <= now) and not recovery:
            raise VerificationDeniedError("attempt is terminal, unsafe, or its lease expired")
        if command.state == VerificationState.EXECUTING and not self.service._requirement_is_current(
            context._connection, context.project, attempt, row,
        ):
            raise VerificationDeniedError("accepted requirement changed before verification execution")
        effective_state = command.state
        effective_stale_reason = command.stale_reason
        if command.state in {VerificationState.FINALIZED, VerificationState.REJECTED} and not self.service._requirement_is_current(
            context._connection, context.project, attempt, row,
        ):
            effective_state = VerificationState.STALE
            effective_stale_reason = "accepted_requirement_revision_is_no_longer_current"
        if effective_state in {VerificationState.FINALIZED, VerificationState.REJECTED, VerificationState.STALE}:
            self._persist_evidence(context, row, command)
        updated = context.execute(
            "UPDATE verification_attempts SET state = ?, updated_at = ?, "
            "observation_json = COALESCE(?, observation_json), "
            "provider_receipt_json = COALESCE(?, provider_receipt_json), "
            "final_source_receipt_json = COALESCE(?, final_source_receipt_json), "
            "inspection_json = COALESCE(?, inspection_json), evidence_id = COALESCE(?, evidence_id), "
            "stale_reason = COALESCE(?, stale_reason), "
            "finalized_at = CASE WHEN ? IN ('finalized', 'rejected', 'stale', 'failed') THEN ? ELSE finalized_at END "
            "WHERE operation_id = ? AND state = ?",
            (effective_state, command.occurred_at, command.observation_json, command.receipt_json,
             command.final_source_receipt_json, command.inspection_json,
             None if command.evidence_id is None else str(command.evidence_id), effective_stale_reason,
             effective_state, command.occurred_at, str(command.operation_id), command.expected_state),
        ).rowcount
        if updated != 1:
            raise VerificationStateError("verification state changed during transition")
        external_state = {
            "prepared": "prepared", "executing": "executing", "observed": "observed",
            "not_started": "unknown", "unknown": "unknown", "failed": "failed",
            "finalized": "finalized", "rejected": "finalized", "stale": "finalized",
        }[effective_state]
        receipt_digest = None
        receipt_json = command.receipt_json or row["provider_receipt_json"]
        if receipt_json is not None:
            receipt_digest = _digest(receipt_json).hex
        context.execute(
            "UPDATE external_operations SET state = ?, updated_at = ?, receipt_digest = COALESCE(?, receipt_digest) "
            "WHERE operation_id = ?",
            (external_state, command.occurred_at, receipt_digest, str(command.operation_id)),
        )
        payload = {
            "operation_id": str(command.operation_id), "attempt_id": str(command.attempt.entity_id),
            "target": str(command.target.entity_id), "requirement_id": row["requirement_id"],
            "action": str(command.action),
            "previous_state": command.expected_state, "state": effective_state,
            "request_digest": row["request_digest"], "source_digest": row["source_digest"],
            "evidence_id": None if command.evidence_id is None else str(command.evidence_id),
            "stale_reason": effective_stale_reason,
        }
        if command.recovery_approval is not None:
            payload["recovery_approval_digest"] = _recovery_approval_digest(command.recovery_approval)
            payload["recovery_intent_kind"] = command.recovery_approval.intent_kind
            payload["recovery_intent_digest"] = command.recovery_approval.intent_digest.hex
        if command.recovery_source_json is not None:
            payload["recovery_source_digest"] = _digest(command.recovery_source_json).hex
        if command.recovery_approval is not None and command.inspection_json is not None:
            payload["recovery_inspection_digest"] = _digest(command.inspection_json).hex
        return CommandEffect(True, {"operation_id": str(command.operation_id), "state": effective_state,
                                    "evidence_id": None if command.evidence_id is None else str(command.evidence_id)},
                             f"todo.verification.{effective_state}", payload)

    def _persist_evidence(self, context: MutationContext, row: sqlite3.Row, command: _Transition) -> None:
        if command.observation_json is None or command.receipt_json is None or command.final_source_receipt_json is None:
            raise VerificationStateError("final evidence requires observation and both trusted source receipts")
        if command.evidence_id is None:
            raise VerificationStateError("final evidence identifier is missing")
        observation = json.loads(command.observation_json)
        receipt = json.loads(command.receipt_json)
        facts = observation["evidence_facts"]
        request = _request_from_json(row["request_json"])
        if (provider_request_digest(request).hex != row["request_digest"]
                or request.operation_id != StableId(row["operation_id"])
                or request.attempt.entity_id != StableId(row["attempt_id"])
                or request.requirement.entity_id != StableId(row["requirement_id"])
                or request.requirement.definition_revision_id != StableId(row["requirement_definition_revision_id"])
                or request.verifier_id != StableId(row["verifier_id"])
                or request.verifier_version != row["verifier_version"]
                or request.contract_digest.hex != row["contract_digest"]
                or request.expected_source.hex != row["source_digest"]):
            raise VerificationObservationMismatchError("persisted request identity differs from operation columns")
        # Exact required-evidence matching is checked again in the writer
        # transaction against the immutable authored requirement projection.
        requirement_row = context._connection.execute(
            "SELECT required_evidence_json FROM requirements WHERE requirement_id = ? "
            "AND definition_revision_id = ?",
            (row["requirement_id"], row["requirement_definition_revision_id"]),
        ).fetchone()
        if requirement_row is None:
            raise VerificationDeniedError("required evidence definition disappeared")
        authored_facts = json.loads(requirement_row["required_evidence_json"])
        actual_facts = [{"name": item["name"], "kind": item["kind"], "version": item["version"]}
                        for item in facts]
        if sorted(authored_facts, key=lambda item: item["name"]) != sorted(actual_facts, key=lambda item: item["name"]):
            raise VerificationObservationMismatchError("provider evidence facts do not exactly satisfy the authored names, kinds, and versions")
        if observation["source_digest"] != row["source_digest"] or observation["contract_digest"] != row["contract_digest"]:
            raise VerificationObservationMismatchError("provider observation differs from the prepared source or contract")
        if (observation["verifier_id"] != row["verifier_id"]
                or observation["verifier_version"] != row["verifier_version"]
                or row["operation_id"] != str(command.operation_id)):
            raise VerificationObservationMismatchError("provider observation differs from the persisted verifier or operation")
        provider = receipt.get("provider", {})
        if (provider.get("provider_id") != row["verifier_id"]
                or provider.get("version") != row["verifier_version"]
                or provider.get("contract_version") != self.service.provider_identity.contract_version
                or receipt.get("correlation_id") != row["operation_id"]
                or receipt.get("request_digest") != row["request_digest"]
                or receipt.get("provenance_ref") != row["operation_id"]):
            raise VerificationObservationMismatchError("verification receipt does not match the stored authorized request")
        receipt_time = datetime.fromisoformat(receipt["observed_at"])
        operation_time = datetime.fromisoformat(row["created_at"])
        command_time = datetime.fromisoformat(command.occurred_at)
        if receipt_time > command_time or receipt_time < operation_time:
            raise VerificationObservationMismatchError("verification receipt timestamp is outside the operation interval")
        inputs = json.loads(row["inputs_json"])
        if observation["inputs"] != inputs:
            raise VerificationObservationMismatchError("provider observation inputs differ from the prepared source inputs")
        final_source = json.loads(command.final_source_receipt_json)
        source = final_source.get("source")
        source_receipt = final_source.get("receipt")
        request = _request_from_json(row["request_json"])
        target = EntityRef(
            context.project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
            StableId(row["definition_revision_id"]),
        )
        source_context = request.context
        if command.recovery_approval is not None:
            if (context.actor != command.recovery_approval.actor
                    or context.authorized_capability_id != command.recovery_approval.capability_id):
                raise VerificationDeniedError("final source receipt is not bound to the approved recovery actor")
            source_context = self.service._context(
                context.actor, context.authorized_capability_id, StableId(row["operation_id"]), target,
            )
        final_request = _source_request(
            source_context, request.attempt, target, request.workspace_id, request.contract,
            StableId(row["operation_id"]), "after", request.expected_source,
        )
        try:
            final_provider = source_receipt["provider"]
            source_time = datetime.fromisoformat(source_receipt["observed_at"])
            if (not isinstance(source, dict)
                    or (command.state != VerificationState.STALE and (
                        source.get("source_digest") != row["source_digest"]
                        or source.get("inputs") != inputs
                        or source.get("working_tree") != json.loads(row["source_receipt_json"])["source"]["working_tree"]
                        or source.get("source_revision") != json.loads(row["source_receipt_json"])["source"].get("source_revision")
                    ))
                    or source.get("repository_id") != json.loads(row["source_receipt_json"])["source"]["repository_id"]
                    or source.get("base_digest") != json.loads(row["source_receipt_json"])["source"]["base_digest"]
                    or final_provider.get("provider_id") != str(self.service.source_identity.provider_id)
                    or final_provider.get("version") != self.service.source_identity.version
                    or final_provider.get("contract_version") != self.service.source_identity.contract_version
                    or source_receipt.get("correlation_id") != str(final_request.correlation_id)
                    or source_receipt.get("request_digest") != provider_request_digest(final_request).hex
                    or source_receipt.get("provenance_ref") != str(request.workspace_id)
                    or source_time > command_time or source_time < operation_time):
                raise ValueError("final source identity or receipt mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationObservationMismatchError("final source receipt does not bind the exact prepared inputs") from exc
        context.execute(
            "INSERT INTO evidence(evidence_id, attempt_id, requirement_id, requirement_definition_revision_id, "
            "operation_id, result, verifier_id, verifier_version, contract_digest, source_digest, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(command.evidence_id), row["attempt_id"], row["requirement_id"],
             row["requirement_definition_revision_id"], str(command.operation_id), observation["verdict"],
             observation["verifier_id"], observation["verifier_version"], row["contract_digest"],
             row["source_digest"], receipt["observed_at"]),
        )
        for item in inputs:
            context.execute(
                "INSERT INTO evidence_inputs(evidence_id, input_name, input_digest) VALUES (?, ?, ?)",
                (str(command.evidence_id), item["name"], item["digest"]),
            )
        verifier_id = observation["verifier_id"]
        artifact_digests = {
            fact["artifact_id"]: fact["digest"] for fact in facts if fact.get("artifact_id") is not None
        }
        for artifact_id in observation["artifact_ids"]:
            existing = context._connection.execute(
                "SELECT provider_id, external_ref, content_digest FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
            if existing is None:
                context.execute(
                    "INSERT INTO artifacts(artifact_id, provider_id, external_ref, content_digest) VALUES (?, ?, ?, NULL)",
                    (artifact_id, verifier_id, artifact_id),
                )
            elif existing["provider_id"] != verifier_id or existing["external_ref"] != artifact_id:
                raise VerificationObservationMismatchError("artifact identifier collides with another provider reference")
            context.execute(
                "INSERT INTO evidence_artifacts(evidence_id, artifact_id) VALUES (?, ?)",
                (str(command.evidence_id), artifact_id),
            )
            digest = artifact_digests.get(artifact_id)
            if digest is not None:
                current = context._connection.execute(
                    "SELECT content_digest FROM artifacts WHERE artifact_id = ?", (artifact_id,)
                ).fetchone()[0]
                if current is not None and current != digest:
                    raise VerificationObservationMismatchError("artifact content digest changed for an immutable artifact reference")
                context.execute(
                    "UPDATE artifacts SET content_digest = ? WHERE artifact_id = ? AND content_digest IS NULL",
                    (digest, artifact_id),
                )
        for fact in facts:
            value_json = None
            if fact.get("benchmark_value") is not None:
                value_json = _json({"value": fact["benchmark_value"], "unit": fact["unit"],
                                    "sample_count": fact["sample_count"]})
            context.execute(
                "INSERT INTO evidence_facts(evidence_id, fact_name, fact_kind, fact_version, fact_digest, artifact_id, value_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(command.evidence_id), fact["name"], fact["kind"], fact["version"], fact["digest"],
                 fact.get("artifact_id"), value_json),
            )


_ALLOWED_TRANSITIONS = {
    VerificationState.PREPARED: frozenset({VerificationState.EXECUTING}),
    VerificationState.EXECUTING: frozenset({VerificationState.OBSERVED, VerificationState.NOT_STARTED, VerificationState.UNKNOWN, VerificationState.FAILED}),
    VerificationState.UNKNOWN: frozenset({VerificationState.OBSERVED, VerificationState.NOT_STARTED, VerificationState.UNKNOWN}),
    VerificationState.NOT_STARTED: frozenset({VerificationState.EXECUTING}),
    VerificationState.OBSERVED: frozenset({VerificationState.FINALIZED, VerificationState.REJECTED, VerificationState.STALE, VerificationState.UNKNOWN}),
}


class VerificationService:
    """Execute and reconcile exact verification operations through injected providers."""

    def __init__(
        self,
        auth: AuthorityAuthService,
        *,
        source_observer: SourceObserver,
        source_identity: ProviderIdentity,
        provider: Verifier,
        provider_identity: ProviderIdentity,
        clock: Callable[[], datetime] | None = None,
        max_source_age: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not callable(getattr(source_observer, "observe", None)):
            raise TypeError("source_observer must implement observe")
        if not callable(getattr(provider, "verify", None)) or not callable(getattr(provider, "inspect", None)):
            raise TypeError("provider must implement verify and inspect")
        if not isinstance(source_identity, ProviderIdentity) or not isinstance(provider_identity, ProviderIdentity):
            raise TypeError("provider identities must be explicit ProviderIdentity values")
        if not isinstance(max_source_age, timedelta) or max_source_age <= timedelta(0):
            raise ValueError("max_source_age must be positive")
        self.auth = auth
        self.source_observer = source_observer
        self.source_identity = source_identity
        self.provider = provider
        self.provider_identity = provider_identity
        self.clock = clock or auth.clock
        self.max_source_age = max_source_age
        self.auth.dispatcher.register(_PrepareHandler(self))
        self.auth.dispatcher.register(_TransitionHandler(self))

    def _now(self) -> datetime:
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("verification clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)

    def _check_revision(self, authority: SQLiteAuthority, expected_revision: int | None) -> None:
        if expected_revision is None:
            return
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        actual = self.auth._revision(authority, None)
        if actual != expected_revision:
            raise StaleAuthorityRevisionError(
                f"authority revision changed: expected {expected_revision}, current {actual}"
            )

    def _validate_recovery_transition(
        self, context: MutationContext, command: _Transition, attempt, row: sqlite3.Row,
    ) -> None:
        approval = command.recovery_approval
        if not _is_recovery_approval(approval):
            raise VerificationDeniedError("recovery transition requires a freshly approved inspection intent")
        if (context.authorized_capability_id != approval.capability_id
                or context.actor != approval.actor):
            # The dispatcher requirement binds the action; the context and
            # approval bind the concrete grant currently authorizing it.
            raise VerificationDeniedError("recovery approval differs from the authenticated writer context")
        if approval.intent_kind not in {"retry_original_operation", "reconcile_observed_effect"}:
            raise VerificationDeniedError("recovery intent does not authorize verification lifecycle changes")
        if (approval.target != attempt.work_item or approval.attempt != attempt.ref
                or approval.run != attempt.run or approval.assignment != attempt.assignment
                or approval.operation is None
                or approval.operation.kind is not EntityKind.EXTERNAL_OPERATION
                or approval.operation.project_id != context.project.project_id
                or approval.operation.entity_id != command.operation_id
                or approval.authority_revision > context.starting_revision):
            raise VerificationDeniedError("recovery approval no longer matches the exact operation context")
        retry_transitions = {
            (VerificationState.NOT_STARTED, VerificationState.EXECUTING),
            (VerificationState.EXECUTING, VerificationState.EXECUTING),
            (VerificationState.UNKNOWN, VerificationState.EXECUTING),
            (VerificationState.EXECUTING, VerificationState.UNKNOWN),
            (VerificationState.EXECUTING, VerificationState.FAILED),
            (VerificationState.EXECUTING, VerificationState.OBSERVED),
            (VerificationState.OBSERVED, VerificationState.FINALIZED),
            (VerificationState.OBSERVED, VerificationState.REJECTED),
            (VerificationState.OBSERVED, VerificationState.STALE),
        }
        reconcile_transitions = {
            (VerificationState.EXECUTING, VerificationState.OBSERVED),
            (VerificationState.UNKNOWN, VerificationState.OBSERVED),
            (VerificationState.OBSERVED, VerificationState.FINALIZED),
            (VerificationState.OBSERVED, VerificationState.REJECTED),
            (VerificationState.OBSERVED, VerificationState.STALE),
        }
        permitted = retry_transitions if approval.intent_kind == "retry_original_operation" else reconcile_transitions
        if command.action != RECOVERY_APPLY_ACTION or (command.expected_state, command.state) not in permitted:
            raise VerificationDeniedError("recovery intent does not authorize this verification transition")
        if (attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.EXPIRED}
                or attempt.lease is None
                or approval.expected_lease_id != attempt.lease.lease_id
                or approval.expected_lease_expires_at != attempt.lease.expires_at
                or approval.expected_source_digest is None
                or approval.expected_source_digest.hex != row["source_digest"]):
            raise VerificationDeniedError("recovery approval lease, state, or source binding changed")

        # R01's approval is collected at a fixed authority revision. The first
        # writer must start there. Later writes in the same recovery chain may
        # proceed only when the latest event is the immediately linked prior
        # transition under this exact proof.
        approval_digest = _recovery_approval_digest(approval)
        if context.starting_revision == approval.authority_revision:
            pass
        elif context.starting_revision > approval.authority_revision:
            prior = context._connection.execute(
                "SELECT event_kind, payload_json, actor_id, actor_incarnation_id "
                "FROM authority_events WHERE semantic_revision = ? ORDER BY event_ordinal DESC LIMIT 1",
                (context.starting_revision,),
            ).fetchone()
            try:
                previous_payload = json.loads(prior["payload_json"]) if prior is not None else {}
            except (TypeError, ValueError):
                previous_payload = {}
            if (prior is None
                    or prior["actor_id"] != str(approval.actor.entity_id)
                    or prior["actor_incarnation_id"] != str(approval.actor.incarnation_id)
                    or previous_payload.get("action") != str(RECOVERY_APPLY_ACTION)
                    or previous_payload.get("operation_id") != str(command.operation_id)
                    or previous_payload.get("attempt_id") != str(attempt.attempt_id)
                    or previous_payload.get("request_digest") != row["request_digest"]
                    or previous_payload.get("source_digest") != row["source_digest"]
                    or previous_payload.get("recovery_intent_kind") != approval.intent_kind
                    or previous_payload.get("recovery_approval_digest") != approval_digest
                    or previous_payload.get("state") != command.expected_state):
                raise VerificationDeniedError("recovery transition is not linked to its immediately preceding approved event")
        else:
            raise VerificationDeniedError("recovery approval is from a future authority revision")

        if (approval.host_observation is None
                or (approval.intent_kind == "retry_original_operation"
                    and approval.host_observation.source is not SourceSafety.CLEAN)
                or approval.host_observation.process is not ProcessLiveness.STOPPED
                or approval.host_observation.children is not ChildActivity.NONE):
            raise VerificationDeniedError("recovery host observation does not prove stopped, safe execution")
        if approval.intent_kind == "reconcile_observed_effect" and approval.host_observation.source not in {
            SourceSafety.CLEAN, SourceSafety.DIRTY,
        }:
            raise VerificationDeniedError("observed-effect reconciliation requires a known source state")
        workspace = _stored_workspace(context._connection, context.project, attempt.ref)
        attempt_row = context._connection.execute(
            "SELECT * FROM attempts WHERE attempt_id = ?", (str(attempt.attempt_id),),
        ).fetchone()
        try:
            observation = _check_observation(
                approval.host_observation, target=attempt.work_item, attempt_ref=attempt.ref,
                row=attempt_row, workspace=workspace, now=self._now(), max_age=self.max_source_age,
            )
        except (AttemptError, TypeError, ValueError) as exc:
            raise VerificationDeniedError(f"recovery host observation is no longer current: {exc}") from exc
        if (observation.lease_id != approval.expected_lease_id
                or observation.observed_lease_expires_at != approval.expected_lease_expires_at
                or observation.source_digest != approval.expected_source_digest):
            raise VerificationDeniedError("recovery host observation differs from its approved source and lease")

        try:
            require_parent_children_resolved(context._connection, attempt.attempt_id)
        except ValueError as exc:
            raise VerificationDeniedError("recovery is blocked by an unresolved native child") from exc
        if context._connection.execute(
            "SELECT 1 FROM outcome_candidates WHERE attempt_id = ? AND state = 'pending' LIMIT 1",
            (str(attempt.attempt_id),),
        ).fetchone() is not None:
            raise VerificationDeniedError("recovery is blocked by a pending outcome candidate")

        request = _request_from_json(row["request_json"])
        if (provider_request_digest(request).hex != row["request_digest"]
                or row["external_digest"] != row["request_digest"]
                or row["external_idempotency_key"] != str(request.idempotency_key)
                or request.operation_id != command.operation_id
                or request.attempt != attempt.ref
                or request.requirement.entity_id != StableId(row["requirement_id"])
                or request.requirement.definition_revision_id != StableId(row["requirement_definition_revision_id"])
                or request.verifier_id != StableId(row["verifier_id"])
                or request.verifier_version != row["verifier_version"]
                or request.verifier_id != self.provider_identity.provider_id
                or request.verifier_version != self.provider_identity.version
                or request.expected_source.hex != row["source_digest"]
                or request.contract_digest.hex != row["contract_digest"]
                or request.context.actor != attempt.actor
                or request.context.project_id != context.project.project_id
                or row["work_item_id"] != str(attempt.work_item.entity_id)
                or row["definition_revision_id"] != str(attempt.work_item.definition_revision_id)):
            raise VerificationObservationMismatchError("recovery operation no longer matches its immutable authorized request")
        if (approval.intent_kind == "retry_original_operation"
                and command.state == VerificationState.EXECUTING):
            self._validate_recovery_inspection(context, command, request, row)
        if (command.expected_state == VerificationState.NOT_STARTED
                and command.state == VerificationState.EXECUTING):
            if command.recovery_source_json is None:
                raise VerificationObservationMismatchError("retry requires a fresh exact source observation")
            self._validate_recovery_source(context, command, request, attempt, row, workspace)
        elif command.state == VerificationState.EXECUTING and approval.intent_kind == "retry_original_operation":
            if command.recovery_source_json is None:
                raise VerificationObservationMismatchError("retry requires a fresh exact source observation")
            self._validate_recovery_source(context, command, request, attempt, row, workspace)
        elif command.recovery_source_json is not None:
            raise VerificationObservationMismatchError("unexpected recovery source observation on this transition")

    def _validate_recovery_inspection(
        self, context: MutationContext, command: _Transition,
        request: VerificationRequest, row: sqlite3.Row,
    ) -> None:
        try:
            document = json.loads(command.inspection_json or "")
            provider_receipt = document["receipt"]
            provider = provider_receipt["provider"]
            observed_at = datetime.fromisoformat(provider_receipt["observed_at"])
            if document.get("state") != VerificationInspectionState.NOT_STARTED.value:
                raise ValueError("provider operation is not NOT_STARTED")
            if document.get("original_receipt") is not None:
                raise ValueError("NOT_STARTED inspection must not contain an execution receipt")
            expected_context = self.service._context(
                context.actor, context.authorized_capability_id,
                command.operation_id, command.target,
            )
            correlation = _id(
                "vrecovery-inspect", f"{command.operation_id}:{command.idempotency_key}",
            )
            inspection_request = EffectInspectionRequest(
                expected_context, command.operation_id, request.idempotency_key,
                Sha256Digest(row["request_digest"]), correlation,
            )
            now = self.service._now()
            if (provider.get("provider_id") != str(self.service.provider_identity.provider_id)
                    or provider.get("version") != self.service.provider_identity.version
                    or provider.get("contract_version") != self.service.provider_identity.contract_version
                    or provider_receipt.get("correlation_id") != str(correlation)
                    or provider_receipt.get("request_digest") != provider_request_digest(inspection_request).hex
                    or provider_receipt.get("provenance_ref") != str(command.operation_id)
                    or observed_at > now
                    or now - observed_at.astimezone(timezone.utc) > self.service.max_source_age):
                raise ValueError("inspection receipt differs from the current exact recovery request")
            StableId(provider_receipt["receipt_id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VerificationObservationMismatchError("retry lacks a fresh exact NOT_STARTED inspection") from exc

    def _validate_recovery_source(
        self, context: MutationContext, command: _Transition, request: VerificationRequest,
        attempt, row: sqlite3.Row, workspace: WorkspaceQualification,
    ) -> None:
        try:
            document = json.loads(command.recovery_source_json or "")
            source = document["source"]
            receipt = document["receipt"]
            provider = receipt["provider"]
            observed_at = datetime.fromisoformat(receipt["observed_at"])
            if not isinstance(source, dict) or not isinstance(receipt, dict):
                raise TypeError("source observation and receipt must be objects")
            expected_request = _source_request(
                self._context(context.actor, context.authorized_capability_id,
                              command.operation_id, command.target),
                attempt.ref, command.target, workspace.workspace_id, request.contract,
                command.operation_id, "before", request.expected_source,
            )
            now = self._now()
            if (source.get("source_digest") != row["source_digest"]
                    or source.get("inputs") != json.loads(row["inputs_json"])
                    or source.get("repository_id") != str(workspace.repository_id)
                    or source.get("base_digest") != workspace.common_base.digest
                    or source.get("working_tree") != WorkingTreeState.CLEAN.value
                    or source.get("source_revision") != json.loads(row["source_receipt_json"])["source"].get("source_revision")
                    or provider.get("provider_id") != str(self.source_identity.provider_id)
                    or provider.get("version") != self.source_identity.version
                    or provider.get("contract_version") != self.source_identity.contract_version
                    or receipt.get("correlation_id") != str(expected_request.correlation_id)
                    or receipt.get("request_digest") != provider_request_digest(expected_request).hex
                    or receipt.get("provenance_ref") != str(workspace.workspace_id)
                    or observed_at > now
                    or now - observed_at.astimezone(timezone.utc) > self.max_source_age):
                raise ValueError("fresh source proof differs from the approved operation source")
            StableId(receipt["receipt_id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VerificationObservationMismatchError("fresh recovery source proof is invalid") from exc

    @staticmethod
    def _requirement_is_current(connection: sqlite3.Connection, project: Project,
                                attempt, operation: sqlite3.Row) -> bool:
        del project
        if attempt.run is not None:
            schedule = connection.execute(
                "SELECT plan_revision_id FROM run_schedules WHERE run_id = ?",
                (str(attempt.run.entity_id),),
            ).fetchone()
            revision_id = None if schedule is None else schedule[0]
        else:
            latest = connection.execute(
                "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            revision_id = None if latest is None else latest[0]
        if revision_id != operation["plan_revision_id"]:
            return False
        return connection.execute(
            "SELECT 1 FROM plan_revision_work_items AS m JOIN requirements AS r "
            "ON r.work_item_id = m.work_item_id AND r.definition_revision_id = m.definition_revision_id "
            "WHERE m.plan_revision_id = ? AND m.work_item_id = ? AND m.definition_revision_id = ? "
            "AND r.requirement_id = ? AND r.definition_revision_id = ?",
            (revision_id, operation["work_item_id"], operation["definition_revision_id"],
             operation["requirement_id"], operation["requirement_definition_revision_id"]),
        ).fetchone() is not None

    def _actor_and_capability(self, authority: SQLiteAuthority, token: str) -> tuple[EntityRef, StableId]:
        return self.auth._actor_for_token(authority, _token_digest(token))

    def _authorize_read(
        self, authority: SQLiteAuthority, bearer_token: str, actor: EntityRef,
        capability_id: StableId, requirement: AuthorizationRequirement,
    ) -> None:
        del capability_id  # The token lookup inside the guarded check is authoritative.
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(
                connection, authority.project, _token_digest(bearer_token), actor, requirement,
            )

    def _selection(
        self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef,
        requirement_ref: EntityRef, operation_id: StableId,
    ) -> tuple[EntityRef, StableId, object, WorkspaceQualification, StableId, CompiledPlan, Requirement]:
        actor, capability_id = self._actor_and_capability(authority, bearer_token)
        with authority.read_transaction() as connection:
            attempt, _, workspace = _attempt_context(connection, authority, attempt_ref, self._now())
            if actor != attempt.actor:
                raise VerificationDeniedError("only the current attempt owner may verify its work")
            plan_revision_id, plan = _plan_for_attempt(connection, authority.project, attempt)
            requirement = _load_requirement(plan, attempt.work_item, requirement_ref)
        auth_requirement = AuthorizationRequirement(
            VERIFY_ACTION, attempt.work_item, attempt.run, attempt.assignment, attempt.ref,
        )
        self._authorize_read(authority, bearer_token, actor, capability_id, auth_requirement)
        if requirement.verification is None:
            raise VerificationDeniedError("requirement has no verification contract")
        if requirement.verification.kind is VerificationKind.DOMAIN_PROVIDER:
            config = requirement.verification.config
            if (str(self.provider_identity.provider_id) != config["provider_id"]
                    or self.provider_identity.version != config["provider_version"]):
                raise VerificationDeniedError("configured verifier identity does not match the authored domain provider")
        return actor, capability_id, attempt, workspace, plan_revision_id, plan, requirement

    def _context(self, actor: EntityRef, capability_id: StableId, operation_id: StableId,
                 target: EntityRef) -> ProviderCallContext:
        return _request_context(actor, capability_id, operation_id, target)

    def _observe_source(
        self, request: SourceObservationRequest, workspace: WorkspaceQualification,
    ) -> tuple[SourceObservation, ProviderReceipt]:
        try:
            result = self.source_observer.observe(request)
        except Exception as exc:
            raise VerificationProviderUnavailableError(f"trusted source observation failed: {exc}") from exc
        if not isinstance(result, ProviderResult):
            raise VerificationProviderUnavailableError("source observer returned no typed ProviderResult")
        if result.status is not ProviderStatus.OBSERVED_SUCCESS or not isinstance(result.value, SourceObservation):
            raise VerificationProviderUnavailableError("source observer could not establish exact input identity")
        receipt = _provider_result_receipt(
            result, self.source_identity, request.correlation_id, provider_request_digest(request),
            request.workspace_id,
        )
        observed = result.value
        if (observed.repository_id != workspace.repository_id
                or observed.base_digest is None
                or observed.base_digest.hex != workspace.common_base.digest):
            raise VerificationObservationMismatchError("source observation differs from the persisted attempt workspace")
        now = self._now()
        observed_at = receipt.observed_at.astimezone(timezone.utc)
        if observed_at > now or now - observed_at > self.max_source_age:
            raise VerificationObservationMismatchError("source observation is stale or from the future")
        return observed, receipt

    def _prepare_request(
        self, *, actor: EntityRef, capability_id: StableId, attempt, workspace: WorkspaceQualification,
        requirement: Requirement, operation_id: StableId, idempotency_key: StableId,
        source: SourceObservation,
    ) -> VerificationRequest:
        contract = requirement.verification
        contract_digest = _contract_digest(contract)
        return VerificationRequest(
            self._context(actor, capability_id, operation_id, attempt.work_item), attempt.ref,
            requirement.ref, operation_id, idempotency_key, self.provider_identity.provider_id,
            source.source_digest, contract_digest, source.inputs, contract, workspace.workspace_id,
            self.provider_identity.version, requirement.required_evidence,
        )

    def _command_key(self, operation_id: StableId, phase: str) -> StableId:
        return _id("verify-" + phase, str(operation_id))

    def _apply_transition(
        self, authority: SQLiteAuthority, bearer_token: str, view: VerificationOperationView, *,
        expected_state: str, state: str, action: StableId, phase: str,
        observation_json: str | None = None, receipt_json: str | None = None,
        final_source_receipt_json: str | None = None, inspection_json: str | None = None,
        evidence_id: StableId | None = None, stale_reason: str | None = None,
        idempotency_key: StableId | None = None, run: EntityRef | None = None,
        assignment: EntityRef | None = None, expected_revision: int | None = None,
        recovery_approval: RecoveryApproval | None = None,
        recovery_source_json: str | None = None,
    ) -> CommandResult:
        command = _Transition(
            action, view.attempt, view.target, view.operation.entity_id, expected_state, state,
            idempotency_key or self._command_key(view.operation.entity_id, phase),
            self._now().isoformat(timespec="microseconds"), run, assignment,
            observation_json, receipt_json, final_source_receipt_json, inspection_json,
            evidence_id, stale_reason, recovery_approval, recovery_source_json,
        )
        return self.auth.execute(
            authority, bearer_token, command, idempotency_key=command.idempotency_key,
            expected_revision=expected_revision,
        )

    @staticmethod
    def _view_from_row(project: Project, row: sqlite3.Row) -> VerificationOperationView:
        def object_or_none(encoded: str | None):
            return None if encoded is None else MappingProxyType(json.loads(encoded))
        return VerificationOperationView(
            EntityRef(project.project_id, EntityKind.EXTERNAL_OPERATION, StableId(row["operation_id"])),
            EntityRef(project.project_id, EntityKind.ATTEMPT, StableId(row["attempt_id"])),
            EntityRef(project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                      StableId(row["definition_revision_id"])),
            EntityRef(project.project_id, EntityKind.REQUIREMENT, StableId(row["requirement_id"]),
                      StableId(row["requirement_definition_revision_id"])),
            StableId(row["plan_revision_id"]),
            ProviderIdentity(StableId(row["verifier_id"]), row["verifier_version"]),
            Sha256Digest(row["contract_digest"]), Sha256Digest(row["source_digest"]),
            tuple(EvidenceInput(StableId(item["name"]), Sha256Digest(item["digest"]))
                  for item in json.loads(row["inputs_json"])),
            Sha256Digest(row["request_digest"]), row["state"],
            datetime.fromisoformat(row["created_at"]), datetime.fromisoformat(row["updated_at"]),
            None if row["evidence_id"] is None else StableId(row["evidence_id"]), row["stale_reason"],
            object_or_none(row["observation_json"]), object_or_none(row["provider_receipt_json"]),
            object_or_none(row["source_receipt_json"]), object_or_none(row["final_source_receipt_json"]),
            object_or_none(row["inspection_json"]),
        )

    def read_operation(self, authority: SQLiteAuthority, operation_ref: EntityRef) -> VerificationOperationView:
        if (not isinstance(operation_ref, EntityRef) or operation_ref.kind is not EntityKind.EXTERNAL_OPERATION
                or operation_ref.project_id != authority.project.project_id):
            raise TypeError("operation_ref must be a project-local external-operation reference")
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM verification_attempts WHERE operation_id = ?",
                (str(operation_ref.entity_id),),
            ).fetchone()
        if row is None:
            raise VerificationNotFoundError(f"verification operation does not exist: {operation_ref.entity_id}")
        return self._view_from_row(authority.project, row)

    def _view_for_idempotency(self, authority: SQLiteAuthority, idempotency_key: StableId) -> VerificationOperationView | None:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT v.* FROM verification_attempts AS v JOIN external_operations AS o USING(operation_id) "
                "WHERE o.idempotency_key = ?", (str(idempotency_key),),
            ).fetchone()
        return None if row is None else self._view_from_row(authority.project, row)

    def execute(
        self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef, requirement_ref: EntityRef,
        *, idempotency_key: StableId, expected_revision: int | None = None,
    ) -> VerificationOperationView:
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        self._check_revision(authority, expected_revision)
        actor, capability_id = self._actor_and_capability(authority, bearer_token)
        existing = self._view_for_idempotency(authority, idempotency_key)
        if existing is not None:
            if existing.attempt != attempt_ref or existing.requirement != requirement_ref:
                raise VerificationObservationMismatchError("idempotency key is already bound to another verification request")
            requirement = AuthorizationRequirement(VERIFY_ACTION, existing.target)
            with authority.read_transaction() as connection:
                attempt, _ = _stored_attempt(connection, authority.project, existing.attempt)
            requirement = AuthorizationRequirement(VERIFY_ACTION, existing.target, attempt.run,
                                                    attempt.assignment, attempt.ref)
            self._authorize_read(authority, bearer_token, actor, capability_id, requirement)
            if existing.state == VerificationState.PREPARED:
                request = self._load_stored_request(authority, existing.operation)
                self._start_and_call(authority, bearer_token, existing, request, attempt.run, attempt.assignment)
            elif existing.state == VerificationState.OBSERVED:
                self._finalize_observed(authority, bearer_token, existing, attempt.run, attempt.assignment)
            # Executing/unknown/not-started require inspect or explicit retry;
            # finalized results are immutable exact retries.
            return self.read_operation(authority, existing.operation)

        if attempt_ref.kind is not EntityKind.ATTEMPT or attempt_ref.project_id != authority.project.project_id:
            raise TypeError("attempt_ref must be a project-local attempt reference")
        operation_id = _id("verify", _json([
            str(idempotency_key), str(attempt_ref.entity_id), str(requirement_ref.entity_id),
            str(requirement_ref.definition_revision_id), str(actor.entity_id), str(actor.incarnation_id),
        ]))
        actor, capability_id, attempt, workspace, plan_revision_id, _plan, requirement = self._selection(
            authority, bearer_token, attempt_ref, requirement_ref, operation_id,
        )
        context = self._context(actor, capability_id, operation_id, attempt.work_item)
        source_request = _source_request(context, attempt.ref, attempt.work_item, workspace.workspace_id,
                                         requirement.verification, operation_id, "before")
        source, source_receipt = self._observe_source(source_request, workspace)
        _receipt_time(source_receipt, now=self._now())
        request = self._prepare_request(
            actor=actor, capability_id=capability_id, attempt=attempt, workspace=workspace,
            requirement=requirement, operation_id=operation_id, idempotency_key=idempotency_key, source=source,
        )
        request_json = _verification_request_json(request)
        now = self._now().isoformat(timespec="microseconds")
        command = _Prepare(
            attempt.ref, attempt.work_item, requirement.ref, plan_revision_id, operation_id,
            idempotency_key, capability_id, self.provider_identity.provider_id, self.provider_identity.version,
            _json(requirement.verification.to_mapping()), request.contract_digest, source.source_digest,
            _json(_inputs_value(source.inputs)),
            _json({"source": _source_value(source), "receipt": _receipt_value(source_receipt)}), request_json,
            provider_request_digest(request), now, attempt.run, attempt.assignment,
        )
        self.auth.execute(authority, bearer_token, command,
                          idempotency_key=self._command_key(operation_id, "prepare"),
                          expected_revision=expected_revision)
        view = self.read_operation(authority, EntityRef(authority.project.project_id,
                                                        EntityKind.EXTERNAL_OPERATION, operation_id))
        self._start_and_call(authority, bearer_token, view, request, attempt.run, attempt.assignment)
        return self.read_operation(authority, view.operation)

    def _load_stored_request(self, authority: SQLiteAuthority, operation_ref: EntityRef) -> VerificationRequest:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT request_json, request_digest FROM verification_attempts WHERE operation_id = ?",
                (str(operation_ref.entity_id),),
            ).fetchone()
        if row is None:
            raise VerificationNotFoundError("verification request is unavailable")
        request = _request_from_json(row["request_json"])
        if provider_request_digest(request).hex != row["request_digest"]:
            raise VerificationObservationMismatchError("persisted verification request digest is corrupt")
        return request

    def _transition_from_view(
        self, authority: SQLiteAuthority, bearer_token: str, view: VerificationOperationView,
        state: str, phase: str, *, expected_state: str | None = None, **kwargs,
    ):
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, view.attempt)
        return self._apply_transition(
            authority, bearer_token, view, expected_state=expected_state or view.state, state=state,
            action=kwargs.pop("action", VERIFY_ACTION), phase=phase,
            run=attempt.run, assignment=attempt.assignment, **kwargs,
        )

    def _start_and_call(self, authority: SQLiteAuthority, bearer_token: str,
                        view: VerificationOperationView, request: VerificationRequest,
                        run: EntityRef | None, assignment: EntityRef | None,
                        *, idempotency_key: StableId | None = None,
                        action: StableId = VERIFY_ACTION,
                        recovery_approval: RecoveryApproval | None = None,
                        recovery_source_json: str | None = None,
                        recovery_inspection_json: str | None = None,
                        expected_revision: int | None = None) -> None:
        recovery_retry = (
            recovery_approval is not None
            and recovery_approval.intent_kind == "retry_original_operation"
            and view.state in {
                VerificationState.EXECUTING, VerificationState.UNKNOWN, VerificationState.NOT_STARTED,
            }
        )
        if (view.state != VerificationState.PREPARED and view.state != VerificationState.NOT_STARTED
                and not recovery_retry):
            raise VerificationStateError("only a durably prepared or proven-not-started operation may execute")
        if recovery_approval is not None and recovery_inspection_json is None:
            raise VerificationObservationMismatchError("recovery retry requires a fresh provider inspection")
        phase_key = (self._command_key(view.operation.entity_id, "executing") if idempotency_key is None
                     else _id("verify-retry", f"{view.operation.entity_id}:{idempotency_key}"))
        started = self._apply_transition(
            authority, bearer_token, view, expected_state=view.state, state=VerificationState.EXECUTING,
            action=action, phase="executing", idempotency_key=phase_key,
            inspection_json=recovery_inspection_json,
            run=run, assignment=assignment, expected_revision=expected_revision,
            recovery_approval=recovery_approval, recovery_source_json=recovery_source_json,
        )
        # A replaying caller did not own the durable effect intent. It must
        # never repeat the provider side effect.
        if started.replayed:
            return
        # The commit above is the durable effect boundary. No Todo writer is
        # held while the injected verifier performs external work.
        try:
            result = self.provider.verify(request)
        except Exception as exc:
            current = self.read_operation(authority, view.operation)
            self._transition_from_view(authority, bearer_token, current, VerificationState.UNKNOWN,
                                       "provider-raised", inspection_json=_json({
                                           "status": "exception", "reason_type": type(exc).__name__,
                                       }), action=action, recovery_approval=recovery_approval)
            return
        if not isinstance(result, ProviderResult):
            self._mark_unknown(authority, bearer_token, view.operation,
                               "provider returned no typed result",
                               action=action, recovery_approval=recovery_approval)
            return
        if result.status in {ProviderStatus.UNKNOWN, ProviderStatus.UNAVAILABLE}:
            self._transition_from_view(
                authority, bearer_token, self.read_operation(authority, view.operation), VerificationState.UNKNOWN,
                "provider-unknown", inspection_json=_json({"status": result.status.value,
                    "reason": None if result.reason_code is None else str(result.reason_code)}),
                action=action, recovery_approval=recovery_approval,
            )
            return
        try:
            receipt = _provider_result_receipt(
                result, self.provider_identity, request.operation_id, provider_request_digest(request),
                request.operation_id,
            )
            _receipt_time(receipt, now=self._now(), earliest=view.created_at)
        except VerificationObservationMismatchError as exc:
            self._mark_unknown(authority, bearer_token, view.operation, str(exc),
                               action=action, recovery_approval=recovery_approval)
            return
        if result.status is ProviderStatus.OBSERVED_FAILURE:
            current = self.read_operation(authority, view.operation)
            self._apply_transition(
                authority, bearer_token, current, expected_state=VerificationState.EXECUTING,
                state=VerificationState.FAILED, action=action, phase="provider-failed",
                receipt_json=_json(_receipt_value(receipt)), inspection_json=_json({"status": "observed_failure",
                    "reason": str(result.reason_code)}), run=run, assignment=assignment,
                recovery_approval=recovery_approval,
            )
            return
        observation = result.value
        if not isinstance(observation, VerificationObservation):
            self._mark_unknown(authority, bearer_token, view.operation,
                               "successful provider result omitted its observation",
                               action=action, recovery_approval=recovery_approval)
            return
        try:
            self._validate_observation(observation, request, receipt, authorized_at=view.created_at)
        except VerificationObservationMismatchError as exc:
            self._mark_unknown(authority, bearer_token, view.operation, str(exc),
                               action=action, recovery_approval=recovery_approval)
            return
        current = self.read_operation(authority, view.operation)
        self._apply_transition(
            authority, bearer_token, current, expected_state=VerificationState.EXECUTING,
            state=VerificationState.OBSERVED, action=action, phase="observed",
            observation_json=_json(_observation_value(observation)), receipt_json=_json(_receipt_value(receipt)),
            run=run, assignment=assignment, recovery_approval=recovery_approval,
        )
        self._finalize_observed(
            authority, bearer_token, self.read_operation(authority, view.operation), run, assignment,
            recovery_approval=recovery_approval,
        )

    def _validate_observation(
        self, observation: VerificationObservation, request: VerificationRequest, receipt: ProviderReceipt,
        *, authorized_at: datetime,
    ) -> None:
        if (observation.operation_id != request.operation_id
                or observation.verifier_id != self.provider_identity.provider_id
                or observation.verifier_version != self.provider_identity.version
                or request.verifier_id != self.provider_identity.provider_id
                or request.verifier_version != self.provider_identity.version
                or observation.source_digest != request.expected_source
                or observation.contract_digest != request.contract_digest
                or _inputs_value(observation.inputs) != _inputs_value(request.inputs)):
            raise VerificationObservationMismatchError("verification observation does not bind the exact operation, source, contract, or inputs")
        if (receipt.correlation_id != request.operation_id or receipt.request_digest != provider_request_digest(request)
                or receipt.provenance_ref != request.operation_id):
            raise VerificationObservationMismatchError("verification receipt does not bind the exact operation request")
        _receipt_time(receipt, now=self._now(), earliest=authorized_at)
        required = sorted(
            (str(item.name), item.kind.value, item.version) for item in request.required_evidence
        )
        actual = sorted(
            (str(item.name), item.kind.value, item.version) for item in observation.evidence_facts
        )
        if actual != required:
            raise VerificationObservationMismatchError(
                "provider evidence facts do not exactly satisfy the authored names, kinds, and versions"
            )
        facts_by_name = {item.name: item for item in observation.evidence_facts}
        for authored in request.required_evidence:
            fact = facts_by_name[authored.name]
            if authored.kind is EvidenceKind.ARTIFACT_REFERENCE and fact.artifact_id is None:
                raise VerificationObservationMismatchError(
                    "artifact_reference evidence must bind an exact artifact identifier"
                )

    def _mark_unknown(self, authority: SQLiteAuthority, bearer_token: str,
                      operation_ref: EntityRef, reason: str, *, action: StableId = VERIFY_ACTION,
                      recovery_approval: RecoveryApproval | None = None) -> None:
        view = self.read_operation(authority, operation_ref)
        if view.state not in {VerificationState.EXECUTING, VerificationState.UNKNOWN}:
            return
        self._transition_from_view(
            authority, bearer_token, view, VerificationState.UNKNOWN, "unknown",
            inspection_json=_json({"status": "unknown", "reason": reason[:512]}),
            action=action, recovery_approval=recovery_approval,
        )

    def _fresh_source_for_view(
        self, authority: SQLiteAuthority, bearer_token: str, view: VerificationOperationView,
        phase: str, recovery_approval: RecoveryApproval | None = None,
    ) -> tuple[SourceObservation, ProviderReceipt, VerificationRequest, WorkspaceQualification]:
        actor, capability_id = self._actor_and_capability(authority, bearer_token)
        request = self._load_stored_request(authority, view.operation)
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, view.attempt)
            workspace = _stored_workspace(connection, authority.project, view.attempt)
        if recovery_approval is None and actor != attempt.actor:
            raise VerificationDeniedError("only the current attempt owner may finalize its verification")
        if recovery_approval is not None and (
            not _is_recovery_approval(recovery_approval)
            or actor != recovery_approval.actor
            or capability_id != recovery_approval.capability_id
            or recovery_approval.intent_kind not in {
                "retry_original_operation", "reconcile_observed_effect",
            }
            or recovery_approval.operation != view.operation
            or recovery_approval.attempt != view.attempt
            or recovery_approval.target != view.target
            or recovery_approval.expected_source_digest != view.source_digest
        ):
            raise VerificationDeniedError("fresh-source request differs from the approved recovery operation")
        source_request = _source_request(
            self._context(actor, capability_id, view.operation.entity_id, view.target), view.attempt,
            view.target, workspace.workspace_id, request.contract, view.operation.entity_id,
            phase, request.expected_source,
        )
        source, receipt = self._observe_source(source_request, workspace)
        return source, receipt, request, workspace

    def _finalize_observed(
        self, authority: SQLiteAuthority, bearer_token: str, view: VerificationOperationView,
        run: EntityRef | None = None, assignment: EntityRef | None = None,
        recovery_approval: RecoveryApproval | None = None,
        expected_revision: int | None = None,
        idempotency_key: StableId | None = None,
    ) -> None:
        if view.state != VerificationState.OBSERVED:
            return
        source, source_receipt, request, _workspace = self._fresh_source_for_view(
            authority, bearer_token, view, "after", recovery_approval,
        )
        observation = json.loads(view.observation or "{}") if isinstance(view.observation, str) else dict(view.observation or {})
        expected_inputs = _inputs_value(request.inputs)
        initial_source = self._stored_source_value(authority, view.operation)
        same_source = (
            source.source_digest == request.expected_source and _inputs_value(source.inputs) == expected_inputs
            and source.working_tree.value == initial_source["working_tree"]
            and str(source.repository_id) == initial_source["repository_id"]
            and (None if source.base_digest is None else source.base_digest.hex) == initial_source["base_digest"]
            and (None if source.source_revision is None else str(source.source_revision)) == initial_source["source_revision"]
            and observation.get("source_digest") == request.expected_source.hex
        )
        status = VerificationState.STALE if not same_source else (
            VerificationState.REJECTED if observation.get("verdict") == EvidenceResult.FAIL.value
            else VerificationState.FINALIZED
        )
        stale_reason = None if same_source else "source_or_selected_inputs_changed_during_verification"
        evidence_id = _id("evidence", str(view.operation.entity_id))
        self._apply_transition(
            authority, bearer_token, view, expected_state=VerificationState.OBSERVED,
            state=status,
            action=VERIFY_ACTION if recovery_approval is None else RECOVERY_APPLY_ACTION,
            phase="finalize",
            observation_json=_json(observation), receipt_json=_json(dict(view.provider_receipt or {})),
            final_source_receipt_json=_json({"source": _source_value(source), "receipt": _receipt_value(source_receipt)}),
            evidence_id=evidence_id, stale_reason=stale_reason, run=run, assignment=assignment,
            expected_revision=expected_revision, recovery_approval=recovery_approval,
            idempotency_key=idempotency_key,
        )

    def recovery_replay(
        self, authority: SQLiteAuthority, bearer_token: str, operation_ref: EntityRef,
        intent_kind: str, idempotency_key: StableId, intent_digest: Sha256Digest,
    ) -> VerificationOperationView | None:
        """Replay an exact recovery lifecycle receipt before volatile inspection.

        Current recovery.apply authority is checked by ``replay_authorized``;
        the event must bind the same operation, intent kind, actor, request,
        and a durable digest of the sealed approval used for its first write.
        """
        if intent_kind not in {"retry_original_operation", "reconcile_observed_effect"}:
            raise ValueError("intent_kind is not a supported verification recovery intent")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        if not isinstance(intent_digest, Sha256Digest):
            raise TypeError("intent_digest must be a Sha256Digest")
        view = self.read_operation(authority, operation_ref)
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, view.attempt)
        command_key = _id(
            "verify-retry" if intent_kind == "retry_original_operation" else "verify-reconcile",
            f"{operation_ref.entity_id}:{idempotency_key}",
        )

        def matches(_connection: sqlite3.Connection, receipt_row: sqlite3.Row) -> bool:
            if receipt_row["event_id"] is None or receipt_row["changed"] != 1:
                return False
            if not isinstance(receipt_row["payload_json"], str):
                return False
            try:
                payload = json.loads(receipt_row["payload_json"])
            except (TypeError, ValueError):
                return False
            digest = payload.get("recovery_approval_digest")
            event_kind = receipt_row["event_kind"]
            return bool(
                isinstance(event_kind, str) and event_kind.startswith("todo.verification.")
                and payload.get("action") == str(RECOVERY_APPLY_ACTION)
                and payload.get("operation_id") == str(operation_ref.entity_id)
                and payload.get("attempt_id") == str(view.attempt.entity_id)
                and payload.get("target") == str(view.target.entity_id)
                and payload.get("request_digest") == view.request_digest.hex
                and payload.get("source_digest") == view.source_digest.hex
                and payload.get("recovery_intent_kind") == intent_kind
                and payload.get("recovery_intent_digest") == intent_digest.hex
                and isinstance(digest, str) and len(digest) == 64
                and all(character in "0123456789abcdef" for character in digest)
            )

        result = self.auth.replay_authorized(
            authority, bearer_token, command_key,
            AuthorizationRequirement(RECOVERY_APPLY_ACTION, view.target, attempt.run,
                                     attempt.assignment, attempt.ref),
            "todo.verification.transition", matches,
        )
        return None if result is None else self.read_operation(authority, operation_ref)

    def _authorize_recovery_call(
        self, authority: SQLiteAuthority, bearer_token: str, view: VerificationOperationView,
        attempt, actor: EntityRef, capability_id: StableId,
        approval: RecoveryApproval | None, intent_kind: str, expected_revision: int | None,
    ) -> RecoveryApproval:
        if not _is_recovery_approval(approval):
            raise VerificationDeniedError("recovery requires a freshly approved inspection intent")
        assert isinstance(approval, RecoveryApproval)
        if (approval.intent_kind != intent_kind or approval.actor != actor
                or approval.capability_id != capability_id
                or approval.target != view.target or approval.attempt != view.attempt
                or approval.run != attempt.run or approval.assignment != attempt.assignment
                or approval.operation != view.operation
                or approval.authority_revision < 0
                or expected_revision is not None and expected_revision != approval.authority_revision):
            raise VerificationDeniedError("recovery approval differs from the authenticated operation intent")
        self._authorize_read(authority, bearer_token, actor, capability_id, AuthorizationRequirement(
            RECOVERY_APPLY_ACTION, view.target, attempt.run, attempt.assignment, attempt.ref,
        ))
        with authority.read_transaction() as connection:
            current, row = _stored_attempt(connection, authority.project, attempt.ref)
            workspace = _stored_workspace(connection, authority.project, attempt.ref)
            try:
                require_parent_children_resolved(connection, attempt.ref.entity_id)
            except ValueError as exc:
                raise VerificationDeniedError("recovery is blocked by an unresolved native child") from exc
            if connection.execute(
                "SELECT 1 FROM outcome_candidates WHERE attempt_id = ? AND state = 'pending' LIMIT 1",
                (str(attempt.ref.entity_id),),
            ).fetchone() is not None:
                raise VerificationDeniedError("recovery is blocked by a pending outcome candidate")
            observation = approval.host_observation
            if (current.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.EXPIRED}
                    or current.lease is None
                    or approval.expected_lease_id != current.lease.lease_id
                    or approval.expected_lease_expires_at != current.lease.expires_at
                    or observation is None
                    or observation.source_digest != approval.expected_source_digest
                    or approval.expected_source_digest != view.source_digest):
                raise VerificationDeniedError("recovery approval lease or source is no longer current")
            try:
                _check_observation(
                    observation, target=view.target, attempt_ref=view.attempt, row=row,
                    workspace=workspace, now=self._now(), max_age=self.max_source_age,
                )
            except (AttemptError, TypeError, ValueError) as exc:
                raise VerificationDeniedError(f"recovery host observation is no longer current: {exc}") from exc
            if (observation.process is not ProcessLiveness.STOPPED
                    or observation.children is not ChildActivity.NONE
                    or intent_kind == "retry_original_operation" and observation.source is not SourceSafety.CLEAN
                    or intent_kind == "reconcile_observed_effect"
                    and observation.source not in {SourceSafety.CLEAN, SourceSafety.DIRTY}):
                raise VerificationDeniedError("recovery host observation does not establish the required safe state")
        request = self._load_stored_request(authority, view.operation)
        if (request.operation_id != view.operation.entity_id or request.attempt != view.attempt
                or request.expected_source != approval.expected_source_digest
                or request.contract_digest != view.contract_digest
                or request.verifier_id != view.verifier.provider_id
                or request.verifier_version != view.verifier.version
                or request.verifier_id != self.provider_identity.provider_id
                or request.verifier_version != self.provider_identity.version):
            raise VerificationObservationMismatchError("recovery request differs from its durable operation identity")
        return approval

    @staticmethod
    def _stored_source_value(authority: SQLiteAuthority, operation_ref: EntityRef) -> dict[str, object]:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT source_receipt_json FROM verification_attempts WHERE operation_id = ?",
                (str(operation_ref.entity_id),),
            ).fetchone()
        if row is None:
            raise VerificationNotFoundError("verification source receipt is unavailable")
        source = json.loads(row[0]).get("source")
        if not isinstance(source, dict):
            raise VerificationObservationMismatchError("stored source identity is malformed")
        return source

    def reconcile(
        self, authority: SQLiteAuthority, bearer_token: str, operation_ref: EntityRef,
        *, idempotency_key: StableId, expected_revision: int | None = None,
        _recovery: bool = False, _recovery_approval: RecoveryApproval | None = None,
    ) -> VerificationOperationView:
        if type(_recovery) is not bool:
            raise TypeError("_recovery must be a bool")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        transition_key = _id("verify-reconcile", f"{operation_ref.entity_id}:{idempotency_key}")
        if _recovery:
            if not _is_recovery_approval(_recovery_approval):
                raise VerificationDeniedError("recovery reconciliation requires a sealed approval")
            replay = self.recovery_replay(
                authority, bearer_token, operation_ref, "reconcile_observed_effect", idempotency_key,
                _recovery_approval.intent_digest,
            )
            if replay is not None:
                return replay
            assert isinstance(_recovery_approval, RecoveryApproval)
            if (expected_revision is not None
                    and expected_revision != _recovery_approval.authority_revision):
                raise VerificationDeniedError("expected revision differs from the approved recovery intent")
            expected_revision = _recovery_approval.authority_revision
        elif _recovery_approval is not None:
            raise VerificationDeniedError("recovery approval cannot be supplied without private recovery mode")
        self._check_revision(authority, expected_revision)
        view = self.read_operation(authority, operation_ref)
        actor, capability_id = self._actor_and_capability(authority, bearer_token)
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, view.attempt)
        recovery_approval = None
        action = VERIFY_RECONCILE_ACTION
        if _recovery:
            recovery_approval = self._authorize_recovery_call(
                authority, bearer_token, view, attempt, actor, capability_id,
                _recovery_approval, "reconcile_observed_effect", expected_revision,
            )
            action = RECOVERY_APPLY_ACTION
        else:
            if actor != attempt.actor:
                raise VerificationDeniedError("only the current attempt owner may reconcile verification")
            self._authorize_read(authority, bearer_token, actor, capability_id, AuthorizationRequirement(
                VERIFY_RECONCILE_ACTION, view.target, attempt.run, attempt.assignment, attempt.ref,
            ))
        with authority.read_transaction() as connection:
            already_reconciled = connection.execute(
                "SELECT 1 FROM command_idempotency WHERE idempotency_key = ?", (str(transition_key),)
            ).fetchone() is not None
        if already_reconciled:
            return self.read_operation(authority, operation_ref)
        if view.state == VerificationState.OBSERVED:
            self._finalize_observed(
                authority, bearer_token, view, attempt.run, attempt.assignment,
                recovery_approval=recovery_approval,
                expected_revision=expected_revision if _recovery else None,
                idempotency_key=transition_key if _recovery else None,
            )
            return self.read_operation(authority, operation_ref)
        if _recovery and view.state not in {VerificationState.EXECUTING, VerificationState.UNKNOWN}:
            raise VerificationStateError("observed-effect recovery requires an unresolved operation, not a retry candidate")
        if view.state not in {VerificationState.EXECUTING, VerificationState.UNKNOWN, VerificationState.NOT_STARTED}:
            return view
        request = self._load_stored_request(authority, operation_ref)
        context = self._context(actor, capability_id, operation_ref.entity_id, view.target)
        correlation = _id("vinspect", f"{operation_ref.entity_id}:{idempotency_key}")
        inspection_request = EffectInspectionRequest(
            context, operation_ref.entity_id, request.idempotency_key, view.request_digest, correlation,
        )
        try:
            result = self.provider.inspect(inspection_request)
        except Exception as exc:
            result = None
            reason = type(exc).__name__
        else:
            reason = "provider returned no typed inspection"
        if not isinstance(result, ProviderResult):
            if _recovery:
                raise VerificationProviderUnavailableError("recovery provider inspection was unavailable")
            current = self.read_operation(authority, operation_ref)
            self._transition_from_view(authority, bearer_token, current, VerificationState.UNKNOWN,
                "inspection-unavailable", action=VERIFY_RECONCILE_ACTION,
                idempotency_key=transition_key,
                expected_revision=expected_revision,
                inspection_json=_json({"status": "unavailable", "reason": reason[:512]}))
            return self.read_operation(authority, operation_ref)
        if result.status in {ProviderStatus.UNKNOWN, ProviderStatus.UNAVAILABLE}:
            if _recovery:
                raise VerificationStateError("recovery inspection did not establish an observed effect")
            current = self.read_operation(authority, operation_ref)
            self._transition_from_view(authority, bearer_token, current, VerificationState.UNKNOWN,
                "inspection-unknown", action=VERIFY_RECONCILE_ACTION,
                idempotency_key=transition_key,
                expected_revision=expected_revision,
                inspection_json=_json({"status": result.status.value,
                    "reason": None if result.reason_code is None else str(result.reason_code)}))
            return self.read_operation(authority, operation_ref)
        if result.status is not ProviderStatus.OBSERVED_SUCCESS:
            if _recovery:
                raise VerificationStateError("recovery inspection did not establish an observed effect")
            current = self.read_operation(authority, operation_ref)
            self._transition_from_view(authority, bearer_token, current, VerificationState.UNKNOWN,
                "inspection-failed", action=VERIFY_RECONCILE_ACTION, idempotency_key=transition_key,
                expected_revision=expected_revision,
                inspection_json=_json({"status": result.status.value,
                    "reason": None if result.reason_code is None else str(result.reason_code)}))
            return self.read_operation(authority, operation_ref)
        receipt = _provider_result_receipt(
            result, self.provider_identity, correlation, provider_request_digest(inspection_request),
            operation_ref.entity_id,
        )
        _receipt_time(receipt, now=self._now(), earliest=view.created_at)
        inspection = result.value
        if not isinstance(inspection, VerificationInspection) or inspection.operation_id != operation_ref.entity_id:
            raise VerificationObservationMismatchError("provider inspection does not match the exact operation")
        inspection_json = _json({
            "state": inspection.state.value, "receipt": _receipt_value(receipt),
            "original_receipt": None if inspection.original_receipt is None else _receipt_value(inspection.original_receipt),
        })
        current = self.read_operation(authority, operation_ref)
        if inspection.state is VerificationInspectionState.NOT_STARTED:
            if _recovery:
                raise VerificationStateError("recovery observed-effect intent cannot authorize a retry")
            self._transition_from_view(authority, bearer_token, current, VerificationState.NOT_STARTED,
                "inspection-not-started", action=VERIFY_RECONCILE_ACTION,
                idempotency_key=transition_key, expected_revision=expected_revision,
                inspection_json=inspection_json)
        elif inspection.state is VerificationInspectionState.RUNNING:
            if _recovery:
                raise VerificationStateError("recovery cannot reconcile a still-running provider operation")
            self._transition_from_view(authority, bearer_token, current, VerificationState.UNKNOWN,
                "inspection-running", action=VERIFY_RECONCILE_ACTION,
                idempotency_key=transition_key, expected_revision=expected_revision,
                inspection_json=inspection_json)
        else:
            observation = inspection.observation
            original_receipt = inspection.original_receipt
            if original_receipt is None:
                raise VerificationObservationMismatchError("completed inspection omitted the original execution receipt")
            if (original_receipt.provider != self.provider_identity
                    or original_receipt.correlation_id != request.operation_id
                    or original_receipt.request_digest != provider_request_digest(request)
                    or original_receipt.provenance_ref != request.operation_id):
                raise VerificationObservationMismatchError("inspection's original receipt does not bind the authorized execution")
            _receipt_time(original_receipt, now=self._now(), earliest=view.created_at)
            self._validate_observation(observation, request, original_receipt, authorized_at=view.created_at)
            self._transition_from_view(
                authority, bearer_token, current, VerificationState.OBSERVED, "inspection-completed",
                action=action, observation_json=_json(_observation_value(observation)),
                idempotency_key=transition_key,
                expected_revision=expected_revision if _recovery else expected_revision,
                receipt_json=_json(_receipt_value(original_receipt)), inspection_json=inspection_json,
                recovery_approval=recovery_approval,
            )
            self._finalize_observed(authority, bearer_token, self.read_operation(authority, operation_ref),
                                    attempt.run, attempt.assignment,
                                    recovery_approval=recovery_approval)
        return self.read_operation(authority, operation_ref)

    def retry_not_started(
        self, authority: SQLiteAuthority, bearer_token: str, operation_ref: EntityRef,
        *, idempotency_key: StableId, expected_revision: int | None = None,
        _recovery: bool = False, _recovery_approval: RecoveryApproval | None = None,
    ) -> VerificationOperationView:
        if type(_recovery) is not bool:
            raise TypeError("_recovery must be a bool")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        if _recovery:
            if not _is_recovery_approval(_recovery_approval):
                raise VerificationDeniedError("recovery retry requires a sealed approval")
            replay = self.recovery_replay(
                authority, bearer_token, operation_ref, "retry_original_operation", idempotency_key,
                _recovery_approval.intent_digest,
            )
            if replay is not None:
                return replay
            assert isinstance(_recovery_approval, RecoveryApproval)
            if (expected_revision is not None
                    and expected_revision != _recovery_approval.authority_revision):
                raise VerificationDeniedError("expected revision differs from the approved recovery intent")
            expected_revision = _recovery_approval.authority_revision
        elif _recovery_approval is not None:
            raise VerificationDeniedError("recovery approval cannot be supplied without private recovery mode")
        self._check_revision(authority, expected_revision)
        view = self.read_operation(authority, operation_ref)
        if (_recovery and view.state not in {
                VerificationState.EXECUTING, VerificationState.UNKNOWN, VerificationState.NOT_STARTED,
        }) or (not _recovery and view.state != VerificationState.NOT_STARTED):
            raise VerificationStateError("retry requires a provider inspection proving NOT_STARTED")
        actor, capability_id = self._actor_and_capability(authority, bearer_token)
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, view.attempt)
        recovery_approval = None
        action = VERIFY_ACTION
        source_json = None
        if _recovery:
            recovery_approval = self._authorize_recovery_call(
                authority, bearer_token, view, attempt, actor, capability_id,
                _recovery_approval, "retry_original_operation", expected_revision,
            )
            action = RECOVERY_APPLY_ACTION
        else:
            if actor != attempt.actor:
                raise VerificationDeniedError("only the current attempt owner may retry verification")
            self._authorize_read(authority, bearer_token, actor, capability_id, AuthorizationRequirement(
                VERIFY_ACTION, view.target, attempt.run, attempt.assignment, attempt.ref,
            ))
        request = self._load_stored_request(authority, operation_ref)
        recovery_inspection_json = None
        retry_key = None
        if _recovery:
            retry_key = _id("verify-retry", f"{view.operation.entity_id}:{idempotency_key}")
            inspection_request = EffectInspectionRequest(
                self._context(actor, capability_id, view.operation.entity_id, view.target),
                view.operation.entity_id, request.idempotency_key, view.request_digest,
                _id("vrecovery-inspect", f"{view.operation.entity_id}:{retry_key}"),
            )
            try:
                inspection_result = self.provider.inspect(inspection_request)
            except Exception as exc:
                raise VerificationProviderUnavailableError(
                    f"recovery provider inspection failed: {type(exc).__name__}"
                ) from exc
            if (not isinstance(inspection_result, ProviderResult)
                    or inspection_result.status is not ProviderStatus.OBSERVED_SUCCESS
                    or not isinstance(inspection_result.value, VerificationInspection)
                    or inspection_result.value.operation_id != view.operation.entity_id
                    or inspection_result.value.state is not VerificationInspectionState.NOT_STARTED
                    or inspection_result.value.original_receipt is not None):
                raise VerificationStateError("recovery retry requires a fresh exact NOT_STARTED provider inspection")
            inspection_receipt = _provider_result_receipt(
                inspection_result, self.provider_identity, inspection_request.correlation_id,
                provider_request_digest(inspection_request), view.operation.entity_id,
            )
            _receipt_time(inspection_receipt, now=self._now(), earliest=view.created_at)
            if self._now() - inspection_receipt.observed_at.astimezone(timezone.utc) > self.max_source_age:
                raise VerificationObservationMismatchError("recovery provider inspection receipt is stale")
            recovery_inspection_json = _json({
                "state": VerificationInspectionState.NOT_STARTED.value,
                "receipt": _receipt_value(inspection_receipt),
                "original_receipt": None,
            })
            source, source_receipt, _request, workspace = self._fresh_source_for_view(
                authority, bearer_token, view, "before", recovery_approval,
            )
            initial_source = self._stored_source_value(authority, operation_ref)
            if (source.source_digest != request.expected_source
                    or _inputs_value(source.inputs) != _inputs_value(request.inputs)
                    or source.working_tree is not WorkingTreeState.CLEAN
                    or str(source.repository_id) != initial_source["repository_id"]
                    or source.base_digest is None):
                raise VerificationObservationMismatchError("fresh recovery source differs from the original operation")
            if (source.base_digest.hex != initial_source["base_digest"]
                    or (None if source.source_revision is None else str(source.source_revision))
                    != initial_source["source_revision"]
                    or source.source_digest.hex != recovery_approval.expected_source_digest.hex):
                raise VerificationObservationMismatchError("fresh recovery source differs from the approved source intent")
            _receipt_time(source_receipt, now=self._now(), earliest=self._now() - self.max_source_age)
            source_json = _json({"source": _source_value(source), "receipt": _receipt_value(source_receipt)})
        self._start_and_call(authority, bearer_token, view, request, attempt.run, attempt.assignment,
                             idempotency_key=idempotency_key, action=action,
                             recovery_approval=recovery_approval,
                             recovery_source_json=source_json,
                             recovery_inspection_json=recovery_inspection_json,
                             expected_revision=expected_revision if _recovery else None)
        return self.read_operation(authority, operation_ref)

    def _effect_inspection_value(self, request: EffectInspectionRequest, receipt: ProviderReceipt,
                                 inspection: VerificationInspection) -> str:
        return _json({"operation_id": str(inspection.operation_id), "state": inspection.state.value,
                      "receipt": _receipt_value(receipt)})


__all__ = [
    "VERIFY_ACTION", "VERIFY_RECONCILE_ACTION", "VerificationError", "VerificationNotFoundError",
    "VerificationDeniedError", "VerificationProviderUnavailableError", "VerificationObservationMismatchError",
    "VerificationStateError", "VerificationState", "VerificationOperationView", "VerificationService",
]
