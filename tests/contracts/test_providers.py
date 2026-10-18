"""Shape and correlation tests for injected provider contracts."""

from datetime import datetime, timedelta, timezone
import unittest

from todo_orchestrator.contracts import (
    CommandExecutionRequest,
    CommandObservation,
    CommandExecutionInspection,
    CommandInspectionState,
    EntityKind,
    EntityRef,
    EffectInspectionRequest,
    EvidenceInput,
    EvidenceResult,
    GitEffectDisposition,
    GitEffectObservation,
    GitEffectRequest,
    GitOperationKind,
    ProviderCallContext,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    ResourcePermitRef,
    ResourcePermitInspection,
    ResourcePermitInspectionState,
    ResourcePermitRequest,
    Sha256Digest,
    SourceObservation,
    SourceObservationRequest,
    StableId,
    TrustedActorContext,
    VerificationObservation,
    VerificationRequest,
    WorkingTreeState,
)


def sid(value: str) -> StableId:
    return StableId(value)


PROJECT = sid("project")
ACTOR = EntityRef(PROJECT, EntityKind.ACTOR, sid("actor"), incarnation_id=sid("inc-1"))
CAPABILITY = EntityRef(PROJECT, EntityKind.CAPABILITY, sid("capability"))
ATTEMPT = EntityRef(PROJECT, EntityKind.ATTEMPT, sid("attempt"))
REQUIREMENT = EntityRef(
    PROJECT, EntityKind.REQUIREMENT, sid("requirement"), definition_revision_id=sid("plan-r1")
)
CONTEXT = ProviderCallContext(PROJECT, ACTOR, CAPABILITY, sid("host-context"), sid("scope"))
RECOVERY_CONTEXT = ProviderCallContext(
    PROJECT,
    EntityRef(PROJECT, EntityKind.ACTOR, sid("recovery-actor"), incarnation_id=sid("recovery-inc-1")),
    EntityRef(PROJECT, EntityKind.CAPABILITY, sid("recovery-capability")),
    sid("recovery-context"),
    sid("recovery-scope"),
)
PROVIDER = ProviderIdentity(sid("fake-provider"), "0.3")
DIGEST = Sha256Digest("a" * 64)
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def receipt(correlation: StableId, *, provider: ProviderIdentity = PROVIDER) -> ProviderReceipt:
    return ProviderReceipt(sid("receipt"), provider, correlation, DIGEST, sid("provenance"), NOW)


class FakeSourceObserver:
    """Disposable example: no filesystem or repository is touched."""

    def observe(self, request: SourceObservationRequest) -> ProviderResult[SourceObservation]:
        value = SourceObservation(sid("repo"), DIGEST, None, WorkingTreeState.CLEAN)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS,
            request.correlation_id,
            PROVIDER,
            value,
            receipt(request.correlation_id),
        )


class LostCommandProvider:
    """In-memory example: execute becomes uncertain; inspect only observes state."""

    def __init__(self) -> None:
        self.execute_calls = 0
        self.inspection_requests: list[EffectInspectionRequest] = []

    def execute(self, request: CommandExecutionRequest) -> ProviderResult[CommandObservation]:
        self.execute_calls += 1
        return ProviderResult(
            ProviderStatus.UNKNOWN, request.operation_id, PROVIDER, reason_code=sid("result_ambiguous")
        )

    def inspect(
        self, request: EffectInspectionRequest
    ) -> ProviderResult[CommandExecutionInspection]:
        self.inspection_requests.append(request)
        value = CommandExecutionInspection(request.operation_id, CommandInspectionState.RUNNING)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS,
            request.correlation_id,
            PROVIDER,
            value,
            receipt(request.correlation_id),
        )


class LostResourceProvider:
    """In-memory example: recovery queries a lost reservation without reserving again."""

    def __init__(self) -> None:
        self.reserve_calls = 0
        self.inspection_requests: list[EffectInspectionRequest] = []

    def reserve(self, request) -> ProviderResult[ResourcePermitRef]:
        self.reserve_calls += 1
        return ProviderResult(
            ProviderStatus.UNKNOWN, request.operation_id, PROVIDER, reason_code=sid("reply_lost")
        )

    def release(self, request) -> ProviderResult:
        raise AssertionError("release must not be called during reservation inspection")

    def inspect(
        self, request: EffectInspectionRequest
    ) -> ProviderResult[ResourcePermitInspection]:
        self.inspection_requests.append(request)
        value = ResourcePermitInspection(request.operation_id, ResourcePermitInspectionState.ABSENT)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS,
            request.correlation_id,
            PROVIDER,
            value,
            receipt(request.correlation_id),
        )


class ProviderEnvelopeTests(unittest.TestCase):
    def test_success_and_failure_require_correlated_receipts(self) -> None:
        value = SourceObservation(sid("repo"), DIGEST, None, WorkingTreeState.CLEAN)
        result = ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, sid("call"), PROVIDER, value, receipt(sid("call"))
        )
        self.assertEqual(result.receipt.correlation_id, result.correlation_id)

        failure = ProviderResult(
            ProviderStatus.OBSERVED_FAILURE,
            sid("call"),
            PROVIDER,
            receipt=receipt(sid("call")),
            reason_code=sid("source_unreadable"),
        )
        self.assertIsNone(failure.value)

        with self.assertRaisesRegex(ValueError, "requires a value"):
            ProviderResult(ProviderStatus.OBSERVED_SUCCESS, sid("call"), PROVIDER,
                           receipt=receipt(sid("call")))
        with self.assertRaisesRegex(ValueError, "correlation"):
            ProviderResult(ProviderStatus.OBSERVED_FAILURE, sid("call"), PROVIDER,
                           receipt=receipt(sid("other")), reason_code=sid("failed"))

    def test_unknown_and_unavailable_do_not_claim_observed_values(self) -> None:
        unknown = ProviderResult(
            ProviderStatus.UNKNOWN, sid("effect"), PROVIDER, reason_code=sid("result_ambiguous")
        )
        unavailable = ProviderResult(
            ProviderStatus.UNAVAILABLE, sid("effect"), reason_code=sid("provider_missing")
        )
        self.assertEqual(unknown.status, ProviderStatus.UNKNOWN)
        self.assertIsNone(unavailable.provider)
        with self.assertRaisesRegex(ValueError, "cannot assert a value"):
            ProviderResult(ProviderStatus.UNKNOWN, sid("effect"), PROVIDER, value=object(),
                           reason_code=sid("uncertain"))
        with self.assertRaisesRegex(ValueError, "cannot assert an observation"):
            ProviderResult(ProviderStatus.UNAVAILABLE, sid("effect"), value=object(),
                           reason_code=sid("missing"))

    def test_trusted_actor_and_todo_capability_are_distinct_references(self) -> None:
        context = TrustedActorContext(
            PROJECT, ACTOR, sid("host-context"), sid("scope"), (sid("git.read"),), NOW + timedelta(minutes=5)
        )
        self.assertEqual(context.actor.incarnation_id, sid("inc-1"))
        with self.assertRaisesRegex(ValueError, "capability must reference"):
            ProviderCallContext(PROJECT, ACTOR, ATTEMPT, sid("host-context"), sid("scope"))
        with self.assertRaisesRegex(ValueError, "incarnation"):
            ProviderCallContext(
                PROJECT,
                EntityRef(PROJECT, EntityKind.ACTOR, sid("actor")),
                CAPABILITY,
                sid("host-context"),
                sid("scope"),
            )


class ProviderContractTests(unittest.TestCase):
    def test_fake_source_observer_returns_a_disposable_correlated_observation(self) -> None:
        request = SourceObservationRequest(CONTEXT, sid("source-call"), DIGEST)
        result = FakeSourceObserver().observe(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS)
        self.assertEqual(result.value.working_tree, WorkingTreeState.CLEAN)
        self.assertEqual(result.receipt.request_digest, DIGEST)

    def test_git_and_command_requests_bind_expected_state_and_retry_identity(self) -> None:
        git = GitEffectRequest(
            CONTEXT, sid("git-op"), sid("git-retry"), GitOperationKind.APPLY_CHANGE, DIGEST, 7
        )
        self.assertEqual(git.expected_authority_revision, 7)
        applied = GitEffectObservation(sid("git-op"), GitEffectDisposition.APPLIED, DIGEST)
        self.assertEqual(applied.resulting_source, DIGEST)
        with self.assertRaisesRegex(ValueError, "requires resulting_source"):
            GitEffectObservation(sid("git-op"), GitEffectDisposition.APPLIED)

        command = CommandExecutionRequest(
            CONTEXT, ATTEMPT, sid("command-op"), sid("command-retry"), DIGEST, 7,
            sid("pytest-tool"), ("pytest", "-q"), 30_000,
        )
        self.assertEqual(command.argv, ("pytest", "-q"))
        with self.assertRaisesRegex(ValueError, "NUL"):
            CommandExecutionRequest(
                CONTEXT, ATTEMPT, sid("command-op"), sid("command-retry"), DIGEST, 7,
                sid("pytest-tool"), ("pytest\x00",), 30_000,
            )
        observation = CommandObservation(sid("command-op"), 1, False, NOW, NOW)
        self.assertEqual(observation.exit_code, 1)

    def test_resource_and_verification_records_preserve_external_provenance(self) -> None:
        permit = ResourcePermitRef(
            sid("permit"), sid("gpu-class"), sid("scope"), 1, NOW + timedelta(minutes=1),
            PROVIDER, sid("permit-receipt"),
        )
        request = ResourcePermitRequest(CONTEXT, ATTEMPT, sid("reserve-op"), sid("reserve-retry"),
                                        sid("gpu-class"), 1)
        self.assertEqual(permit.issuer, PROVIDER)
        self.assertEqual(request.resource_class, permit.resource_class)

        evidence_input = EvidenceInput(sid("test-report"), DIGEST)
        verification = VerificationRequest(
            CONTEXT, ATTEMPT, REQUIREMENT, sid("verify-op"), sid("verify-retry"), sid("pytest"),
            DIGEST, DIGEST, (evidence_input,),
        )
        observed = VerificationObservation(
            sid("verify-op"), EvidenceResult.PASS, sid("pytest"), "8.4", DIGEST, DIGEST,
            verification.inputs, (sid("artifact"),),
        )
        self.assertEqual(observed.verdict, EvidenceResult.PASS)
        self.assertEqual(observed.source_digest, verification.expected_source)

    def test_unknown_command_is_inspected_with_original_binding_without_reexecution(self) -> None:
        original = CommandExecutionRequest(
            CONTEXT, ATTEMPT, sid("unknown-command"), sid("command-retry"), DIGEST, 7,
            sid("pytest-tool"), ("pytest", "-q"), 30_000,
        )
        provider = LostCommandProvider()
        uncertain = provider.execute(original)
        self.assertEqual(uncertain.status, ProviderStatus.UNKNOWN)

        query = EffectInspectionRequest(
            RECOVERY_CONTEXT, original.operation_id, original.idempotency_key, DIGEST, sid("inspect-command")
        )
        inspected = provider.inspect(query)
        self.assertEqual(inspected.status, ProviderStatus.OBSERVED_SUCCESS)
        self.assertEqual(inspected.value.state, CommandInspectionState.RUNNING)
        self.assertIsNone(inspected.value.observation)
        self.assertEqual(provider.execute_calls, 1)
        self.assertEqual(provider.inspection_requests, [query])
        self.assertNotEqual(query.context, original.context)
        self.assertEqual(query.operation_id, original.operation_id)
        self.assertEqual(query.idempotency_key, original.idempotency_key)
        self.assertEqual(inspected.receipt.correlation_id, query.correlation_id)

    def test_unknown_reservation_is_inspected_without_a_second_reserve(self) -> None:
        original = ResourcePermitRequest(
            CONTEXT, ATTEMPT, sid("unknown-reserve"), sid("reserve-retry"), sid("gpu-class"), 1
        )
        provider = LostResourceProvider()
        uncertain = provider.reserve(original)
        self.assertEqual(uncertain.status, ProviderStatus.UNKNOWN)

        query = EffectInspectionRequest(
            RECOVERY_CONTEXT, original.operation_id, original.idempotency_key, DIGEST, sid("inspect-reserve")
        )
        inspected = provider.inspect(query)
        self.assertEqual(inspected.value.state, ResourcePermitInspectionState.ABSENT)
        self.assertIsNone(inspected.value.permit)
        self.assertEqual(provider.reserve_calls, 1)
        self.assertEqual(provider.inspection_requests, [query])
        self.assertNotEqual(query.context, original.context)
        self.assertEqual(query.operation_id, original.operation_id)
        self.assertEqual(query.idempotency_key, original.idempotency_key)


if __name__ == "__main__":
    unittest.main()
