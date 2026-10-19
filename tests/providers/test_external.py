"""Primary I04 tests for conservative resource-effect recovery."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority.attempts import AttemptTransitionError
from todo_orchestrator.contracts import ProviderResult, ProviderStatus, StableId
from todo_orchestrator.contracts.providers import (
    ResourcePermitInspection,
    ResourcePermitInspectionState,
    ResourcePermitReleaseRequest,
    ResourcePermitRequest,
)
from todo_orchestrator.providers.resources import (
    ResourcePermitProviderUnavailableError,
    ResourcePermitState,
)

from tests.providers import test_external_independent as _fixtures

LedgerResourceProvider = _fixtures.LedgerResourceProvider
RESOURCE_IDENTITY = _fixtures.RESOURCE_IDENTITY
FixedClock = _fixtures.FixedClock


class AmbiguousReleaseProvider(LedgerResourceProvider):
    """Models a release that may have happened but cannot be confirmed."""

    def release(self, request: ResourcePermitReleaseRequest) -> ProviderResult:
        self.release_requests.append(request)
        # Simulate that the external system may have acted before the response
        # was lost. This observation is deliberately not promoted to evidence.
        self.released.add(request.permit.permit_id)
        return ProviderResult(
            ProviderStatus.UNKNOWN,
            request.operation_id,
            RESOURCE_IDENTITY,
            reason_code=StableId("i04-release-result-unknown"),
        )

    def inspect(self, request) -> ProviderResult:
        self.inspection_requests.append(request)
        return ProviderResult(
            ProviderStatus.UNKNOWN,
            request.correlation_id,
            RESOURCE_IDENTITY,
            reason_code=StableId("i04-permit-inspection-unknown"),
        )


class RetryableResourceProvider(LedgerResourceProvider):
    """First reserve is interrupted before effect; later one is definitive."""

    def __init__(self, clock):
        super().__init__(clock)
        self.reserve_calls = []

    def reserve(self, request: ResourcePermitRequest) -> ProviderResult:
        self.reserve_calls.append(request)
        if len(self.reserve_calls) == 1:
            return ProviderResult(
                ProviderStatus.UNKNOWN,
                request.operation_id,
                RESOURCE_IDENTITY,
                reason_code=StableId("i04-reserve-interrupted"),
            )
        return super().reserve(request)

    def inspect(self, request) -> ProviderResult:
        self.inspection_requests.append(request)
        resource_request = request.resource_permit_request
        operation_id = resource_request.operation_id if resource_request is not None else request.operation_id
        permit = self.permits.get(operation_id)
        state = ResourcePermitInspectionState.ABSENT if permit is None else ResourcePermitInspectionState.HELD
        receipt = self._receipt(request.correlation_id, request)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS,
            request.correlation_id,
            RESOURCE_IDENTITY,
            ResourcePermitInspection(request.operation_id, state, permit),
            receipt,
        )


class RetryableReleaseProvider(LedgerResourceProvider):
    def __init__(self, clock):
        super().__init__(clock)
        self.release_calls = 0

    def release(self, request: ResourcePermitReleaseRequest) -> ProviderResult:
        self.release_calls += 1
        if self.release_calls == 1:
            self.release_requests.append(request)
            return ProviderResult(
                ProviderStatus.UNKNOWN,
                request.operation_id,
                RESOURCE_IDENTITY,
                reason_code=StableId("i04-release-interrupted"),
            )
        return super().release(request)

class ResourcePermitAmbiguityTests(unittest.TestCase):
    def test_unknown_release_preserves_held_occupancy_and_blocks_parent_finish(self):
        with tempfile.TemporaryDirectory(prefix="todo-i04-ambiguous-resource-") as temporary:
            root = Path(temporary)
            provider = AmbiguousReleaseProvider(FixedClock())
            fixture = _fixtures.ExternalProviderIndependentTests()
            fixture.root = root
            _project, _project_root, session, _composition, _command, _clock = fixture._project(
                resource_provider=provider,
            )
            try:
                dispatched = fixture._dispatch(session)
                held = session.reserve_resource(
                    dispatched.attempt_ref,
                    "i04-ambiguous-resource-class",
                    1,
                    idempotency_key=StableId("i04-ambiguous-reserve"),
                )
                self.assertEqual(held.state, ResourcePermitState.HELD)

                ambiguous = session.release_resource(
                    held.operation_id,
                    idempotency_key=StableId("i04-ambiguous-release"),
                )
                self.assertEqual(ambiguous.state, ResourcePermitState.UNKNOWN)
                self.assertEqual(len(provider.release_requests), 1)
                after_effect = session.read_model().semantic_revision

                # Read-only observation cannot promote an unknown release.
                readback = session.inspect_resource(held.operation_id)
                self.assertEqual(readback.state, ResourcePermitState.HELD)
                self.assertIsNone(readback.inspection_state)
                self.assertEqual(session.read_model().semantic_revision, after_effect)

                # Reconciliation requires a definitive typed observation. An
                # unavailable/unknown inspection leaves both rows unresolved.
                with self.assertRaises(ResourcePermitProviderUnavailableError):
                    session.reconcile_resource(
                        ambiguous.operation_id,
                        idempotency_key=StableId("i04-ambiguous-inspect"),
                    )
                self.assertEqual(session.read_model().semantic_revision, after_effect)
                self.assertEqual(session.inspect_resource(held.operation_id).state, ResourcePermitState.HELD)

                with self.assertRaises(AttemptTransitionError):
                    session.finish(
                        dispatched.attempt_ref,
                        dispatched.lease_id,
                        idempotency_key=StableId("i04-finish-with-unknown-permit"),
                    )
                self.assertEqual(session.read_model().semantic_revision, after_effect)
                self.assertEqual(len(provider.release_requests), 1)
            finally:
                session.close()

    def test_definitive_absence_allows_only_explicit_same_operation_retry(self):
        with tempfile.TemporaryDirectory(prefix="todo-i04-resource-retry-") as temporary:
            root = Path(temporary)
            provider = RetryableResourceProvider(FixedClock())
            fixture = _fixtures.ExternalProviderIndependentTests()
            fixture.root = root
            _project, _project_root, session, _composition, _command, _clock = fixture._project(
                resource_provider=provider,
            )
            try:
                dispatched = fixture._dispatch(session)
                uncertain = session.reserve_resource(
                    dispatched.attempt_ref,
                    "i04-retry-resource-class",
                    1,
                    idempotency_key=StableId("i04-retry-reserve"),
                )
                self.assertEqual(uncertain.state, ResourcePermitState.UNKNOWN)
                operation_id = uncertain.operation_id
                initial_request = provider.reserve_calls[0]

                not_applied = session.reconcile_resource(
                    operation_id,
                    idempotency_key=StableId("i04-reconcile-absent"),
                )
                self.assertEqual(not_applied.state, ResourcePermitState.NOT_APPLIED)
                self.assertEqual(len(provider.reserve_calls), 1)

                retried = session.retry_resource(
                    operation_id,
                    idempotency_key=StableId("i04-explicit-resource-retry"),
                )
                self.assertEqual(retried.operation_id, operation_id)
                self.assertEqual(retried.state, ResourcePermitState.HELD)
                self.assertEqual(len(provider.reserve_calls), 2)
                self.assertEqual(provider.reserve_calls[1], initial_request)
                self.assertEqual(len(provider.reserve_requests), 1)
                before_replay = (len(provider.reserve_calls), len(provider.inspection_requests),
                                 session.read_model().semantic_revision)

                replayed = session.retry_resource(
                    operation_id,
                    idempotency_key=StableId("i04-explicit-resource-retry"),
                    expected_revision=1,
                )
                self.assertEqual(replayed, retried)
                self.assertEqual(
                    (len(provider.reserve_calls), len(provider.inspection_requests),
                     session.read_model().semantic_revision),
                    before_replay,
                )
            finally:
                session.close()

    def test_release_retry_reuses_exact_original_permit_and_owner(self):
        with tempfile.TemporaryDirectory(prefix="todo-i04-resource-release-retry-") as temporary:
            root = Path(temporary)
            provider = RetryableReleaseProvider(FixedClock())
            fixture = _fixtures.ExternalProviderIndependentTests()
            fixture.root = root
            _project, _project_root, session, _composition, _command, _clock = fixture._project(
                resource_provider=provider,
            )
            try:
                dispatched = fixture._dispatch(session)
                held = session.reserve_resource(
                    dispatched.attempt_ref,
                    "i04-release-retry-resource-class",
                    1,
                    idempotency_key=StableId("i04-release-retry-reserve"),
                )
                uncertain = session.release_resource(
                    held.operation_id,
                    idempotency_key=StableId("i04-release-retry-release"),
                )
                self.assertEqual(uncertain.state, ResourcePermitState.UNKNOWN)
                release_operation_id = uncertain.operation_id
                first_request = provider.release_requests[0]

                not_applied = session.reconcile_resource(
                    release_operation_id,
                    idempotency_key=StableId("i04-release-retry-reconcile"),
                )
                self.assertEqual(not_applied.state, ResourcePermitState.NOT_APPLIED)
                retried = session.retry_resource(
                    release_operation_id,
                    idempotency_key=StableId("i04-release-retry-explicit"),
                )
                self.assertEqual(retried.operation_id, release_operation_id)
                self.assertEqual(retried.state, ResourcePermitState.RELEASED)
                self.assertEqual(provider.release_calls, 2)
                self.assertEqual(provider.release_requests[1], first_request)
                reservation = session.inspect_resource(held.operation_id)
                self.assertEqual(reservation.state, ResourcePermitState.RELEASED)
            finally:
                session.close()


if __name__ == "__main__":
    unittest.main()
