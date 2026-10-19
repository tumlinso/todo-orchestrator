"""Independent I04 regressions for stale receipts and unresolved permits."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority.attempts import AttemptTransitionError
from todo_orchestrator.contracts import (
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    StableId,
    provider_request_digest,
)
from todo_orchestrator.contracts.providers import ResourcePermitRef, ResourcePermitRelease
from todo_orchestrator.providers.resources import ResourcePermitState
from todo_orchestrator.verification.acceptance import CandidateDeniedError
from tests.providers import test_external_independent as _fixtures


class _StaleReserveProvider(_fixtures.LedgerResourceProvider):
    def reserve(self, request):
        self.reserve_requests.append(request)
        assert request.scope_id is not None and request.lease_expires_at is not None
        receipt = ProviderReceipt(
            StableId("i04-review-stale-reserve-receipt"), _fixtures.RESOURCE_IDENTITY,
            request.operation_id, provider_request_digest(request), request.operation_id,
            _fixtures.NOW - timedelta(days=30),
        )
        permit = ResourcePermitRef(
            StableId("i04-review-stale-reserve-permit"), request.resource_class,
            request.scope_id, request.units, request.lease_expires_at,
            _fixtures.RESOURCE_IDENTITY, receipt.receipt_id,
        )
        # Model a reservation that happened even though the provider returned
        # a stale receipt for it.
        self.permits[request.operation_id] = permit
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.operation_id,
            _fixtures.RESOURCE_IDENTITY, permit, receipt,
        )


class _StaleReleaseProvider(_fixtures.LedgerResourceProvider):
    def release(self, request):
        self.release_requests.append(request)
        receipt = ProviderReceipt(
            StableId("i04-review-stale-release-receipt"), _fixtures.RESOURCE_IDENTITY,
            request.operation_id, provider_request_digest(request), request.operation_id,
            _fixtures.NOW - timedelta(days=30),
        )
        # Deliberately leave the external permit held.
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.operation_id,
            _fixtures.RESOURCE_IDENTITY,
            ResourcePermitRelease(request.operation_id, request.permit.permit_id, True),
            receipt,
        )


class ExternalProviderReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-i04-review-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _session(self, provider):
        fixture = _fixtures.ExternalProviderIndependentTests()
        fixture.root = self.root
        *_, session, _composition, _command_provider, _clock = fixture._project(
            resource_provider=provider,
        )
        return fixture, session

    def test_stale_reservation_receipt_keeps_effect_unresolved_and_blocks_finish(self):
        fixture, session = self._session(_StaleReserveProvider(_fixtures.FixedClock()))
        with session:
            dispatched = fixture._dispatch(session)
            operation = session.reserve_resource(
                dispatched.attempt_ref, StableId("i04-review-stale-class"), 1,
                idempotency_key=StableId("i04-review-stale-reserve"),
            )

            self.assertEqual(operation.state, ResourcePermitState.UNKNOWN)
            with self.assertRaises(AttemptTransitionError):
                session.finish(
                    dispatched.attempt_ref, dispatched.lease_id,
                    idempotency_key=StableId("i04-review-stale-reserve-finish"),
                )

    def test_stale_release_receipt_does_not_clear_held_permit_or_finish_attempt(self):
        provider = _StaleReleaseProvider(_fixtures.FixedClock())
        fixture, session = self._session(provider)
        with session:
            dispatched = fixture._dispatch(session)
            reservation = session.reserve_resource(
                dispatched.attempt_ref, StableId("i04-review-stale-release-class"), 1,
                idempotency_key=StableId("i04-review-stale-release-reserve"),
            )
            self.assertEqual(reservation.state, ResourcePermitState.HELD)

            release = session.release_resource(
                reservation.operation_id,
                idempotency_key=StableId("i04-review-stale-release"),
            )

            self.assertEqual(release.state, ResourcePermitState.UNKNOWN)
            permit = provider.permits[reservation.operation_id]
            self.assertNotIn(permit.permit_id, provider.released)
            with self.assertRaises(AttemptTransitionError):
                session.finish(
                    dispatched.attempt_ref, dispatched.lease_id,
                    idempotency_key=StableId("i04-review-stale-release-finish"),
                )

    def test_held_permit_blocks_candidate_report_without_authority_churn(self):
        fixture, session = self._session(_fixtures.LedgerResourceProvider(_fixtures.FixedClock()))
        with session:
            dispatched = fixture._dispatch(session)
            reservation = session.reserve_resource(
                dispatched.attempt_ref, StableId("i04-review-report-class"), 1,
                idempotency_key=StableId("i04-review-report-reserve"),
            )
            self.assertEqual(reservation.state, ResourcePermitState.HELD)
            before = session.read_model().semantic_revision

            with self.assertRaises(CandidateDeniedError):
                session.report(
                    dispatched.attempt_ref, "completed",
                    idempotency_key=StableId("i04-review-report-held"),
                )

            self.assertEqual(session.read_model().semantic_revision, before)
            with session._reader() as authority:
                count = authority.connection.execute(
                    "SELECT COUNT(*) FROM outcome_candidates WHERE attempt_id = ?",
                    (str(dispatched.attempt_ref.entity_id),),
                ).fetchone()[0]
            self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
