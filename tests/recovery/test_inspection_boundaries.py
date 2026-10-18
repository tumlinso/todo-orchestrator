"""Unknown source state must not look like a qualified recovery disposition."""

from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

from tests.recovery import test_inspection_independent as fixtures
from tests.verification import test_execution_independent as verification_fixture
from tests.verification import test_acceptance_independent as acceptance_fixture
from todo_orchestrator.authority.attempts import RECONCILE_ACTION
from todo_orchestrator.contracts import OutcomeDisposition, StableId
from todo_orchestrator.coordination.children import ChildExecutionService
from todo_orchestrator.model import (
    AttemptScopeSnapshot, CHILD_DELEGATE_ACTION, CHILD_WORKER_ACTIONS, SourceSafety,
)
from todo_orchestrator.operations.inspection import (
    RECOVERY_INSPECT_ACTION, RecoveryInspectionService,
)
from todo_orchestrator.views.recovery import RecoveryIntentKind, RecoveryOperationStatus, RecoveryStatus


class RecoverySourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoveryInspectionIndependentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def assert_unknown_source_is_uncertain(self):
        self.fixture.host.override = lambda observation: replace(
            observation, source=SourceSafety.UNKNOWN,
        )
        before = self.fixture.fixture.state_snapshot()
        result = self.fixture.inspect()
        self.assertEqual(result.status, RecoveryStatus.UNCERTAIN)
        self.assertTrue(result.blockers)
        self.assertEqual(result.intents, ())
        self.assertFalse(next(
            item.satisfied for item in result.preconditions if item.code == "source_clean"
        ))
        self.assertEqual(self.fixture.fixture.state_snapshot(), before)

    def test_unknown_source_on_live_lease_is_uncertain(self):
        self.assert_unknown_source_is_uncertain()

    def test_unknown_source_on_expired_lease_is_uncertain(self):
        first = self.fixture.inspect()
        self.fixture.fixture.clock.value = first.lease_expires_at + timedelta(seconds=1)
        self.assert_unknown_source_is_uncertain()

    def test_valid_observation_after_request_start_is_not_rejected_as_future(self):
        clock = verification_fixture.SteppingClock(self.fixture.fixture.clock.value)
        self.fixture.fixture.clock = clock
        self.fixture.fixture.auth.clock = clock
        self.fixture.host.delegate.clock = clock
        self.fixture.service.clock = clock
        before = self.fixture.fixture.state_snapshot()
        result = self.fixture.inspect()
        self.assertIsNotNone(result.host_observation)
        self.assertEqual(result.status, RecoveryStatus.ACTIVE)
        self.assertEqual(result.blockers, ())
        self.assertEqual(self.fixture.fixture.state_snapshot(), before)


class RecoveryNativeChildBoundaryTests(unittest.TestCase):
    def test_active_native_child_blocks_attempt_and_effect_retry_previews(self):
        fixture = verification_fixture.IndependentVerificationExecutionTests()
        actions = (*verification_fixture.OWNER_ACTIONS, CHILD_DELEGATE_ACTION,
                   *CHILD_WORKER_ACTIONS, RECOVERY_INSPECT_ACTION)
        with patch.object(verification_fixture, "OWNER_ACTIONS", actions):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        parent = fixture.claim("verify", fixture.owner.bearer_token, key="r01-child-parent")
        children = ChildExecutionService(fixture.auth, attempts=fixture.attempts)
        with fixture.open_writer() as authority:
            children.start_child(
                authority, fixture.owner.bearer_token, parent, "worker-other",
                execution_id=StableId("r01-occupied-child"), logical_id=StableId("r01-child-logical"),
                scope=AttemptScopeSnapshot((("src/verify/child", "write"),), ()),
                actions=CHILD_WORKER_ACTIONS, idempotency_key=StableId("r01-occupied-child-start"),
            )
        key = StableId("r01-child-not-started-verification")
        with fixture.open_writer() as authority:
            with patch.object(fixture.verifier, "verify", side_effect=KeyboardInterrupt("before effect")):
                with self.assertRaises(KeyboardInterrupt):
                    fixture.verification.execute(
                        authority, fixture.owner.bearer_token, parent,
                        fixture.requirement_ref("check-verify"), idempotency_key=key,
                    )
            operation = fixture.verification._view_for_idempotency(authority, key).operation
        inspector = RecoveryInspectionService(
            fixture.auth, host=fixture.host,
            operation_inspectors={"verification": fixture.verifier},
            source_observer=fixture.source, clock=fixture.clock,
        )
        before = fixture.state_snapshot()
        for method, reference in ((inspector.inspect_attempt, parent),
                                  (inspector.inspect_effect, operation)):
            with self.subTest(entrypoint=method.__name__), fixture.open_reader() as authority:
                report = method(authority, fixture.owner.bearer_token, reference)
                self.assertNotEqual(report.status, RecoveryStatus.SAFELY_RETRYABLE)
                self.assertTrue(report.blockers)
                self.assertTrue(report.operations)
                self.assertNotEqual(report.operations[0].status, RecoveryOperationStatus.SAFELY_RETRYABLE)
                self.assertFalse(any(intent.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION
                                     for intent in report.intents))
            self.assertEqual(fixture.state_snapshot(), before)


class RecoveryCandidateBoundaryTests(unittest.TestCase):
    def test_pending_candidate_blocks_release_before_and_after_expiry_reconciliation(self):
        case = acceptance_fixture.IndependentOutcomeAcceptanceTests()
        actions = (*acceptance_fixture.REPORT_ACTIONS, RECOVERY_INSPECT_ACTION, RECONCILE_ACTION)
        with patch.object(acceptance_fixture, "REPORT_ACTIONS", actions):
            case.setUp()
        self.addCleanup(case.doCleanups)
        fixture = case.fixture
        parent = fixture.claim("prerequisite", fixture.owner.bearer_token, key="r01-candidate-parent")
        case.report(fixture.owner.bearer_token, parent, OutcomeDisposition.COMPLETED,
                    "r01-pending-candidate")
        inspector = RecoveryInspectionService(fixture.auth, host=fixture.host, clock=fixture.clock)
        with fixture.open_reader() as authority:
            first = inspector.inspect_attempt(authority, fixture.owner.bearer_token, parent)
        fixture.clock.value = first.lease_expires_at + timedelta(seconds=1)
        for reconciled in (False, True):
            if reconciled:
                with fixture.open_writer() as authority:
                    fixture.attempts.reconcile_expired(
                        authority, fixture.owner.bearer_token, parent,
                        idempotency_key=StableId("r01-retain-reported-candidate"),
                    )
            before = fixture.state_snapshot()
            with self.subTest(reconciled=reconciled), fixture.open_reader() as authority:
                result = inspector.inspect_attempt(authority, fixture.owner.bearer_token, parent)
                self.assertEqual(result.status, RecoveryStatus.UNCERTAIN)
                self.assertTrue(result.blockers)
                self.assertFalse(any(intent.kind is RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT
                                     for intent in result.intents))
            self.assertEqual(fixture.state_snapshot(), before)


if __name__ == "__main__":
    unittest.main()
