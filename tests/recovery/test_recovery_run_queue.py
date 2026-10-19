"""Recovery releases execution ownership without consuming a queued assignment."""

from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

from tests.coordination import test_dispatch_independent as fixture_module
from todo_orchestrator.authority import AuthorityError
from todo_orchestrator.contracts import Sha256Digest, StableId
from todo_orchestrator.model import RunSchedule
from todo_orchestrator.operations.inspection import RECOVERY_INSPECT_ACTION, RecoveryInspectionService
from todo_orchestrator.operations.recovery import RECOVERY_APPLY_ACTION, RecoveryExecutionService
from todo_orchestrator.views.recovery import RecoveryIntentKind


class RecoveryRunQueueTests(unittest.TestCase):
    def test_expired_run_assignment_requeues_and_old_session_cannot_resume(self):
        fixture = fixture_module.IndependentDispatchTests()
        actions = (*fixture_module.OWNER_ACTIONS, RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION)
        with patch.object(fixture_module, "OWNER_ACTIONS", actions):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original_inspect = fixture.host.inspect_attempt
        fixture.host.inspect_attempt = lambda attempt, workspace: replace(
            original_inspect(attempt, workspace), source_digest=Sha256Digest("4" * 64),
        )
        run_id = StableId("recovery-requeue-run")
        with fixture.open_writer() as authority:
            fixture.coordination.open_run(
                authority, fixture.owner.bearer_token, fixture.plan,
                RunSchedule(run_id, fixture.plan.revision.ref),
                idempotency_key=StableId("recovery-open-run"),
                expected_revision=fixture.revision(),
            )
        with fixture.open_reader() as authority:
            run = fixture.coordination.read_run(authority, run_id)
        original = fixture.dispatch("recovery-first-dispatch", run=run.run.ref)
        outcomes = fixture.outcome_snapshot()
        inspection = RecoveryInspectionService(fixture.auth, host=fixture.host, clock=fixture.clock)
        recovery = RecoveryExecutionService(inspection, attempts=fixture.attempts, clock=fixture.clock)
        fixture.clock.now = original.attempt.lease.expires_at + timedelta(seconds=1)
        with fixture.open_reader() as authority:
            report = inspection.inspect_attempt(
                authority, fixture.owner.bearer_token, original.attempt.ref,
            )
        intent, = (item for item in report.intents
                   if item.kind is RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT)
        with fixture.open_writer() as authority:
            recovery.apply(authority, fixture.owner.bearer_token, intent,
                           idempotency_key=StableId("recovery-release-run-attempt"))
        before = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            with self.assertRaises(AuthorityError):
                fixture.coordination.resume(
                    authority, original.bearer_token, fixture.plan, original.attempt.ref,
                    original.attempt.lease.lease_id,
                    idempotency_key=StableId("recovery-old-session-resume"),
                )
        self.assertEqual(fixture.state_snapshot(), before)
        replacement = fixture.dispatch(
            "recovery-second-dispatch", run=original.attempt.run,
            assignment=original.attempt.assignment, work_item=original.attempt.work_item,
        )
        self.assertNotEqual(replacement.attempt.ref, original.attempt.ref)
        self.assertEqual(replacement.attempt.assignment, original.attempt.assignment)
        self.assertEqual(replacement.attempt.run, original.attempt.run)
        self.assertEqual(replacement.attempt.work_item, original.attempt.work_item)
        self.assertEqual(fixture.outcome_snapshot(), outcomes)
