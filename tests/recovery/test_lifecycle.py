"""Public run lifecycle flows over disposable SQLite authorities."""

from datetime import timedelta
import unittest

from todo_orchestrator.authority import (
    AuthenticationFailedError,
    CapabilityDeniedError,
    IdempotencyConflictError,
)
from todo_orchestrator.contracts import OutcomeDisposition, StableId
from todo_orchestrator.coordination import RUN_DISPATCH_ACTION, RUN_SCHEDULE_ACTION
from todo_orchestrator.model import RunSchedule, ScheduledWork
from todo_orchestrator.operations.lifecycle import (
    RUN_CLOSE_ACTION,
    RUN_HANDOFF_ACTION,
    RUN_RETIRE_ACTION,
    RunAssignmentHandoff,
    RunLifecycleService,
)

from tests.verification import test_acceptance_independent as acceptance_fixture
from tests.verification.test_execution_independent import PROJECT


class RunLifecyclePublicTests(unittest.TestCase):
    """Exercise close, handoff, authorization, and replay via public services."""

    def setUp(self):
        self.acceptance = acceptance_fixture.IndependentOutcomeAcceptanceTests()
        self.acceptance.setUp()
        self.addCleanup(self.acceptance.doCleanups)
        self.f = self.acceptance.fixture
        self.lifecycle = RunLifecycleService(self.f.auth)
        self.owner = self._issue_owner(
            (
                *acceptance_fixture.REPORT_ACTIONS,
                RUN_SCHEDULE_ACTION,
                RUN_DISPATCH_ACTION,
                RUN_CLOSE_ACTION,
                RUN_RETIRE_ACTION,
                RUN_HANDOFF_ACTION,
                StableId("todo.capability.delegate"),
                StableId("todo.capability.revoke"),
            ),
            "r03-lifecycle-public-owner",
        )

    def _issue_owner(self, actions, key):
        f = self.f
        with f.open_writer() as authority:
            return f.auth.login_local_owner(
                authority,
                acceptance_fixture.OWNER_PASSWORD,
                actions=tuple(dict.fromkeys(actions)),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def _delegate(self, credential, actions, key, *, scope=None, run=None, assignment=None):
        f = self.f
        with f.open_writer() as authority:
            return f.auth.delegate(
                authority,
                self.owner.bearer_token,
                credential,
                actions=tuple(actions),
                scope=scope or PROJECT.ref,
                run=run,
                assignment=assignment,
                expires_at=f.clock() + timedelta(minutes=30),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def _open_run(self, run_id, work_ids):
        f = self.f
        schedule = RunSchedule(
            StableId(run_id),
            f.plan.revision.ref,
            work=tuple(ScheduledWork(f.work_ref(work_id)) for work_id in work_ids),
        )
        with f.open_writer() as authority:
            f.coordination.open_run(
                authority,
                self.owner.bearer_token,
                f.plan,
                schedule,
                idempotency_key=StableId(run_id + "-open"),
                expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            return f.coordination.read_run(authority, StableId(run_id))

    def _dispatch(self, run, entry, key):
        f = self.f
        with f.open_writer() as authority:
            return f.coordination.dispatch(
                authority,
                self.owner.bearer_token,
                f.plan,
                workspace_id=StableId(key + "-workspace"),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
                work_item=entry.assignment.work_item,
                run=run.run.ref,
                assignment=entry.assignment.ref,
            )

    def _complete(self, dispatched, key):
        f = self.f
        with f.open_writer() as authority:
            _report, candidate = self.acceptance.acceptance.report_candidate(
                authority,
                dispatched.bearer_token,
                dispatched.attempt.ref,
                OutcomeDisposition.COMPLETED,
                idempotency_key=StableId(key + "-report"),
                expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            self.acceptance.acceptance.accept_candidate(
                authority,
                self.owner.bearer_token,
                dispatched.attempt.ref,
                candidate,
                idempotency_key=StableId(key + "-accept"),
                expected_revision=f.revision(),
            )

    def _snapshot(self):
        f = self.f
        with f.open_reader() as authority:
            return f.dispatcher.logical_fingerprint(authority), f.revision()

    def test_completed_run_can_close_and_retains_its_exact_schedule(self):
        f = self.f
        run = self._open_run("r03-close-completed", ("prerequisite",))
        entry = run.entries[0]
        dispatched = self._dispatch(run, entry, "r03-close-dispatch")
        self._complete(dispatched, "r03-close-outcome")

        with f.open_reader() as authority:
            reviewed = self.lifecycle.read_lifecycle(authority, run.run.ref)
        with f.open_writer() as authority:
            result = self.lifecycle.close_run(
                authority,
                self.owner.bearer_token,
                run.run.ref,
                schedule_digest=reviewed.schedule_digest,
                idempotency_key=StableId("r03-close-run"),
                expected_revision=f.revision(),
            )

        with f.open_reader() as authority:
            closed = self.lifecycle.read_lifecycle(authority, run.run.ref)
        self.assertEqual(result.receipt.result["state"], "closed")
        self.assertEqual(closed.event_kind, "todo.run.closed")
        self.assertEqual(closed.schedule.entries, run.entries)
        self.assertEqual(closed.schedule.lanes, run.lanes)
        self.assertEqual(closed.schedule_digest, reviewed.schedule_digest)

    def test_retirement_handoff_requires_both_actions_and_replays_only_exact_request(self):
        f = self.f
        source = self._open_run("r03-handoff-source", ("prerequisite",))
        successor = self._open_run("r03-handoff-successor", ("prerequisite", "verify"))
        source_assignment = source.entries[0].assignment.ref
        successor_same_work = next(
            item.assignment.ref for item in successor.entries
            if item.assignment.work_item == source.entries[0].assignment.work_item
        )
        successor_other_work = next(
            item.assignment.ref for item in successor.entries
            if item.assignment.work_item != source.entries[0].assignment.work_item
        )
        handoff = RunAssignmentHandoff(source_assignment, successor_same_work)
        with f.open_reader() as authority:
            reviewed = self.lifecycle.read_lifecycle(authority, source.run.ref)

        # Source retirement authorization alone cannot authorize the successor
        # assignment. The inverse grant cannot authorize the source transition.
        source_only = self._delegate(
            "worker-verify", (RUN_RETIRE_ACTION,), "r03-retire-source-only",
            scope=source.run.ref, run=source.run.ref,
        )
        successor_only = self._delegate(
            "worker-missing", (RUN_HANDOFF_ACTION,), "r03-handoff-successor-only",
            scope=successor.run.ref, run=successor.run.ref, assignment=successor_same_work,
        )
        snapshot = self._snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.lifecycle.retire_run(
                    authority,
                    source_only.bearer_token,
                    source.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=StableId("r03-source-without-successor"),
                    expected_revision=f.revision(),
                    successor_run=successor.run.ref,
                    handoffs=(handoff,),
                )
        self.assertEqual(self._snapshot(), snapshot)
        with f.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.lifecycle.retire_run(
                    authority,
                    successor_only.bearer_token,
                    source.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=StableId("r03-successor-without-source"),
                    expected_revision=f.revision(),
                    successor_run=successor.run.ref,
                    handoffs=(handoff,),
                )
        self.assertEqual(self._snapshot(), snapshot)

        operator = self._delegate(
            "worker-other",
            (RUN_RETIRE_ACTION, RUN_HANDOFF_ACTION),
            "r03-lifecycle-handoff-operator",
        )
        operation_revision = f.revision()
        operation_key = StableId("r03-retire-with-handoff")
        with f.open_writer() as authority:
            result = self.lifecycle.retire_run(
                authority,
                operator.bearer_token,
                source.run.ref,
                schedule_digest=reviewed.schedule_digest,
                idempotency_key=operation_key,
                expected_revision=operation_revision,
                successor_run=successor.run.ref,
                handoffs=(handoff,),
            )
        self.assertEqual(result.receipt.actor, operator.capability.actor)

        after_retirement = self._snapshot()
        with f.open_writer() as authority:
            replay = self.lifecycle.retire_run(
                authority,
                operator.bearer_token,
                source.run.ref,
                schedule_digest=reviewed.schedule_digest,
                idempotency_key=operation_key,
                expected_revision=operation_revision,
                successor_run=successor.run.ref,
                handoffs=(handoff,),
            )
        self.assertTrue(replay.replayed)
        self.assertEqual(self._snapshot(), after_retirement)

        altered_handoff = RunAssignmentHandoff(source_assignment, successor_other_work)
        with f.open_writer() as authority:
            with self.assertRaises(IdempotencyConflictError):
                self.lifecycle.retire_run(
                    authority,
                    operator.bearer_token,
                    source.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=operation_key,
                    expected_revision=operation_revision,
                    successor_run=successor.run.ref,
                    handoffs=(altered_handoff,),
                )
        self.assertEqual(self._snapshot(), after_retirement)

        with f.open_reader() as authority:
            retired = self.lifecycle.read_lifecycle(authority, source.run.ref)
        self.assertEqual(retired.event_kind, "todo.run.retired")
        self.assertEqual(retired.successor_run, successor.run.ref)
        self.assertEqual(retired.handoffs, (handoff,))
        self.assertEqual(retired.schedule.entries, source.entries)

        with f.open_writer() as authority:
            f.auth.revoke_family(
                authority,
                self.owner.bearer_token,
                operator.capability.capability_id,
                idempotency_key=StableId("r03-revoke-handoff-operator"),
                expected_revision=f.revision(),
            )
        after_revocation = self._snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.lifecycle.retire_run(
                    authority,
                    operator.bearer_token,
                    source.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=operation_key,
                    expected_revision=operation_revision,
                    successor_run=successor.run.ref,
                    handoffs=(handoff,),
                )
        self.assertEqual(self._snapshot(), after_revocation)


if __name__ == "__main__":
    unittest.main()
