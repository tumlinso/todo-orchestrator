"""Terminal run state remains authoritative across dispatch and command replay."""

import unittest
from unittest.mock import patch

from tests.coordination import test_dispatch_independent as fixture_module
from todo_orchestrator.authority import AuthorityError
from todo_orchestrator.contracts import RunState, Sha256Digest, StableId
from todo_orchestrator.operations.lifecycle import (
    RUN_RETIRE_ACTION, RunLifecycleService, UnresolvedRunAssignment,
)
from todo_orchestrator.coordination.store import canonical_schedule_json, schedule_digest
from todo_orchestrator.model import RunSchedule


class LifecycleRunBoundaryTests(unittest.TestCase):
    def test_retirement_cannot_be_undone_by_dispatch_resume_or_open_replay(self):
        fixture = fixture_module.IndependentDispatchTests()
        with patch.object(fixture_module, "OWNER_ACTIONS", (*fixture_module.OWNER_ACTIONS, RUN_RETIRE_ACTION)):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        lifecycle = RunLifecycleService(fixture.auth)
        run_id = StableId("terminal-run-boundary")
        schedule = RunSchedule(run_id, fixture.plan.revision.ref)
        opening_revision = fixture.revision()
        opening_key = StableId("terminal-run-open")
        with fixture.open_writer() as authority:
            fixture.coordination.open_run(
                authority, fixture.owner.bearer_token, fixture.plan, schedule,
                idempotency_key=opening_key, expected_revision=opening_revision,
            )
        with fixture.open_reader() as authority:
            run = fixture.coordination.read_run(authority, run_id)
        selected = fixture.dispatch("terminal-run-dispatch", run=run.run.ref)
        with fixture.open_writer() as authority:
            fixture.coordination.finish(
                authority, selected.bearer_token, selected.attempt.ref,
                selected.attempt.lease.lease_id,
                idempotency_key=StableId("terminal-run-release"),
            )
        outcomes = fixture.outcome_snapshot()
        digest = Sha256Digest(schedule_digest(canonical_schedule_json(run)))
        with fixture.open_writer() as authority:
            lifecycle.retire_run(
                authority, fixture.owner.bearer_token, run.run.ref,
                schedule_digest=digest, idempotency_key=StableId("terminal-run-retire"),
                expected_revision=fixture.revision(),
                unresolved=tuple(UnresolvedRunAssignment(
                    entry.assignment.ref, "Explicitly retained for later operator scheduling",
                ) for entry in run.entries),
            )
        before = fixture.state_snapshot()
        with self.assertRaises(AuthorityError):
            fixture.dispatch("terminal-run-redispatch", run=run.run.ref)
        self.assertEqual(fixture.state_snapshot(), before)
        with fixture.open_writer() as authority:
            with self.assertRaises(AuthorityError):
                fixture.coordination.resume(
                    authority, selected.bearer_token, fixture.plan, selected.attempt.ref,
                    selected.attempt.lease.lease_id,
                    idempotency_key=StableId("terminal-run-old-resume"),
                )
        self.assertEqual(fixture.state_snapshot(), before)
        with fixture.open_writer() as authority:
            replay = fixture.coordination.open_run(
                authority, fixture.owner.bearer_token, fixture.plan, schedule,
                idempotency_key=opening_key, expected_revision=opening_revision,
            )
        self.assertTrue(replay.replayed)
        self.assertEqual(fixture.state_snapshot(), before)
        self.assertEqual(fixture.outcome_snapshot(), outcomes)
        with fixture.open_reader() as authority:
            terminal = fixture.coordination.read_run(authority, run_id)
        self.assertEqual(terminal.run.state, RunState.RETIRED)
        self.assertEqual(terminal.entries, run.entries)
