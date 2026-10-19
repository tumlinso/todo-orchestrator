"""Independent public-flow checks for work lineage and run lifecycle."""

from copy import deepcopy
import json
import unittest
from datetime import timedelta

from todo_orchestrator.contracts import OutcomeDisposition, StableId
from todo_orchestrator.authority.attempts import AttemptTransitionError
from todo_orchestrator.planning import ExplicitRetirement
from todo_orchestrator.model import (
    AttemptScopeSnapshot, LaneSpec, QueuePolicy, RunCharter, RunSchedule, ScheduledWork,
)
from todo_orchestrator.operations.lifecycle import (
    RUN_CLOSE_ACTION, RUN_RETIRE_ACTION, RunDispositionError, RunLifecycleService,
    RunLifecycleStaleError, RunNotQuiescentError, UnresolvedRunAssignment,
)
from todo_orchestrator.coordination.children import ChildExecutionService
from todo_orchestrator.model.children import (
    CHILD_CANDIDATE_SUBMIT_ACTION, CHILD_DELEGATE_ACTION, CHILD_READ_ACTION,
    CHILD_REVIEW_ACTION, CHILD_RETRY_ACTION, CHILD_STOP_RECONCILE_ACTION, CHILD_WRITE_ACTION,
)
from todo_orchestrator.verification.service import VerificationState

from tests.verification import test_acceptance_independent as _acceptance_fixture
from tests.verification.test_execution_independent import PROJECT


class LifecycleIndependentTests(unittest.TestCase):
    """Exercise supersession with durable accepted history in a disposable DB."""

    def setUp(self):
        self.fixture = _acceptance_fixture.IndependentOutcomeAcceptanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture.fixture

    def _package(self):
        f = self.f
        return {
            "format": "todo-orchestrator.plan",
            "schema_version": 1,
            "package_id": "r03-lifecycle-independent",
            "project": {
                "project_id": str(PROJECT.project_id),
                "authority_id": str(PROJECT.authority_id),
            },
            "work_items": [
                {
                    "id": "legacy",
                    "title": "Legacy producer",
                    "objective": "Produce the accepted predecessor result",
                    "outcome": "The predecessor result remains auditable",
                    "scope": {"paths": [], "concepts": ["legacy"]},
                    "acceptance": {
                        "assertions": ["the result is accepted"],
                        "required_evidence": [],
                        "allowed_dispositions": ["completed"],
                    },
                },
                {
                    "id": "consumer",
                    "title": "Downstream consumer",
                    "objective": "Consume the producer result",
                    "outcome": "The dependency names an exact producer definition",
                    "parent_id": "legacy",
                    "requirement_groups": [{
                        "kind": "prerequisite", "mode": "all", "members": ["needs-legacy"],
                    }],
                    "scope": {"paths": [], "concepts": ["consumer"]},
                    "acceptance": {
                        "assertions": ["the dependency remains explicit"],
                        "required_evidence": [],
                        "allowed_dispositions": ["completed"],
                    },
                },
            ],
            "requirements": [{
                "id": "needs-legacy",
                "work_item_id": "consumer",
                "kind": "prerequisite",
                "description": "The producer must be accepted first",
                "target": {
                    "project_id": str(PROJECT.project_id),
                    "kind": "work_item",
                    "entity_id": "legacy",
                },
            }],
        }

    def _commit_plan(self, document, key, *, retirement=None):
        f = self.f
        retirements = () if retirement is None else (
            retirement if isinstance(retirement, tuple) else (retirement,)
        )
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with f.open_writer() as authority:
            preview = f.plans.preview(
                authority,
                encoded,
                explicit_retirements=retirements,
            )
            if preview.conflicts:
                raise AssertionError(f"unexpected plan conflicts: {preview.conflicts}")
            if any(item.severity.value == "error" for item in preview.diagnostics):
                raise AssertionError(
                    f"unexpected plan diagnostics: {preview.diagnostics}; "
                    f"retirements: {retirements}; retire_ops: "
                    f"{tuple((item.entity_kind, item.entity_id, item.before) for item in preview.operations if item.kind.value == 'retire')}"
                )
            result = f.plans.commit(
                authority,
                f.owner.bearer_token,
                encoded,
                reviewed_digest=preview.digest,
                idempotency_key=StableId(key),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
                explicit_retirements=retirements,
            )
            f.plan = f.plans.load_accepted_plan(authority)
        return result

    def test_exact_supersession_retargets_downstream_and_keeps_accepted_history(self):
        f = self.f
        document = self._package()
        self._commit_plan(document, "r03-initial-plan")
        original_plan_id = f.plan.revision.plan_revision_id
        predecessor = f.work_ref("legacy")
        predecessor_requirement = f.requirement_ref("needs-legacy")

        dispatched = self.fixture.dispatch("legacy", "r03-dispatch-predecessor")
        _, candidate = self.fixture.report(
            dispatched.bearer_token,
            dispatched.attempt.ref,
            OutcomeDisposition.COMPLETED,
            "r03-report-predecessor",
        )
        self.fixture.accept(
            f.owner.bearer_token, dispatched.attempt.ref, candidate,
            "r03-accept-predecessor",
        )
        with f.open_reader() as authority:
            outcome = authority.connection.execute(
                "SELECT outcome_id, work_item_id, definition_revision_id "
                "FROM outcomes WHERE work_item_id = 'legacy'"
            ).fetchone()
            provenance_before = authority.connection.execute(
                "SELECT canonical_json, content_digest FROM outcome_provenance WHERE outcome_id = ?",
                (outcome["outcome_id"],),
            ).fetchone()
        self.assertEqual(outcome["definition_revision_id"], str(predecessor.definition_revision_id))
        self.assertIsNotNone(provenance_before)

        replacement = {
            "id": "replacement",
            "title": "Successor producer",
            "objective": "Replace the predecessor without rewriting its record",
            "outcome": "The successor is linked to the exact predecessor definition",
            "supersedes": [{
                "project_id": str(predecessor.project_id),
                "kind": "work_item",
                "entity_id": str(predecessor.entity_id),
                "revision_id": str(predecessor.definition_revision_id),
            }],
            "scope": {"paths": [], "concepts": ["replacement"]},
            "acceptance": {
                "assertions": ["the replacement is explicit"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
        }
        revised = deepcopy(document)
        revised["work_items"] = [replacement, revised["work_items"][1]]
        consumer = revised["work_items"][1]
        consumer["parent_id"] = "replacement"
        consumer["requirement_groups"][0]["members"] = ["needs-replacement"]
        revised["requirements"] = [{
            "id": "needs-replacement",
            "work_item_id": "consumer",
            "kind": "prerequisite",
            "description": "The successor must be accepted first",
            "target": {
                "project_id": str(PROJECT.project_id),
                "kind": "work_item",
                "entity_id": "replacement",
            },
        }]

        before_unresolved_preview = f.state_snapshot()
        with f.open_reader() as authority:
            unresolved_preview = f.plans.preview(
                authority, json.dumps(revised, ensure_ascii=False, sort_keys=True),
                explicit_retirements=(ExplicitRetirement(predecessor),),
            )
        self.assertIn(
            "retired_definition_still_referenced",
            {item.code for item in unresolved_preview.diagnostics},
        )
        self.assertEqual(f.state_snapshot(), before_unresolved_preview)

        committed = self._commit_plan(
            revised, "r03-supersede-predecessor",
            retirement=(ExplicitRetirement(predecessor), ExplicitRetirement(predecessor_requirement)),
        )
        self.assertTrue(committed.receipt.changed)
        successor = f.work_ref("replacement")
        consumer_ref = f.work_ref("consumer")
        accepted = f.plans.load_accepted_plan
        with f.open_reader() as authority:
            current = accepted(authority)
            historical = accepted(authority, original_plan_id)
            history_row = authority.connection.execute(
                "SELECT canonical_json, content_digest FROM outcome_provenance WHERE outcome_id = ?",
                (outcome["outcome_id"],),
            ).fetchone()
            persisted_outcome = authority.connection.execute(
                "SELECT work_item_id, definition_revision_id FROM outcomes WHERE outcome_id = ?",
                (outcome["outcome_id"],),
            ).fetchone()

        self.assertIn(predecessor, {item.definition.ref for item in historical.work_items})
        self.assertNotIn(predecessor, {item.definition.ref for item in current.work_items})
        self.assertNotIn(predecessor_requirement, {item.definition.ref for item in current.requirements})
        successor_item = next(item for item in current.work_items if item.definition.ref == successor)
        self.assertEqual(successor_item.definition.supersedes, (predecessor,))
        consumer_item = next(item for item in current.work_items if item.definition.ref == consumer_ref)
        self.assertEqual(consumer_item.definition.parent, successor)
        retargeted = next(item for item in current.requirements
                          if item.definition.requirement_id == StableId("needs-replacement"))
        self.assertEqual(retargeted.target.reference, successor)
        self.assertEqual((persisted_outcome["work_item_id"], persisted_outcome["definition_revision_id"]),
                         (str(predecessor.entity_id), str(predecessor.definition_revision_id)))
        self.assertEqual((history_row["canonical_json"], history_row["content_digest"]),
                         (provenance_before["canonical_json"], provenance_before["content_digest"]))

    def test_active_native_child_blocks_run_retirement_without_authority_churn(self):
        f = self.f
        child_actions = (
            CHILD_DELEGATE_ACTION, CHILD_RETRY_ACTION, CHILD_REVIEW_ACTION,
            CHILD_STOP_RECONCILE_ACTION, CHILD_READ_ACTION, CHILD_WRITE_ACTION,
            CHILD_CANDIDATE_SUBMIT_ACTION,
        )
        with f.open_writer() as authority:
            owner = f.auth.login_local_owner(
                authority,
                _acceptance_fixture.OWNER_PASSWORD,
                actions=tuple(dict.fromkeys((*_acceptance_fixture.REPORT_ACTIONS,
                                             StableId("todo.run.schedule"), RUN_RETIRE_ACTION,
                                             *child_actions))),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId("r03-lifecycle-owner"),
                expected_revision=f.revision(),
            )
        run_id = StableId("r03-child-run")
        parallel_lane = StableId("r03-parallel")
        schedule = RunSchedule(
            run_id, f.plan.revision.ref,
            lanes=(LaneSpec(parallel_lane, QueuePolicy.PARALLEL),),
            work=tuple(ScheduledWork(item.definition.ref, parallel_lane, owner.capability.actor)
                       for item in f.plan.work_items),
            charter=RunCharter(
                "Exercise run retirement safety",
                ("Keep the assignment bindings exact",),
                ("Retirement leaves unresolved work explicit",),
            ),
        )
        with f.open_writer() as authority:
            f.coordination.open_run(
                authority, owner.bearer_token, f.plan, schedule,
                idempotency_key=StableId("r03-child-run-open"), expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            run = f.coordination.read_run(authority, run_id)
        entry = next(item for item in run.entries if item.assignment.work_item == f.work_ref("verify"))
        with f.open_writer() as authority:
            dispatched = f.coordination.dispatch(
                authority, owner.bearer_token, f.plan,
                workspace_id=StableId("r03-child-parent-workspace"),
                idempotency_key=StableId("r03-child-parent-dispatch"),
                expected_revision=f.revision(), work_item=entry.assignment.work_item,
                run=run.run.ref, assignment=entry.assignment.ref,
            )
        children = ChildExecutionService(f.auth, attempts=f.attempts)
        child_scope = AttemptScopeSnapshot((("src/verify/nested", "write"),), ())
        with f.open_writer() as authority:
            children.start_child(
                authority, dispatched.bearer_token, dispatched.attempt.ref, "worker-other",
                execution_id=StableId("r03-live-child"), logical_id=StableId("r03-live-child-logical"),
                scope=child_scope,
                actions=(CHILD_READ_ACTION, CHILD_WRITE_ACTION, CHILD_CANDIDATE_SUBMIT_ACTION),
                idempotency_key=StableId("r03-live-child-start"), expected_revision=f.revision(),
            )

        lifecycle = RunLifecycleService(f.auth)
        with f.open_reader() as authority:
            reviewed = lifecycle.read_lifecycle(authority, run.run.ref)
        unresolved = tuple(UnresolvedRunAssignment(
            item.assignment.ref, "Retain unfinished work pending safe successor scheduling",
        ) for item in run.entries)
        before = self._authority_snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(RunNotQuiescentError):
                lifecycle.retire_run(
                    authority, owner.bearer_token, run.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=StableId("r03-retire-with-live-child"),
                    expected_revision=f.revision(), unresolved=unresolved,
                )
        self.assertEqual(self._authority_snapshot(), before)

    def test_close_requires_completed_assignments_and_retirement_requires_fresh_digest(self):
        f = self.f
        with f.open_writer() as authority:
            owner = f.auth.login_local_owner(
                authority,
                _acceptance_fixture.OWNER_PASSWORD,
                actions=tuple(dict.fromkeys((*_acceptance_fixture.REPORT_ACTIONS,
                                             StableId("todo.run.schedule"),
                                             RUN_CLOSE_ACTION, RUN_RETIRE_ACTION))),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId("r03-disposition-owner"),
                expected_revision=f.revision(),
            )
        run_id = StableId("r03-disposition-run")
        with f.open_writer() as authority:
            f.coordination.open_run(
                authority, owner.bearer_token, f.plan,
                RunSchedule(run_id, f.plan.revision.ref),
                idempotency_key=StableId("r03-disposition-open"), expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            run = f.coordination.read_run(authority, run_id)
        lifecycle = RunLifecycleService(f.auth)
        with f.open_reader() as authority:
            reviewed = lifecycle.read_lifecycle(authority, run.run.ref)
        before = self._authority_snapshot(run_id)
        with f.open_writer() as authority:
            with self.assertRaises(RunLifecycleStaleError):
                lifecycle.retire_run(
                    authority, owner.bearer_token, run.run.ref,
                    schedule_digest=type(reviewed.schedule_digest)("0" * 64),
                    idempotency_key=StableId("r03-stale-schedule-retire"),
                    expected_revision=f.revision(),
                    unresolved=tuple(UnresolvedRunAssignment(
                        entry.assignment.ref, "Explicitly retained for later scheduling",
                    ) for entry in run.entries),
                )
        self.assertEqual(self._authority_snapshot(run_id), before)
        with f.open_writer() as authority:
            with self.assertRaises(RunDispositionError):
                lifecycle.close_run(
                    authority, owner.bearer_token, run.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=StableId("r03-close-incomplete-run"),
                    expected_revision=f.revision(),
                )
        self.assertEqual(self._authority_snapshot(run_id), before)

        unresolved = tuple(UnresolvedRunAssignment(
            entry.assignment.ref, "Explicitly retained for later scheduling",
        ) for entry in run.entries)
        with f.open_writer() as authority:
            lifecycle.retire_run(
                authority, owner.bearer_token, run.run.ref,
                schedule_digest=reviewed.schedule_digest,
                idempotency_key=StableId("r03-retire-unresolved-run"),
                expected_revision=f.revision(), unresolved=unresolved,
            )
        with f.open_reader() as authority:
            retired = lifecycle.read_lifecycle(authority, run.run.ref)
        self.assertEqual(retired.event_kind, "todo.run.retired")
        self.assertEqual(retired.unresolved, unresolved)
        self.assertEqual(retired.schedule.entries, run.entries)
        self.assertEqual(retired.schedule.lanes, run.lanes)
        self.assertEqual(retired.schedule_digest, reviewed.schedule_digest)

    def test_unresolved_verification_effect_blocks_attempt_release_and_run_retirement(self):
        f = self.f
        with f.open_writer() as authority:
            owner = f.auth.login_local_owner(
                authority,
                _acceptance_fixture.OWNER_PASSWORD,
                actions=tuple(dict.fromkeys((*_acceptance_fixture.REPORT_ACTIONS,
                                             StableId("todo.run.schedule"), RUN_RETIRE_ACTION))),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId("r03-effect-owner"),
                expected_revision=f.revision(),
            )
        run_id = StableId("r03-effect-run")
        target = f.work_ref("verify")
        schedule = RunSchedule(
            run_id, f.plan.revision.ref,
            work=(ScheduledWork(target),),
        )
        with f.open_writer() as authority:
            f.coordination.open_run(
                authority, owner.bearer_token, f.plan, schedule,
                idempotency_key=StableId("r03-effect-run-open"), expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            run = f.coordination.read_run(authority, run_id)
        assignment = run.entries[0].assignment.ref
        with f.open_writer() as authority:
            dispatched = f.coordination.dispatch(
                authority, owner.bearer_token, f.plan,
                workspace_id=StableId("r03-effect-workspace"),
                idempotency_key=StableId("r03-effect-dispatch"),
                expected_revision=f.revision(), work_item=target,
                run=run.run.ref, assignment=assignment,
            )
        f.verification.provider.raise_after_effect = True
        with f.open_writer() as authority:
            interrupted = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("r03-interrupted-verification"),
                expected_revision=f.revision(),
            )
        self.assertEqual(interrupted.state, VerificationState.UNKNOWN)
        lease_id = dispatched.attempt.lease.lease_id
        before = self._authority_snapshot(run_id)
        with f.open_writer() as authority:
            with self.assertRaises(AttemptTransitionError):
                f.attempts.release(
                    authority, dispatched.bearer_token, dispatched.attempt.ref, lease_id,
                    idempotency_key=StableId("r03-release-after-interrupted-check"),
                    expected_revision=f.revision(),
                )

        lifecycle = RunLifecycleService(f.auth)
        with f.open_reader() as authority:
            reviewed = lifecycle.read_lifecycle(authority, run.run.ref)
        with f.open_writer() as authority:
            with self.assertRaises(RunNotQuiescentError):
                lifecycle.retire_run(
                    authority, owner.bearer_token, run.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=StableId("r03-retire-pending-effect"),
                    expected_revision=f.revision(),
                    unresolved=(UnresolvedRunAssignment(
                        assignment, "Verification effect still needs recovery",
                    ),),
                )
        self.assertEqual(self._authority_snapshot(run_id), before)

    def _authority_snapshot(self, run_id=StableId("r03-child-run")):
        f = self.f
        with f.open_reader() as authority:
            return (
                f.dispatcher.logical_fingerprint(authority),
                f.revision(),
                authority.connection.execute("SELECT state FROM runs WHERE run_id = ?",
                                             (str(run_id),)).fetchone()[0],
                authority.connection.execute("SELECT count(*) FROM authority_events").fetchone()[0],
            )


if __name__ == "__main__":
    unittest.main()
