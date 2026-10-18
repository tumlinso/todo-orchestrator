"""Integration checks for persisted run queues and shared claim admission."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AttemptService,
    AuthorityAuthService,
    CommandDispatcher,
    SQLiteAuthority,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.contracts import (
    ActorKind,
    AttemptState,
    EntityKind,
    EntityRef,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.contracts.providers import ProviderIdentity, ProviderReceipt
from todo_orchestrator.coordination import (
    CoordinationError,
    CoordinationService,
    IsolationPolicy,
    LaneSpec,
    QueuePolicy,
    RUN_SCHEDULE_ACTION,
    RunCharter,
    RunSchedule,
    ScheduledWork,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceIsolation,
    WorkspaceQualification,
)
from todo_orchestrator.model.eligibility import EligibilityRequest, EligibilityStatus
from todo_orchestrator.planning import PlanService, compile_plan_json


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("coord-project"), StableId("coord-authority"))
OWNER_PASSWORD = "coordination fixture owner password 538"
PLAN_COMMIT = StableId("todo.plan.commit")
CLAIM_ACTION = StableId("todo.attempt.claim")
HEARTBEAT_ACTION = StableId("todo.attempt.heartbeat")
RELEASE_ACTION = StableId("todo.attempt.release")
FINISH_ACTION = StableId("todo.attempt.finish")
DISPATCH_ACTION = StableId("todo.run.dispatch")
RECONCILE_ACTION = StableId("todo.attempt.reconcile_expired")
CAPABILITY_DELEGATE = StableId("todo.capability.delegate")
CAPABILITY_REVOKE = StableId("todo.capability.revoke")


class MutableClock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class FakeHost:
    def __init__(self):
        self.calls = 0
        self.now = lambda: NOW
        self.workspace_isolations = {}

    def qualify_workspace(self, workspace_id, target, correlation_id):
        self.calls += 1
        provider = ProviderIdentity(StableId("coord-host"), "1")
        base = QualifiedSourceRevision(PROJECT.project_id, StableId("coord-repo"), StableId("base"), "a" * 64)
        receipt = ProviderReceipt(
            StableId(f"coord-receipt-{self.calls}"), provider, correlation_id,
            Sha256Digest("b" * 64), base.ref, self.now(),
        )
        return WorkspaceQualification(
            workspace_id, StableId("coord-repo"), base,
            QualifiedDestination(PROJECT.project_id, StableId("coord-repo"), StableId("main")),
            receipt, self.workspace_isolations.get(workspace_id),
        )

    def inspect_attempt(self, attempt, workspace):
        self.calls += 1
        assert attempt.lease is not None
        receipt = ProviderReceipt(
            StableId(f"coord-receipt-{self.calls}"), ProviderIdentity(StableId("coord-host"), "1"),
            attempt.attempt_id, Sha256Digest("c" * 64), workspace.common_base.ref, self.now(),
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


def package_document(work_ids=("alpha",), *, shared_scope=False):
    paths = ("src/shared", "src/shared") if shared_scope else tuple(f"src/{name}" for name in work_ids)
    work_items = []
    for work_id, path in zip(work_ids, paths):
        work_items.append({
            "id": work_id,
            "title": f"Work {work_id}",
            "objective": f"Deliver {work_id}",
            "outcome": f"{work_id} is ready",
            "scope": {"paths": [{"path": path, "access": "write"}], "concepts": [], "locks": []},
            "acceptance": {"assertions": ["ready"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
        })
    return json.dumps({
        "format": "todo-orchestrator.plan", "schema_version": 1,
        "package_id": "coordination-fixture",
        "project": {"project_id": str(PROJECT.project_id), "authority_id": str(PROJECT.authority_id)},
        "work_items": work_items,
    }, sort_keys=True)


def synthetic_workspace_isolation(workspace_id):
    encoded = str(workspace_id).encode("utf-8")

    def identity(label):
        return Sha256Digest(hashlib.sha256(label.encode("ascii") + b"\0" + encoded).hexdigest())

    return WorkspaceIsolation(
        Sha256Digest("d" * 64), identity("root"), identity("index"),
        StableId("refs/heads/synthetic/" + str(workspace_id)), identity("admin"),
    )


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = MutableClock()
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(self.dispatcher, clock=self.clock)
        with self.open_writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="owner", idempotency_key=StableId("coord-enroll"),
                expected_revision=0,
            )
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD,
                actions=(PLAN_COMMIT, RUN_SCHEDULE_ACTION, DISPATCH_ACTION, CLAIM_ACTION, HEARTBEAT_ACTION,
                         RELEASE_ACTION, FINISH_ACTION, RECONCILE_ACTION, CAPABILITY_DELEGATE, CAPABILITY_REVOKE),
                scope=PROJECT.ref, expires_at=NOW + timedelta(days=1),
                idempotency_key=StableId("coord-owner-token"),
                expected_revision=enrollment.receipt.semantic_revision,
            )
        self.plans = PlanService(self.auth)
        self.host = FakeHost()
        self.host.now = self.clock
        self.attempts = AttemptService(self.auth, host=self.host, clock=self.clock)
        self.coordination = CoordinationService(self.auth, attempts=self.attempts)
        self.plan = None

    def open_writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def open_reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    def accept_plan(self, work_ids=("alpha",), *, shared_scope=False):
        package_json = package_document(work_ids, shared_scope=shared_scope)
        parsed = compile_plan_json(package_json, PROJECT)
        self.assertTrue(parsed.ok, parsed.diagnostics)
        with self.open_writer() as authority:
            preview = self.plans.preview(authority, package_json)
            self.plans.commit(
                authority, self.owner.bearer_token, package_json,
                reviewed_digest=preview.digest, idempotency_key=StableId("coord-plan-" + str(len(work_ids))),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            self.plan = self.plans.load_accepted_plan(authority)
        return self.plan

    @staticmethod
    def ref(plan, work_id):
        return next(item.definition.ref for item in plan.work_items
                    if item.definition.work_item_id == StableId(work_id))

    def revision(self):
        with self.open_reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def open_schedule(self, plan, schedule, key="coord-run", expected_revision=None):
        with self.open_writer() as authority:
            return self.coordination.open_run(
                authority, self.owner.bearer_token, plan, schedule,
                idempotency_key=StableId(key),
                expected_revision=self.revision() if expected_revision is None else expected_revision,
            )

    def claim(self, plan, entry, *, key, workspace="workspace"):
        with self.open_writer() as authority:
            return self.attempts.claim(
                authority, self.owner.bearer_token, entry.assignment.work_item, plan,
                idempotency_key=StableId(key), expected_revision=self.revision(),
                workspace_id=StableId(workspace), run=entry.assignment.run,
                assignment=entry.assignment.ref,
            )

    def test_default_lane_roundtrip_is_claimable_and_exact_retry_is_stable(self):
        plan = self.accept_plan()
        schedule = RunSchedule(StableId("simple-run"), plan.revision.ref)
        initial_revision = self.revision()
        first = self.open_schedule(plan, schedule, "simple-run-create", initial_revision)
        self.assertTrue(first.receipt.changed)
        with self.open_reader() as authority:
            view = self.coordination.read_run(authority, StableId("simple-run"))
        self.assertEqual(len(view.lanes), 1)
        self.assertEqual(view.lanes[0].lane_id, StableId("default"))
        self.assertIs(view.lanes[0].queue_policy, QueuePolicy.SERIAL)
        self.assertEqual(len(view.entries), 1)
        entry = view.entries[0]
        self.assertEqual(entry.assignment.work_item, self.ref(plan, "alpha"))
        self.assertEqual(entry.assignment.run, view.run.ref)
        self.assertEqual(entry.queue_position, 0)

        before_revision = self.revision()
        replay = self.open_schedule(plan, schedule, "simple-run-create", initial_revision)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, first.receipt)
        self.assertEqual(self.revision(), before_revision)

        second_key_noop = self.open_schedule(plan, schedule, "simple-run-second-key")
        self.assertFalse(second_key_noop.receipt.changed)
        self.assertEqual(second_key_noop.receipt.event_id, None)
        self.assertEqual(self.revision(), before_revision)
        claimed = self.claim(plan, entry, key="simple-run-claim")
        self.assertEqual(claimed.receipt.result["state"], AttemptState.ADMITTED.value)

    def test_closed_historical_queue_does_not_force_run_assignment(self):
        plan = self.accept_plan()
        schedule = RunSchedule(StableId("closed-run"), plan.revision.ref)
        self.open_schedule(plan, schedule, "closed-run-create")
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute("UPDATE runs SET state = 'closed' WHERE run_id = ?", (str(schedule.run_id),))
        with self.open_writer() as authority:
            claimed = self.attempts.claim(
                authority, self.owner.bearer_token, self.ref(plan, "alpha"), plan,
                idempotency_key=StableId("closed-run-free-claim"), expected_revision=self.revision(),
                workspace_id=StableId("closed-run-workspace"),
            )
        self.assertEqual(claimed.receipt.result["state"], AttemptState.ADMITTED.value)

    def test_serial_queue_requires_exact_assignment_and_reconciled_predecessor_outcome(self):
        plan = self.accept_plan(("alpha", "beta"))
        run = RunSchedule(StableId("serial-run"), plan.revision.ref)
        self.open_schedule(plan, run, "serial-run-create")
        with self.open_reader() as authority:
            view = self.coordination.read_run(authority, run.run_id)
        by_work = {str(entry.assignment.work_item.entity_id): entry for entry in view.entries}

        with self.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError) as bypass:
                self.attempts.claim(
                    authority, self.owner.bearer_token, by_work["alpha"].assignment.work_item, plan,
                    idempotency_key=StableId("serial-bypass"), expected_revision=self.revision(),
                    workspace_id=StableId("bypass-workspace"),
                )
        self.assertIn("scheduled_assignment_required", {cause.code for cause in bypass.exception.decision.causes})

        alpha = by_work["alpha"]
        beta = by_work["beta"]
        first = self.claim(plan, alpha, key="serial-alpha", workspace="serial-alpha-workspace")
        with self.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError) as occupied:
                self.attempts.claim(
                    authority, self.owner.bearer_token, beta.assignment.work_item, plan,
                    idempotency_key=StableId("serial-beta-blocked"), expected_revision=self.revision(),
                    workspace_id=StableId("serial-beta-workspace"), run=beta.assignment.run,
                    assignment=beta.assignment.ref,
                )
        self.assertIn("serial_lane_occupied", {cause.code for cause in occupied.exception.decision.causes})

        attempt_ref = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, StableId(first.receipt.result["attempt_id"]))
        with self.open_writer() as authority:
            self.attempts.release(
                authority, self.owner.bearer_token, attempt_ref,
                StableId(first.receipt.result["lease_id"]), idempotency_key=StableId("serial-alpha-release"),
                expected_revision=self.revision(),
            )
        outcome_actor = self.owner.capability.actor
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, disposition, "
                    "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at, attempt_id) "
                    "VALUES (?, ?, ?, 1, 'completed', ?, ?, ?, ?)",
                    ("serial-alpha-outcome", str(alpha.assignment.work_item.entity_id),
                     str(alpha.assignment.work_item.definition_revision_id), str(outcome_actor.entity_id),
                     str(outcome_actor.incarnation_id), NOW.isoformat(), str(attempt_ref.entity_id)),
                )
        later = self.claim(plan, beta, key="serial-beta-after-outcome", workspace="serial-beta-workspace")
        self.assertEqual(later.receipt.result["state"], AttemptState.ADMITTED.value)

    def test_role_is_a_required_grant_action_not_an_actor_label(self):
        plan = self.accept_plan()
        role = StableId("todo.role.builder")
        schedule = RunSchedule(
            StableId("role-run"), plan.revision.ref,
            (LaneSpec(StableId("builders"), required_role=role),),
        )
        self.open_schedule(plan, schedule, "role-run-create")
        with self.open_reader() as authority:
            entry = self.coordination.read_run(authority, schedule.run_id).entries[0]
        with self.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError) as denied:
                self.attempts.claim(
                    authority, self.owner.bearer_token, entry.assignment.work_item, plan,
                    idempotency_key=StableId("role-missing-action"), expected_revision=self.revision(),
                    workspace_id=StableId("role-workspace"), run=entry.assignment.run,
                    assignment=entry.assignment.ref,
                )
        self.assertIn("lane_role_action_missing", {cause.code for cause in denied.exception.decision.causes})

        with self.open_writer() as authority:
            role_grant = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=(CLAIM_ACTION, role), scope=PROJECT.ref,
                run=entry.assignment.run, assignment=entry.assignment.ref,
                expires_at=NOW + timedelta(hours=1), idempotency_key=StableId("builder-role-grant"),
                expected_revision=self.revision(),
            )
        with self.open_writer() as authority:
            granted = self.attempts.claim(
                authority, role_grant.bearer_token, entry.assignment.work_item, plan,
                idempotency_key=StableId("role-with-action"), expected_revision=self.revision(),
                workspace_id=StableId("role-workspace"), run=entry.assignment.run,
                assignment=entry.assignment.ref,
            )
        self.assertEqual(granted.receipt.result["state"], AttemptState.ADMITTED.value)

    def test_parallel_lane_labels_do_not_override_overlapping_scope_admission(self):
        self.host.workspace_isolations.update({
            StableId(workspace): synthetic_workspace_isolation(workspace)
            for workspace in ("shared-workspace", "separate-workspace")
        })
        plan = self.accept_plan(("alpha", "beta"), shared_scope=True)
        charter = RunCharter("Deliver both work items", ("Do not edit generated state",), ("Both results are accepted",))
        schedule = RunSchedule(
            StableId("parallel-run"), plan.revision.ref,
            (
                LaneSpec(StableId("lane-a"), QueuePolicy.PARALLEL),
                LaneSpec(StableId("lane-b"), QueuePolicy.PARALLEL),
            ),
            (
                ScheduledWork(self.ref(plan, "alpha"), StableId("lane-a")),
                ScheduledWork(self.ref(plan, "beta"), StableId("lane-b")),
            ),
            charter,
        )
        self.open_schedule(plan, schedule, "parallel-run-create")
        with self.open_reader() as authority:
            view = self.coordination.read_run(authority, schedule.run_id)
        self.assertEqual([str(entry.assignment.work_item.entity_id) for entry in view.entries], ["alpha", "beta"])
        first, second = view.entries
        self.claim(plan, first, key="parallel-first", workspace="shared-workspace")
        with self.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError) as denied:
                self.attempts.claim(
                    authority, self.owner.bearer_token, second.assignment.work_item, plan,
                    idempotency_key=StableId("parallel-same-workspace"), expected_revision=self.revision(),
                    workspace_id=StableId("shared-workspace"), run=second.assignment.run,
                    assignment=second.assignment.ref,
                )
        self.assertIn("unsafe_source_overlap", {cause.code for cause in denied.exception.decision.causes})

        separated = self.claim(plan, second, key="parallel-qualified-workspace", workspace="separate-workspace")
        self.assertEqual(separated.receipt.result["state"], AttemptState.ADMITTED.value)

    def test_qualified_workspace_lane_is_unknown_without_candidate_provider_fact(self):
        plan = self.accept_plan()
        schedule = RunSchedule(
            StableId("qualified-run"), plan.revision.ref,
            (LaneSpec(StableId("isolated"), isolation_policy=IsolationPolicy.QUALIFIED_WORKSPACES),),
        )
        self.open_schedule(plan, schedule, "qualified-run-create")
        with self.open_reader() as authority:
            entry = self.coordination.read_run(authority, schedule.run_id).entries[0]
            request = EligibilityRequest(
                entry.assignment.work_item, self.owner.capability.actor, CLAIM_ACTION, self.revision(),
                run=entry.assignment.run, assignment=entry.assignment.ref,
            )
            decision = self.attempts.eligibility.evaluate_read(authority, request, plan)
        self.assertIs(decision.status, EligibilityStatus.UNKNOWN)
        self.assertIn("lane_candidate_workspace_unqualified", {cause.code for cause in decision.causes})
        claimed = self.claim(plan, entry, key="qualified-run-claim", workspace="qualified-candidate")
        self.assertEqual(claimed.receipt.result["state"], AttemptState.ADMITTED.value)

    def test_dispatched_bearer_renews_its_bounded_lease_and_finish_revokes_it(self):
        plan = self.accept_plan()
        target = self.ref(plan, "alpha")
        with self.open_writer() as authority:
            dispatched = self.coordination.dispatch(
                authority, self.owner.bearer_token, plan,
                workspace_id=StableId("dispatch-renewal-workspace"),
                work_item=target, idempotency_key=StableId("dispatch-renewal"),
                expected_revision=self.revision(),
            )
        self.assertIsNone(dispatched.attempt.run)
        self.assertIsNone(dispatched.attempt.assignment)
        original_expiry = dispatched.capability.expires_at
        self.clock.now += timedelta(minutes=1)
        with self.open_writer() as authority:
            resumed = self.coordination.resume(
                authority, dispatched.bearer_token, plan, dispatched.attempt.ref,
                dispatched.attempt.lease.lease_id,
                idempotency_key=StableId("dispatch-renewal-heartbeat-1"),
                expected_revision=self.revision(), work_item=target,
            )
        renewed_lease = StableId(resumed.receipt.result["lease_id"])
        self.assertGreater(
            datetime.fromisoformat(resumed.receipt.result["lease_expires_at"]), original_expiry,
        )
        with self.open_reader() as authority:
            child_expiry = authority.connection.execute(
                "SELECT expires_at FROM capabilities WHERE capability_id = ?",
                (str(dispatched.capability.capability_id),),
            ).fetchone()[0]
        self.assertEqual(datetime.fromisoformat(child_expiry),
                         datetime.fromisoformat(resumed.receipt.result["lease_expires_at"]))

        self.clock.now += timedelta(minutes=1)
        with self.open_writer() as authority:
            resumed_again = self.coordination.resume(
                authority, dispatched.bearer_token, plan, dispatched.attempt.ref, renewed_lease,
                idempotency_key=StableId("dispatch-renewal-heartbeat-2"),
                expected_revision=self.revision(), work_item=target,
            )
        current_lease = StableId(resumed_again.receipt.result["lease_id"])
        with self.open_writer() as authority:
            finished = self.coordination.finish(
                authority, dispatched.bearer_token, dispatched.attempt.ref, current_lease,
                idempotency_key=StableId("dispatch-renewal-finish"),
                expected_revision=self.revision(),
            )
        self.assertFalse(finished.receipt.result["outcome_accepted"])
        with self.open_reader() as authority:
            attempt_state = authority.connection.execute(
                "SELECT state FROM attempts WHERE attempt_id = ?",
                (str(dispatched.attempt.attempt_id),),
            ).fetchone()[0]
            revoked = authority.connection.execute(
                "SELECT revoked FROM capabilities WHERE capability_id = ?",
                (str(dispatched.capability.capability_id),),
            ).fetchone()[0]
            outcomes = authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0]
        self.assertEqual(attempt_state, AttemptState.RELEASED.value)
        self.assertEqual(revoked, 1)
        self.assertEqual(outcomes, 0)

    def test_resume_refuses_contradictory_target_without_state_change(self):
        plan = self.accept_plan(("alpha", "beta"))
        target = self.ref(plan, "alpha")
        with self.open_writer() as authority:
            dispatched = self.coordination.dispatch(
                authority, self.owner.bearer_token, plan,
                workspace_id=StableId("dispatch-selector-workspace"),
                work_item=target, idempotency_key=StableId("dispatch-selector"),
                expected_revision=self.revision(),
            )
        before = self.revision()
        with self.open_writer() as authority:
            with self.assertRaisesRegex(CoordinationError, "target conflicts"):
                self.coordination.resume(
                    authority, dispatched.bearer_token, plan, dispatched.attempt.ref,
                    dispatched.attempt.lease.lease_id,
                    idempotency_key=StableId("dispatch-selector-mismatch"),
                    expected_revision=before, work_item=self.ref(plan, "beta"),
                )
        self.assertEqual(self.revision(), before)

    def test_wrong_definition_and_stale_schedule_requests_have_no_state_churn(self):
        plan = self.accept_plan()
        wrong_ref = EntityRef(
            PROJECT.project_id, EntityKind.WORK_ITEM, StableId("alpha"),
            definition_revision_id=StableId("not-the-accepted-definition"),
        )
        schedule = RunSchedule(
            StableId("wrong-definition-run"), plan.revision.ref,
            work=(ScheduledWork(wrong_ref),),
        )
        revision_before = self.revision()
        with self.open_writer() as authority:
            with self.assertRaisesRegex(CoordinationError, "exact definition"):
                self.coordination.open_run(
                    authority, self.owner.bearer_token, plan, schedule,
                    idempotency_key=StableId("wrong-definition-create"), expected_revision=revision_before,
                )
        self.assertEqual(self.revision(), revision_before)
        with self.open_reader() as authority:
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM runs").fetchone()[0], 0)

        valid = RunSchedule(StableId("stale-run"), plan.revision.ref)
        with self.open_writer() as authority:
            with self.assertRaises(StaleAuthorityRevisionError):
                self.coordination.open_run(
                    authority, self.owner.bearer_token, plan, valid,
                    idempotency_key=StableId("stale-run-key"), expected_revision=revision_before - 1,
                )
        self.assertEqual(self.revision(), revision_before)


if __name__ == "__main__":
    unittest.main()
