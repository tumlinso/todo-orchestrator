"""Independent end-to-end checks for optional run and lane scheduling."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AuthorityAuthService,
    AuthorityError,
    CommandDispatcher,
    EligibilityAdapter,
    SQLiteAuthority,
)
from todo_orchestrator.authority.attempts import AttemptService, CLAIM_ACTION
from todo_orchestrator.contracts import (
    EntityKind,
    EntityRef,
    Project,
    ProviderIdentity,
    ProviderReceipt,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.coordination import CoordinationService
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    IsolationPolicy,
    LaneSpec,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    QueuePolicy,
    RunCharter,
    RunSchedule,
    ScheduledWork,
    SourceSafety,
    WorkspaceIsolation,
    WorkspaceQualification,
)
from todo_orchestrator.planning import PlanService


NOW = datetime(2026, 10, 18, 18, 0, tzinfo=timezone.utc)
PROJECT = Project(StableId("coordination-independent-project"), StableId("coordination-independent-authority"))
OWNER_PASSWORD = "coordination independent owner credential 927"
PLAN_ACTION = StableId("todo.plan.commit")
SCHEDULE_ACTION = StableId("todo.run.schedule")
ROLE_BUILD = StableId("todo.role.builder")
ROLE_REVIEW = StableId("todo.role.reviewer")
REPOSITORY = StableId("coordination-independent-repository")
CLAIM_ACTIONS = (CLAIM_ACTION,)
OWNER_ACTIONS = (
    PLAN_ACTION, SCHEDULE_ACTION, CLAIM_ACTION, ROLE_BUILD, ROLE_REVIEW,
    StableId("todo.attempt.heartbeat"), StableId("todo.attempt.release"),
    StableId("todo.attempt.reconcile_expired"), StableId("todo.capability.delegate"),
    StableId("todo.capability.revoke"),
)
WORKER_ACTIONS = (CLAIM_ACTION, ROLE_REVIEW)


def plan_json(project: Project = PROJECT) -> str:
    """A small accepted-plan candidate with overlapping and disjoint scopes."""
    work = (
        ("work-gamma", "docs/guide.md"),
        ("work-delta", "assets/report.json"),
        ("work-beta", "src/pkg/sub"),
        ("work-alpha", "src/pkg"),
    )
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "coordination-independent-plan",
        "project": {"project_id": str(project.project_id), "authority_id": str(project.authority_id)},
        "work_items": [
            {
                "id": item_id,
                "title": item_id,
                "objective": "Exercise run scheduling without an external agent scheduler",
                "outcome": "The selected work item has a stable assignment",
                "scope": {"paths": [{"path": path, "access": "write"}], "concepts": [], "locks": []},
                "ownership": {"mode": "any", "actors": []},
                "acceptance": {
                    "assertions": ["assignment is exact"],
                    "required_evidence": [],
                    "allowed_dispositions": ["completed"],
                },
            }
            for item_id, path in work
        ],
    }
    return json.dumps(document)


class FixedClock:
    def __call__(self):
        return NOW


def synthetic_workspace_isolation(workspace_id):
    encoded = str(workspace_id).encode("utf-8")

    def identity(label):
        return Sha256Digest(hashlib.sha256(label.encode("ascii") + b"\0" + encoded).hexdigest())

    return WorkspaceIsolation(
        Sha256Digest("a" * 64), identity("root"), identity("index"),
        StableId("refs/heads/synthetic/" + str(workspace_id)), identity("admin"),
    )


class TrustedHost:
    """Deterministic trusted provider fixture used only by disposable tests."""

    def __init__(self):
        self.qualification_calls = 0
        self.workspace_isolations = {}

    def qualify_workspace(self, workspace_id, target, correlation_id):
        self.qualification_calls += 1
        provider = ProviderIdentity(StableId("coordination-test-host"), "1")
        base = QualifiedSourceRevision(PROJECT.project_id, REPOSITORY, StableId("base-main"), "1" * 64)
        destination = QualifiedDestination(PROJECT.project_id, REPOSITORY, StableId("main"))
        receipt = ProviderReceipt(
            StableId("qualification-" + hashlib.sha256(str(correlation_id).encode()).hexdigest()[:18]),
            provider, correlation_id, Sha256Digest("2" * 64), base.ref, NOW,
        )
        return WorkspaceQualification(
            workspace_id, REPOSITORY, base, destination, receipt,
            self.workspace_isolations.get(workspace_id),
        )

    def inspect_attempt(self, attempt, workspace):
        receipt = ProviderReceipt(
            StableId("inspection-" + hashlib.sha256(str(attempt.attempt_id).encode()).hexdigest()[:18]),
            ProviderIdentity(StableId("coordination-test-host"), "1"), attempt.attempt_id,
            Sha256Digest("3" * 64), workspace.common_base.ref, NOW,
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


class IndependentSchedulingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = FixedClock()
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(self.dispatcher, clock=self.clock)
        with self.open_writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="scheduling fixture owner",
                idempotency_key=StableId("coordination-owner-enrollment"), expected_revision=0,
            )
        with self.open_writer() as authority:
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=OWNER_ACTIONS, scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("coordination-owner-token"),
                expected_revision=enrollment.receipt.semantic_revision,
            )
        self.plan_service = PlanService(self.auth)
        self.plan_package = plan_json()
        with self.open_writer() as authority:
            preview = self.plan_service.preview(authority, self.plan_package)
            self.plan_service.commit(
                authority, self.owner.bearer_token, self.plan_package,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("coordination-accepted-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
        with self.open_reader() as authority:
            self.plan = self.plan_service.load_accepted_plan(authority)
        self.coordination = CoordinationService(self.auth)
        self.host = TrustedHost()
        self.attempts = AttemptService(
            self.auth, eligibility=EligibilityAdapter(clock=self.clock),
            host=self.host, clock=self.clock,
        )

    def open_writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def open_reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    def revision(self):
        with self.open_reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def state_snapshot(self):
        with self.open_reader() as authority:
            fingerprint = self.dispatcher.logical_fingerprint(authority)
            counts = tuple(
                (table, authority.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
                for table in (
                    "authority_events", "command_receipts", "command_idempotency", "runs",
                    "assignments", "run_schedules", "run_lanes", "run_queue", "attempts",
                )
            )
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
        return fingerprint, revision, counts

    def work(self, item_id):
        return next(item.definition.ref for item in self.plan.work_items
                    if str(item.definition.work_item_id) == item_id)

    def schedule(self, run_id, *, lanes=(), work=(), charter=None):
        return RunSchedule(
            StableId(run_id), self.plan.revision.ref, tuple(lanes), tuple(work), charter,
        )

    @staticmethod
    def charter():
        return RunCharter(
            "Coordinate accepted independent work safely",
            ("Keep each assignment within its accepted work definition",),
            ("Every assignment remains linked to the accepted plan revision",),
        )

    def open_run(self, schedule, *, key, expected_revision=None):
        revision = self.revision() if expected_revision is None else expected_revision
        with self.open_writer() as authority:
            return self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, schedule,
                expected_revision=revision,
                idempotency_key=StableId(key),
            )

    def read_run(self, run_id):
        with self.open_reader() as authority:
            return self.coordination.read_run(authority, StableId(run_id))

    def claim(self, token, run, entry, key, workspace_id):
        revision = self.revision()
        with self.open_writer() as authority:
            return self.attempts.claim(
                authority, token, entry.assignment.work_item, self.plan,
                idempotency_key=StableId(key), expected_revision=revision,
                workspace_id=StableId(workspace_id), run=run.ref,
                assignment=entry.assignment.ref,
            )

    def test_default_run_is_reopenable_and_simple_claim_has_distinct_identity_layers(self):
        schedule = self.schedule("simple-run")
        before_revision = self.revision()
        created = self.open_run(schedule, key="simple-run-open", expected_revision=before_revision)
        view = self.read_run("simple-run")

        self.assertEqual(tuple(str(lane.lane_id) for lane in view.lanes), ("default",))
        self.assertIs(view.lanes[0].queue_policy, QueuePolicy.SERIAL)
        self.assertEqual(len(view.entries), len(self.plan.revision.work_items))
        self.assertEqual(len({entry.assignment.ref for entry in view.entries}), len(view.entries))
        self.assertTrue(all(entry.assignment.work_item in self.plan.revision.work_items for entry in view.entries))

        replay = self.open_run(schedule, key="simple-run-open", expected_revision=before_revision)
        before_replay = self.state_snapshot()
        replay = self.open_run(schedule, key="simple-run-open", expected_revision=before_revision)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, created.receipt)
        self.assertEqual(self.state_snapshot(), before_replay)
        entry = view.entries[0]
        claimed = self.claim(
            self.owner.bearer_token, view.run, entry, "simple-run-claim", "simple-run-workspace"
        )
        attempt_ref = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT,
                                StableId(claimed.receipt.result["attempt_id"]))
        self.assertNotEqual(entry.assignment.work_item, entry.assignment.ref)
        self.assertNotEqual(entry.assignment.ref, attempt_ref)
        self.assertNotEqual(entry.assignment.work_item, attempt_ref)
        self.assertNotEqual(entry.assignment.run, self.plan.revision.ref)

    def test_mixed_lane_policies_roles_and_queue_order_survive_reopen_and_retry(self):
        self.host.workspace_isolations.update({
            StableId(workspace): synthetic_workspace_isolation(workspace)
            for workspace in (
                "serial-alpha-workspace", "parallel-beta-workspace", "parallel-gamma-workspace",
            )
        })
        lanes = (
            LaneSpec(StableId("lane-z"), QueuePolicy.SERIAL, ROLE_BUILD, IsolationPolicy.SHARED_SCOPES),
            LaneSpec(StableId("lane-a"), QueuePolicy.PARALLEL, ROLE_REVIEW,
                     IsolationPolicy.QUALIFIED_WORKSPACES),
        )
        worker_revision = self.revision()
        with self.open_writer() as authority:
            worker = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=WORKER_ACTIONS, scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("mixed-run-worker-token"),
                expected_revision=worker_revision,
            )
        work = (
            ScheduledWork(self.work("work-gamma"), StableId("lane-a"), worker.capability.actor),
            ScheduledWork(self.work("work-delta"), StableId("lane-z"), self.owner.capability.actor),
            ScheduledWork(self.work("work-beta"), StableId("lane-a"), self.owner.capability.actor),
            ScheduledWork(self.work("work-alpha"), StableId("lane-z"), self.owner.capability.actor),
        )
        schedule = self.schedule("mixed-run", lanes=lanes, work=work, charter=self.charter())
        old_revision = self.revision()
        created = self.open_run(schedule, key="mixed-run-open", expected_revision=old_revision)
        self.assertEqual(len(created.receipt.result["assignment_ids"]), 4)

        view = self.read_run("mixed-run")
        self.assertEqual(tuple(str(lane.lane_id) for lane in view.lanes), ("lane-a", "lane-z"))
        by_lane = {
            lane: tuple((str(entry.assignment.work_item.entity_id), entry.queue_position)
                        for entry in view.entries if str(entry.lane_id) == lane)
            for lane in ("lane-a", "lane-z")
        }
        self.assertEqual(by_lane["lane-a"], (("work-beta", 0), ("work-gamma", 1)))
        self.assertEqual(by_lane["lane-z"], (("work-alpha", 0), ("work-delta", 1)))
        self.assertEqual(
            tuple((entry.queue_policy, entry.required_role, entry.isolation_policy)
                  for entry in view.entries),
            ((QueuePolicy.PARALLEL, ROLE_REVIEW, IsolationPolicy.QUALIFIED_WORKSPACES),
             (QueuePolicy.PARALLEL, ROLE_REVIEW, IsolationPolicy.QUALIFIED_WORKSPACES),
             (QueuePolicy.SERIAL, ROLE_BUILD, IsolationPolicy.SHARED_SCOPES),
             (QueuePolicy.SERIAL, ROLE_BUILD, IsolationPolicy.SHARED_SCOPES)),
        )
        self.assertEqual(
            next(entry for entry in view.entries if str(entry.assignment.work_item.entity_id) == "work-gamma")
            .assignment.assignee,
            worker.capability.actor,
        )
        before_replay = self.state_snapshot()
        replay = self.open_run(schedule, key="mixed-run-open", expected_revision=old_revision)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, created.receipt)
        self.assertEqual(self.state_snapshot(), before_replay)
        self.assertEqual(self.read_run("mixed-run"), view)

        alpha = next(entry for entry in view.entries
                     if str(entry.assignment.work_item.entity_id) == "work-alpha")
        delta = next(entry for entry in view.entries
                     if str(entry.assignment.work_item.entity_id) == "work-delta")
        beta = next(entry for entry in view.entries
                    if str(entry.assignment.work_item.entity_id) == "work-beta")
        gamma = next(entry for entry in view.entries
                     if str(entry.assignment.work_item.entity_id) == "work-gamma")
        self.claim(self.owner.bearer_token, view.run, alpha,
                   "serial-lane-first", "serial-alpha-workspace")
        before_serial_refusal = self.state_snapshot()
        with self.assertRaises(AttemptAdmissionDeniedError) as refused:
            self.claim(self.owner.bearer_token, view.run, delta,
                       "serial-lane-second", "serial-delta-workspace")
        self.assertIn("serial_lane_occupied", {cause.code for cause in refused.exception.decision.causes})
        self.assertEqual(self.state_snapshot(), before_serial_refusal)

        parallel_first = self.claim(
            self.owner.bearer_token, view.run, beta, "parallel-lane-beta", "parallel-beta-workspace"
        )
        parallel_second = self.claim(
            worker.bearer_token, view.run, gamma, "parallel-lane-gamma", "parallel-gamma-workspace"
        )
        self.assertTrue(parallel_first.receipt.changed)
        self.assertTrue(parallel_second.receipt.changed)
        self.assertNotEqual(
            parallel_first.receipt.result["attempt_id"], parallel_second.receipt.result["attempt_id"]
        )

    def test_assignment_actor_and_role_label_cannot_replace_required_grant_action(self):
        revision = self.revision()
        with self.open_writer() as authority:
            worker = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=CLAIM_ACTIONS, scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("role-less-claim-token"),
                expected_revision=revision,
            )
        schedule = self.schedule(
            "role-guarded-run",
            lanes=(LaneSpec(StableId("review"), QueuePolicy.PARALLEL, ROLE_REVIEW),),
            work=(ScheduledWork(self.work("work-alpha"), StableId("review"), worker.capability.actor),),
            charter=self.charter(),
        )
        self.open_run(schedule, key="role-guarded-run-open")
        view = self.read_run("role-guarded-run")
        before = self.state_snapshot()
        with self.assertRaises(AttemptAdmissionDeniedError) as refused:
            self.claim(worker.bearer_token, view.run, view.entries[0],
                       "role-action-required", "role-guarded-workspace")
        self.assertIn("lane_role_action_missing", {cause.code for cause in refused.exception.decision.causes})
        self.assertEqual(self.state_snapshot(), before)

    def test_parallel_lane_and_qualified_workspace_policy_do_not_bypass_scope_overlap(self):
        schedule = self.schedule(
            "cross-lane-overlap-run",
            lanes=(
                LaneSpec(StableId("lane-serial"), QueuePolicy.SERIAL,
                         isolation_policy=IsolationPolicy.SHARED_SCOPES),
                LaneSpec(StableId("lane-parallel"), QueuePolicy.PARALLEL,
                         isolation_policy=IsolationPolicy.QUALIFIED_WORKSPACES),
            ),
            work=(
                ScheduledWork(self.work("work-alpha"), StableId("lane-serial")),
                ScheduledWork(self.work("work-beta"), StableId("lane-parallel")),
            ),
            charter=self.charter(),
        )
        self.open_run(schedule, key="cross-lane-overlap-open")
        view = self.read_run("cross-lane-overlap-run")
        alpha = next(entry for entry in view.entries
                     if str(entry.assignment.work_item.entity_id) == "work-alpha")
        beta = next(entry for entry in view.entries
                    if str(entry.assignment.work_item.entity_id) == "work-beta")
        self.claim(self.owner.bearer_token, view.run, alpha,
                   "cross-lane-alpha-claim", "shared-workspace")
        before = self.state_snapshot()
        with self.assertRaises(AttemptAdmissionDeniedError) as refused:
            self.claim(self.owner.bearer_token, view.run, beta,
                       "cross-lane-beta-claim", "shared-workspace")
        self.assertIn("unsafe_source_overlap", {cause.code for cause in refused.exception.decision.causes})
        self.assertEqual(self.state_snapshot(), before)

    def test_nonmember_definition_is_refused_without_authority_churn(self):
        stale_work = EntityRef(
            PROJECT.project_id, EntityKind.WORK_ITEM, self.work("work-alpha").entity_id,
            definition_revision_id=StableId("not-the-accepted-definition"),
        )
        schedule = self.schedule("stale-definition-run", work=(ScheduledWork(stale_work),))
        before = self.state_snapshot()
        with self.assertRaises(AuthorityError):
            self.open_run(schedule, key="stale-definition-open")
        self.assertEqual(self.state_snapshot(), before)


if __name__ == "__main__":
    unittest.main()
