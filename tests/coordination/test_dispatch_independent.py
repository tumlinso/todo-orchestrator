"""Independent integration checks for atomic dispatch and resumption."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AuthorityAuthService,
    AuthorityError,
    CommandDispatcher,
    EligibilityAdapter,
    SQLiteAuthority,
)
from todo_orchestrator.authority.attempts import AttemptService, CLAIM_ACTION
from todo_orchestrator.authority.auth import (
    AuthenticatedPrincipal,
    AuthenticationFailedError,
    CapabilityDeniedError,
    CapabilityDeliveryUncertainError,
)
from todo_orchestrator.contracts import (
    ActorKind,
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
    QueuePolicy,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    RunCharter,
    RunSchedule,
    ScheduledWork,
    WorkspaceQualification,
)
from todo_orchestrator.planning import PlanService


NOW = datetime(2026, 10, 18, 18, 0, tzinfo=timezone.utc)
PROJECT = Project(StableId("dispatch-independent-project"), StableId("dispatch-independent-authority"))
OWNER_PASSWORD = "dispatch independent owner credential 927"
REPOSITORY = StableId("dispatch-independent-repository")
PLAN_ACTION = StableId("todo.plan.commit")
SCHEDULE_ACTION = StableId("todo.run.schedule")
DISPATCH_ACTION = StableId("todo.run.dispatch")
HEARTBEAT_ACTION = StableId("todo.attempt.heartbeat")
RELEASE_ACTION = StableId("todo.attempt.release")
FINISH_ACTION = StableId("todo.attempt.finish")
OWNER_ACTIONS = (
    PLAN_ACTION, SCHEDULE_ACTION, DISPATCH_ACTION, CLAIM_ACTION,
    HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION,
    StableId("todo.capability.delegate"), StableId("todo.capability.revoke"),
)


def plan_json(project: Project = PROJECT) -> str:
    """A small plan with disjoint scopes, so optional queues can run safely."""
    work = (
        ("work-gamma", "docs/guide.md"),
        ("work-delta", "assets/report.json"),
        ("work-beta", "src/pkg/sub"),
        ("work-alpha", "src/pkg"),
    )
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "dispatch-independent-plan",
        "project": {"project_id": str(project.project_id), "authority_id": str(project.authority_id)},
        "work_items": [
            {
                "id": item_id,
                "title": item_id,
                "objective": "Exercise durable dispatch without an external scheduler",
                "outcome": "The attempt and bounded capability remain linked",
                "scope": {"paths": [{"path": path, "access": "write"}], "concepts": [], "locks": []},
                "ownership": {"mode": "any", "actors": []},
                "acceptance": {
                    "assertions": ["attempt identity is exact"],
                    "required_evidence": [],
                    "allowed_dispositions": ["completed"],
                },
            }
            for item_id, path in work
        ],
    }
    return json.dumps(document)


def plan_with_unknown_alpha_blocker() -> str:
    """Add a real, unresolved graph prerequisite to alpha for selector tests."""
    document = json.loads(plan_json())
    document["checkpoints"] = [{
        "id": "alpha-checkpoint", "title": "Alpha checkpoint",
        "acceptance": {"assertions": ["checkpoint is accepted"], "required_evidence": [],
                       "allowed_dispositions": ["completed"]},
        "unknowns": [], "producers": [],
    }]
    document["dependencies"] = [{
        "source": {"project_id": str(PROJECT.project_id), "kind": "work_item", "entity_id": "work-alpha"},
        "mode": "all",
        "members": [{
            "relation": "checkpoint_accepted",
            "target": {"project_id": str(PROJECT.project_id), "kind": "checkpoint", "entity_id": "alpha-checkpoint"},
        }],
    }]
    return json.dumps(document, sort_keys=True)


class FixedClock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


class TestAuthenticator:
    provider_id = "dispatch-independent-test-provider"

    def authenticate(self, credential):
        if credential != "dispatch independent worker credential":
            return None
        return AuthenticatedPrincipal("dispatch-independent-worker", ActorKind.AUTOMATION, "worker B")


class TrustedHost:
    """Deterministic trusted provider fixture for temporary authorities only."""

    def __init__(self, clock):
        self.clock = clock

    def qualify_workspace(self, workspace_id, target, correlation_id):
        now = self.clock()
        provider = ProviderIdentity(StableId("dispatch-test-host"), "1")
        base = QualifiedSourceRevision(PROJECT.project_id, REPOSITORY, StableId("base-main"), "1" * 64)
        destination = QualifiedDestination(PROJECT.project_id, REPOSITORY, StableId("main"))
        receipt = ProviderReceipt(
            StableId("dispatch-qualification-" + hashlib.sha256(str(correlation_id).encode()).hexdigest()[:14]),
            provider, correlation_id, Sha256Digest("2" * 64), base.ref, now,
        )
        return WorkspaceQualification(workspace_id, REPOSITORY, base, destination, receipt)

    def inspect_attempt(self, attempt, workspace):
        now = self.clock()
        receipt = ProviderReceipt(
            StableId("dispatch-inspection-" + hashlib.sha256(
                (str(attempt.attempt_id) + now.isoformat()).encode()
            ).hexdigest()[:14]),
            ProviderIdentity(StableId("dispatch-test-host"), "1"), attempt.attempt_id,
            Sha256Digest("3" * 64), workspace.common_base.ref, now,
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


class IndependentDispatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = FixedClock()
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(
            self.dispatcher, clock=self.clock, authenticator=TestAuthenticator(),
        )
        with self.open_writer() as authority:
            enrolled = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="dispatch fixture owner",
                idempotency_key=StableId("dispatch-owner-enrollment"), expected_revision=0,
            )
        with self.open_writer() as authority:
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=OWNER_ACTIONS, scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=2),
                idempotency_key=StableId("dispatch-owner-token"),
                expected_revision=enrolled.receipt.semantic_revision,
            )
        self.plan_service = PlanService(self.auth)
        self.plan_package = (
            plan_with_unknown_alpha_blocker()
            if self._testMethodName == "test_run_selector_skips_unknown_candidate_but_preserves_all_unknown_refusal"
            else plan_json()
        )
        with self.open_writer() as authority:
            preview = self.plan_service.preview(authority, self.plan_package)
            self.plan_service.commit(
                authority, self.owner.bearer_token, self.plan_package,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("dispatch-accepted-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
        with self.open_reader() as authority:
            self.plan = self.plan_service.load_accepted_plan(authority)
        self.host = TrustedHost(self.clock)
        self.attempts = AttemptService(
            self.auth, eligibility=EligibilityAdapter(clock=self.clock),
            host=self.host, clock=self.clock,
        )
        self.coordination = CoordinationService(self.auth, attempts=self.attempts)

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
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            tables = tuple(row[0] for row in authority.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ))
            counts = tuple(
                (name, authority.connection.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0])
                for name in tables
            )
        return fingerprint, revision, counts

    def outcome_snapshot(self):
        with self.open_reader() as authority:
            return tuple(
                (table, tuple(tuple(row) for row in authority.connection.execute(query)))
                for table, query in (
                    ("outcomes", "SELECT * FROM outcomes ORDER BY outcome_id"),
                    ("evidence", "SELECT * FROM evidence ORDER BY evidence_id"),
                    ("outcome_evidence", "SELECT * FROM outcome_evidence ORDER BY outcome_id, evidence_id"),
                )
            )

    def resume_in_new_process(self, bearer_token, attempt_ref, lease_id, idempotency_key):
        """Open the same authority and renew from a fresh OS process."""
        script = r'''
import json
import sys
from datetime import datetime
from pathlib import Path
from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, EligibilityAdapter, SQLiteAuthority
from todo_orchestrator.authority.attempts import AttemptService
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, StableId
from todo_orchestrator.coordination import CoordinationService
from todo_orchestrator.planning import PlanService

class Host:
    def qualify_workspace(self, *_args):
        raise AssertionError("resume must not requalify the workspace")
    def inspect_attempt(self, *_args):
        raise AssertionError("resume does not inspect terminal safety")

request = json.load(sys.stdin)
project = Project(StableId(request["project_id"]), StableId(request["authority_id"]))
clock = lambda: datetime.fromisoformat(request["now"])
auth = AuthorityAuthService(CommandDispatcher(), clock=clock)
attempts = AttemptService(auth, eligibility=EligibilityAdapter(clock=clock), host=Host(), clock=clock)
coordination = CoordinationService(auth, attempts=attempts)
attempt_ref = EntityRef(project.project_id, EntityKind.ATTEMPT, StableId(request["attempt_id"]))
with SQLiteAuthority.open_writer(Path(request["path"]), project) as authority:
    plan = PlanService(auth).load_accepted_plan(authority)
    result = coordination.resume(
        authority, request["token"], plan, attempt_ref, StableId(request["lease_id"]),
        idempotency_key=StableId(request["idempotency_key"]),
    )
    print(json.dumps(result.receipt.result, sort_keys=True))
'''
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
        payload = {
            "path": str(self.path),
            "project_id": str(PROJECT.project_id),
            "authority_id": str(PROJECT.authority_id),
            "now": self.clock().isoformat(),
            "token": bearer_token,
            "attempt_id": str(attempt_ref.entity_id),
            "lease_id": str(lease_id),
            "idempotency_key": str(idempotency_key),
        }
        completed = subprocess.run(
            [sys.executable, "-S", "-c", script], input=json.dumps(payload),
            text=True, capture_output=True, cwd=Path(__file__).resolve().parents[2],
            env=environment, check=False, timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def work(self, item_id):
        return next(item.definition.ref for item in self.plan.work_items
                    if str(item.definition.work_item_id) == item_id)

    def dispatch(self, key, *, work_item=None, run=None, assignment=None, workspace=None,
                 expected_revision=None):
        revision = self.revision() if expected_revision is None else expected_revision
        with self.open_writer() as authority:
            return self.coordination.dispatch(
                authority, self.owner.bearer_token, self.plan,
                workspace_id=StableId(workspace or f"workspace-{key}"),
                idempotency_key=StableId(key), expected_revision=revision,
                work_item=work_item, run=run, assignment=assignment,
            )

    def test_run_selector_uses_stored_queue_order_and_dispatch_secret_is_one_time(self):
        # The actual RunSchedule is created below so this test exercises the public C01 flow.
        from todo_orchestrator.model import RunSchedule

        schedule = RunSchedule(StableId("dispatch-ordered-run"), self.plan.revision.ref)
        revision = self.revision()
        with self.open_writer() as authority:
            self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, schedule,
                idempotency_key=StableId("dispatch-open-run"), expected_revision=revision,
            )
        # Reopen explicitly after the queue has committed; entries are canonical lane/position order.
        with self.open_reader() as authority:
            view = self.coordination.read_run(authority, StableId("dispatch-ordered-run"))
        dispatch_revision = self.revision()
        selected = self.dispatch(
            "dispatch-run-only", run=view.run.ref, expected_revision=dispatch_revision,
        )
        self.assertEqual(selected.attempt.work_item, view.entries[0].assignment.work_item)
        self.assertEqual(selected.attempt.assignment, view.entries[0].assignment.ref)
        self.assertEqual(selected.attempt.run, view.run.ref)
        self.assertEqual(selected.attempt.actor, self.owner.capability.actor)
        self.assertEqual(selected.capability.actor, selected.attempt.actor)
        self.assertEqual(selected.capability.attempt, selected.attempt.ref)
        self.assertEqual(selected.capability.scope, selected.attempt.work_item)
        self.assertEqual(selected.capability.expires_at, selected.attempt.lease.expires_at)
        self.assertEqual(
            set(selected.capability.actions),
            {HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION},
        )
        self.assertEqual(self.outcome_snapshot(), (
            ("outcomes", ()), ("evidence", ()), ("outcome_evidence", ()),
        ))

        before_retry = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(CapabilityDeliveryUncertainError) as replay:
                self.coordination.dispatch(
                    authority, self.owner.bearer_token, self.plan,
                    workspace_id=StableId("workspace-dispatch-run-only"),
                    run=view.run.ref, idempotency_key=StableId("dispatch-run-only"),
                    expected_revision=dispatch_revision,
                )
        self.assertEqual(replay.exception.receipt, selected.receipt)
        self.assertEqual(self.state_snapshot(), before_retry)
        with self.open_reader() as authority:
            dump = "\n".join(authority.connection.iterdump())
        self.assertNotIn(selected.bearer_token, dump)
        self.assertNotIn(selected.bearer_token, json.dumps(selected.receipt.result, sort_keys=True))

    def test_dispatch_failure_after_claim_rolls_back_attempt_and_grant(self):
        before = self.state_snapshot()
        failure = RuntimeError("injected capability mint failure")
        attempt_id = "attempt-" + hashlib.sha256(b"dispatch-rollback").hexdigest()

        def fail_after_claim(context, **_kwargs):
            claimed = context._connection.execute(
                "SELECT state FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            self.assertIsNotNone(claimed, "fault seam must run after the claim has been inserted")
            self.assertEqual(claimed[0], "admitted")
            raise failure

        with self.open_writer() as authority:
            with patch.object(
                self.auth, "_derive_scoped_capability_in_transaction", side_effect=fail_after_claim,
            ) as mint:
                with self.assertRaisesRegex(RuntimeError, "injected capability mint failure"):
                    self.coordination.dispatch(
                        authority, self.owner.bearer_token, self.plan,
                        workspace_id=StableId("workspace-rollback"),
                        work_item=self.work("work-gamma"),
                        idempotency_key=StableId("dispatch-rollback"),
                        expected_revision=before[1],
                    )
                mint.assert_called_once()
        self.assertEqual(self.state_snapshot(), before)

    def test_multiple_open_assignments_are_ambiguous_and_do_not_create_attempts(self):
        target = self.work("work-delta")
        for run_id in ("dispatch-ambiguous-a", "dispatch-ambiguous-b"):
            schedule = RunSchedule(
                StableId(run_id), self.plan.revision.ref,
                work=(ScheduledWork(target),),
            )
            with self.open_writer() as authority:
                self.coordination.open_run(
                    authority, self.owner.bearer_token, self.plan, schedule,
                    idempotency_key=StableId(f"open-{run_id}"), expected_revision=self.revision(),
                )
        before = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthorityError):
                self.coordination.dispatch(
                    authority, self.owner.bearer_token, self.plan,
                    workspace_id=StableId("workspace-ambiguous"), work_item=target,
                    idempotency_key=StableId("dispatch-ambiguous"), expected_revision=before[1],
                )
        self.assertEqual(self.state_snapshot(), before)

        # A dispatch grant alone cannot authorize the nested attempt claim.
        with self.open_writer() as authority:
            dispatch_only = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=(DISPATCH_ACTION,), scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("dispatch-only-token"),
                expected_revision=self.revision(),
            )
        before_denial = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.coordination.dispatch(
                    authority, dispatch_only.bearer_token, self.plan,
                    workspace_id=StableId("workspace-missing-claim-right"),
                    work_item=self.work("work-gamma"),
                    idempotency_key=StableId("dispatch-missing-claim-right"),
                    expected_revision=before_denial[1],
                )
        self.assertEqual(self.state_snapshot(), before_denial)

    def test_run_selector_skips_unknown_candidate_but_preserves_all_unknown_refusal(self):
        lane = LaneSpec(
            StableId("dispatch-parallel-lane"), QueuePolicy.PARALLEL,
            isolation_policy=IsolationPolicy.SHARED_SCOPES,
        )
        charter = RunCharter(
            "Dispatch independent eligible work",
            ("Do not bypass target-specific admission",),
            ("Unknown candidates remain unclaimed while unrelated eligible work can proceed",),
        )
        schedule = RunSchedule(
            StableId("dispatch-unknown-and-eligible"), self.plan.revision.ref,
            lanes=(lane,),
            work=(
                ScheduledWork(self.work("work-alpha"), lane.lane_id),
                ScheduledWork(self.work("work-gamma"), lane.lane_id),
            ),
            charter=charter,
        )
        with self.open_writer() as authority:
            self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, schedule,
                idempotency_key=StableId("open-unknown-and-eligible"),
                expected_revision=self.revision(),
            )
        before = self.state_snapshot()
        selected = self.dispatch(
            "dispatch-after-unknown", run=EntityRef(PROJECT.project_id, EntityKind.RUN,
                                                    StableId("dispatch-unknown-and-eligible")),
            expected_revision=before[1],
        )
        self.assertEqual(selected.attempt.work_item, self.work("work-gamma"))
        self.assertNotEqual(selected.attempt.work_item, self.work("work-alpha"))

        # With no eligible candidate, automatic selection must still refuse
        # without leaving a claim, receipt, grant, or event behind.
        only_unknown = RunSchedule(
            StableId("dispatch-all-unknown"), self.plan.revision.ref,
            lanes=(LaneSpec(StableId("dispatch-unknown-only-lane"), QueuePolicy.SERIAL),),
            work=(ScheduledWork(self.work("work-alpha"), StableId("dispatch-unknown-only-lane")),),
        )
        with self.open_writer() as authority:
            self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, only_unknown,
                idempotency_key=StableId("open-all-unknown"), expected_revision=self.revision(),
            )
        before_refusal = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError):
                self.coordination.dispatch(
                    authority, self.owner.bearer_token, self.plan,
                    workspace_id=StableId("workspace-all-unknown"),
                    run=EntityRef(PROJECT.project_id, EntityKind.RUN, StableId("dispatch-all-unknown")),
                    idempotency_key=StableId("dispatch-all-unknown"),
                    expected_revision=before_refusal[1],
                )
        self.assertEqual(self.state_snapshot(), before_refusal)

    def test_resume_after_service_reconstruction_and_reject_expired_or_revoked_attempt_grants(self):
        dispatched = self.dispatch("dispatch-resume", work_item=self.work("work-gamma"))
        attempt_ref = dispatched.attempt.ref
        lease_id = dispatched.attempt.lease.lease_id

        # A fresh process has no in-memory dispatch or authentication cache.
        resumed = self.resume_in_new_process(
            dispatched.bearer_token, attempt_ref, lease_id, StableId("dispatch-resume-heartbeat"),
        )
        self.assertEqual(resumed["attempt_id"], str(attempt_ref.entity_id))
        new_lease_id = StableId(resumed["lease_id"])
        with self.open_reader() as authority:
            stored_expiry = authority.connection.execute(
                "SELECT c.expires_at FROM capabilities AS c WHERE c.capability_id = ?",
                (str(dispatched.capability.capability_id),),
            ).fetchone()[0]
        self.assertEqual(stored_expiry, resumed["lease_expires_at"])

        before = self.state_snapshot()
        foreign = EntityRef(StableId("different-project"), EntityKind.ATTEMPT, StableId("foreign-attempt"))
        with self.open_writer() as authority:
            with self.assertRaises((AuthorityError, ValueError, TypeError)):
                self.coordination.resume(
                    authority, dispatched.bearer_token, self.plan, foreign, new_lease_id,
                    idempotency_key=StableId("dispatch-foreign-resume"), expected_revision=before[1],
                )
        self.assertEqual(self.state_snapshot(), before)

        with self.open_writer() as authority:
            self.auth.revoke_family(
                authority, self.owner.bearer_token, dispatched.capability.capability_id,
                idempotency_key=StableId("dispatch-revoke-child"), expected_revision=self.revision(),
            )
        after_revoke = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.coordination.resume(
                    authority, dispatched.bearer_token, self.plan, attempt_ref, new_lease_id,
                    idempotency_key=StableId("dispatch-resume-revoked"), expected_revision=after_revoke[1],
                )
        self.assertEqual(self.state_snapshot(), after_revoke)

    def test_delegated_worker_attempt_grant_renews_past_lease_but_not_ancestor_expiry(self):
        worker_expiry = NOW + timedelta(minutes=4)
        worker_actions = (
            DISPATCH_ACTION, CLAIM_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION,
        )
        with self.open_writer() as authority:
            worker = self.auth.delegate(
                authority, self.owner.bearer_token, "dispatch independent worker credential",
                actions=worker_actions, scope=PROJECT.ref, expires_at=worker_expiry,
                idempotency_key=StableId("dispatch-delegate-worker"),
                expected_revision=self.revision(),
            )

        with self.open_writer() as authority:
            dispatched = self.coordination.dispatch(
                authority, worker.bearer_token, self.plan,
                workspace_id=StableId("workspace-delegated-worker"),
                work_item=self.work("work-gamma"),
                idempotency_key=StableId("dispatch-delegated-worker"),
                expected_revision=self.revision(),
            )
        self.assertEqual(dispatched.attempt.actor, worker.capability.actor)
        self.assertEqual(dispatched.capability.actor, worker.capability.actor)
        original_lease_expiry = dispatched.attempt.lease.expires_at
        self.assertLess(original_lease_expiry, worker_expiry)

        def capability_lineage():
            with self.open_reader() as authority:
                lineage = []
                capability_id = dispatched.capability.capability_id
                while capability_id is not None:
                    row = authority.connection.execute(
                        "SELECT capability_id, parent_capability_id, expires_at "
                        "FROM capabilities WHERE capability_id = ?", (str(capability_id),),
                    ).fetchone()
                    self.assertIsNotNone(row)
                    lineage.append((StableId(row["capability_id"]),
                                    datetime.fromisoformat(row["expires_at"])))
                    capability_id = (StableId(row["parent_capability_id"])
                                     if row["parent_capability_id"] else None)
                return lineage

        initial_lineage = capability_lineage()
        self.assertEqual([entry[0] for entry in initial_lineage], [
            dispatched.capability.capability_id,
            worker.capability.capability_id,
            self.owner.capability.capability_id,
        ])
        self.assertEqual(initial_lineage[0][1], original_lease_expiry)

        # The worker's attempt-scoped bearer is a child of a different actor's
        # delegated grant. A renewal should extend it to the new lease, while
        # respecting the coordinator and owner ancestor expiries.
        self.clock.now += timedelta(minutes=1)
        with self.open_writer() as authority:
            first_resume = self.coordination.resume(
                authority, dispatched.bearer_token, self.plan, dispatched.attempt.ref,
                dispatched.attempt.lease.lease_id,
                idempotency_key=StableId("dispatch-delegated-renewal-one"),
                expected_revision=self.revision(),
            )
        first_lease_expiry = datetime.fromisoformat(first_resume.receipt.result["lease_expires_at"])
        first_lease_id = StableId(first_resume.receipt.result["lease_id"])
        first_lineage = capability_lineage()
        self.assertGreater(first_lineage[0][1], original_lease_expiry)
        self.assertEqual(first_lineage[0][1], first_lease_expiry)
        self.assertTrue(all(first_lineage[0][1] <= ancestor_expiry
                            for _, ancestor_expiry in first_lineage[1:]))

        # Cross the original lease deadline, then resume with the renewed
        # attempt bearer to prove it remained usable beyond its first expiry.
        self.clock.now = original_lease_expiry + timedelta(seconds=5)
        with self.open_writer() as authority:
            second_resume = self.coordination.resume(
                authority, dispatched.bearer_token, self.plan, dispatched.attempt.ref,
                first_lease_id,
                idempotency_key=StableId("dispatch-delegated-renewal-two"),
                expected_revision=self.revision(),
            )
        second_lease_expiry = datetime.fromisoformat(second_resume.receipt.result["lease_expires_at"])
        second_lease_id = StableId(second_resume.receipt.result["lease_id"])
        second_lineage = capability_lineage()
        self.assertGreater(self.clock(), original_lease_expiry)
        self.assertGreater(second_lease_expiry, self.clock())
        self.assertLessEqual(second_lineage[0][1], worker_expiry)
        self.assertLessEqual(second_lineage[0][1], second_lease_expiry)
        self.assertTrue(all(second_lineage[0][1] <= ancestor_expiry
                            for _, ancestor_expiry in second_lineage[1:]))
        self.assertEqual(second_lineage[1][1], worker_expiry)

        # Renewal cannot revive the child after the delegated worker ancestor
        # expires, even though the attempt lease itself has a later deadline.
        self.clock.now = worker_expiry + timedelta(seconds=1)
        before_expired_resume = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.coordination.resume(
                    authority, dispatched.bearer_token, self.plan, dispatched.attempt.ref,
                    second_lease_id,
                    idempotency_key=StableId("dispatch-delegated-renewal-after-ancestor-expiry"),
                    expected_revision=before_expired_resume[1],
                )
        self.assertEqual(self.state_snapshot(), before_expired_resume)

    def test_expired_lease_cannot_be_resumed_and_finish_preserves_existing_outcomes(self):
        dispatched = self.dispatch("dispatch-expiring", work_item=self.work("work-gamma"))
        self.clock.now += timedelta(minutes=5)
        before = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthorityError):
                self.coordination.resume(
                    authority, self.owner.bearer_token, self.plan, dispatched.attempt.ref,
                    dispatched.attempt.lease.lease_id,
                    idempotency_key=StableId("dispatch-resume-expired"), expected_revision=before[1],
                )
        self.assertEqual(self.state_snapshot(), before)

        # Seed one already-accepted, foreign-to-this-dispatch outcome/evidence pair
        # in this disposable authority; C02 finish must retain it and must not
        # turn dispatch itself into an acceptance operation.
        finished = self.dispatch("dispatch-finish", work_item=self.work("work-delta"))
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO evidence(evidence_id, attempt_id, requirement_id, "
                    "requirement_definition_revision_id, result, verifier_id, verifier_version, "
                    "contract_digest, observed_at) VALUES (?, ?, NULL, NULL, 'pass', ?, ?, ?, ?)",
                    ("fixture-evidence", str(dispatched.attempt.attempt_id), "fixture-verifier", "1",
                     "4" * 64, NOW.isoformat()),
                )
                connection.execute(
                    "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, "
                    "disposition, accepted_by_actor_id, accepted_by_incarnation_id, accepted_at, attempt_id) "
                    "VALUES (?, ?, ?, 1, 'completed', ?, ?, ?, ?)",
                    ("fixture-outcome", str(dispatched.attempt.work_item.entity_id),
                     str(dispatched.attempt.work_item.definition_revision_id),
                     str(self.owner.capability.actor.entity_id),
                     str(self.owner.capability.actor.incarnation_id), NOW.isoformat(),
                     str(dispatched.attempt.attempt_id)),
                )
                connection.execute(
                    "INSERT INTO outcome_evidence(outcome_id, evidence_id) VALUES (?, ?)",
                    ("fixture-outcome", "fixture-evidence"),
                )
        before_finish = self.outcome_snapshot()
        with self.open_writer() as authority:
            finished_result = self.coordination.finish(
                authority, finished.bearer_token, finished.attempt.ref,
                finished.attempt.lease.lease_id,
                idempotency_key=StableId("dispatch-finish-terminal"),
                expected_revision=self.revision(),
            )
        self.assertNotIn("outcome_id", finished_result.receipt.result)
        with self.open_reader() as authority:
            outcome = authority.connection.execute(
                "SELECT disposition, attempt_id FROM outcomes WHERE outcome_id = 'fixture-outcome'"
            ).fetchone()
            evidence = authority.connection.execute(
                "SELECT result, attempt_id FROM evidence WHERE evidence_id = 'fixture-evidence'"
            ).fetchone()
            relation = authority.connection.execute(
                "SELECT outcome_id, evidence_id FROM outcome_evidence WHERE outcome_id = 'fixture-outcome'"
            ).fetchone()
            child = authority.connection.execute(
                "SELECT revoked FROM capabilities WHERE capability_id = ?",
                (str(finished.capability.capability_id),),
            ).fetchone()
        self.assertEqual(tuple(outcome), ("completed", str(dispatched.attempt.attempt_id)))
        self.assertEqual(tuple(evidence), ("pass", str(dispatched.attempt.attempt_id)))
        self.assertEqual(tuple(relation), ("fixture-outcome", "fixture-evidence"))
        self.assertEqual(child[0], 1)
        self.assertEqual(
            self.outcome_snapshot(), before_finish,
            "finish may write lifecycle/audit rows but must preserve outcome/evidence rows and links",
        )


if __name__ == "__main__":
    unittest.main()
