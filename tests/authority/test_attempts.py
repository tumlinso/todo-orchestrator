from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AttemptObservationMismatchError,
    AttemptService,
    AuthorityAuthService,
    CommandDispatcher,
    SQLiteAuthority,
)
from todo_orchestrator.contracts import (
    AttemptState,
    EntityKind,
    EntityRef,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.contracts.providers import ProviderIdentity, ProviderReceipt
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceQualification,
)
from todo_orchestrator.planning import compile_plan, parse_plan_json


NOW = datetime(2031, 4, 5, 6, 7, 8, tzinfo=timezone.utc)
PROJECT = Project(StableId("attempt-project"), StableId("attempt-authority"))
ATTEMPT_ACTIONS = tuple(StableId(value) for value in (
    "todo.attempt.claim", "todo.attempt.heartbeat", "todo.attempt.release",
    "todo.attempt.reconcile_expired",
))
OWNER_PASSWORD = "attempt fixture owner phrase 927"


def _plan(project: Project, *, second=False):
    work_items = [{
        "id": "work-one",
        "title": "First work item",
        "objective": "Own the first scope",
        "outcome": "The first outcome is present",
        "scope": {"paths": [{"path": "src/one", "access": "write"}], "concepts": [], "locks": []},
        "acceptance": {"assertions": ["result exists"], "required_evidence": [],
                        "allowed_dispositions": ["completed"]},
        "ownership": {"mode": "any", "actors": []},
    }]
    if second:
        work_items.append({
            "id": "work-two",
            "title": "Second work item",
            "objective": "Own the second scope",
            "outcome": "The second outcome is present",
            "scope": {"paths": [{"path": "src/two", "access": "write"}], "concepts": [], "locks": []},
            "acceptance": {"assertions": ["result exists"], "required_evidence": [],
                            "allowed_dispositions": ["completed"]},
            "ownership": {"mode": "any", "actors": []},
        })
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "attempt-fixture",
        "project": {"project_id": str(project.project_id), "authority_id": str(project.authority_id)},
        "work_items": work_items,
    }
    parsed = parse_plan_json(json.dumps(document))
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    compiled = compile_plan(parsed.package, project)
    if not compiled.ok:
        raise AssertionError(compiled.diagnostics)
    return compiled.plan


class MutableClock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


class FakeHost:
    def __init__(self, clock):
        self.clock = clock
        self.source = SourceSafety.CLEAN
        self.process = ProcessLiveness.STOPPED
        self.children = ChildActivity.NONE
        self.before_return = None
        self.qualification_calls = 0
        self.inspection_calls = 0

    def qualify_workspace(self, workspace_id, target, correlation_id):
        self.qualification_calls += 1
        provider = ProviderIdentity(StableId("fixture-host"), "1")
        base = QualifiedSourceRevision(
            PROJECT.project_id, StableId("fixture-repo"), StableId("base-commit"), "a" * 64
        )
        destination = QualifiedDestination(
            PROJECT.project_id, StableId("fixture-repo"), StableId("main")
        )
        receipt = ProviderReceipt(
            StableId(f"workspace-receipt-{self.qualification_calls}"), provider,
            correlation_id, Sha256Digest("b" * 64), base.ref, self.clock(),
        )
        return WorkspaceQualification(workspace_id, StableId("fixture-repo"), base, destination, receipt)

    def inspect_attempt(self, attempt, workspace):
        self.inspection_calls += 1
        assert attempt.lease is not None
        receipt = ProviderReceipt(
            StableId(f"safety-receipt-{self.inspection_calls}"),
            ProviderIdentity(StableId("fixture-host"), "1"), attempt.attempt_id,
            Sha256Digest("c" * 64), workspace.common_base.ref, self.clock(),
        )
        result = AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, self.source, self.process, self.children, receipt,
        )
        callback, self.before_return = self.before_return, None
        if callback is not None:
            callback()
        return result


class AttemptAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = MutableClock()
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(self.dispatcher, clock=self.clock)
        with self.open_writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="owner", idempotency_key=StableId("enroll"),
                expected_revision=0,
            )
        with self.open_writer() as authority:
            self.issued = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=ATTEMPT_ACTIONS, scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=1), idempotency_key=StableId("owner-token"),
                expected_revision=enrollment.receipt.semantic_revision,
            )
        self.plan = _plan(PROJECT, second=True)
        self.target = self.plan.work_items[0].definition.ref
        self.host = FakeHost(self.clock)
        self.service = AttemptService(self.auth, host=self.host, clock=self.clock)
        self._seed_plan()

    def open_writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def open_reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    def _seed_plan(self):
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO plan_revisions(plan_revision_id, sequence, state, content_digest) "
                    "VALUES (?, 1, 'accepted', ?)",
                    (str(self.plan.revision.plan_revision_id), self.plan.content_digest.hex),
                )
                for item in self.plan.work_items:
                    definition = item.definition
                    connection.execute(
                        "INSERT INTO work_items(work_item_id, definition_revision_id, title, outcome) "
                        "VALUES (?, ?, ?, ?)",
                        (str(definition.work_item_id), str(definition.definition_revision_id),
                         definition.title, definition.outcome),
                    )
                    connection.execute(
                        "INSERT INTO plan_revision_work_items(plan_revision_id, work_item_id) VALUES (?, ?)",
                        (str(self.plan.revision.plan_revision_id), str(definition.work_item_id)),
                    )

    @property
    def current_revision(self):
        with self.open_reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def test_claim_heartbeat_release_and_exact_retries_preserve_receipts(self):
        with self.open_writer() as authority:
            claim = self.service.claim(
                authority, self.issued.bearer_token, self.target, self.plan,
                idempotency_key=StableId("claim-one"), expected_revision=self.current_revision,
                workspace_id=StableId("workspace-one"),
            )
            self.assertTrue(claim.receipt.changed)
            attempt_id = StableId(claim.receipt.result["attempt_id"])
            old_lease = StableId(claim.receipt.result["lease_id"])
            replay = self.service.claim(
                authority, self.issued.bearer_token, self.target, self.plan,
                idempotency_key=StableId("claim-one"), expected_revision=claim.receipt.semantic_revision - 1,
                workspace_id=StableId("workspace-one"),
            )
            self.assertTrue(replay.replayed)
            self.assertEqual(replay.receipt, claim.receipt)
            self.assertEqual(self.host.qualification_calls, 1)
            snapshot = authority.connection.execute(
                "SELECT scope_json, scope_digest FROM attempt_scope_snapshots WHERE attempt_id = ?",
                (str(attempt_id),),
            ).fetchone()
            self.assertIsNotNone(snapshot)
            self.assertEqual(json.loads(snapshot["scope_json"]), {
                "locks": [], "paths": [["src/one", "write"]],
            })
            self.assertEqual(len(snapshot["scope_digest"]), 64)
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM attempt_scope_snapshots WHERE attempt_id = ?", (str(attempt_id),)
            ).fetchone()[0], 1)

            heartbeat = self.service.heartbeat(
                authority, self.issued.bearer_token,
                EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, attempt_id), old_lease, self.plan,
                idempotency_key=StableId("heartbeat-one"),
                expected_revision=claim.receipt.semantic_revision,
            )
            new_lease = StableId(heartbeat.receipt.result["lease_id"])
            self.assertNotEqual(new_lease, old_lease)
            heart_replay = self.service.heartbeat(
                authority, self.issued.bearer_token,
                EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, attempt_id), old_lease, self.plan,
                idempotency_key=StableId("heartbeat-one"),
                expected_revision=claim.receipt.semantic_revision,
            )
            self.assertTrue(heart_replay.replayed)
            self.assertEqual(heart_replay.receipt, heartbeat.receipt)

            release = self.service.release(
                authority, self.issued.bearer_token,
                EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, attempt_id), new_lease,
                idempotency_key=StableId("release-one"),
                expected_revision=heartbeat.receipt.semantic_revision,
            )
            self.assertEqual(release.receipt.result["state"], AttemptState.RELEASED.value)
            release_replay = self.service.release(
                authority, self.issued.bearer_token,
                EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, attempt_id), new_lease,
                idempotency_key=StableId("release-one"),
                expected_revision=heartbeat.receipt.semantic_revision,
            )
            self.assertTrue(release_replay.replayed)
            self.assertEqual(release_replay.receipt, release.receipt)
            self.assertEqual(self.host.inspection_calls, 1)
            row = authority.connection.execute(
                "SELECT state, lease_id, lease_expires_at FROM attempts WHERE attempt_id = ?",
                (str(attempt_id),),
            ).fetchone()
            self.assertEqual(tuple(row), ("released", None, None))

    def test_a_second_live_claim_for_the_same_definition_is_refused_without_churn(self):
        with self.open_writer() as authority:
            events_before = authority.connection.execute("SELECT count(*) FROM authority_events").fetchone()[0]
            first = self.service.claim(
                authority, self.issued.bearer_token, self.target, self.plan,
                idempotency_key=StableId("claim-one"), expected_revision=self.current_revision,
                workspace_id=StableId("workspace-one"),
            )
            before = self.current_revision
            with self.assertRaises(AttemptAdmissionDeniedError):
                self.service.claim(
                    authority, self.issued.bearer_token, self.target, self.plan,
                    idempotency_key=StableId("claim-two"), expected_revision=before,
                    workspace_id=StableId("workspace-two"),
                )
            self.assertEqual(self.current_revision, before)
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM attempts").fetchone()[0], 1)
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM authority_events").fetchone()[0], events_before + 1)
            self.assertNotEqual(first.receipt.result["attempt_id"], "")

    def test_heartbeat_during_inspection_invalidates_release_snapshot(self):
        with self.open_writer() as authority:
            claim = self.service.claim(
                authority, self.issued.bearer_token, self.target, self.plan,
                idempotency_key=StableId("claim-one"), expected_revision=self.current_revision,
                workspace_id=StableId("workspace-one"),
            )
            attempt_ref = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT,
                                   StableId(claim.receipt.result["attempt_id"]))
            original_lease = StableId(claim.receipt.result["lease_id"])

        def renew_after_snapshot():
            with self.open_writer() as writer:
                self.service.heartbeat(
                    writer, self.issued.bearer_token, attempt_ref, original_lease, self.plan,
                    idempotency_key=StableId("heartbeat-race"),
                )

        self.host.before_return = renew_after_snapshot
        before = self.current_revision
        with self.open_writer() as authority:
            with self.assertRaises(AttemptObservationMismatchError):
                self.service.release(
                    authority, self.issued.bearer_token, attempt_ref, original_lease,
                    idempotency_key=StableId("release-raced"),
                )
        self.assertEqual(self.current_revision, before + 1)  # The heartbeat committed; release did not.
        with self.open_reader() as authority:
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM command_idempotency WHERE idempotency_key = 'release-raced'"
            ).fetchone()[0], 0)

    def test_expiry_quarantines_dirty_work_and_clean_release_is_explicit(self):
        with self.open_writer() as authority:
            claim = self.service.claim(
                authority, self.issued.bearer_token, self.target, self.plan,
                idempotency_key=StableId("claim-one"), expected_revision=self.current_revision,
                workspace_id=StableId("workspace-one"),
            )
        attempt_ref = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT,
                               StableId(claim.receipt.result["attempt_id"]))
        lease_id = StableId(claim.receipt.result["lease_id"])
        self.clock.value = NOW + timedelta(minutes=3)
        self.host.source = SourceSafety.DIRTY
        with self.open_writer() as authority:
            reconciled = self.service.reconcile_expired(
                authority, self.issued.bearer_token, attempt_ref,
                idempotency_key=StableId("reconcile-one"),
            )
            self.assertEqual(reconciled.receipt.result["state"], AttemptState.QUARANTINED.value)
            revision_after_quarantine = reconciled.receipt.semantic_revision

        with self.open_reader() as reopened:
            row = reopened.connection.execute(
                "SELECT payload_json FROM authority_events WHERE event_kind = 'todo.attempt.quarantined' "
                "ORDER BY semantic_revision DESC LIMIT 1"
            ).fetchone()
            audit = json.loads(row["payload_json"])["safety_observation"]
            self.assertEqual(audit["source"], SourceSafety.DIRTY.value)
            self.assertEqual(audit["process"], ProcessLiveness.STOPPED.value)
            self.assertEqual(audit["children"], ChildActivity.NONE.value)
            self.assertEqual(audit["receipt"]["correlation_id"], str(attempt_ref.entity_id))
            self.assertEqual(audit["receipt"]["provider_id"], "fixture-host")

        with self.open_writer() as authority:
            self.host.source = SourceSafety.CLEAN
            released = self.service.release(
                authority, self.issued.bearer_token, attempt_ref, lease_id,
                idempotency_key=StableId("release-clean"),
                expected_revision=revision_after_quarantine,
            )
            self.assertEqual(released.receipt.result["state"], AttemptState.RELEASED.value)
            self.assertGreater(released.receipt.semantic_revision, revision_after_quarantine)

    def test_run_and_assignment_bound_grant_is_carried_through_the_lifecycle(self):
        run = EntityRef(PROJECT.project_id, EntityKind.RUN, StableId("run-bound"))
        assignment = EntityRef(PROJECT.project_id, EntityKind.ASSIGNMENT, StableId("assignment-bound"))
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO runs(run_id, plan_revision_id, state) VALUES (?, ?, 'open')",
                    (str(run.entity_id), str(self.plan.revision.plan_revision_id)),
                )
                connection.execute(
                    "INSERT INTO assignments(assignment_id, work_item_id, definition_revision_id, run_id) "
                    "VALUES (?, ?, ?, ?)",
                    (str(assignment.entity_id), str(self.target.entity_id),
                     str(self.target.definition_revision_id), str(run.entity_id)),
                )
            bound = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=ATTEMPT_ACTIONS, scope=self.target,
                run=run, assignment=assignment, expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("bound-token"), expected_revision=self.current_revision,
            )
            with authority.write_transaction() as connection:
                connection.execute(
                    "UPDATE assignments SET assignee_actor_id = ?, assignee_incarnation_id = ? "
                    "WHERE assignment_id = ?",
                    (str(bound.capability.actor.entity_id), str(bound.capability.actor.incarnation_id),
                     str(assignment.entity_id)),
                )
            claim = self.service.claim(
                authority, bound.bearer_token, self.target, self.plan,
                idempotency_key=StableId("bound-claim"), expected_revision=bound.receipt.semantic_revision,
                workspace_id=StableId("workspace-bound"), run=run, assignment=assignment,
            )
            attempt_ref = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT,
                                   StableId(claim.receipt.result["attempt_id"]))
            heartbeat = self.service.heartbeat(
                authority, bound.bearer_token, attempt_ref,
                StableId(claim.receipt.result["lease_id"]), self.plan,
                idempotency_key=StableId("bound-heartbeat"),
                expected_revision=claim.receipt.semantic_revision,
            )
            released = self.service.release(
                authority, bound.bearer_token, attempt_ref,
                StableId(heartbeat.receipt.result["lease_id"]),
                idempotency_key=StableId("bound-release"),
                expected_revision=heartbeat.receipt.semantic_revision,
            )
            self.assertEqual(released.receipt.result["state"], AttemptState.RELEASED.value)

    def test_reported_expiry_is_marked_uncertain_not_invalid_expired_transition(self):
        with self.open_writer() as authority:
            claim = self.service.claim(
                authority, self.issued.bearer_token, self.target, self.plan,
                idempotency_key=StableId("claim-one"), expected_revision=self.current_revision,
                workspace_id=StableId("workspace-one"),
            )
            authority.connection.execute(
                "UPDATE attempts SET state = 'reported' WHERE attempt_id = ?",
                (claim.receipt.result["attempt_id"],),
            )
        attempt_ref = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT,
                               StableId(claim.receipt.result["attempt_id"]))
        self.clock.value = NOW + timedelta(minutes=3)
        with self.open_writer() as authority:
            reconciled = self.service.reconcile_expired(
                authority, self.issued.bearer_token, attempt_ref,
                idempotency_key=StableId("reported-reconcile"),
            )
        self.assertEqual(reconciled.receipt.result["state"], AttemptState.UNCERTAIN.value)


if __name__ == "__main__":
    unittest.main()
