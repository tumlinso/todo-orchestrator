"""Independent disposable-authority checks for authenticated plan commits."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AuthenticationFailedError,
    AuthenticatedPrincipal,
    AuthorityAuthService,
    CommandDispatcher,
    SQLiteAuthority,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.contracts import ActorKind, EntityKind, EntityRef, Project, Sha256Digest, StableId
from todo_orchestrator.planning import ExplicitRetirement, PlanCommitError, PlanService

try:
    from .test_package import package_document
except ImportError:
    from test_package import package_document


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("commit-project"), StableId("commit-authority"))
OWNER_PASSWORD = "independent commit fixture owner phrase 927"
PLAN_COMMIT = StableId("todo.plan.commit")
CAPABILITY_DELEGATE = StableId("todo.capability.delegate")
CAPABILITY_REVOKE = StableId("todo.capability.revoke")


class MutableClock:
    def __call__(self):
        return NOW


class FixtureAuthenticator:
    provider_id = "independent-plan-fixture"

    def authenticate(self, credential):
        if credential == "plan-worker":
            return AuthenticatedPrincipal("plan-worker-subject", ActorKind.AUTOMATION, "plan worker")
        return None


class PlanCommitIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(
            self.dispatcher, clock=MutableClock(), authenticator=FixtureAuthenticator()
        )
        self.plans = PlanService(self.auth)
        with self.open_writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="fixture owner",
                idempotency_key=StableId("enroll-owner"), expected_revision=0,
            )
            self.root = self.auth.login_local_owner(
                authority, OWNER_PASSWORD,
                actions=(PLAN_COMMIT, CAPABILITY_DELEGATE, CAPABILITY_REVOKE),
                scope=PROJECT.ref, expires_at=NOW + timedelta(days=1),
                idempotency_key=StableId("issue-root"),
                expected_revision=enrollment.receipt.semantic_revision,
            )
            self.worker = self.auth.delegate(
                authority, self.root.bearer_token, "plan-worker", actions=(PLAN_COMMIT,),
                scope=PROJECT.ref, expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("delegate-plan-worker"),
                expected_revision=self.root.receipt.semantic_revision,
            )

    def open_writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def open_reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    @staticmethod
    def package_text(document=None):
        value = deepcopy(package_document() if document is None else document)

        def rebind_project_ids(item):
            if isinstance(item, dict):
                for key, child in tuple(item.items()):
                    if key == "project_id" and child == "project-a":
                        item[key] = str(PROJECT.project_id)
                    elif key == "authority_id" and child == "authority-a":
                        item[key] = str(PROJECT.authority_id)
                    else:
                        rebind_project_ids(child)
            elif isinstance(item, list):
                for child in item:
                    rebind_project_ids(child)

        rebind_project_ids(value)
        # The package fixture's supersedes reference intentionally describes an
        # unrelated old-plan example. A first import must not invent that history.
        for work_item in value.get("work_items", []):
            work_item.pop("supersedes", None)
        return json.dumps(value, sort_keys=True)

    def commit_preview(self, authority, token, package_json, idempotency_key):
        change_set = self.plans.preview(authority, package_json)
        result = self.plans.commit(
            authority, token, package_json,
            reviewed_digest=change_set.digest,
            idempotency_key=StableId(idempotency_key),
            expected_authority_revision=change_set.expected_authority_revision,
            expected_plan_revision_id=change_set.expected_revision_id,
        )
        return change_set, result

    def stable_state(self):
        with self.open_reader() as authority:
            fingerprint = self.dispatcher.logical_fingerprint(authority)
            with authority.read_transaction() as connection:
                revision = connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
                ).fetchone()[0]
                counts = tuple(
                    connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in (
                        "plan_revisions", "plan_revision_snapshots", "work_items",
                        "plan_revision_work_items", "authority_events", "command_receipts",
                        "command_idempotency",
                    )
                )
            return fingerprint, revision, counts

    @staticmethod
    def work_ref(plan, work_item_id):
        return next(
            item.definition.ref for item in plan.work_items
            if item.definition.work_item_id == StableId(work_item_id)
        )

    @staticmethod
    def history_document():
        document = deepcopy(package_document())
        verify = next(item for item in document["work_items"] if item["id"] == "verify")
        verify["parent_id"] = "build"
        verify["requirement_groups"] = [{
            "kind": "prerequisite", "mode": "all", "members": ["verify-build"],
        }]
        document["requirements"].append({
            "id": "verify-build", "work_item_id": "verify", "kind": "prerequisite",
            "description": "Build must exist before verification",
            "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
        })
        cleanup = deepcopy(verify)
        cleanup.update({
            "id": "cleanup", "title": "Clean temporary package files",
            "objective": "Remove temporary package files", "outcome": "Temporary files are removed",
        })
        cleanup.pop("parent_id", None)
        cleanup.pop("requirement_groups", None)
        document["work_items"].append(cleanup)
        return document

    @staticmethod
    def simple_document():
        return {
            "format": "todo-orchestrator.plan", "schema_version": 1,
            "package_id": "independent-commit", "project": {
                "project_id": str(PROJECT.project_id), "authority_id": str(PROJECT.authority_id),
            },
            "work_items": [{
                "id": name, "title": name, "objective": "Deliver " + name,
                "outcome": "Ready " + name,
                "scope": {"paths": [], "concepts": [name]},
                "acceptance": {"assertions": ["ready"], "required_evidence": [],
                               "allowed_dispositions": ["completed"]},
            } for name in ("alpha", "beta")],
        }

    def seed_history_facts(self, plan):
        build_ref = self.work_ref(plan, "build")
        verify_ref = self.work_ref(plan, "verify")
        actor = self.root.capability.actor
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                # Deliberately fixture-only rows: the test concerns replan behavior
                # against already accepted execution facts, not their command APIs.
                connection.execute(
                    "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, disposition, "
                    "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at) "
                    "VALUES (?, ?, ?, 1, 'completed', ?, ?, ?)",
                    ("accepted-build", str(build_ref.entity_id), str(build_ref.definition_revision_id),
                     str(actor.entity_id), str(actor.incarnation_id), NOW.isoformat()),
                )
                connection.execute(
                    "INSERT INTO attempts(attempt_id, work_item_id, definition_revision_id, actor_id, "
                    "actor_incarnation_id, state, lease_id, lease_expires_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
                    ("active-verify", str(verify_ref.entity_id), str(verify_ref.definition_revision_id),
                     str(actor.entity_id), str(actor.incarnation_id), "lease-verify",
                     (NOW + timedelta(hours=1)).isoformat()),
                )

    def test_first_commit_survives_reopen_and_identical_reimport_is_noop(self):
        package_json = self.package_text()
        with self.open_writer() as authority:
            before = self.plans.read_snapshot(authority)
            self.assertIsNone(before.accepted_plan)
            first_preview = self.plans.preview(authority, package_json)
            self.assertIsNone(first_preview.expected_revision_id)
            first = self.plans.commit(
                authority, self.root.bearer_token, package_json,
                reviewed_digest=first_preview.digest,
                idempotency_key=StableId("initial-plan-commit"),
                expected_authority_revision=first_preview.expected_authority_revision,
                expected_plan_revision_id=None,
            )
            self.assertTrue(first.receipt.changed)
            self.assertEqual(first.receipt.semantic_revision, first_preview.expected_authority_revision + 1)

        with self.open_reader() as authority:
            snapshot = self.plans.read_snapshot(authority)
            accepted = self.plans.load_accepted_plan(authority)
            self.assertIsNotNone(snapshot.accepted_plan)
            self.assertIsNotNone(accepted)
            self.assertEqual(snapshot.accepted_plan.revision.plan_revision_id, accepted.revision.plan_revision_id)
            self.assertTrue(accepted.source_manifests_supplied)
            self.assertEqual(len(accepted.source_manifests), 2)
            reopened_preview = self.plans.preview(authority, package_json)
            self.assertTrue(reopened_preview.is_noop)
            self.assertEqual(reopened_preview.expected_revision_id, accepted.revision.plan_revision_id)
            self.assertEqual(reopened_preview.expected_authority_revision, snapshot.authority_revision)

        before_noop = self.stable_state()
        with self.open_writer() as authority:
            noop = self.plans.commit(
                authority, self.root.bearer_token, package_json,
                reviewed_digest=reopened_preview.digest,
                idempotency_key=StableId("identical-reimport"),
                expected_authority_revision=reopened_preview.expected_authority_revision,
                expected_plan_revision_id=reopened_preview.expected_revision_id,
            )
        after_noop = self.stable_state()
        self.assertFalse(noop.receipt.changed)
        self.assertIsNone(noop.receipt.event_id)
        self.assertEqual(after_noop[0:2], before_noop[0:2])
        self.assertEqual(after_noop[2][0:5], before_noop[2][0:5])

    def test_authenticated_exact_retry_replays_but_revoked_retry_is_refused_without_churn(self):
        package_json = self.package_text()
        with self.open_writer() as authority:
            change_set = self.plans.preview(authority, package_json)
            command = dict(
                reviewed_digest=change_set.digest,
                idempotency_key=StableId("worker-plan-commit"),
                expected_authority_revision=change_set.expected_authority_revision,
                expected_plan_revision_id=change_set.expected_revision_id,
            )
            committed = self.plans.commit(authority, self.worker.bearer_token, package_json, **command)
            replayed = self.plans.commit(authority, self.worker.bearer_token, package_json, **command)
            self.assertTrue(committed.receipt.changed)
            self.assertTrue(replayed.replayed)
            self.assertEqual(replayed.receipt, committed.receipt)
            self.auth.revoke_family(
                authority, self.root.bearer_token, self.worker.capability.capability_id,
                idempotency_key=StableId("revoke-plan-worker"),
            )

        after_revoke = self.stable_state()
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.plans.commit(authority, self.worker.bearer_token, package_json, **command)
        self.assertEqual(self.stable_state(), after_revoke)

    def test_stale_and_tampered_reviews_are_rejected_without_state_churn(self):
        original_json = self.package_text(self.simple_document())
        with self.open_writer() as authority:
            original_preview = self.plans.preview(authority, original_json)
            self.plans.commit(
                authority, self.root.bearer_token, original_json,
                reviewed_digest=original_preview.digest,
                idempotency_key=StableId("stale-seed"),
                expected_authority_revision=original_preview.expected_authority_revision,
                expected_plan_revision_id=None,
            )
            revised_document = self.simple_document()
            revised_document["work_items"][0]["title"] = "Reviewed newer package"
            revised_json = self.package_text(revised_document)
            current_preview = self.plans.preview(authority, revised_json)
            self.plans.commit(
                authority, self.root.bearer_token, revised_json,
                reviewed_digest=current_preview.digest,
                idempotency_key=StableId("stale-advance"),
                expected_authority_revision=current_preview.expected_authority_revision,
                expected_plan_revision_id=current_preview.expected_revision_id,
            )
            before_stale = self.stable_state()
            with self.assertRaises(StaleAuthorityRevisionError):
                self.plans.commit(
                    authority, self.root.bearer_token, original_json,
                    reviewed_digest=original_preview.digest,
                    idempotency_key=StableId("stale-review"),
                    expected_authority_revision=original_preview.expected_authority_revision,
                    expected_plan_revision_id=None,
                )
            self.assertEqual(self.stable_state(), before_stale)

            tampered_document = deepcopy(revised_document)
            tampered_document["work_items"][0]["title"] = "Unreviewed package text"
            tampered_json = self.package_text(tampered_document)
            current_review = self.plans.preview(authority, revised_json)
            before_tamper = self.stable_state()
            with self.assertRaises(PlanCommitError):
                self.plans.commit(
                    authority, self.root.bearer_token, tampered_json,
                    reviewed_digest=current_review.digest,
                    idempotency_key=StableId("tampered-review"),
                    expected_authority_revision=current_review.expected_authority_revision,
                    expected_plan_revision_id=current_review.expected_revision_id,
                )
            self.assertEqual(self.stable_state(), before_tamper)

    def test_unrelated_replan_preserves_exact_history_and_guards_active_or_accepted_work(self):
        initial_json = self.package_text(self.history_document())
        with self.open_writer() as authority:
            initial_preview = self.plans.preview(authority, initial_json)
            initial_result = self.plans.commit(
                authority, self.root.bearer_token, initial_json,
                reviewed_digest=initial_preview.digest,
                idempotency_key=StableId("history-initial"),
                expected_authority_revision=initial_preview.expected_authority_revision,
                expected_plan_revision_id=None,
            )
        with self.open_reader() as authority:
            original = self.plans.load_accepted_plan(authority)
        old_build = self.work_ref(original, "build")
        old_verify = self.work_ref(original, "verify")
        old_cleanup = self.work_ref(original, "cleanup")
        old_requirement = next(item for item in original.requirements
                               if item.definition.requirement_id == StableId("verify-build"))
        self.assertEqual(old_verify.definition_revision_id, old_requirement.definition.definition_revision_id)
        self.assertEqual(old_requirement.target.reference, old_build)
        original_verify = next(item for item in original.work_items
                               if item.definition.work_item_id == StableId("verify"))
        self.assertEqual(original_verify.definition.parent, old_build)
        self.seed_history_facts(original)

        changed_document = self.history_document()
        cleanup = next(item for item in changed_document["work_items"] if item["id"] == "cleanup")
        cleanup["title"] = "Clean generated package files"
        changed_json = self.package_text(changed_document)
        with self.open_writer() as authority:
            preview = self.plans.preview(authority, changed_json)
            self.assertFalse(preview.conflicts, preview.conflicts)
            changed = self.plans.commit(
                authority, self.root.bearer_token, changed_json,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("history-replan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            self.assertTrue(changed.receipt.changed)
        with self.open_reader() as authority:
            current = self.plans.load_accepted_plan(authority)
            historical = self.plans.load_accepted_plan(authority, original.revision.plan_revision_id)
            self.assertEqual(historical, original)
            self.assertEqual(self.work_ref(current, "build"), old_build)
            self.assertEqual(self.work_ref(current, "verify"), old_verify)
            retained_verify = next(item for item in current.work_items
                                   if item.definition.work_item_id == StableId("verify"))
            retained_requirement = next(item for item in current.requirements
                                        if item.definition.requirement_id == StableId("verify-build"))
            self.assertEqual(retained_verify.definition.parent, old_build)
            self.assertEqual(retained_requirement.target.reference, old_build)
            self.assertEqual(retained_requirement.definition.definition_revision_id,
                             retained_verify.definition.definition_revision_id)
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM outcomes WHERE outcome_id = 'accepted-build' AND work_item_id = ? "
                "AND definition_revision_id = ?", (str(old_build.entity_id), str(old_build.definition_revision_id)),
            ).fetchone()[0], 1)
            current_cleanup = self.work_ref(current, "cleanup")

        # An active claim blocks mutation of its exact definition, even when
        # unrelated work has since received a new revision.
        active_change = deepcopy(changed_document)
        verify = next(item for item in active_change["work_items"] if item["id"] == "verify")
        verify["scope"]["concepts"] = ["verification", "new scope"]
        active_json = self.package_text(active_change)
        before_active_refusal = self.stable_state()
        with self.open_writer() as authority:
            active_preview = self.plans.preview(authority, active_json)
            self.assertIn("active_attempt_requires_transition", {item.code for item in active_preview.conflicts})
            with self.assertRaises(PlanCommitError):
                self.plans.commit(
                    authority, self.root.bearer_token, active_json,
                    reviewed_digest=active_preview.digest,
                    idempotency_key=StableId("active-verify-replan"),
                    expected_authority_revision=active_preview.expected_authority_revision,
                    expected_plan_revision_id=active_preview.expected_revision_id,
                )
        self.assertEqual(self.stable_state(), before_active_refusal)

        # Accepted terminal evidence also prevents weakening its acceptance gate.
        terminal_change = deepcopy(changed_document)
        build = next(item for item in terminal_change["work_items"] if item["id"] == "build")
        build["acceptance"]["allowed_dispositions"] = ["no_change"]
        terminal_json = self.package_text(terminal_change)
        with self.open_writer() as authority:
            terminal_preview = self.plans.preview(authority, terminal_json)
            self.assertTrue(terminal_preview.conflicts, "completed work must not silently lose its acceptance contract")
            before_terminal_refusal = self.stable_state()
            with self.assertRaises(PlanCommitError):
                self.plans.commit(
                    authority, self.root.bearer_token, terminal_json,
                    reviewed_digest=terminal_preview.digest,
                    idempotency_key=StableId("completed-build-replan"),
                    expected_authority_revision=terminal_preview.expected_authority_revision,
                    expected_plan_revision_id=terminal_preview.expected_revision_id,
                )
            self.assertEqual(self.stable_state(), before_terminal_refusal)

        # A true exact retirement leaves old accepted history readable but excludes
        # that definition from current membership.
        retirement_document = deepcopy(changed_document)
        retirement_document["work_items"] = [item for item in retirement_document["work_items"] if item["id"] != "cleanup"]
        retirement_json = self.package_text(retirement_document)
        with self.open_writer() as authority:
            retirement_preview = self.plans.preview(
                authority, retirement_json, explicit_retirements=(ExplicitRetirement(current_cleanup),),
            )
            self.assertFalse(retirement_preview.conflicts, retirement_preview.conflicts)
            retired = self.plans.commit(
                authority, self.root.bearer_token, retirement_json,
                reviewed_digest=retirement_preview.digest,
                idempotency_key=StableId("cleanup-retirement"),
                expected_authority_revision=retirement_preview.expected_authority_revision,
                expected_plan_revision_id=retirement_preview.expected_revision_id,
                explicit_retirements=(ExplicitRetirement(current_cleanup),),
            )
            self.assertTrue(retired.receipt.changed)
        with self.open_reader() as authority:
            current = self.plans.load_accepted_plan(authority)
            historical = self.plans.load_accepted_plan(authority, initial_result.receipt.result["plan_revision_id"])
            self.assertNotIn(current_cleanup, {item.definition.ref for item in current.work_items})
            self.assertIn(old_cleanup, {item.definition.ref for item in historical.work_items})


if __name__ == "__main__":
    unittest.main()
