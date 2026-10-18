"""Plan-service behavior against disposable standalone authorities."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, SQLiteAuthority
from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.planning.service import PlanCommitError, PlanService


class PlanServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "plans.sqlite3"
        self.project = Project(StableId("project"), StableId("authority"))
        SQLiteAuthority.initialize(self.path, self.project)
        self.authority = SQLiteAuthority.open_writer(self.path, self.project)
        self.addCleanup(self.authority.close)
        self.dispatcher = CommandDispatcher()
        now = datetime(2026, 10, 18, tzinfo=timezone.utc)
        self.auth = AuthorityAuthService(self.dispatcher, clock=lambda: now)
        self.service = PlanService(self.auth)
        enrollment = self.auth.enroll_local_owner(
            self.authority, "local fixture credential 491", label="owner",
            idempotency_key=StableId("enroll"), expected_revision=0)
        self.owner = self.auth.login_local_owner(
            self.authority, "local fixture credential 491",
            actions=(StableId("todo.plan.commit"),), expires_at=now + timedelta(days=1),
            idempotency_key=StableId("login"), expected_revision=enrollment.receipt.semantic_revision)
        self.document = {
            "format": "todo-orchestrator.plan", "schema_version": 1, "package_id": "fixture",
            "project": {"project_id": "project", "authority_id": "authority"},
            "work_items": [{
                "id": name, "title": name, "objective": "Deliver " + name, "outcome": "Ready " + name,
                "scope": {"paths": [], "concepts": [name]},
                "acceptance": {"assertions": ["ready"], "required_evidence": [], "allowed_dispositions": ["completed"]},
                "motivation": "Retain authored intent",
                "references": [{"label": "spec", "uri": "docs/spec.md"}],
            } for name in ("alpha", "beta")],
        }

    def commit(self, document, key):
        text = json.dumps(document)
        preview = self.service.preview(self.authority, text)
        result = self.service.commit(
            self.authority, self.owner.bearer_token, text,
            reviewed_digest=preview.digest, idempotency_key=StableId(key),
            expected_authority_revision=preview.expected_authority_revision,
            expected_plan_revision_id=preview.expected_revision_id)
        return preview, result, self.service.load_accepted_plan(self.authority)

    def test_reversion_is_a_new_revision_and_preserves_prior_snapshots(self):
        _, first, original = self.commit(self.document, "first")
        revised = deepcopy(self.document)
        revised["work_items"][0]["title"] = "alpha revised"
        _, second, intermediate = self.commit(revised, "second")
        _, third, restored = self.commit(self.document, "third")
        self.assertEqual([original.revision.sequence, intermediate.revision.sequence, restored.revision.sequence], [1, 2, 3])
        self.assertEqual(restored.revision.based_on_revision_id, intermediate.revision.plan_revision_id)
        self.assertEqual(len({result.receipt.result["plan_revision_id"] for result in (first, second, third)}), 3)
        historical = self.service.load_accepted_plan(self.authority, original.revision.plan_revision_id)
        self.assertEqual(historical, original)
        self.assertEqual(restored.work_items[0].definition.title, "alpha")
        self.assertEqual(original.work_items[1].definition.ref, restored.work_items[1].definition.ref)

    def test_partial_update_persists_omitted_records_and_authored_context(self):
        _, _, original = self.commit(self.document, "initial")
        partial = deepcopy(self.document)
        partial["work_items"] = [partial["work_items"][0]]
        partial["work_items"][0]["title"] = "Changed alpha"
        del partial["work_items"][0]["references"]
        del partial["work_items"][0]["motivation"]
        _, _, accepted = self.commit(partial, "partial")
        self.assertEqual(len(accepted.work_items), 2)
        self.assertEqual(accepted.work_items[0].context.references, original.work_items[0].context.references)
        self.assertEqual(accepted.work_items[0].context.motivation, original.work_items[0].context.motivation)
        self.assertEqual(accepted.work_items[1], original.work_items[1])

    def test_invalid_package_and_duplicate_service_registration_do_not_mutate(self):
        PlanService(self.auth)
        before = self.dispatcher.logical_fingerprint(self.authority)
        with self.assertRaises(PlanCommitError):
            self.service.preview(self.authority, '{"format":"unknown"}')
        self.assertEqual(before, self.dispatcher.logical_fingerprint(self.authority))

    def test_exact_retry_uses_semantic_intent_across_json_and_generation_cosmetics(self):
        preview, first, _ = self.commit(self.document, "semantic-retry")
        cosmetic = deepcopy(self.document)
        cosmetic["generation_metadata"] = {"generator": "different annotation"}
        replay = self.service.commit(
            self.authority, self.owner.bearer_token, json.dumps(cosmetic, indent=4),
            reviewed_digest=preview.digest, idempotency_key=StableId("semantic-retry"),
            expected_authority_revision=preview.expected_authority_revision,
            expected_plan_revision_id=preview.expected_revision_id)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, first.receipt)

    def test_explicit_historical_prerequisite_is_not_retargeted_to_current_definition(self):
        _, _, first = self.commit(self.document, "historical-base")
        old_alpha = first.work_items[0].definition.ref
        revised = deepcopy(self.document)
        revised["work_items"][0]["title"] = "New alpha"
        _, _, second = self.commit(revised, "new-alpha")
        self.assertNotEqual(second.work_items[0].definition.ref, old_alpha)
        revised["requirements"] = [{
            "id": "historical-alpha", "work_item_id": "beta", "kind": "prerequisite",
            "description": "Use the original accepted definition", "target": {
                "project_id": "project", "kind": "work_item", "entity_id": "alpha",
                "revision_id": str(old_alpha.definition_revision_id),
            },
        }]
        revised["work_items"][1]["requirement_groups"] = [{
            "kind": "prerequisite", "mode": "all", "members": ["historical-alpha"],
        }]
        # The package supplies beta only; alpha's current definition is retained
        # by omission, while this target explicitly names its older version.
        revised["work_items"] = [revised["work_items"][1]]
        _, _, third = self.commit(revised, "bind-historical-alpha")
        self.assertEqual(third.requirements[0].target.reference, old_alpha)
        self.assertEqual(third.requirements[0].definition.target, old_alpha)

    def test_split_and_merge_keep_exact_predecessor_lineage_and_history(self):
        _, _, original = self.commit(self.document, "lineage-base")
        predecessor = original.work_items[0].definition.ref

        def successor(name, predecessors):
            value = deepcopy(self.document["work_items"][0])
            value.update(id=name, title=name, supersedes=[{
                "project_id": str(ref.project_id), "kind": "work_item",
                "entity_id": str(ref.entity_id), "revision_id": str(ref.definition_revision_id),
            } for ref in predecessors])
            return value

        split = deepcopy(self.document)
        split["work_items"] = [successor("split-one", [predecessor]), successor("split-two", [predecessor])]
        _, _, divided = self.commit(split, "split")
        pieces = [item.definition.ref for item in divided.work_items if str(item.definition.work_item_id).startswith("split-")]
        self.assertEqual(len(pieces), 2)
        for item in divided.work_items:
            if item.definition.ref in pieces:
                self.assertEqual(item.definition.supersedes, (predecessor,))
        merge = deepcopy(self.document)
        merge["work_items"] = [successor("merged", pieces)]
        _, _, merged = self.commit(merge, "merge")
        current = next(item for item in merged.work_items if item.definition.work_item_id == StableId("merged"))
        self.assertEqual(set(current.definition.supersedes), set(pieces))
        self.assertEqual(self.service.load_accepted_plan(self.authority, original.revision.plan_revision_id), original)


if __name__ == "__main__":
    unittest.main()
