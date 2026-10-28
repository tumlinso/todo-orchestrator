"""Regression for monotonic plans whose dependency-source order changes."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api import PlanPreviewV1, ProviderComposition, TodoApplication
from todo_orchestrator.contracts import StableId


class SnapshotDependencyOrderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-dependency-order-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.project_id = StableId("dependency-order-project")
        self.authority_id = StableId("dependency-order-authority")

    def package(self, work_items, dependencies, package_id):
        return json.dumps({
            "format": "todo-orchestrator.plan",
            "schema_version": 1,
            "package_id": package_id,
            "project": {
                "project_id": str(self.project_id),
                "authority_id": str(self.authority_id),
            },
            "work_items": [
                {
                    "id": identifier,
                    "title": identifier,
                    "objective": "Preserve " + identifier,
                    "outcome": "Available: " + identifier,
                    "scope": {"paths": [], "concepts": [identifier]},
                    "acceptance": {
                        "assertions": ["the work item is retained"],
                        "required_evidence": [],
                        "allowed_dispositions": ["completed"],
                    },
                }
                for identifier in work_items
            ],
            "dependencies": [
                {
                    "source": {
                        "project_id": str(self.project_id),
                        "kind": "work_item",
                        "entity_id": source,
                    },
                    "mode": "all",
                    "members": [{
                        "relation": "completion",
                        "target": {
                            "project_id": str(self.project_id),
                            "kind": "work_item",
                            "entity_id": target,
                        },
                    }],
                }
                for source, target in dependencies
            ],
        }, sort_keys=True, separators=(",", ":"))

    def commit(self, session, package_text, key):
        preview = session.preview_plan(package_text)
        self.assertFalse(preview.has_conflicts)
        serialized = PlanPreviewV1.from_json(preview.to_json())
        self.assertEqual(serialized, preview)
        return session.commit_plan(package_text, serialized, idempotency_key=StableId(key))

    def test_additive_plan_canonically_orders_retained_and_new_dependency_groups(self):
        with TodoApplication.initialize(
            self.root,
            project_id=self.project_id,
            repository_id=StableId("dependency-order-repository"),
            authority_id=self.authority_id,
            owner_credential="ephemeral dependency order fixture credential",
            providers=ProviderComposition(),
        ) as owner:
            token = owner.bearer_token
            initial = self.package(
                ["root", "z_old"], [("z_old", "root")], "dependency-order-initial",
            )
            first = self.commit(owner, initial, "dependency-order-initial-commit")
            first_model = owner.read_model()
            first_work = first_model.sections["work_definitions"]
            self.assertEqual(
                {item["work_item_id"] for item in first_work}, {"root", "z_old"},
            )

            additive = self.package(
                ["a_seed", "a_new"], [("a_new", "a_seed")], "dependency-order-additive",
            )
            second = self.commit(owner, additive, "dependency-order-additive-commit")
            second_model = owner.read_model()
            self.assertEqual(second.semantic_revision, first.semantic_revision + 1)
            second_work = second_model.sections["work_definitions"]
            self.assertEqual(
                {item["work_item_id"] for item in second_work},
                {"root", "z_old", "a_seed", "a_new"},
            )
            by_id = {item["work_item_id"]: item for item in second_work}
            for item in first_work:
                self.assertEqual(by_id[item["work_item_id"]], item)

        # Reopening and replaying the same complete plan exercises stored
        # snapshot reconstruction rather than trusting only the commit receipt.
        with TodoApplication.open(
            self.root,
            bearer_token=token,
            providers=ProviderComposition(),
        ) as reopened:
            roundtrip = reopened.preview_plan(additive)
            self.assertFalse(roundtrip.has_conflicts)
            self.assertEqual(roundtrip.expected_authority_revision, second.semantic_revision)
            replay = reopened.commit_plan(
                additive, PlanPreviewV1.from_json(roundtrip.to_json()),
                idempotency_key=StableId("dependency-order-noop-replay"),
            )
            self.assertFalse(replay.changed)
            self.assertEqual(reopened.read_model().semantic_revision, second.semantic_revision)


if __name__ == "__main__":
    unittest.main()
