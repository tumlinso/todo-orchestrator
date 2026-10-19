"""The application facade authorizes and applies a reviewed legacy import."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api import LEGACY_IMPORT_ACTION, TodoApplication
from todo_orchestrator.authority.auth import CapabilityDeniedError
from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.migration import (
    LEGACY_PROJECT_SCHEMA_VERSION,
    LEGACY_SNAPSHOT_FORMAT,
    LEGACY_SNAPSHOT_VERSION,
    LEGACY_SOURCE_SYSTEM,
)
from todo_orchestrator.operations.export import AUTHORITY_READ_ACTION


OWNER_CREDENTIAL = "legacy migration facade credential 527"


def _snapshot() -> str:
    envelope = {
        "format": LEGACY_SNAPSHOT_FORMAT,
        "version": LEGACY_SNAPSHOT_VERSION,
        "source": {
            "system": LEGACY_SOURCE_SYSTEM,
            "project_id": "legacy-source-project",
            "schema_version": LEGACY_PROJECT_SCHEMA_VERSION,
            "authority_revision": 9,
            "exported_at": "2026-10-19T11:00:00Z",
        },
        "project": {"name": "Archived source project"},
        "tables": {
            "tasks": [{"id": "legacy-task-1", "status": "in_progress", "title": "Imported task"}],
            "task_dependencies": [],
            "events": [{"id": "event-1", "task_id": "legacy-task-1", "event_type": "created"}],
            "project_declarations": [{
                "kind": "orientation",
                "id": "legacy-guidance",
                "version": 2,
                "payload_json": "{\"purpose\":\"Preserve imported project direction\"}",
                "origin": "operator",
                "task_id": None,
                "retired": 0,
                "created_at": "2026-10-18T10:00:00Z",
                "revision": 7,
            }],
            "project_fragment_invalidations": [{
                "id": "invalidation-1", "kind": "orientation", "entity_id": "legacy-guidance",
                "revision": 8, "reason": "source changed",
            }],
        },
        "history": [{
            "source_table": "events",
            "source_id": "event-1",
            "entity_id": "legacy-task-1",
            "revision": 3,
            "occurred_at": "2026-10-18T12:00:00Z",
            "event_type": "created",
            "payload": {"title": "Imported task"},
        }],
    }
    body = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    envelope["snapshot_digest"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class LegacyMigrationFacadeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-legacy-import-api-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.project = Project(StableId("legacy-api-project"), StableId("legacy-api-authority"))

    def initialize(self, *, owner_actions):
        return TodoApplication.initialize(
            self.root,
            project_id=self.project.project_id,
            repository_id=StableId("legacy-api-repository"),
            authority_id=self.project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            owner_actions=owner_actions,
        )

    def test_preview_import_and_history_use_public_facade(self):
        actions = (
            StableId("todo.plan.commit"), AUTHORITY_READ_ACTION, LEGACY_IMPORT_ACTION,
        )
        with self.initialize(owner_actions=actions) as session:
            snapshot = _snapshot()
            preview = session.preview_legacy_import(snapshot)
            self.assertEqual(preview.project_id, self.project.project_id)
            self.assertEqual(preview.included_task_ids, ("legacy-task-1",))

            receipt = session.import_legacy_snapshot(
                snapshot,
                session.serialize("legacy-import-preview", preview),
                idempotency_key=StableId("legacy-api-import"),
            )
            self.assertEqual(receipt.imported_work_items, 1)
            self.assertEqual(receipt.history_records, 1)
            self.assertIsNotNone(receipt.plan_revision_id)

            page = session.search_legacy_history("created", import_id=receipt.import_id)
            self.assertEqual(len(page.records), 1)
            self.assertEqual(page.records[0].source_id, "event-1")
            native_id = json.loads(preview.package_json)["work_items"][0]["id"]
            current = session.read_legacy_current_tasks(import_id=receipt.import_id)
            self.assertEqual(len(current.records), 1)
            task = current.records[0]
            self.assertEqual(task.source_project_id, StableId("legacy-source-project"))
            self.assertEqual(task.source_task_id, "legacy-task-1")
            self.assertEqual(task.source_title, "Imported task")
            self.assertEqual(task.source_status, "in_progress")
            self.assertEqual(task.mapping_kind, "current")
            self.assertEqual(task.native_work_item_id, StableId(native_id))
            self.assertIsNotNone(task.definition_revision_id)
            self.assertFalse(task.completion_asserted)
            self.assertIsNone(task.completion_assertion_digest)
            self.assertEqual(page.records[0].native_work_item_id, StableId(native_id))

            context = session.read_legacy_project_context(import_id=receipt.import_id, limit=1)
            self.assertEqual(len(context.records), 1)
            declaration = context.records[0]
            self.assertEqual(declaration.source_table, "project_declarations")
            self.assertEqual(declaration.source_system, LEGACY_SOURCE_SYSTEM)
            self.assertEqual(declaration.source_project_id, StableId("legacy-source-project"))
            self.assertEqual(declaration.source_authority_revision, 9)
            self.assertEqual(declaration.source_digest, preview.source_digest)
            self.assertEqual(declaration.source_project_name, "Archived source project")
            self.assertEqual(declaration.source_repository_id, None)
            self.assertEqual(declaration.import_semantic_revision, receipt.semantic_revision)
            self.assertEqual(declaration.row["kind"], "orientation")
            self.assertEqual(declaration.row["version"], 2)
            self.assertEqual(declaration.row["retired"], 0)
            self.assertEqual(declaration.row["task_id"], None)
            self.assertEqual(declaration.row["revision"], 7)
            self.assertEqual(declaration.payload, {"purpose": "Preserve imported project direction"})
            self.assertIsNotNone(context.next_cursor)

            following = session.read_legacy_project_context(
                import_id=receipt.import_id, limit=1,
                after={"import_id": str(receipt.import_id),
                       "source_table": context.next_cursor.source_table,
                       "source_id": context.next_cursor.source_id},
            )
            self.assertEqual(len(following.records), 1)
            self.assertEqual(following.records[0].source_table, "project_fragment_invalidations")
            self.assertEqual(following.records[0].row["reason"], "source changed")
            self.assertIsNone(following.next_cursor)

    def test_legacy_preview_requires_project_read_authority(self):
        with self.initialize(owner_actions=(StableId("todo.plan.commit"),)) as session:
            with self.assertRaises(CapabilityDeniedError):
                session.preview_legacy_import(_snapshot())
            with self.assertRaises(CapabilityDeniedError):
                session.read_legacy_current_tasks()
            with self.assertRaises(CapabilityDeniedError):
                session.read_legacy_project_context()


if __name__ == "__main__":
    unittest.main()
