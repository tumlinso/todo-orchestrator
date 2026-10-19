"""Focused tests for the standalone legacy snapshot boundary and converter."""

from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.migration import (
    LEGACY_PROJECT_SCHEMA_VERSION,
    LEGACY_SNAPSHOT_FORMAT,
    LEGACY_SNAPSHOT_VERSION,
    LEGACY_SOURCE_SYSTEM,
    LegacySnapshotError,
    build_legacy_import_preview,
    parse_legacy_snapshot,
)
from todo_orchestrator.migration import snapshot as snapshot_module


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _snapshot(tasks, *, events=(), extra_tables=None):
    envelope = {
        "format": LEGACY_SNAPSHOT_FORMAT,
        "version": LEGACY_SNAPSHOT_VERSION,
        "source": {
            "system": LEGACY_SOURCE_SYSTEM,
            "project_id": "legacy-source",
            "schema_version": LEGACY_PROJECT_SCHEMA_VERSION,
            "authority_revision": 4,
            "exported_at": "2026-10-19T11:00:00Z",
        },
        "project": {"name": "Source project"},
        "tables": {"tasks": list(tasks), "task_dependencies": [], "events": list(events)},
        "history": [],
    }
    envelope["tables"].update(extra_tables or {})
    envelope["snapshot_digest"] = hashlib.sha256(_canonical(envelope).encode("utf-8")).hexdigest()
    return envelope


class LegacySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.project = Project(StableId("native-project"), StableId("native-authority"))

    def test_current_done_and_open_tasks_preserve_ids_and_parent_lineage(self):
        document = _snapshot([
            {"id": "V200-01", "status": "done", "title": "Completed parent", "revision": 12},
            {"id": "TO-I04", "status": "in_progress", "title": "Open child", "parent_id": "V200-01"},
            {"id": "closed-old", "status": "closed", "title": "Closed historical row"},
        ])
        preview = build_legacy_import_preview(document, self.project, 0, None)
        plan = json.loads(preview.package_json)

        self.assertEqual(preview.included_task_ids, ("TO-I04", "V200-01"))
        self.assertEqual(preview.completed_task_ids, ("V200-01",))
        self.assertEqual(preview.archive_only_task_ids, ("closed-old",))
        definitions = {item["id"]: item for item in plan["work_items"]}
        self.assertIn("V200-01", definitions)
        self.assertIn("TO-I04", definitions)
        self.assertEqual(definitions["TO-I04"]["parent_id"], "V200-01")
        self.assertEqual(definitions["V200-01"]["acceptance"]["allowed_dispositions"], ["completed"])

    def test_valid_source_id_is_preserved_when_another_id_collides(self):
        document = _snapshot([
            {"id": "reserved-work", "status": "planned", "title": "Existing ID collision"},
            {"id": "ordinary-work", "status": "planned", "title": "Keep source ID"},
        ])
        preview = build_legacy_import_preview(
            document, self.project, 0, None, reserved_work_item_ids={"reserved-work"},
        )
        ids = {item["id"] for item in json.loads(preview.package_json)["work_items"]}
        self.assertIn("ordinary-work", ids)
        self.assertNotIn("reserved-work", ids)
        self.assertTrue(any(item.startswith("legacy-task-") for item in ids))

    def test_embedded_legacy_recovery_approval_field_is_rejected(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            events=[{"seq": 1, "payload_json": _canonical({"recovery_approval": "secret-value"})}],
        )
        with self.assertRaisesRegex(LegacySnapshotError, "sensitive field"):
            parse_legacy_snapshot(document)

    def test_valid_embedded_json_is_scanned_without_rescanning_its_raw_cell(self):
        embedded = _canonical({"message": "safe embedded text"})
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"evidence": [{"metadata_json": embedded}]},
        )
        original = snapshot_module._SECRET_ASSIGNMENT
        raw_cell_scans = []

        class CountingAssignment:
            def finditer(self, value):
                if value is embedded:
                    raw_cell_scans.append(value)
                return original.finditer(value)

        with patch.object(snapshot_module, "_SECRET_ASSIGNMENT", CountingAssignment()):
            parse_legacy_snapshot(document)

        self.assertEqual(raw_cell_scans, [])

    def test_opaque_malformed_json_remains_scanned_for_credentials(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"evidence": [{"metadata_json": '{"message": token=secret-value'}]},
        )

        with self.assertRaisesRegex(LegacySnapshotError, "unredacted sensitive value"):
            parse_legacy_snapshot(document)

    def test_semantic_authorization_and_manifest_paths_are_not_credentials(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"claims": [{
                "gpu_authorization": {"policy": "paired-device"},
                "fallback_authorization": "manual-review-required",
                "baseline_manifest_json": _canonical({
                    "files": {"tests/compiler/lto/implement_explicit_program_planning_authorization_test.cc": "sha256"},
                }),
            }]},
        )
        parsed, _ = parse_legacy_snapshot(document)
        self.assertIn("gpu_authorization", parsed["tables"]["claims"][0])

    def test_exact_authorization_credential_and_embedded_bearer_are_rejected(self):
        for payload in (
            {"authorization": "Bearer abc123"},
            {"authorization_token": "abc123"},
            {"auth_header": "Bearer abc123"},
            {"message": "request used Bearer abc123"},
            {"message": "authorization: abc123"},
        ):
            with self.subTest(payload=payload):
                document = _snapshot(
                    [{"id": "task-1", "status": "planned", "title": "Task"}],
                    events=[{"seq": 1, "payload_json": _canonical(payload)}],
                )
                with self.assertRaises(LegacySnapshotError):
                    parse_legacy_snapshot(document)

    def test_sanitized_credential_assignment_is_accepted(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            events=[{"seq": 1, "payload_json": _canonical({"message": "token=[REDACTED]"})}],
        )
        parse_legacy_snapshot(document)

    def test_done_task_glob_is_preserved_in_archive_without_native_path_scope(self):
        document = _snapshot(
            [{"id": "task-1", "status": "done", "title": "Task"}],
            extra_tables={"ownership_scopes": [{
                "task_id": "task-1", "path": "Cellerator/data/*.csh5", "mode": "forbidden",
            }]},
        )
        preview = build_legacy_import_preview(document, self.project, 0, None)
        work = json.loads(preview.package_json)["work_items"][0]
        self.assertEqual(work["scope"]["paths"], [])
        self.assertFalse(preview.attention)

    def test_unrepresentable_open_glob_requires_attention_without_scope_expansion(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"ownership_scopes": [{
                "task_id": "task-1", "path": "src/**/*.py", "mode": "exclusive",
            }]},
        )
        preview = build_legacy_import_preview(document, self.project, 0, None)
        work = json.loads(preview.package_json)["work_items"][0]
        self.assertEqual(work["scope"]["paths"], [])
        self.assertTrue(any("without expanding worker path rights" in item.message for item in preview.attention))

    def test_forbidden_open_glob_uses_conservative_prefix_and_marks_translation(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"ownership_scopes": [{
                "task_id": "task-1", "path": "src/generated/*.py", "mode": "forbidden",
            }]},
        )
        preview = build_legacy_import_preview(document, self.project, 0, None)
        work = json.loads(preview.package_json)["work_items"][0]
        self.assertEqual(work["scope"]["paths"], [{"path": "src/generated", "access": "forbidden"}])
        self.assertIn("legacy-forbidden-glob-prefix-translation", work["scope"]["concepts"])

    def test_forbidden_glob_overlapping_another_scope_blocks_without_ambiguous_paths(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"ownership_scopes": [
                {"task_id": "task-1", "path": "src/generated/*.py", "mode": "forbidden"},
                {"task_id": "task-1", "path": "src/generated/tool.py", "mode": "exclusive"},
            ]},
        )
        preview = build_legacy_import_preview(document, self.project, 0, None)
        work = json.loads(preview.package_json)["work_items"][0]
        self.assertEqual(work["scope"]["paths"], [{"path": "src/generated/tool.py", "access": "write"}])
        self.assertNotIn("legacy-forbidden-glob-prefix-translation", work["scope"]["concepts"])
        self.assertTrue(any("overlaps another native path scope" in item.message for item in preview.attention))

    def test_partially_representable_gate_attention_has_distinct_requirement_id(self):
        document = _snapshot(
            [{"id": "task-1", "status": "planned", "title": "Task"}],
            extra_tables={"gates": [{
                "id": "gate-1", "task_id": "task-1", "type": "command", "required": 1,
                "config_json": _canonical({"argv": ["echo", "ok"], "unexpected": "legacy-field"}),
            }]},
        )
        preview = build_legacy_import_preview(document, self.project, 0, None)
        plan = json.loads(preview.package_json)
        requirement_ids = [requirement["id"] for requirement in plan["requirements"]]
        self.assertEqual(len(requirement_ids), len(set(requirement_ids)))
        self.assertTrue(preview.attention)


if __name__ == "__main__":
    unittest.main()
