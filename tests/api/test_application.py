"""Primary public application facade tests using disposable authorities."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest

from todo_orchestrator.api import (
    RunSchedule,
    ScheduledWork,
    PlanPreviewV1,
    ProjectMetadataV1,
    ProviderComposition,
    TodoApplication,
)
from todo_orchestrator.authority.auth import CapabilityDeniedError
from todo_orchestrator.authority.sqlite import SQLiteAuthority
from todo_orchestrator.contracts import EntityKind, Project, StableId


OWNER_CREDENTIAL = "disposable application facade credential 816"


def package(project: Project) -> str:
    return json.dumps({
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "application-facade-package",
        "project": {
            "project_id": str(project.project_id),
            "authority_id": str(project.authority_id),
        },
        "work_items": [{
            "id": "facade-work",
            "title": "Exercise the public facade",
            "objective": "Preview and commit an authored task through the public API",
            "outcome": "The accepted plan has a stable public receipt",
            "scope": {"paths": [], "concepts": ["facade"], "locks": []},
            "acceptance": {
                "assertions": ["the plan can be committed"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
            "ownership": {"mode": "any", "actors": []},
        }],
    }, sort_keys=True, separators=(",", ":"))


class ApplicationFacadeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-api-facade-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.project = Project(StableId("facade-project"), StableId("facade-authority"))
        self.providers = ProviderComposition()

    def initialize(self, **kwargs):
        return TodoApplication.initialize(
            self.root,
            project_id=self.project.project_id,
            repository_id=StableId("facade-repository"),
            authority_id=self.project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            providers=self.providers,
            **kwargs,
        )

    def test_metadata_roundtrip_and_public_plan_preview_commit_read(self):
        package_text = package(self.project)
        with self.initialize() as session:
            metadata_path = self.root / ".todo-orchestrator" / "project.json"
            metadata_text = metadata_path.read_text(encoding="utf-8")
            self.assertEqual(metadata_text, session.metadata.to_json())
            self.assertEqual(ProjectMetadataV1.from_json(metadata_text), session.metadata)

            preview = session.preview_plan(package_text)
            self.assertIsInstance(preview, PlanPreviewV1)
            self.assertFalse(preview.has_conflicts)
            self.assertEqual(PlanPreviewV1.from_json(preview.to_json()), preview)
            receipt = session.commit_plan(
                package_text, preview, idempotency_key=StableId("facade-plan-commit")
            )
            self.assertTrue(receipt.changed)
            model = session.read_model()
            self.assertEqual(model.project_id, self.project.project_id)
            self.assertEqual(model.semantic_revision, receipt.semantic_revision)
            self.assertEqual(model.sections["work_definitions"][0]["title"], "Exercise the public facade")

    def test_plan_preview_requires_current_project_read_action_without_state_churn(self):
        with self.initialize(owner_actions=(StableId("todo.plan.commit"),)) as session:
            authority_path = self.root / ".todo-orchestrator" / "authority.sqlite3"
            with SQLiteAuthority.open_reader(authority_path, self.project) as authority:
                with authority.read_transaction() as connection:
                    before = connection.execute(
                        "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
                    ).fetchone()[0]
            with self.assertRaises(CapabilityDeniedError):
                session.preview_plan(package(self.project))
            with SQLiteAuthority.open_reader(authority_path, self.project) as authority:
                with authority.read_transaction() as connection:
                    after = connection.execute(
                        "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
                    ).fetchone()[0]
            self.assertEqual(after, before)

    def test_bearer_output_is_private_redacted_and_never_overwritten(self):
        token_path = Path(self.temporary.name) / "owner.token"
        with self.initialize() as session:
            bearer = session.bearer_token
            self.assertNotIn(bearer, repr(session))
            session.write_bearer(token_path)
            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
            self.assertEqual(token_path.read_text(encoding="utf-8").strip(), bearer)
            with self.assertRaises(FileExistsError):
                session.write_bearer(token_path)
            self.assertEqual(token_path.read_text(encoding="utf-8").strip(), bearer)
        with self.assertRaises(RuntimeError):
            _ = session.bearer_token

    def test_private_backup_and_explicit_restore_preserve_project_identity(self):
        backup_path = Path(self.temporary.name) / "authority-backup.sqlite3"
        restored_path = Path(self.temporary.name) / "restored.sqlite3"
        with self.initialize() as session:
            current = session.read_model()
            backup = session.backup(backup_path, expected_revision=current.semantic_revision)
            self.assertEqual(backup.manifest.semantic_revision, current.semantic_revision)

        with TodoApplication.restore_backup(
            backup_path,
            restored_path,
            manifest=backup.manifest,
            expected_project_id=self.project.project_id,
            expected_authority_id=self.project.authority_id,
            expected_revision=backup.manifest.semantic_revision,
        ) as restored:
            self.assertEqual(restored.project, self.project)

    def test_run_schedule_read_and_digest_use_default_queue(self):
        package_text = package(self.project)
        with self.initialize() as session:
            preview = session.preview_plan(package_text)
            committed = session.commit_plan(
                package_text, preview, idempotency_key=StableId("facade-run-plan-commit")
            )
            plan_revision = session.ref(
                EntityKind.PLAN_REVISION, StableId(committed.result["plan_revision_id"])
            )
            work = session.work_item_ref("facade-work", StableId(committed.result["plan_revision_id"]))
            schedule = RunSchedule(
                StableId("facade-run"), plan_revision, work=(ScheduledWork(work),),
            )
            opened = session.open_run(
                plan_revision.entity_id, schedule, idempotency_key=StableId("facade-open-run"),
                expected_revision=committed.semantic_revision,
            )
            view = session.read_run("facade-run")
            self.assertTrue(opened.changed)
            self.assertEqual(len(view.entries), 1)
            self.assertEqual(session.run_schedule_digest("facade-run").hex,
                             session.run_schedule_digest(schedule.run_id).hex)


if __name__ == "__main__":
    unittest.main()
