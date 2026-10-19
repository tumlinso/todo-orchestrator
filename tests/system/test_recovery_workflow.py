"""Integrated process-loss recovery through the public application API.

The fixture deliberately kills a subprocess after a real ``git worktree add``
and before either provider or authority finalization. A second process opens
the same project, inspects without mutation, then applies the exact observed
effect intent. The test records public export and Git byte snapshots around
that boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from todo_orchestrator.api import (
    DEFAULT_OWNER_ACTIONS,
    ProviderComposition,
    TodoApplication,
    authority_path,
)
from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.providers.git import GitRepositoryConfig

from tests.system import test_standalone_workflow as workflow_fixture


_CHILD = r'''
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from todo_orchestrator.api import ProviderComposition, TodoApplication
from todo_orchestrator.contracts import StableId
from todo_orchestrator.providers.git import GitRepositoryConfig

p = json.loads(sys.stdin.read())
def providers():
    config = GitRepositoryConfig(
        StableId(p["project_id"]), StableId(p["repository_id"]),
        Path(p["repository"]), Path(p["workspace_root"]), Path(p["journal_root"]),
        StableId(p["base_ref"]), StableId(p["integration_ref"]),
    )
    return ProviderComposition.local_git(
        config, clock=lambda: datetime.now(timezone.utc),
    )

if p["mode"] == "crash":
    composition = providers()
    composition.git_provider.failure_hook = lambda stage, _request: (
        os._exit(73) if stage == "after_effect" else None
    )
    with TodoApplication.open(
        p["project_root"], bearer_token=p["bearer_token"], providers=composition,
    ) as session:
        session.create_workspace(
            StableId(p["work_item_id"]),
            idempotency_key=StableId(p["idempotency_key"]),
            workspace_id=StableId(p["workspace_id"]),
            plan_revision_id=StableId(p["plan_revision_id"]),
        )
    raise SystemExit("the after-effect interruption hook did not run")

if p["mode"] == "recover":
    composition = providers()
    effect_calls = [0]
    original_perform = composition.git_provider.perform
    def counted_perform(request):
        effect_calls[0] += 1
        return original_perform(request)
    composition.git_provider.perform = counted_perform
    with TodoApplication.open(
        p["project_root"], bearer_token=p["bearer_token"], providers=composition,
    ) as session:
        before = session.read_model()
        report = session.inspect_effect(StableId(p["operation_id"]))
        after_inspection = session.read_model()
        assert before.to_json() == after_inspection.to_json(), "read-only inspection changed the public model"
        assert report.operations and report.operations[0].status.value == "effect_observed"
        assert not report.blockers, "the current operation/source binding is not fully proven"
        assert report.operations[0].git_observation is not None
        assert report.operations[0].git_observation.disposition.value == "applied"
        intents = [item for item in report.intents if item.kind.value == "reconcile_observed_effect"]
        assert len(intents) == 1, "fresh inspection did not produce one exact observed-effect intent"
        intent = intents[0]
        assert intent.expected_source_digest is not None
        assert report.operations[0].source_observation is not None
        assert report.operations[0].source_observation.source_digest == intent.expected_source_digest
        applied = session.apply_recovery(
            intent,
            idempotency_key=StableId("q03-reconcile-workspace-after-process-loss"),
            expected_revision=report.authority_revision,
        )
        final = session.read_model()
        assert effect_calls[0] == 0, "reconciliation replayed the external Git effect"
        assert final.sections["git_effect_operations"][0]["state"] == "finalized"
        assert final.sections["external_operations"][0]["state"] == "finalized"
        backup = session.backup(
            p["backup_path"], expected_revision=final.semantic_revision,
        )
        print(json.dumps({
            "inspection_status": report.status.value,
            "operation_status": report.operations[0].status.value,
            "read_only_inspection": before.to_json() == after_inspection.to_json(),
            "intent_kind": intent.kind.value,
            "intent_source_matches_current": (
                report.operations[0].source_observation.source_digest == intent.expected_source_digest
            ),
            "application_disposition": applied.disposition,
            "external_effect_calls_during_recovery": effect_calls[0],
            "semantic_revision": final.semantic_revision,
            "git_effect_state": final.sections["git_effect_operations"][0]["state"],
            "authority_event_count": len(final.sections["authority_history"]),
            "backup_manifest": backup.manifest.to_dict(),
        }, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0)

raise SystemExit("unknown child mode")
'''


class RecoveryWorkflowProcessRestartTests(unittest.TestCase):
    def test_real_git_effect_is_inspected_then_reconciled_after_process_loss(self):
        temporary = tempfile.TemporaryDirectory(prefix="todo-q03-integrated-recovery-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        git = workflow_fixture.TemporaryGitRepository(root)
        project = Project(StableId("q03-recovery-project"), StableId("q03-recovery-authority"))
        repository_id = StableId("q03-recovery-repository")
        workspace_id = StableId("q03-recovery-workspace")
        project_root = root / "standalone-project"
        backup_path = root / "recovered-authority.sqlite3"
        config = GitRepositoryConfig(
            project.project_id,
            repository_id,
            git.repository,
            root / "managed-workspaces",
            root / "provider-journal",
            StableId("refs/heads/main"),
            StableId("refs/heads/todo-integration"),
        )
        clock = lambda: datetime.now(timezone.utc)
        composition = ProviderComposition.local_git(
            config,
            process_observer=workflow_fixture.StoppedProcessObserver(),
            child_observer=workflow_fixture.EmptyChildObserver(),
            clock=clock,
        )
        owner_actions = tuple(sorted({*DEFAULT_OWNER_ACTIONS, StableId("todo.capability.delegate")}))
        package = workflow_fixture._plan(project)
        with TodoApplication.initialize(
            project_root,
            project_id=project.project_id,
            repository_id=repository_id,
            authority_id=project.authority_id,
            owner_credential="Q03 disposable recovery owner credential 641",
            owner_actions=owner_actions,
            providers=composition,
        ) as owner:
            preview = owner.preview_plan(package)
            commit = owner.commit_plan(
                package, preview, idempotency_key=StableId("q03-commit-recovery-plan"),
            )
            plan_revision_id = StableId(str(commit.result["plan_revision_id"]))
            work_item_id = owner.work_item_ref("alpha", plan_revision_id).entity_id
            bearer_token = owner.bearer_token

        base_before = git.snapshot(git.repository)
        child_payload = {
            "project_root": str(project_root),
            "project_id": str(project.project_id),
            "repository_id": str(repository_id),
            "repository": str(git.repository),
            "workspace_root": str(config.workspace_root),
            "journal_root": str(config.journal_root),
            "base_ref": str(config.base_ref),
            "integration_ref": str(config.integration_ref),
            "bearer_token": bearer_token,
            "plan_revision_id": str(plan_revision_id),
            "work_item_id": str(work_item_id),
            "workspace_id": str(workspace_id),
            "idempotency_key": "q03-interrupted-workspace-create",
            "backup_path": str(backup_path),
        }
        env = os.environ.copy()
        env["PYTHONPATH"] = "src:."
        crash = subprocess.run(
            [sys.executable, "-S", "-c", _CHILD],
            input=json.dumps({**child_payload, "mode": "crash"}),
            text=True,
            capture_output=True,
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            check=False,
        )
        self.assertEqual(crash.returncode, 73, crash.stderr)

        workspace = composition.git_provider.workspace_path_for(workspace_id)
        self.assertTrue(workspace.is_dir(), "the interrupted child did not leave the real Git worktree")
        workspace_before_recovery = git.snapshot(workspace)
        self.assertEqual(workspace_before_recovery[0], base_before[0])
        self.assertEqual(workspace_before_recovery[2], "")

        # Read the immutable metadata after the issuing session has closed.
        from todo_orchestrator.api import read_project_metadata

        metadata = read_project_metadata(project_root)
        db_path = authority_path(project_root, metadata)
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as connection:
            row = connection.execute(
                "SELECT operation_id, state, observation_json, provider_receipt_json "
                "FROM git_effect_operations"
            ).fetchone()
        self.assertIsNotNone(row)
        operation_id, effect_state, observation_json, provider_receipt_json = row
        self.assertEqual(effect_state, "executing")
        self.assertIsNone(observation_json)
        self.assertIsNone(provider_receipt_json)
        journal_file = config.journal_root / "operations" / (
            hashlib.sha256(operation_id.encode("utf-8")).hexdigest() + ".json"
        )
        provider_journal = json.loads(journal_file.read_text(encoding="utf-8"))
        self.assertEqual(provider_journal["state"], "executing")
        self.assertIsNone(provider_journal["observation"])
        self.assertIsNone(provider_journal["receipt"])

        recovery = subprocess.run(
            [sys.executable, "-S", "-c", _CHILD],
            input=json.dumps({**child_payload, "mode": "recover", "operation_id": operation_id}),
            text=True,
            capture_output=True,
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            check=False,
        )
        self.assertEqual(recovery.returncode, 0, recovery.stderr)
        result = json.loads(recovery.stdout)
        self.assertTrue(result["read_only_inspection"])
        self.assertEqual(result["operation_status"], "effect_observed")
        self.assertEqual(result["intent_kind"], "reconcile_observed_effect")
        self.assertTrue(result["intent_source_matches_current"])
        self.assertEqual(result["application_disposition"], "reconcile_observed_effect")
        self.assertEqual(result["external_effect_calls_during_recovery"], 0)
        self.assertEqual(result["git_effect_state"], "finalized")
        self.assertGreater(result["authority_event_count"], 0)
        self.assertEqual(result["backup_manifest"]["semantic_revision"], result["semantic_revision"])
        self.assertEqual(git.snapshot(workspace), workspace_before_recovery)
        self.assertEqual(git.snapshot(git.repository), base_before)
        worktree_listing = git.git(git.repository, "worktree", "list", "--porcelain").stdout
        self.assertEqual(sum(line.startswith("worktree ") for line in worktree_listing.splitlines()), 2)

        with sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True) as connection:
            exported_effect = connection.execute(
                "SELECT state FROM git_effect_operations WHERE operation_id = ?", (operation_id,),
            ).fetchone()
            exported_events = connection.execute("SELECT COUNT(*) FROM authority_events").fetchone()[0]
        self.assertEqual(exported_effect, ("finalized",))
        self.assertEqual(exported_events, result["authority_event_count"])


if __name__ == "__main__":
    unittest.main()
