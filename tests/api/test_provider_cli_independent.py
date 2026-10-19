"""Public CLI workflow qualification with an explicitly trusted Git provider."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from todo_orchestrator.api import ProviderComposition, TodoApplication
from todo_orchestrator.api.metadata import read_project_metadata
from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.model import ChildActivity, ProcessLiveness
from todo_orchestrator.providers.git import GitRepositoryConfig

from tests.api.test_standalone_independent import (
    EmptyChildObserver,
    StoppedProcessObserver,
    _plan,
)
from tests.verification.test_git_independent import TemporaryGitRepository


OWNER_CREDENTIAL = "I01 disposable CLI owner credential 742"
FACTORY_SPECIFICATION = "i01_trusted_provider:provider_factory"


class ProviderCliIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-i01-provider-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project_root = self.base / "project"
        self.project_root.mkdir()
        git_fixture = self.base / "git-fixture"
        git_fixture.mkdir()
        self.git = TemporaryGitRepository(git_fixture)
        self.factory_root = self.base / "trusted-provider"
        self.factory_root.mkdir()
        self.managed_workspaces = self.base / "managed-workspaces"
        self.provider_journal = self.base / "provider-journal"
        self.project = Project(StableId("i01-cli-project"), StableId("i01-cli-authority"))
        self.repository_id = StableId("i01-cli-repository")
        self.base_ref = StableId("refs/heads/main")
        self.integration_ref = StableId("refs/heads/todo-integration")
        self._write_trusted_factory()

        repository_root = Path(__file__).resolve().parents[2]
        self.environment = os.environ.copy()
        self.environment["PYTHONPATH"] = os.pathsep.join(
            (str(repository_root / "src"), str(self.factory_root))
        )
        self.environment.pop("TODO_BEARER_TOKEN", None)
        self.environment.pop("TODO_OWNER_CREDENTIAL", None)
        self.environment["I01_GIT_REPOSITORY"] = str(self.git.repository)
        self.environment["I01_MANAGED_WORKSPACES"] = str(self.managed_workspaces)
        self.environment["I01_PROVIDER_JOURNAL"] = str(self.provider_journal)
        self.environment["I01_BASE_REF"] = str(self.base_ref)
        self.environment["I01_INTEGRATION_REF"] = str(self.integration_ref)
        self.repository_root = repository_root

    def _write_trusted_factory(self):
        factory = self.factory_root / "i01_trusted_provider.py"
        factory.write_text(
            """from pathlib import Path
import os

from todo_orchestrator.api import ProviderComposition
from todo_orchestrator.contracts import StableId
from todo_orchestrator.model import ChildActivity, ProcessLiveness
from todo_orchestrator.providers.git import GitRepositoryConfig


class _StoppedProcessObserver:
    def inspect(self, attempt):
        return ProcessLiveness.STOPPED


class _EmptyChildObserver:
    def inspect(self, attempt):
        return ChildActivity.NONE


def provider_factory(root, metadata):
    config = GitRepositoryConfig(
        metadata.project_id,
        metadata.repository_id,
        Path(os.environ["I01_GIT_REPOSITORY"]),
        Path(os.environ["I01_MANAGED_WORKSPACES"]),
        Path(os.environ["I01_PROVIDER_JOURNAL"]),
        StableId(os.environ["I01_BASE_REF"]),
        StableId(os.environ["I01_INTEGRATION_REF"]),
    )
    return ProviderComposition.local_git(
        config,
        process_observer=_StoppedProcessObserver(),
        child_observer=_EmptyChildObserver(),
    )
""",
            encoding="utf-8",
        )

    def _cli(self, *arguments, token_file: Path | None = None, extra_env=None):
        command = [
            sys.executable,
            "-S",
            "-m",
            "todo_orchestrator",
            "--root",
            str(self.project_root),
            "--provider-factory",
            FACTORY_SPECIFICATION,
        ]
        if token_file is not None:
            command.extend(("--token-file", str(token_file)))
        command.extend(str(argument) for argument in arguments)
        environment = self.environment.copy()
        if extra_env:
            environment.update(extra_env)
        return subprocess.run(
            command,
            cwd=self.repository_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def _success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def _providers(self):
        config = GitRepositoryConfig(
            self.project.project_id,
            self.repository_id,
            self.git.repository,
            self.managed_workspaces,
            self.provider_journal,
            self.base_ref,
            self.integration_ref,
        )
        return ProviderComposition.local_git(
            config,
            process_observer=StoppedProcessObserver(),
            child_observer=EmptyChildObserver(),
        )

    def _provision_workspace(self, work_item: str, workspace_id: str, owner_token: Path):
        metadata = read_project_metadata(self.project_root)
        with TodoApplication.open(
            self.project_root,
            bearer_token=owner_token.read_text(encoding="utf-8").strip(),
            providers=self._providers(),
        ) as session:
            created = session.create_workspace(
                StableId(work_item),
                idempotency_key=StableId(f"i01-cli-create-{work_item}"),
                workspace_id=StableId(workspace_id),
            )
            self.assertTrue(created.operation_id.value)
        self.assertEqual(metadata.project_id, self.project.project_id)

    def test_cli_plan_dispatch_report_accept_and_separate_finish_with_trusted_factory(self):
        owner_token = self.base / "owner.token"
        init_environment = {"TODO_OWNER_CREDENTIAL": OWNER_CREDENTIAL}
        initialized = self._success(self._cli(
            "init",
            "--project-id", self.project.project_id,
            "--repository-id", self.repository_id,
            "--authority-id", self.project.authority_id,
            "--token-output", owner_token,
            "--json",
            extra_env=init_environment,
        ))
        self.assertEqual(initialized["payload"]["project_id"], self.project.project_id.value)
        self.assertEqual(stat.S_IMODE(owner_token.stat().st_mode), 0o600)
        owner_bearer = owner_token.read_text(encoding="utf-8").strip()
        self.assertTrue(owner_bearer)
        self.assertNotIn(owner_bearer, json.dumps(initialized))

        package_path = self.base / "plan.json"
        preview_path = self.base / "plan-preview.json"
        package_path.write_text(_plan(self.project), encoding="utf-8")
        preview_command = self._cli(
            "plan", "preview", package_path, "--output", preview_path,
            token_file=owner_token,
        )
        self.assertEqual(preview_command.returncode, 0, preview_command.stdout + preview_command.stderr)
        preview = json.loads(preview_path.read_text(encoding="utf-8"))
        self.assertEqual(preview["project_id"], self.project.project_id.value)
        self.assertFalse(preview["has_conflicts"])

        committed = self._success(self._cli(
            "plan", "commit", package_path, "--preview", preview_path,
            "--idempotency-key", "i01-cli-plan-commit", "--json",
            token_file=owner_token,
        ))
        self.assertTrue(committed["receipt_id"])

        accept_workspace = "i01-cli-accept-workspace"
        finish_workspace = "i01-cli-finish-workspace"
        self._provision_workspace("accept", accept_workspace, owner_token)
        self._provision_workspace("finish", finish_workspace, owner_token)

        accept_token = self.base / "accept-attempt.token"
        dispatched = self._success(self._cli(
            "dispatch", "--work-item", "accept", "--workspace-id", accept_workspace,
            "--idempotency-key", "i01-cli-dispatch-accept", "--token-output", accept_token,
            "--json", token_file=owner_token,
        ))
        self.assertEqual(stat.S_IMODE(accept_token.stat().st_mode), 0o600)
        accept_bearer = accept_token.read_text(encoding="utf-8").strip()
        self.assertNotIn(accept_bearer, json.dumps(dispatched))
        attempt_id = dispatched["attempt_ref"]["entity_id"]

        reported = self._success(self._cli(
            "report", "--attempt", attempt_id, "--disposition", "completed",
            "--idempotency-key", "i01-cli-report-accept", "--json",
            token_file=accept_token,
        ))
        self.assertEqual(reported["attempt_ref"]["entity_id"], attempt_id)
        candidate_id = reported["candidate_ref"]["entity_id"]
        accepted = self._success(self._cli(
            "accept", "--attempt", attempt_id, "--candidate", candidate_id,
            "--idempotency-key", "i01-cli-accept-result", "--json",
            token_file=owner_token,
        ))
        self.assertTrue(accepted["receipt_id"])

        finish_token = self.base / "finish-attempt.token"
        finish_dispatch = self._success(self._cli(
            "dispatch", "--work-item", "finish", "--workspace-id", finish_workspace,
            "--idempotency-key", "i01-cli-dispatch-finish", "--token-output", finish_token,
            "--json", token_file=owner_token,
        ))
        self.assertEqual(stat.S_IMODE(finish_token.stat().st_mode), 0o600)
        finish_bearer = finish_token.read_text(encoding="utf-8").strip()
        self.assertNotIn(finish_bearer, json.dumps(finish_dispatch))
        finish_attempt_id = finish_dispatch["attempt_ref"]["entity_id"]
        finished = self._success(self._cli(
            "finish", "--attempt", finish_attempt_id,
            "--lease", finish_dispatch["lease_id"],
            "--idempotency-key", "i01-cli-finish-attempt", "--json",
            token_file=finish_token,
        ))
        self.assertTrue(finished["receipt_id"])

        read_model_path = self.base / "read-model.json"
        read_result = self._cli(
            "read", "--output", read_model_path, token_file=owner_token,
        )
        self.assertEqual(read_result.returncode, 0, read_result.stdout + read_result.stderr)
        model = json.loads(read_model_path.read_text(encoding="utf-8"))
        self.assertEqual(model["project_id"], self.project.project_id.value)
        attempts = {row["attempt_id"]: row for row in model["sections"]["attempts"]}
        self.assertEqual(attempts[attempt_id]["state"], "accepted")
        self.assertIsNone(attempts[attempt_id]["lease_id"])
        self.assertEqual(attempts[finish_attempt_id]["state"], "released")
        self.assertIsNone(attempts[finish_attempt_id]["lease_id"])
        outcomes = model["sections"]["outcomes"]
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["work_item_id"], "accept")
        self.assertEqual(outcomes[0]["attempt_id"], attempt_id)


if __name__ == "__main__":
    unittest.main()
