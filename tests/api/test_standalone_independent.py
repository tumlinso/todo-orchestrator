"""Independent public-facade and installed-artifact qualification for I01."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from todo_orchestrator.api import ProviderComposition, TodoApplication, TodoApplicationError
from todo_orchestrator.contracts import (
    OutcomeDisposition,
    Project,
    StableId,
)
from todo_orchestrator.model import ChildActivity as ModelChildActivity
from todo_orchestrator.model import ProcessLiveness as ModelProcessLiveness
from todo_orchestrator.providers.git import GitEffectState, GitRepositoryConfig

from tests.verification.test_git_independent import TemporaryGitRepository


OWNER_CREDENTIAL = "I01 disposable owner credential 591"


class StoppedProcessObserver:
    """Explicit test host evidence; the Git provider supplies all Git facts."""

    def inspect(self, attempt):
        return ModelProcessLiveness.STOPPED


class EmptyChildObserver:
    def inspect(self, attempt):
        return ModelChildActivity.NONE


def _plan(project: Project, items: tuple[str, ...] = ("accept", "finish")) -> str:
    return json.dumps(
        {
            "format": "todo-orchestrator.plan",
            "schema_version": 1,
            "package_id": "i01-standalone-api",
            "project": {
                "project_id": str(project.project_id),
                "authority_id": str(project.authority_id),
            },
            "work_items": [
                {
                    "id": item,
                    "title": f"Exercise {item}",
                    "objective": f"Exercise the public {item} path",
                    "outcome": f"The {item} path is recorded",
                    "scope": {"paths": [], "concepts": [item], "locks": []},
                    "acceptance": {
                        "assertions": ["the result has a durable receipt"],
                        "required_evidence": [],
                        "allowed_dispositions": ["completed"],
                    },
                    "ownership": {"mode": "any", "actors": []},
                }
                for item in items
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class StandaloneApplicationIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-i01-api-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git = TemporaryGitRepository(self.root)
        self.project = Project(StableId("i01-api-project"), StableId("i01-api-authority"))
        self.repository_id = StableId("i01-api-repository")
        config = GitRepositoryConfig(
            self.project.project_id,
            self.repository_id,
            self.git.repository,
            self.root / "managed-workspaces",
            self.root / "provider-journal",
            StableId("refs/heads/main"),
            StableId("refs/heads/todo-integration"),
        )
        self.git_provider = ProviderComposition.local_git(
            config,
            process_observer=StoppedProcessObserver(),
            child_observer=EmptyChildObserver(),
        )
        self.project_root = self.root / "new-project"
        self.project_root.mkdir()

    def test_new_project_public_plan_claim_report_accept_and_finish_with_native_git(self):
        with TodoApplication.initialize(
            self.project_root,
            project_id=self.project.project_id,
            repository_id=self.repository_id,
            authority_id=self.project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            providers=self.git_provider,
        ) as session:
            package = _plan(self.project)
            preview = session.preview_plan(package)
            committed = session.commit_plan(
                package, preview, idempotency_key=StableId("i01-plan-commit")
            )
            self.assertTrue(committed.receipt_id.value)

            accepted_target = StableId("accept")
            accepted_workspace = StableId("i01-accept-workspace")
            created = session.create_workspace(
                accepted_target,
                idempotency_key=StableId("i01-create-accept-workspace"),
                workspace_id=accepted_workspace,
            )
            self.assertIs(created.state, GitEffectState.FINALIZED)
            accepted_attempt = session.dispatch(
                accepted_workspace,
                idempotency_key=StableId("i01-dispatch-accept"),
                work_item=accepted_target,
            )
            self.assertIsNotNone(accepted_attempt.attempt_ref)
            candidate = session.report(
                accepted_attempt.attempt_ref,
                OutcomeDisposition.COMPLETED,
                idempotency_key=StableId("i01-report-accept"),
            )
            self.assertEqual(candidate.attempt_ref, accepted_attempt.attempt_ref)
            accepted = session.accept(
                accepted_attempt.attempt_ref,
                candidate.candidate_ref,
                idempotency_key=StableId("i01-accept-result"),
            )
            self.assertTrue(accepted.receipt_id.value)

            finish_target = StableId("finish")
            finish_workspace = StableId("i01-finish-workspace")
            session.create_workspace(
                finish_target,
                idempotency_key=StableId("i01-create-finish-workspace"),
                workspace_id=finish_workspace,
            )
            finish_attempt = session.dispatch(
                finish_workspace,
                idempotency_key=StableId("i01-dispatch-finish"),
                work_item=finish_target,
            )
            finished = session.finish(
                finish_attempt.attempt_ref,
                finish_attempt.lease_id,
                idempotency_key=StableId("i01-finish-attempt"),
            )
            self.assertTrue(finished.receipt_id.value)

            model = session.read_model()
            self.assertIsNotNone(model)
            self.assertTrue(
                self.git_provider.git_provider.workspace_path_for(accepted_workspace).is_dir()
            )
            self.assertTrue(
                self.git_provider.git_provider.workspace_path_for(finish_workspace).is_dir()
            )

    def test_open_of_missing_authority_does_not_create_project_state_or_echo_token(self):
        missing = self.root / "missing-project"
        secret = "not-a-real-session-token-should-not-echo"
        with self.assertRaises(TodoApplicationError) as caught:
            TodoApplication.open(missing, bearer_token=secret)
        self.assertNotIn(secret, str(caught.exception))
        self.assertFalse(missing.exists())

    def test_cli_missing_state_error_is_bounded_and_does_not_echo_bearer(self):
        missing = self.root / "cli-missing-project"
        secret = "i01-cli-bearer-must-not-appear-in-errors"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
        environment["TODO_BEARER_TOKEN"] = secret
        result = subprocess.run(
            [
                sys.executable, "-S", "-m", "todo_orchestrator", "--root", str(missing),
                "read",
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertLessEqual(len(output), 2048)
        self.assertNotIn(secret, output)
        self.assertNotIn("handlers are not initialized", output)
        self.assertFalse(missing.exists())

    def test_installed_wheel_runs_public_plan_api_under_isolated_python(self):
        with tempfile.TemporaryDirectory(prefix="todo-i01-wheel-") as temporary:
            temporary_path = Path(temporary)
            project = temporary_path / "build-source"
            (project / "src").mkdir(parents=True)
            repository_root = Path(__file__).resolve().parents[2]
            shutil.copy2(repository_root / "pyproject.toml", project / "pyproject.toml")
            shutil.copy2(repository_root / "README.md", project / "README.md")
            shutil.copytree(
                repository_root / "src" / "todo_orchestrator",
                project / "src" / "todo_orchestrator",
            )

            wheels = temporary_path / "wheels"
            wheels.mkdir()
            build = subprocess.run(
                [
                    sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps",
                    "--no-build-isolation", "--wheel-dir", str(wheels), str(project),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            wheel_files = list(wheels.glob("todo_orchestrator-*.whl"))
            self.assertEqual(len(wheel_files), 1)
            target = temporary_path / "installed"
            install = subprocess.run(
                [
                    sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
                    "--target", str(target), str(wheel_files[0]),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(install.returncode, 0, install.stdout + install.stderr)

            package = _plan(
                Project(StableId("i01-installed-project"), StableId("i01-installed-authority")),
                ("installed",),
            )
            code = f"""
import importlib
import importlib.util
import json
import pathlib
import sys

target = pathlib.Path({str(target)!r}).resolve()
sys.path.insert(0, str(target))
from todo_orchestrator.api import TodoApplication
from todo_orchestrator.contracts import Project, StableId
import todo_orchestrator
import todo_orchestrator.api
import todo_orchestrator.api.cli

for module in (todo_orchestrator, todo_orchestrator.api, todo_orchestrator.api.cli,
               importlib.import_module(TodoApplication.__module__)):
    assert pathlib.Path(module.__file__).resolve().is_relative_to(target), module.__file__
assert importlib.util.find_spec('project_control') is None
assert not any(name == 'project_control' or name.startswith('project_control.')
               for name in sys.modules)
root = pathlib.Path({str(temporary_path / 'installed-project')!r})
root.mkdir()
project = Project(StableId('i01-installed-project'), StableId('i01-installed-authority'))
package = {package!r}
with TodoApplication.initialize(root, project_id=project.project_id,
                                repository_id=StableId('i01-installed-repository'),
                                authority_id=project.authority_id,
                                owner_credential='isolated installed artifact owner 266') as session:
    preview = session.preview_plan(package)
    committed = session.commit_plan(package, preview,
                                    idempotency_key=StableId('i01-installed-plan-commit'))
    assert committed.receipt_id.value
assert root.exists()
assert not any(name == 'project_control' or name.startswith('project_control.')
               for name in sys.modules)
"""
            environment = os.environ.copy()
            environment.pop("PYTHONPATH", None)
            smoke = subprocess.run(
                [sys.executable, "-I", "-S", "-c", code],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(smoke.returncode, 0, smoke.stdout + smoke.stderr)


if __name__ == "__main__":
    unittest.main()
