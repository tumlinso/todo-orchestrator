"""A run cannot retire while a run-bound Git effect lacks an attempt."""

import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from todo_orchestrator.contracts import Sha256Digest, StableId
from todo_orchestrator.model import RunSchedule
from todo_orchestrator.operations.lifecycle import (
    RUN_RETIRE_ACTION,
    RunLifecycleService,
    RunNotQuiescentError,
    UnresolvedRunAssignment,
)
from todo_orchestrator.providers.git import GitRepositoryConfig, GitRepositoryProvider
from todo_orchestrator.providers.git.service import CREATE_WORKSPACE_ACTION, GitEffectService

from tests.coordination import test_dispatch_independent as dispatch_fixture


class UnattachedRunEffectLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dispatch_fixture.IndependentDispatchTests()
        actions = (*dispatch_fixture.OWNER_ACTIONS, RUN_RETIRE_ACTION, CREATE_WORKSPACE_ACTION)
        with patch.object(dispatch_fixture, "OWNER_ACTIONS", actions):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_interrupted_pre_attempt_workspace_effect_blocks_retirement(self):
        fixture = self.fixture
        repository = Path(fixture.directory.name) / "repository"
        repository.mkdir()

        def git(*args: str) -> str:
            result = subprocess.run(
                ["git", "-C", str(repository), *args], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            return result.stdout.strip()

        subprocess.run(
            ["git", "init", "-b", "main", str(repository)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        git("config", "user.name", "Disposable Lifecycle Fixture")
        git("config", "user.email", "lifecycle@example.invalid")
        (repository / "README.txt").write_text("temporary base\n", encoding="utf-8")
        git("add", "README.txt")
        git("commit", "--quiet", "-m", "temporary base")
        base_commit = git("rev-parse", "HEAD")
        git("branch", "todo-orchestrator-integration", base_commit)

        provider = GitRepositoryProvider(
            GitRepositoryConfig(
                dispatch_fixture.PROJECT.project_id,
                dispatch_fixture.REPOSITORY,
                repository,
                Path(fixture.directory.name) / "worktrees",
                Path(fixture.directory.name) / "provider-journal",
                StableId("refs/heads/main"),
                StableId("refs/heads/todo-orchestrator-integration"),
            ),
            clock=fixture.clock,
        )
        effects = GitEffectService(fixture.auth, provider, clock=fixture.clock)
        run_id = StableId("unattached-effect-run")
        with fixture.open_writer() as authority:
            fixture.coordination.open_run(
                authority,
                fixture.owner.bearer_token,
                fixture.plan,
                RunSchedule(run_id, fixture.plan.revision.ref),
                idempotency_key=StableId("unattached-effect-run-open"),
                expected_revision=fixture.revision(),
            )
        with fixture.open_reader() as authority:
            schedule = fixture.coordination.read_run(authority, run_id)
        entry = schedule.entries[0]
        workspace_id = StableId("unattached-effect-workspace")

        def interrupt_after_workspace_creation(stage, _request):
            if stage == "after_effect":
                raise SystemExit("simulated process loss after workspace creation")

        provider.failure_hook = interrupt_after_workspace_creation
        with fixture.open_writer() as authority:
            with self.assertRaisesRegex(SystemExit, "after workspace creation"):
                effects.create_workspace(
                    authority,
                    fixture.owner.bearer_token,
                    entry.assignment.work_item,
                    idempotency_key=StableId("unattached-effect-create"),
                    workspace_id=workspace_id,
                    expected_revision=fixture.revision(),
                    run=schedule.run.ref,
                    assignment=entry.assignment.ref,
                )

        workspace = provider.workspace_path_for(workspace_id)
        self.assertTrue(workspace.is_dir())
        with fixture.open_reader() as authority:
            operation = authority.connection.execute(
                "SELECT e.attempt_id, g.state, g.request_json "
                "FROM external_operations AS e JOIN git_effect_operations AS g USING(operation_id)"
            ).fetchone()
            self.assertIsNone(operation["attempt_id"])
            self.assertEqual(operation["state"], "executing")
            intent = json.loads(operation["request_json"])["request"]
            self.assertEqual(intent["run"]["entity_id"], str(run_id))
            self.assertEqual(intent["assignment"]["entity_id"], str(entry.assignment.ref.entity_id))

        before_retirement = fixture.state_snapshot()
        lifecycle = RunLifecycleService(fixture.auth)
        with fixture.open_reader() as authority:
            reviewed = lifecycle.read_lifecycle(authority, schedule.run.ref)
        with fixture.open_writer() as authority:
            with self.assertRaises(RunNotQuiescentError):
                lifecycle.retire_run(
                    authority,
                    fixture.owner.bearer_token,
                    schedule.run.ref,
                    schedule_digest=reviewed.schedule_digest,
                    idempotency_key=StableId("unattached-effect-retire"),
                    expected_revision=fixture.revision(),
                    unresolved=tuple(
                        UnresolvedRunAssignment(item.assignment.ref, "retained for later scheduling")
                        for item in schedule.entries
                    ),
                )

        self.assertEqual(fixture.state_snapshot(), before_retirement)
        self.assertTrue(workspace.is_dir())
        with fixture.open_reader() as authority:
            self.assertEqual(
                authority.connection.execute("SELECT state FROM runs WHERE run_id = ?", (str(run_id),)).fetchone()[0],
                "open",
            )
            self.assertEqual(
                authority.connection.execute("SELECT state FROM git_effect_operations").fetchone()[0],
                "executing",
            )


if __name__ == "__main__":
    unittest.main()
