"""Base-ref observations are read-only and identify the exact configured Git ref."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from todo_orchestrator.contracts import (
    EntityKind,
    EntityRef,
    ProviderCallContext,
    ProviderStatus,
    SourceObservationRequest,
    StableId,
    WorkingTreeState,
)
from todo_orchestrator.contracts.providers import provider_request_digest
from todo_orchestrator.providers.git import GitRepositoryConfig, GitRepositoryProvider


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


class GitBaseObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="todo-git-base-observation-")
        self.root = Path(self.temp.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(self.repository)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        git(self.repository, "config", "user.name", "Fixture Owner")
        git(self.repository, "config", "user.email", "fixture@example.invalid")
        (self.repository / "source.txt").write_text("initial base\n", encoding="utf-8")
        git(self.repository, "add", "source.txt")
        git(self.repository, "commit", "-m", "initial base")
        self.initial = git(self.repository, "rev-parse", "HEAD")
        self.base_ref = StableId("refs/heads/recovery-base")
        git(self.repository, "update-ref", str(self.base_ref), self.initial)
        self.config = GitRepositoryConfig(
            StableId("todo-project"), StableId("fixture-repository"), self.repository,
            self.root / "worktrees", self.root / "provider-journal",
            StableId("refs/heads/main"), StableId("refs/heads/todo-integration"),
        )
        git(self.repository, "branch", "todo-integration", self.initial)
        self.provider = GitRepositoryProvider(self.config)
        project = self.config.project_id
        self.context = ProviderCallContext(
            project,
            EntityRef(project, EntityKind.ACTOR, StableId("reader"), incarnation_id=StableId("reader-inc")),
            EntityRef(project, EntityKind.CAPABILITY, StableId("reader-cap")),
            StableId("host-context"), StableId("read-scope"),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_observes_exact_ref_with_query_correlated_read_only_receipt(self) -> None:
        request = SourceObservationRequest(
            self.context, StableId("base-query-1"), base_ref=self.base_ref,
        )
        before_effects = git(self.repository, "worktree", "list", "--porcelain")
        result = self.provider.observe(request)

        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        revision = self.provider.qualified_revision(self.base_ref)
        self.assertEqual(result.value.repository_id, self.config.repository_id)
        self.assertEqual(result.value.source_digest.hex, revision.digest)
        self.assertEqual(result.value.base_digest, result.value.source_digest)
        self.assertEqual(result.value.source_revision, revision.ref)
        self.assertEqual(result.value.working_tree, WorkingTreeState.CLEAN)
        self.assertEqual(result.value.inputs, ())
        self.assertEqual(result.value.artifacts, ())
        self.assertEqual(result.receipt.correlation_id, request.correlation_id)
        self.assertEqual(result.receipt.request_digest, provider_request_digest(request))
        self.assertEqual(result.receipt.provenance_ref, self.base_ref)
        self.assertEqual(before_effects, git(self.repository, "worktree", "list", "--porcelain"))

    def test_same_query_shape_observes_a_moved_base_ref_as_a_new_identity(self) -> None:
        request = SourceObservationRequest(
            self.context, StableId("base-query-move"), base_ref=self.base_ref,
        )
        first = self.provider.observe(request)
        self.assertEqual(first.status, ProviderStatus.OBSERVED_SUCCESS, first)

        (self.repository / "source.txt").write_text("new base\n", encoding="utf-8")
        git(self.repository, "add", "source.txt")
        git(self.repository, "commit", "-m", "advance recovery base")
        moved = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "update-ref", str(self.base_ref), moved)

        second = self.provider.observe(request)
        self.assertEqual(second.status, ProviderStatus.OBSERVED_SUCCESS, second)
        self.assertEqual(second.receipt.request_digest, first.receipt.request_digest)
        self.assertEqual(second.receipt.correlation_id, request.correlation_id)
        self.assertEqual(second.receipt.provenance_ref, self.base_ref)
        self.assertEqual(second.value.source_revision, StableId(moved))
        self.assertNotEqual(second.value.source_digest, first.value.source_digest)

