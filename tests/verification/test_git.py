"""Disposable real-Git checks for the local repository provider."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from todo_orchestrator.contracts import (
    EffectInspectionRequest,
    EntityKind,
    EntityRef,
    GitEffectDisposition,
    GitEffectRequest,
    GitOperationKind,
    ProviderCallContext,
    ProviderStatus,
    Sha256Digest,
    StableId,
    SourceObservationRequest,
    WorkingTreeState,
)
from todo_orchestrator.contracts.providers import provider_request_digest
from todo_orchestrator.providers.git import GitRepositoryConfig, GitRepositoryProvider


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip()


class GitRepositoryProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="todo-git-provider-")
        self.root = Path(self.temp.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(self.repository)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git(self.repository, "config", "user.name", "Fixture Owner")
        git(self.repository, "config", "user.email", "fixture@example.invalid")
        (self.repository / ".gitignore").write_text("ignored.out\n", encoding="utf-8")
        (self.repository / "source.txt").write_text("base\n", encoding="utf-8")
        git(self.repository, "add", ".gitignore", "source.txt")
        git(self.repository, "commit", "-m", "base")
        self.initial_head = git(self.repository, "rev-parse", "HEAD")
        self.config = GitRepositoryConfig(
            StableId("todo-project"), StableId("fixture-repository"), self.repository,
            self.root / "worktrees", self.root / "provider-journal",
            StableId("refs/heads/main"), StableId("refs/heads/main"),
        )
        self.provider = GitRepositoryProvider(self.config)
        self.context = ProviderCallContext(
            StableId("todo-project"),
            EntityRef(StableId("todo-project"), EntityKind.ACTOR, StableId("owner"), incarnation_id=StableId("owner-inc")),
            EntityRef(StableId("todo-project"), EntityKind.CAPABILITY, StableId("test-cap")),
            StableId("host-fixture"), StableId("work-scope"),
        )
        self.target = EntityRef(StableId("todo-project"), EntityKind.WORK_ITEM,
                                StableId("work-item"), definition_revision_id=StableId("definition-v1"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create_workspace(self, workspace_id: str, operation_id: str | None = None) -> GitEffectRequest:
        revision = self.provider.qualified_revision()
        request = GitEffectRequest(
            self.context, StableId(operation_id or f"create-{workspace_id}"), StableId(f"idem-create-{workspace_id}"),
            GitOperationKind.CREATE_WORKSPACE, Sha256Digest(revision.digest), 1,
            StableId(workspace_id), self.config.base_ref,
        )
        result = self.provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.APPLIED)
        return request

    def make_source_commit(self, workspace_id: str, filename: str = "feature.txt", value: str = "feature\n") -> str:
        path = self.provider.workspace_path_for(StableId(workspace_id))
        (path / filename).write_text(value, encoding="utf-8")
        git(path, "add", filename)
        git(path, "commit", "-m", "source change")
        return git(path, "rev-parse", "HEAD")

    def integrate_request(self, workspace_id: str, source_commit: str, *, expected_destination: str | None = None,
                          operation_id: str = "integrate-one") -> GitEffectRequest:
        source_revision = self.provider.qualified_revision(StableId(source_commit))
        return GitEffectRequest(
            self.context, StableId(operation_id), StableId(f"idem-{operation_id}"), GitOperationKind.INTEGRATE,
            Sha256Digest(source_revision.digest), 1, StableId(workspace_id), None, StableId(source_commit),
            self.config.integration_ref, StableId(expected_destination or self.initial_head),
        )

    def test_linked_workspaces_have_distinct_roots_indexes_and_refs(self) -> None:
        self.create_workspace("workspace-a")
        self.create_workspace("workspace-b")
        first = self.provider.qualify_workspace(StableId("workspace-a"), self.target, StableId("correlation-a"))
        second = self.provider.qualify_workspace(StableId("workspace-b"), self.target, StableId("correlation-b"))

        self.assertIsNotNone(first.isolation)
        self.assertIsNotNone(second.isolation)
        self.assertEqual(first.common_base, second.common_base)
        self.assertEqual(first.destination, second.destination)
        self.assertEqual(first.isolation.repository_storage, second.isolation.repository_storage)
        self.assertNotEqual(first.isolation.workspace_root, second.isolation.workspace_root)
        self.assertNotEqual(first.isolation.index_file, second.isolation.index_file)
        self.assertNotEqual(first.isolation.head_ref, second.isolation.head_ref)
        self.assertEqual(git(self.repository, "rev-parse", "--git-common-dir"), ".git")

    def test_source_identity_includes_ignored_untracked_contents_and_reports_dirty(self) -> None:
        self.create_workspace("workspace-source")
        workspace = self.provider.qualify_workspace(
            StableId("workspace-source"), self.target, StableId("correlation-source"),
        )
        request = SourceObservationRequest(
            self.context, StableId("source-observation"), attempt=EntityRef(
                StableId("todo-project"), EntityKind.ATTEMPT, StableId("attempt-source")),
            workspace_id=workspace.workspace_id, target=self.target,
        )
        clean = self.provider.observe(request)
        self.assertEqual(clean.status, ProviderStatus.OBSERVED_SUCCESS, clean)
        self.assertEqual(clean.value.working_tree, WorkingTreeState.CLEAN)
        before = clean.value.source_digest

        ignored = self.provider.workspace_path_for(StableId("workspace-source")) / "ignored.out"
        ignored.write_text("meaningful ignored input\n", encoding="utf-8")
        dirty = self.provider.observe(request)
        self.assertEqual(dirty.status, ProviderStatus.OBSERVED_SUCCESS, dirty)
        self.assertEqual(dirty.value.working_tree, WorkingTreeState.DIRTY)
        self.assertNotEqual(dirty.value.source_digest, before)
        self.assertIn(Sha256Digest(__import__("hashlib").sha256(b"meaningful ignored input\n").hexdigest()),
                      {item.digest for item in dirty.value.inputs})

    def test_integration_uses_expected_old_ref_and_publishes_merge_commit(self) -> None:
        self.create_workspace("workspace-integrate")
        source = self.make_source_commit("workspace-integrate")
        request = self.integrate_request("workspace-integrate", source)

        result = self.provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(git(self.repository, "rev-parse", "refs/heads/main"), str(result.value.external_ref))
        parents = git(self.repository, "show", "-s", "--format=%P", "refs/heads/main").split()
        self.assertEqual(parents, [self.initial_head, source])
        self.assertTrue((self.provider.workspace_path_for(StableId("workspace-integrate")) / "feature.txt").exists())

    def test_stale_destination_ref_is_refused_without_advancing_it(self) -> None:
        self.create_workspace("workspace-stale")
        source = self.make_source_commit("workspace-stale")
        (self.repository / "destination.txt").write_text("advance\n", encoding="utf-8")
        git(self.repository, "add", "destination.txt")
        git(self.repository, "commit", "-m", "advance destination")
        current = git(self.repository, "rev-parse", "HEAD")
        request = self.integrate_request("workspace-stale", source, expected_destination=self.initial_head,
                                         operation_id="stale-integration")

        result = self.provider.perform(request)
        self.assertEqual(result.value.disposition, GitEffectDisposition.REJECTED)
        self.assertEqual(git(self.repository, "rev-parse", "refs/heads/main"), current)

    def test_conflicting_integration_preserves_both_worktrees_and_destination_ref(self) -> None:
        self.create_workspace("workspace-conflict")
        source_path = self.provider.workspace_path_for(StableId("workspace-conflict"))
        (source_path / "source.txt").write_text("source edit\n", encoding="utf-8")
        git(source_path, "add", "source.txt")
        git(source_path, "commit", "-m", "source edit")
        source = git(source_path, "rev-parse", "HEAD")

        (self.repository / "source.txt").write_text("destination edit\n", encoding="utf-8")
        git(self.repository, "add", "source.txt")
        git(self.repository, "commit", "-m", "destination edit")
        destination_before = git(self.repository, "rev-parse", "refs/heads/main")
        request = self.integrate_request("workspace-conflict", source,
                                         expected_destination=destination_before, operation_id="conflict-integration")

        result = self.provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.CONFLICT)
        self.assertTrue(result.value.conflict_refs)
        self.assertEqual(git(self.repository, "rev-parse", "refs/heads/main"), destination_before)
        self.assertEqual((self.repository / "source.txt").read_text(encoding="utf-8"), "destination edit\n")
        self.assertEqual((source_path / "source.txt").read_text(encoding="utf-8"), "source edit\n")

    def test_crash_after_ref_advance_is_inspected_without_second_advance(self) -> None:
        self.create_workspace("workspace-recover")
        source = self.make_source_commit("workspace-recover")
        request = self.integrate_request("workspace-recover", source, operation_id="recover-integration")
        stages: list[str] = []

        def fail(stage: str, _request: GitEffectRequest) -> None:
            stages.append(stage)
            if stage == "after_effect":
                raise RuntimeError("injected crash after compare-and-set")

        provider = GitRepositoryProvider(self.config, failure_hook=fail)
        interrupted = provider.perform(request)
        self.assertEqual(interrupted.status, ProviderStatus.UNAVAILABLE)
        advanced = git(self.repository, "rev-parse", "refs/heads/main")
        inspection = EffectInspectionRequest(
            self.context, request.operation_id, request.idempotency_key, provider_request_digest(request),
            request.operation_id, request,
        )
        recovered = provider.inspect(inspection)
        self.assertEqual(recovered.status, ProviderStatus.OBSERVED_SUCCESS, recovered)
        self.assertEqual(recovered.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(git(self.repository, "rev-parse", "refs/heads/main"), advanced)
        self.assertEqual(stages, ["before_effect", "after_effect"])

    def test_dirty_destination_stays_untouched(self) -> None:
        self.create_workspace("workspace-dirty-dest")
        source = self.make_source_commit("workspace-dirty-dest")
        changed = self.repository / "staged.txt"
        changed.write_text("keep this staged data\n", encoding="utf-8")
        git(self.repository, "add", "staged.txt")
        index_before = git(self.repository, "write-tree")
        request = self.integrate_request("workspace-dirty-dest", source, operation_id="dirty-destination")

        result = self.provider.perform(request)
        self.assertEqual(result.value.disposition, GitEffectDisposition.DIRTY)
        self.assertEqual(git(self.repository, "write-tree"), index_before)
        self.assertEqual(changed.read_text(encoding="utf-8"), "keep this staged data\n")
        self.assertEqual(git(self.repository, "rev-parse", "refs/heads/main"), self.initial_head)


if __name__ == "__main__":
    unittest.main()
