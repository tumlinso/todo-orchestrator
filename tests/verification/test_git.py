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
        self.integration_ref = StableId("refs/heads/todo-orchestrator/integration")
        git(self.repository, "branch", "todo-orchestrator/integration", self.initial_head)
        self.config = GitRepositoryConfig(
            StableId("todo-project"), StableId("fixture-repository"), self.repository,
            self.root / "worktrees", self.root / "provider-journal",
            StableId("refs/heads/main"), self.integration_ref,
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
            self.config.integration_ref,
            StableId(expected_destination or git(self.repository, "rev-parse", self.config.integration_ref.value)),
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
        self.assertEqual(clean.value.source_revision, StableId(git(
            self.provider.workspace_path_for(StableId("workspace-source")), "rev-parse", "HEAD",
        )))

    def test_default_source_policy_includes_authored_todo_orchestrator_files(self) -> None:
        self.assertEqual(self.config.excluded_paths, ())
        self.create_workspace("workspace-authored-config")
        workspace = self.provider.qualify_workspace(
            StableId("workspace-authored-config"), self.target, StableId("correlation-authored-config"),
        )
        request = SourceObservationRequest(
            self.context, StableId("source-observation-authored-config"), attempt=EntityRef(
                StableId("todo-project"), EntityKind.ATTEMPT, StableId("attempt-authored-config")),
            workspace_id=workspace.workspace_id, target=self.target,
        )

        content = b"authored project configuration\n"
        authored = self.provider.workspace_path_for(StableId("workspace-authored-config"))
        authored = authored / ".todo-orchestrator" / "project.json"
        authored.parent.mkdir()
        authored.write_bytes(content)

        observed = self.provider.observe(request)
        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS, observed)
        self.assertEqual(observed.value.working_tree, WorkingTreeState.DIRTY)
        self.assertIn(Sha256Digest(__import__("hashlib").sha256(content).hexdigest()),
                      {item.digest for item in observed.value.inputs})

    def test_source_identity_binds_exclusion_policy_even_when_selected_contents_match(self) -> None:
        self.create_workspace("workspace-policy-identity")
        workspace = self.provider.qualify_workspace(
            StableId("workspace-policy-identity"), self.target, StableId("correlation-policy-identity"),
        )
        request = SourceObservationRequest(
            self.context, StableId("source-observation-policy-identity"), attempt=EntityRef(
                StableId("todo-project"), EntityKind.ATTEMPT, StableId("attempt-policy-identity")),
            workspace_id=workspace.workspace_id, target=self.target,
        )
        content = self.provider.observe(request)
        self.assertEqual(content.status, ProviderStatus.OBSERVED_SUCCESS, content)
        self.assertEqual(content.value.working_tree, WorkingTreeState.CLEAN)
        self.assertEqual(content.value.source_digest.hex, self.provider.qualified_revision().digest)

        alternate_config = GitRepositoryConfig(
            self.config.project_id, self.config.repository_id, self.repository,
            self.config.workspace_root, self.config.journal_root,
            self.config.base_ref, self.config.integration_ref,
            excluded_paths=("unused-source-directory",),
        )
        alternate_provider = GitRepositoryProvider(alternate_config)
        alternate = alternate_provider.observe(request)
        self.assertEqual(alternate.status, ProviderStatus.OBSERVED_SUCCESS, alternate)
        self.assertEqual(alternate.value.working_tree, WorkingTreeState.CLEAN)
        self.assertEqual(alternate.value.inputs, content.value.inputs)
        self.assertNotEqual(alternate.value.source_digest, content.value.source_digest)
        self.assertEqual(alternate.value.source_digest.hex, alternate_provider.qualified_revision().digest)
        self.assertNotEqual(alternate_provider.qualified_revision().digest,
                            self.provider.qualified_revision().digest)

    def test_workspace_inspection_rejects_same_path_branch_recreation(self) -> None:
        request = self.create_workspace("workspace-reincarnated", "create-reincarnated")
        path = self.provider.workspace_path_for(StableId("workspace-reincarnated"))
        branch = self.provider._workspace_branch(StableId("workspace-reincarnated"))
        git(self.repository, "worktree", "remove", "--force", str(path))
        git(self.repository, "worktree", "add", str(path), branch.value)

        query = EffectInspectionRequest(
            self.context, request.operation_id, request.idempotency_key,
            provider_request_digest(request), StableId("inspect-reincarnated"), request,
        )
        result = self.provider.inspect(query)
        self.assertEqual(result.status, ProviderStatus.UNKNOWN)

    def test_create_workspace_retry_reuses_durable_incarnation_after_record_only_crash(self) -> None:
        revision = self.provider.qualified_revision()
        request = GitEffectRequest(
            self.context, StableId("create-record-crash"), StableId("idem-create-record-crash"),
            GitOperationKind.CREATE_WORKSPACE, Sha256Digest(revision.digest), 1,
            StableId("workspace-record-crash"), self.config.base_ref,
        )

        def fail(stage: str, _request: GitEffectRequest) -> None:
            if stage == "after_workspace_record":
                raise RuntimeError("injected crash after durable workspace intent")

        interrupted = GitRepositoryProvider(self.config, failure_hook=fail).perform(request)
        self.assertEqual(interrupted.status, ProviderStatus.UNAVAILABLE)
        query = EffectInspectionRequest(
            self.context, request.operation_id, request.idempotency_key, provider_request_digest(request),
            StableId("inspect-record-crash"), request,
        )
        inspected = self.provider.inspect(query)
        self.assertEqual(inspected.status, ProviderStatus.OBSERVED_SUCCESS, inspected)
        self.assertEqual(inspected.value.disposition, GitEffectDisposition.NOT_APPLIED)

        retried = self.provider.retry_not_applied(request)
        self.assertEqual(retried.status, ProviderStatus.OBSERVED_SUCCESS, retried)
        self.assertEqual(retried.value.disposition, GitEffectDisposition.APPLIED)
        qualified = self.provider.qualify_workspace(
            StableId("workspace-record-crash"), self.target, StableId("record-crash-qualified"),
        )
        self.assertIsNotNone(qualified.isolation.worktree_admin)

    def test_index_only_staged_content_changes_identity_and_reports_dirty(self) -> None:
        self.create_workspace("workspace-index-only")
        workspace = self.provider.qualify_workspace(
            StableId("workspace-index-only"), self.target, StableId("correlation-index-only"),
        )
        request = SourceObservationRequest(
            self.context, StableId("source-observation-index-only"), attempt=EntityRef(
                StableId("todo-project"), EntityKind.ATTEMPT, StableId("attempt-index-only")),
            workspace_id=workspace.workspace_id, target=self.target,
        )
        clean = self.provider.observe(request)
        self.assertEqual(clean.status, ProviderStatus.OBSERVED_SUCCESS, clean)
        self.assertEqual(clean.value.working_tree, WorkingTreeState.CLEAN)

        staged_content = b"staged blob without a worktree file\n"
        staged_file = self.root / "staged-index-content.txt"
        staged_file.write_bytes(staged_content)
        path = self.provider.workspace_path_for(StableId("workspace-index-only"))
        blob = git(path, "hash-object", "-w", str(staged_file))
        git(path, "update-index", "--add", "--cacheinfo", f"100644,{blob},index-only.txt")
        self.assertFalse((path / "index-only.txt").exists())

        dirty = self.provider.observe(request)
        self.assertEqual(dirty.status, ProviderStatus.OBSERVED_SUCCESS, dirty)
        self.assertEqual(dirty.value.working_tree, WorkingTreeState.DIRTY)
        self.assertNotEqual(dirty.value.source_digest, clean.value.source_digest)
        self.assertIn(Sha256Digest(__import__("hashlib").sha256(staged_content).hexdigest()),
                      {item.digest for item in dirty.value.inputs})

    def test_integration_uses_expected_old_ref_and_publishes_merge_commit(self) -> None:
        self.create_workspace("workspace-integrate")
        source = self.make_source_commit("workspace-integrate")
        request = self.integrate_request("workspace-integrate", source)

        result = self.provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), str(result.value.external_ref))
        parents = git(self.repository, "show", "-s", "--format=%P", self.config.integration_ref.value).split()
        self.assertEqual(parents, [self.initial_head, source])
        self.assertEqual(git(self.repository, "rev-parse", "refs/heads/main"), self.initial_head)
        self.assertTrue((self.provider.workspace_path_for(StableId("workspace-integrate")) / "feature.txt").exists())

    def test_stale_destination_ref_is_refused_without_advancing_it(self) -> None:
        self.create_workspace("workspace-stale")
        source = self.make_source_commit("workspace-stale")
        (self.repository / "destination.txt").write_text("advance\n", encoding="utf-8")
        git(self.repository, "add", "destination.txt")
        git(self.repository, "commit", "-m", "advance destination")
        current = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "update-ref", self.config.integration_ref.value, current)
        request = self.integrate_request("workspace-stale", source, expected_destination=self.initial_head,
                                         operation_id="stale-integration")

        result = self.provider.perform(request)
        self.assertEqual(result.value.disposition, GitEffectDisposition.REJECTED)
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), current)

    def test_inspection_never_attributes_another_operations_merge_commit(self) -> None:
        self.create_workspace("workspace-operation-identity")
        source = self.make_source_commit("workspace-operation-identity")
        expected_old = git(self.repository, "rev-parse", self.config.integration_ref.value)
        first = self.integrate_request(
            "workspace-operation-identity", source, expected_destination=expected_old,
            operation_id="integration-first-identity",
        )
        first_result = self.provider.perform(first)
        self.assertEqual(first_result.status, ProviderStatus.OBSERVED_SUCCESS, first_result)
        self.assertEqual(first_result.value.disposition, GitEffectDisposition.APPLIED)
        first_commit = git(self.repository, "rev-parse", self.config.integration_ref.value)

        second = self.integrate_request(
            "workspace-operation-identity", source, expected_destination=expected_old,
            operation_id="integration-second-identity",
        )
        second_result = self.provider.perform(second)
        self.assertEqual(second_result.status, ProviderStatus.OBSERVED_SUCCESS, second_result)
        self.assertEqual(second_result.value.disposition, GitEffectDisposition.REJECTED)

        query = EffectInspectionRequest(
            self.context, second.operation_id, second.idempotency_key,
            provider_request_digest(second), StableId("inspect-second-identity"), second,
        )
        inspected = self.provider.inspect(query)
        self.assertEqual(inspected.status, ProviderStatus.UNKNOWN, inspected)
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), first_commit)

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
        destination_before = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "update-ref", self.config.integration_ref.value, destination_before)
        request = self.integrate_request("workspace-conflict", source,
                                         expected_destination=destination_before, operation_id="conflict-integration")

        result = self.provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.CONFLICT)
        self.assertTrue(result.value.conflict_refs)
        self.assertIsNotNone(result.value.conflict_tree)
        self.assertEqual(git(self.repository, "cat-file", "-t", str(result.value.conflict_tree)), "tree")
        self.assertEqual(git(self.repository, "rev-parse", "--verify", str(result.value.external_ref)),
                         str(result.value.conflict_tree))
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), destination_before)
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
        advanced = git(self.repository, "rev-parse", self.config.integration_ref.value)
        inspection = EffectInspectionRequest(
            self.context, request.operation_id, request.idempotency_key, provider_request_digest(request),
            request.operation_id, request,
        )
        recovered = provider.inspect(inspection)
        self.assertEqual(recovered.status, ProviderStatus.OBSERVED_SUCCESS, recovered)
        self.assertEqual(recovered.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), advanced)
        self.assertEqual(stages, ["before_effect", "after_commit_object", "after_effect"])

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
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), self.initial_head)

    def test_crash_after_merge_object_is_inspected_then_retried_without_new_object(self) -> None:
        self.create_workspace("workspace-object-recovery")
        source = self.make_source_commit("workspace-object-recovery")
        request = self.integrate_request("workspace-object-recovery", source,
                                         operation_id="object-recovery")

        def fail(stage: str, _request: GitEffectRequest) -> None:
            if stage == "after_commit_object":
                raise RuntimeError("injected crash after merge commit creation")

        provider = GitRepositoryProvider(self.config, failure_hook=fail)
        interrupted = provider.perform(request)
        self.assertEqual(interrupted.status, ProviderStatus.UNAVAILABLE)
        journal = provider._read_json(provider._operation_record_path(request.operation_id))
        pending_commit = journal["pending_commit"]["commit"]
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), self.initial_head)

        inspection = EffectInspectionRequest(
            self.context, request.operation_id, request.idempotency_key, provider_request_digest(request),
            StableId("object-inspection"), request,
        )
        inspected = provider.inspect(inspection)
        self.assertEqual(inspected.status, ProviderStatus.OBSERVED_SUCCESS, inspected)
        self.assertEqual(inspected.value.disposition, GitEffectDisposition.NOT_APPLIED)
        retried = provider.retry_not_applied(request)
        self.assertEqual(retried.status, ProviderStatus.OBSERVED_SUCCESS, retried)
        self.assertEqual(retried.value.external_ref, StableId(pending_commit))
        self.assertEqual(git(self.repository, "rev-parse", self.config.integration_ref.value), pending_commit)


if __name__ == "__main__":
    unittest.main()
