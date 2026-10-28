"""Trusted gitlink identity and nested-worktree safety checks."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from todo_orchestrator.contracts import (
    EntityKind,
    EntityRef,
    GitEffectRequest,
    GitOperationKind,
    ProviderCallContext,
    ProviderStatus,
    Sha256Digest,
    SourceObservationRequest,
    StableId,
    WorkingTreeState,
)
from todo_orchestrator.providers.git import GitProviderError, GitRepositoryConfig, GitRepositoryProvider


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


class GitlinkProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="todo-gitlink-provider-")
        self.root = Path(self.temp.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.nested_source = self.root / "nested-source"
        self.nested_source.mkdir()
        for path in (self.repository, self.nested_source):
            subprocess.run(["git", "init", "-b", "main", str(path)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            git(path, "config", "user.name", "Fixture Owner")
            git(path, "config", "user.email", "fixture@example.invalid")

        (self.repository / "ordinary.txt").write_text("unchanged parent file\n", encoding="utf-8")
        git(self.repository, "add", "ordinary.txt")
        git(self.repository, "commit", "-m", "parent base")
        (self.nested_source / ".gitignore").write_text("ignored.dat\n", encoding="utf-8")
        (self.nested_source / ".gitattributes").write_text("nested.txt filter=probe\n", encoding="utf-8")
        (self.nested_source / "nested.txt").write_text("nested base\n", encoding="utf-8")
        git(self.nested_source, "add", ".gitignore", ".gitattributes", "nested.txt")
        git(self.nested_source, "commit", "-m", "nested base")
        self.nested_oid = git(self.nested_source, "rev-parse", "HEAD")
        git(self.repository, "update-index", "--add", "--cacheinfo",
            f"160000,{self.nested_oid},modules/probe")
        git(self.repository, "commit", "-m", "record nested source pointer")
        self.head = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "branch", "todo-orchestrator/integration", self.head)

        self.project = StableId("gitlink-fixture")
        self.repository_id = StableId("gitlink-repository")
        self.base_ref = StableId("refs/heads/main")
        self.integration_ref = StableId("refs/heads/todo-orchestrator/integration")
        self.default_provider = GitRepositoryProvider(self._config("reject"))
        self.provider = GitRepositoryProvider(self._config("opaque_clean"))
        self.context = ProviderCallContext(
            self.project,
            EntityRef(self.project, EntityKind.ACTOR, StableId("owner"), incarnation_id=StableId("owner-inc")),
            EntityRef(self.project, EntityKind.CAPABILITY, StableId("gitlink-test-cap")),
            StableId("gitlink-test-host"), StableId("gitlink-test-scope"),
        )
        self.target = EntityRef(self.project, EntityKind.WORK_ITEM, StableId("gitlink-test-item"),
                                definition_revision_id=StableId("gitlink-test-definition"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _config(self, policy: str) -> GitRepositoryConfig:
        return GitRepositoryConfig(
            self.project, self.repository_id, self.repository,
            self.root / f"worktrees-{policy}", self.root / f"journal-{policy}",
            self.base_ref, self.integration_ref, gitlink_policy=policy,
        )

    def _create_workspace(self, provider: GitRepositoryProvider, workspace_id: str) -> Path:
        revision = provider.qualified_revision()
        request = GitEffectRequest(
            self.context, StableId(f"create-{workspace_id}"), StableId(f"idem-{workspace_id}"),
            GitOperationKind.CREATE_WORKSPACE, Sha256Digest(revision.digest), 1,
            StableId(workspace_id), provider.config.base_ref,
        )
        result = provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        return provider.workspace_path_for(StableId(workspace_id))

    def test_default_provider_still_rejects_gitlinks_and_non_gitlink_identity_is_stable(self) -> None:
        with self.assertRaisesRegex(GitProviderError, "explicitly trusted"):
            self.default_provider.qualified_revision()

        ordinary = self.root / "ordinary-only"
        ordinary.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(ordinary)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git(ordinary, "config", "user.name", "Fixture Owner")
        git(ordinary, "config", "user.email", "fixture@example.invalid")
        (ordinary / "plain.txt").write_bytes(b"plain\n")
        git(ordinary, "add", "plain.txt")
        git(ordinary, "commit", "-m", "ordinary base")
        git(ordinary, "branch", "todo-orchestrator/integration")
        configs = [
            GitRepositoryConfig(self.project, self.repository_id, ordinary,
                                self.root / f"ordinary-worktrees-{policy}",
                                self.root / f"ordinary-journal-{policy}", self.base_ref,
                                self.integration_ref, gitlink_policy=policy)
            for policy in ("reject", "opaque_clean")
        ]
        self.assertEqual(
            GitRepositoryProvider(configs[0]).qualified_revision().digest,
            GitRepositoryProvider(configs[1]).qualified_revision().digest,
        )

    def test_uninitialized_gitlink_is_pointer_only_and_reported_in_source_inputs(self) -> None:
        revision = self.provider.qualified_revision()
        expected_pointer = hashlib.sha256(
            b"todo-orchestrator-gitlink-pointer-v1\0" + self.nested_oid.encode("ascii")
        ).hexdigest()
        pointer = next(entry for entry in self.provider._commit_manifest(self.head) if entry.mode == "160000")
        self.assertEqual(pointer.digest, expected_pointer)

        workspace = self._create_workspace(self.provider, "gitlink-uninitialized")
        current, staged, safety = self.provider._path_state(workspace, self.head)
        self.assertEqual(safety.value, "clean")
        entry = next(entry for entry in current if entry.mode == "160000")
        self.assertEqual(entry.coverage, "uninitialized-pointer-only")
        self.assertEqual(current, staged)

        request = SourceObservationRequest(
            self.context, StableId("source-gitlink-uninitialized"),
            attempt=EntityRef(self.project, EntityKind.ATTEMPT, StableId("attempt-gitlink-uninitialized")),
            workspace_id=StableId("gitlink-uninitialized"), target=self.target,
        )
        observed = self.provider.observe(request)
        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS, observed)
        self.assertEqual(observed.value.working_tree, WorkingTreeState.CLEAN)
        self.assertEqual(observed.value.source_digest.hex, revision.digest)
        gitlink_inputs = [item for item in observed.value.inputs if str(item.name).startswith("gitlink-")]
        self.assertEqual(len(gitlink_inputs), 1)
        self.assertIn("uninitialized-pointer-only", str(gitlink_inputs[0].name))
        self.assertEqual(gitlink_inputs[0].digest.hex, expected_pointer)

    def _initialize_nested_checkout(self, workspace: Path) -> Path:
        nested = workspace / "modules" / "probe"
        nested.parent.mkdir(parents=True, exist_ok=True)
        if nested.exists():
            nested.rmdir()
        gitdir = self.provider._common_git_dir(workspace) / "modules" / "probe"
        gitdir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--separate-git-dir", str(gitdir), str(self.nested_source), str(nested)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return nested

    def test_initialized_gitlink_requires_trusted_gitfile_exact_head_and_no_nested_changes(self) -> None:
        workspace = self._create_workspace(self.provider, "gitlink-initialized")
        nested = self._initialize_nested_checkout(workspace)
        marker = self.root / "filter-command-was-run"
        marker_command = shlex.quote(str(marker))
        git(nested, "config", "filter.probe.clean", f"printf clean >> {marker_command}; cat")
        git(nested, "config", "filter.probe.smudge", f"printf smudge >> {marker_command}; cat")
        git(nested, "config", "core.fsmonitor", f"printf fsmonitor >> {marker_command}")
        current, _staged, safety = self.provider._path_state(workspace, self.head)
        self.assertEqual(safety.value, "clean")
        self.assertFalse(marker.exists(),
                         f"source observation must not execute repository-selected filters or fsmonitor: "
                         f"{marker.read_text() if marker.exists() else ''}")
        entry = next(entry for entry in current if entry.mode == "160000")
        self.assertEqual(entry.coverage, "initialized-clean-at-committed-pointer")

        # Initialization changes evidence coverage but not source identity; both
        # states are bound to the same immutable parent gitlink OID.
        uninitialized_workspace = self._create_workspace(self.provider, "gitlink-uninitialized-peer")
        uninitialized, _index, _safety = self.provider._path_state(uninitialized_workspace, self.head)
        self.assertEqual(self.provider._source_digest(current, current),
                         self.provider._source_digest(uninitialized, uninitialized))

        (nested / "nested.txt").write_text("modified\n", encoding="utf-8")
        with self.assertRaisesRegex(GitProviderError, "unverified changes"):
            self.provider._path_state(workspace, self.head)
        git(nested, "checkout", "--", "nested.txt")

        (nested / "ignored.dat").write_text("ignored content\n", encoding="utf-8")
        with self.assertRaisesRegex(GitProviderError, "unverified changes"):
            self.provider._path_state(workspace, self.head)
        (nested / "ignored.dat").unlink()

        (nested / "untracked.dat").write_text("untracked content\n", encoding="utf-8")
        with self.assertRaisesRegex(GitProviderError, "unverified changes"):
            self.provider._path_state(workspace, self.head)
        (nested / "untracked.dat").unlink()

        git(nested, "checkout", "--detach", "--force", "HEAD")
        other = self.root / "other-nested-source"
        subprocess.run(["git", "clone", str(self.nested_source), str(other)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (other / "nested.txt").write_text("different commit\n", encoding="utf-8")
        git(other, "config", "user.name", "Fixture Owner")
        git(other, "config", "user.email", "fixture@example.invalid")
        git(other, "add", "nested.txt")
        git(other, "commit", "-m", "different nested source")
        new_commit = git(other, "rev-parse", "HEAD")
        git(nested, "fetch", str(other), new_commit)
        git(nested, "checkout", "--detach", new_commit)
        with self.assertRaisesRegex(GitProviderError, "committed pointer"):
            self.provider._path_state(workspace, self.head)

    def test_uninitialized_content_pointer_mismatch_and_escaping_gitfile_are_rejected(self) -> None:
        workspace = self._create_workspace(self.provider, "gitlink-tamper")
        link = workspace / "modules" / "probe"
        link.mkdir(parents=True, exist_ok=True)
        (link / "unexpected.txt").write_text("unverified\n", encoding="utf-8")
        with self.assertRaisesRegex(GitProviderError, "unverified content"):
            self.provider._path_state(workspace, self.head)
        (link / "unexpected.txt").unlink()

        nested = self._initialize_nested_checkout(workspace)
        gitfile = nested / ".git"
        gitfile.write_text("gitdir: /tmp/outside-untrusted-gitdir\n", encoding="utf-8")
        with self.assertRaisesRegex(GitProviderError, "cannot be resolved|escapes"):
            self.provider._path_state(workspace, self.head)

        symlink_workspace = self._create_workspace(self.provider, "gitlink-symlink")
        symlink_target = self.root / "external-directory"
        symlink_target.mkdir()
        link = symlink_workspace / "modules" / "probe"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.rmdir()
        link.symlink_to(symlink_target, target_is_directory=True)
        with self.assertRaisesRegex(GitProviderError, "real directory"):
            self.provider._path_state(symlink_workspace, self.head)

        ancestor_workspace = self._create_workspace(self.provider, "gitlink-symlink-parent")
        outside_modules = self.root / "external-modules"
        outside_modules.mkdir()
        (ancestor_workspace / "modules" / "probe").rmdir()
        (ancestor_workspace / "modules").rmdir()
        (ancestor_workspace / "modules").symlink_to(outside_modules, target_is_directory=True)
        with self.assertRaisesRegex(GitProviderError, "non-directory parent"):
            self.provider._path_state(ancestor_workspace, self.head)


if __name__ == "__main__":
    unittest.main()
