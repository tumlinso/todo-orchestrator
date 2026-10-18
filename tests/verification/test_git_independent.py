"""Independent V04 tests using only disposable, real Git repositories."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class TemporaryGitRepository:
    """Small real-Git fixture with linked worktrees and byte-level snapshots."""

    def __init__(self, root: Path):
        self.root = root
        self.executable = shutil.which("git")
        if self.executable is None:
            raise unittest.SkipTest("Git is required for V04 provider qualification")
        self.repository = root / "repository"
        self.repository.mkdir()
        self.worktree_root = root / "worktrees"
        self.worktree_root.mkdir()
        self.git(self.repository, "init", "--quiet", "--initial-branch=main")
        self.git(self.repository, "config", "user.name", "Todo Orchestrator Fixture")
        self.git(self.repository, "config", "user.email", "todo-fixture@example.invalid")
        (self.repository / "README.md").write_bytes(b"fixture repository\n")
        (self.repository / "module.txt").write_bytes(b"base value\nsecond line\n")
        self.git(self.repository, "add", "README.md", "module.txt")
        self.git(self.repository, "commit", "--quiet", "-m", "disposable base")
        self.base = self.git(self.repository, "rev-parse", "HEAD").stdout.strip()
        self.worktrees: dict[str, Path] = {"repository": self.repository}

    def git(self, cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["GIT_OPTIONAL_LOCKS"] = "0"
        result = subprocess.run(
            [self.executable, *args],
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if check and result.returncode:
            raise AssertionError(
                f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
            )
        return result

    def add_worktree(
        self,
        name: str,
        *,
        branch: str | None = None,
        start: str | None = None,
    ) -> Path:
        path = self.worktree_root / name
        args = ["worktree", "add", "--quiet"]
        if branch is None:
            args.extend(["--detach", str(path), start or self.base])
        else:
            args.extend(["-b", branch, str(path), start or self.base])
        self.git(self.repository, *args)
        self.worktrees[name] = path
        self.git(path, "config", "user.name", "Todo Orchestrator Fixture")
        self.git(path, "config", "user.email", "todo-fixture@example.invalid")
        return path

    def identities(self, worktree: Path) -> dict[str, str]:
        top = self.git(worktree, "rev-parse", "--show-toplevel").stdout.strip()
        git_dir = self.git(worktree, "rev-parse", "--absolute-git-dir").stdout.strip()
        common_dir = self.git(worktree, "rev-parse", "--git-common-dir").stdout.strip()
        index = self.git(worktree, "rev-parse", "--git-path", "index").stdout.strip()
        if not os.path.isabs(common_dir):
            common_dir = str((worktree / common_dir).resolve())
        if not os.path.isabs(index):
            index = str((worktree / index).resolve())
        return {
            "root": str(Path(top).resolve()),
            "git_dir": str(Path(git_dir).resolve()),
            "common_dir": str(Path(common_dir).resolve()),
            "index": str(Path(index).resolve()),
            "head": self.git(worktree, "rev-parse", "HEAD").stdout.strip(),
        }

    def snapshot(self, worktree: Path) -> tuple[str, bytes, str, tuple[tuple[str, bytes | str], ...]]:
        identities = self.identities(worktree)
        index = Path(identities["index"])
        status = self.git(
            worktree, "status", "--porcelain=v2", "--untracked-files=all"
        ).stdout
        contents: list[tuple[str, bytes | str]] = []
        for path in sorted(worktree.rglob("*")):
            relative = path.relative_to(worktree)
            if relative.parts[0] == ".git" or path.is_dir():
                continue
            value: bytes | str = os.readlink(path) if path.is_symlink() else path.read_bytes()
            contents.append((relative.as_posix(), value))
        return identities["head"], index.read_bytes(), status, tuple(contents)

    def make_dirty_source(self, worktree: Path) -> None:
        # One staged tracked edit, one later unstaged edit, and one untracked file.
        (worktree / "README.md").write_bytes(b"staged owner text\n")
        self.git(worktree, "add", "README.md")
        (worktree / "module.txt").write_bytes(b"unstaged owner text\nsecond line\n")
        (worktree / "new untracked.bin").write_bytes(b"untracked owner bytes\x00\xff")

    def make_conflict(self) -> tuple[Path, Path, str]:
        source = self.add_worktree("source", branch="source")
        integration = self.add_worktree("integration", branch="integration")
        (source / "module.txt").write_bytes(b"source side\nsecond line\n")
        self.git(source, "add", "module.txt")
        self.git(source, "commit", "--quiet", "-m", "source change")
        (integration / "module.txt").write_bytes(b"destination side\nsecond line\n")
        self.git(integration, "add", "module.txt")
        self.git(integration, "commit", "--quiet", "-m", "destination change")
        merged = self.git(
            integration, "merge", "--no-commit", "--no-ff", "source", check=False
        )
        if merged.returncode == 0:
            raise AssertionError("fixture changes unexpectedly merged without a conflict")
        return source, integration, merged.stderr


class TemporaryGitFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-v04-git-")
        self.addCleanup(self.temporary.cleanup)
        self.git = TemporaryGitRepository(Path(self.temporary.name))

    def test_linked_worktrees_have_distinct_roots_gitdirs_indexes_and_heads(self):
        first = self.git.add_worktree("first", branch="first")
        second = self.git.add_worktree("second", branch="second")
        first_ids = self.git.identities(first)
        second_ids = self.git.identities(second)

        self.assertNotEqual(first_ids["root"], second_ids["root"])
        self.assertNotEqual(first_ids["git_dir"], second_ids["git_dir"])
        self.assertNotEqual(first_ids["index"], second_ids["index"])
        self.assertEqual(first_ids["head"], second_ids["head"])
        # Linked worktrees share common Git storage; it is not an isolation proof.
        self.assertEqual(first_ids["common_dir"], second_ids["common_dir"])

    def test_snapshot_distinguishes_staged_unstaged_and_untracked_bytes(self):
        source = self.git.add_worktree("source", branch="source")
        before = self.git.snapshot(source)
        self.git.make_dirty_source(source)
        after = self.git.snapshot(source)

        self.assertEqual(before[0], after[0])  # no commit/ref change
        self.assertNotEqual(before[1], after[1])  # staged content changes index
        self.assertNotEqual(before[2], after[2])  # staged/unstaged/untracked status
        observed = dict(after[3])
        self.assertEqual(observed["README.md"], b"staged owner text\n")
        self.assertEqual(observed["module.txt"], b"unstaged owner text\nsecond line\n")
        self.assertEqual(observed["new untracked.bin"], b"untracked owner bytes\x00\xff")

    def test_conflict_fixture_leaves_conflict_markers_and_unmerged_index(self):
        _, integration, _ = self.git.make_conflict()
        before = self.git.snapshot(integration)
        module = dict(before[3])["module.txt"]

        self.assertIn(b"<<<<<<<", module)
        self.assertIn(b"=======", module)
        self.assertIn(b">>>>>>>", module)
        self.assertIn("u ", before[2])
        stages = self.git.git(integration, "ls-files", "-u", "--", "module.txt").stdout
        self.assertTrue(stages)

    def test_expected_old_ref_update_rejects_a_stale_destination_head(self):
        integration = self.git.add_worktree("integration", branch="integration")
        expected = self.git.git(integration, "rev-parse", "HEAD").stdout.strip()
        (integration / "destination.txt").write_bytes(b"advanced\n")
        self.git.git(integration, "add", "destination.txt")
        self.git.git(integration, "commit", "--quiet", "-m", "advance destination")
        advanced = self.git.git(integration, "rev-parse", "HEAD").stdout.strip()

        stale = self.git.git(
            integration,
            "update-ref",
            "refs/heads/integration",
            expected,
            expected,
            check=False,
        )
        self.assertNotEqual(stale.returncode, 0)
        self.assertEqual(
            self.git.git(integration, "rev-parse", "refs/heads/integration").stdout.strip(),
            advanced,
        )


if __name__ == "__main__":
    unittest.main()
