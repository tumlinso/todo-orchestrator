"""Exact, bounded object reads for committed and staged Git manifests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from todo_orchestrator.contracts import StableId
from todo_orchestrator.providers.git import GitProviderError, GitRepositoryConfig, GitRepositoryProvider


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


class GitObjectBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="todo-git-object-batch-")
        self.root = Path(self.temp.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(self.repository)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git(self.repository, "config", "user.name", "Fixture Owner")
        git(self.repository, "config", "user.email", "fixture@example.invalid")

        self.binary = bytes(range(256)) * 4097 + b"\0trailing"
        (self.repository / "binary.dat").write_bytes(self.binary)
        (self.repository / "duplicate-a.dat").write_bytes(b"shared contents\n")
        (self.repository / "duplicate-b.dat").write_bytes(b"shared contents\n")
        (self.repository / "ordinary.txt").write_bytes(b"ordinary text\n")
        (self.repository / "link-target.txt").write_bytes(b"target bytes\n")
        (self.repository / "link.txt").symlink_to("link-target.txt")
        (self.repository / ".gitattributes").write_text("filtered.txt filter=probe\n", encoding="ascii")
        (self.repository / "filtered.txt").write_bytes(b"unfiltered source bytes\n")
        git(self.repository, "add", ".")
        git(self.repository, "commit", "-m", "fixture")
        self.head = git(self.repository, "rev-parse", "HEAD")
        git(self.repository, "branch", "todo-orchestrator/integration", self.head)
        self.provider = GitRepositoryProvider(GitRepositoryConfig(
            StableId("object-batch-project"), StableId("object-batch-repository"),
            self.repository, self.root / "worktrees", self.root / "journal",
            StableId("refs/heads/main"), StableId("refs/heads/todo-orchestrator/integration"),
        ))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_committed_and_index_manifests_preserve_content_and_duplicate_blob_semantics(self) -> None:
        git(self.repository, "config", "filter.probe.clean", "printf 'clean-ran' >> '" +
            str(self.root / "filter-ran") + "'; cat")
        git(self.repository, "config", "filter.probe.smudge", "printf 'smudge-ran' >> '" +
            str(self.root / "filter-ran") + "'; cat")
        git(self.repository, "config", "core.fsmonitor", "printf 'fsmonitor-ran' >> '" +
            str(self.root / "filter-ran") + "'")

        committed = self.provider._commit_manifest(self.head)
        staged = self.provider._index_manifest(self.repository)
        self.assertEqual(committed, staged)
        self.assertFalse((self.root / "filter-ran").exists(),
                         "manifest reads must not execute filters or fsmonitor")
        by_path = {entry.path.decode(): entry for entry in committed}
        self.assertEqual(by_path["binary.dat"].digest, hashlib.sha256(self.binary).hexdigest())
        self.assertEqual(by_path["ordinary.txt"].digest,
                         hashlib.sha256(b"ordinary text\n").hexdigest())
        self.assertEqual(by_path["link.txt"].mode, "120000")
        self.assertEqual(by_path["link.txt"].digest, hashlib.sha256(b"link-target.txt").hexdigest())
        self.assertEqual(by_path["duplicate-a.dat"].digest, by_path["duplicate-b.dat"].digest)

        duplicate_oid = git(self.repository, "rev-parse", f"{self.head}:duplicate-a.dat")
        content_hashes = self.provider._blob_digests([duplicate_oid, duplicate_oid])
        expected = hashlib.sha256(b"shared contents\n").hexdigest()
        self.assertEqual(content_hashes, (expected, expected))

    def test_missing_non_blob_mismatched_and_truncated_records_are_rejected(self) -> None:
        with self.assertRaises(GitProviderError):
            self.provider._blob_digests(["f" * 40])

        commit_oid = self.head
        with self.assertRaisesRegex(GitProviderError, "wrong object"):
            self.provider._blob_digests([commit_oid])

        oid = git(self.repository, "rev-parse", f"{self.head}:ordinary.txt")
        cases = {
            "mismatched-oid": f"{('0' if oid[0] != '0' else '1') + oid[1:]} blob 1\nx\n".encode(),
            "malformed-size": f"{oid} blob nope\nx\n".encode(),
            "truncated": f"{oid} blob 8\nxx".encode(),
            "wrong-content": f"{oid} blob 1\nx\n".encode(),
        }
        for name, output in cases.items():
            with self.subTest(name=name), self._fake_git(self, output=output):
                with self.assertRaises(GitProviderError):
                    self.provider._blob_digests([oid])

    def test_sha256_object_ids_are_verified_with_their_git_object_framing(self) -> None:
        content = b"sha256-format blob\n"
        object_hash = hashlib.sha256(f"blob {len(content)}\0".encode() + content).hexdigest()
        response = f"{object_hash} blob {len(content)}\n".encode() + content + b"\n"
        with self._fake_git(self, output=response):
            self.assertEqual(self.provider._blob_digests([object_hash]),
                             (hashlib.sha256(content).hexdigest(),))

    def test_batch_command_timeout_is_bounded(self) -> None:
        oid = git(self.repository, "rev-parse", f"{self.head}:ordinary.txt")
        with tempfile.TemporaryDirectory(prefix="todo-fake-git-timeout-") as directory:
            executable = Path(directory) / "git"
            executable.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(2)\n", encoding="ascii")
            executable.chmod(0o755)
            environment = self.provider._environment()
            environment["PATH"] = directory
            provider = GitRepositoryProvider(GitRepositoryConfig(
                StableId("timeout-project"), StableId("timeout-repository"),
                self.repository, self.root / "timeout-worktrees", self.root / "timeout-journal",
                StableId("refs/heads/main"), StableId("refs/heads/todo-orchestrator/integration"),
                command_timeout_seconds=0.1,
            ))
            started = time.monotonic()
            with patch.object(provider, "_environment", return_value=environment):
                with self.assertRaisesRegex(GitProviderError, "bounded batch"):
                    provider._blob_digests([oid])
            self.assertLess(time.monotonic() - started, 1.0)

    class _fake_git:
        def __init__(self, testcase: "GitObjectBatchTests", *, output: bytes) -> None:
            self.testcase = testcase
            self.output = output

        def __enter__(self):
            self.directory = tempfile.TemporaryDirectory(prefix="todo-fake-git-object-")
            path = Path(self.directory.name) / "git"
            encoded = repr(self.output)
            path.write_text(
                "#!/usr/bin/python3\nimport sys\nsys.stdout.buffer.write(" + encoded + ")\n",
                encoding="ascii",
            )
            path.chmod(0o755)
            environment = self.testcase.provider._environment()
            environment["PATH"] = self.directory.name
            self.patch = patch.object(self.testcase.provider, "_environment", return_value=environment)
            self.patch.start()
            return self

        def __exit__(self, *_exc) -> None:
            self.patch.stop()
            self.directory.cleanup()


if __name__ == "__main__":
    unittest.main()
