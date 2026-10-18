from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .fixtures import disposable_git_repository, disposable_sqlite


class DisposableFixtureTests(unittest.TestCase):
    def test_sqlite_fixture_is_created_and_closed_in_temporary_storage(self) -> None:
        with disposable_sqlite() as (database, connection):
            temporary_directory = database.parent
            self.assertTrue(database.is_relative_to(Path(tempfile.gettempdir())))
            self.assertTrue(database.is_file())
            connection.execute("CREATE TABLE fixture (value TEXT NOT NULL)")
            connection.execute("INSERT INTO fixture VALUES (?)", ("ok",))
            self.assertEqual(connection.execute("SELECT value FROM fixture").fetchone(), ("ok",))
        self.assertFalse(temporary_directory.exists())

    @unittest.skipUnless(shutil.which("git"), "Git executable is unavailable")
    def test_git_fixture_has_a_local_commit(self) -> None:
        with disposable_git_repository() as repository:
            temporary_directory = repository.parent
            self.assertTrue(repository.is_relative_to(Path(tempfile.gettempdir())))
            head = subprocess.run(
                [shutil.which("git") or "git", "rev-parse", "--verify", "HEAD"],
                cwd=repository,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(len(head.stdout.strip()), 40)
        self.assertFalse(temporary_directory.exists())


if __name__ == "__main__":
    unittest.main()
