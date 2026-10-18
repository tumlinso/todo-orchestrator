from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Iterator


@contextmanager
def disposable_sqlite() -> Iterator[tuple[Path, sqlite3.Connection]]:
    """Yield a fresh database inside a temporary directory."""
    with tempfile.TemporaryDirectory(prefix="todo-orchestrator-sqlite-") as temporary:
        database = Path(temporary) / "fixture.sqlite3"
        connection = sqlite3.connect(database)
        try:
            yield database, connection
        finally:
            connection.close()


@contextmanager
def disposable_git_repository() -> Iterator[Path]:
    """Yield a locally initialized, committed Git repository in a temp directory."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required for this disposable fixture")
    with tempfile.TemporaryDirectory(prefix="todo-orchestrator-git-") as temporary:
        repository = Path(temporary) / "repository"
        repository.mkdir()

        def run(*arguments: str) -> None:
            subprocess.run(
                [git, *arguments],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            )

        run("init", "--quiet")
        run("config", "user.name", "Todo Orchestrator Fixture")
        run("config", "user.email", "todo-fixture@example.invalid")
        (repository / "fixture.txt").write_text("disposable fixture\n")
        run("add", "fixture.txt")
        run("commit", "--quiet", "-m", "fixture")
        yield repository
