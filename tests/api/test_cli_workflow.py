"""Disposable project smoke for the native CLI and public application facade."""

import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
import io
import json

from todo_orchestrator.api.cli import main


class CliWorkflowTests(unittest.TestCase):
    def test_init_preview_commit_and_read_use_disposable_native_authority(self):
        with tempfile.TemporaryDirectory(prefix="todo-cli-flow-") as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            credential = "disposable CLI credential for isolated smoke"
            token_path = Path(temporary) / "owner.token"
            plan_path = Path(temporary) / "plan.json"
            preview_path = Path(temporary) / "preview.json"
            projection_path = Path(temporary) / "read-model.json"
            project_id = "example-project"
            authority_id = "example-authority"
            example = Path(__file__).resolve().parents[2] / "references" / "quickstart-plan.json"
            plan_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            previous = os.environ.get("TODO_OWNER_CREDENTIAL")
            os.environ["TODO_OWNER_CREDENTIAL"] = credential
            try:
                self.assertEqual(self._run([
                    "--root", str(root), "init", "--project-id", project_id,
                    "--repository-id", "example-repository", "--authority-id", authority_id,
                    "--token-output", str(token_path),
                ]), 0)
            finally:
                if previous is None:
                    os.environ.pop("TODO_OWNER_CREDENTIAL", None)
                else:
                    os.environ["TODO_OWNER_CREDENTIAL"] = previous

            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
            token = token_path.read_text(encoding="utf-8").strip()
            self.assertTrue(token)
            self.assertEqual(self._run([
                "--root", str(root), "--token-file", str(token_path), "plan", "preview",
                str(plan_path), "--output", str(preview_path),
            ]), 0)
            preview = json.loads(preview_path.read_text(encoding="utf-8"))
            self.assertEqual(preview["project_id"], project_id)
            self.assertEqual(self._run([
                "--root", str(root), "--token-file", str(token_path), "plan", "commit",
                str(plan_path), "--preview", str(preview_path), "--idempotency-key", "cli-smoke-commit",
            ]), 0)
            database = root / ".todo-orchestrator" / "authority.sqlite3"
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as authority:
                snapshot = json.loads(authority.execute(
                    "SELECT canonical_json FROM plan_revision_snapshots ORDER BY rowid DESC LIMIT 1"
                ).fetchone()[0])
            dependencies = snapshot["effective_plan"]["package"]["dependencies"]
            self.assertEqual(len(dependencies), 1)
            self.assertEqual(dependencies[0]["source"]["entity_id"], "review")
            self.assertEqual(dependencies[0]["members"][0]["target"]["entity_id"], "write")
            self.assertEqual(self._run([
                "--root", str(root), "--token-file", str(token_path), "read",
                "--output", str(projection_path),
            ]), 0)
            projection = json.loads(projection_path.read_text(encoding="utf-8"))
            self.assertEqual(projection["project_id"], project_id)
            self.assertEqual(projection["authority_id"], authority_id)
            self.assertGreaterEqual(projection["semantic_revision"], 1)
            self.assertTrue((root / ".todo-orchestrator" / "authority.sqlite3").is_file())

            attempt_token = Path(temporary) / "attempt.token"
            status, error = self._run_capture([
                "--root", str(root), "--token-file", str(token_path), "dispatch",
                "--work-item", "write", "--workspace-id", "missing-workspace",
                "--idempotency-key", "cli-smoke-dispatch", "--token-output", str(attempt_token),
            ])
            self.assertEqual(status, 2)
            self.assertIn("required trusted provider unavailable: attempt_host", error)
            self.assertFalse(attempt_token.exists())
            after_path = Path(temporary) / "after-read.json"
            self.assertEqual(self._run([
                "--root", str(root), "--token-file", str(token_path), "read",
                "--output", str(after_path),
            ]), 0)
            after = json.loads(after_path.read_text(encoding="utf-8"))
            self.assertEqual(after["semantic_revision"], projection["semantic_revision"])

    def _run(self, argv):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(argv)

    def _run_capture(self, argv):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = main(argv)
        return status, error.getvalue()


if __name__ == "__main__":
    unittest.main()
