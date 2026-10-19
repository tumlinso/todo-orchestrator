"""State-free command-line help and version checks."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api.cli import main


class CliBootstrapTests(unittest.TestCase):
    def _exit(self, arguments):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                main(arguments)
        return result.exception.code, output.getvalue()

    def test_help_and_version_do_not_create_project_state_or_load_workflow(self):
        with tempfile.TemporaryDirectory(prefix="todo-cli-help-") as temporary:
            root = Path(temporary) / "does-not-exist"
            code, help_text = self._exit(["--root", str(root), "--help"])
            self.assertEqual(code, 0)
            self.assertIn("init", help_text)
            self.assertIn("plan", help_text)
            self.assertIn("recovery", help_text)
            self.assertFalse(root.exists())

            code, version_text = self._exit(["--root", str(root), "--version"])
            self.assertEqual(code, 0)
            self.assertIn("todo ", version_text)
            self.assertFalse(root.exists())

    def test_authentication_does_not_accept_raw_secret_options(self):
        with tempfile.TemporaryDirectory(prefix="todo-cli-args-") as temporary:
            root = Path(temporary) / "does-not-exist"
            code, output = self._exit([
                "--root", str(root), "auth", "login", "--token-output", str(root / "token"),
                "--password", "must-not-be-a-cli-argument",
            ])
            self.assertNotEqual(code, 0)
            self.assertNotIn("must-not-be-a-cli-argument", output)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
