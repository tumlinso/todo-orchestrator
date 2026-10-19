from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src"


class SourceCliTests(unittest.TestCase):
    def run_source_module(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE)
        return subprocess.run(
            [sys.executable, "-S", "-m", "todo_orchestrator", *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_module_help_lists_explicit_workflow_commands_without_opening_state(self) -> None:
        result = self.run_source_module("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("plan", result.stdout)
        self.assertIn("recovery", result.stdout)
        self.assertIn("do not open or initialize", result.stdout)

    def test_no_arguments_print_help_without_opening_authority(self) -> None:
        result = self.run_source_module()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: todo", result.stdout)

    def test_version_is_available(self) -> None:
        result = self.run_source_module("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "todo 0.2.0")

    def test_unknown_command_error_does_not_echo_raw_arguments(self) -> None:
        secret = "do-not-print-this-value"
        result = self.run_source_module("unknown", secret)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage: todo", result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_import_is_source_bound_and_does_not_load_project_control(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE)
        code = (
            f"import sys, pathlib; sys.path.insert(0, {str(SOURCE)!r}); "
            "import todo_orchestrator; "
            "assert pathlib.Path(todo_orchestrator.__file__).resolve().is_relative_to("
            f"pathlib.Path({str(SOURCE)!r}).resolve()); "
            "assert not any(name == 'project_control' or name.startswith('project_control.') "
            "for name in sys.modules)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", code],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
