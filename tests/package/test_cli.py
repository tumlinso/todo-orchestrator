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

    def test_module_help_describes_unimplemented_workflow_commands(self) -> None:
        result = self.run_source_module("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Workflow commands are not available yet.", result.stdout)
        self.assertIn("only help and version information", result.stdout)

    def test_no_arguments_print_help_without_claiming_workflow_success(self) -> None:
        result = self.run_source_module()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Workflow commands are not available yet.", result.stdout)

    def test_version_is_available(self) -> None:
        result = self.run_source_module("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "todo 0.1.0")

    def test_unknown_workflow_command_is_rejected(self) -> None:
        result = self.run_source_module("claim")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: claim", result.stderr)

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
