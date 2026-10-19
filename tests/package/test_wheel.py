from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]


class WheelInstallTests(unittest.TestCase):
    def test_offline_wheel_build_and_isolated_target_import(self) -> None:
        with tempfile.TemporaryDirectory(prefix="todo-orchestrator-wheel-") as temporary:
            temporary_path = Path(temporary)
            project = temporary_path / "project"
            (project / "src").mkdir(parents=True)
            shutil.copy2(ROOT / "pyproject.toml", project / "pyproject.toml")
            shutil.copy2(ROOT / "README.md", project / "README.md")
            shutil.copytree(
                ROOT / "src" / "todo_orchestrator",
                project / "src" / "todo_orchestrator",
            )

            wheels = temporary_path / "wheels"
            wheels.mkdir()
            build = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-index",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(wheels),
                    str(project),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)

            wheel_files = list(wheels.glob("todo_orchestrator-*.whl"))
            self.assertEqual(len(wheel_files), 1)
            with zipfile.ZipFile(wheel_files[0]) as archive:
                entry_points = next(
                    name for name in archive.namelist() if name.endswith("entry_points.txt")
                )
                self.assertIn("todo = todo_orchestrator.api.cli:main", archive.read(entry_points).decode())

            target = temporary_path / "target"
            install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--target",
                    str(target),
                    str(wheel_files[0]),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(install.returncode, 0, install.stdout + install.stderr)

            code = f"""
import importlib.util
import pathlib
import sys

sys.path.insert(0, {str(target)!r})
import todo_orchestrator
import todo_orchestrator.api as api
import todo_orchestrator.api.cli as cli
import todo_orchestrator.contracts.domain as domain
from todo_orchestrator.api.cli import main

target = pathlib.Path({str(target)!r}).resolve()
for module in (todo_orchestrator, api, cli, domain):
    assert pathlib.Path(module.__file__).resolve().is_relative_to(target)
assert importlib.util.find_spec('project_control') is None
try:
    main(['--version'])
except SystemExit as error:
    assert error.code == 0
else:
    raise AssertionError('--version did not exit successfully')
assert not any(name == 'project_control' or name.startswith('project_control.') for name in sys.modules)
"""
            environment = os.environ.copy()
            environment.pop("PYTHONPATH", None)
            smoke = subprocess.run(
                [sys.executable, "-I", "-S", "-c", code],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(smoke.returncode, 0, smoke.stderr)
            self.assertEqual(smoke.stdout.strip(), "todo 0.2.0")


if __name__ == "__main__":
    unittest.main()
