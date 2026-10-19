"""Run selected original behavior tests against disposable legacy fixtures.

The original source is loaded only in isolated child interpreters. Each selected
test uses the old suite's V2Repo TemporaryDirectory fixture; this harness never
imports the old implementation into the standalone test process.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = Path(__file__).with_name("legacy-corpus.v1.json")
LEGACY_PACKAGE = """
from pathlib import Path
import importlib
import io
import json
import sys
import unittest

root = Path(sys.argv[1]).resolve()
case_id = sys.argv[2]
module = importlib.import_module("todo_orchestrator")
package_path = Path(module.__file__).resolve()
expected_package = (root / "todo_orchestrator").resolve()
if not package_path.is_relative_to(expected_package):
    raise SystemExit(f"legacy import escaped pinned source: {package_path}")
suite = unittest.defaultTestLoader.loadTestsFromName(case_id)
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
summary = {
    "test": case_id,
    "tests_run": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "successful": result.wasSuccessful(),
    "package_path": str(package_path),
}
print("Q01-LEGACY-RESULT=" + json.dumps(summary, sort_keys=True))
if not result.wasSuccessful():
    print(stream.getvalue(), file=sys.stderr)
    raise SystemExit(1)
"""


class LegacyFixtureCorpusTests(unittest.TestCase):
    def _corpus(self) -> dict[str, object]:
        value = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(value["format"], "todo-orchestrator.legacy-qualification-corpus")
        self.assertEqual(value["version"], 1)
        self.assertIsInstance(value["cases"], list)
        self.assertGreaterEqual(len(value["cases"]), 7)
        return value

    def _legacy_root(self, corpus: dict[str, object]) -> Path:
        reference = corpus["reference"]
        override = os.environ.get("TODO_ORCHESTRATOR_REFERENCE_ROOT")
        root = Path(override) if override else Path(reference["default_root"])
        root = root.expanduser().resolve()
        if not root.is_dir():
            if override:
                self.fail(f"explicit TODO_ORCHESTRATOR_REFERENCE_ROOT does not exist: {root}")
            self.skipTest(
                "captured legacy source is not available in this environment; "
                "no runtime parity result is claimed"
            )

        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(revision, reference["revision"], "legacy source revision differs from captured baseline")

        scoped_status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--", "todo_orchestrator", "tests"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(scoped_status, "", "legacy source or tests have uncommitted changes")
        return root

    def _check_reference_hashes(self, corpus: dict[str, object], root: Path) -> None:
        baseline_path = REPOSITORY_ROOT / corpus["reference"]["baseline"]
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        source = next(
            item for item in baseline["sources"]
            if item["name"] == corpus["reference"]["source_name"]
        )
        self.assertEqual(source["revision"], corpus["reference"]["revision"])
        expected = {item["path"]: item["sha256_after"] for item in source["hashes"]}
        fixture_paths = {"tests/v2_helpers.py"}
        fixture_paths.update(case["reference_file"] for case in corpus["cases"])
        for relative in sorted(fixture_paths):
            self.assertIn(relative, expected, f"baseline is missing the test identity for {relative}")
            digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, expected[relative], f"legacy fixture identity changed: {relative}")

    def _isolated_environment(self, root: Path, temp_root: Path) -> dict[str, str]:
        home = temp_root / "home"
        temp = temp_root / "tmp"
        run = temp_root / "cwd"
        for path in (home, temp, run, home / ".config", home / ".cache"):
            path.mkdir(parents=True, exist_ok=True)
        return {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(home),
            "TMPDIR": str(temp),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "PYTHONPATH": os.pathsep.join((str(root), str(root / "tests"))),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def test_selected_legacy_behaviors_on_disposable_projects(self):
        corpus = self._corpus()
        root = self._legacy_root(corpus)
        self._check_reference_hashes(corpus, root)

        results = []
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                with tempfile.TemporaryDirectory(prefix="todo-q01-legacy-") as temporary:
                    temp_root = Path(temporary)
                    env = self._isolated_environment(root, temp_root)
                    process = subprocess.run(
                        [sys.executable, "-B", "-S", "-c", LEGACY_PACKAGE,
                         str(root), case["reference_test"]],
                        cwd=temp_root / "cwd",
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=90,
                    )
                self.assertEqual(
                    process.returncode, 0,
                    f"{case['id']} failed against {corpus['reference']['revision']}\n"
                    f"stdout:\n{process.stdout}\nstderr:\n{process.stderr}",
                )
                summaries = [
                    line.partition("=")[2]
                    for line in process.stdout.splitlines()
                    if line.startswith("Q01-LEGACY-RESULT=")
                ]
                self.assertEqual(len(summaries), 1, process.stdout)
                summary = json.loads(summaries[0])
                self.assertTrue(summary["successful"], summary)
                self.assertEqual(summary["tests_run"], 1, summary)
                self.assertEqual(summary["test"], case["reference_test"])
                self.assertTrue(
                    Path(summary["package_path"]).is_relative_to(root / "todo_orchestrator"),
                    summary,
                )
                results.append(case["id"])

        self.assertEqual(len(results), len(corpus["cases"]))


if __name__ == "__main__":
    unittest.main()
