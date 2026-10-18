import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_reference_baseline import DEFAULT_MANIFEST, validate, verify_external


class ReferenceBaselineTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(DEFAULT_MANIFEST.read_text())

    def test_checked_in_baseline_is_complete(self):
        validate(self.manifest)
        self.assertEqual(len(self.manifest["inventory"]), 12)
        self.assertEqual(len(self.manifest["fixtures"]), 9)

    def test_rejects_missing_capability_evidence(self):
        broken = copy.deepcopy(self.manifest)
        broken["inventory"] = broken["inventory"][:8]
        with self.assertRaisesRegex(ValueError, "inventory"):
            validate(broken)

    def test_rejects_source_fingerprint_drift_in_capture_record(self):
        broken = copy.deepcopy(self.manifest)
        broken["sources"][0]["hashes"][0]["sha256_after"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source hash changed"):
            validate(broken)

    def test_external_check_detects_changed_reference_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            captured = root / "db.py"
            captured.write_text("changed source")
            source = {
                "root": str(root),
                "git_root": str(root),
                "hashes": [{"path": "db.py", "sha256_after": "0" * 64}],
            }
            problems = verify_external(source, check_git=False)
            self.assertEqual(len(problems), 1)
            self.assertIn("hash differs", problems[0])


if __name__ == "__main__":
    unittest.main()
