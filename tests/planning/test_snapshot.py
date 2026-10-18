import json
import unittest

from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.planning import (
    accepted_plan_payload,
    compile_plan_json,
    decode_accepted_plan,
    encode_accepted_plan,
)


class AcceptedSnapshotCodecTests(unittest.TestCase):
    def test_minimal_plan_without_producer_roundtrips_canonically(self):
        project = Project(StableId("snapshot-project"), StableId("snapshot-authority"))
        package = {
            "format": "todo-orchestrator.plan",
            "schema_version": 1,
            "package_id": "minimal",
            "project": {
                "project_id": str(project.project_id),
                "authority_id": str(project.authority_id),
            },
            "work_items": [{
                "id": "work",
                "title": "Work",
                "objective": "Complete the work",
                "outcome": "Work is complete",
                "scope": {"paths": [], "concepts": []},
                "acceptance": {
                    "assertions": ["it passes"],
                    "required_evidence": [],
                    "allowed_dispositions": ["completed"],
                },
            }],
        }
        result = compile_plan_json(json.dumps(package), project)
        self.assertTrue(result.ok, result.diagnostics)
        encoded = encode_accepted_plan(
            result.plan,
            authority_id=project.authority_id,
            semantic_revision=1,
            based_on_revision_id=None,
        )
        restored = decode_accepted_plan(encoded, project, sequence=1)
        self.assertEqual(accepted_plan_payload(restored), accepted_plan_payload(result.plan))


if __name__ == "__main__":
    unittest.main()
