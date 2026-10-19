"""Prevent public read models from echoing an issued bearer as a structured ID."""

from datetime import timedelta
import json
from unittest.mock import patch
import unittest

from todo_orchestrator.contracts import StableId
from todo_orchestrator.operations.export import (
    AUTHORITY_READ_ACTION,
    AuthorityExportService,
    UnsafePublicProjectionError,
)

from tests.recovery.test_export_independent import ExportIndependentTests
from tests.verification.test_execution_independent import (
    OWNER_PASSWORD,
    PROJECT,
    package_json,
)


class AuthorityExportStructuralGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ExportIndependentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture.f

    def test_known_bearer_used_as_work_id_is_refused_without_echo_or_churn(self):
        f = self.f
        read_grant, _backup_grant = self.fixture._export_grants()
        service = AuthorityExportService(f.auth)

        # StableId permits URL-safe opaque strings. Force an issued bearer into
        # that namespace so the projection's structural-ref guard is exercised.
        bearer = "r04-known-bearer-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        with f.open_writer() as authority:
            with patch("todo_orchestrator.authority.auth._bearer", return_value=bearer):
                issued = f.auth.login_local_owner(
                    authority,
                    OWNER_PASSWORD,
                    actions=(StableId("todo.attempt.claim"),),
                    scope=PROJECT.ref,
                    expires_at=f.clock() + timedelta(hours=1),
                    idempotency_key=StableId("r04-structural-secret-credential"),
                    expected_revision=f.revision(),
                )
        self.assertEqual(issued.bearer_token, bearer)

        # Ordinary structural identifiers remain useful in the public model.
        with f.open_reader() as authority:
            baseline = service.read_model(
                authority, read_grant.bearer_token, expected_revision=f.revision(),
            )
        self.assertIn(
            "verify",
            {row["work_item_id"] for row in baseline.sections["work_definitions"]},
        )

        document = json.loads(package_json())
        document["work_items"].append({
            "id": bearer,
            "title": "credential-shaped identifier",
            "objective": "Exercise public projection collision handling",
            "outcome": "The issued bearer is never serialized as an identifier",
            "scope": {"paths": [], "concepts": [], "locks": []},
            "ownership": {"mode": "any", "actors": []},
            "acceptance": {
                "assertions": ["public exports do not echo issued credentials"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
        })
        package_json_with_collision = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with f.open_writer() as authority:
            preview = f.plans.preview(authority, package_json_with_collision)
            f.plans.commit(
                authority,
                f.owner.bearer_token,
                package_json_with_collision,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("r04-structural-secret-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )

        before = self.fixture._authority_state()
        with f.open_reader() as authority:
            with self.assertRaises(UnsafePublicProjectionError) as raised:
                service.read_model(
                    authority, read_grant.bearer_token, expected_revision=f.revision(),
                )
        self.assertNotIn(bearer, str(raised.exception))
        self.assertNotIn(bearer, repr(raised.exception))
        self.assertEqual(self.fixture._authority_state(), before)


def load_tests(loader, _tests, _pattern):
    # The imported fixture is a TestCase; keep this module's discovery focused
    # on the structural credential regression.
    return loader.loadTestsFromTestCase(AuthorityExportStructuralGuardTests)


if __name__ == "__main__":
    unittest.main()
