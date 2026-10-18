"""Issued credentials cannot become durable child identities or receipts."""

import unittest

from todo_orchestrator.contracts import StableId
from todo_orchestrator.coordination.children import ChildExecutionDeniedError
from tests.coordination import test_children_independent as fixtures


class ChildIdentityCredentialGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ChildExecutionIndependentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def assert_secret_denied(self, operation, bearer, key):
        before = self.fixture.state_snapshot()
        with self.assertRaises(ChildExecutionDeniedError) as failure:
            operation()
        self.assertNotIn(bearer, str(failure.exception))
        self.assertEqual(before, self.fixture.state_snapshot())
        with self.fixture.open_reader() as authority:
            self.assertIsNone(authority.connection.execute(
                "SELECT 1 FROM command_idempotency WHERE idempotency_key = ?",
                (key,),
            ).fetchone())

    def test_issued_bearer_cannot_be_execution_identity(self):
        bearer = self.fixture.parent_capability.bearer_token
        key = "c05-secret-execution-identity"
        self.assert_secret_denied(
            lambda: self.fixture.start_child(execution_id=bearer, key=key), bearer, key,
        )

    def test_issued_bearer_cannot_be_logical_identity(self):
        bearer = self.fixture.parent_capability.bearer_token
        key = "c05-secret-logical-identity"
        self.assert_secret_denied(
            lambda: self.fixture.start_child(logical_id=bearer, key=key), bearer, key,
        )

    def test_issued_bearer_cannot_be_candidate_identity(self):
        child = self.fixture.start_child()
        bearer = child.bearer_token
        key = "c05-secret-candidate-identity"

        def submit():
            with self.fixture.open_writer() as authority:
                self.fixture.children.submit_candidate(
                    authority, bearer, child.view.execution_id,
                    candidate_id=StableId(bearer), summary="A bounded child result",
                    idempotency_key=StableId(key),
                    expected_revision=self.fixture.revision(),
                )

        self.assert_secret_denied(submit, bearer, key)


if __name__ == "__main__":
    unittest.main()
