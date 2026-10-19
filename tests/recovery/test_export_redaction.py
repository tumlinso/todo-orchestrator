"""Public authority projections exclude recoverable authentication material."""

import base64
from datetime import timedelta
import json
import unittest
from unittest.mock import patch

from tests.verification import test_execution_independent as fixture_module
from todo_orchestrator.authority import CapabilityDeniedError
from todo_orchestrator.contracts import StableId
from todo_orchestrator.operations.export import AuthorityExportService


READ = StableId("todo.authority.read")


class ExportRedactionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.IndependentVerificationExecutionTests()
        with patch.object(fixture_module, "OWNER_ACTIONS", (*fixture_module.OWNER_ACTIONS, READ)):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.service = AuthorityExportService(self.fixture.auth)

    def test_public_model_and_markdown_do_not_disclose_credentials(self):
        fixture = self.fixture
        before = fixture.state_snapshot()
        with fixture.open_reader() as authority:
            private = authority.connection.execute(
                "SELECT salt, password_digest FROM local_owner_credentials"
            ).fetchone()
            token_digests = [row[0] for row in authority.connection.execute(
                "SELECT token_digest FROM capability_tokens"
            )]
            model = self.service.read_model(
                authority, fixture.owner.bearer_token, expected_revision=fixture.revision(),
            )
        rendered = self.service.render_markdown(model)
        serialized = json.dumps(model.to_dict(), sort_keys=True)
        planned = fixture.plan.work_items[0]
        work = next(row for row in model.sections["work_definitions"]
                    if row["work_item_id"] == str(planned.definition.work_item_id)
                    and row["definition_revision_id"] == str(planned.definition.definition_revision_id))
        self.assertEqual(work["title"], planned.definition.title)
        self.assertEqual(work["outcome"], planned.definition.outcome)
        self.assertEqual(work["objective"], planned.context.objective)
        self.assertIn(planned.definition.title, rendered)
        private_values = [fixture_module.OWNER_PASSWORD, fixture.owner.bearer_token, *token_digests]
        for value in private:
            private_values.extend((value.hex(), base64.b64encode(value).decode(), str(value)))
        for output in (serialized, model.to_json(), rendered):
            for value in private_values:
                self.assertNotIn(value, output)
        self.assertEqual(fixture.state_snapshot(), before)

    def test_work_scoped_read_grant_cannot_export_the_whole_authority(self):
        fixture = self.fixture
        with fixture.open_writer() as authority:
            scoped = fixture.auth.delegate(
                authority, fixture.owner.bearer_token, "worker-other",
                actions=(READ,), scope=fixture.work_ref("verify"),
                expires_at=fixture.clock() + timedelta(minutes=5),
                idempotency_key=StableId("export-work-scoped-read"),
                expected_revision=fixture.revision(),
            )
        before = fixture.state_snapshot()
        with fixture.open_reader() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.service.read_model(authority, scoped.bearer_token)
        self.assertEqual(fixture.state_snapshot(), before)
