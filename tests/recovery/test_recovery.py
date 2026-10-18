"""Primary public recovery-application behavior checks."""

from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

from tests.verification import test_execution_independent as fixture_module
from todo_orchestrator.authority import IdempotencyConflictError
from todo_orchestrator.contracts import Sha256Digest, StableId
from todo_orchestrator.operations.inspection import RecoveryInspectionService, RECOVERY_INSPECT_ACTION
from todo_orchestrator.operations.recovery import RecoveryExecutionService
from todo_orchestrator.views.recovery import RecoveryIntentKind
from todo_orchestrator.authority.auth import RECOVERY_APPLY_ACTION


class RecoveryExecutionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.IndependentVerificationExecutionTests()
        with patch.object(
            fixture_module, "OWNER_ACTIONS",
            (*fixture_module.OWNER_ACTIONS, RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION),
        ):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

        original = self.fixture.host.inspect_attempt

        def inspect_with_exact_source(attempt, workspace):
            return replace(original(attempt, workspace), source_digest=Sha256Digest("4" * 64))

        self.fixture.host.inspect_attempt = inspect_with_exact_source
        self.inspection = RecoveryInspectionService(
            self.fixture.auth, host=self.fixture.host,
            operation_inspectors={"verification": self.fixture.verifier},
            source_observer=self.fixture.source, clock=self.fixture.clock,
        )
        self.recovery = RecoveryExecutionService(
            self.inspection, attempts=self.fixture.attempts,
            verification=self.fixture.verification, clock=self.fixture.clock,
        )
        self.attempt = self.fixture.claim("verify", self.fixture.owner.bearer_token, key="r02-primary-attempt")

    def inspect(self):
        with self.fixture.open_reader() as authority:
            return self.inspection.inspect_attempt(authority, self.fixture.owner.bearer_token, self.attempt)

    def apply(self, intent, key):
        with self.fixture.open_writer() as authority:
            return self.recovery.apply(
                authority, self.fixture.owner.bearer_token, intent,
                idempotency_key=StableId(key), expected_revision=intent.expected_authority_revision,
            )

    def test_recovery_replay_is_bound_to_the_exact_preview(self):
        active = self.inspect()
        self.fixture.clock.value = active.lease_expires_at + timedelta(seconds=1)
        report = self.inspect()
        intent, = (item for item in report.intents
                   if item.kind is RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT)

        applied = self.apply(intent, "r02-exact-preview-replay")
        after = self.fixture.state_snapshot()
        replay = self.apply(intent, "r02-exact-preview-replay")
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.result.receipt, applied.result.receipt)
        self.assertEqual(self.fixture.state_snapshot(), after)

        changed_condition = replace(intent.preconditions[0], detail="different inspected precondition")
        changed_intent = replace(intent, preconditions=(changed_condition, *intent.preconditions[1:]))
        with self.fixture.open_writer() as authority:
            with self.assertRaises(IdempotencyConflictError):
                self.recovery.apply(
                    authority, self.fixture.owner.bearer_token, changed_intent,
                    idempotency_key=StableId("r02-exact-preview-replay"),
                )
        self.assertEqual(self.fixture.state_snapshot(), after)

