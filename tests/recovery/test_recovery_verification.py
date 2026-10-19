"""Focused public-flow qualification for recovery of verification operations."""

from dataclasses import replace
from datetime import timedelta
import json
import unittest
from unittest.mock import patch

from tests.verification import test_execution_independent as fixture_module
from todo_orchestrator.authority import CapabilityDeniedError, SQLiteAuthority
from todo_orchestrator.authority.auth import RECOVERY_APPLY_ACTION
from todo_orchestrator.authority.commands import IdempotencyConflictError
from todo_orchestrator.contracts import Sha256Digest, StableId
from todo_orchestrator.operations.inspection import RECOVERY_INSPECT_ACTION, RecoveryInspectionService
from todo_orchestrator.operations.recovery import RecoveryExecutionService, RecoveryIntentStaleError
from todo_orchestrator.verification.service import VerificationDeniedError, VerificationState
from todo_orchestrator.views.recovery import RecoveryIntentKind


class VerificationRecoveryTests(unittest.TestCase):
    def make_fixture(self):
        fixture = fixture_module.IndependentVerificationExecutionTests()
        actions = (*fixture_module.OWNER_ACTIONS, RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION)
        with patch.object(fixture_module, "OWNER_ACTIONS", actions):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)

        original_inspect_attempt = fixture.host.inspect_attempt

        def inspect_attempt_with_source(attempt, workspace):
            return replace(
                original_inspect_attempt(attempt, workspace),
                source_digest=Sha256Digest("4" * 64),
            )

        fixture.host.inspect_attempt = inspect_attempt_with_source
        inspection = RecoveryInspectionService(
            fixture.auth,
            host=fixture.host,
            operation_inspectors={"verification": fixture.verifier},
            source_observer=fixture.source,
            clock=fixture.clock,
        )
        recovery = RecoveryExecutionService(
            inspection,
            attempts=fixture.attempts,
            verification=fixture.verification,
            clock=fixture.clock,
        )
        return fixture, inspection, recovery

    def delegate_operator(self, fixture, attempt, *, key="recovery-verification-operator"):
        with fixture.open_writer() as authority:
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            return fixture.auth.delegate(
                authority,
                fixture.owner.bearer_token,
                "worker-other",
                actions=(RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION),
                scope=fixture.work_ref("verify"),
                attempt=attempt,
                expires_at=fixture.owner.capability.expires_at - timedelta(seconds=1),
                idempotency_key=StableId(key),
                expected_revision=revision,
            )

    def delegate_inspector(self, fixture, attempt, *, key="recovery-verification-inspector"):
        with fixture.open_writer() as authority:
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            return fixture.auth.delegate(
                authority,
                fixture.owner.bearer_token,
                "worker-missing",
                actions=(RECOVERY_INSPECT_ACTION,),
                scope=fixture.work_ref("verify"),
                attempt=attempt,
                expires_at=fixture.owner.capability.expires_at - timedelta(seconds=1),
                idempotency_key=StableId(key),
                expected_revision=revision,
            )

    def start_interrupted_operation(self, fixture, *, effect_already_ran):
        worker = fixture.delegate_worker("verify", "worker-verify", key=(
            "recovery-verification-effect-worker" if effect_already_ran
            else "recovery-verification-retry-worker"
        ))
        attempt = fixture.claim("verify", worker.bearer_token, key=(
            "recovery-verification-effect-attempt" if effect_already_ran
            else "recovery-verification-retry-attempt"
        ))
        request_key = StableId(
            "recovery-verification-effect-request" if effect_already_ran
            else "recovery-verification-retry-request"
        )
        with fixture.open_writer() as authority:
            if effect_already_ran:
                original_verify = fixture.verifier.verify

                def interrupt_after_effect(request):
                    original_verify(request)
                    raise KeyboardInterrupt("fixture stopped after provider effect")

                with patch.object(fixture.verifier, "verify", side_effect=interrupt_after_effect):
                    with self.assertRaisesRegex(KeyboardInterrupt, "after provider effect"):
                        fixture.verification.execute(
                            authority,
                            worker.bearer_token,
                            attempt,
                            fixture.requirement_ref("check-verify"),
                            idempotency_key=request_key,
                        )
            else:
                with patch.object(
                    fixture.verifier, "verify",
                    side_effect=KeyboardInterrupt("fixture stopped before provider effect"),
                ):
                    with self.assertRaisesRegex(KeyboardInterrupt, "before provider effect"):
                        fixture.verification.execute(
                            authority,
                            worker.bearer_token,
                            attempt,
                            fixture.requirement_ref("check-verify"),
                            idempotency_key=request_key,
                        )
            operation = fixture.verification._view_for_idempotency(authority, request_key)
        self.assertEqual(operation.state, VerificationState.EXECUTING)
        return worker, attempt, request_key, operation

    def revoke_worker(self, fixture, worker, *, key):
        with fixture.open_writer() as authority:
            fixture.auth.revoke_family(
                authority,
                fixture.owner.bearer_token,
                worker.capability.capability_id,
                idempotency_key=StableId(key),
                expected_revision=authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
                ).fetchone()[0],
            )

    def inspect(self, fixture, inspection, token, attempt):
        with fixture.open_reader() as authority:
            return inspection.inspect_attempt(authority, token, attempt)

    @staticmethod
    def event_payloads(authority, operation_id):
        rows = authority.connection.execute(
            "SELECT actor_id, actor_incarnation_id, payload_json FROM authority_events "
            "ORDER BY semantic_revision, event_ordinal"
        ).fetchall()
        return [
            (row["actor_id"], row["actor_incarnation_id"], json.loads(row["payload_json"]))
            for row in rows
            if json.loads(row["payload_json"]).get("operation_id") == str(operation_id)
        ]

    def test_expired_attempt_with_completed_verification_can_be_released(self):
        fixture, inspection, recovery = self.make_fixture()
        worker = fixture.delegate_worker(
            "verify", "worker-verify", key="recovery-completed-verification-worker",
        )
        attempt = fixture.claim(
            "verify", worker.bearer_token, key="recovery-completed-verification-attempt",
        )
        with fixture.open_writer() as authority:
            completed = fixture.verification.execute(
                authority,
                worker.bearer_token,
                attempt,
                fixture.requirement_ref("check-verify"),
                idempotency_key=StableId("recovery-completed-verification-operation"),
            )
        self.assertEqual(completed.state, VerificationState.FINALIZED)

        operator = self.delegate_operator(
            fixture, attempt, key="recovery-completed-verification-operator",
        )
        with fixture.open_reader() as authority:
            stored_attempt = fixture.attempts._attempt_for_service(authority, attempt)
        fixture.clock.value = stored_attempt.lease.expires_at + timedelta(seconds=1)
        report = self.inspect(fixture, inspection, operator.bearer_token, attempt)
        intent, = (item for item in report.intents
                   if item.kind is RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT)
        self.assertIn(completed.operation, intent.operations)

        with fixture.open_writer() as authority:
            applied = recovery.apply(
                authority,
                operator.bearer_token,
                intent,
                idempotency_key=StableId("recovery-completed-verification-release"),
            )
        self.assertEqual(applied.disposition, RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT.value)
        with fixture.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT state, lease_id FROM attempts WHERE attempt_id = ?",
                (str(attempt.entity_id),),
            ).fetchone()
        self.assertEqual(row["state"], "released")
        self.assertIsNone(row["lease_id"])

    def test_expired_operation_retries_once_after_original_credential_revocation(self):
        fixture, inspection, recovery = self.make_fixture()
        worker, attempt, _request_key, original = self.start_interrupted_operation(
            fixture, effect_already_ran=False,
        )
        operator = self.delegate_operator(fixture, attempt)
        self.revoke_worker(fixture, worker, key="recovery-verification-revoke-worker")

        with fixture.open_reader() as authority:
            stored_attempt = fixture.attempts._attempt_for_service(authority, attempt)
        fixture.clock.value = stored_attempt.lease.expires_at + timedelta(seconds=1)
        report = self.inspect(fixture, inspection, operator.bearer_token, attempt)
        intent, = (item for item in report.intents
                   if item.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION)
        self.assertEqual(intent.operations, (original.operation,))
        self.assertEqual(intent.expected_lease_id, stored_attempt.lease.lease_id)

        outer_key = StableId("recovery-verification-retry-apply")
        with fixture.open_writer() as authority:
            applied = recovery.apply(authority, operator.bearer_token, intent, idempotency_key=outer_key)
        self.assertEqual(applied.disposition, RecoveryIntentKind.RETRY_ORIGINAL_OPERATION.value)
        result = applied.result
        self.assertEqual(result.operation, original.operation)
        self.assertEqual(result.request_digest, original.request_digest)
        self.assertEqual(result.state, VerificationState.FINALIZED)
        self.assertEqual(fixture.verifier.counts()[0], 1)

        with fixture.open_reader() as authority:
            request = fixture.verification._load_stored_request(authority, original.operation)
            self.assertEqual(request.context.actor, worker.capability.actor)
            self.assertEqual(request.expected_source, original.source_digest)
            recovered_events = [
                item for item in self.event_payloads(authority, original.operation.entity_id)
                if item[2].get("action") == str(RECOVERY_APPLY_ACTION)
            ]
        self.assertTrue(recovered_events)
        self.assertEqual(recovered_events[-1][0], str(operator.capability.actor.entity_id))
        self.assertEqual(recovered_events[-1][1], str(operator.capability.actor.incarnation_id))

        # A new authorization grant moves the authority revision. Exact replay
        # must still return the durable result before re-running providers.
        observer = self.delegate_inspector(fixture, attempt)
        calls_before_replay = fixture.verifier.counts()
        before_replay = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            replay = recovery.apply(authority, operator.bearer_token, intent, idempotency_key=outer_key)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.result.operation, original.operation)
        self.assertEqual(fixture.verifier.counts(), calls_before_replay)
        self.assertEqual(fixture.state_snapshot(), before_replay)

        before_guard_rejections = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            with self.assertRaises(IdempotencyConflictError):
                fixture.verification.recovery_replay(
                    authority,
                    operator.bearer_token,
                    original.operation,
                    intent.kind.value,
                    outer_key,
                    Sha256Digest("f" * 64),
                )
            with self.assertRaises(CapabilityDeniedError):
                recovery.apply(authority, observer.bearer_token, intent, idempotency_key=outer_key)
            with self.assertRaises(VerificationDeniedError):
                fixture.verification.retry_not_started(
                    authority,
                    operator.bearer_token,
                    original.operation,
                    idempotency_key=StableId("recovery-verification-unsealed-private-call"),
                    _recovery=True,
                )
            with self.assertRaises(VerificationDeniedError):
                fixture.verification.reconcile(
                    authority,
                    operator.bearer_token,
                    original.operation,
                    idempotency_key=StableId("recovery-verification-unsealed-reconcile"),
                    _recovery=True,
                )
        self.assertEqual(fixture.verifier.counts(), calls_before_replay)
        self.assertEqual(fixture.state_snapshot(), before_guard_rejections)

        before_stale = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            with self.assertRaises(RecoveryIntentStaleError):
                recovery.apply(
                    authority,
                    operator.bearer_token,
                    intent,
                    idempotency_key=StableId("recovery-verification-stale-intent"),
                )
        self.assertEqual(fixture.state_snapshot(), before_stale)
        self.assertEqual(fixture.verifier.counts(), calls_before_replay)

    def test_observed_provider_effect_reconciles_without_reexecution_by_current_operator(self):
        fixture, inspection, recovery = self.make_fixture()
        worker, attempt, _request_key, original = self.start_interrupted_operation(
            fixture, effect_already_ran=True,
        )
        operator = self.delegate_operator(fixture, attempt, key="recovery-verification-effect-operator")
        self.revoke_worker(fixture, worker, key="recovery-verification-effect-revoke-worker")

        with fixture.open_reader() as authority:
            stored_attempt = fixture.attempts._attempt_for_service(authority, attempt)
        fixture.clock.value = stored_attempt.lease.expires_at + timedelta(seconds=1)
        report = self.inspect(fixture, inspection, operator.bearer_token, attempt)
        reconcile, = (item for item in report.intents
                      if item.kind is RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT)
        self.assertEqual(reconcile.operations, (original.operation,))

        outer_key = StableId("recovery-verification-effect-reconcile")
        with fixture.open_writer() as authority:
            applied = recovery.apply(authority, operator.bearer_token, reconcile, idempotency_key=outer_key)
        result = applied.result
        self.assertEqual(applied.disposition, RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT.value)
        self.assertEqual(result.operation, original.operation)
        self.assertEqual(result.request_digest, original.request_digest)
        self.assertEqual(result.state, VerificationState.FINALIZED)
        self.assertEqual(fixture.verifier.counts()[0], 1)
        with fixture.open_reader() as authority:
            request = fixture.verification._load_stored_request(authority, original.operation)
            self.assertEqual(request.context.actor, worker.capability.actor)
            self.assertEqual(request.expected_source, original.source_digest)
            events = [
                item for item in self.event_payloads(authority, original.operation.entity_id)
                if item[2].get("action") == str(RECOVERY_APPLY_ACTION)
                and item[2].get("recovery_intent_kind") == reconcile.kind.value
            ]
        self.assertTrue(events)
        self.assertTrue(all(event[0] == str(operator.capability.actor.entity_id) for event in events))
        calls_before_replay = fixture.verifier.counts()
        with fixture.open_writer() as authority:
            replay = recovery.apply(authority, operator.bearer_token, reconcile, idempotency_key=outer_key)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.result.operation, original.operation)
        self.assertEqual(fixture.verifier.counts(), calls_before_replay)
