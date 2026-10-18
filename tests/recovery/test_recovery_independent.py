"""Independent public-flow qualification for authorized recovery transitions."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.verification import test_execution_independent as verification_fixture
from tests.verification import test_git_independent as git_fixture
from todo_orchestrator.authority import (
    CLAIM_ACTION, AttemptObservationMismatchError, CapabilityDeniedError, SQLiteAuthority,
)
from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.model import ChildActivity, ProcessLiveness
from todo_orchestrator.operations.inspection import RECOVERY_INSPECT_ACTION, RecoveryInspectionService
from todo_orchestrator.operations.recovery import (
    RECOVERY_APPLY_ACTION,
    RecoveryExecutionService,
    RecoveryIntentStaleError,
)
from todo_orchestrator.providers.git.service import CREATE_WORKSPACE_ACTION, GitEffectService
from todo_orchestrator.verification.service import VerificationState
from todo_orchestrator.views.recovery import RecoveryIntentKind, RecoveryOperationStatus


class RecoveryTransitionIndependentTests(unittest.TestCase):
    def make_verification_fixture(self):
        fixture = verification_fixture.IndependentVerificationExecutionTests()
        actions = (*verification_fixture.OWNER_ACTIONS, RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION)
        with patch.object(verification_fixture, "OWNER_ACTIONS", actions):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original_inspect = fixture.host.inspect_attempt

        def inspect_with_source_digest(attempt, workspace):
            return replace(
                original_inspect(attempt, workspace),
                source_digest=Sha256Digest("4" * 64),
            )

        fixture.host.inspect_attempt = inspect_with_source_digest
        inspection = RecoveryInspectionService(
            fixture.auth, host=fixture.host,
            operation_inspectors={"verification": fixture.verifier},
            source_observer=fixture.source, clock=fixture.clock,
        )
        recovery = RecoveryExecutionService(
            inspection, attempts=fixture.attempts, verification=fixture.verification,
            clock=fixture.clock,
        )
        return fixture, inspection, recovery

    def apply(self, fixture, recovery, token, intent, key, *, expected_revision=None):
        with fixture.open_writer() as authority:
            return recovery.apply(authority, token, intent, idempotency_key=StableId(key),
                                  expected_revision=expected_revision)

    def inspect_attempt(self, fixture, inspection, token, attempt):
        with fixture.open_reader() as authority:
            return inspection.inspect_attempt(authority, token, attempt)

    def test_expired_safe_attempt_is_released_by_exact_intent_and_retry_is_idempotent(self):
        fixture, inspection, recovery = self.make_verification_fixture()
        attempt = fixture.claim("verify", fixture.owner.bearer_token, key="r02-safe-attempt")
        active = self.inspect_attempt(fixture, inspection, fixture.owner.bearer_token, attempt)
        fixture.clock.value = active.lease_expires_at + timedelta(seconds=1)
        report = self.inspect_attempt(fixture, inspection, fixture.owner.bearer_token, attempt)
        intent, = (item for item in report.intents
                   if item.kind is RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT)
        before = fixture.state_snapshot()

        applied = self.apply(fixture, recovery, fixture.owner.bearer_token,
                             intent, "r02-release-expired",
                             expected_revision=intent.expected_authority_revision)
        after = fixture.state_snapshot()
        replay = self.apply(fixture, recovery, fixture.owner.bearer_token,
                            intent, "r02-release-expired")

        self.assertEqual(applied.disposition, RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT.value)
        self.assertFalse(applied.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.result.receipt, applied.result.receipt)
        self.assertEqual(after[1], before[1] + 1)
        self.assertEqual(fixture.state_snapshot(), after)
        with fixture.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT state, lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),)
            ).fetchone()
            self.assertEqual(row["state"], "released")
            self.assertIsNone(row["lease_id"])
            event = authority.connection.execute(
                "SELECT e.event_kind, e.actor_id, e.actor_incarnation_id "
                "FROM command_idempotency i JOIN command_receipts r USING(receipt_id) "
                "JOIN authority_events e USING(event_id) WHERE i.idempotency_key = ?",
                ("r02-release-expired",),
            ).fetchone()
            self.assertEqual(event["event_kind"], "todo.attempt.recovery_released")
            self.assertEqual(event["actor_id"], str(fixture.owner.capability.actor.entity_id))

    def test_inspect_only_actor_and_forged_or_stale_previews_cannot_apply(self):
        fixture, inspection, recovery = self.make_verification_fixture()
        attempt = fixture.claim("verify", fixture.owner.bearer_token, key="r02-auth-attempt")
        active = self.inspect_attempt(fixture, inspection, fixture.owner.bearer_token, attempt)
        fixture.clock.value = active.lease_expires_at + timedelta(seconds=1)
        report = self.inspect_attempt(fixture, inspection, fixture.owner.bearer_token, attempt)
        intent, = (item for item in report.intents
                   if item.kind is RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT)

        with fixture.open_writer() as authority:
            observer = fixture.auth.delegate(
                authority, fixture.owner.bearer_token, "worker-other",
                actions=(RECOVERY_INSPECT_ACTION,), scope=fixture.work_ref("verify"), attempt=attempt,
                expires_at=fixture.clock() + timedelta(minutes=5),
                idempotency_key=StableId("r02-inspection-only-grant"),
                expected_revision=fixture.revision(),
            )
        stale = replace(intent, expected_authority_revision=intent.expected_authority_revision + 17)
        before = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                recovery.apply(authority, observer.bearer_token, intent,
                               idempotency_key=StableId("r02-unauthorized-apply"))
        self.assertEqual(fixture.state_snapshot(), before)
        with fixture.open_writer() as authority:
            with self.assertRaises(RecoveryIntentStaleError):
                recovery.apply(authority, fixture.owner.bearer_token, stale,
                               idempotency_key=StableId("r02-forged-intent"))
        self.assertEqual(fixture.state_snapshot(), before)
        with fixture.open_writer() as authority:
            with self.assertRaises(RecoveryIntentStaleError):
                recovery.apply(
                    authority, fixture.owner.bearer_token, intent,
                    idempotency_key=StableId("r02-stale-explicit-cas"),
                    expected_revision=intent.expected_authority_revision - 1,
                )
        self.assertEqual(fixture.state_snapshot(), before)

        # A valid approval preview becomes stale when the authority revision moves.
        with fixture.open_writer() as authority:
            fixture.auth.delegate(
                authority, fixture.owner.bearer_token, "worker-missing",
                actions=(RECOVERY_INSPECT_ACTION,), scope=fixture.work_ref("verify"), attempt=attempt,
                expires_at=fixture.clock() + timedelta(minutes=5),
                idempotency_key=StableId("r02-revision-bump-grant"),
                expected_revision=fixture.revision(),
            )
        before_stale_apply = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            with self.assertRaises(RecoveryIntentStaleError):
                recovery.apply(authority, fixture.owner.bearer_token, intent,
                               idempotency_key=StableId("r02-stale-preview"))
        self.assertEqual(fixture.state_snapshot(), before_stale_apply)

    def test_recovery_can_retry_proven_not_started_verification_as_distinct_approver(self):
        fixture, inspection, recovery = self.make_verification_fixture()
        worker = fixture.delegate_worker("verify", "worker-verify", key="r02-check-worker-grant")
        attempt = fixture.claim("verify", worker.bearer_token, key="r02-check-attempt")
        check_key = StableId("r02-check-execution")
        with fixture.open_writer() as authority:
            with patch.object(fixture.verifier, "verify", side_effect=KeyboardInterrupt("before provider effect")):
                with self.assertRaisesRegex(KeyboardInterrupt, "before provider effect"):
                    fixture.verification.execute(
                        authority, worker.bearer_token, attempt,
                        fixture.requirement_ref("check-verify"), idempotency_key=check_key,
                    )
            pending = fixture.verification._view_for_idempotency(authority, check_key)
        report = self.inspect_attempt(fixture, inspection, fixture.owner.bearer_token, attempt)
        retry, = (item for item in report.intents
                  if item.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION)
        self.assertEqual(retry.operations, (pending.operation,))
        self.assertEqual(report.operations[0].status, RecoveryOperationStatus.SAFELY_RETRYABLE)

        # The applying principal is the separately authorized owner, not the
        # original verifier worker. Recovery approval is explicit and audited.
        applied = self.apply(fixture, recovery, fixture.owner.bearer_token,
                             retry, "r02-retry-not-started")
        self.assertEqual(applied.disposition, RecoveryIntentKind.RETRY_ORIGINAL_OPERATION.value)
        self.assertEqual(fixture.verifier.counts(), (1, 1))
        with fixture.open_reader() as authority:
            persisted = fixture.verification._view_for_idempotency(authority, check_key)
            event = authority.connection.execute(
                "SELECT e.actor_id, e.actor_incarnation_id FROM command_idempotency i "
                "JOIN command_receipts r USING(receipt_id) JOIN authority_events e USING(event_id) "
                "WHERE i.idempotency_key = ?", ("r02-retry-not-started",),
            ).fetchone()
            self.assertEqual(persisted.state, VerificationState.FINALIZED)
            self.assertEqual(event["actor_id"], str(fixture.owner.capability.actor.entity_id))
            self.assertNotEqual(event["actor_id"], str(worker.capability.actor.entity_id))


class DirtyWorkspaceHandoffIndependentTests(unittest.TestCase):
    def test_stopped_dirty_workspace_is_requeued_without_changing_any_git_bytes(self):
        fixture = git_fixture.GitProviderIndependentTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        authority_path, project, auth, _issued, plan, provider, attempts = fixture._admission_fixture(count=1)

        class StaticStoppedWriter:
            def inspect(self, _attempt):
                return ProcessLiveness.STOPPED

        class StaticNoChildren:
            def inspect(self, _attempt):
                return ChildActivity.NONE

        # Replace fixed fixture clocks with one controllable clock before any
        # attempt lease is issued; host observations remain tied to the same time.
        clock = verification_fixture.FixedClock(datetime(2035, 1, 2, tzinfo=timezone.utc))
        auth.clock = clock
        provider.clock = clock
        provider.process_observer = StaticStoppedWriter()
        provider.child_observer = StaticNoChildren()
        # Reuse the fixture's registered handler rather than registering a
        # duplicate AttemptService on the same dispatcher.
        attempts.clock = clock
        target = plan.work_items[0].definition.ref
        workspace_id = StableId("r02-preserved-dirty-workspace")
        workspace = fixture._create_workspace_with(provider, workspace_id)
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            owner = auth.login_local_owner(
                authority, "temporary fixture owner credential 937",
                actions=(CLAIM_ACTION, CREATE_WORKSPACE_ACTION,
                         RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION),
                scope=project.ref, expires_at=clock() + timedelta(days=1),
                idempotency_key=StableId("r02-dirty-recovery-owner"),
                expected_revision=authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                ).fetchone()[0],
            )
            claimed = attempts.claim(
                authority, owner.bearer_token, target, plan,
                idempotency_key=StableId("r02-dirty-claim"),
                expected_revision=authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                ).fetchone()[0],
                workspace_id=workspace_id,
            )
        attempt = EntityRef(project.project_id, EntityKind.ATTEMPT,
                            StableId(claimed.receipt.result["attempt_id"]))

        tracked = workspace / "module.txt"
        tracked.write_bytes(b"staged contents\n")
        fixture.git.git(workspace, "add", "module.txt")
        staged_index = Path(fixture.git.identities(workspace)["index"]).read_bytes()
        tracked.write_bytes(b"later unstaged contents\n")
        untracked = workspace / "preserve-me.bin"
        untracked.write_bytes(b"uncommitted bytes\x00must survive\n")
        before_git = fixture.git.snapshot(workspace)

        inspection = RecoveryInspectionService(auth, host=provider, clock=clock)
        recovery = RecoveryExecutionService(inspection, attempts=attempts, clock=clock)
        with SQLiteAuthority.open_reader(authority_path, project) as authority:
            active = inspection.inspect_attempt(authority, owner.bearer_token, attempt)
        clock.value = active.lease_expires_at + timedelta(seconds=1)
        with SQLiteAuthority.open_reader(authority_path, project) as authority:
            report = inspection.inspect_attempt(authority, owner.bearer_token, attempt)
        handoff, = (item for item in report.intents
                    if item.kind is RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE)

        # A source edit after review must invalidate that preview, and the
        # refusal must preserve the newly changed tree just as carefully.
        late_file = workspace / "arrived-after-review.txt"
        late_file.write_bytes(b"late bytes remain untouched\n")
        after_late_edit = fixture.git.snapshot(workspace)
        self.assertNotEqual(after_late_edit, before_git)
        before_stale_apply = self.authority_snapshot(auth, authority_path, project)
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            with self.assertRaises(RecoveryIntentStaleError):
                recovery.apply(authority, owner.bearer_token, handoff,
                               idempotency_key=StableId("r02-stale-dirty-handoff"))
        self.assertEqual(self.authority_snapshot(auth, authority_path, project), before_stale_apply)
        self.assertEqual(fixture.git.snapshot(workspace), after_late_edit)
        with SQLiteAuthority.open_reader(authority_path, project) as authority:
            refreshed = inspection.inspect_attempt(authority, owner.bearer_token, attempt)
        handoff, = (item for item in refreshed.intents
                    if item.kind is RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE)

        # Exercise the narrower race after apply's read-only reinspection but
        # before the attempt service's writer-time host guard. The first apply
        # observation is valid for the reviewed dirty tree; mutate immediately
        # after that receipt is returned. The writer observation must then see
        # a different digest and refuse without changing authority or bytes.
        race_file = workspace / "writer-race.txt"
        original_inspect = provider.inspect_attempt
        raced = False

        def mutate_after_first_apply_observation(current_attempt, current_workspace):
            nonlocal raced
            observed = original_inspect(current_attempt, current_workspace)
            race_observations.append(observed.source_digest)
            if not raced:
                raced = True
                race_file.write_bytes(b"changed after apply preflight\n")
            return observed

        provider.inspect_attempt = mutate_after_first_apply_observation
        race_observations = []
        before_writer_race = self.authority_snapshot(auth, authority_path, project)
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            with self.assertRaises(AttemptObservationMismatchError):
                recovery.apply(
                    authority, owner.bearer_token, handoff,
                    idempotency_key=StableId("r02-writer-race-dirty-handoff"),
                )
        self.assertTrue(raced)
        self.assertEqual(len(race_observations), 2, race_observations)
        self.assertEqual(race_observations[0], handoff.expected_source_digest)
        self.assertNotEqual(race_observations[1], handoff.expected_source_digest)
        self.assertEqual(self.authority_snapshot(auth, authority_path, project), before_writer_race)
        self.assertTrue(race_file.exists())
        after_writer_race = fixture.git.snapshot(workspace)
        provider.inspect_attempt = original_inspect
        with SQLiteAuthority.open_reader(authority_path, project) as authority:
            refreshed = inspection.inspect_attempt(authority, owner.bearer_token, attempt)
        handoff, = (item for item in refreshed.intents
                    if item.kind is RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE)

        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            result = recovery.apply(
                authority, owner.bearer_token, handoff,
                idempotency_key=StableId("r02-dirty-handoff"),
            )
            self.assertEqual(result.disposition, RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE.value)
            self.assertTrue(result.result.receipt.result["workspace_preserved"])
            self.assertEqual(result.result.receipt.result["workspace_id"], str(workspace_id))
        self.assertEqual(fixture.git.snapshot(workspace), after_writer_race)
        self.assertEqual(Path(fixture.git.identities(workspace)["index"]).read_bytes(), staged_index)

        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            next_claim = attempts.claim(
                authority, owner.bearer_token, target, plan,
                idempotency_key=StableId("r02-reclaim-preserved-workspace"),
                expected_revision=authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                ).fetchone()[0],
                workspace_id=workspace_id,
            )
        self.assertEqual(next_claim.receipt.result["state"], "admitted")
        self.assertEqual(fixture.git.snapshot(workspace), after_writer_race)

    @staticmethod
    def authority_snapshot(auth, authority_path, project):
        with SQLiteAuthority.open_reader(authority_path, project) as authority:
            return (
                auth.dispatcher.logical_fingerprint(authority),
                authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                ).fetchone()[0],
            )


if __name__ == "__main__":
    unittest.main()
