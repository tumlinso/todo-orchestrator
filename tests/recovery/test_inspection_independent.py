"""Independent public-flow checks for read-only recovery inspection."""

from dataclasses import replace
from datetime import timedelta
import unittest

from tests.verification import test_git_independent as git_fixture
from tests.verification import test_execution_independent as verification_fixture
from todo_orchestrator.authority import CapabilityDeniedError, SQLiteAuthority
from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.model import ChildActivity, ProcessLiveness, SourceSafety
from todo_orchestrator.operations.inspection import (
    RecoveryInspectionService, RecoveryStatus,
)
from todo_orchestrator.views.recovery import RecoveryIntentKind, RecoveryOperationStatus
from todo_orchestrator.providers.git.service import CREATE_WORKSPACE_ACTION, GitEffectService


INSPECT_ACTION = StableId("todo.recovery.inspect")


class MutableInspectionHost:
    def __init__(self, delegate):
        self.delegate = delegate
        self.override = None
        self.failure = None
        self.calls = []

    def inspect_attempt(self, attempt, workspace):
        self.calls.append((attempt.ref, workspace.workspace_id, workspace.common_base.ref))
        if self.failure is not None:
            raise self.failure
        observation = self.delegate.inspect_attempt(attempt, workspace)
        if observation.source_digest is None:
            observation = replace(observation, source_digest=Sha256Digest("4" * 64))
        return observation if self.override is None else self.override(observation)


class RecoveryInspectionIndependentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = verification_fixture.IndependentVerificationExecutionTests()
        owner_actions = verification_fixture.OWNER_ACTIONS
        verification_fixture.OWNER_ACTIONS = (*owner_actions, INSPECT_ACTION)
        try:
            self.fixture.setUp()
        finally:
            verification_fixture.OWNER_ACTIONS = owner_actions
        self.addCleanup(self.fixture.doCleanups)
        self.attempt_ref = self.fixture.claim(
            "verify", self.fixture.owner.bearer_token, key="r01-inspection-attempt",
        )
        self.work_ref = self.fixture.work_ref("verify")
        with self.fixture.open_writer() as authority:
            grant = self.fixture.auth.delegate(
                authority, self.fixture.owner.bearer_token, "worker-other",
                actions=(INSPECT_ACTION,), scope=self.work_ref, attempt=self.attempt_ref,
                expires_at=self.fixture.clock() + timedelta(minutes=30),
                idempotency_key=StableId("r01-inspection-grant"),
                expected_revision=self.fixture.revision(),
            )
        self.grant = grant
        self.host = MutableInspectionHost(self.fixture.host)
        self.service = RecoveryInspectionService(
            self.fixture.auth, host=self.host, clock=self.fixture.clock,
        )

    def inspect(self):
        with self.fixture.open_reader() as authority:
            return self.service.inspect_attempt(authority, self.grant.bearer_token, self.attempt_ref)

    def test_inspection_is_read_only_exactly_bound_and_repeatable_after_reopen(self):
        before = self.fixture.state_snapshot()
        first = self.inspect()
        self.assertEqual(first.attempt, self.attempt_ref)
        self.assertEqual(first.target, self.work_ref)
        self.assertEqual(first.host_observation.attempt, self.attempt_ref)
        self.assertEqual(first.host_observation.lease_id, first.lease_id)
        self.assertEqual(self.host.calls[0][0], self.attempt_ref)
        self.assertEqual(first.host_observation.workspace.workspace_id, self.host.calls[0][1])
        self.assertEqual(len(self.host.calls), 1)
        self.assertEqual(self.fixture.state_snapshot(), before)
        second = self.inspect()
        self.assertEqual(second.attempt, first.attempt)
        self.assertEqual(second.target, first.target)
        self.assertEqual(second.lease_id, first.lease_id)
        self.assertEqual(len(self.host.calls), 2)
        self.assertEqual(self.fixture.state_snapshot(), before)

    def test_expired_safe_attempt_has_preview_intent_without_reconciliation(self):
        active = self.inspect()
        self.fixture.clock.value = active.lease_expires_at + timedelta(seconds=1)
        before = self.fixture.state_snapshot()

        result = self.inspect()

        self.assertEqual(result.status, RecoveryStatus.EXPIRED)
        self.assertEqual(len(result.intents), 1)
        intent = result.intents[0]
        self.assertEqual(intent.attempt, self.attempt_ref)
        self.assertEqual(intent.expected_authority_revision, result.authority_revision)
        self.assertEqual(intent.expected_lease_id, result.lease_id)
        self.assertEqual(intent.workspace_id, result.workspace_id)
        self.assertEqual(
            {item.code for item in intent.preconditions},
            {"authority_revision_unchanged", "stored_workspace_binding_valid", "source_clean",
             "process_stopped", "no_active_children", "host_state_matches_exact_lease"},
        )
        self.assertEqual(result.state, active.state)
        self.assertEqual(self.fixture.state_snapshot(), before)

    def test_expired_live_and_unknown_workspace_stay_blocked_while_dirty_gets_handoff(self):
        active = self.inspect()
        self.fixture.clock.value = active.lease_expires_at + timedelta(seconds=1)
        for process, children in (
            (ProcessLiveness.LIVE, ChildActivity.NONE),
            (ProcessLiveness.UNKNOWN, ChildActivity.NONE),
            (ProcessLiveness.STOPPED, ChildActivity.ACTIVE),
            (ProcessLiveness.STOPPED, ChildActivity.UNKNOWN),
        ):
            self.host.override = lambda observation, process=process, children=children: replace(
                observation, process=process, children=children,
            )
            live = self.inspect()
            self.assertEqual(live.status, RecoveryStatus.UNKNOWN_LIVE)
            self.assertEqual(live.intents, ())

        self.host.override = lambda observation: replace(
            observation, source=SourceSafety.DIRTY,
        )
        dirty = self.inspect()
        self.assertEqual(dirty.status, RecoveryStatus.DIRTY)
        self.assertEqual(
            tuple(item.kind for item in dirty.intents),
            (RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE,),
        )

        self.host.override = lambda observation: replace(
            observation, source=SourceSafety.UNKNOWN,
        )
        unknown_source = self.inspect()
        self.assertEqual(unknown_source.status, RecoveryStatus.UNCERTAIN)
        self.assertEqual(unknown_source.intents, ())

    def test_unavailable_host_observation_is_uncertain_and_never_releases(self):
        active = self.inspect()
        self.fixture.clock.value = active.lease_expires_at + timedelta(seconds=1)
        self.host.failure = RuntimeError("provider unavailable")
        before = self.fixture.state_snapshot()

        result = self.inspect()

        self.assertEqual(result.status, RecoveryStatus.UNCERTAIN)
        self.assertIsNone(result.host_observation)
        self.assertEqual(result.intents, ())
        self.assertTrue(result.blockers)
        self.assertEqual(self.fixture.state_snapshot(), before)

    def test_inspection_grant_cannot_be_reused_for_another_attempt(self):
        other_attempt = self.fixture.claim(
            "other", self.fixture.owner.bearer_token, key="r01-other-attempt",
        )
        before = self.fixture.state_snapshot()
        with self.fixture.open_reader() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.service.inspect_attempt(authority, self.grant.bearer_token, other_attempt)
        self.assertEqual(self.fixture.state_snapshot(), before)


class RecoveryEffectInspectionIndependentTests(unittest.TestCase):
    def test_unattached_not_applied_workspace_is_retryable_only_while_exact_base_is_current(self):
        fixture = git_fixture.GitProviderIndependentTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path, project, auth, _issued, plan, provider, _attempts = fixture._admission_fixture(count=1)
        target = plan.work_items[0].definition.ref
        with SQLiteAuthority.open_writer(path, project) as authority:
            owner = auth.login_local_owner(
                authority, "temporary fixture owner credential 937",
                actions=(CREATE_WORKSPACE_ACTION, INSPECT_ACTION), scope=project.ref,
                expires_at=auth.clock() + timedelta(hours=1),
                idempotency_key=StableId("r01-before-effect-owner"),
                expected_revision=authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                ).fetchone()[0],
            )
        git_service = GitEffectService(auth, provider, clock=auth.clock)

        def interrupt(stage, _request):
            if stage == "before_effect":
                raise SystemExit("interrupt before workspace effect")

        provider.failure_hook = interrupt
        with SQLiteAuthority.open_writer(path, project) as authority:
            with self.assertRaisesRegex(SystemExit, "before workspace"):
                git_service.create_workspace(
                    authority, owner.bearer_token, target,
                    idempotency_key=StableId("r01-before-effect-workspace"),
                    expected_revision=authority.connection.execute(
                        "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                    ).fetchone()[0],
                )
            row = authority.connection.execute(
                "SELECT operation_id, state FROM git_effect_operations"
            ).fetchone()
            operation_ref = EntityRef(project.project_id, EntityKind.EXTERNAL_OPERATION,
                                      StableId(row["operation_id"]))
            self.assertEqual(row["state"], "executing")
            before_fingerprint = auth.dispatcher.logical_fingerprint(authority)
            before_revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0]

        inspector = RecoveryInspectionService(
            auth, host=provider, operation_inspectors={"git": provider},
            source_observer=provider, clock=auth.clock,
        )
        with SQLiteAuthority.open_reader(path, project) as authority:
            result = inspector.inspect_effect(authority, owner.bearer_token, operation_ref)
            self.assertEqual(result.status, RecoveryStatus.SAFELY_RETRYABLE)
            self.assertEqual(result.operations[0].status, RecoveryOperationStatus.SAFELY_RETRYABLE)
            self.assertIsNotNone(result.source_observation)
            self.assertEqual(result.source_observation.source_revision,
                             provider.qualified_revision(fixture.base_ref).ref)
            self.assertEqual(len(result.intents), 1)
            self.assertEqual(result.intents[0].kind, RecoveryIntentKind.RETRY_ORIGINAL_OPERATION)
            self.assertEqual(result.intents[0].operations, (operation_ref,))
            self.assertEqual(auth.dispatcher.logical_fingerprint(authority), before_fingerprint)
            self.assertEqual(authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0], before_revision)

        # Advancing the exact authored base ref after the interruption invalidates
        # the preview even if the original external effect remains absent.
        fixture.git.git(fixture.git.repository, "checkout", "main")
        (fixture.git.repository / "module.txt").write_bytes(b"changed base\n")
        fixture.git.git(fixture.git.repository, "add", "module.txt")
        fixture.git.git(fixture.git.repository, "commit", "--quiet", "-m", "advance base")
        moved_fingerprint = None
        moved_revision = None
        with SQLiteAuthority.open_reader(path, project) as authority:
            moved_fingerprint = auth.dispatcher.logical_fingerprint(authority)
            moved_revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0]
        with SQLiteAuthority.open_reader(path, project) as authority:
            moved = inspector.inspect_effect(authority, owner.bearer_token, operation_ref)
            self.assertEqual(moved.status, RecoveryStatus.UNCERTAIN)
            self.assertEqual(moved.intents, ())
            self.assertIn("pre_attempt_source_identity_mismatch",
                          {item.code for item in moved.blockers})
            self.assertEqual(auth.dispatcher.logical_fingerprint(authority), moved_fingerprint)
            self.assertEqual(authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0], moved_revision)

    def test_interrupted_workspace_effect_is_inspected_without_reconciliation(self):
        fixture = git_fixture.GitProviderIndependentTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path, project, auth, _issued, plan, provider, _attempts = fixture._admission_fixture(count=1)
        target = plan.work_items[0].definition.ref
        with SQLiteAuthority.open_writer(path, project) as authority:
            owner = auth.login_local_owner(
                authority, "temporary fixture owner credential 937",
                actions=(CREATE_WORKSPACE_ACTION, INSPECT_ACTION), scope=project.ref,
                expires_at=auth.clock() + timedelta(hours=1),
                idempotency_key=StableId("r01-git-inspection-owner"),
                expected_revision=authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                ).fetchone()[0],
            )
        git_service = GitEffectService(auth, provider, clock=auth.clock)

        def interrupt(stage, _request):
            if stage == "after_effect":
                raise SystemExit("interrupt after physical workspace creation")

        provider.failure_hook = interrupt
        with SQLiteAuthority.open_writer(path, project) as authority:
            with self.assertRaisesRegex(SystemExit, "after physical workspace"):
                git_service.create_workspace(
                    authority, owner.bearer_token, target,
                    idempotency_key=StableId("r01-interrupted-workspace"),
                    expected_revision=authority.connection.execute(
                        "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
                    ).fetchone()[0],
                )
            row = authority.connection.execute(
                "SELECT operation_id, state, observation_json, provider_receipt_json "
                "FROM git_effect_operations"
            ).fetchone()
            operation_ref = EntityRef(project.project_id, EntityKind.EXTERNAL_OPERATION,
                                      StableId(row["operation_id"]))
            self.assertEqual(row["state"], "executing")
            self.assertIsNone(row["provider_receipt_json"])
            self.assertIsNone(row["observation_json"])
            before_fingerprint = auth.dispatcher.logical_fingerprint(authority)
            before_revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0]

        inspector = RecoveryInspectionService(
            auth, host=provider, operation_inspectors={"git": provider},
            source_observer=provider, clock=auth.clock,
        )
        with SQLiteAuthority.open_reader(path, project) as authority:
            result = inspector.inspect_effect(authority, owner.bearer_token, operation_ref)
            self.assertIsNone(result.attempt)
            self.assertEqual(result.target, target)
            self.assertEqual(
                {item.code for item in result.preconditions},
                {"authority_revision_unchanged", "exact_effect_identity_valid"},
            )
            self.assertEqual(len(result.operations), 1)
            operation = result.operations[0]
            self.assertEqual(operation.operation, operation_ref)
            self.assertIsNone(operation.attempt)
            self.assertIsNotNone(operation.inspection_receipt)
            self.assertTrue(result.intents)
            self.assertEqual(result.intents[0].operations, (operation_ref,))
            self.assertEqual(result.intents[0].kind.value, "reconcile_observed_effect")
            self.assertEqual(auth.dispatcher.logical_fingerprint(authority), before_fingerprint)
            self.assertEqual(authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0], before_revision)
            row = authority.connection.execute(
                "SELECT state, observation_json, provider_receipt_json "
                "FROM git_effect_operations"
            ).fetchone()
            self.assertEqual(row["state"], "executing")
            self.assertIsNone(row["observation_json"])
            self.assertIsNone(row["provider_receipt_json"])


if __name__ == "__main__":
    unittest.main()
