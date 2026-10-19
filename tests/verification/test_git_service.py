"""Public accepted-source integration checks using disposable Git and Todo state."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import json
import subprocess
import unittest
from unittest.mock import patch

from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, SQLiteAuthority
from todo_orchestrator.contracts import (
    EntityKind,
    OutcomeDisposition,
    ProviderResult,
    ProviderStatus,
    SourceObservation,
    StableId,
)
from todo_orchestrator.model import ChildActivity, ProcessLiveness
from todo_orchestrator.providers.git import GitRepositoryConfig, GitRepositoryProvider
from todo_orchestrator.providers.git.service import (
    CREATE_WORKSPACE_ACTION,
    INTEGRATE_ACTION,
    READ_ACTION,
    RECONCILE_ACTION,
    GitEffectDeniedError,
    GitEffectService,
    GitEffectState,
)

from tests.verification import test_acceptance_independent as acceptance_fixtures
from tests.verification.test_acceptance_independent import (
    ACCEPT_OUTCOME_ACTION,
    REPORT_ACTIONS,
)
from tests.verification.test_execution_independent import PROJECT, REPOSITORY


class _StoppedProcesses:
    def inspect(self, _attempt):
        return ProcessLiveness.STOPPED


class _NoChildren:
    def inspect(self, _attempt):
        return ChildActivity.NONE


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


class GitEffectServiceIntegrationTests(unittest.TestCase):
    def setUp(self):
        case = acceptance_fixtures.IndependentOutcomeAcceptanceTests()
        case.setUp()
        self.case = case
        self.addCleanup(case.doCleanups)
        self.fixture = case.fixture

        self.repository = Path(self.fixture.temporary.name) / "accepted-source-repository"
        self.repository.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(self.repository)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _git(self.repository, "config", "user.name", "Disposable Fixture")
        _git(self.repository, "config", "user.email", "fixture@example.invalid")
        (self.repository / "README.txt").write_text("accepted Git source fixture\n", encoding="utf-8")
        _git(self.repository, "add", "README.txt")
        _git(self.repository, "commit", "--quiet", "-m", "base")
        self.base_commit = _git(self.repository, "rev-parse", "HEAD")
        self.destination_ref = StableId("refs/heads/todo-orchestrator/integration")
        _git(self.repository, "branch", "todo-orchestrator/integration", self.base_commit)

        self.provider = GitRepositoryProvider(
            GitRepositoryConfig(
                PROJECT.project_id, REPOSITORY, self.repository,
                self.repository.parent / "worktrees", self.repository.parent / "provider-journal",
                StableId("refs/heads/main"), self.destination_ref,
            ),
            clock=self.fixture.clock,
            process_observer=_StoppedProcesses(), child_observer=_NoChildren(),
        )
        self.fixture.coordination.attempts.host = self.provider
        self.fixture.verification.source_observer = self.provider
        self.fixture.verification.source_identity = self.provider.identity
        self.case.acceptance.source_observer = self.provider
        self.case.acceptance.source_identity = self.provider.identity
        self.case.acceptance.host = self.provider
        self.case.acceptance.host_identity = self.provider.identity
        self.effects = GitEffectService(self.fixture.auth, self.provider, clock=self.fixture.clock)
        self.workspace_id = StableId("v03-workspace-verify")

        with self.fixture.open_writer() as authority:
            self.git_owner = self.fixture.auth.login_local_owner(
                authority,
                acceptance_fixtures.OWNER_PASSWORD,
                actions=REPORT_ACTIONS + (CREATE_WORKSPACE_ACTION, INTEGRATE_ACTION),
                scope=PROJECT.ref,
                expires_at=self.fixture.clock() + timedelta(hours=1),
                idempotency_key=StableId("accepted-git-owner-login"),
                expected_revision=self.fixture.revision(),
            )
            self.effects.create_workspace(
                authority, self.git_owner.bearer_token, self.fixture.work_ref("verify"),
                idempotency_key=StableId("accepted-git-workspace-create"),
                workspace_id=self.workspace_id,
                expected_revision=self.fixture.revision(),
            )

    def _accept_verified_source(self):
        f = self.fixture
        dispatched = self.case.dispatch("verify", "accepted-git-dispatch")
        workspace = self.provider.workspace_path_for(self.workspace_id)
        source_file = workspace / "src" / "verify" / "source.txt"
        source_file.parent.mkdir(parents=True)
        source_file.write_text("the exact accepted source\n", encoding="utf-8")
        _git(workspace, "add", "src/verify/source.txt")
        _git(workspace, "commit", "--quiet", "-m", "accepted source")
        source_commit = _git(workspace, "rev-parse", "HEAD")

        with f.open_writer() as authority:
            verified = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("accepted-git-check"), expected_revision=f.revision(),
            )
        self.assertEqual(verified.state, "finalized")
        _, candidate = self.case.report(
            dispatched.bearer_token, dispatched.attempt.ref,
            OutcomeDisposition.COMPLETED, "accepted-git-report",
        )
        approver = self.case.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"),
            "accepted-git-approver",
        )
        accepted = self.case.accept(
            approver.bearer_token, dispatched.attempt.ref, candidate, "accepted-git-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        return dispatched, source_commit

    def test_integrates_only_the_exact_accepted_clean_source_commit(self):
        dispatched, accepted_source = self._accept_verified_source()
        with self.fixture.open_writer() as authority:
            integrated = self.effects.integrate_attempt(
                authority, self.git_owner.bearer_token, dispatched.attempt.ref,
                idempotency_key=StableId("accepted-git-integrate"),
                expected_revision=self.fixture.revision(),
            )
        self.assertEqual(integrated.state, GitEffectState.FINALIZED)
        self.assertEqual(integrated.request.source_commit, StableId(accepted_source))
        self.assertEqual(_git(self.repository, "rev-parse", self.destination_ref.value),
                         str(integrated.observation.external_ref))
        parents = _git(self.repository, "show", "-s", "--format=%P", self.destination_ref.value).split()
        self.assertEqual(parents, [self.base_commit, accepted_source])

    def test_integration_canonicalizes_accepted_source_input_order(self):
        dispatched, accepted_source = self._accept_verified_source()
        original_observe = self.provider.observe
        observed_orders = []

        def observe_reverse_sorted_inputs(request):
            result = original_observe(request)
            if (result.status is not ProviderStatus.OBSERVED_SUCCESS
                    or not isinstance(result.value, SourceObservation)):
                return result
            source = result.value
            inputs = tuple(sorted(source.inputs, key=lambda item: str(item.name), reverse=True))
            observed_orders.append(tuple(str(item.name) for item in inputs))
            return ProviderResult(
                result.status,
                result.correlation_id,
                result.provider,
                replace(source, inputs=inputs),
                result.receipt,
                result.reason_code,
            )

        with patch.object(self.provider, "observe", side_effect=observe_reverse_sorted_inputs):
            with self.fixture.open_writer() as authority:
                integrated = self.effects.integrate_attempt(
                    authority,
                    self.git_owner.bearer_token,
                    dispatched.attempt.ref,
                    idempotency_key=StableId("accepted-git-integrate-input-order"),
                    expected_revision=self.fixture.revision(),
                )

        self.assertEqual(integrated.state, GitEffectState.FINALIZED)
        self.assertEqual(integrated.request.source_commit, StableId(accepted_source))
        self.assertTrue(observed_orders)
        self.assertGreater(len(observed_orders[0]), 1)
        self.assertEqual(observed_orders[0], tuple(sorted(observed_orders[0], reverse=True)))

    def test_clean_commit_after_acceptance_is_refused_without_intent_or_ref_churn(self):
        dispatched, _accepted_source = self._accept_verified_source()
        workspace = self.provider.workspace_path_for(self.workspace_id)
        later = workspace / "src" / "verify" / "later.txt"
        later.write_text("not part of accepted evidence\n", encoding="utf-8")
        _git(workspace, "add", "src/verify/later.txt")
        _git(workspace, "commit", "--quiet", "-m", "unaccepted later source")
        destination_before = _git(self.repository, "rev-parse", self.destination_ref.value)
        with self.fixture.open_writer() as authority:
            before_revision = self.fixture.revision()
            before_operations = authority.connection.execute(
                "SELECT count(*) FROM git_effect_operations"
            ).fetchone()[0]
            with self.assertRaises(GitEffectDeniedError):
                self.effects.integrate_attempt(
                    authority, self.git_owner.bearer_token, dispatched.attempt.ref,
                    idempotency_key=StableId("reject-unaccepted-git-integrate"),
                    expected_revision=before_revision,
                )
            self.assertEqual(self.fixture.revision(), before_revision)
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM git_effect_operations"
            ).fetchone()[0], before_operations)
        self.assertEqual(_git(self.repository, "rev-parse", self.destination_ref.value), destination_before)

    def test_interrupted_accepted_integration_reconciles_after_source_receipt_ages(self):
        dispatched, accepted_source = self._accept_verified_source()

        def interrupt(stage, _request):
            if stage == "after_effect":
                raise SystemExit("simulated process loss after integration ref advance")

        self.provider.failure_hook = interrupt
        operation_key = StableId("accepted-git-interrupted-integrate")
        with self.fixture.open_writer() as authority:
            with self.assertRaises(SystemExit):
                self.effects.integrate_attempt(
                    authority, self.git_owner.bearer_token, dispatched.attempt.ref,
                    idempotency_key=operation_key, expected_revision=self.fixture.revision(),
                )
            operations = authority.connection.execute(
                "SELECT operation_id, state, request_json FROM git_effect_operations"
            ).fetchall()
            row = next(
                item for item in operations
                if json.loads(item["request_json"])["request"]["operation"] == "integrate"
            )
            self.assertEqual(row["state"], "executing")
            operation_id = StableId(row["operation_id"])
            intent = json.loads(row["request_json"])
            saved_source_receipt = intent["source_receipt"]
            self.assertIsNotNone(saved_source_receipt)

        destination_after_effect = _git(self.repository, "rev-parse", self.destination_ref.value)
        self.assertEqual(
            _git(self.repository, "show", "-s", "--format=%P", destination_after_effect).split(),
            [self.base_commit, accepted_source],
        )
        self.fixture.clock.value += timedelta(minutes=2)
        auth = AuthorityAuthService(CommandDispatcher(), clock=self.fixture.clock)
        provider = GitRepositoryProvider(
            self.provider.config, clock=self.fixture.clock,
            process_observer=_StoppedProcesses(), child_observer=_NoChildren(),
        )
        recovery_service = GitEffectService(auth, provider, clock=self.fixture.clock)

        with self.fixture.open_writer() as authority:
            recovery = auth.login_local_owner(
                authority, acceptance_fixtures.OWNER_PASSWORD,
                actions=(READ_ACTION, RECONCILE_ACTION), scope=PROJECT.ref,
                expires_at=self.fixture.clock() + timedelta(hours=1),
                idempotency_key=StableId("accepted-git-integration-recovery-login"),
                expected_revision=self.fixture.revision(),
            )
            operation_before_reconcile = recovery_service.read_operation(
                authority, recovery.bearer_token, operation_id,
            )
            self.assertIsNotNone(operation_before_reconcile.accepted_source_receipt)
            source_receipt_age = (
                self.fixture.clock() - operation_before_reconcile.accepted_source_receipt.observed_at
            )
            self.assertGreater(source_receipt_age, recovery_service.max_observation_age)
            reconciled = recovery_service.reconcile(
                authority, recovery.bearer_token, operation_id,
                idempotency_key=StableId("accepted-git-integration-recovery-query"),
                expected_revision=self.fixture.revision(),
            )

        self.assertEqual(reconciled.state, GitEffectState.FINALIZED)
        self.assertEqual(reconciled.request.source_commit, StableId(accepted_source))
        self.assertEqual(reconciled.observation.external_ref, StableId(destination_after_effect))
        self.assertEqual(_git(self.repository, "rev-parse", self.destination_ref.value), destination_after_effect)
        self.assertIsNone(reconciled.provider_receipt)
        self.assertIsNotNone(reconciled.inspection_receipt)
        self.assertEqual(reconciled.accepted_source_receipt.receipt_id, StableId(saved_source_receipt["receipt_id"]))


if __name__ == "__main__":
    unittest.main()
