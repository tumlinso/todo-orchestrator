"""Independent public Git-effect lifecycle checks with disposable authorities."""

from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from tests.verification import test_git_independent as fixtures
from todo_orchestrator.authority import (
    AuthenticationFailedError, AuthorityAuthService, CapabilityDeniedError,
    CommandDispatcher, SQLiteAuthority,
)
from todo_orchestrator.contracts import EffectInspectionRequest, StableId, provider_request_digest
from todo_orchestrator.providers.git.service import (
    CREATE_WORKSPACE_ACTION,
    READ_ACTION,
    RECONCILE_ACTION,
    GitEffectService,
    GitEffectState,
)


class IndependentGitServiceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GitProviderIndependentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        (self.path, self.project, self.auth, _issued, self.plan,
         self.provider, _attempts) = self.fixture._admission_fixture(count=1)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            issued = self.auth.login_local_owner(
                authority, "temporary fixture owner credential 937",
                actions=(CREATE_WORKSPACE_ACTION, READ_ACTION, RECONCILE_ACTION),
                scope=self.project.ref, expires_at=self.auth.clock() + timedelta(days=1),
                idempotency_key=StableId("independent-git-service-login"),
                expected_revision=self.revision(authority),
            )
        self.token = issued.bearer_token
        self.service = GitEffectService(self.auth, self.provider, clock=self.auth.clock)
        self.target = self.plan.work_items[0].definition.ref

    @staticmethod
    def revision(authority):
        return authority.connection.execute(
            "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
        ).fetchone()[0]

    def test_public_workspace_roundtrip_and_exact_retry_preserve_original_receipt(self):
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            revision = self.revision(authority)
            view = self.service.create_workspace(
                authority, self.token, self.target,
                idempotency_key=StableId("independent-public-workspace"),
                expected_revision=revision,
            )
            self.assertEqual(view.state, GitEffectState.FINALIZED)
            self.assertIsNotNone(view.provider_receipt)
            self.assertIsNotNone(view.qualification)
            self.assertTrue(self.provider.workspace_path_for(view.request.workspace_id).is_dir())
            stored = self.service.read_operation(authority, self.token, view.operation_id)
            self.assertEqual(stored.provider_receipt, view.provider_receipt)
            before_retry = self.revision(authority)
            replay = self.service.create_workspace(
                authority, self.token, self.target,
                idempotency_key=StableId("independent-public-workspace"),
                expected_revision=revision,
            )
            self.assertEqual(replay, view)
            self.assertEqual(self.revision(authority), before_retry)
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM git_effect_operations"
            ).fetchone()[0], 1)

    def test_effect_without_authority_receipt_is_inspected_after_reopen(self):
        def interrupt(stage, request):
            if stage == "after_effect":
                raise SystemExit("injected interruption after workspace effect")

        self.provider.failure_hook = interrupt
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with self.assertRaisesRegex(SystemExit, "injected interruption"):
                self.service.create_workspace(
                    authority, self.token, self.target,
                    idempotency_key=StableId("independent-workspace-interruption"),
                    expected_revision=self.revision(authority),
                )
            row = authority.connection.execute(
                "SELECT operation_id, state FROM git_effect_operations"
            ).fetchone()
            self.assertEqual(row["state"], "executing")
            operation = StableId(row["operation_id"])
        fresh_provider = type(self.provider)(self.provider.config, clock=self.auth.clock)
        fresh_auth = AuthorityAuthService(CommandDispatcher(), clock=self.auth.clock)
        fresh_service = GitEffectService(fresh_auth, fresh_provider, clock=self.auth.clock)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            recovered = fresh_service.reconcile(
                authority, self.token, operation,
                idempotency_key=StableId("independent-inspect-workspace"),
                expected_revision=self.revision(authority),
            )
            self.assertEqual(recovered.state, GitEffectState.FINALIZED)
            self.assertIsNone(recovered.provider_receipt)
            self.assertIsNotNone(recovered.inspection_receipt)
            self.assertTrue(fresh_provider.workspace_path_for(recovered.request.workspace_id).is_dir())
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM git_effect_operations"
            ).fetchone()[0], 1)

    def test_inspection_receipt_binds_current_query_including_recovery_context(self):
        original = self.fixture.create_request("query-envelope-workspace")
        self.fixture.provider.perform(original)
        query = EffectInspectionRequest(
            self.fixture.context, original.operation_id, original.idempotency_key,
            provider_request_digest(original), StableId("new-inspection-context-query"), original,
        )
        result = self.fixture.provider.inspect(query)
        self.assertIsNotNone(result.receipt)
        self.assertEqual(result.receipt.correlation_id, query.correlation_id)
        self.assertEqual(result.receipt.request_digest, provider_request_digest(query))

    def test_durable_provider_receipt_is_recovered_when_authority_finalization_was_interrupted(self):
        def interrupt(*args, **kwargs):
            raise SystemExit("interrupted after durable provider receipt")

        self.service._store_provider_result = interrupt
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with self.assertRaises(SystemExit):
                self.service.create_workspace(
                    authority, self.token, self.target,
                    idempotency_key=StableId("receipt-before-authority-finalize"),
                    expected_revision=self.revision(authority),
                )
            row = authority.connection.execute(
                "SELECT operation_id, state FROM git_effect_operations"
            ).fetchone()
            self.assertEqual(row["state"], "executing")
            operation = StableId(row["operation_id"])
        original = json.loads(self.provider._operation_record_path(operation).read_text())["receipt"]
        self.assertIsNotNone(original)
        auth = AuthorityAuthService(CommandDispatcher(), clock=self.auth.clock)
        provider = type(self.provider)(self.provider.config, clock=self.auth.clock)
        service = GitEffectService(auth, provider, clock=self.auth.clock)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            recovered = service.reconcile(
                authority, self.token, operation,
                idempotency_key=StableId("inspect-existing-provider-receipt"),
                expected_revision=self.revision(authority),
            )
            self.assertEqual(recovered.state, GitEffectState.FINALIZED)
            self.assertIsNotNone(recovered.inspection_receipt)
            self.assertIsNotNone(recovered.provider_receipt)
            self.assertEqual(str(recovered.provider_receipt.receipt_id), original["receipt_id"])

    def test_separate_recovery_grant_can_inspect_after_original_grant_expires(self):
        def interrupt(stage, request):
            if stage == "after_effect":
                raise SystemExit("interrupted before effect receipt")

        self.provider.failure_hook = interrupt
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with self.assertRaises(SystemExit):
                self.service.create_workspace(
                    authority, self.token, self.target,
                    idempotency_key=StableId("expired-actor-workspace"),
                    expected_revision=self.revision(authority),
                )
            operation = StableId(authority.connection.execute(
                "SELECT operation_id FROM git_effect_operations"
            ).fetchone()[0])
        future = self.auth.clock() + timedelta(days=2)
        auth = AuthorityAuthService(CommandDispatcher(), clock=lambda: future)
        provider = type(self.provider)(self.provider.config, clock=lambda: future)
        service = GitEffectService(auth, provider, clock=lambda: future)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            recovery = auth.login_local_owner(
                authority, "temporary fixture owner credential 937",
                actions=(READ_ACTION, RECONCILE_ACTION), scope=self.project.ref,
                expires_at=future + timedelta(days=1),
                idempotency_key=StableId("separate-recovery-only-login"),
                expected_revision=self.revision(authority),
            )
            with self.assertRaises(AuthenticationFailedError):
                service.read_operation(authority, self.token, operation)
            before = self.revision(authority)
            original = service.read_operation(authority, recovery.bearer_token, operation)
            self.assertEqual(self.revision(authority), before)
            recovered = service.reconcile(
                authority, recovery.bearer_token, operation,
                idempotency_key=StableId("separate-recovery-inspection"),
                expected_revision=before,
            )
            self.assertEqual(recovered.state, GitEffectState.FINALIZED)
            self.assertNotEqual(original.request.context.actor, recovery.capability.actor)
            self.assertIsNone(recovered.provider_receipt)
            self.assertIsNotNone(recovered.inspection_receipt)
            with self.assertRaises(CapabilityDeniedError):
                service.create_workspace(
                    authority, recovery.bearer_token, self.target,
                    idempotency_key=StableId("recovery-must-not-create"),
                    expected_revision=self.revision(authority),
                )

    def test_process_exit_after_git_effect_recovers_without_repeating_creation(self):
        config = self.provider.config
        payload = {
            "path": str(self.path), "project": str(self.project.project_id),
            "authority": str(self.project.authority_id), "token": self.token,
            "target": str(self.target.entity_id), "definition": str(self.target.definition_revision_id),
            "repository_id": str(config.repository_id), "repository": str(config.repository_root),
            "workspaces": str(config.workspace_root), "journal": str(config.journal_root),
            "base": str(config.base_ref), "destination": str(config.integration_ref),
            "now": self.auth.clock().isoformat(),
        }
        script = '''
from datetime import datetime
import json, os, sys
from pathlib import Path
from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, SQLiteAuthority
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, StableId
from todo_orchestrator.providers.git import GitRepositoryConfig, GitRepositoryProvider
from todo_orchestrator.providers.git.service import GitEffectService
p = json.load(sys.stdin)
clock = lambda: datetime.fromisoformat(p["now"])
project = Project(StableId(p["project"]), StableId(p["authority"]))
target = EntityRef(project.project_id, EntityKind.WORK_ITEM, StableId(p["target"]),
                   definition_revision_id=StableId(p["definition"]))
config = GitRepositoryConfig(project.project_id, StableId(p["repository_id"]),
    Path(p["repository"]), Path(p["workspaces"]), Path(p["journal"]),
    StableId(p["base"]), StableId(p["destination"]))
def interrupt(stage, request):
    if stage == "after_effect":
        os._exit(73)
provider = GitRepositoryProvider(config, clock=clock, failure_hook=interrupt)
auth = AuthorityAuthService(CommandDispatcher(), clock=clock)
service = GitEffectService(auth, provider, clock=clock)
with SQLiteAuthority.open_writer(Path(p["path"]), project) as authority:
    revision = authority.connection.execute(
        "SELECT semantic_revision FROM authority_meta WHERE singleton=1").fetchone()[0]
    service.create_workspace(authority, p["token"], target,
        idempotency_key=StableId("independent-real-process-crash"), expected_revision=revision)
'''
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2] / "src"))
        child = subprocess.run(
            [sys.executable, "-S", "-c", script], input=json.dumps(payload), text=True,
            capture_output=True, env=environment, timeout=30,
        )
        self.assertEqual(child.returncode, 73, child.stderr)
        fresh_auth = AuthorityAuthService(CommandDispatcher(), clock=self.auth.clock)
        fresh_provider = type(self.provider)(config, clock=self.auth.clock)
        service = GitEffectService(fresh_auth, fresh_provider, clock=self.auth.clock)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            row = authority.connection.execute(
                "SELECT operation_id, state FROM git_effect_operations"
            ).fetchone()
            self.assertEqual(row["state"], "executing")
            before = self.fixture.git.git(config.repository_root, "worktree", "list", "--porcelain").stdout
            recovered = service.reconcile(
                authority, self.token, StableId(row["operation_id"]),
                idempotency_key=StableId("inspect-real-process-crash"),
                expected_revision=self.revision(authority),
            )
            self.assertEqual(recovered.state, GitEffectState.FINALIZED)
            self.assertIsNone(recovered.provider_receipt)
            self.assertIsNotNone(recovered.inspection_receipt)
            self.assertEqual(
                self.fixture.git.git(config.repository_root, "worktree", "list", "--porcelain").stdout,
                before,
            )
