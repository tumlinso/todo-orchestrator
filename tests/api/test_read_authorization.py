"""Facade read methods retain current authority and scope checks."""

from datetime import timedelta
from pathlib import Path
import tempfile
import unittest

from tests.api import test_standalone_independent as plans
from tests.verification import test_execution_independent as fixtures
from todo_orchestrator.api import (
    DEFAULT_OWNER_ACTIONS, ProviderComposition, TodoApplication, TodoAuthenticationError,
)
from todo_orchestrator.authority import (
    AuthorityAuthService, CapabilityDeniedError, CommandDispatcher, SQLiteAuthority,
)
from todo_orchestrator.contracts import StableId
from todo_orchestrator.operations.export import AUTHORITY_READ_ACTION
from todo_orchestrator.planning import PlanService


class ReadAuthorizationTests(unittest.TestCase):
    def test_project_preview_and_snapshot_refuse_scoped_revoked_and_expired_grants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clock = fixtures.FixedClock()
            providers = ProviderComposition(clock=clock)
            with TodoApplication.initialize(
                root, project_id=StableId("api-read-project"),
                repository_id=StableId("api-read-repository"),
                owner_credential=plans.OWNER_CREDENTIAL, providers=providers,
                owner_actions=(*DEFAULT_OWNER_ACTIONS, StableId("todo.capability.delegate"),
                               StableId("todo.capability.revoke")),
            ) as owner:
                project, token = owner.project, owner.bearer_token
                package = plans._plan(project)
                owner.commit_plan(package, owner.preview_plan(package),
                                  idempotency_key=StableId("api-read-plan"))
            path = root / ".todo-orchestrator" / "authority.sqlite3"
            dispatcher = CommandDispatcher()
            auth = AuthorityAuthService(dispatcher, clock=clock,
                                        authenticator=fixtures.FixtureAuthenticator())
            with SQLiteAuthority.open_reader(path, project) as authority:
                work = PlanService(auth).load_accepted_plan(authority).work_items[0].definition.ref

            def fingerprint():
                with SQLiteAuthority.open_reader(path, project) as authority:
                    return dispatcher.logical_fingerprint(authority)

            def grant(scope, key, duration=timedelta(minutes=5)):
                with SQLiteAuthority.open_writer(path, project) as authority:
                    return auth.delegate(
                        authority, token, "worker-other", actions=(AUTHORITY_READ_ACTION,),
                        scope=scope, expires_at=clock() + duration, idempotency_key=StableId(key),
                    )

            scoped = grant(work, "api-work-read")
            before = fingerprint()
            with TodoApplication.open(root, bearer_token=scoped.bearer_token, providers=providers) as session:
                for read in (lambda: session.preview_plan(package), session.read_snapshot):
                    with self.assertRaises(CapabilityDeniedError):
                        read()
            self.assertEqual(fingerprint(), before)

            revoked = grant(project.ref, "api-revoked-read")
            with TodoApplication.open(root, bearer_token=revoked.bearer_token, providers=providers) as session:
                session.preview_plan(package)
                session.read_snapshot()
            with SQLiteAuthority.open_writer(path, project) as authority:
                auth.revoke_family(authority, token, revoked.capability.capability_id,
                                   idempotency_key=StableId("api-revoke-reader"))
            before = fingerprint()
            with self.assertRaises((TodoAuthenticationError, CapabilityDeniedError)):
                with TodoApplication.open(root, bearer_token=revoked.bearer_token, providers=providers) as session:
                    session.preview_plan(package)
            self.assertEqual(fingerprint(), before)

            expired = grant(project.ref, "api-expired-read", timedelta(seconds=30))
            clock.value += timedelta(minutes=1)
            before = fingerprint()
            with self.assertRaises((TodoAuthenticationError, CapabilityDeniedError)):
                with TodoApplication.open(root, bearer_token=expired.bearer_token, providers=providers) as session:
                    session.read_snapshot()
            self.assertEqual(fingerprint(), before)
