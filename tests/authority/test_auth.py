from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from todo_orchestrator.authority import (
    AuthenticationFailedError,
    AuthenticatedPrincipal,
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeliveryUncertainError,
    CapabilityDeniedError,
    CommandDispatcher,
    IdempotencyConflictError,
    IssuedCapability,
    OwnerAlreadyEnrolledError,
    SQLiteAuthority,
)
from todo_orchestrator.contracts import ActorKind, EntityKind, EntityRef, Project, StableId
from todo_orchestrator.model import CommandEffect


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("auth-project"), StableId("auth-authority"))
OWNER_PASSWORD = "fixture owner phrase 927"
ACTION = StableId("fixture.write")
DELEGATE = StableId("todo.capability.delegate")
REVOKE = StableId("todo.capability.revoke")
PROJECT_SCOPE = EntityRef(PROJECT.project_id, EntityKind.PROJECT, PROJECT.project_id)
WORK_SCOPE = EntityRef(PROJECT.project_id, EntityKind.WORK_ITEM, StableId("work-one"),
                       definition_revision_id=StableId("plan-one"))


@dataclass(frozen=True)
class NoOpCommand:
    value: str
    scope: EntityRef
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    attempt: EntityRef | None = None


class NoOpHandler:
    kind = "fixture.noop"
    command_type = NoOpCommand

    def authorization_requirement(self, command: NoOpCommand) -> AuthorizationRequirement:
        return AuthorizationRequirement(ACTION, command.scope, command.run,
                                        command.assignment, command.attempt)

    def canonical_payload(self, command: NoOpCommand) -> dict[str, object]:
        return {"value": command.value, "scope_kind": command.scope.kind.value,
                "scope_id": str(command.scope.entity_id),
                "definition_revision_id": (str(command.scope.definition_revision_id)
                                            if command.scope.definition_revision_id else None)}

    def apply(self, context, command: NoOpCommand) -> CommandEffect:
        return CommandEffect(False, {"accepted": command.value})


class FakeAuthenticator:
    provider_id = "fixture-host"

    def authenticate(self, credential: object) -> AuthenticatedPrincipal | None:
        if credential == "worker":
            return AuthenticatedPrincipal("subject-worker", ActorKind.AUTOMATION, "worker")
        if credential == "other":
            return AuthenticatedPrincipal("subject-other", ActorKind.SERVICE, "other")
        if credential == "grandchild":
            return AuthenticatedPrincipal("subject-grandchild", ActorKind.AUTOMATION, "grandchild")
        return None


class MutableClock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class AuthorityAuthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = MutableClock()
        self.dispatcher = CommandDispatcher([NoOpHandler()])
        self.auth = AuthorityAuthService(self.dispatcher, clock=self.clock, authenticator=FakeAuthenticator())
        with self.open_writer() as authority:
            self.enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="local owner", idempotency_key=StableId("enroll-owner"),
                expected_revision=0,
            )

    def open_reader(self, project: Project = PROJECT):
        return SQLiteAuthority.open_reader(self.path, project)

    def open_writer(self, project: Project = PROJECT):
        return SQLiteAuthority.open_writer(self.path, project)

    def issue_owner(self, *, actions=(ACTION, DELEGATE, REVOKE), scope=PROJECT_SCOPE,
                    expires_at=NOW + timedelta(hours=1), key="owner-root", expected_revision=None):
        with self.open_writer() as authority:
            return self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=actions, scope=scope, expires_at=expires_at,
                idempotency_key=StableId(key), expected_revision=expected_revision,
            )

    def snapshot(self):
        with self.open_reader() as authority:
            connection = authority.connection
            revision = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            tables = ("actors", "local_owner_credentials", "capabilities", "capability_tokens",
                      "capability_actions", "authority_events", "command_receipts", "command_idempotency")
            counts = tuple(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                           for table in tables)
            revoked = tuple(connection.execute(
                "SELECT capability_id, revoked FROM capabilities ORDER BY capability_id"
            ).fetchall())
            return revision, counts, tuple(tuple(row) for row in revoked)

    def test_plan_scope_authorizes_its_definitions_but_not_another_revision(self):
        plan_scope = EntityRef(PROJECT.project_id, EntityKind.PLAN_REVISION, StableId("plan-one"))
        issued = self.issue_owner(scope=plan_scope)
        with self.open_writer() as authority:
            result = self.auth.execute(authority, issued.bearer_token,
                                       NoOpCommand("same plan", WORK_SCOPE),
                                       idempotency_key=StableId("same-plan"))
        self.assertEqual(result.receipt.result["accepted"], "same plan")
        before = self.snapshot()
        other = EntityRef(PROJECT.project_id, EntityKind.WORK_ITEM, WORK_SCOPE.entity_id,
                          definition_revision_id=StableId("other-plan"))
        with self.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.auth.execute(authority, issued.bearer_token, NoOpCommand("other", other),
                                  idempotency_key=StableId("other-plan"))
        self.assertEqual(self.snapshot(), before)

    def test_owner_enrollment_and_bearer_storage_keep_credentials_and_tokens_secret(self):
        issued = self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        self.assertIsInstance(issued, IssuedCapability)
        self.assertNotIn(issued.bearer_token, repr(issued))
        token_digest = hashlib.sha256(issued.bearer_token.encode("ascii")).hexdigest()
        with self.open_reader() as authority:
            connection = authority.connection
            stored = connection.execute(
                "SELECT token_digest FROM capability_tokens WHERE capability_id = ?",
                (str(issued.capability.capability_id),),
            ).fetchone()[0]
            owner = connection.execute("SELECT salt, password_digest FROM local_owner_credentials").fetchone()
        self.assertEqual(stored, token_digest)
        self.assertNotEqual(owner[0], OWNER_PASSWORD.encode("utf-8"))
        self.assertNotEqual(owner[1], OWNER_PASSWORD.encode("utf-8"))
        self.assertNotIn(issued.bearer_token.encode("ascii"), self.path.read_bytes())
        with self.assertRaises(OwnerAlreadyEnrolledError):
            with self.open_writer() as authority:
                self.auth.enroll_local_owner(
                    authority, "second owner phrase 928", label="spoofed admin",
                    idempotency_key=StableId("enroll-second"),
                )

    def test_local_credential_authenticates_and_issuance_replay_cannot_recover_bearer(self):
        root = self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        before = self.snapshot()
        with self.assertRaises(CapabilityDeliveryUncertainError) as caught:
            self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        self.assertEqual(caught.exception.receipt, root.receipt)
        self.assertEqual(self.snapshot(), before)
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.auth.login_local_owner(
                    authority, "wrong owner phrase 111", actions=(ACTION,), scope=PROJECT_SCOPE,
                    expires_at=NOW + timedelta(hours=1), idempotency_key=StableId("wrong-login"),
                )

    def test_issuance_retry_uses_bootstrap_label_when_other_incarnation_sorts_first(self):
        with patch("todo_orchestrator.authority.auth._new_id",
                   side_effect=lambda prefix: StableId("inc-0000" if prefix == "inc" else "cap-0000")):
            issued = self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        # This disposable fixture creates a second incarnation with a different
        # display label and an ID that sorts before the bootstrap incarnation.
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ?",
                    ("secondary incarnation", str(issued.capability.actor.entity_id),
                     str(issued.capability.actor.incarnation_id)),
                )
        before = self.snapshot()
        with self.assertRaises(CapabilityDeliveryUncertainError) as caught:
            self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        self.assertEqual(caught.exception.receipt, issued.receipt)
        self.assertEqual(self.snapshot(), before)

    def test_authorized_command_and_exact_retries_check_live_expiry_before_replay(self):
        root = self.issue_owner(expires_at=NOW + timedelta(seconds=5),
                                expected_revision=self.enrollment.receipt.semantic_revision)
        command = NoOpCommand("one", PROJECT_SCOPE)
        with self.open_writer() as authority:
            first = self.auth.execute(authority, root.bearer_token, command,
                                      idempotency_key=StableId("command-one"),
                                      expected_revision=root.receipt.semantic_revision)
        self.assertFalse(first.replayed)
        before = self.snapshot()
        self.clock.value = NOW + timedelta(seconds=6)
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.auth.execute(authority, root.bearer_token, command,
                                  idempotency_key=StableId("command-one"),
                                  expected_revision=root.receipt.semantic_revision)
        self.assertEqual(self.snapshot(), before)

    def test_revoked_capability_cannot_replay_an_existing_command_and_refusal_writes_nothing(self):
        root = self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        command = NoOpCommand("one", PROJECT_SCOPE)
        with self.open_writer() as authority:
            self.auth.execute(authority, root.bearer_token, command,
                              idempotency_key=StableId("command-one"),
                              expected_revision=root.receipt.semantic_revision)
            self.auth.revoke_family(authority, root.bearer_token, root.capability.capability_id,
                                    idempotency_key=StableId("revoke-root"))
        before = self.snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.auth.execute(authority, root.bearer_token, command,
                                  idempotency_key=StableId("command-one"),
                                  expected_revision=root.receipt.semantic_revision)
        self.assertEqual(self.snapshot(), before)

    def test_delegation_narrows_rights_rejects_self_and_revokes_descendant_family_atomically(self):
        root = self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        child_scope = WORK_SCOPE
        child_expiry = NOW + timedelta(minutes=30)
        with self.open_writer() as authority:
            child = self.auth.delegate(
                authority, root.bearer_token, "worker", actions=(ACTION, DELEGATE, REVOKE),
                scope=child_scope, expires_at=child_expiry,
                idempotency_key=StableId("delegate-worker"),
                expected_revision=root.receipt.semantic_revision,
            )
        child_task = NoOpCommand("child", child_scope)
        with self.open_writer() as authority:
            self.auth.execute(authority, child.bearer_token, child_task,
                              idempotency_key=StableId("child-command"))
            with self.assertRaises(CapabilityDeniedError):
                self.auth.delegate(authority, child.bearer_token, "worker", actions=(ACTION,),
                                   scope=child_scope, expires_at=NOW + timedelta(minutes=10),
                                   idempotency_key=StableId("self-delegate"))
            grandchild = self.auth.delegate(
                authority, child.bearer_token, "grandchild", actions=(ACTION,), scope=child_scope,
                expires_at=NOW + timedelta(minutes=10), idempotency_key=StableId("delegate-grandchild"),
            )
            self.auth.revoke_family(authority, root.bearer_token, child.capability.capability_id,
                                    idempotency_key=StableId("revoke-child-family"))
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            repeated = self.auth.revoke_family(
                authority, root.bearer_token, child.capability.capability_id,
                idempotency_key=StableId("revoke-child-family-again"),
            )
            self.assertFalse(repeated.receipt.changed)
            self.assertEqual(repeated.receipt.semantic_revision, revision)
        with self.open_reader() as authority:
            states = dict(authority.connection.execute(
                "SELECT capability_id, revoked FROM capabilities WHERE capability_id IN (?, ?) ",
                (str(child.capability.capability_id), str(grandchild.capability.capability_id)),
            ).fetchall())
        self.assertEqual(states, {str(child.capability.capability_id): 1,
                                  str(grandchild.capability.capability_id): 1})
        before = self.snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.auth.execute(authority, grandchild.bearer_token, child_task,
                                  idempotency_key=StableId("after-revoke"))
        self.assertEqual(self.snapshot(), before)

    def test_escalating_child_grant_and_foreign_authority_token_are_refused_without_writes(self):
        root = self.issue_owner(expected_revision=self.enrollment.receipt.semantic_revision)
        before = self.snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.auth.delegate(authority, root.bearer_token, "other", actions=(StableId("admin.write"),),
                                   scope=PROJECT_SCOPE, expires_at=NOW + timedelta(minutes=10),
                                   idempotency_key=StableId("escalate"),
                                   expected_revision=root.receipt.semantic_revision)
        self.assertEqual(self.snapshot(), before)
        foreign_project = Project(StableId("foreign-project"), StableId("foreign-authority"))
        foreign_path = Path(self.directory.name) / "foreign.sqlite3"
        SQLiteAuthority.initialize(foreign_path, foreign_project)
        with SQLiteAuthority.open_writer(foreign_path, foreign_project) as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.auth.execute(authority, root.bearer_token, NoOpCommand("foreign", PROJECT_SCOPE),
                                  idempotency_key=StableId("foreign-command"))
        self.assertEqual(self.snapshot(), before)

    def test_command_handler_refusal_of_role_only_identity_never_reaches_dispatch(self):
        before = self.snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                self.auth.execute(authority, "admin", NoOpCommand("spoof", PROJECT_SCOPE),
                                  idempotency_key=StableId("spoofed-role"))
        self.assertEqual(self.snapshot(), before)

    def test_trusted_principal_identity_components_are_unambiguously_qualified(self):
        left = self.auth._principal_actor_id(PROJECT, "provider\0part", "subject")
        right = self.auth._principal_actor_id(PROJECT, "provider", "part\0subject")
        self.assertNotEqual(left, right)


if __name__ == "__main__":
    unittest.main()
