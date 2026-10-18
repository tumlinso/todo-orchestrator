"""Independent adversarial checks for the public authentication boundary."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AuthenticationFailedError,
    AuthenticatedPrincipal,
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeliveryUncertainError,
    CapabilityDeniedError,
    CommandDispatcher,
    OwnerAlreadyEnrolledError,
    SQLiteAuthority,
)
from todo_orchestrator.contracts import ActorKind, EntityKind, EntityRef, Project, StableId
from todo_orchestrator.model import CommandEffect


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("auth-independent-project"), StableId("auth-independent-authority"))
OWNER_PASSWORD = "fixture independent owner 927"
ACTION = StableId("fixture.independent.write")
DELEGATE = StableId("todo.capability.delegate")
REVOKE = StableId("todo.capability.revoke")
PROJECT_SCOPE = EntityRef(PROJECT.project_id, EntityKind.PROJECT, PROJECT.project_id)
WORK_SCOPE = EntityRef(PROJECT.project_id, EntityKind.WORK_ITEM, StableId("work-one"),
                       definition_revision_id=StableId("plan-one"))


@dataclass(frozen=True)
class ProbeCommand:
    scope: EntityRef
    marker: str
    claimed_role: str
    claimed_actor: EntityRef


class ProbeHandler:
    """A fixed-action handler that records the dispatcher-authenticated actor."""

    kind = "fixture.independent.auth_probe"
    command_type = ProbeCommand

    def authorization_requirement(self, command: ProbeCommand) -> AuthorizationRequirement:
        return AuthorizationRequirement(ACTION, command.scope)

    def canonical_payload(self, command: ProbeCommand) -> dict[str, object]:
        return {
            "scope_kind": command.scope.kind.value,
            "scope_id": str(command.scope.entity_id),
            "scope_incarnation_id": (str(command.scope.incarnation_id)
                                     if command.scope.incarnation_id else None),
            "marker": command.marker,
            "claimed_role": command.claimed_role,
            "claimed_actor_id": str(command.claimed_actor.entity_id),
            "claimed_actor_incarnation_id": str(command.claimed_actor.incarnation_id),
        }

    def apply(self, context, command: ProbeCommand) -> CommandEffect:
        actual_actor = context.actor
        updated = context.execute(
            "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ?",
            ("probe:" + command.marker, str(actual_actor.entity_id), str(actual_actor.incarnation_id)),
        )
        if updated.rowcount != 1:
            raise AssertionError("authenticated actor incarnation was not registered")
        actual = {"actor_id": str(actual_actor.entity_id),
                  "incarnation_id": str(actual_actor.incarnation_id)}
        payload = {"marker": command.marker, "claimed_role": command.claimed_role,
                   "claimed_actor_id": str(command.claimed_actor.entity_id),
                   "claimed_actor_incarnation_id": str(command.claimed_actor.incarnation_id),
                   "authenticated_actor": actual}
        return CommandEffect(True, {"authenticated_actor": actual,
                                    "claimed_role": command.claimed_role},
                             "fixture.independent.auth_probe", payload)


class FakeAuthenticator:
    provider_id = "fixture-independent-host"

    def authenticate(self, credential: object) -> AuthenticatedPrincipal | None:
        principals = {
            "worker": AuthenticatedPrincipal("subject-worker", ActorKind.AUTOMATION, "worker"),
            "sibling": AuthenticatedPrincipal("subject-sibling", ActorKind.SERVICE, "sibling"),
            "grandchild": AuthenticatedPrincipal("subject-grandchild", ActorKind.AUTOMATION, "grandchild"),
        }
        return principals.get(credential) if isinstance(credential, str) else None


class MutableClock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


class IndependentAuthorityAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = MutableClock()
        self.dispatcher = CommandDispatcher([ProbeHandler()])
        self.auth = AuthorityAuthService(
            self.dispatcher, clock=self.clock, authenticator=FakeAuthenticator()
        )
        with self.open_writer() as authority:
            self.enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="bootstrap person",
                idempotency_key=StableId("independent-enroll"), expected_revision=0,
            )

    def open_reader(self, path: Path | None = None, project: Project = PROJECT):
        return SQLiteAuthority.open_reader(path or self.path, project)

    def open_writer(self, path: Path | None = None, project: Project = PROJECT):
        return SQLiteAuthority.open_writer(path or self.path, project)

    def logical_dump(self, path: Path | None = None, project: Project = PROJECT) -> str:
        with self.open_reader(path, project) as authority:
            return "\n".join(authority.connection.iterdump())

    def issue_owner(self, *, actions=(ACTION,), scope=PROJECT_SCOPE,
                    expires_at=NOW + timedelta(hours=1), key="independent-owner",
                    expected_revision=None):
        with self.open_writer() as authority:
            return self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=actions, scope=scope,
                expires_at=expires_at, idempotency_key=StableId(key),
                expected_revision=expected_revision,
            )

    @staticmethod
    def probe(scope: EntityRef, marker: str) -> ProbeCommand:
        forged_actor = EntityRef(PROJECT.project_id, EntityKind.ACTOR,
                                 StableId("claimed-actor"), incarnation_id=StableId("claimed-inc"))
        return ProbeCommand(scope, marker, "administrator", forged_actor)

    def test_local_enrollment_creates_only_a_human_owner_and_refusal_is_read_only(self):
        owner_id = self.enrollment.receipt.result["actor_id"]
        incarnation_id = self.enrollment.receipt.result["incarnation_id"]
        with self.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT kind, label FROM actors WHERE actor_id = ? AND incarnation_id = ?",
                (owner_id, incarnation_id),
            ).fetchone()
        self.assertEqual(tuple(row), (ActorKind.HUMAN.value, "bootstrap person"))

        before = self.logical_dump()
        with self.assertRaises(OwnerAlreadyEnrolledError):
            with self.open_writer() as authority:
                self.auth.enroll_local_owner(
                    authority, "second independent owner 928", label="administrator",
                    idempotency_key=StableId("independent-second-enroll"),
                )
        self.assertEqual(self.logical_dump(), before)

        with self.assertRaises(AuthenticationFailedError):
            with self.open_writer() as authority:
                self.auth.login_local_owner(
                    authority, "wrong independent owner phrase 929", actions=(ACTION,),
                    scope=PROJECT_SCOPE, expires_at=NOW + timedelta(hours=1),
                    idempotency_key=StableId("independent-wrong-password"),
                )
        self.assertEqual(self.logical_dump(), before)

    def test_bearer_is_absent_from_full_database_dump_and_issuance_replay_is_uncertain(self):
        issuance_key = StableId("independent-secret-issuance")
        expiry = NOW + timedelta(hours=1)
        with self.open_writer() as authority:
            issued = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=(ACTION,), scope=PROJECT_SCOPE,
                expires_at=expiry, idempotency_key=issuance_key,
                expected_revision=self.enrollment.receipt.semantic_revision,
            )
        self.assertNotIn(issued.bearer_token, repr(issued))

        with self.open_writer() as authority:
            result = self.auth.execute(
                authority, issued.bearer_token, self.probe(PROJECT_SCOPE, "persist-event"),
                idempotency_key=StableId("independent-secret-command"),
                expected_revision=issued.receipt.semantic_revision,
            )
        self.assertTrue(result.receipt.changed)
        self.assertIsNotNone(result.receipt.event_id)
        dump = self.logical_dump()
        self.assertNotIn(issued.bearer_token, dump)
        self.assertIn(hashlib.sha256(issued.bearer_token.encode("ascii")).hexdigest(), dump)
        self.assertNotIn(OWNER_PASSWORD, dump)

        with self.assertRaises(CapabilityDeliveryUncertainError) as caught:
            with self.open_writer() as authority:
                self.auth.login_local_owner(
                    authority, OWNER_PASSWORD, actions=(ACTION,), scope=PROJECT_SCOPE,
                    expires_at=expiry, idempotency_key=issuance_key,
                    expected_revision=self.enrollment.receipt.semantic_revision,
                )
        self.assertEqual(caught.exception.receipt, issued.receipt)
        self.assertNotIn(issued.bearer_token, str(caught.exception))
        self.assertEqual(self.logical_dump(), dump)

    def test_expired_exact_retry_is_rejected_before_replay_without_any_database_write(self):
        expiry = NOW + timedelta(seconds=5)
        issued = self.issue_owner(expires_at=expiry, key="independent-expiring")
        command = self.probe(PROJECT_SCOPE, "expiry-replay")
        with self.open_writer() as authority:
            first = self.auth.execute(
                authority, issued.bearer_token, command,
                idempotency_key=StableId("independent-expiry-command"),
                expected_revision=issued.receipt.semantic_revision,
            )
        self.assertFalse(first.replayed)
        before = self.logical_dump()
        self.clock.value = expiry + timedelta(microseconds=1)
        with self.assertRaises(AuthenticationFailedError):
            with self.open_writer() as authority:
                self.auth.execute(
                    authority, issued.bearer_token, command,
                    idempotency_key=StableId("independent-expiry-command"),
                    expected_revision=issued.receipt.semantic_revision,
                )
        self.assertEqual(self.logical_dump(), before)

    def test_revoked_exact_retry_is_rejected_before_replay_without_any_database_write(self):
        issued = self.issue_owner(actions=(ACTION, REVOKE), key="independent-revoking")
        command = self.probe(PROJECT_SCOPE, "revoked-replay")
        with self.open_writer() as authority:
            self.auth.execute(
                authority, issued.bearer_token, command,
                idempotency_key=StableId("independent-revoked-command"),
                expected_revision=issued.receipt.semantic_revision,
            )
            self.auth.revoke_family(
                authority, issued.bearer_token, issued.capability.capability_id,
                idempotency_key=StableId("independent-revoke-self"),
            )
        before = self.logical_dump()
        with self.assertRaises(AuthenticationFailedError):
            with self.open_writer() as authority:
                self.auth.execute(
                    authority, issued.bearer_token, command,
                    idempotency_key=StableId("independent-revoked-command"),
                    expected_revision=issued.receipt.semantic_revision,
                )
        self.assertEqual(self.logical_dump(), before)

    def test_scope_and_audit_identity_bind_actor_incarnation_not_command_role_claims(self):
        allowed_scope = EntityRef(PROJECT.project_id, EntityKind.ACTOR, StableId("target-actor"),
                                  incarnation_id=StableId("target-incarnation-a"))
        issued = self.issue_owner(scope=allowed_scope, key="independent-incarnation-bound")
        command = self.probe(allowed_scope, "incarnation-bound")
        with self.open_writer() as authority:
            result = self.auth.execute(
                authority, issued.bearer_token, command,
                idempotency_key=StableId("independent-incarnation-command"),
            )
        self.assertEqual(command.claimed_role, "administrator")
        self.assertNotEqual(command.claimed_actor.incarnation_id, allowed_scope.incarnation_id)
        self.assertEqual(result.receipt.actor, issued.capability.actor)
        self.assertEqual(result.receipt.result["authenticated_actor"]["actor_id"],
                         str(issued.capability.actor.entity_id))

        wrong_incarnation = EntityRef(PROJECT.project_id, EntityKind.ACTOR, allowed_scope.entity_id,
                                      incarnation_id=StableId("target-incarnation-b"))
        before = self.logical_dump()
        with self.assertRaises(CapabilityDeniedError):
            with self.open_writer() as authority:
                self.auth.execute(
                    authority, issued.bearer_token,
                    self.probe(wrong_incarnation, "wrong-incarnation"),
                    idempotency_key=StableId("independent-wrong-incarnation-command"),
                )
        self.assertEqual(self.logical_dump(), before)

        foreign_project = Project(StableId("auth-independent-foreign-project"),
                                  StableId("auth-independent-foreign-authority"))
        foreign_path = Path(self.directory.name) / "foreign.sqlite3"
        SQLiteAuthority.initialize(foreign_path, foreign_project)
        foreign_before = self.logical_dump(foreign_path, foreign_project)
        with self.assertRaises(AuthenticationFailedError):
            with self.open_writer(foreign_path, foreign_project) as authority:
                self.auth.execute(
                    authority, issued.bearer_token,
                    self.probe(EntityRef(foreign_project.project_id, EntityKind.PROJECT,
                                         foreign_project.project_id), "foreign-token"),
                    idempotency_key=StableId("independent-foreign-token"),
                )
        self.assertEqual(self.logical_dump(foreign_path, foreign_project), foreign_before)

    def test_delegation_is_narrowed_and_family_revoke_preserves_sibling_and_parent(self):
        root = self.issue_owner(actions=(ACTION, DELEGATE, REVOKE),
                                expires_at=NOW + timedelta(hours=4), key="independent-family-root")
        before = self.logical_dump()
        with self.assertRaises(CapabilityDeniedError):
            with self.open_writer() as authority:
                self.auth.delegate(
                    authority, root.bearer_token, "worker",
                    actions=(ACTION, DELEGATE, REVOKE, StableId("fixture.admin")),
                    scope=WORK_SCOPE, expires_at=NOW + timedelta(hours=2),
                    idempotency_key=StableId("independent-escalation"),
                )
        self.assertEqual(self.logical_dump(), before)

        with self.open_writer() as authority:
            child = self.auth.delegate(
                authority, root.bearer_token, "worker", actions=(ACTION, DELEGATE, REVOKE),
                scope=WORK_SCOPE, expires_at=NOW + timedelta(hours=2),
                idempotency_key=StableId("independent-child"),
            )
        before_widen = self.logical_dump()
        with self.assertRaises(CapabilityDeniedError):
            with self.open_writer() as authority:
                self.auth.delegate(
                    authority, child.bearer_token, "sibling", actions=(ACTION,),
                    scope=PROJECT_SCOPE, expires_at=NOW + timedelta(hours=1),
                    idempotency_key=StableId("independent-widen-scope"),
                )
        self.assertEqual(self.logical_dump(), before_widen)

        with self.open_writer() as authority:
            grandchild = self.auth.delegate(
                authority, child.bearer_token, "grandchild", actions=(ACTION,),
                scope=WORK_SCOPE, expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("independent-grandchild"),
            )
            sibling = self.auth.delegate(
                authority, root.bearer_token, "sibling", actions=(ACTION,),
                scope=WORK_SCOPE, expires_at=NOW + timedelta(hours=2),
                idempotency_key=StableId("independent-sibling"),
            )
            self.auth.revoke_family(
                authority, root.bearer_token, child.capability.capability_id,
                idempotency_key=StableId("independent-family-revoke"),
            )

        with self.open_reader() as authority:
            states = dict(authority.connection.execute(
                "SELECT capability_id, revoked FROM capabilities WHERE capability_id IN (?, ?, ?, ?) ",
                (str(root.capability.capability_id), str(child.capability.capability_id),
                 str(grandchild.capability.capability_id), str(sibling.capability.capability_id)),
            ).fetchall())
        self.assertEqual(states, {
            str(root.capability.capability_id): 0,
            str(child.capability.capability_id): 1,
            str(grandchild.capability.capability_id): 1,
            str(sibling.capability.capability_id): 0,
        })
        after_revoke = self.logical_dump()
        for token, marker in ((child.bearer_token, "revoked-child"),
                              (grandchild.bearer_token, "revoked-grandchild")):
            with self.assertRaises(AuthenticationFailedError):
                with self.open_writer() as authority:
                    self.auth.execute(authority, token, self.probe(WORK_SCOPE, marker),
                                      idempotency_key=StableId("independent-" + marker))
            self.assertEqual(self.logical_dump(), after_revoke)

        with self.open_writer() as authority:
            sibling_result = self.auth.execute(
                authority, sibling.bearer_token, self.probe(WORK_SCOPE, "sibling-still-live"),
                idempotency_key=StableId("independent-sibling-live"),
            )
            root_result = self.auth.execute(
                authority, root.bearer_token, self.probe(PROJECT_SCOPE, "parent-still-live"),
                idempotency_key=StableId("independent-parent-live"),
            )
        self.assertEqual(sibling_result.receipt.actor, sibling.capability.actor)
        self.assertEqual(root_result.receipt.actor, root.capability.actor)


if __name__ == "__main__":
    unittest.main()
