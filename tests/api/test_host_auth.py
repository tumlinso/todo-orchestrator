"""Trusted host principal sessions use the public facade and attenuate grants."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api import (
    DEFAULT_OWNER_ACTIONS,
    AuthenticatedPrincipal,
    AuthenticationProviderUnavailableError,
    CAPABILITY_DELEGATE_ACTION,
    CAPABILITY_READ_ACTION,
    CAPABILITY_REVOKE_ACTION,
    CapabilityViewV1,
    ProviderComposition,
    TodoApplication,
    TodoAuthenticationError,
)
from todo_orchestrator.authority import (
    CapabilityDeniedError,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.contracts import ActorKind, EntityKind, EntityRef, StableId
from todo_orchestrator.operations.export import AUTHORITY_READ_ACTION


OWNER_CREDENTIAL = "host auth facade fixture owner credential 479"
DELEGATE_ACTION = CAPABILITY_DELEGATE_ACTION
REVOKE_ACTION = CAPABILITY_REVOKE_ACTION


class FixtureAuthenticator:
    provider_id = "project-control-test"

    def authenticate(self, credential: object) -> AuthenticatedPrincipal | None:
        subjects = {"authenticated-user": "human-1", "authenticated-reviewer": "human-2"}
        subject = subjects.get(credential) if isinstance(credential, str) else None
        if subject is None:
            return None
        return AuthenticatedPrincipal(subject, ActorKind.HUMAN, subject)


class HostAuthFacadeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-host-auth-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        self.providers = ProviderComposition(principal_authenticator=FixtureAuthenticator())
        self.project_id = StableId("host-auth-project")
        self.owner_actions = tuple(sorted({
            *DEFAULT_OWNER_ACTIONS, DELEGATE_ACTION, REVOKE_ACTION, CAPABILITY_READ_ACTION,
        }))

    def initialize(self):
        return TodoApplication.initialize(
            self.root,
            project_id=self.project_id,
            repository_id=StableId("host-auth-repository"),
            authority_id=StableId("host-auth-authority"),
            owner_credential=OWNER_CREDENTIAL,
            owner_actions=self.owner_actions,
            providers=self.providers,
        )

    def work_scope(self, session):
        return EntityRef(
            session.project.project_id,
            EntityKind.WORK_ITEM,
            StableId("host-auth-work"),
            definition_revision_id=StableId("host-auth-work-rev"),
        )

    def test_host_principal_session_is_attenuated_and_secret_stays_private(self):
        clock = [datetime.now(timezone.utc)]
        providers = ProviderComposition(
            principal_authenticator=FixtureAuthenticator(),
            clock=lambda: clock[0],
        )
        self.providers = providers
        with self.initialize() as owner:
            issued = owner.delegate_principal(
                "authenticated-user",
                scope=self.work_scope(owner),
                actions=(AUTHORITY_READ_ACTION, CAPABILITY_READ_ACTION, DELEGATE_ACTION),
                expires_at=clock[0] + timedelta(minutes=5),
                idempotency_key=StableId("host-auth-session-1"),
            )
            token = issued.bearer_token
            self.assertNotIn(token, repr(issued))
            self.assertNotIn(token, owner.serialize("issued-capability", issued))

            view = owner.read_capability(issued.capability.capability_id)
            self.assertIsInstance(view, CapabilityViewV1)
            self.assertFalse(view.revoked)
            self.assertEqual(view.capability.scope, self.work_scope(owner))
            self.assertNotIn(token, owner.serialize("capability-view", view))
            unrelated = owner.delegate_principal(
                "authenticated-reviewer",
                scope=owner.project.ref,
                actions=(AUTHORITY_READ_ACTION,),
                expires_at=clock[0] + timedelta(minutes=5),
                idempotency_key=StableId("host-auth-unrelated-capability"),
            )

            with TodoApplication.open(self.root, bearer_token=token, providers=providers) as worker:
                own_view = worker.read_capability(issued.capability.capability_id)
                self.assertFalse(own_view.revoked)
                grandchild = worker.delegate_principal(
                    "authenticated-reviewer",
                    scope=self.work_scope(owner),
                    actions=(AUTHORITY_READ_ACTION,),
                    expires_at=clock[0] + timedelta(minutes=2),
                    idempotency_key=StableId("host-auth-grandchild-session"),
                )
                with self.assertRaises(CapabilityDeniedError):
                    worker.read_capability(unrelated.capability.capability_id)
                with self.assertRaises(CapabilityDeniedError):
                    worker.delegate_principal(
                        "authenticated-reviewer",
                        scope=owner.project.ref,
                        actions=(AUTHORITY_READ_ACTION,),
                        expires_at=clock[0] + timedelta(minutes=2),
                        idempotency_key=StableId("host-auth-widen-scope"),
                    )
                with self.assertRaises(CapabilityDeniedError):
                    worker.delegate_principal(
                        "authenticated-reviewer",
                        scope=self.work_scope(owner),
                        actions=(StableId("todo.plan.commit"),),
                        expires_at=clock[0] + timedelta(minutes=2),
                        idempotency_key=StableId("host-auth-widen-actions"),
                    )

            with TodoApplication.open(
                self.root, bearer_token=unrelated.bearer_token, providers=providers,
            ) as read_only_worker:
                with self.assertRaises(CapabilityDeniedError):
                    read_only_worker.read_capability(unrelated.capability.capability_id)

            receipt = owner.revoke_capability(
                issued.capability.capability_id,
                idempotency_key=StableId("host-auth-revoke-worker"),
            )
            self.assertEqual(receipt.command_kind, "authority.capability.revoke_family")
            self.assertTrue(owner.read_capability(issued.capability.capability_id).revoked)
            self.assertTrue(owner.read_capability(grandchild.capability.capability_id).revoked)
            with self.assertRaises(TodoAuthenticationError):
                TodoApplication.open(self.root, bearer_token=token, providers=providers)
            with self.assertRaises(TodoAuthenticationError):
                TodoApplication.open(
                    self.root, bearer_token=grandchild.bearer_token, providers=providers,
                )

    def test_absent_authenticator_forged_identity_and_stale_revision_are_refused(self):
        with self.initialize() as owner:
            bearer = owner.bearer_token
            with self.assertRaises(AuthenticationProviderUnavailableError):
                with TodoApplication.open(
                    self.root, bearer_token=bearer, providers=ProviderComposition(),
                ) as unconfigured:
                    unconfigured.delegate_principal(
                        "authenticated-user", scope=owner.project.ref,
                        actions=(AUTHORITY_READ_ACTION,),
                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
                        idempotency_key=StableId("host-auth-no-provider"),
                    )
            from todo_orchestrator.authority.auth import AuthenticationFailedError
            with self.assertRaises(AuthenticationFailedError):
                owner.delegate_principal(
                    AuthenticatedPrincipal("attacker", ActorKind.HUMAN, "attacker"),
                    scope=owner.project.ref,
                    actions=(AUTHORITY_READ_ACTION,),
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
                    idempotency_key=StableId("host-auth-forged-principal"),
                )

            revision = owner.read_model().semantic_revision
            with self.assertRaises(StaleAuthorityRevisionError):
                owner.delegate_principal(
                    "authenticated-user", scope=owner.project.ref,
                    actions=(AUTHORITY_READ_ACTION,),
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
                    idempotency_key=StableId("host-auth-stale-revision"),
                    expected_revision=max(0, revision - 1),
                )
            self.assertEqual(owner.read_model().semantic_revision, revision)

    def test_provider_composition_rejects_untrusted_or_malformed_authenticator_shape(self):
        with self.assertRaises(TypeError):
            ProviderComposition(principal_authenticator=object())

        class InvalidProviderId:
            provider_id = "  "

            def authenticate(self, credential):
                return None

        with self.assertRaises(ValueError):
            ProviderComposition(principal_authenticator=InvalidProviderId())


if __name__ == "__main__":
    unittest.main()
