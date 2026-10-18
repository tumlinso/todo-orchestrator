"""Local actor authentication and transactional, revocable capabilities.

The service accepts credentials and bearer tokens, never caller-supplied Actor
objects or role labels. It is a local authority boundary: callers that can
construct the trusted service composition or call CommandDispatcher.execute
directly are trusted engine code, not remote clients.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
import sqlite3
from typing import Protocol
from uuid import uuid4

from todo_orchestrator.contracts import (
    ActorKind, Capability, EntityKind, EntityRef, Project, StableId,
)
from todo_orchestrator.model import CommandEffect, CommandEnvelope, CommandResult

from .commands import CommandDispatcher, MutationContext
from .scopes import scope_covers as _scope_covers
from .sqlite import AuthorityError, SQLiteAuthority


LOCAL_OWNER_SCRYPT_N = 1 << 14
LOCAL_OWNER_SCRYPT_R = 8
LOCAL_OWNER_SCRYPT_P = 1
_OWNER_ACTIONS = (StableId("todo.capability.delegate"), StableId("todo.capability.revoke"))


class AuthorizationError(AuthorityError):
    """Base for authentication and capability refusals."""


class AuthenticationFailedError(AuthorizationError):
    """A credential or capability token is unknown, invalid, or no longer valid."""


class CapabilityDeniedError(AuthorizationError):
    """A valid capability does not grant the requested action, scope, or context."""


class OwnerAlreadyEnrolledError(AuthorizationError):
    """The one-time local owner enrollment has already been used."""


class OwnerEnrollmentNotAllowedError(AuthorizationError):
    """Local owner enrollment is only available before the first actor exists."""


class AuthenticationProviderUnavailableError(AuthorizationError):
    """Delegation requires a configured trusted principal authenticator."""


class CapabilityDeliveryUncertainError(RuntimeError):
    """A durable issuance receipt exists, but its one-time bearer cannot be recovered."""

    def __init__(self, receipt) -> None:
        self.receipt = receipt
        super().__init__(
            "capability issuance was already committed; the one-time bearer was not retained"
        )


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Identity returned by a trusted, service-injected host authenticator."""

    subject_id: str
    kind: ActorKind
    label: str

    def __post_init__(self) -> None:
        _nonempty(self.subject_id, "subject_id")
        _nonempty(self.label, "label")
        if not isinstance(self.kind, ActorKind):
            raise TypeError("kind must be an ActorKind supplied by the trusted authenticator")


class PrincipalAuthenticator(Protocol):
    """Trusted composition seam; callers submit credentials, not this identity value."""

    provider_id: str

    def authenticate(self, credential: object) -> AuthenticatedPrincipal | None:
        """Return a provider-authenticated principal, or None for refusal."""


@dataclass(frozen=True)
class AuthorizationRequirement:
    """Trusted handler-derived action and resource context for one command."""

    action: StableId
    scope: EntityRef
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    attempt: EntityRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, StableId):
            raise TypeError("action must be a StableId")
        if not isinstance(self.scope, EntityRef):
            raise TypeError("scope must be an EntityRef")
        for value, kind, name in (
            (self.run, EntityKind.RUN, "run"),
            (self.assignment, EntityKind.ASSIGNMENT, "assignment"),
            (self.attempt, EntityKind.ATTEMPT, "attempt"),
        ):
            if value is not None and (value.kind is not kind or value.project_id != self.scope.project_id):
                raise ValueError(f"{name} must be a project-local {kind.value} reference")


@dataclass(frozen=True)
class IssuedCapability:
    """One-time bearer delivery plus the durable, non-secret grant receipt."""

    capability: Capability
    bearer_token: str = field(repr=False)
    receipt: object


@dataclass(frozen=True)
class _EnrollOwner:
    actor_id: StableId
    incarnation_id: StableId
    label: str
    salt: bytes = field(repr=False)
    password_digest: bytes = field(repr=False)


@dataclass(frozen=True)
class _IssueOwnerCapability:
    capability_id: StableId
    actor_id: StableId
    incarnation_id: StableId
    label: str
    scope: EntityRef
    actions: tuple[StableId, ...]
    run: EntityRef | None
    assignment: EntityRef | None
    attempt: EntityRef | None
    expires_at: datetime
    token_digest: str = field(repr=False)


@dataclass(frozen=True)
class _DelegateCapability:
    parent_capability_id: StableId
    provider_id: str
    child_actor_id: StableId
    child_incarnation_id: StableId
    child_kind: ActorKind
    child_label: str
    capability_id: StableId
    scope: EntityRef
    actions: tuple[StableId, ...]
    run: EntityRef | None
    assignment: EntityRef | None
    attempt: EntityRef | None
    expires_at: datetime
    token_digest: str = field(repr=False)


@dataclass(frozen=True)
class _RevokeCapabilityFamily:
    requester_capability_id: StableId
    target_capability_id: StableId
    expected_scope: EntityRef
    expected_run: EntityRef | None
    expected_assignment: EntityRef | None
    expected_attempt: EntityRef | None


def _nonempty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be non-empty text without surrounding whitespace")


def _id(value: StableId | str, name: str) -> StableId:
    if isinstance(value, StableId):
        return value
    raise TypeError(f"{name} must be a StableId")


def _unique_actions(actions: Sequence[StableId]) -> tuple[StableId, ...]:
    result = tuple(actions)
    if not result or any(not isinstance(action, StableId) for action in result):
        raise ValueError("actions must be a non-empty sequence of StableId values")
    if len(set(result)) != len(result):
        raise ValueError("actions must not contain duplicates")
    return result


def _aware(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware(value, "timestamp").isoformat(timespec="microseconds")


def _new_id(prefix: str) -> StableId:
    return StableId(f"{prefix}-{uuid4().hex}")


def _bearer() -> str:
    return secrets.token_urlsafe(32)


def _token_digest(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise AuthenticationFailedError("invalid bearer token")
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AuthenticationFailedError("invalid bearer token") from exc
    return hashlib.sha256(encoded).hexdigest()


def _password_bytes(credential: str) -> bytes:
    if not isinstance(credential, str):
        raise TypeError("local owner credential must be text")
    encoded = credential.encode("utf-8")
    if len(encoded) < 12 or len(encoded) > 1024:
        raise ValueError("local owner credential must contain 12 to 1024 UTF-8 bytes")
    return encoded


def _scrypt(password: bytes, salt: bytes, n: int = LOCAL_OWNER_SCRYPT_N,
            r: int = LOCAL_OWNER_SCRYPT_R, p: int = LOCAL_OWNER_SCRYPT_P) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)


def _scope_parts(scope: EntityRef) -> tuple[str, str, str | None, str | None]:
    return (
        scope.kind.value,
        str(scope.entity_id),
        str(scope.definition_revision_id) if scope.definition_revision_id is not None else None,
        str(scope.incarnation_id) if scope.incarnation_id is not None else None,
    )


def _scope_payload(scope: EntityRef) -> dict[str, str | None]:
    kind, entity_id, definition, incarnation = _scope_parts(scope)
    return {"kind": kind, "entity_id": entity_id, "definition_revision_id": definition,
            "incarnation_id": incarnation}


def _context_payload(run: EntityRef | None, assignment: EntityRef | None,
                     attempt: EntityRef | None) -> dict[str, str | None]:
    return {
        "run_id": str(run.entity_id) if run else None,
        "assignment_id": str(assignment.entity_id) if assignment else None,
        "attempt_id": str(attempt.entity_id) if attempt else None,
    }


def _context_ids(run: EntityRef | None, assignment: EntityRef | None,
                 attempt: EntityRef | None) -> tuple[str | None, str | None, str | None]:
    return tuple(str(value.entity_id) if value is not None else None
                 for value in (run, assignment, attempt))  # type: ignore[return-value]


def _validate_grant(project: Project, scope: EntityRef, actions: tuple[StableId, ...],
                    run: EntityRef | None, assignment: EntityRef | None,
                    attempt: EntityRef | None, expires_at: datetime, now: datetime) -> None:
    if scope.project_id != project.project_id:
        raise ValueError("capability scope belongs to a different project")
    for value, kind, name in (
        (run, EntityKind.RUN, "run"),
        (assignment, EntityKind.ASSIGNMENT, "assignment"),
        (attempt, EntityKind.ATTEMPT, "attempt"),
    ):
        if value is not None and (value.kind is not kind or value.project_id != project.project_id):
            raise ValueError(f"{name} must be a project-local {kind.value} reference")
    if _aware(expires_at, "expires_at") <= _aware(now, "current time"):
        raise ValueError("expires_at must be in the future")
    if not actions:
        raise ValueError("a capability must grant at least one action")


def _scope_from_row(project: Project, row: sqlite3.Row) -> EntityRef:
    try:
        kind = EntityKind(row["scope_kind"])
        return EntityRef(
            project.project_id, kind, StableId(row["scope_entity_id"]),
            definition_revision_id=(StableId(row["scope_definition_revision_id"])
                                    if row["scope_definition_revision_id"] is not None else None),
            incarnation_id=(StableId(row["scope_incarnation_id"])
                            if row["scope_incarnation_id"] is not None else None),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationError("stored capability scope is invalid") from exc


def _context_from_row(project: Project, row: sqlite3.Row) -> tuple[EntityRef | None, EntityRef | None, EntityRef | None]:
    kinds = (EntityKind.RUN, EntityKind.ASSIGNMENT, EntityKind.ATTEMPT)
    names = ("run_id", "assignment_id", "attempt_id")
    values = []
    for kind, name in zip(kinds, names):
        value = row[name]
        values.append(EntityRef(project.project_id, kind, StableId(value)) if value is not None else None)
    return tuple(values)  # type: ignore[return-value]


def _actor_ref(project: Project, actor_id: str, incarnation_id: str) -> EntityRef:
    return EntityRef(project.project_id, EntityKind.ACTOR, StableId(actor_id),
                     incarnation_id=StableId(incarnation_id))


def _capability_from_values(project: Project, capability_id: StableId, actor: EntityRef,
                            scope: EntityRef, actions: tuple[StableId, ...],
                            run: EntityRef | None, assignment: EntityRef | None,
                            attempt: EntityRef | None, expires_at: datetime,
                            parent_id: StableId | None = None) -> Capability:
    return Capability(capability_id, project.project_id, actor, scope, actions,
                      run, assignment, attempt, expires_at,
                      EntityRef(project.project_id, EntityKind.CAPABILITY, parent_id)
                      if parent_id is not None else None)


def _insert_capability(context: MutationContext, *, capability_id: StableId, actor_id: StableId,
                       incarnation_id: StableId, parent_id: StableId | None, scope: EntityRef,
                       actions: tuple[StableId, ...], run: EntityRef | None,
                       assignment: EntityRef | None, attempt: EntityRef | None,
                       expires_at: datetime, token_digest: str) -> None:
    scope_kind, scope_id, definition_id, scope_incarnation_id = _scope_parts(scope)
    run_id, assignment_id, attempt_id = _context_ids(run, assignment, attempt)
    context.execute(
        "INSERT INTO capabilities(capability_id, actor_id, actor_incarnation_id, parent_capability_id, "
        "scope_kind, scope_entity_id, scope_definition_revision_id, scope_incarnation_id, run_id, "
        "assignment_id, attempt_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(capability_id), str(actor_id), str(incarnation_id), str(parent_id) if parent_id else None,
         scope_kind, scope_id, definition_id, scope_incarnation_id, run_id, assignment_id,
         attempt_id, _iso(expires_at)),
    )
    context.execute("INSERT INTO capability_tokens(capability_id, token_digest) VALUES (?, ?)",
                    (str(capability_id), token_digest))
    for ordinal, action in enumerate(actions):
        context.execute(
            "INSERT INTO capability_actions(capability_id, action_ordinal, action) VALUES (?, ?, ?)",
            (str(capability_id), ordinal, str(action)),
        )


def _stored_capability(connection: sqlite3.Connection, capability_id: StableId) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT c.*, t.token_digest FROM capabilities AS c "
        "LEFT JOIN capability_tokens AS t USING (capability_id) WHERE c.capability_id = ?",
        (str(capability_id),),
    ).fetchone()


def _stored_actions(connection: sqlite3.Connection, capability_id: StableId) -> tuple[StableId, ...]:
    rows = connection.execute(
        "SELECT action FROM capability_actions WHERE capability_id = ? ORDER BY action_ordinal",
        (str(capability_id),),
    ).fetchall()
    return tuple(StableId(row[0]) for row in rows)


def _context_covers(grant: tuple[EntityRef | None, ...], target: tuple[EntityRef | None, ...]) -> bool:
    return all(granted is None or granted == required
               for granted, required in zip(grant, target))


def _strictly_narrower(parent: sqlite3.Row, parent_scope: EntityRef,
                       parent_actions: tuple[StableId, ...], child_scope: EntityRef,
                       child_actions: tuple[StableId, ...], child_context: tuple[EntityRef | None, ...],
                       child_expiry: datetime) -> bool:
    parent_context_ids = (parent["run_id"], parent["assignment_id"], parent["attempt_id"])
    child_context_ids = tuple(str(item.entity_id) if item is not None else None for item in child_context)
    parent_expiry = datetime.fromisoformat(parent["expires_at"]) if parent["expires_at"] else None
    context_subset = all(before is None or before == after
                         for before, after in zip(parent_context_ids, child_context_ids))
    strict_context = parent_context_ids != child_context_ids
    expiry_subset = parent_expiry is None or (child_expiry <= parent_expiry)
    strict_expiry = parent_expiry is None or child_expiry < parent_expiry
    action_subset = set(child_actions) <= set(parent_actions)
    scope_subset = _scope_covers(parent_scope, child_scope)
    strict_scope = parent_scope != child_scope
    return (
        context_subset and expiry_subset and action_subset and scope_subset
        and (set(child_actions) < set(parent_actions) or strict_scope or strict_context or strict_expiry)
    )


def _family_contains(connection: sqlite3.Connection, parent_id: StableId, target_id: StableId) -> bool:
    return connection.execute(
        "WITH RECURSIVE descendants(capability_id) AS ("
        " SELECT capability_id FROM capabilities WHERE capability_id = ?"
        " UNION SELECT child.capability_id FROM capabilities AS child"
        " JOIN descendants AS parent ON child.parent_capability_id = parent.capability_id)"
        " SELECT 1 FROM descendants WHERE capability_id = ? LIMIT 1",
        (str(parent_id), str(target_id)),
    ).fetchone() is not None


class _EnrollOwnerHandler:
    kind = "authority.local_owner.enroll"
    command_type = _EnrollOwner
    allows_unregistered_actor = True

    def canonical_payload(self, command: _EnrollOwner) -> dict[str, object]:
        return {"actor_id": str(command.actor_id), "incarnation_id": str(command.incarnation_id),
                "label": command.label, "credential_scheme": "scrypt-16384-8-1"}

    def apply(self, context: MutationContext, command: _EnrollOwner) -> CommandEffect:
        context.execute("INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                        (str(command.actor_id), str(command.incarnation_id), ActorKind.HUMAN.value, command.label))
        context.execute(
            "INSERT INTO local_owner_credentials(singleton, actor_id, bootstrap_incarnation_id, salt, "
            "password_digest, scrypt_n, scrypt_r, scrypt_p) VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
            (str(command.actor_id), str(command.incarnation_id), command.salt, command.password_digest,
             LOCAL_OWNER_SCRYPT_N, LOCAL_OWNER_SCRYPT_R, LOCAL_OWNER_SCRYPT_P),
        )
        actor = str(command.actor_id)
        incarnation = str(command.incarnation_id)
        return CommandEffect(
            True, {"actor_id": actor, "incarnation_id": incarnation},
            "authority.local_owner.enrolled",
            {"actor_id": actor, "incarnation_id": incarnation, "kind": "human", "label": command.label},
        )


class _IssueOwnerCapabilityHandler:
    kind = "authority.capability.issue_owner"
    command_type = _IssueOwnerCapability

    def canonical_payload(self, command: _IssueOwnerCapability) -> dict[str, object]:
        return {
            "actor_id": str(command.actor_id), "label": command.label,
            "scope": _scope_payload(command.scope), "actions": [str(a) for a in command.actions],
            **_context_payload(command.run, command.assignment, command.attempt),
            "expires_at": _iso(command.expires_at),
        }

    def apply(self, context: MutationContext, command: _IssueOwnerCapability) -> CommandEffect:
        context.execute("INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                        (str(command.actor_id), str(command.incarnation_id), ActorKind.HUMAN.value, command.label))
        _insert_capability(context, capability_id=command.capability_id, actor_id=command.actor_id,
                           incarnation_id=command.incarnation_id, parent_id=None, scope=command.scope,
                           actions=command.actions, run=command.run, assignment=command.assignment,
                           attempt=command.attempt, expires_at=command.expires_at,
                           token_digest=command.token_digest)
        return CommandEffect(
            True, {"capability_id": str(command.capability_id), "actor_id": str(command.actor_id),
                   "incarnation_id": str(command.incarnation_id)},
            "authority.capability.issued",
            {"capability_id": str(command.capability_id), "actor_id": str(command.actor_id),
             "incarnation_id": str(command.incarnation_id), "parent_capability_id": None},
        )


class _DelegateCapabilityHandler:
    kind = "authority.capability.delegate"
    command_type = _DelegateCapability

    def authorization_requirement(self, command: _DelegateCapability) -> AuthorizationRequirement:
        return AuthorizationRequirement(StableId("todo.capability.delegate"), command.scope,
                                        command.run, command.assignment, command.attempt)

    def canonical_payload(self, command: _DelegateCapability) -> dict[str, object]:
        return {
            "parent_capability_id": str(command.parent_capability_id),
            "provider_id": command.provider_id, "child_actor_id": str(command.child_actor_id),
            "child_kind": command.child_kind.value, "child_label": command.child_label,
            "scope": _scope_payload(command.scope), "actions": [str(a) for a in command.actions],
            **_context_payload(command.run, command.assignment, command.attempt),
            "expires_at": _iso(command.expires_at),
        }

    def apply(self, context: MutationContext, command: _DelegateCapability) -> CommandEffect:
        connection = context._connection
        parent = _stored_capability(connection, command.parent_capability_id)
        if parent is None or parent["revoked"]:
            raise CapabilityDeniedError("parent capability is unavailable")
        parent_scope = _scope_from_row(context.project, parent)
        parent_actions = _stored_actions(connection, command.parent_capability_id)
        child_context = (command.run, command.assignment, command.attempt)
        if command.child_actor_id == StableId(parent["actor_id"]):
            raise CapabilityDeniedError("a capability cannot be delegated to its owning actor")
        if not _strictly_narrower(parent, parent_scope, parent_actions, command.scope,
                                  command.actions, child_context, command.expires_at):
            raise CapabilityDeniedError("child capability must be a strict subset of its parent")
        prior_kind = connection.execute("SELECT kind FROM actors WHERE actor_id = ? LIMIT 1",
                                        (str(command.child_actor_id),)).fetchone()
        if prior_kind is not None and prior_kind[0] != command.child_kind.value:
            raise CapabilityDeniedError("trusted principal kind changed for an existing actor")
        context.execute("INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                        (str(command.child_actor_id), str(command.child_incarnation_id),
                         command.child_kind.value, command.child_label))
        _insert_capability(context, capability_id=command.capability_id,
                           actor_id=command.child_actor_id, incarnation_id=command.child_incarnation_id,
                           parent_id=command.parent_capability_id, scope=command.scope,
                           actions=command.actions, run=command.run, assignment=command.assignment,
                           attempt=command.attempt, expires_at=command.expires_at,
                           token_digest=command.token_digest)
        return CommandEffect(
            True, {"capability_id": str(command.capability_id), "actor_id": str(command.child_actor_id),
                   "incarnation_id": str(command.child_incarnation_id),
                   "parent_capability_id": str(command.parent_capability_id)},
            "authority.capability.delegated",
            {"capability_id": str(command.capability_id), "actor_id": str(command.child_actor_id),
             "incarnation_id": str(command.child_incarnation_id),
             "parent_capability_id": str(command.parent_capability_id),
             "provider_id": command.provider_id},
        )


class _RevokeCapabilityHandler:
    kind = "authority.capability.revoke_family"
    command_type = _RevokeCapabilityFamily

    def authorization_requirement(self, command: _RevokeCapabilityFamily) -> AuthorizationRequirement:
        return AuthorizationRequirement(StableId("todo.capability.revoke"), command.expected_scope,
                                        command.expected_run, command.expected_assignment,
                                        command.expected_attempt)

    def canonical_payload(self, command: _RevokeCapabilityFamily) -> dict[str, object]:
        return {"requester_capability_id": str(command.requester_capability_id),
                "target_capability_id": str(command.target_capability_id)}

    def apply(self, context: MutationContext, command: _RevokeCapabilityFamily) -> CommandEffect:
        connection = context._connection
        target = _stored_capability(connection, command.target_capability_id)
        parent = _stored_capability(connection, command.requester_capability_id)
        if target is None or parent is None or not _family_contains(
            connection, command.requester_capability_id, command.target_capability_id
        ):
            raise CapabilityDeniedError("target capability is outside the caller's grant family")
        if (_scope_from_row(context.project, target) != command.expected_scope
                or _context_from_row(context.project, target) != (
                    command.expected_run, command.expected_assignment, command.expected_attempt
                )):
            raise CapabilityDeniedError("target capability changed during revocation")
        before_changes = connection.total_changes
        connection.execute(
            "WITH RECURSIVE descendants(capability_id) AS ("
            " SELECT capability_id FROM capabilities WHERE capability_id = ?"
            " UNION SELECT child.capability_id FROM capabilities AS child"
            " JOIN descendants AS parent ON child.parent_capability_id = parent.capability_id)"
            " UPDATE capabilities SET revoked = 1 WHERE revoked = 0"
            " AND capability_id IN (SELECT capability_id FROM descendants)",
            (str(command.target_capability_id),),
        )
        changed = connection.total_changes - before_changes
        return CommandEffect(
            bool(changed), {"target_capability_id": str(command.target_capability_id),
                            "revoked_count": changed},
            "authority.capability.family_revoked" if changed else None,
            {"target_capability_id": str(command.target_capability_id),
             "revoked_count": changed} if changed else None,
        )


class AuthorityAuthService:
    """Public credential boundary for local owner grants and scoped commands."""

    def __init__(self, dispatcher: CommandDispatcher, *,
                 clock: Callable[[], datetime] | None = None,
                 authenticator: PrincipalAuthenticator | None = None) -> None:
        if not isinstance(dispatcher, CommandDispatcher):
            raise TypeError("dispatcher must be a CommandDispatcher")
        self.dispatcher = dispatcher
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.authenticator = authenticator
        for handler in (_EnrollOwnerHandler(), _IssueOwnerCapabilityHandler(),
                        _DelegateCapabilityHandler(), _RevokeCapabilityHandler()):
            self.dispatcher.register(handler)

    def _now(self) -> datetime:
        return _aware(self.clock(), "clock value")

    @staticmethod
    def _revision(authority: SQLiteAuthority, expected_revision: int | None) -> int:
        if expected_revision is not None:
            if type(expected_revision) is not int or expected_revision < 0:
                raise ValueError("expected_revision must be a non-negative integer")
            return expected_revision
        with authority.read_transaction() as connection:
            row = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
        if row is None:
            raise AuthorizationError("authority revision is unavailable")
        return row[0]

    @staticmethod
    def _scope(authority: SQLiteAuthority, scope: EntityRef | None) -> EntityRef:
        result = scope or EntityRef(authority.project.project_id, EntityKind.PROJECT,
                                    authority.project.project_id)
        if not isinstance(result, EntityRef) or result.project_id != authority.project.project_id:
            raise ValueError("scope must be a typed reference in this authority's project")
        return result

    def enroll_local_owner(self, authority: SQLiteAuthority, credential: str, *, label: str,
                           idempotency_key: StableId, expected_revision: int | None = None) -> CommandResult:
        """Create the first human owner atomically; local write access is the bootstrap trust boundary."""
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        _nonempty(label, "label")
        password = _password_bytes(credential)
        salt = secrets.token_bytes(16)
        digest = _scrypt(password, salt)
        actor_id, incarnation_id = _new_id("actor"), _new_id("inc")
        with authority.read_transaction() as connection:
            if connection.execute("SELECT 1 FROM local_owner_credentials").fetchone() is not None:
                raise OwnerAlreadyEnrolledError("a local owner is already enrolled")
            if connection.execute("SELECT 1 FROM actors LIMIT 1").fetchone() is not None:
                raise OwnerEnrollmentNotAllowedError("local owner enrollment is closed after the first actor")
        command = _EnrollOwner(actor_id, incarnation_id, label, salt, digest)
        envelope = CommandEnvelope(command, _id(idempotency_key, "idempotency_key"),
                                   self._revision(authority, expected_revision),
                                   _actor_ref(authority.project, str(actor_id), str(incarnation_id)))
        return self.dispatcher.execute(authority, envelope)

    def login_local_owner(self, authority: SQLiteAuthority, credential: str, *,
                          actions: Sequence[StableId] = _OWNER_ACTIONS,
                          scope: EntityRef | None = None,
                          run: EntityRef | None = None, assignment: EntityRef | None = None,
                          attempt: EntityRef | None = None, expires_at: datetime,
                          idempotency_key: StableId, expected_revision: int | None = None) -> IssuedCapability:
        password = _password_bytes(credential)
        action_set = _unique_actions(actions)
        target_scope = self._scope(authority, scope)
        expiry = _aware(expires_at, "expires_at")
        _validate_grant(authority.project, target_scope, action_set, run, assignment, attempt,
                        expiry, self._now())
        with authority.read_transaction() as connection:
            owner = connection.execute("SELECT actor_id, bootstrap_incarnation_id FROM local_owner_credentials "
                                        "WHERE singleton = 1").fetchone()
        if owner is None:
            raise AuthenticationFailedError("local owner credential is not enrolled")
        actor_id = StableId(owner["actor_id"])
        bootstrap_actor = _actor_ref(authority.project, owner["actor_id"], owner["bootstrap_incarnation_id"])
        incarnation_id, capability_id = _new_id("inc"), _new_id("cap")
        token = _bearer()
        command = _IssueOwnerCapability(capability_id, actor_id, incarnation_id,
                                        self._owner_label(authority, actor_id), target_scope,
                                        action_set, run, assignment, attempt, expiry, _token_digest(token))
        envelope = CommandEnvelope(command, _id(idempotency_key, "idempotency_key"),
                                   self._revision(authority, expected_revision), bootstrap_actor)

        def check(connection: sqlite3.Connection, snapshot: object, _handler: object,
                  actor: EntityRef) -> None:
            row = connection.execute("SELECT * FROM local_owner_credentials WHERE singleton = 1").fetchone()
            if (row is None or actor.entity_id != StableId(row["actor_id"])
                    or actor.incarnation_id != StableId(row["bootstrap_incarnation_id"])
                    or not hmac.compare_digest(_scrypt(password, row["salt"], row["scrypt_n"],
                                                       row["scrypt_r"], row["scrypt_p"]), row["password_digest"])):
                raise AuthenticationFailedError("local owner authentication failed")
            if snapshot.expires_at <= self._now():
                raise CapabilityDeniedError("requested capability would already be expired")

        result = self.dispatcher._execute_authorized(authority, envelope, check)
        if result.replayed:
            raise CapabilityDeliveryUncertainError(result.receipt)
        actor = _actor_ref(authority.project, str(actor_id), str(incarnation_id))
        return IssuedCapability(
            _capability_from_values(authority.project, capability_id, actor, target_scope,
                                    action_set, run, assignment, attempt, expiry),
            token, result.receipt,
        )

    @staticmethod
    def _owner_label(authority: SQLiteAuthority, actor_id: StableId) -> str:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT actor.label FROM actors AS actor "
                "JOIN local_owner_credentials AS owner "
                "ON owner.actor_id = actor.actor_id "
                "AND owner.bootstrap_incarnation_id = actor.incarnation_id "
                "WHERE owner.singleton = 1 AND owner.actor_id = ?",
                (str(actor_id),),
            ).fetchone()
        if row is None or not isinstance(row[0], str):
            raise AuthenticationFailedError("local owner identity is unavailable")
        return row[0]

    def _actor_for_token(self, authority: SQLiteAuthority, digest: str) -> tuple[EntityRef, StableId]:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT c.actor_id, c.actor_incarnation_id, c.capability_id FROM capability_tokens AS t "
                "JOIN capabilities AS c USING (capability_id) WHERE t.token_digest = ?", (digest,)
            ).fetchone()
        if row is None:
            raise AuthenticationFailedError("bearer token is unknown")
        return (_actor_ref(authority.project, row["actor_id"], row["actor_incarnation_id"]),
                StableId(row["capability_id"]))

    def _authorize_capability(self, connection: sqlite3.Connection, project: Project, digest: str,
                              actor: EntityRef, requirement: AuthorizationRequirement) -> StableId:
        row = connection.execute(
            "SELECT c.* FROM capability_tokens AS t JOIN capabilities AS c USING (capability_id) "
            "WHERE t.token_digest = ?", (digest,)
        ).fetchone()
        if row is None or row["revoked"]:
            raise AuthenticationFailedError("bearer token is revoked or unknown")
        if (actor.project_id != project.project_id or actor.entity_id != StableId(row["actor_id"])
                or actor.incarnation_id != StableId(row["actor_incarnation_id"])):
            raise AuthenticationFailedError("bearer token identity does not match its actor incarnation")
        if row["expires_at"] is not None and datetime.fromisoformat(row["expires_at"]) <= self._now():
            raise AuthenticationFailedError("bearer token has expired")
        scope = _scope_from_row(project, row)
        if not _scope_covers(scope, requirement.scope):
            raise CapabilityDeniedError("capability does not cover the requested scope")
        run, assignment, attempt = _context_from_row(project, row)
        if not _context_covers((run, assignment, attempt),
                               (requirement.run, requirement.assignment, requirement.attempt)):
            raise CapabilityDeniedError("capability does not cover the requested run or attempt context")
        if requirement.action not in _stored_actions(connection, StableId(row["capability_id"])):
            raise CapabilityDeniedError("capability does not grant the requested action")
        return StableId(row["capability_id"])

    def execute(self, authority: SQLiteAuthority, bearer_token: str, command: object, *,
                idempotency_key: StableId, expected_revision: int | None = None) -> CommandResult:
        """Dispatch a registered command under its trusted handler-derived requirement."""
        digest = _token_digest(bearer_token)
        actor, _ = self._actor_for_token(authority, digest)
        envelope = CommandEnvelope(command, _id(idempotency_key, "idempotency_key"),
                                   self._revision(authority, expected_revision), actor)

        def check(connection: sqlite3.Connection, snapshot: object, handler: object,
                  current_actor: EntityRef) -> None:
            method = getattr(handler, "authorization_requirement", None)
            if not callable(method):
                raise CapabilityDeniedError("command handler does not declare an authorization requirement")
            requirement = method(snapshot)
            if not isinstance(requirement, AuthorizationRequirement):
                raise CapabilityDeniedError("command handler returned an invalid authorization requirement")
            self._authorize_capability(connection, authority.project, digest, current_actor, requirement)

        return self.dispatcher._execute_authorized(authority, envelope, check)

    def delegate(self, authority: SQLiteAuthority, bearer_token: str, child_credential: object, *,
                 actions: Sequence[StableId], scope: EntityRef,
                 run: EntityRef | None = None, assignment: EntityRef | None = None,
                 attempt: EntityRef | None = None, expires_at: datetime,
                 idempotency_key: StableId, expected_revision: int | None = None) -> IssuedCapability:
        if self.authenticator is None:
            raise AuthenticationProviderUnavailableError("delegation requires an injected trusted authenticator")
        principal = self.authenticator.authenticate(child_credential)
        if principal is None or not isinstance(principal, AuthenticatedPrincipal):
            raise AuthenticationFailedError("trusted authenticator refused the child principal")
        provider_id = getattr(self.authenticator, "provider_id", None)
        _nonempty(provider_id, "authenticator.provider_id")
        if not isinstance(scope, EntityRef) or scope.project_id != authority.project.project_id:
            raise ValueError("scope must be a typed reference in this authority's project")
        action_set = _unique_actions(actions)
        expiry = _aware(expires_at, "expires_at")
        _validate_grant(authority.project, scope, action_set, run, assignment, attempt,
                        expiry, self._now())
        parent_digest = _token_digest(bearer_token)
        parent_actor, parent_id = self._actor_for_token(authority, parent_digest)
        if parent_actor.entity_id == self._principal_actor_id(authority.project, provider_id, principal.subject_id):
            raise CapabilityDeniedError("a capability cannot be delegated back to its owning actor")
        child_actor_id = self._principal_actor_id(authority.project, provider_id, principal.subject_id)
        capability_id, incarnation_id = _new_id("cap"), _new_id("inc")
        token = _bearer()
        command = _DelegateCapability(
            parent_id, provider_id, child_actor_id, incarnation_id, principal.kind,
            principal.label, capability_id, scope, action_set, run, assignment, attempt,
            expiry, _token_digest(token),
        )
        envelope = CommandEnvelope(command, _id(idempotency_key, "idempotency_key"),
                                   self._revision(authority, expected_revision), parent_actor)

        def check(connection: sqlite3.Connection, snapshot: object, handler: object,
                  actor: EntityRef) -> None:
            requirement = handler.authorization_requirement(snapshot)
            parent_id = self._authorize_capability(connection, authority.project, parent_digest, actor, requirement)
            if parent_id != snapshot.parent_capability_id:
                raise AuthenticationFailedError("bearer token does not identify the requested parent capability")
            if snapshot.expires_at <= self._now():
                raise CapabilityDeniedError("requested child capability would already be expired")

        result = self.dispatcher._execute_authorized(authority, envelope, check)
        if result.replayed:
            raise CapabilityDeliveryUncertainError(result.receipt)
        child_actor = _actor_ref(authority.project, str(child_actor_id), str(incarnation_id))
        return IssuedCapability(
            _capability_from_values(authority.project, capability_id, child_actor, scope,
                                    action_set, run, assignment, attempt, expiry, parent_id),
            token, result.receipt,
        )

    @staticmethod
    def _principal_actor_id(project: Project, provider_id: str, subject_id: str) -> StableId:
        material = json.dumps(
            [str(project.project_id), provider_id, subject_id], ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        return StableId("actor-" + hashlib.sha256(material).hexdigest())

    def revoke_family(self, authority: SQLiteAuthority, bearer_token: str,
                      target_capability_id: StableId, *, idempotency_key: StableId,
                      expected_revision: int | None = None) -> CommandResult:
        parent_digest = _token_digest(bearer_token)
        actor, requester_id = self._actor_for_token(authority, parent_digest)
        target_id = _id(target_capability_id, "target_capability_id")
        with authority.read_transaction() as connection:
            target = _stored_capability(connection, target_id)
            if target is None:
                raise CapabilityDeniedError("target capability is unknown")
            target_scope = _scope_from_row(authority.project, target)
            target_context = _context_from_row(authority.project, target)
        command = _RevokeCapabilityFamily(requester_id, target_id, target_scope, *target_context)
        envelope = CommandEnvelope(command, _id(idempotency_key, "idempotency_key"),
                                   self._revision(authority, expected_revision), actor)

        def check(connection: sqlite3.Connection, snapshot: object, handler: object,
                  current_actor: EntityRef) -> None:
            current_target = _stored_capability(connection, snapshot.target_capability_id)
            if current_target is None or (
                _scope_from_row(authority.project, current_target) != snapshot.expected_scope
                or _context_from_row(authority.project, current_target) != (
                    snapshot.expected_run, snapshot.expected_assignment, snapshot.expected_attempt
                )
            ):
                raise CapabilityDeniedError("target capability changed before revocation")
            requirement = handler.authorization_requirement(snapshot)
            current_parent_id = self._authorize_capability(
                connection, authority.project, parent_digest, current_actor, requirement
            )
            if current_parent_id != snapshot.requester_capability_id or not _family_contains(
                connection, current_parent_id, snapshot.target_capability_id
            ):
                raise CapabilityDeniedError("target capability is outside the caller's grant family")

        return self.dispatcher._execute_authorized(authority, envelope, check)


__all__ = [
    "AuthenticatedPrincipal", "AuthenticationFailedError",
    "AuthenticationProviderUnavailableError", "AuthorizationError", "AuthorizationRequirement",
    "AuthorityAuthService", "CapabilityDeliveryUncertainError", "CapabilityDeniedError",
    "IssuedCapability", "LOCAL_OWNER_SCRYPT_N", "LOCAL_OWNER_SCRYPT_P", "LOCAL_OWNER_SCRYPT_R",
    "OwnerAlreadyEnrolledError", "OwnerEnrollmentNotAllowedError", "PrincipalAuthenticator",
]
