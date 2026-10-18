"""Authenticated subordinate executions bounded by a parent attempt.

Child execution records are durable coordination facts, not independent plan,
run, or attempt authorities. Their capability and scope are derived inside the
same writer transaction that records the child execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import sqlite3
from uuid import uuid4

from todo_orchestrator.authority.attempts import (
    AttemptError,
    AttemptHostUnavailableError,
    AttemptObservationMismatchError,
    AttemptService,
    AttemptTransitionError,
    _attempt_from_row,
    _check_observation,
    _iso as _attempt_iso,
    _observation_audit,
    _parse_time,
    _stored_attempt,
    _stored_workspace,
)
from todo_orchestrator.authority.auth import (
    AuthenticatedPrincipal,
    AuthenticationFailedError,
    AuthenticationProviderUnavailableError,
    AuthorizationError,
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeliveryUncertainError,
    CapabilityDeniedError,
    _actor_ref,
    _bearer,
    _capability_from_values,
    _context_from_row,
    _insert_capability,
    _scope_from_row,
    _stored_actions,
    _stored_capability,
    _token_digest,
)
from todo_orchestrator.authority.child_store import (
    decode_child_scope,
    require_parent_children_resolved,
)
from todo_orchestrator.authority.commands import (
    IdempotencyConflictError,
    MutationContext,
    StaleAuthorityRevisionError,
    _authorization_authorizer,
)
from todo_orchestrator.authority.eligibility import _scope_snapshot_payload
from todo_orchestrator.authority.sqlite import AuthorityError, SQLiteAuthority
from todo_orchestrator.contracts import (
    ActorKind,
    AttemptState,
    EntityKind,
    EntityRef,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.model import (
    CHILD_CANDIDATE_SUBMIT_ACTION,
    CHILD_CANCEL_ACTION,
    CHILD_DELEGATE_ACTION,
    CHILD_READ_ACTION,
    CHILD_REVIEW_ACTION,
    CHILD_RETRY_ACTION,
    CHILD_STOP_RECONCILE_ACTION,
    CHILD_WORKER_ACTIONS,
    CHILD_WRITE_ACTION,
    AttemptSafetyObservation,
    AttemptScopeSnapshot,
    ChildActivity,
    ChildArtifactRef,
    ChildCandidate,
    ChildCandidateDecision,
    ChildExecutionGrant,
    ChildExecutionState,
    ChildExecutionView,
    ChildReview,
    CommandEffect,
    ProcessLiveness,
    SourceSafety,
)

from .child_scope import child_scopes_conflict, require_child_scope_subset
from .payloads import PayloadRejectedError, validate_bounded_text


_MAX_CHILD_SUMMARY_BYTES = 4096
_MAX_CHILD_REASON_BYTES = 2048
_TOKEN_CHAR_RUN = re.compile(r"[A-Za-z0-9_-]{32,}")


def _ref_identity_values(ref: EntityRef | None) -> tuple[str, ...]:
    if ref is None:
        return ()
    return (
        str(ref.project_id), ref.kind.value, str(ref.entity_id),
        "" if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "" if ref.incarnation_id is None else str(ref.incarnation_id),
    )


def _validate_structural_values(connection: sqlite3.Connection, values: tuple[str, ...]) -> None:
    """Keep issued bearer material out of durable child identities and receipts."""
    issued_digests = frozenset(
        row[0] for row in connection.execute("SELECT token_digest FROM capability_tokens").fetchall()
    )
    try:
        for value in values:
            if value == "":
                continue
            validate_bounded_text(
                value, field="child identity", max_bytes=1000, connection=connection,
                allow_multiline=False,
            )
            # Stable IDs can embed a bearer with punctuation around it. Scan
            # bounded ASCII runs as context envelopes do, without echoing it.
            for match in _TOKEN_CHAR_RUN.finditer(value):
                token_run = match.group(0)
                for start in range(len(token_run)):
                    for end in range(start + 32, len(token_run) + 1):
                        candidate = token_run[start:end]
                        if hashlib.sha256(candidate.encode("ascii")).hexdigest() in issued_digests:
                            raise PayloadRejectedError("unsafe identity")
    except (PayloadRejectedError, UnicodeError, ValueError) as exc:
        raise ChildExecutionDeniedError("child input contains an unsafe structural identity") from exc


def _validate_scope_identity(connection: sqlite3.Connection, scope: AttemptScopeSnapshot) -> None:
    values = tuple(value for path, access in scope.paths for value in (path, access)) + tuple(
        value for lock, mode in scope.locks for value in (lock, mode)
    )
    _validate_structural_values(connection, values)


class ChildExecutionError(AuthorityError):
    """Base class for subordinate execution service refusals."""


class ChildExecutionNotFoundError(ChildExecutionError):
    """A requested child execution is absent from this authority."""


class ChildExecutionDeniedError(ChildExecutionError):
    """Current authority, parent state, or child bounds refuse the operation."""


class ChildExecutionStateError(ChildExecutionError):
    """The requested child transition is invalid for its current durable state."""


class ChildExecutionObservationError(ChildExecutionError):
    """A provider observation is stale, unsafe, or not bound to current state."""


def _utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value, "timestamp").isoformat(timespec="microseconds")


def _digest_json(encoded: str) -> str:
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _scope_value(scope: AttemptScopeSnapshot) -> dict[str, object]:
    return {"locks": [list(item) for item in sorted(scope.locks)],
            "paths": [list(item) for item in sorted(scope.paths)]}


def _actions_json(actions: tuple[StableId, ...]) -> str:
    return _json([str(value) for value in actions])


def _decode_actions(encoded: object, digest: object) -> tuple[StableId, ...]:
    if not isinstance(encoded, str) or not isinstance(digest, str) or _digest_json(encoded) != digest:
        raise ChildExecutionError("stored child action snapshot is invalid")
    try:
        values = json.loads(encoded)
        if not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values):
            raise ValueError("unexpected child action value")
        actions = tuple(StableId(value) for value in values)
        if len(set(actions)) != len(actions) or _actions_json(actions) != encoded:
            raise ValueError("child action snapshot is not canonical")
        return actions
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ChildExecutionError("stored child action snapshot cannot be decoded") from exc


def _ref_value(ref: EntityRef) -> dict[str, str | None]:
    return {
        "project_id": str(ref.project_id),
        "kind": ref.kind.value,
        "entity_id": str(ref.entity_id),
        "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _artifacts_value(artifacts: tuple[ChildArtifactRef, ...], project_id: StableId) -> list[dict[str, str]]:
    if not isinstance(artifacts, tuple) or any(not isinstance(item, ChildArtifactRef) for item in artifacts):
        raise TypeError("artifacts must be a tuple of ChildArtifactRef values")
    if any(item.ref.project_id != project_id for item in artifacts):
        raise ValueError("child artifact references must belong to this authority project")
    keyed = sorted(artifacts, key=lambda item: (str(item.ref.entity_id), item.digest.hex))
    if len({item.ref for item in keyed}) != len(keyed):
        raise ValueError("child artifact references must be unique")
    return [{"artifact_id": str(item.ref.entity_id), "digest": item.digest.hex} for item in keyed]


def _decode_artifacts(encoded: object, digest: object, project_id: StableId) -> tuple[ChildArtifactRef, ...]:
    if not isinstance(encoded, str) or not isinstance(digest, str) or _digest_json(encoded) != digest:
        raise ChildExecutionError("stored child artifact snapshot is invalid")
    try:
        values = json.loads(encoded)
        if not isinstance(values, list) or any(
            not isinstance(item, dict) or set(item) != {"artifact_id", "digest"}
            or not isinstance(item["artifact_id"], str) or not isinstance(item["digest"], str)
            for item in values
        ):
            raise ValueError("unexpected artifact snapshot fields")
        artifacts = tuple(ChildArtifactRef(
            EntityRef(project_id, EntityKind.ARTIFACT, StableId(item["artifact_id"])),
            Sha256Digest(item["digest"]),
        ) for item in values)
        if _json(_artifacts_value(artifacts, project_id)) != encoded:
            raise ValueError("artifact snapshot is not canonical")
        return artifacts
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ChildExecutionError("stored child artifact snapshot cannot be decoded") from exc


def _child_row(connection: sqlite3.Connection, execution_id: StableId) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT execution.*, capability.expires_at, parent.run_id AS parent_run_id, "
        "parent.assignment_id AS parent_assignment_id "
        "FROM child_executions AS execution "
        "JOIN capabilities AS capability USING(capability_id) "
        "JOIN attempts AS parent ON parent.attempt_id = execution.parent_attempt_id "
        "WHERE execution.execution_id = ?",
        (str(execution_id),),
    ).fetchone()


def _candidate_review(connection: sqlite3.Connection, execution_id: StableId):
    row = connection.execute(
        "SELECT candidate.*, review.review_id, review.decision, review.reviewer_actor_id, "
        "review.reviewer_incarnation_id, review.reason, review.reviewed_at "
        "FROM child_candidates AS candidate LEFT JOIN child_candidate_reviews AS review USING(candidate_id) "
        "WHERE candidate.execution_id = ?",
        (str(execution_id),),
    ).fetchone()
    return row


def _view_from_row(connection: sqlite3.Connection, project_id: StableId, row: sqlite3.Row) -> ChildExecutionView:
    try:
        scope = decode_child_scope(row["scope_json"], row["scope_digest"])
        actions = _decode_actions(row["actions_json"], row["actions_digest"])
        parent_attempt = EntityRef(project_id, EntityKind.ATTEMPT, StableId(row["parent_attempt_id"]))
        target = EntityRef(project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                           definition_revision_id=StableId(row["definition_revision_id"]))
        actor = EntityRef(project_id, EntityKind.ACTOR, StableId(row["child_actor_id"]),
                          incarnation_id=StableId(row["child_incarnation_id"]))
        if row["expires_at"] is None:
            raise ValueError("child capability has no expiry")
        candidate_row = _candidate_review(connection, StableId(row["execution_id"]))
        candidate = None
        review = None
        if candidate_row is not None:
            candidate = ChildCandidate(
                StableId(candidate_row["candidate_id"]), StableId(row["execution_id"]),
                candidate_row["summary"],
                _decode_artifacts(candidate_row["artifacts_json"], candidate_row["artifacts_digest"], project_id),
                EntityRef(project_id, EntityKind.ACTOR, StableId(candidate_row["submitted_by_actor_id"]),
                          incarnation_id=StableId(candidate_row["submitted_by_incarnation_id"])),
                _parse_time(candidate_row["submitted_at"]),
            )
            if candidate_row["review_id"] is not None:
                review = ChildReview(
                    StableId(candidate_row["review_id"]), candidate.candidate_id,
                    ChildCandidateDecision(candidate_row["decision"]),
                    EntityRef(project_id, EntityKind.ACTOR, StableId(candidate_row["reviewer_actor_id"]),
                              incarnation_id=StableId(candidate_row["reviewer_incarnation_id"])),
                    candidate_row["reason"], _parse_time(candidate_row["reviewed_at"]),
                )
        return ChildExecutionView(
            StableId(row["execution_id"]), StableId(row["logical_id"]), row["ordinal"],
            parent_attempt, target, actor, scope, actions, StableId(row["capability_id"]),
            ChildExecutionState(row["state"]), _parse_time(row["created_at"]),
            _parse_time(row["expires_at"]),
            None if row["retry_of_execution_id"] is None else StableId(row["retry_of_execution_id"]),
            candidate, review,
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ChildExecutionError("stored child execution record is invalid") from exc


def _intent(event_row: sqlite3.Row) -> dict[str, object]:
    try:
        value = json.loads(event_row["payload_json"])
    except (TypeError, ValueError) as exc:
        raise IdempotencyConflictError("stored child command event is invalid") from exc
    if not isinstance(value, dict):
        raise IdempotencyConflictError("stored child command event is invalid")
    return value


def _matches_intent(event_row: sqlite3.Row, expected: dict[str, object], event_kind: str) -> bool:
    if event_row["event_kind"] != event_kind:
        return False
    stored = _intent(event_row)
    return all(stored.get(key) == value for key, value in expected.items())


class _ImmutableChildCommand:
    def __deepcopy__(self, memo):
        return self


@dataclass(frozen=True)
class _StartChild(_ImmutableChildCommand):
    parent_attempt: EntityRef
    target: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    execution_id: StableId
    logical_id: StableId
    retry_of: StableId | None
    child_actor_id: StableId
    child_incarnation_id: StableId
    child_kind: ActorKind
    child_label: str
    provider_id: str
    scope: AttemptScopeSnapshot
    scope_json: str
    scope_digest: str
    actions: tuple[StableId, ...]
    actions_json: str
    actions_digest: str
    capability_id: StableId
    token_digest: str
    parent_token_digest: str
    created_at: str


@dataclass(frozen=True)
class _SubmitCandidate(_ImmutableChildCommand):
    execution_id: StableId
    target: EntityRef
    parent_attempt: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    candidate_id: StableId
    summary: str
    artifacts_json: str
    artifacts_digest: str
    token_digest: str
    occurred_at: str


@dataclass(frozen=True)
class _ReviewChildCandidate(_ImmutableChildCommand):
    execution_id: StableId
    target: EntityRef
    parent_attempt: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    candidate_id: StableId
    review_id: StableId
    decision: ChildCandidateDecision
    reason: str | None
    occurred_at: str


@dataclass(frozen=True)
class _CancelChild(_ImmutableChildCommand):
    execution_id: StableId
    target: EntityRef
    parent_attempt: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    cancellation_id: StableId
    reason: str | None
    occurred_at: str


@dataclass(frozen=True)
class _ReconcileChildStopped(_ImmutableChildCommand):
    execution_id: StableId
    target: EntityRef
    parent_attempt: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    observation: AttemptSafetyObservation | None
    occurred_at: str


class _ChildHandlerBase:
    def __init__(self, service: "ChildExecutionService") -> None:
        self.service = service

    @staticmethod
    def _stored_parent(context: MutationContext, attempt_ref: EntityRef):
        try:
            return _stored_attempt(context._connection, context.project, attempt_ref)
        except AttemptError as exc:
            raise ChildExecutionNotFoundError("parent attempt is unavailable") from exc

    def _check_linked_child(self, context: MutationContext, digest: str, execution_id: StableId) -> None:
        row = context._connection.execute(
            "SELECT capability_id FROM capability_tokens WHERE token_digest = ?", (digest,)
        ).fetchone()
        if row is None:
            raise AuthenticationFailedError("child bearer is unavailable")
        child = context._connection.execute(
            "SELECT execution_id FROM child_executions WHERE capability_id = ?", (row["capability_id"],)
        ).fetchone()
        if child is None or child["execution_id"] != str(execution_id):
            raise CapabilityDeniedError("child bearer is not bound to this execution")

    @staticmethod
    def _event(intent: dict[str, object], **values: object) -> dict[str, object]:
        return {**intent, **values}


class _StartChildHandler(_ChildHandlerBase):
    kind = "todo.child.execution.start"
    command_type = _StartChild

    def authorization_requirement(self, command: _StartChild) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            CHILD_RETRY_ACTION if command.retry_of is not None else CHILD_DELEGATE_ACTION,
            command.target, command.run, command.assignment, command.parent_attempt,
        )

    def canonical_payload(self, command: _StartChild) -> dict[str, object]:
        return {
            "parent_attempt": str(command.parent_attempt.entity_id),
            "target": {"entity_id": str(command.target.entity_id),
                       "definition_revision_id": str(command.target.definition_revision_id)},
            "run": None if command.run is None else str(command.run.entity_id),
            "assignment": None if command.assignment is None else str(command.assignment.entity_id),
            "execution_id": str(command.execution_id), "logical_id": str(command.logical_id),
            "retry_of": None if command.retry_of is None else str(command.retry_of),
            "child_actor_id": str(command.child_actor_id),
            "scope": json.loads(command.scope_json),
            "actions": [str(action) for action in command.actions],
        }

    def apply(self, context: MutationContext, command: _StartChild) -> CommandEffect:
        _validate_structural_values(context._connection, (
            str(context.idempotency_key),
            str(command.execution_id), str(command.logical_id),
            "" if command.retry_of is None else str(command.retry_of),
            str(command.child_actor_id), str(command.child_incarnation_id),
            command.child_label, command.provider_id, str(command.capability_id),
            *(str(item) for item in command.actions),
            *_ref_identity_values(command.parent_attempt), *_ref_identity_values(command.target),
        ))
        _validate_scope_identity(context._connection, command.scope)
        attempt, attempt_row = self._stored_parent(context, command.parent_attempt)
        if (attempt.work_item != command.target or attempt.run != command.run
                or attempt.assignment != command.assignment or attempt.actor != context.actor):
            raise ChildExecutionDeniedError("child must be delegated by the exact live parent attempt owner")
        now = self.service.attempts._now()
        if (attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE}
                or attempt.lease is None or attempt.lease.expires_at <= now):
            raise ChildExecutionDeniedError("parent attempt is not live with a current lease")

        parent_capability_id = self.service.auth._authorize_capability(
            context._connection, context.project, command.parent_token_digest, context.actor,
            self.authorization_requirement(command),
        )
        parent_cap = _stored_capability(context._connection, parent_capability_id)
        if parent_cap is None or parent_cap["revoked"]:
            raise CapabilityDeniedError("parent capability is unavailable")
        if (parent_cap["attempt_id"] not in (None, str(attempt.attempt_id))
                or parent_cap["run_id"] not in (None, None if attempt.run is None else str(attempt.run.entity_id))
                or parent_cap["assignment_id"] not in (
                    None, None if attempt.assignment is None else str(attempt.assignment.entity_id)
                )):
            raise CapabilityDeniedError("parent capability context exceeds this attempt")
        parent_actions = _stored_actions(context._connection, parent_capability_id)
        if (command.child_actor_id == context.actor.entity_id
                or not set(command.actions).issubset(set(parent_actions))
                or not set(command.actions) < set(parent_actions)
                or not set(command.actions).issubset(set(CHILD_WORKER_ACTIONS))):
            raise CapabilityDeniedError("child action set must be a strict subset of worker-safe parent actions")

        try:
            parent_scope_row = context._connection.execute(
                "SELECT scope_json, scope_digest FROM attempt_scope_snapshots WHERE attempt_id = ?",
                (str(attempt.attempt_id),),
            ).fetchone()
            if parent_scope_row is None:
                raise ValueError("parent attempt has no immutable scope snapshot")
            parent_scope = decode_child_scope(parent_scope_row["scope_json"], parent_scope_row["scope_digest"])
            require_child_scope_subset(parent_scope, command.scope)
        except (TypeError, ValueError) as exc:
            raise ChildExecutionDeniedError("child scope is not a strict safe subset of the parent") from exc

        parent_expiry = None if parent_cap["expires_at"] is None else _parse_time(parent_cap["expires_at"])
        child_expiry = attempt.lease.expires_at
        if parent_expiry is not None:
            child_expiry = min(child_expiry, parent_expiry)
        if child_expiry <= now:
            raise ChildExecutionDeniedError("child capability would already be expired")

        sibling_rows = context._connection.execute(
            "SELECT execution_id, scope_json, scope_digest FROM child_executions "
            "WHERE parent_attempt_id = ? AND (state <> 'stopped' OR execution_id IN ("
            "SELECT candidate.execution_id FROM child_candidates AS candidate "
            "LEFT JOIN child_candidate_reviews AS review USING(candidate_id) "
            "WHERE review.review_id IS NULL)) ORDER BY execution_id",
            (str(attempt.attempt_id),),
        ).fetchall()
        for sibling in sibling_rows:
            sibling_scope = decode_child_scope(sibling["scope_json"], sibling["scope_digest"])
            if child_scopes_conflict(command.scope, sibling_scope):
                raise ChildExecutionDeniedError("child scope conflicts with unresolved sibling work")

        history = context._connection.execute(
            "SELECT execution_id, ordinal, state FROM child_executions "
            "WHERE parent_attempt_id = ? AND logical_id = ? ORDER BY ordinal",
            (str(attempt.attempt_id), str(command.logical_id)),
        ).fetchall()
        ordinal = len(history) + 1
        if ordinal > self.service.max_retries:
            raise ChildExecutionDeniedError("child retry bound has been reached")
        if ordinal == 1:
            if command.retry_of is not None:
                raise ChildExecutionDeniedError("first child execution cannot name a retry predecessor")
        else:
            previous = history[-1]
            if command.retry_of is None or command.retry_of.value != previous["execution_id"]:
                raise ChildExecutionDeniedError("retry must name the latest execution of this logical child")
            if previous["state"] != ChildExecutionState.STOPPED.value:
                raise ChildExecutionDeniedError("retry requires a prior child with verified stopped state")
            disposition = context._connection.execute(
                "SELECT review.decision, cancellation.execution_id FROM child_executions AS execution "
                "LEFT JOIN child_candidates AS candidate USING(execution_id) "
                "LEFT JOIN child_candidate_reviews AS review USING(candidate_id) "
                "LEFT JOIN child_cancellations AS cancellation USING(execution_id) "
                "WHERE execution.execution_id = ?",
                (previous["execution_id"],),
            ).fetchone()
            if disposition["decision"] == ChildCandidateDecision.ACCEPTED.value:
                raise ChildExecutionDeniedError("accepted child result cannot be retried")
            if disposition["decision"] is None and disposition["execution_id"] is None:
                raise ChildExecutionDeniedError("retry requires a rejected candidate or durable cancellation")

        prior_actor_kind = context._connection.execute(
            "SELECT kind FROM actors WHERE actor_id = ? LIMIT 1", (str(command.child_actor_id),)
        ).fetchone()
        if prior_actor_kind is not None and prior_actor_kind["kind"] != command.child_kind.value:
            raise CapabilityDeniedError("trusted child principal kind changed")
        context.execute(
            "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
            (str(command.child_actor_id), str(command.child_incarnation_id),
             command.child_kind.value, command.child_label),
        )
        _insert_capability(
            context, capability_id=command.capability_id,
            actor_id=command.child_actor_id, incarnation_id=command.child_incarnation_id,
            parent_id=parent_capability_id, scope=command.target, actions=command.actions,
            run=attempt.run, assignment=attempt.assignment, attempt=attempt.ref,
            expires_at=child_expiry, token_digest=command.token_digest,
        )
        context.execute(
            "INSERT INTO child_executions(execution_id, parent_attempt_id, logical_id, ordinal, "
            "retry_of_execution_id, work_item_id, definition_revision_id, child_actor_id, "
            "child_incarnation_id, capability_id, scope_json, scope_digest, actions_json, actions_digest, "
            "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
            (str(command.execution_id), str(attempt.attempt_id), str(command.logical_id), ordinal,
             None if command.retry_of is None else str(command.retry_of),
             str(attempt.work_item.entity_id), str(attempt.work_item.definition_revision_id),
             str(command.child_actor_id), str(command.child_incarnation_id), str(command.capability_id),
             command.scope_json, command.scope_digest, command.actions_json, command.actions_digest,
             command.created_at, command.created_at),
        )
        intent = self.canonical_payload(command)
        payload = self._event(
            intent, ordinal=ordinal, capability_id=str(command.capability_id),
            child_incarnation_id=str(command.child_incarnation_id), expires_at=_iso(child_expiry),
            scope_digest=command.scope_digest, actions_digest=command.actions_digest,
        )
        return CommandEffect(
            True,
            {"execution_id": str(command.execution_id), "logical_id": str(command.logical_id),
             "ordinal": ordinal, "capability_id": str(command.capability_id), "state": "active"},
            "todo.child.execution.started", payload,
        )


class _SubmitCandidateHandler(_ChildHandlerBase):
    kind = "todo.child.candidate.submit"
    command_type = _SubmitCandidate

    def authorization_requirement(self, command: _SubmitCandidate) -> AuthorizationRequirement:
        return AuthorizationRequirement(CHILD_CANDIDATE_SUBMIT_ACTION, command.target,
                                        command.run, command.assignment, command.parent_attempt)

    def canonical_payload(self, command: _SubmitCandidate) -> dict[str, object]:
        return {"execution_id": str(command.execution_id), "candidate_id": str(command.candidate_id),
                "target": str(command.target.entity_id), "summary": command.summary,
                "artifacts_digest": command.artifacts_digest}

    def apply(self, context: MutationContext, command: _SubmitCandidate) -> CommandEffect:
        try:
            artifact_values = tuple(
                value
                for artifact in json.loads(command.artifacts_json)
                for value in (artifact["artifact_id"], artifact["digest"])
            )
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ChildExecutionDeniedError("child candidate contains invalid structural references") from exc
        _validate_structural_values(context._connection, (
            str(context.idempotency_key),
            str(command.execution_id), str(command.candidate_id),
            *_ref_identity_values(command.target), *_ref_identity_values(command.parent_attempt),
            *artifact_values,
        ))
        self._check_linked_child(context, command.token_digest, command.execution_id)
        row = _child_row(context._connection, command.execution_id)
        if row is None:
            raise ChildExecutionNotFoundError("child execution does not exist")
        if (row["work_item_id"] != str(command.target.entity_id)
                or row["definition_revision_id"] != str(command.target.definition_revision_id)
                or row["parent_attempt_id"] != str(command.parent_attempt.entity_id)
                or row["parent_run_id"] != (None if command.run is None else str(command.run.entity_id))
                or row["parent_assignment_id"] != (None if command.assignment is None else str(command.assignment.entity_id))
                or row["child_actor_id"] != str(context.actor.entity_id)
                or row["child_incarnation_id"] != str(context.actor.incarnation_id)):
            raise CapabilityDeniedError("candidate submitter is not the exact child execution actor")
        if row["state"] != ChildExecutionState.ACTIVE.value:
            raise ChildExecutionStateError("only an active child execution can submit a candidate")
        summary = validate_bounded_text(command.summary, field="child candidate summary",
                                        max_bytes=_MAX_CHILD_SUMMARY_BYTES,
                                        connection=context._connection)
        parent_attempt, _ = _stored_attempt(context._connection, context.project, command.parent_attempt)
        if parent_attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE} or parent_attempt.lease is None:
            raise ChildExecutionDeniedError("candidate requires a live parent attempt")
        if parent_attempt.lease.expires_at <= self.service.attempts._now():
            raise ChildExecutionDeniedError("parent attempt lease expired before candidate submission")
        artifacts = json.loads(command.artifacts_json)
        for item in artifacts:
            artifact = context._connection.execute(
                "SELECT content_digest FROM artifacts WHERE artifact_id = ?", (item["artifact_id"],)
            ).fetchone()
            if artifact is None or artifact["content_digest"] != item["digest"]:
                raise ChildExecutionDeniedError("candidate artifact is not a verified existing authority artifact")
        context.execute(
            "INSERT INTO child_candidates(candidate_id, execution_id, summary, artifacts_json, artifacts_digest, "
            "submitted_by_actor_id, submitted_by_incarnation_id, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (str(command.candidate_id), str(command.execution_id), summary, command.artifacts_json,
             command.artifacts_digest, str(context.actor.entity_id), str(context.actor.incarnation_id),
             command.occurred_at),
        )
        changed = context.execute(
            "UPDATE child_executions SET state = 'candidate', updated_at = ? "
            "WHERE execution_id = ? AND state = 'active'",
            (command.occurred_at, str(command.execution_id)),
        ).rowcount
        if changed != 1:
            raise ChildExecutionStateError("child state changed while submitting candidate")
        return CommandEffect(
            True, {"candidate_id": str(command.candidate_id), "execution_id": str(command.execution_id),
                   "state": "candidate"},
            "todo.child.candidate.submitted",
            self._event(self.canonical_payload(command), submitted_by_actor_id=str(context.actor.entity_id),
                        submitted_by_incarnation_id=str(context.actor.incarnation_id), submitted_at=command.occurred_at),
        )


class _ReviewCandidateHandler(_ChildHandlerBase):
    kind = "todo.child.candidate.review"
    command_type = _ReviewChildCandidate

    def authorization_requirement(self, command: _ReviewChildCandidate) -> AuthorizationRequirement:
        return AuthorizationRequirement(CHILD_REVIEW_ACTION, command.target,
                                        command.run, command.assignment, command.parent_attempt)

    def canonical_payload(self, command: _ReviewChildCandidate) -> dict[str, object]:
        return {"execution_id": str(command.execution_id), "candidate_id": str(command.candidate_id),
                "review_id": str(command.review_id), "decision": command.decision.value,
                "reason": command.reason, "target": str(command.target.entity_id)}

    def apply(self, context: MutationContext, command: _ReviewChildCandidate) -> CommandEffect:
        _validate_structural_values(context._connection, (
            str(context.idempotency_key),
            str(command.execution_id), str(command.candidate_id), str(command.review_id),
            *_ref_identity_values(command.target), *_ref_identity_values(command.parent_attempt),
        ))
        row = _child_row(context._connection, command.execution_id)
        if row is None:
            raise ChildExecutionNotFoundError("child execution does not exist")
        if (row["work_item_id"] != str(command.target.entity_id)
                or row["definition_revision_id"] != str(command.target.definition_revision_id)
                or row["parent_attempt_id"] != str(command.parent_attempt.entity_id)
                or row["parent_run_id"] != (None if command.run is None else str(command.run.entity_id))
                or row["parent_assignment_id"] != (None if command.assignment is None else str(command.assignment.entity_id))):
            raise ChildExecutionDeniedError("review does not match the child execution context")
        if (row["child_actor_id"] == str(context.actor.entity_id)
                and row["child_incarnation_id"] == str(context.actor.incarnation_id)):
            raise CapabilityDeniedError("a child cannot review its own candidate")
        candidate = context._connection.execute(
            "SELECT candidate_id FROM child_candidates WHERE execution_id = ?",
            (str(command.execution_id),),
        ).fetchone()
        if candidate is None or candidate["candidate_id"] != str(command.candidate_id):
            raise ChildExecutionStateError("candidate does not belong to this execution")
        if context._connection.execute(
            "SELECT 1 FROM child_candidate_reviews WHERE candidate_id = ?",
            (str(command.candidate_id),),
        ).fetchone() is not None:
            raise ChildExecutionStateError("candidate already has a durable review")
        reason = command.reason
        if reason is not None:
            reason = validate_bounded_text(reason, field="child review reason", max_bytes=_MAX_CHILD_REASON_BYTES,
                                           connection=context._connection)
        context.execute(
            "INSERT INTO child_candidate_reviews(review_id, candidate_id, decision, reviewer_actor_id, "
            "reviewer_incarnation_id, reason, reviewed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(command.review_id), str(command.candidate_id), command.decision.value,
             str(context.actor.entity_id), str(context.actor.incarnation_id), reason, command.occurred_at),
        )
        return CommandEffect(
            True, {"review_id": str(command.review_id), "candidate_id": str(command.candidate_id),
                   "decision": command.decision.value},
            "todo.child.candidate.reviewed",
            self._event(self.canonical_payload(command), reviewer_actor_id=str(context.actor.entity_id),
                        reviewer_incarnation_id=str(context.actor.incarnation_id), reviewed_at=command.occurred_at),
        )


class _CancelChildHandler(_ChildHandlerBase):
    kind = "todo.child.execution.cancel_requested"
    command_type = _CancelChild

    def authorization_requirement(self, command: _CancelChild) -> AuthorizationRequirement:
        return AuthorizationRequirement(CHILD_CANCEL_ACTION, command.target,
                                        command.run, command.assignment, command.parent_attempt)

    def canonical_payload(self, command: _CancelChild) -> dict[str, object]:
        return {"execution_id": str(command.execution_id), "cancellation_id": str(command.cancellation_id),
                "reason": command.reason, "target": str(command.target.entity_id)}

    def apply(self, context: MutationContext, command: _CancelChild) -> CommandEffect:
        _validate_structural_values(context._connection, (
            str(context.idempotency_key),
            str(command.execution_id), str(command.cancellation_id),
            *_ref_identity_values(command.target), *_ref_identity_values(command.parent_attempt),
        ))
        row = _child_row(context._connection, command.execution_id)
        if row is None:
            raise ChildExecutionNotFoundError("child execution does not exist")
        parent, _ = self._stored_parent(context, command.parent_attempt)
        if (row["parent_attempt_id"] != str(parent.attempt_id)
                or row["work_item_id"] != str(command.target.entity_id)
                or row["definition_revision_id"] != str(command.target.definition_revision_id)
                or row["parent_run_id"] != (None if command.run is None else str(command.run.entity_id))
                or row["parent_assignment_id"] != (None if command.assignment is None else str(command.assignment.entity_id))
                or parent.actor != context.actor):
            raise CapabilityDeniedError("only the owning parent attempt may cancel this child")
        if row["state"] == ChildExecutionState.STOPPED.value:
            raise ChildExecutionStateError("a stopped child execution cannot be cancelled")
        if context._connection.execute(
            "SELECT 1 FROM child_cancellations WHERE execution_id = ?", (str(command.execution_id),)
        ).fetchone() is not None:
            raise ChildExecutionStateError("child cancellation was already requested")
        reason = command.reason
        if reason is not None:
            reason = validate_bounded_text(reason, field="child cancellation reason",
                                           max_bytes=_MAX_CHILD_REASON_BYTES,
                                           connection=context._connection)
        context.execute(
            "INSERT INTO child_cancellations(cancellation_id, execution_id, requested_by_actor_id, "
            "requested_by_incarnation_id, reason, requested_at) VALUES (?, ?, ?, ?, ?, ?)",
            (str(command.cancellation_id), str(command.execution_id), str(context.actor.entity_id),
             str(context.actor.incarnation_id), reason, command.occurred_at),
        )
        changed = context.execute(
            "UPDATE child_executions SET state = 'cancel_requested', updated_at = ? "
            "WHERE execution_id = ? AND state IN ('active', 'candidate')",
            (command.occurred_at, str(command.execution_id)),
        ).rowcount
        if changed != 1:
            raise ChildExecutionStateError("child state changed while cancellation was requested")
        revoked = self.service.auth._revoke_capability_family_in_transaction(
            context, StableId(row["capability_id"])
        )
        return CommandEffect(
            True, {"execution_id": str(command.execution_id), "state": "cancel_requested"},
            "todo.child.execution.cancel_requested",
            self._event(self.canonical_payload(command), requested_by_actor_id=str(context.actor.entity_id),
                        requested_by_incarnation_id=str(context.actor.incarnation_id),
                        requested_at=command.occurred_at, revoked_capabilities=revoked),
        )


class _ReconcileChildStoppedHandler(_ChildHandlerBase):
    kind = "todo.child.execution.stopped"
    command_type = _ReconcileChildStopped

    def authorization_requirement(self, command: _ReconcileChildStopped) -> AuthorizationRequirement:
        return AuthorizationRequirement(CHILD_STOP_RECONCILE_ACTION, command.target,
                                        command.run, command.assignment, command.parent_attempt)

    def canonical_payload(self, command: _ReconcileChildStopped) -> dict[str, object]:
        return {"execution_id": str(command.execution_id), "target": str(command.target.entity_id),
                "parent_attempt": str(command.parent_attempt.entity_id)}

    def apply(self, context: MutationContext, command: _ReconcileChildStopped) -> CommandEffect:
        _validate_structural_values(context._connection, (
            str(context.idempotency_key), str(command.execution_id),
            *_ref_identity_values(command.target), *_ref_identity_values(command.parent_attempt),
        ))
        row = _child_row(context._connection, command.execution_id)
        if row is None:
            raise ChildExecutionNotFoundError("child execution does not exist")
        parent, parent_row = self._stored_parent(context, command.parent_attempt)
        if (row["parent_attempt_id"] != str(parent.attempt_id)
                or row["work_item_id"] != str(command.target.entity_id)
                or row["definition_revision_id"] != str(command.target.definition_revision_id)
                or row["parent_run_id"] != (None if command.run is None else str(command.run.entity_id))
                or row["parent_assignment_id"] != (None if command.assignment is None else str(command.assignment.entity_id))):
            raise ChildExecutionDeniedError("stop observation target or parent context changed")
        if row["state"] == ChildExecutionState.STOPPED.value:
            return CommandEffect(False, {"execution_id": str(command.execution_id), "state": "stopped"})
        workspace = _stored_workspace(context._connection, context.project, parent.ref)
        observation = _check_observation(
            command.observation, target=parent.work_item, attempt_ref=parent.ref, row=parent_row,
            workspace=workspace, now=self.service.attempts._now(),
            max_age=self.service.attempts.max_observation_age,
        )
        if (not observation.safe_to_release
                or observation.process is not ProcessLiveness.STOPPED
                or observation.children is not ChildActivity.NONE):
            raise ChildExecutionObservationError("host has not proven a clean, stopped parent execution")
        audit_json = _json(_observation_audit(observation))
        context.execute(
            "INSERT INTO child_stop_observations(execution_id, parent_attempt_id, lease_id, "
            "lease_expires_at, observation_json, receipt_id, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(command.execution_id), str(parent.attempt_id), str(observation.lease_id),
             _attempt_iso(observation.observed_lease_expires_at), audit_json,
             str(observation.receipt.receipt_id), _attempt_iso(observation.receipt.observed_at)),
        )
        changed = context.execute(
            "UPDATE child_executions SET state = 'stopped', updated_at = ? "
            "WHERE execution_id = ? AND state IN ('active', 'candidate', 'cancel_requested')",
            (command.occurred_at, str(command.execution_id)),
        ).rowcount
        if changed != 1:
            raise ChildExecutionStateError("child state changed while recording stop evidence")
        revoked = self.service.auth._revoke_capability_family_in_transaction(
            context, StableId(row["capability_id"])
        )
        payload = self._event(
            self.canonical_payload(command), state="stopped", provider_receipt_id=str(observation.receipt.receipt_id),
            observation=audit_json, revoked_capabilities=revoked,
        )
        return CommandEffect(
            True, {"execution_id": str(command.execution_id), "state": "stopped",
                   "provider_receipt_id": str(observation.receipt.receipt_id)},
            "todo.child.execution.stopped", payload,
        )


class ChildExecutionService:
    """Authenticated child delegation, result review, cancellation, and stop reconciliation."""

    def __init__(self, auth: AuthorityAuthService, *, attempts: AttemptService, max_retries: int = 3) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not isinstance(attempts, AttemptService) or attempts.auth is not auth:
            raise TypeError("attempts must use the same AuthorityAuthService")
        if type(max_retries) is not int or not 1 <= max_retries <= 3:
            raise ValueError("max_retries must be between 1 and the frozen schema limit of 3")
        self.auth = auth
        self.attempts = attempts
        self.max_retries = max_retries
        handlers = getattr(auth, "_child_execution_handlers", None)
        if handlers is None:
            handlers = (
                _StartChildHandler(self), _SubmitCandidateHandler(self), _ReviewCandidateHandler(self),
                _CancelChildHandler(self), _ReconcileChildStoppedHandler(self),
            )
            for handler in handlers:
                auth.dispatcher.register(handler)
            auth._child_execution_handlers = handlers
        else:
            for handler in handlers:
                handler.service = self

    def _attempt_context(self, authority: SQLiteAuthority, parent_attempt: EntityRef):
        attempt = self.attempts._attempt_for_service(authority, parent_attempt)
        if attempt is None:
            raise ChildExecutionNotFoundError("parent attempt does not exist")
        return attempt

    def _requirement(self, action: StableId, target: EntityRef, attempt: EntityRef,
                     run: EntityRef | None, assignment: EntityRef | None) -> AuthorizationRequirement:
        return AuthorizationRequirement(action, target, run, assignment, attempt)

    def _replay(self, authority: SQLiteAuthority, bearer_token: str, key: StableId,
                requirement: AuthorizationRequirement, command_kind: str,
                expected: dict[str, object], event_kind: str):
        return self.auth.replay_authorized(
            authority, bearer_token, key, requirement, command_kind,
            lambda _connection, row: _matches_intent(row, expected, event_kind),
        )

    def _execute_with_replay(self, authority: SQLiteAuthority, bearer_token: str, command: object,
                             *, idempotency_key: StableId, expected_revision: int | None,
                             requirement: AuthorizationRequirement, command_kind: str,
                             expected: dict[str, object], event_kind: str,
                             secret_delivery: bool = False):
        prior = self._replay(authority, bearer_token, idempotency_key, requirement, command_kind, expected, event_kind)
        if prior is not None:
            if secret_delivery:
                raise CapabilityDeliveryUncertainError(prior.receipt)
            return prior
        try:
            result = self.auth.execute(
                authority, bearer_token, command, idempotency_key=idempotency_key,
                expected_revision=expected_revision,
            )
        except StaleAuthorityRevisionError:
            prior = self._replay(authority, bearer_token, idempotency_key, requirement,
                                 command_kind, expected, event_kind)
            if prior is not None:
                if secret_delivery:
                    raise CapabilityDeliveryUncertainError(prior.receipt)
                return prior
            raise
        if result.replayed and secret_delivery:
            raise CapabilityDeliveryUncertainError(result.receipt)
        return result

    def start_child(
        self,
        authority: SQLiteAuthority,
        parent_bearer_token: str,
        parent_attempt: EntityRef,
        child_credential: object,
        *,
        execution_id: StableId,
        logical_id: StableId,
        scope: AttemptScopeSnapshot,
        actions: tuple[StableId, ...],
        idempotency_key: StableId,
        retry_of: StableId | None = None,
        expected_revision: int | None = None,
    ) -> ChildExecutionGrant:
        if not isinstance(authority, SQLiteAuthority) or authority.readonly:
            raise TypeError("authority must be a writable SQLiteAuthority")
        if parent_attempt.project_id != authority.project.project_id or parent_attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("parent_attempt must be a same-project attempt reference")
        if not all(isinstance(value, StableId) for value in (execution_id, logical_id, idempotency_key)):
            raise TypeError("child execution, logical, and idempotency IDs must be StableId values")
        if retry_of is not None and not isinstance(retry_of, StableId):
            raise TypeError("retry_of must be a StableId or None")
        if not isinstance(scope, AttemptScopeSnapshot):
            raise TypeError("scope must be an AttemptScopeSnapshot")
        if not isinstance(actions, tuple) or not actions or any(not isinstance(action, StableId) for action in actions):
            raise TypeError("actions must be a non-empty tuple of StableId values")
        if len(set(actions)) != len(actions):
            raise ValueError("child actions must be unique")
        if self.auth.authenticator is None:
            raise AuthenticationProviderUnavailableError("child execution requires a trusted principal authenticator")
        principal = self.auth.authenticator.authenticate(child_credential)
        if principal is None or not isinstance(principal, AuthenticatedPrincipal):
            raise AuthenticationFailedError("trusted authenticator refused the child principal")
        provider_id = getattr(self.auth.authenticator, "provider_id", None)
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise AuthenticationProviderUnavailableError("trusted authenticator has no provider identity")
        actor_id = self.auth._principal_actor_id(authority.project, provider_id, principal.subject_id)
        encoded_scope = _scope_snapshot_payload(scope)
        scope_digest = _digest_json(encoded_scope)
        actions_json = _actions_json(actions)
        actions_digest = _digest_json(actions_json)
        attempt = self._attempt_context(authority, parent_attempt)
        action = CHILD_RETRY_ACTION if retry_of is not None else CHILD_DELEGATE_ACTION
        requirement = self._requirement(action, attempt.work_item, attempt.ref, attempt.run, attempt.assignment)
        with authority.read_transaction() as connection:
            _validate_structural_values(connection, (
                str(idempotency_key), str(execution_id), str(logical_id),
                "" if retry_of is None else str(retry_of), str(actor_id), principal.label, provider_id,
                *_ref_identity_values(attempt.ref), *_ref_identity_values(attempt.work_item),
                *(str(item) for item in actions),
            ))
            _validate_scope_identity(connection, scope)
        intent = {
            "parent_attempt": str(attempt.attempt_id),
            "target": {"entity_id": str(attempt.work_item.entity_id),
                       "definition_revision_id": str(attempt.work_item.definition_revision_id)},
            "run": None if attempt.run is None else str(attempt.run.entity_id),
            "assignment": None if attempt.assignment is None else str(attempt.assignment.entity_id),
            "execution_id": str(execution_id), "logical_id": str(logical_id),
            "retry_of": None if retry_of is None else str(retry_of),
            "child_actor_id": str(actor_id), "scope": json.loads(encoded_scope),
            "actions": [str(item) for item in actions],
        }
        prior = self._replay(authority, parent_bearer_token, idempotency_key, requirement,
                             "todo.child.execution.start", intent, "todo.child.execution.started")
        if prior is not None:
            raise CapabilityDeliveryUncertainError(prior.receipt)

        capability_id = StableId("cap-" + uuid4().hex)
        incarnation_id = StableId("inc-" + uuid4().hex)
        token = _bearer()
        command = _StartChild(
            attempt.ref, attempt.work_item, attempt.run, attempt.assignment,
            execution_id, logical_id, retry_of, actor_id, incarnation_id,
            principal.kind, principal.label, provider_id, scope, encoded_scope, scope_digest,
            actions, actions_json, actions_digest, capability_id, _token_digest(token),
            _token_digest(parent_bearer_token), _iso(self.attempts._now()),
        )
        result = self._execute_with_replay(
            authority, parent_bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision, requirement=requirement,
            command_kind="todo.child.execution.start", expected=intent,
            event_kind="todo.child.execution.started", secret_delivery=True,
        )
        with authority.read_transaction() as connection:
            row = _child_row(connection, execution_id)
            if row is None:
                raise ChildExecutionError("child execution receipt exists without its durable record")
            view = _view_from_row(connection, authority.project.project_id, row)
        return ChildExecutionGrant(view, token, result.receipt)

    def read_execution(self, authority: SQLiteAuthority, bearer_token: str,
                       execution_id: StableId) -> ChildExecutionView:
        if not isinstance(execution_id, StableId):
            raise TypeError("execution_id must be a StableId")
        digest = _token_digest(bearer_token)
        actor, _ = self.auth._actor_for_token(authority, digest)
        with authority.read_transaction() as connection:
            row = _child_row(connection, execution_id)
            if row is None:
                raise ChildExecutionNotFoundError("child execution does not exist")
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM,
                               StableId(row["work_item_id"]),
                               definition_revision_id=StableId(row["definition_revision_id"]))
            parent = EntityRef(authority.project.project_id, EntityKind.ATTEMPT,
                               StableId(row["parent_attempt_id"]))
            run = None if row["parent_run_id"] is None else EntityRef(authority.project.project_id,
                                                                       EntityKind.RUN, StableId(row["parent_run_id"]))
            assignment = None if row["parent_assignment_id"] is None else EntityRef(
                authority.project.project_id, EntityKind.ASSIGNMENT, StableId(row["parent_assignment_id"]))
            requirement = self._requirement(CHILD_READ_ACTION, target, parent, run, assignment)
            connection.set_authorizer(_authorization_authorizer)
            try:
                cap_id = self.auth._authorize_capability(connection, authority.project, digest, actor, requirement)
                linked = connection.execute(
                    "SELECT execution_id FROM child_executions WHERE capability_id = ?", (str(cap_id),)
                ).fetchone()
                if linked is not None and linked["execution_id"] != str(execution_id):
                    raise CapabilityDeniedError("child bearer is bound to another execution")
            finally:
                connection.set_authorizer(None)
            return _view_from_row(connection, authority.project.project_id, row)

    def submit_candidate(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        execution_id: StableId,
        *,
        candidate_id: StableId,
        summary: str,
        artifacts: tuple[ChildArtifactRef, ...] = (),
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> ChildCandidate:
        if not all(isinstance(value, StableId) for value in (execution_id, candidate_id, idempotency_key)):
            raise TypeError("execution, candidate, and idempotency IDs must be StableId values")
        with authority.read_transaction() as connection:
            row = _child_row(connection, execution_id)
            if row is None:
                raise ChildExecutionNotFoundError("child execution does not exist")
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                               definition_revision_id=StableId(row["definition_revision_id"]))
            parent = EntityRef(authority.project.project_id, EntityKind.ATTEMPT, StableId(row["parent_attempt_id"]))
            run = None if row["parent_run_id"] is None else EntityRef(authority.project.project_id,
                                                                       EntityKind.RUN, StableId(row["parent_run_id"]))
            assignment = None if row["parent_assignment_id"] is None else EntityRef(
                authority.project.project_id, EntityKind.ASSIGNMENT, StableId(row["parent_assignment_id"]))
        artifact_value = _artifacts_value(artifacts, authority.project.project_id)
        artifacts_json = _json(artifact_value)
        artifacts_digest = _digest_json(artifacts_json)
        clean_summary = validate_bounded_text(summary, field="child candidate summary",
                                             max_bytes=_MAX_CHILD_SUMMARY_BYTES, allow_multiline=False)
        structural_values = [str(idempotency_key), str(execution_id), str(candidate_id), clean_summary]
        structural_values.extend(_ref_identity_values(target))
        structural_values.extend(_ref_identity_values(parent))
        for item in artifact_value:
            structural_values.extend((item["artifact_id"], item["digest"]))
        with authority.read_transaction() as connection:
            _validate_structural_values(connection, tuple(structural_values))
        intent = {"execution_id": str(execution_id), "candidate_id": str(candidate_id),
                  "target": str(target.entity_id), "summary": clean_summary,
                  "artifacts_digest": artifacts_digest}
        requirement = self._requirement(CHILD_CANDIDATE_SUBMIT_ACTION, target, parent, run, assignment)
        replay = self._replay(authority, bearer_token, idempotency_key, requirement,
                              "todo.child.candidate.submit", intent, "todo.child.candidate.submitted")
        if replay is None:
            command = _SubmitCandidate(execution_id, target, parent, run, assignment, candidate_id,
                                       clean_summary, artifacts_json, artifacts_digest,
                                       _token_digest(bearer_token), _iso(self.attempts._now()))
            self._execute_with_replay(
                authority, bearer_token, command, idempotency_key=idempotency_key,
                expected_revision=expected_revision, requirement=requirement,
                command_kind="todo.child.candidate.submit", expected=intent,
                event_kind="todo.child.candidate.submitted",
            )
        with authority.read_transaction() as connection:
            candidate = _candidate_review(connection, execution_id)
            if candidate is None or candidate["candidate_id"] != str(candidate_id):
                raise ChildExecutionError("child candidate receipt is missing its durable candidate")
            artifacts_value = _decode_artifacts(candidate["artifacts_json"], candidate["artifacts_digest"],
                                                authority.project.project_id)
            return ChildCandidate(
                StableId(candidate["candidate_id"]), execution_id, candidate["summary"], artifacts_value,
                EntityRef(authority.project.project_id, EntityKind.ACTOR,
                          StableId(candidate["submitted_by_actor_id"]),
                          incarnation_id=StableId(candidate["submitted_by_incarnation_id"])),
                _parse_time(candidate["submitted_at"]),
            )

    def review_candidate(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        execution_id: StableId,
        candidate_id: StableId,
        decision: ChildCandidateDecision,
        *,
        review_id: StableId,
        reason: str | None = None,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> ChildReview:
        if not isinstance(decision, ChildCandidateDecision):
            raise TypeError("decision must be a ChildCandidateDecision")
        if not all(isinstance(value, StableId) for value in
                   (execution_id, candidate_id, review_id, idempotency_key)):
            raise TypeError("review identity values must be StableId values")
        with authority.read_transaction() as connection:
            row = _child_row(connection, execution_id)
            if row is None:
                raise ChildExecutionNotFoundError("child execution does not exist")
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                               definition_revision_id=StableId(row["definition_revision_id"]))
            parent = EntityRef(authority.project.project_id, EntityKind.ATTEMPT, StableId(row["parent_attempt_id"]))
            run = None if row["parent_run_id"] is None else EntityRef(authority.project.project_id,
                                                                       EntityKind.RUN, StableId(row["parent_run_id"]))
            assignment = None if row["parent_assignment_id"] is None else EntityRef(
                authority.project.project_id, EntityKind.ASSIGNMENT, StableId(row["parent_assignment_id"]))
        clean_reason = None if reason is None else validate_bounded_text(
            reason, field="child review reason", max_bytes=_MAX_CHILD_REASON_BYTES, allow_multiline=False)
        with authority.read_transaction() as connection:
            _validate_structural_values(connection, (
                str(idempotency_key), str(execution_id), str(candidate_id), str(review_id),
                *_ref_identity_values(target), *_ref_identity_values(parent),
                "" if clean_reason is None else clean_reason,
            ))
        intent = {"execution_id": str(execution_id), "candidate_id": str(candidate_id),
                  "review_id": str(review_id), "decision": decision.value,
                  "reason": clean_reason, "target": str(target.entity_id)}
        requirement = self._requirement(CHILD_REVIEW_ACTION, target, parent, run, assignment)
        replay = self._replay(authority, bearer_token, idempotency_key, requirement,
                              "todo.child.candidate.review", intent, "todo.child.candidate.reviewed")
        if replay is None:
            command = _ReviewChildCandidate(execution_id, target, parent, run, assignment,
                                            candidate_id, review_id, decision, clean_reason,
                                            _iso(self.attempts._now()))
            self._execute_with_replay(
                authority, bearer_token, command, idempotency_key=idempotency_key,
                expected_revision=expected_revision, requirement=requirement,
                command_kind="todo.child.candidate.review", expected=intent,
                event_kind="todo.child.candidate.reviewed",
            )
        with authority.read_transaction() as connection:
            review_row = connection.execute(
                "SELECT * FROM child_candidate_reviews WHERE candidate_id = ?", (str(candidate_id),)
            ).fetchone()
        if review_row is None or review_row["review_id"] != str(review_id):
            raise ChildExecutionError("child review receipt is missing its durable review")
        return ChildReview(
            StableId(review_row["review_id"]), candidate_id,
            ChildCandidateDecision(review_row["decision"]),
            EntityRef(authority.project.project_id, EntityKind.ACTOR,
                      StableId(review_row["reviewer_actor_id"]),
                      incarnation_id=StableId(review_row["reviewer_incarnation_id"])),
            review_row["reason"], _parse_time(review_row["reviewed_at"]),
        )

    def request_cancel(
        self,
        authority: SQLiteAuthority,
        parent_bearer_token: str,
        execution_id: StableId,
        *,
        cancellation_id: StableId,
        reason: str | None = None,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ):
        if not isinstance(execution_id, StableId) or not isinstance(cancellation_id, StableId):
            raise TypeError("execution_id and cancellation_id must be StableId values")
        with authority.read_transaction() as connection:
            row = _child_row(connection, execution_id)
            if row is None:
                raise ChildExecutionNotFoundError("child execution does not exist")
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                               definition_revision_id=StableId(row["definition_revision_id"]))
            parent = EntityRef(authority.project.project_id, EntityKind.ATTEMPT, StableId(row["parent_attempt_id"]))
            run = None if row["parent_run_id"] is None else EntityRef(authority.project.project_id,
                                                                       EntityKind.RUN, StableId(row["parent_run_id"]))
            assignment = None if row["parent_assignment_id"] is None else EntityRef(
                authority.project.project_id, EntityKind.ASSIGNMENT, StableId(row["parent_assignment_id"]))
        clean_reason = None if reason is None else validate_bounded_text(
            reason, field="child cancellation reason", max_bytes=_MAX_CHILD_REASON_BYTES, allow_multiline=False)
        with authority.read_transaction() as connection:
            _validate_structural_values(connection, (
                str(idempotency_key), str(execution_id), str(cancellation_id),
                *_ref_identity_values(target), *_ref_identity_values(parent),
                "" if clean_reason is None else clean_reason,
            ))
        intent = {"execution_id": str(execution_id), "cancellation_id": str(cancellation_id),
                  "reason": clean_reason, "target": str(target.entity_id)}
        requirement = self._requirement(CHILD_CANCEL_ACTION, target, parent, run, assignment)
        command = _CancelChild(execution_id, target, parent, run, assignment, cancellation_id,
                               clean_reason, _iso(self.attempts._now()))
        return self._execute_with_replay(
            authority, parent_bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision, requirement=requirement,
            command_kind="todo.child.execution.cancel_requested", expected=intent,
            event_kind="todo.child.execution.cancel_requested",
        )

    def reconcile_stopped(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        execution_id: StableId,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ):
        if not isinstance(execution_id, StableId) or not isinstance(idempotency_key, StableId):
            raise TypeError("execution and idempotency IDs must be StableId values")
        with authority.read_transaction() as connection:
            row = _child_row(connection, execution_id)
            if row is None:
                raise ChildExecutionNotFoundError("child execution does not exist")
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                               definition_revision_id=StableId(row["definition_revision_id"]))
            parent_ref = EntityRef(authority.project.project_id, EntityKind.ATTEMPT,
                                   StableId(row["parent_attempt_id"]))
            parent, _ = _stored_attempt(connection, authority.project, parent_ref)
            workspace = _stored_workspace(connection, authority.project, parent_ref)
        run, assignment = parent.run, parent.assignment
        intent = {"execution_id": str(execution_id), "target": str(target.entity_id),
                  "parent_attempt": str(parent_ref.entity_id)}
        requirement = self._requirement(CHILD_STOP_RECONCILE_ACTION, target, parent_ref, run, assignment)
        replay = self._replay(authority, bearer_token, idempotency_key, requirement,
                              "todo.child.execution.stopped", intent, "todo.child.execution.stopped")
        if replay is not None:
            return replay
        try:
            observation = self.attempts.host.inspect_attempt(parent, workspace)
        except Exception as exc:
            raise AttemptHostUnavailableError("host safety inspection for child stop failed") from exc
        if not isinstance(observation, AttemptSafetyObservation):
            raise AttemptHostUnavailableError("host returned no typed child stop observation")
        command = _ReconcileChildStopped(execution_id, target, parent_ref, run, assignment,
                                         observation, _iso(self.attempts._now()))
        return self._execute_with_replay(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision, requirement=requirement,
            command_kind="todo.child.execution.stopped", expected=intent,
            event_kind="todo.child.execution.stopped",
        )


__all__ = [
    "CHILD_CANDIDATE_SUBMIT_ACTION", "CHILD_CANCEL_ACTION", "CHILD_DELEGATE_ACTION",
    "CHILD_READ_ACTION", "CHILD_REVIEW_ACTION", "CHILD_RETRY_ACTION",
    "CHILD_STOP_RECONCILE_ACTION", "CHILD_WORKER_ACTIONS", "CHILD_WRITE_ACTION",
    "ChildExecutionDeniedError", "ChildExecutionError", "ChildExecutionNotFoundError",
    "ChildExecutionObservationError", "ChildExecutionService", "ChildExecutionStateError",
]
