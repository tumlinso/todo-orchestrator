"""Authenticated, idempotent application of exact read-only recovery intents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from typing import Any

from todo_orchestrator.authority.attempts import AttemptService
from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    RECOVERY_APPLY_ACTION,
    RECOVERY_INSPECT_ACTION,
    _token_digest,
)
from todo_orchestrator.authority.recovery_approval import _issue_recovery_approval
from todo_orchestrator.authority.sqlite import AuthorityError, SQLiteAuthority
from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.model import CommandResult
from todo_orchestrator.providers.git.service import GitEffectService
from todo_orchestrator.verification.service import VerificationService

from .inspection import RecoveryInspectionService, _operation_rows
from ..views.recovery import RecoveryInspection, RecoveryIntent, RecoveryIntentKind


RECOVERY_APPLY_ACTION_ID = RECOVERY_APPLY_ACTION


def _ref_payload(value: EntityRef | None) -> object:
    if value is None:
        return None
    return [
        str(value.project_id), value.kind.value, str(value.entity_id),
        None if value.definition_revision_id is None else str(value.definition_revision_id),
        None if value.incarnation_id is None else str(value.incarnation_id),
    ]


def _intent_digest(intent: RecoveryIntent) -> Sha256Digest:
    """Bind idempotency replay to the full caller-supplied inspection preview."""
    payload = {
        "kind": intent.kind.value,
        "attempt": _ref_payload(intent.attempt),
        "target": _ref_payload(intent.target),
        "operations": [_ref_payload(item) for item in intent.operations],
        "expected_authority_revision": intent.expected_authority_revision,
        "expected_lease_id": None if intent.expected_lease_id is None else str(intent.expected_lease_id),
        "expected_source_digest": None if intent.expected_source_digest is None
            else intent.expected_source_digest.hex,
        "workspace_id": None if intent.workspace_id is None else str(intent.workspace_id),
        "preconditions": [
            {"code": item.code, "satisfied": item.satisfied,
             "subject": _ref_payload(item.subject), "detail": item.detail}
            for item in intent.preconditions
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return Sha256Digest(hashlib.sha256(encoded.encode("ascii")).hexdigest())


class RecoveryApplyError(AuthorityError):
    """Base refusal for applying a recovery intent."""


class RecoveryIntentStaleError(RecoveryApplyError):
    """The exact approved inspection intent is no longer currently available."""


class RecoveryApplyProviderUnavailableError(RecoveryApplyError):
    """A required trusted recovery service or provider is not configured."""


@dataclass(frozen=True)
class RecoveryApplyResult:
    intent: RecoveryIntent
    actor: EntityRef
    disposition: str
    semantic_revision: int
    replayed: bool
    result: object
    completed_at: datetime


def _now(clock) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("recovery execution clock must return an aware datetime")
    return value.astimezone(timezone.utc)


class RecoveryExecutionService:
    """Apply one freshly revalidated R01 intent under a current principal grant.

    The principal must hold both ``todo.recovery.inspect`` and
    ``todo.recovery.apply`` for the exact target and attempt context. A
    serialized intent is a proposal only: this service re-inspects it and
    requires exact equality before routing it to the existing attempt,
    verification, or Git lifecycle service.
    """

    def __init__(
        self,
        inspection: RecoveryInspectionService,
        *,
        attempts: AttemptService,
        verification: VerificationService | None = None,
        git_effects: GitEffectService | None = None,
        clock=None,
    ) -> None:
        if not isinstance(inspection, RecoveryInspectionService):
            raise TypeError("inspection must be a RecoveryInspectionService")
        if not isinstance(attempts, AttemptService):
            raise TypeError("attempts must be an AttemptService")
        auth = inspection.auth
        if attempts.auth is not auth:
            raise ValueError("recovery, inspection, and attempt services must share one auth service")
        if verification is not None and (
            not isinstance(verification, VerificationService) or verification.auth is not auth
        ):
            raise ValueError("verification service must share the recovery auth service")
        if git_effects is not None and (
            not isinstance(git_effects, GitEffectService) or git_effects.auth is not auth
        ):
            raise ValueError("Git effect service must share the recovery auth service")
        self.auth = auth
        self.inspection = inspection
        self.attempts = attempts
        self.verification = verification
        self.git_effects = git_effects
        self.clock = clock or inspection.clock

    def _context(self, authority: SQLiteAuthority, intent: RecoveryIntent):
        if intent.target.project_id != authority.project.project_id:
            raise RecoveryIntentStaleError("recovery target belongs to another authority")
        if intent.attempt is not None:
            if intent.attempt.kind is not EntityKind.ATTEMPT:
                raise RecoveryIntentStaleError("recovery attempt reference is invalid")
            with authority.read_transaction() as connection:
                row = connection.execute(
                    "SELECT * FROM attempts WHERE attempt_id = ?", (str(intent.attempt.entity_id),)
                ).fetchone()
                if row is None:
                    raise RecoveryIntentStaleError("recovery attempt is no longer present")
                from todo_orchestrator.authority.attempts import _attempt_from_row

                attempt = _attempt_from_row(authority.project, row)
            if attempt.work_item != intent.target:
                raise RecoveryIntentStaleError("recovery target differs from the exact stored attempt")
            return attempt.work_item, attempt.run, attempt.assignment, attempt.ref, attempt.lease
        if len(intent.operations) != 1 or intent.operations[0].kind is not EntityKind.EXTERNAL_OPERATION:
            raise RecoveryIntentStaleError("unattached recovery requires exactly one external operation")
        with authority.read_transaction() as connection:
            records = _operation_rows(connection, authority.project.project_id,
                                      operation_id=intent.operations[0].entity_id)
        if len(records) != 1:
            raise RecoveryIntentStaleError("the exact external operation is no longer present")
        target, run, assignment, attempt_ref, _workspace_id = self.inspection._operation_context(
            records[0], authority,
        )
        if target != intent.target or attempt_ref is not None:
            raise RecoveryIntentStaleError("unattached effect identity changed")
        return target, run, assignment, None, None

    def _authorize(self, authority: SQLiteAuthority, bearer_token: str, intent: RecoveryIntent):
        target, run, assignment, attempt, lease = self._context(authority, intent)
        digest = _token_digest(bearer_token)
        actor, capability_id = self.auth._actor_for_token(authority, digest)
        with authority.read_transaction() as connection:
            for action in (RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION):
                self.auth._authorize_capability(
                    connection, authority.project, digest, actor,
                    AuthorizationRequirement(action, target, run, assignment, attempt),
                )
        return actor, capability_id, target, run, assignment, attempt, lease

    def _inspect(self, authority: SQLiteAuthority, bearer_token: str,
                 intent: RecoveryIntent) -> RecoveryInspection:
        with SQLiteAuthority.open_reader(authority.path, authority.project) as reader:
            if intent.attempt is not None:
                return self.inspection.inspect_attempt(reader, bearer_token, intent.attempt)
            if len(intent.operations) != 1:
                raise RecoveryIntentStaleError("effect recovery requires exactly one operation reference")
            return self.inspection.inspect_effect(reader, bearer_token, intent.operations[0])

    @staticmethod
    def _matching_intent(view: RecoveryInspection, intent: RecoveryIntent) -> bool:
        return any(candidate == intent for candidate in view.intents)

    def _attempt_replay(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        intent: RecoveryIntent,
        idempotency_key: StableId,
        target: EntityRef,
        run: EntityRef | None,
        assignment: EntityRef | None,
        attempt: EntityRef,
    ) -> CommandResult | None:
        handoff = intent.kind is RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE
        if intent.kind is not RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT and not handoff:
            return None

        def matches(_connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
            if row["event_kind"] not in {
                "todo.attempt.recovery_released", "todo.attempt.recovery_workspace_handoff",
            } or row["event_id"] is None:
                return False
            try:
                import json

                payload = json.loads(row["payload_json"])
                result = json.loads(row["result_json"])
            except (TypeError, ValueError):
                return False
            return bool(
                payload.get("attempt_id") == str(attempt.entity_id)
                and payload.get("recovery") is True
                and payload.get("previous_lease_id") == str(intent.expected_lease_id)
                and payload.get("expected_source_digest") == (
                    None if intent.expected_source_digest is None else intent.expected_source_digest.hex
                )
                and payload.get("recovery_intent_digest") == _intent_digest(intent).hex
                and payload.get("workspace_preserved") is handoff
                and payload.get("workspace_id") == (
                    None if not handoff else str(intent.workspace_id)
                )
                and result.get("attempt_id") == str(attempt.entity_id)
            )

        return self.auth.replay_authorized(
            authority, bearer_token, idempotency_key,
            AuthorizationRequirement(RECOVERY_APPLY_ACTION, target, run, assignment, attempt),
            "todo.attempt.reconcile_expired", matches,
        )

    def apply(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        intent: RecoveryIntent,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> RecoveryApplyResult:
        if not isinstance(authority, SQLiteAuthority) or authority.readonly:
            raise TypeError("recovery apply requires an existing writable SQLiteAuthority")
        if not isinstance(intent, RecoveryIntent):
            raise TypeError("intent must be a RecoveryIntent returned by read-only inspection")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        actor, capability_id, target, run, assignment, attempt, lease = self._authorize(
            authority, bearer_token, intent,
        )
        operation_targeted = intent.kind in {
            RecoveryIntentKind.RETRY_ORIGINAL_OPERATION,
            RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT,
        }
        if operation_targeted and len(intent.operations) == 1:
            operation_ref = intent.operations[0]
            operation_kind = None
            with authority.read_transaction() as connection:
                operation_records = _operation_rows(
                    connection, authority.project.project_id, operation_id=operation_ref.entity_id,
                )
            if len(operation_records) == 1:
                operation_kind = (
                    "git" if operation_records[0].git is not None else
                    "verification" if operation_records[0].verification is not None else None
                )
            replay_service = self.git_effects if operation_kind == "git" else (
                self.verification if operation_kind == "verification" else None
            )
            replay_method = getattr(replay_service, "recovery_replay", None)
            if callable(replay_method):
                replayed_operation = replay_method(
                    authority, bearer_token, operation_ref, intent.kind.value, idempotency_key,
                    _intent_digest(intent),
                )
                if replayed_operation is not None:
                    return RecoveryApplyResult(
                        intent, actor, intent.kind.value, self.auth._revision(authority, None), True,
                        replayed_operation, _now(self.clock),
                    )
        replay = None if attempt is None else self._attempt_replay(
            authority, bearer_token, intent, idempotency_key, target, run, assignment, attempt,
        )
        if replay is not None:
            return RecoveryApplyResult(
                intent, actor, str(intent.kind.value), replay.receipt.semantic_revision, True,
                replay, _now(self.clock),
            )
        current_revision = self.auth._revision(authority, expected_revision)
        if current_revision != intent.expected_authority_revision:
            raise RecoveryIntentStaleError("authority changed after recovery intent inspection")
        if expected_revision is not None and expected_revision != intent.expected_authority_revision:
            raise RecoveryIntentStaleError("expected revision differs from the inspected recovery intent")
        view = self._inspect(authority, bearer_token, intent)
        if view.authority_revision != intent.expected_authority_revision or not self._matching_intent(view, intent):
            raise RecoveryIntentStaleError("recovery intent preconditions are no longer satisfied")

        operation = None
        if operation_targeted and intent.operations:
            operation = next((item for item in view.operations if item.operation == intent.operations[0]), None)
            if operation is None:
                raise RecoveryIntentStaleError("recovery operation is absent from the current inspection")
        observation = view.host_observation
        approval = _issue_recovery_approval(
            intent_kind=intent.kind.value,
            actor=actor,
            capability_id=capability_id,
            target=target,
            attempt=attempt,
            run=run,
            assignment=assignment,
            operation=None if not operation_targeted or operation is None else operation.operation,
            intent_digest=_intent_digest(intent),
            authority_revision=intent.expected_authority_revision,
            expected_lease_id=intent.expected_lease_id,
            expected_lease_expires_at=view.lease_expires_at,
            expected_source_digest=intent.expected_source_digest,
            host_observation=observation,
        )

        if intent.kind in {RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT,
                           RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE}:
            if attempt is None or intent.expected_lease_id is None:
                raise RecoveryIntentStaleError("attempt recovery requires its exact lease")
            command_result = self.attempts.reconcile_expired(
                authority, bearer_token, attempt,
                idempotency_key=idempotency_key,
                expected_revision=intent.expected_authority_revision,
                expected_lease_id=intent.expected_lease_id,
                expected_source_digest=intent.expected_source_digest,
                _recovery=True,
                _preserve_dirty_workspace=(intent.kind is RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE),
                _recovery_approval=approval,
            )
            result: object = command_result
            replayed = command_result.replayed
            semantic_revision = command_result.receipt.semantic_revision
        elif intent.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION:
            if operation is None:
                raise RecoveryIntentStaleError("retry intent does not identify a durable operation")
            if operation.kind == "verification":
                if self.verification is None:
                    raise RecoveryApplyProviderUnavailableError("verification recovery service is unavailable")
                result = self.verification.retry_not_started(
                    authority, bearer_token, operation.operation,
                    idempotency_key=idempotency_key,
                    expected_revision=intent.expected_authority_revision,
                    _recovery=True,
                    _recovery_approval=approval,
                )
            elif operation.kind == "git":
                if self.git_effects is None:
                    raise RecoveryApplyProviderUnavailableError("Git effect recovery service is unavailable")
                result = self.git_effects.retry_not_applied(
                    authority, bearer_token, StableId(str(operation.operation.entity_id)),
                    idempotency_key=idempotency_key,
                    expected_revision=intent.expected_authority_revision,
                    _recovery=True,
                    _recovery_approval=approval,
                )
            else:
                raise RecoveryApplyProviderUnavailableError("operation kind has no supported retry service")
            replayed = False
            semantic_revision = self.auth._revision(authority, None)
        elif intent.kind is RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT:
            if operation is None:
                raise RecoveryIntentStaleError("reconcile intent does not identify a durable operation")
            if operation.kind == "verification":
                if self.verification is None:
                    raise RecoveryApplyProviderUnavailableError("verification recovery service is unavailable")
                result = self.verification.reconcile(
                    authority, bearer_token, operation.operation,
                    idempotency_key=idempotency_key,
                    expected_revision=intent.expected_authority_revision,
                    _recovery=True,
                    _recovery_approval=approval,
                )
            elif operation.kind == "git":
                if self.git_effects is None:
                    raise RecoveryApplyProviderUnavailableError("Git effect recovery service is unavailable")
                result = self.git_effects.reconcile(
                    authority, bearer_token, StableId(str(operation.operation.entity_id)),
                    idempotency_key=idempotency_key,
                    expected_revision=intent.expected_authority_revision,
                    _recovery=True,
                    _recovery_approval=approval,
                )
            else:
                raise RecoveryApplyProviderUnavailableError("operation kind has no supported reconcile service")
            replayed = False
            semantic_revision = self.auth._revision(authority, None)
        else:
            raise RecoveryApplyError("unsupported recovery intent kind")
        return RecoveryApplyResult(
            intent, actor, intent.kind.value, semantic_revision, replayed, result, _now(self.clock),
        )


__all__ = [
    "RECOVERY_APPLY_ACTION_ID", "RecoveryApplyError", "RecoveryApplyProviderUnavailableError",
    "RecoveryApplyResult", "RecoveryExecutionService", "RecoveryIntentStaleError",
]
