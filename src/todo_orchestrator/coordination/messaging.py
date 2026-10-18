"""Authenticated, append-only scoped messages and deterministic inbox cursors.

Recipient membership controls delivery only. Every send, sync, read, and answer
still requires a current capability for the exact message scope and the
caller's own run/assignment/attempt context.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import sqlite3
from typing import Iterable

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeniedError,
    _actor_ref,
)
from todo_orchestrator.authority.commands import DuplicateCommandHandlerError, MutationContext
from todo_orchestrator.authority.sqlite import AuthorityError, InvalidAuthorityError, SQLiteAuthority
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, Sha256Digest, StableId
from todo_orchestrator.model import CommandEffect, CommandResult

from .payloads import PayloadRejectedError, validate_bounded_text


MESSAGE_SEND_ACTION = StableId("todo.message.send")
MESSAGE_READ_ACTION = StableId("todo.message.read")
QUESTION_ANSWER_ACTION = StableId("todo.question.answer")
# Decision/interface-change messages are informational notifications only. The
# authoritative records are written by DeclarationService under separate actions.
MESSAGE_TYPES = frozenset({"question", "decision", "interface_change", "status", "artifact", "conflict", "handoff"})


class MessagingError(AuthorityError):
    """Base error for authenticated coordination messaging."""


class MessageScopeError(MessagingError):
    """The message scope or context is absent, foreign, or inconsistent."""


class MessageNotFoundError(MessagingError):
    """A message is not deliverable to the authenticated actor."""


class AnswerConflictError(MessagingError):
    """A question already has an answer or cannot be answered by this actor."""


class CursorError(MessagingError):
    """A requested cursor advance is invalid or exceeds delivered messages."""


class MessageType(str, Enum):
    QUESTION = "question"
    ANSWER = "answer"
    DECISION = "decision"
    INTERFACE_CHANGE = "interface_change"
    STATUS = "status"
    ARTIFACT = "artifact"
    CONFLICT = "conflict"
    HANDOFF = "handoff"


@dataclass(frozen=True)
class MessageContentRef:
    artifact: EntityRef
    digest: Sha256Digest

    def __post_init__(self) -> None:
        if (not isinstance(self.artifact, EntityRef) or self.artifact.kind is not EntityKind.ARTIFACT
                or not isinstance(self.digest, Sha256Digest)):
            raise ValueError("content reference must be an artifact EntityRef and SHA-256 digest")


@dataclass(frozen=True)
class MessageView:
    sequence: int
    message_id: StableId
    project_id: StableId
    scope: EntityRef
    message_type: MessageType
    sender: EntityRef
    created_at: datetime
    context_run: EntityRef | None
    context_assignment: EntityRef | None
    context_attempt: EntityRef | None
    subject: str
    body: str | None
    content_ref: MessageContentRef | None
    reply_to: StableId | None


@dataclass(frozen=True)
class InboxStatus:
    scope: EntityRef
    recipient: EntityRef
    delivered_sequence: int
    read_sequence: int
    unread_count: int


@dataclass(frozen=True)
class InboxPage:
    messages: tuple[MessageView, ...]
    delivered_sequence: int
    read_sequence: int
    receipt: CommandResult


@dataclass(frozen=True)
class _Send:
    scope: EntityRef
    recipients: tuple[EntityRef, ...]
    message_type: MessageType
    subject: str
    body: str | None
    content_ref: MessageContentRef | None
    context_run: EntityRef | None
    context_assignment: EntityRef | None
    context_attempt: EntityRef | None
    message_id: StableId
    created_at: datetime


@dataclass(frozen=True)
class _Answer:
    question_id: StableId
    body: str | None
    content_ref: MessageContentRef | None
    context_run: EntityRef | None
    context_assignment: EntityRef | None
    context_attempt: EntityRef | None
    message_id: StableId
    scope: EntityRef
    recipients: tuple[EntityRef, ...]
    created_at: datetime


@dataclass(frozen=True)
class _Sync:
    scope: EntityRef
    context_run: EntityRef | None
    context_assignment: EntityRef | None
    context_attempt: EntityRef | None
    limit: int
    cursor_id: StableId


@dataclass(frozen=True)
class _MarkRead:
    scope: EntityRef
    context_run: EntityRef | None
    context_assignment: EntityRef | None
    context_attempt: EntityRef | None
    through_sequence: int
    cursor_id: StableId


def _scope_tuple(ref: EntityRef) -> tuple[str, str, str | None, str | None]:
    return (
        ref.kind.value,
        str(ref.entity_id),
        None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        None if ref.incarnation_id is None else str(ref.incarnation_id),
    )


def _context_tuple(run: EntityRef | None, assignment: EntityRef | None,
                   attempt: EntityRef | None) -> tuple[str | None, str | None, str | None]:
    return tuple(None if ref is None else str(ref.entity_id) for ref in (run, assignment, attempt))  # type: ignore[return-value]


def _ref_json(ref: EntityRef | None) -> dict[str, str | None] | None:
    if ref is None:
        return None
    return {
        "project_id": str(ref.project_id), "kind": ref.kind.value, "entity_id": str(ref.entity_id),
        "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _message_id(key: StableId, namespace: str) -> StableId:
    digest = hashlib.sha256((namespace + "\0" + str(key)).encode("utf-8")).hexdigest()
    return StableId(f"msg-{digest}")


def _cursor_id(actor: EntityRef, scope: EntityRef, run: EntityRef | None) -> StableId:
    raw = "\0".join((str(actor.project_id), str(actor.entity_id), str(actor.incarnation_id),
                      "" if run is None else str(run.entity_id),
                      *("" if part is None else part for part in _scope_tuple(scope))))
    return StableId("cursor-" + hashlib.sha256(raw.encode("utf-8")).hexdigest())


def _validate_context(
    project_id: StableId,
    scope: EntityRef,
    run: EntityRef | None,
    assignment: EntityRef | None,
    attempt: EntityRef | None,
) -> None:
    if scope.project_id != project_id:
        raise MessageScopeError("message scope belongs to another project")
    values = (run, assignment, attempt)
    if any(value is not None for value in values) and any(value is None for value in values):
        raise MessageScopeError("run, assignment, and attempt context must be supplied together")
    if run is not None:
        expected = (EntityKind.RUN, EntityKind.ASSIGNMENT, EntityKind.ATTEMPT)
        for value, kind in zip(values, expected):
            if value.kind is not kind or value.project_id != project_id:
                raise MessageScopeError("message context must contain project-local run, assignment, and attempt refs")


def _validate_context_rows(
    connection: sqlite3.Connection,
    project_id: StableId,
    scope: EntityRef,
    actor: EntityRef,
    run: EntityRef | None,
    assignment: EntityRef | None,
    attempt: EntityRef | None,
    *,
    require_live: bool = True,
) -> None:
    _validate_context(project_id, scope, run, assignment, attempt)
    if run is None:
        return
    row = connection.execute(
        "SELECT a.run_id, a.work_item_id, a.definition_revision_id, a.assignee_actor_id, "
        "a.assignee_incarnation_id, t.assignment_id, t.run_id AS attempt_run_id, "
        "t.work_item_id AS attempt_work_item_id, t.definition_revision_id AS attempt_definition_revision_id, "
        "t.state, t.actor_id, t.actor_incarnation_id "
        "FROM assignments AS a JOIN attempts AS t ON t.attempt_id = ? "
        "WHERE a.assignment_id = ? AND a.run_id = ?",
        (str(attempt.entity_id), str(assignment.entity_id), str(run.entity_id)),
    ).fetchone()
    if row is None or row["assignment_id"] != str(assignment.entity_id):
        raise MessageScopeError("attempt, assignment, and run context do not identify one persisted assignment")
    if (row["attempt_run_id"] != str(run.entity_id)
            or row["attempt_work_item_id"] != row["work_item_id"]
            or row["attempt_definition_revision_id"] != row["definition_revision_id"]):
        raise MessageScopeError("attempt is not bound to the supplied run assignment and exact work definition")
    if (row["actor_id"] != str(actor.entity_id)
            or row["actor_incarnation_id"] != str(actor.incarnation_id)):
        raise MessageScopeError("run context attempt belongs to a different actor incarnation")
    if scope.kind is EntityKind.WORK_ITEM and (
        scope.entity_id != StableId(row["work_item_id"])
        or scope.definition_revision_id != StableId(row["definition_revision_id"])
    ):
        raise MessageScopeError("attempt context does not match the exact work-item message scope")
    context_ref = {EntityKind.RUN: run, EntityKind.ASSIGNMENT: assignment,
                   EntityKind.ATTEMPT: attempt}.get(scope.kind)
    if context_ref is not None and scope != context_ref:
        raise MessageScopeError("attempt context does not match the exact message scope")
    if require_live and row["state"] not in {"admitted", "active", "reported"}:
        raise MessageScopeError("message context attempt is not live")
    if scope.kind in {
        EntityKind.WORK_ITEM, EntityKind.REQUIREMENT, EntityKind.CHECKPOINT,
        EntityKind.INTERFACE, EntityKind.BARRIER, EntityKind.DECISION, EntityKind.INVARIANT,
    }:
        from todo_orchestrator.authority.scopes import plan_scope_membership

        run_row = connection.execute(
            "SELECT plan_revision_id FROM runs WHERE run_id = ?", (str(run.entity_id),)
        ).fetchone()
        if run_row is None:
            raise MessageScopeError("run context is not persisted")
        plan_ref = EntityRef(project_id, EntityKind.PLAN_REVISION, StableId(run_row["plan_revision_id"]))
        if scope not in plan_scope_membership(connection, Project(project_id, StableId(
            connection.execute("SELECT authority_id FROM authority_meta WHERE singleton = 1").fetchone()[0]
        )), plan_ref):
            raise MessageScopeError("message scope is not a member of the run's exact accepted plan")


def _validate_scope_exists(connection: sqlite3.Connection, project_id: StableId, scope: EntityRef) -> None:
    if scope.project_id != project_id:
        raise MessageScopeError("message scope belongs to another project")
    if scope.kind is EntityKind.PROJECT:
        if scope.entity_id != project_id:
            raise MessageScopeError("project scope must name this authority project")
        return
    if scope.kind in {EntityKind.CHECKPOINT, EntityKind.INTERFACE, EntityKind.BARRIER, EntityKind.DECISION, EntityKind.INVARIANT}:
        from todo_orchestrator.planning import decode_accepted_plan
        from todo_orchestrator.authority.sqlite import load_plan_revision_snapshot
        revisions = connection.execute(
            "SELECT plan_revision_id, sequence FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC"
        ).fetchall()
        meta = connection.execute("SELECT project_id, authority_id FROM authority_meta WHERE singleton = 1").fetchone()
        if not revisions or meta is None:
            raise MessageScopeError("declaration message scope is not present in the current accepted plan")
        project = Project(StableId(meta["project_id"]), StableId(meta["authority_id"]))
        candidates = {"barrier", "rendezvous"} if scope.kind is EntityKind.BARRIER else {scope.kind.value + "s"}
        declared = False
        for revision in revisions:
            record = load_plan_revision_snapshot(connection, project, StableId(revision["plan_revision_id"]))
            plan = decode_accepted_plan(record.canonical_json, project, sequence=record.sequence or revision["sequence"])
            if any(item.kind in candidates and item.declaration_id == scope.entity_id for item in plan.declarations):
                declared = True
                break
        if not declared:
            raise MessageScopeError("declaration message scope is not present in the current accepted plan")
        return
    lookup: dict[EntityKind, tuple[str, str, str | None]] = {
        EntityKind.PLAN_REVISION: ("plan_revisions", "plan_revision_id", None),
        EntityKind.WORK_ITEM: ("work_items", "work_item_id", "definition_revision_id"),
        EntityKind.REQUIREMENT: ("requirements", "requirement_id", "definition_revision_id"),
        EntityKind.RUN: ("runs", "run_id", None),
        EntityKind.ASSIGNMENT: ("assignments", "assignment_id", None),
        EntityKind.ATTEMPT: ("attempts", "attempt_id", None),
        EntityKind.ACTOR: ("actors", "actor_id", "incarnation_id"),
        EntityKind.CAPABILITY: ("capabilities", "capability_id", None),
        EntityKind.EVIDENCE: ("evidence", "evidence_id", None),
        EntityKind.ARTIFACT: ("artifacts", "artifact_id", None),
        EntityKind.OUTCOME: ("outcomes", "outcome_id", None),
        EntityKind.EXTERNAL_OPERATION: ("external_operations", "operation_id", None),
    }
    item = lookup.get(scope.kind)
    if item is None:
        raise MessageScopeError("message scope kind is unsupported")
    table, id_column, version_column = item
    filters = [f"{id_column} = ?"]
    values: list[object] = [str(scope.entity_id)]
    if version_column is not None:
        field_value = scope.definition_revision_id if version_column == "definition_revision_id" else scope.incarnation_id
        filters.append(f"{version_column} = ?")
        values.append(str(field_value))
    if table == "actors":
        filters.append("incarnation_id = ?")
        values.append(str(scope.incarnation_id))
    sql = f"SELECT 1 FROM {table} WHERE " + " AND ".join(filters) + " LIMIT 1"
    if connection.execute(sql, values).fetchone() is None:
        raise MessageScopeError("message scope does not identify a persisted project-local entity")


def _validate_content(connection: sqlite3.Connection, project_id: StableId,
                      content_ref: MessageContentRef | None) -> None:
    if content_ref is None:
        return
    if content_ref.artifact.project_id != project_id:
        raise MessageScopeError("content artifact belongs to a different project")
    row = connection.execute(
        "SELECT content_digest FROM artifacts WHERE artifact_id = ?", (str(content_ref.artifact.entity_id),)
    ).fetchone()
    if row is None or row["content_digest"] != content_ref.digest.hex:
        raise MessageScopeError("content artifact digest is absent or does not match stored artifact provenance")


def _view(row: sqlite3.Row, project_id: StableId) -> MessageView:
    try:
        scope = EntityRef(
            project_id, EntityKind(row["scope_kind"]), StableId(row["scope_entity_id"]),
            definition_revision_id=(StableId(row["scope_definition_revision_id"])
                                    if row["scope_definition_revision_id"] else None),
            incarnation_id=(StableId(row["scope_incarnation_id"])
                            if row["scope_incarnation_id"] else None),
        )
        content = None
        if row["content_ref_entity_id"] is not None:
            content = MessageContentRef(
                EntityRef(project_id, EntityKind.ARTIFACT, StableId(row["content_ref_entity_id"])),
                Sha256Digest(row["content_digest"]),
            )
        return MessageView(
            int(row["sequence"]), StableId(row["message_id"]), project_id, scope,
            MessageType(row["message_type"]),
            _actor_ref_from_fields(project_id, row["sender_actor_id"], row["sender_incarnation_id"]),
            datetime.fromisoformat(row["created_at"]),
            None if row["context_run_id"] is None else EntityRef(project_id, EntityKind.RUN, StableId(row["context_run_id"])),
            None if row["context_assignment_id"] is None else EntityRef(project_id, EntityKind.ASSIGNMENT, StableId(row["context_assignment_id"])),
            None if row["context_attempt_id"] is None else EntityRef(project_id, EntityKind.ATTEMPT, StableId(row["context_attempt_id"])),
            row["subject"], row["body_text"], content,
            None if row["reply_to_message_id"] is None else StableId(row["reply_to_message_id"]),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise InvalidAuthorityError("stored coordination message is malformed") from exc


def _actor_ref_from_fields(project_id: StableId, actor_id: str, incarnation_id: str) -> EntityRef:
    return EntityRef(project_id, EntityKind.ACTOR, StableId(actor_id), incarnation_id=StableId(incarnation_id))


def _cursor_row(
    connection: sqlite3.Connection, actor: EntityRef, scope: EntityRef, run: EntityRef | None,
) -> sqlite3.Row | None:
    kind, entity_id, definition_id, incarnation_id = _scope_tuple(scope)
    return connection.execute(
        "SELECT * FROM coordination_message_cursors WHERE recipient_actor_id = ? "
        "AND recipient_incarnation_id = ? AND scope_kind = ? AND scope_entity_id = ? "
        "AND scope_definition_revision_id IS ? AND scope_incarnation_id IS ? AND context_run_id IS ?",
        (str(actor.entity_id), str(actor.incarnation_id), kind, entity_id, definition_id, incarnation_id,
         None if run is None else str(run.entity_id)),
    ).fetchone()


class _MessageHandler:
    kind = "todo.message.send"
    command_type = _Send
    action = MESSAGE_SEND_ACTION

    def authorization_requirement(self, command: _Send) -> AuthorizationRequirement:
        return AuthorizationRequirement(self.action, command.scope, command.context_run,
                                        command.context_assignment, command.context_attempt)

    def canonical_payload(self, command: _Send) -> dict[str, object]:
        return {
            "scope": _ref_json(command.scope), "recipients": [_ref_json(ref) for ref in command.recipients],
            "message_type": command.message_type.value, "subject": command.subject, "body": command.body,
            "content_ref": None if command.content_ref is None else {
                "artifact": _ref_json(command.content_ref.artifact), "digest": command.content_ref.digest.hex,
            }, "context": [_ref_json(item) for item in (
                command.context_run, command.context_assignment, command.context_attempt,
            )], "message_id": str(command.message_id),
        }

    def apply(self, context: MutationContext, command: _Send) -> CommandEffect:
        connection = context._connection
        validate_bounded_text(command.subject, field="subject", max_bytes=256,
                              connection=connection, allow_multiline=False)
        if command.body is not None:
            validate_bounded_text(command.body, field="body", connection=connection)
        _validate_scope_exists(connection, context.project.project_id, command.scope)
        _validate_context_rows(connection, context.project.project_id, command.scope, context.actor,
                               command.context_run, command.context_assignment, command.context_attempt,
                               require_live=False)
        _validate_content(connection, context.project.project_id, command.content_ref)
        for recipient in command.recipients:
            if recipient.project_id != context.project.project_id or recipient.kind is not EntityKind.ACTOR:
                raise MessageScopeError("recipients must be project-local actor incarnations")
            if connection.execute(
                "SELECT 1 FROM actors WHERE actor_id = ? AND incarnation_id = ?",
                (str(recipient.entity_id), str(recipient.incarnation_id)),
            ).fetchone() is None:
                raise MessageScopeError("recipient actor incarnation is not registered")
        if command.message_type is MessageType.QUESTION and not command.recipients:
            raise MessageScopeError("questions require at least one explicit recipient")
        self._insert(context, command, None)
        result = {"message_id": str(command.message_id)}
        return CommandEffect(True, result, "todo.message.sent", {
            "message_id": str(command.message_id), "message_type": command.message_type.value,
            "scope": _ref_json(command.scope), "recipient_count": len(command.recipients),
        })

    @staticmethod
    def _insert(context: MutationContext, command: _Send | _Answer, reply_to: str | None) -> int:
        scope = command.scope
        recipients = command.recipients
        message_type = command.message_type.value if isinstance(command, _Send) else "answer"
        subject = command.subject if isinstance(command, _Send) else "Answer"
        kind, entity_id, definition_id, incarnation_id = _scope_tuple(scope)
        run_id, assignment_id, attempt_id = _context_tuple(
            command.context_run, command.context_assignment, command.context_attempt
        )
        content = command.content_ref
        cursor = context.execute(
            "INSERT INTO coordination_messages(message_id, project_id, scope_kind, scope_entity_id, "
            "scope_definition_revision_id, scope_incarnation_id, message_type, sender_actor_id, "
            "sender_incarnation_id, created_at, context_run_id, context_assignment_id, context_attempt_id, "
            "subject, body_text, content_ref_project_id, content_ref_kind, content_ref_entity_id, "
            "content_ref_definition_revision_id, content_ref_incarnation_id, content_digest, reply_to_message_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(command.message_id), str(context.project.project_id), kind, entity_id, definition_id,
             incarnation_id, message_type, str(context.actor.entity_id), str(context.actor.incarnation_id),
             command.created_at.astimezone(timezone.utc).isoformat(),
             run_id, assignment_id, attempt_id, subject, command.body,
             None if content is None else str(content.artifact.project_id),
             None if content is None else content.artifact.kind.value,
             None if content is None else str(content.artifact.entity_id),
             None if content is None else None, None if content is None else None,
             None if content is None else content.digest.hex, reply_to),
        )
        for recipient in recipients:
            context.execute(
                "INSERT INTO coordination_message_recipients(message_id, recipient_actor_id, recipient_incarnation_id) "
                "VALUES (?, ?, ?)",
                (str(command.message_id), str(recipient.entity_id), str(recipient.incarnation_id)),
            )
        return int(cursor.lastrowid)


class _AnswerHandler:
    kind = "todo.question.answer"
    command_type = _Answer

    def authorization_requirement(self, command: _Answer) -> AuthorizationRequirement:
        return AuthorizationRequirement(QUESTION_ANSWER_ACTION, command.scope, command.context_run,
                                        command.context_assignment, command.context_attempt)

    def canonical_payload(self, command: _Answer) -> dict[str, object]:
        return {
            "question_id": str(command.question_id), "scope": _ref_json(command.scope), "body": command.body,
            "content_ref": None if command.content_ref is None else {
                "artifact": _ref_json(command.content_ref.artifact), "digest": command.content_ref.digest.hex,
            }, "context": [_ref_json(item) for item in (
                command.context_run, command.context_assignment, command.context_attempt,
            )], "message_id": str(command.message_id),
        }

    def apply(self, context: MutationContext, command: _Answer) -> CommandEffect:
        connection = context._connection
        if command.body is not None:
            validate_bounded_text(command.body, field="answer", connection=connection)
        question = connection.execute(
            "SELECT * FROM coordination_messages WHERE message_id = ? AND message_type = 'question'",
            (str(command.question_id),),
        ).fetchone()
        if question is None:
            raise MessageNotFoundError("question does not exist")
        scope = EntityRef(
            context.project.project_id, EntityKind(question["scope_kind"]), StableId(question["scope_entity_id"]),
            definition_revision_id=(StableId(question["scope_definition_revision_id"])
                                    if question["scope_definition_revision_id"] else None),
            incarnation_id=(StableId(question["scope_incarnation_id"])
                            if question["scope_incarnation_id"] else None),
        )
        if command.scope != scope:
            raise MessageScopeError("question scope changed before answer authorization")
        command = _Answer(
            command.question_id, command.body, command.content_ref, command.context_run,
            command.context_assignment, command.context_attempt, command.message_id, scope,
            (_actor_ref_from_fields(context.project.project_id, question["sender_actor_id"], question["sender_incarnation_id"]),),
            command.created_at,
        )
        if connection.execute(
            "SELECT 1 FROM coordination_message_recipients WHERE message_id = ? AND recipient_actor_id = ? "
            "AND recipient_incarnation_id = ?",
            (str(command.question_id), str(context.actor.entity_id), str(context.actor.incarnation_id)),
        ).fetchone() is None:
            raise MessageNotFoundError("question is not addressed to this actor incarnation")
        try:
            _validate_context_rows(connection, context.project.project_id, scope, context.actor,
                                   command.context_run, command.context_assignment, command.context_attempt)
            _validate_content(connection, context.project.project_id, command.content_ref)
        except MessageScopeError:
            raise
        question_run = question["context_run_id"]
        if (str(command.context_run.entity_id) if command.context_run else None) != question_run:
            raise MessageScopeError("answer must use the same run-binding class as its question")
        try:
            _MessageHandler._insert(context, command, str(command.question_id))
        except sqlite3.IntegrityError as exc:
            raise AnswerConflictError("question already has an answer") from exc
        return CommandEffect(True, {"message_id": str(command.message_id)}, "todo.question.answered", {
            "message_id": str(command.message_id), "question_id": str(command.question_id),
        })


class _CursorHandler:
    kind = "todo.message.cursor"
    command_type = (_Sync, _MarkRead)

    def __init__(self, service: "MessagingService", *, sync: bool) -> None:
        self.service = service
        self.sync = sync
        self.kind = "todo.message.sync" if sync else "todo.message.mark_read"
        self.command_type = _Sync if sync else _MarkRead

    def authorization_requirement(self, command: _Sync | _MarkRead) -> AuthorizationRequirement:
        action = MESSAGE_READ_ACTION
        return AuthorizationRequirement(action, command.scope, command.context_run,
                                        command.context_assignment, command.context_attempt)

    def canonical_payload(self, command: _Sync | _MarkRead) -> dict[str, object]:
        payload: dict[str, object] = {
            "scope": _ref_json(command.scope),
            "context_run": _ref_json(command.context_run),
            "context": [_ref_json(item) for item in (
                command.context_run, command.context_assignment, command.context_attempt,
            )],
        }
        if isinstance(command, _Sync):
            payload["limit"] = command.limit
        else:
            payload["through_sequence"] = command.through_sequence
        return payload

    def apply(self, context: MutationContext, command: _Sync | _MarkRead) -> CommandEffect:
        connection = context._connection
        _validate_scope_exists(connection, context.project.project_id, command.scope)
        _validate_context_rows(connection, context.project.project_id, command.scope, context.actor,
                               command.context_run, command.context_assignment, command.context_attempt)
        cursor = _cursor_row(connection, context.actor, command.scope, command.context_run)
        if cursor is None:
            delivered = read = 0
        else:
            delivered, read = int(cursor["delivered_sequence"]), int(cursor["read_sequence"])
        if isinstance(command, _Sync):
            kind, entity_id, definition_id, incarnation_id = _scope_tuple(command.scope)
            rows = connection.execute(
                "SELECT m.* FROM coordination_messages AS m JOIN coordination_message_recipients AS r USING(message_id) "
                "WHERE r.recipient_actor_id = ? AND r.recipient_incarnation_id = ? AND m.scope_kind = ? "
                "AND m.scope_entity_id = ? AND m.scope_definition_revision_id IS ? AND m.scope_incarnation_id IS ? "
                "AND m.context_run_id IS ? "
                "AND m.sequence > ? ORDER BY m.sequence LIMIT ?",
                (str(context.actor.entity_id), str(context.actor.incarnation_id), kind, entity_id,
                 definition_id, incarnation_id,
                 None if command.context_run is None else str(command.context_run.entity_id),
                 delivered, command.limit),
            ).fetchall()
            if rows:
                next_delivered = int(rows[-1]["sequence"])
                now = self.service.auth._now().astimezone(timezone.utc).isoformat()
                if cursor is None:
                    context.execute(
                        "INSERT INTO coordination_message_cursors(cursor_id, recipient_actor_id, "
                        "recipient_incarnation_id, scope_kind, scope_entity_id, scope_definition_revision_id, "
                        "scope_incarnation_id, context_run_id, delivered_sequence, read_sequence, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (str(command.cursor_id), str(context.actor.entity_id), str(context.actor.incarnation_id),
                         kind, entity_id, definition_id, incarnation_id,
                         None if command.context_run is None else str(command.context_run.entity_id), 0, 0, now),
                    )
                    context.execute(
                        "UPDATE coordination_message_cursors SET delivered_sequence = ?, updated_at = ? "
                        "WHERE cursor_id = ?",
                        (next_delivered, now, str(command.cursor_id)),
                    )
                else:
                    context.execute(
                        "UPDATE coordination_message_cursors SET delivered_sequence = ?, updated_at = ? "
                        "WHERE cursor_id = ?",
                        (next_delivered, now, cursor["cursor_id"]),
                    )
                return CommandEffect(True, {
                    "message_ids": [row["message_id"] for row in rows],
                    "delivered_sequence": next_delivered, "read_sequence": read,
                }, "todo.message.inbox_synced", {
                    "recipient": _ref_json(context.actor), "scope": _ref_json(command.scope),
                    "from_sequence": delivered, "through_sequence": next_delivered,
                    "message_count": len(rows),
                })
            return CommandEffect(False, {"message_ids": [], "delivered_sequence": delivered, "read_sequence": read})

        target = command.through_sequence
        if target < read or target > delivered:
            raise CursorError("read watermark must be monotonic and no greater than delivered sequence")
        if target > read:
            kind, entity_id, definition_id, incarnation_id = _scope_tuple(command.scope)
            exists = connection.execute(
                "SELECT 1 FROM coordination_messages m JOIN coordination_message_recipients r USING(message_id) "
                "WHERE m.sequence = ? AND r.recipient_actor_id = ? AND r.recipient_incarnation_id = ? "
                "AND m.scope_kind = ? AND m.scope_entity_id = ? "
                "AND m.scope_definition_revision_id IS ? AND m.scope_incarnation_id IS ? "
                "AND m.context_run_id IS ?",
                (target, str(context.actor.entity_id), str(context.actor.incarnation_id), kind, entity_id,
                 definition_id, incarnation_id,
                 None if command.context_run is None else str(command.context_run.entity_id)),
            ).fetchone()
            if exists is None:
                raise CursorError("read watermark must identify a delivered message in this recipient scope")
        if target == read:
            return CommandEffect(False, {"read_sequence": read, "delivered_sequence": delivered})
        now = self.service.auth._now().astimezone(timezone.utc).isoformat()
        if cursor is None:
            raise CursorError("cannot mark messages read before they are delivered")
        context.execute(
            "UPDATE coordination_message_cursors SET read_sequence = ?, updated_at = ? WHERE cursor_id = ?",
            (target, now, cursor["cursor_id"]),
        )
        return CommandEffect(True, {"read_sequence": target, "delivered_sequence": delivered},
                             "todo.message.inbox_read", {
            "recipient": _ref_json(context.actor), "scope": _ref_json(command.scope), "through_sequence": target,
        })


class MessagingService:
    """Append-only message/question service with per-incarnation inbox cursors."""

    def __init__(self, auth: AuthorityAuthService) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        self.auth = auth
        for handler in (_MessageHandler(), _AnswerHandler(),
                        _CursorHandler(self, sync=True), _CursorHandler(self, sync=False)):
            try:
                auth.dispatcher.register(handler)
            except DuplicateCommandHandlerError:
                binding = auth.dispatcher._by_type.get(handler.command_type)
                if binding is None or type(binding.handler) is not type(handler):
                    raise

    def send(
        self, authority: SQLiteAuthority, bearer_token: str, scope: EntityRef,
        recipients: Iterable[EntityRef], *, message_type: MessageType = MessageType.STATUS,
        subject: str, body: str | None = None, content_ref: MessageContentRef | None = None,
        context_run: EntityRef | None = None, context_assignment: EntityRef | None = None,
        context_attempt: EntityRef | None = None, idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        if not isinstance(scope, EntityRef) or not isinstance(message_type, MessageType):
            raise TypeError("scope and message_type must be typed values")
        if message_type.value not in MESSAGE_TYPES:
            raise ValueError("message_type is not a sendable informational message type")
        recipient_tuple = tuple(recipients)
        if any(not isinstance(ref, EntityRef) for ref in recipient_tuple):
            raise TypeError("recipients must contain EntityRef values")
        if len(set(recipient_tuple)) != len(recipient_tuple):
            raise ValueError("recipients must be unique actor incarnations")
        if any(ref.kind is not EntityKind.ACTOR for ref in recipient_tuple):
            raise ValueError("recipients must be actor references")
        if not recipient_tuple:
            raise ValueError("messages require at least one explicit recipient")
        subject = validate_bounded_text(subject, field="subject", max_bytes=256, allow_multiline=False)
        if body is None and content_ref is None:
            raise ValueError("a message must include body text or an artifact content reference")
        if body is not None:
            body = validate_bounded_text(body, field="body")
        if content_ref is not None and not isinstance(content_ref, MessageContentRef):
            raise TypeError("content_ref must be a MessageContentRef")
        _validate_context(authority.project.project_id, scope, context_run, context_assignment, context_attempt)
        command = _Send(scope, recipient_tuple, message_type, subject, body, content_ref,
                        context_run, context_assignment, context_attempt, _message_id(idempotency_key, "send"),
                        self.auth._now())
        return self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                 expected_revision=expected_revision)

    def ask(self, authority: SQLiteAuthority, bearer_token: str, scope: EntityRef,
            recipients: Iterable[EntityRef], *, subject: str, body: str | None = None,
            content_ref: MessageContentRef | None = None, context_run: EntityRef | None = None,
            context_assignment: EntityRef | None = None, context_attempt: EntityRef | None = None,
            idempotency_key: StableId, expected_revision: int | None = None) -> CommandResult:
        return self.send(
            authority, bearer_token, scope, recipients, message_type=MessageType.QUESTION,
            subject=subject, body=body, content_ref=content_ref, context_run=context_run,
            context_assignment=context_assignment, context_attempt=context_attempt,
            idempotency_key=idempotency_key, expected_revision=expected_revision,
        )

    def answer(
        self, authority: SQLiteAuthority, bearer_token: str, question: MessageView | StableId, *,
        body: str | None = None, content_ref: MessageContentRef | None = None,
        context_run: EntityRef | None = None, context_assignment: EntityRef | None = None,
        context_attempt: EntityRef | None = None, idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        if isinstance(question, MessageView):
            if question.project_id != authority.project.project_id or question.message_type is not MessageType.QUESTION:
                raise MessageNotFoundError("question is unavailable to this authority")
            question_id = question.message_id
        else:
            question_id = question
        if not isinstance(question_id, StableId):
            raise TypeError("question must be a StableId or EntityRef")
        if body is None and content_ref is None:
            raise ValueError("an answer must include body text or an artifact content reference")
        if body is not None:
            body = validate_bounded_text(body, field="answer")
        if content_ref is not None and not isinstance(content_ref, MessageContentRef):
            raise TypeError("content_ref must be a MessageContentRef")
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM coordination_messages WHERE message_id = ? AND message_type = 'question'",
                (str(question_id),),
            ).fetchone()
            if row is None:
                raise MessageNotFoundError("question does not exist")
            scope = EntityRef(
                authority.project.project_id, EntityKind(row["scope_kind"]), StableId(row["scope_entity_id"]),
                definition_revision_id=(StableId(row["scope_definition_revision_id"])
                                        if row["scope_definition_revision_id"] else None),
                incarnation_id=(StableId(row["scope_incarnation_id"])
                                if row["scope_incarnation_id"] else None),
            )
            recipients = (_actor_ref_from_fields(
                authority.project.project_id, row["sender_actor_id"], row["sender_incarnation_id"]
            ),)
        _validate_context(authority.project.project_id, scope, context_run, context_assignment, context_attempt)
        bound = _Answer(question_id, body, content_ref, context_run, context_assignment, context_attempt,
                        _message_id(idempotency_key, "answer"), scope, recipients, self.auth._now())
        try:
            return self.auth.execute(authority, bearer_token, bound, idempotency_key=idempotency_key,
                                     expected_revision=expected_revision)
        except CapabilityDeniedError as exc:
            # The pre-read only derives the immutable question scope. Do not
            # reveal whether a guessed ID exists to a caller lacking rights.
            raise MessageNotFoundError("question is unavailable to this actor") from exc

    def sync_inbox(
        self, authority: SQLiteAuthority, bearer_token: str, scope: EntityRef, *,
        context_run: EntityRef | None = None, context_assignment: EntityRef | None = None,
        context_attempt: EntityRef | None = None, limit: int = 50, idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> InboxPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be from 1 through 100")
        _validate_context(authority.project.project_id, scope, context_run, context_assignment, context_attempt)
        actor, _ = self.auth._actor_for_token(authority, _token_digest_for_service(bearer_token))
        command = _Sync(scope, context_run, context_assignment, context_attempt, limit,
                        _cursor_id(actor, scope, context_run))
        result = self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                   expected_revision=expected_revision)
        ids = tuple(result.receipt.result.get("message_ids", ()))
        with authority.read_transaction() as connection:
            rows = []
            for message_id in ids:
                row = connection.execute(
                    "SELECT m.* FROM coordination_messages m JOIN coordination_message_recipients r USING(message_id) "
                    "WHERE m.message_id = ? AND r.recipient_actor_id = ? AND r.recipient_incarnation_id = ? "
                    "AND m.context_run_id IS ?",
                    (message_id, str(actor.entity_id), str(actor.incarnation_id),
                     None if context_run is None else str(context_run.entity_id)),
                ).fetchone()
                if row is None:
                    raise InvalidAuthorityError("synced message is no longer delivered to the recipient")
                rows.append(_view(row, authority.project.project_id))
            delivered = int(result.receipt.result.get("delivered_sequence", 0))
            read = int(result.receipt.result.get("read_sequence", 0))
        return InboxPage(tuple(rows), delivered, read, result)

    def mark_read(
        self, authority: SQLiteAuthority, bearer_token: str, scope: EntityRef, *,
        through_sequence: int, context_run: EntityRef | None = None,
        context_assignment: EntityRef | None = None, context_attempt: EntityRef | None = None,
        idempotency_key: StableId, expected_revision: int | None = None,
    ) -> CommandResult:
        if type(through_sequence) is not int or through_sequence < 0:
            raise ValueError("through_sequence must be a non-negative integer")
        _validate_context(authority.project.project_id, scope, context_run, context_assignment, context_attempt)
        actor, _ = self.auth._actor_for_token(authority, _token_digest_for_service(bearer_token))
        command = _MarkRead(scope, context_run, context_assignment, context_attempt,
                            through_sequence, _cursor_id(actor, scope, context_run))
        return self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                 expected_revision=expected_revision)

    def inbox_status(self, authority: SQLiteAuthority, bearer_token: str, scope: EntityRef, *,
                     context_run: EntityRef | None = None, context_assignment: EntityRef | None = None,
                     context_attempt: EntityRef | None = None) -> InboxStatus:
        _validate_context(authority.project.project_id, scope, context_run, context_assignment, context_attempt)
        digest = _token_digest_for_service(bearer_token)
        actor, _ = self.auth._actor_for_token(authority, digest)
        requirement = AuthorizationRequirement(MESSAGE_READ_ACTION, scope, context_run, context_assignment, context_attempt)
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, digest, actor, requirement)
            _validate_scope_exists(connection, authority.project.project_id, scope)
            _validate_context_rows(connection, authority.project.project_id, scope, actor,
                                   context_run, context_assignment, context_attempt, require_live=False)
            cursor = _cursor_row(connection, actor, scope, context_run)
            delivered = 0 if cursor is None else int(cursor["delivered_sequence"])
            read = 0 if cursor is None else int(cursor["read_sequence"])
            kind, entity_id, definition_id, incarnation_id = _scope_tuple(scope)
            unread = connection.execute(
                "SELECT COUNT(*) FROM coordination_messages m JOIN coordination_message_recipients r USING(message_id) "
                "WHERE r.recipient_actor_id = ? AND r.recipient_incarnation_id = ? AND m.scope_kind = ? "
                "AND m.scope_entity_id = ? AND m.scope_definition_revision_id IS ? AND m.scope_incarnation_id IS ? "
                "AND m.context_run_id IS ? AND m.sequence > ?",
                (str(actor.entity_id), str(actor.incarnation_id), kind, entity_id, definition_id,
                 incarnation_id, None if context_run is None else str(context_run.entity_id), read),
            ).fetchone()[0]
            return InboxStatus(scope, actor, delivered, read, int(unread))


def _token_digest_for_service(token: str) -> str:
    from todo_orchestrator.authority.auth import _token_digest

    return _token_digest(token)


__all__ = [
    "AnswerConflictError", "CursorError", "InboxPage", "InboxStatus", "MESSAGE_READ_ACTION",
    "MESSAGE_SEND_ACTION", "MESSAGE_TYPES", "MessageContentRef", "MessageNotFoundError", "MessageScopeError",
    "MessageType", "MessageView", "MessagingError", "MessagingService", "PayloadRejectedError",
    "QUESTION_ANSWER_ACTION",
]
