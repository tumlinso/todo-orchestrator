"""Atomic typed commands, receipts, events, history, and state fingerprints.

Registered handlers are trusted engine code. Request objects never contain SQL
or scripts; handlers receive a transaction-scoped context that permits only
single statements against semantic tables and blocks dispatcher-owned state.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import sqlite3
from typing import Any
from uuid import uuid4

from todo_orchestrator.contracts import EntityKind, EntityRef, Project, StableId
from todo_orchestrator.model import (
    AuthorityDelta,
    CommandEffect,
    CommandEnvelope,
    CommandHandler,
    CommandReceipt,
    CommandResult,
    HistoryEvent,
)

from .sqlite import AuthorityError, ReadOnlyAuthorityError, SCHEMA_VERSION, SQLiteAuthority, _REQUIRED_TABLES


class CommandDispatchError(AuthorityError):
    """Base class for typed command dispatch failures."""


class DuplicateCommandHandlerError(CommandDispatchError):
    """A command kind or typed command is already registered."""


class UnknownCommandHandlerError(CommandDispatchError):
    """No trusted handler is registered for the typed command."""


class IdempotencyConflictError(CommandDispatchError):
    """An idempotency key was reused with a different request digest."""


class StaleAuthorityRevisionError(CommandDispatchError):
    """The command's expected semantic revision is not current."""


class CommandActorNotRegisteredError(CommandDispatchError):
    """The command actor incarnation is not registered in this authority."""


class CommandHandlerContractError(CommandDispatchError):
    """A trusted handler violated the mutation/no-op contract."""


_DISPATCHER_OWNED_TABLES = frozenset({
    "authority_meta", "authority_events", "command_receipts", "command_idempotency",
    "sqlite_master", "sqlite_schema", "sqlite_sequence",
})

_BLOCKED_ACTION_NAMES = (
    "SQLITE_TRANSACTION", "SQLITE_SAVEPOINT", "SQLITE_PRAGMA", "SQLITE_ATTACH", "SQLITE_DETACH",
    "SQLITE_ALTER_TABLE", "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE", "SQLITE_CREATE_TEMP_INDEX",
    "SQLITE_CREATE_TEMP_TABLE", "SQLITE_CREATE_TEMP_TRIGGER", "SQLITE_CREATE_TEMP_VIEW",
    "SQLITE_CREATE_TRIGGER", "SQLITE_CREATE_VIEW", "SQLITE_CREATE_VTABLE", "SQLITE_DROP_INDEX",
    "SQLITE_DROP_TABLE", "SQLITE_DROP_TEMP_INDEX", "SQLITE_DROP_TEMP_TABLE", "SQLITE_DROP_TEMP_TRIGGER",
    "SQLITE_DROP_TEMP_VIEW", "SQLITE_DROP_TRIGGER", "SQLITE_DROP_VIEW", "SQLITE_DROP_VTABLE",
    "SQLITE_REINDEX", "SQLITE_ANALYZE",
)
_BLOCKED_SQLITE_ACTIONS = frozenset(
    getattr(sqlite3, name) for name in _BLOCKED_ACTION_NAMES if hasattr(sqlite3, name)
)
_DML_SQLITE_ACTIONS = frozenset({sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE})
_FINGERPRINT_EXCLUDED_TABLES = frozenset({
    "authority_meta", "authority_events", "command_receipts", "command_idempotency",
})
_FINGERPRINT_TABLES = tuple(sorted(_REQUIRED_TABLES - _FINGERPRINT_EXCLUDED_TABLES))


def _json_value(value: object, name: str = "JSON value") -> object:
    if value is None or type(value) in {str, bool, int}:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError(f"{name} must not contain non-finite numbers")
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{name} object keys must be strings")
            result[key] = _json_value(child, name)
        return result
    if isinstance(value, (list, tuple)):
        return [_json_value(child, name) for child in value]
    raise TypeError(f"{name} contains a non-JSON value: {type(value).__name__}")


def _canonical_object(value: Mapping[str, object], name: str) -> tuple[dict[str, object], str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a JSON object mapping")
    normalized = _json_value(value, name)
    if not isinstance(normalized, dict):
        raise TypeError(f"{name} must be a JSON object mapping")
    encoded = json.dumps(normalized, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return normalized, encoded


def _decode_object(encoded: str, name: str) -> dict[str, object]:
    try:
        value = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise CommandHandlerContractError(f"stored {name} is not valid JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise CommandHandlerContractError(f"stored {name} is not a JSON object")
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _request_digest(
    *, kind: str, payload_json: str, actor: EntityRef, expected_revision: int
) -> str:
    request = {
        "actor": {
            "project_id": str(actor.project_id),
            "actor_id": str(actor.entity_id),
            "incarnation_id": str(actor.incarnation_id),
        },
        "command_kind": kind,
        "expected_revision": expected_revision,
        "payload": json.loads(payload_json),
    }
    canonical = json.dumps(request, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _receipt_from_row(row: sqlite3.Row) -> CommandReceipt:
    try:
        actor = EntityRef(
            StableId(row["project_id"]),
            EntityKind.ACTOR,
            StableId(row["actor_id"]),
            incarnation_id=StableId(row["actor_incarnation_id"]),
        )
        created_at = datetime.fromisoformat(row["created_at"])
        return CommandReceipt(
            receipt_id=StableId(row["receipt_id"]),
            command_kind=row["command_kind"],
            semantic_revision=row["semantic_revision"],
            changed=bool(row["changed"]),
            event_id=StableId(row["event_id"]) if row["event_id"] is not None else None,
            actor=actor,
            result=_decode_object(row["result_json"], "command receipt"),
            created_at=created_at,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CommandHandlerContractError(f"stored command receipt is invalid: {exc}") from exc


def _history_event_from_row(row: sqlite3.Row, project: Project) -> HistoryEvent:
    try:
        actor = EntityRef(
            project.project_id,
            EntityKind.ACTOR,
            StableId(row["actor_id"]),
            incarnation_id=StableId(row["actor_incarnation_id"]),
        )
        return HistoryEvent(
            event_id=StableId(row["event_id"]),
            semantic_revision=row["semantic_revision"],
            event_ordinal=row["event_ordinal"],
            event_kind=row["event_kind"],
            payload=_decode_object(row["payload_json"], "authority event"),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            actor=actor,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CommandHandlerContractError(f"stored authority event is invalid: {exc}") from exc


@dataclass(frozen=True)
class _HandlerBinding:
    kind: str
    command_type: type[Any]
    handler: CommandHandler[Any]


class MutationContext:
    """Short-lived, single-transaction interface for trusted domain handlers.

    `execute` runs one statement with bound values. Dispatcher metadata, event,
    receipt, idempotency, PRAGMA, transaction, and schema operations are denied
    while the handler runs. The handler controls SQL templates; the request does
    not.
    """

    __slots__ = (
        "project", "actor", "starting_revision", "authority", "idempotency_key",
        "authorized_capability_id", "_connection", "_active",
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        project: Project,
        actor: EntityRef,
        starting_revision: int,
        authority: SQLiteAuthority,
        idempotency_key: StableId,
        authorized_capability_id: StableId | None = None,
    ) -> None:
        self.project = project
        self.actor = actor
        self.starting_revision = starting_revision
        self.authority = authority
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        self.idempotency_key = idempotency_key
        if authorized_capability_id is not None and not isinstance(authorized_capability_id, StableId):
            raise TypeError("authorized_capability_id must be a StableId or None")
        self.authorized_capability_id = authorized_capability_id
        self._connection = connection
        self._active = True

    def execute(
        self,
        statement: str,
        parameters: Sequence[object] | Mapping[str, object] = (),
    ) -> sqlite3.Cursor:
        """Run one handler-owned SQL statement with bound request values."""

        if not self._active:
            raise CommandHandlerContractError("mutation context is no longer active")
        if not isinstance(statement, str) or not statement.strip():
            raise TypeError("statement must be non-empty text")
        if not isinstance(parameters, (Sequence, Mapping)) or isinstance(parameters, (str, bytes, bytearray)):
            raise TypeError("parameters must be a sequence or mapping of bound values")
        return self._connection.execute(statement, parameters)

    def _deactivate(self) -> None:
        self._active = False


def _handler_authorizer(action: int, first: str | None, second: str | None, _database: str | None, _source: str | None) -> int:
    if action in _BLOCKED_SQLITE_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action in _DML_SQLITE_ACTIONS and first is not None and first.lower() in _DISPATCHER_OWNED_TABLES:
        return sqlite3.SQLITE_DENY
    if action == getattr(sqlite3, "SQLITE_FUNCTION", -1) and (second or first or "").lower() == "load_extension":
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _authorization_authorizer(action: int, first: str | None, second: str | None, database: str | None, source: str | None) -> int:
    if action in _DML_SQLITE_ACTIONS:
        return sqlite3.SQLITE_DENY
    return _handler_authorizer(action, first, second, database, source)


class CommandDispatcher:
    """Dispatch trusted typed handlers in atomic authority transactions."""

    def __init__(self, handlers: Sequence[CommandHandler[Any]] = ()) -> None:
        self._by_kind: dict[str, _HandlerBinding] = {}
        self._by_type: dict[type[Any], _HandlerBinding] = {}
        for handler in handlers:
            self.register(handler)

    def register(self, handler: CommandHandler[Any]) -> None:
        """Register trusted engine code for one exact command type and kind."""

        kind = getattr(handler, "kind", None)
        command_type = getattr(handler, "command_type", None)
        if not isinstance(kind, str) or not callable(getattr(handler, "canonical_payload", None)) or not callable(
            getattr(handler, "apply", None)
        ):
            raise TypeError("handler must define kind, command_type, canonical_payload, and apply")
        StableId(kind)
        if not isinstance(command_type, type):
            raise TypeError("handler command_type must be a type")
        if kind in self._by_kind or command_type in self._by_type:
            raise DuplicateCommandHandlerError(f"command kind or type is already registered: {kind}")
        binding = _HandlerBinding(kind, command_type, handler)
        self._by_kind[kind] = binding
        self._by_type[command_type] = binding

    def _binding(self, command: object) -> _HandlerBinding:
        try:
            return self._by_type[type(command)]
        except KeyError as exc:
            raise UnknownCommandHandlerError(
                f"no trusted command handler is registered for {type(command).__name__}"
            ) from exc

    def execute(self, authority: SQLiteAuthority, envelope: CommandEnvelope[Any]) -> CommandResult:
        """Run trusted internal code; this entry point does not authenticate callers."""
        return self._execute(authority, envelope, None)

    def _execute_authorized(
        self,
        authority: SQLiteAuthority,
        envelope: CommandEnvelope[Any],
        authorization_check: Callable[[sqlite3.Connection, Any, CommandHandler[Any], EntityRef], None],
    ) -> CommandResult:
        """Service seam: check current credentials under the writer lock, even on retries.

        The trusted service callback receives the same private command snapshot
        used for digesting and applying the command. It must raise on refusal
        and may only read authority state.
        """
        if not callable(authorization_check):
            raise TypeError("authorization_check must be callable")
        return self._execute(authority, envelope, authorization_check)

    def _execute(
        self,
        authority: SQLiteAuthority,
        envelope: CommandEnvelope[Any],
        authorization_check: Callable[[sqlite3.Connection, Any, CommandHandler[Any], EntityRef], None] | None,
    ) -> CommandResult:

        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if authority.readonly:
            raise ReadOnlyAuthorityError("cannot execute commands through a read-only authority")
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be a CommandEnvelope")
        # Own one snapshot before hashing. The caller may hold a mutable
        # command object and change it while a handler is preparing the write;
        # digesting and applying separate observations would bind the receipt
        # to a request different from the effect that actually ran.
        command = deepcopy(envelope.command)
        binding = self._binding(command)
        if envelope.actor.project_id != authority.project.project_id:
            raise CommandDispatchError("command actor belongs to a different project")

        canonical_payload, payload_json = _canonical_object(
            binding.handler.canonical_payload(command), "command payload"
        )
        del canonical_payload  # The canonical string is used for digesting and is never dispatched as SQL.
        digest = _request_digest(
            kind=binding.kind,
            payload_json=payload_json,
            actor=envelope.actor,
            expected_revision=envelope.expected_revision,
        )

        with authority.write_transaction() as connection:
            authorized_capability_id: StableId | None = None
            if authorization_check is not None:
                before_authorization = connection.total_changes
                try:
                    connection.set_authorizer(_authorization_authorizer)
                    authorization_result = authorization_check(connection, command, binding.handler, envelope.actor)
                finally:
                    connection.set_authorizer(None)
                if connection.total_changes != before_authorization:
                    raise CommandHandlerContractError("authorization checks must not mutate authority state")
                if authorization_result is not None and not isinstance(authorization_result, StableId):
                    raise CommandHandlerContractError(
                        "authorization checks must return None or the authenticated capability ID"
                    )
                authorized_capability_id = authorization_result
            existing = connection.execute(
                "SELECT i.request_digest, r.receipt_id, r.command_kind, r.semantic_revision, r.changed, "
                "r.event_id, r.actor_id, r.actor_incarnation_id, r.result_json, r.created_at, m.project_id "
                "FROM command_idempotency AS i "
                "JOIN command_receipts AS r ON r.receipt_id = i.receipt_id "
                "CROSS JOIN authority_meta AS m WHERE i.idempotency_key = ? AND m.singleton = 1",
                (str(envelope.idempotency_key),),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != digest:
                    raise IdempotencyConflictError(
                        f"idempotency key {envelope.idempotency_key} is bound to a different request"
                    )
                return CommandResult(_receipt_from_row(existing), replayed=True)

            revision_row = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()
            if revision_row is None:
                raise CommandHandlerContractError("authority semantic revision is missing")
            current_revision = revision_row[0]
            if current_revision != envelope.expected_revision:
                raise StaleAuthorityRevisionError(
                    f"expected semantic revision {envelope.expected_revision}, current revision is {current_revision}"
                )

            actor_row = connection.execute(
                "SELECT 1 FROM actors WHERE actor_id = ? AND incarnation_id = ?",
                (str(envelope.actor.entity_id), str(envelope.actor.incarnation_id)),
            ).fetchone()
            bootstrap_actor = (
                actor_row is None
                and getattr(binding.handler, "allows_unregistered_actor", False) is True
                and connection.execute("SELECT 1 FROM actors LIMIT 1").fetchone() is None
            )
            if actor_row is None and not bootstrap_actor:
                raise CommandActorNotRegisteredError(
                    f"actor incarnation is not registered: {envelope.actor.entity_id}/{envelope.actor.incarnation_id}"
                )

            before_changes = connection.total_changes
            context = MutationContext(
                connection, authority.project, envelope.actor, current_revision, authority,
                envelope.idempotency_key, authorized_capability_id,
            )
            try:
                connection.set_authorizer(_handler_authorizer)
                effect = binding.handler.apply(context, command)
            finally:
                connection.set_authorizer(None)
                context._deactivate()

            if not isinstance(effect, CommandEffect):
                raise CommandHandlerContractError("command handler must return a CommandEffect")
            semantic_writes = connection.total_changes - before_changes
            if effect.changed and semantic_writes <= 0:
                raise CommandHandlerContractError("handler reported a change without changing semantic rows")
            if not effect.changed and semantic_writes != 0:
                raise CommandHandlerContractError("handler changed semantic rows but reported a no-op")

            result_value, result_json = _canonical_object(effect.result, "command result")
            del result_value
            event_id: str | None = None
            event_json: str | None = None
            semantic_revision = current_revision
            now = _now()
            if effect.changed:
                event_id = "event-" + uuid4().hex
                _, event_json = _canonical_object(effect.event_payload, "event payload")  # type: ignore[arg-type]
                semantic_revision = current_revision + 1
                updated = connection.execute(
                    "UPDATE authority_meta SET semantic_revision = ? "
                    "WHERE singleton = 1 AND semantic_revision = ?",
                    (semantic_revision, current_revision),
                )
                if updated.rowcount != 1:
                    raise StaleAuthorityRevisionError("authority revision changed during command execution")
                connection.execute(
                    "INSERT INTO authority_events(event_id, semantic_revision, event_ordinal, event_kind, "
                    "payload_json, occurred_at, actor_id, actor_incarnation_id) "
                    "VALUES (?, ?, 0, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        semantic_revision,
                        effect.event_kind,
                        event_json,
                        _iso_time(now),
                        str(envelope.actor.entity_id),
                        str(envelope.actor.incarnation_id),
                    ),
                )

            receipt_id = "receipt-" + uuid4().hex
            connection.execute(
                "INSERT INTO command_receipts(receipt_id, command_kind, semantic_revision, changed, event_id, "
                "actor_id, actor_incarnation_id, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt_id,
                    binding.kind,
                    semantic_revision,
                    int(effect.changed),
                    event_id,
                    str(envelope.actor.entity_id),
                    str(envelope.actor.incarnation_id),
                    result_json,
                    _iso_time(now),
                ),
            )
            connection.execute(
                "INSERT INTO command_idempotency(idempotency_key, request_digest, receipt_id) VALUES (?, ?, ?)",
                (str(envelope.idempotency_key), digest, receipt_id),
            )
            receipt = CommandReceipt(
                receipt_id=StableId(receipt_id),
                command_kind=binding.kind,
                semantic_revision=semantic_revision,
                changed=effect.changed,
                event_id=StableId(event_id) if event_id is not None else None,
                actor=envelope.actor,
                result=_decode_object(result_json, "command result"),
                created_at=now,
            )
            return CommandResult(receipt, replayed=False)

    def delta(self, authority: SQLiteAuthority, since_revision: int = 0) -> AuthorityDelta:
        """Return a stable revision-bounded event delta from one read snapshot."""

        if type(since_revision) is not int or since_revision < 0:
            raise ValueError("since_revision must be a non-negative integer")
        with authority.read_transaction() as connection:
            revision_row = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()
            if revision_row is None:
                raise CommandHandlerContractError("authority semantic revision is missing")
            current_revision = revision_row[0]
            if since_revision > current_revision:
                raise ValueError("since_revision cannot exceed the current semantic revision")
            rows = connection.execute(
                "SELECT event_id, semantic_revision, event_ordinal, event_kind, payload_json, occurred_at, "
                "actor_id, actor_incarnation_id FROM authority_events "
                "WHERE semantic_revision > ? AND semantic_revision <= ? "
                "ORDER BY semantic_revision, event_ordinal, event_id",
                (since_revision, current_revision),
            ).fetchall()
            events = tuple(_history_event_from_row(row, authority.project) for row in rows)
        return AuthorityDelta(since_revision, current_revision, events)

    def history(self, authority: SQLiteAuthority, after_revision: int = 0) -> tuple[HistoryEvent, ...]:
        """Return committed events in semantic revision order."""

        return self.delta(authority, after_revision).events

    def logical_fingerprint(self, authority: SQLiteAuthority) -> str:
        """Hash normalized semantic rows, independent of SQLite/WAL page layout.

        Event and command receipt tables are intentionally excluded: history is
        queried explicitly, while no-op receipts must not change the logical
        state fingerprint.
        """

        with authority.read_transaction() as connection:
            meta = connection.execute(
                "SELECT project_id, authority_id, semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()
            if meta is None:
                raise CommandHandlerContractError("authority metadata row is missing")
            tables: list[dict[str, object]] = []
            for table in _FINGERPRINT_TABLES:
                columns = [row["name"] for row in connection.execute(f'PRAGMA table_info("{table}")')]
                if not columns:
                    raise CommandHandlerContractError(f"fingerprint table is missing: {table}")
                quoted_columns = ", ".join('"' + name.replace('"', '""') + '"' for name in columns)
                rows = connection.execute(
                    f'SELECT {quoted_columns} FROM "{table}" ORDER BY {quoted_columns}'
                ).fetchall()
                normalized_rows = [
                    [_fingerprint_value(value) for value in tuple(row)]
                    for row in rows
                ]
                tables.append({"name": table, "columns": columns, "rows": normalized_rows})
            state = {
                "schema_version": SCHEMA_VERSION,
                "project_id": meta["project_id"],
                "authority_id": meta["authority_id"],
                "semantic_revision": meta["semantic_revision"],
                "tables": tables,
            }
            canonical = json.dumps(
                _json_value(state, "logical state"),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _fingerprint_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    return _json_value(value, "SQLite logical value")


__all__ = [
    "CommandActorNotRegisteredError",
    "CommandDispatchError",
    "CommandDispatcher",
    "CommandHandlerContractError",
    "DuplicateCommandHandlerError",
    "IdempotencyConflictError",
    "MutationContext",
    "StaleAuthorityRevisionError",
    "UnknownCommandHandlerError",
]
