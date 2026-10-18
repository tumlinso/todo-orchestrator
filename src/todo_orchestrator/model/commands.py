"""Typed command envelopes and immutable authority result values.

These models describe trusted in-process command handlers and persisted
provenance. They do not authenticate actors or authorize operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Generic, Mapping, Protocol, TypeVar, TYPE_CHECKING

from todo_orchestrator.contracts import EntityKind, EntityRef, StableId

if TYPE_CHECKING:
    from todo_orchestrator.authority.commands import MutationContext


CommandT = TypeVar("CommandT")


@dataclass(frozen=True)
class CommandEnvelope(Generic[CommandT]):
    """One typed request bound to an actor incarnation and expected revision."""

    command: CommandT
    idempotency_key: StableId
    expected_revision: int
    actor: EntityRef

    def __post_init__(self) -> None:
        if not isinstance(self.idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        if type(self.expected_revision) is not int or self.expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        if not isinstance(self.actor, EntityRef) or self.actor.kind is not EntityKind.ACTOR:
            raise ValueError("actor must be an actor EntityRef with an incarnation")


@dataclass(frozen=True)
class CommandEffect:
    """A handler's result and optional single semantic event."""

    changed: bool
    result: Mapping[str, object]
    event_kind: str | None = None
    event_payload: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if type(self.changed) is not bool:
            raise TypeError("changed must be a bool")
        if not isinstance(self.result, Mapping):
            raise TypeError("result must be a JSON object mapping")
        if self.changed:
            if not isinstance(self.event_kind, str) or not self.event_kind.strip():
                raise ValueError("a changed command must provide an event_kind")
            if not isinstance(self.event_payload, Mapping):
                raise TypeError("a changed command must provide an event_payload mapping")
        elif self.event_kind is not None or self.event_payload is not None:
            raise ValueError("a no-op command must not provide an event")


@dataclass(frozen=True)
class CommandReceipt:
    """Durable outcome identity returned by first execution and exact retries."""

    receipt_id: StableId
    command_kind: str
    semantic_revision: int
    changed: bool
    event_id: StableId | None
    actor: EntityRef
    result: Mapping[str, object]
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_id, StableId):
            raise TypeError("receipt_id must be a StableId")
        if not isinstance(self.command_kind, str) or not self.command_kind.strip():
            raise ValueError("command_kind must be non-empty text")
        if type(self.semantic_revision) is not int or self.semantic_revision < 0:
            raise ValueError("semantic_revision must be a non-negative integer")
        if type(self.changed) is not bool:
            raise TypeError("changed must be a bool")
        if self.changed != (self.event_id is not None):
            raise ValueError("event_id must be present exactly when changed is true")
        if self.event_id is not None and not isinstance(self.event_id, StableId):
            raise TypeError("event_id must be a StableId")
        if not isinstance(self.actor, EntityRef) or self.actor.kind is not EntityKind.ACTOR:
            raise ValueError("actor must be an actor EntityRef")
        if not isinstance(self.result, Mapping):
            raise TypeError("result must be a mapping")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")


@dataclass(frozen=True)
class CommandResult:
    """The stored receipt and whether this call replayed it."""

    receipt: CommandReceipt
    replayed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, CommandReceipt):
            raise TypeError("receipt must be a CommandReceipt")
        if type(self.replayed) is not bool:
            raise TypeError("replayed must be a bool")


@dataclass(frozen=True)
class HistoryEvent:
    """One immutable committed authority event with actor incarnation provenance."""

    event_id: StableId
    semantic_revision: int
    event_ordinal: int
    event_kind: str
    payload: Mapping[str, object]
    occurred_at: datetime
    actor: EntityRef


@dataclass(frozen=True)
class AuthorityDelta:
    """History events after a revision through a stable current revision."""

    since_revision: int
    current_revision: int
    events: tuple[HistoryEvent, ...]


class CommandHandler(Protocol[CommandT]):
    """Trusted in-process implementation for one typed command kind.

    The dispatcher deep-copies each command once before calling the handler.
    `canonical_payload` must be pure, and neither handler method should mutate
    that private command snapshot, so the digest and applied effect describe
    the same request.
    """

    kind: str
    command_type: type[CommandT]

    def canonical_payload(self, command: CommandT) -> Mapping[str, object]:
        """Purely return a deterministic JSON object identifying command intent."""

    def apply(self, context: MutationContext, command: CommandT) -> CommandEffect:
        """Apply local changes without mutating command; return event and result."""


__all__ = [
    "AuthorityDelta",
    "CommandEffect",
    "CommandEnvelope",
    "CommandHandler",
    "CommandReceipt",
    "CommandResult",
    "HistoryEvent",
]
