"""Authenticated, bounded task context and append-only authored findings.

Context capsules are derived on read from one validated accepted plan and
current authority facts. They are never persisted. The renderer deliberately
omits inboxes, source-file bodies, logs, and transcripts; large material stays
behind typed references owned by its provider.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
import sqlite3
import base64
from typing import Any, Callable

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    CONTEXT_FINDING_INVALIDATE_ACTION,
    CONTEXT_FINDING_PUBLISH_ACTION,
    CONTEXT_READ_ACTION,
    _token_digest,
)
from todo_orchestrator.authority.commands import DuplicateCommandHandlerError, MutationContext
from todo_orchestrator.authority.declarations import load_plan_declaration, native_declaration_facts
from todo_orchestrator.authority.sqlite import (
    AuthorityError,
    InvalidAuthorityError,
    SQLiteAuthority,
    load_plan_revision_snapshot,
)
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, Sha256Digest, StableId
from todo_orchestrator.model import CommandEffect, CommandResult
from todo_orchestrator.model.context import (
    ContextCapsule,
    ContextCapsuleStatus,
    ContextChangeKind,
    ContextExpansion,
    ContextExpansionStatus,
    ContextFinding,
    ContextFragment,
    ContextFragmentChange,
    ContextFragmentKind,
    ContextFragmentRef,
    ContextManifest,
)
from todo_orchestrator.planning import ConditionResult, decode_accepted_plan

from .payloads import PayloadRejectedError, validate_bounded_text
from .store import load_run_schedule


FINDING_PUBLISH_COMMAND = "todo.context.finding.publish"
FINDING_INVALIDATE_COMMAND = "todo.context.finding.invalidate"
DEFAULT_CONTEXT_MAX_BYTES = 16 * 1024
MAX_CONTEXT_MAX_BYTES = 64 * 1024
MIN_CONTEXT_MAX_BYTES = 4096
MAX_CONTEXT_FRAGMENT_BYTES = 8192
MAX_EXPANDED_FRAGMENT_BYTES = 65536
CONTEXT_EXPANSION_CHUNK_BYTES = 2048
MAX_RENDER_DEPTH = 10
MAX_RENDER_NODES = 4096
MAX_RENDER_TEXT_BYTES = 32 * 1024
MAX_CONTEXT_EVENTS = 100
MAX_CONTEXT_FINDINGS = 32
_SOURCE_KINDS = frozenset({
    ContextFragmentKind.PLAN,
    ContextFragmentKind.WORK_ITEM,
    ContextFragmentKind.ASSIGNMENT,
    ContextFragmentKind.DECLARATIONS,
    ContextFragmentKind.SOURCE_REFERENCES,
})
_FRAGMENT_ORDER = tuple(ContextFragmentKind)
_OMIT = object()
_TOKEN_CHAR_RUN = re.compile(r"[A-Za-z0-9_-]{32,}")


class ContextError(AuthorityError):
    """Base class for authenticated context and finding operations."""


class ContextUnavailableError(ContextError):
    """The exact accepted context or a durable fact is not available."""

    def __init__(self, message: str, *, required_bytes: int | None = None) -> None:
        super().__init__(message)
        self.required_bytes = required_bytes


class ContextScopeError(ContextError):
    """The target or optional run/assignment/attempt context is inconsistent."""


class ContextStaleError(ContextError):
    """A finding was based on a context manifest that is no longer current."""


class ContextFindingConflictError(ContextError):
    """A finding version changed or was invalidated by another command."""


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _plain_context_value(value: object) -> object:
    """Convert immutable domain containers to their lossless JSON values."""
    if isinstance(value, StableId):
        return str(value)
    if isinstance(value, Sha256Digest):
        return value.hex
    if isinstance(value, EntityRef):
        return _ref_payload(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _plain_context_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_context_value(child) for child in value]
    if is_dataclass(value) and not isinstance(value, type):
        return _plain_context_value({item.name: getattr(value, item.name) for item in fields(value)})
    if value is None or type(value) in {str, bool, int, float}:
        return value
    raise TypeError("accepted declaration contains a non-canonical context value")


def _sha(value: str) -> Sha256Digest:
    return Sha256Digest(hashlib.sha256(value.encode("utf-8")).hexdigest())


def _ref_payload(ref: EntityRef | None) -> dict[str, str | None] | None:
    if ref is None:
        return None
    return {
        "project_id": str(ref.project_id),
        "kind": ref.kind.value,
        "entity_id": str(ref.entity_id),
        "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _ref_from_payload(project_id: StableId, raw: object) -> EntityRef:
    if not isinstance(raw, dict) or set(raw) != {
        "project_id", "kind", "entity_id", "definition_revision_id", "incarnation_id",
    }:
        raise ValueError("stored context reference has an unsupported shape")
    if raw["project_id"] != str(project_id):
        raise ValueError("stored context reference belongs to another project")
    return EntityRef(
        project_id,
        EntityKind(raw["kind"]),
        StableId(raw["entity_id"]),
        None if raw["definition_revision_id"] is None else StableId(raw["definition_revision_id"]),
        None if raw["incarnation_id"] is None else StableId(raw["incarnation_id"]),
    )


def _fragment_ref_payload(ref: ContextFragmentRef) -> dict[str, str]:
    return {"fragment_id": str(ref.fragment_id), "kind": ref.kind.value, "digest": ref.digest.hex}


def _fragment_ref_from_payload(raw: object) -> ContextFragmentRef:
    if not isinstance(raw, dict) or set(raw) != {"fragment_id", "kind", "digest"}:
        raise ValueError("stored fragment reference has an unsupported shape")
    return ContextFragmentRef(StableId(raw["fragment_id"]), ContextFragmentKind(raw["kind"]), Sha256Digest(raw["digest"]))


def _manifest_material(
    plan_revision: EntityRef,
    work_item: EntityRef,
    run: EntityRef | None,
    assignment: EntityRef | None,
    attempt: EntityRef | None,
    refs: tuple[ContextFragmentRef, ...],
    *,
    since_revision: int | None,
    source_only: bool,
) -> str:
    selected = tuple(
        ref for ref in refs
        if not source_only or ref.kind in _SOURCE_KINDS
    )
    return _canonical({
        "format": "todo-orchestrator.context-manifest",
        "version": 2,
        "plan_revision": _ref_payload(plan_revision),
        "work_item": _ref_payload(work_item),
        "run": _ref_payload(run),
        "assignment": _ref_payload(assignment),
        "attempt": _ref_payload(attempt),
        # Delta-cursor selection changes the full context manifest, but not the
        # authored-source digest used to validate findings.
        "since_revision": None if source_only else since_revision,
        "fragments": [_fragment_ref_payload(item) for item in selected],
    })


def _make_manifest(
    plan_revision: EntityRef,
    work_item: EntityRef,
    run: EntityRef | None,
    assignment: EntityRef | None,
    attempt: EntityRef | None,
    refs: tuple[ContextFragmentRef, ...],
    since_revision: int | None = None,
) -> ContextManifest:
    return ContextManifest(
        plan_revision, work_item, run, assignment, attempt, refs,
        _sha(_manifest_material(plan_revision, work_item, run, assignment, attempt, refs,
                                since_revision=since_revision, source_only=False)),
        _sha(_manifest_material(plan_revision, work_item, run, assignment, attempt, refs,
                                since_revision=since_revision, source_only=True)),
        since_revision,
    )


def _manifest_is_well_formed(manifest: ContextManifest) -> bool:
    anchor = "\0".join((
        str(manifest.work_item.project_id),
        str(manifest.work_item.entity_id),
        "" if manifest.run is None else str(manifest.run.entity_id),
        "" if manifest.assignment is None else str(manifest.assignment.entity_id),
        "" if manifest.attempt is None else str(manifest.attempt.entity_id),
    ))
    return (
        len(manifest.fragments) <= len(ContextFragmentKind)
        and len({item.kind for item in manifest.fragments}) == len(manifest.fragments)
        and all(item.fragment_id == _fragment_id(anchor, item.kind) for item in manifest.fragments)
        and manifest.digest == _sha(_manifest_material(
            manifest.plan_revision, manifest.work_item, manifest.run, manifest.assignment,
            manifest.attempt, manifest.fragments, since_revision=manifest.since_revision, source_only=False,
        ))
        and manifest.source_digest == _sha(_manifest_material(
            manifest.plan_revision, manifest.work_item, manifest.run, manifest.assignment,
            manifest.attempt, manifest.fragments, since_revision=manifest.since_revision, source_only=True,
        ))
    )


def _validate_structural_texts(connection: sqlite3.Connection, values: tuple[str, ...]) -> None:
    """Reject secret-bearing identity fields before they enter a public envelope.

    Structural references cannot be redacted without invalidating their exact
    identity, so unsafe values fail closed instead of being echoed.
    """
    issued_digests = frozenset(row[0] for row in connection.execute(
        "SELECT token_digest FROM capability_tokens"
    ).fetchall())
    for value in values:
        try:
            validate_bounded_text(value, field="context identity", max_bytes=1000,
                                  allow_multiline=False)
        except (PayloadRejectedError, ValueError) as exc:
            raise ContextUnavailableError("context contains an unsafe structural identity") from exc
        for run in _TOKEN_CHAR_RUN.finditer(value):
            token_run = run.group(0)
            for start in range(len(token_run)):
                for end in range(start + 32, len(token_run) + 1):
                    candidate = token_run[start:end]
                    if hashlib.sha256(candidate.encode("ascii")).hexdigest() in issued_digests:
                        raise ContextUnavailableError("context contains an unsafe structural identity")


def _ref_identity_texts(ref: EntityRef | None) -> tuple[str, ...]:
    if ref is None:
        return ()
    return (
        str(ref.project_id), ref.kind.value, str(ref.entity_id),
        "" if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "" if ref.incarnation_id is None else str(ref.incarnation_id),
    )


def _validate_manifest_texts(connection: sqlite3.Connection, manifest: ContextManifest) -> None:
    refs = (manifest.plan_revision, manifest.work_item, manifest.run, manifest.assignment, manifest.attempt)
    values = [value for ref in refs for value in _ref_identity_texts(ref)]
    for item in manifest.fragments:
        values.extend((str(item.fragment_id), item.kind.value, item.digest.hex))
    values.extend((manifest.digest.hex, manifest.source_digest.hex))
    _validate_structural_texts(connection, tuple(value for value in values if value))


class _RenderBudget:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.nodes = 0
        self.text_bytes = 0
        self.omitted = 0


def _safe_text(value: str, budget: _RenderBudget) -> str | object:
    if not value:
        return ""
    try:
        validated = validate_bounded_text(
            value, field="context value", max_bytes=min(1000, 4096),
            connection=budget.connection, allow_multiline=True,
        )
    except (PayloadRejectedError, ValueError):
        budget.omitted += 1
        return _OMIT
    byte_count = len(validated.encode("utf-8"))
    if budget.text_bytes + byte_count > MAX_RENDER_TEXT_BYTES:
        budget.omitted += 1
        return _OMIT
    budget.text_bytes += byte_count
    return validated


def _safe_reference(ref: EntityRef, budget: _RenderBudget) -> dict[str, object]:
    fields_value: dict[str, object] = {"kind": ref.kind.value}
    for key, item in (
        ("project_id", ref.project_id), ("entity_id", ref.entity_id),
        ("definition_revision_id", ref.definition_revision_id), ("incarnation_id", ref.incarnation_id),
    ):
        if item is None:
            fields_value[key] = None
            continue
        safe = _safe_text(str(item), budget)
        fields_value[key] = "[omitted]" if safe is _OMIT else safe
    return fields_value


def _safe_value(value: object, budget: _RenderBudget, depth: int = 0) -> object:
    budget.nodes += 1
    if budget.nodes > MAX_RENDER_NODES or depth > MAX_RENDER_DEPTH:
        budget.omitted += 1
        return _OMIT
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _OMIT
    if isinstance(value, EntityRef):
        return _safe_reference(value, budget)
    if isinstance(value, Enum):
        return _safe_value(value.value, budget, depth + 1)
    if isinstance(value, StableId):
        return _safe_text(str(value), budget)
    if isinstance(value, str):
        return _safe_text(value, budget)
    if isinstance(value, Sha256Digest):
        return value.hex
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            safe_key = _safe_text(str(key), budget)
            if safe_key is _OMIT:
                continue
            safe_child = _safe_value(child, budget, depth + 1)
            if safe_child is not _OMIT:
                result[safe_key] = safe_child
        return result
    if isinstance(value, (tuple, list)):
        result = []
        for child in value[:128]:
            safe_child = _safe_value(child, budget, depth + 1)
            if safe_child is not _OMIT:
                result.append(safe_child)
        if len(value) > 128:
            budget.omitted += len(value) - 128
        return result
    if is_dataclass(value) and not isinstance(value, type):
        return _safe_value({item.name: getattr(value, item.name) for item in fields(value)}, budget, depth + 1)
    budget.omitted += 1
    return _OMIT


def _safe_payload(connection: sqlite3.Connection, value: Mapping[str, object]) -> dict[str, object]:
    budget = _RenderBudget(connection)
    result = _safe_value(value, budget)
    if not isinstance(result, dict):
        result = {"reference_only": True}
    if budget.omitted:
        result["rendering_note"] = "Some authored values were omitted by safety or size limits."
    return result


def _fragment_id(anchor: str, kind: ContextFragmentKind) -> StableId:
    digest = hashlib.sha256((anchor + "\0" + kind.value).encode("utf-8")).hexdigest()
    return StableId("ctx-" + digest)


def _make_fragment(
    connection: sqlite3.Connection,
    anchor: str,
    kind: ContextFragmentKind,
    payload: Mapping[str, object],
    *,
    include_large: bool = False,
) -> ContextFragment:
    safe = _safe_payload(connection, payload)
    encoded = _canonical(safe)
    byte_count = len(encoded.encode("utf-8"))
    if byte_count > MAX_EXPANDED_FRAGMENT_BYTES:
        raise ContextUnavailableError("context fragment exceeds the bounded expansion limit")
    if byte_count > MAX_CONTEXT_FRAGMENT_BYTES and not include_large:
        source_digest = _sha(encoded)
        encoded = _canonical({
            "reference_only": True,
            "content_digest": source_digest.hex,
            "content_bytes": byte_count,
            "reason": "fragment exceeded the safe inline size limit",
            "expansion": {
                "operation": "expand_fragment",
                "fragment_id": str(_fragment_id(anchor, kind)),
                "content_digest": source_digest.hex,
                "page_encoding": "base64-utf8-bytes",
                "page_bytes": CONTEXT_EXPANSION_CHUNK_BYTES,
            },
        })
    ref = ContextFragmentRef(_fragment_id(anchor, kind), kind, _sha(encoded))
    return ContextFragment(ref, encoded)


def _actor_ref(project_id: StableId, actor_id: str, incarnation_id: str) -> EntityRef:
    return EntityRef(project_id, EntityKind.ACTOR, StableId(actor_id), incarnation_id=StableId(incarnation_id))


@dataclass(frozen=True)
class _PublishFinding:
    work_item: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    attempt: EntityRef | None
    source_manifest: ContextManifest
    source_fragments: tuple[ContextFragmentRef, ...]
    finding_id: StableId
    expected_finding_version: int | None
    summary: str
    created_at: datetime


@dataclass(frozen=True)
class _InvalidateFinding:
    work_item: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    attempt: EntityRef | None
    source_manifest: ContextManifest
    finding_id: StableId
    finding_version: int
    reason: str
    created_at: datetime


def _publish_intent(command: _PublishFinding) -> dict[str, object]:
    return {
        "work_item": _ref_payload(command.work_item),
        "run": _ref_payload(command.run),
        "assignment": _ref_payload(command.assignment),
        "attempt": _ref_payload(command.attempt),
        "plan_revision": _ref_payload(command.source_manifest.plan_revision),
        "source_manifest_digest": command.source_manifest.source_digest.hex,
        "source_fragments": [_fragment_ref_payload(item) for item in command.source_fragments],
        "finding_id": str(command.finding_id),
        "expected_finding_version": command.expected_finding_version,
        "summary": command.summary,
    }


def _invalidate_intent(command: _InvalidateFinding) -> dict[str, object]:
    return {
        "work_item": _ref_payload(command.work_item),
        "run": _ref_payload(command.run),
        "assignment": _ref_payload(command.assignment),
        "attempt": _ref_payload(command.attempt),
        "plan_revision": _ref_payload(command.source_manifest.plan_revision),
        "source_manifest_digest": command.source_manifest.source_digest.hex,
        "finding_id": str(command.finding_id),
        "finding_version": command.finding_version,
        "reason": command.reason,
    }


class _FindingHandler:
    kind = FINDING_PUBLISH_COMMAND
    command_type = _PublishFinding

    def __init__(self, service: ContextService) -> None:
        self.service = service

    def authorization_requirement(self, command: _PublishFinding) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            CONTEXT_FINDING_PUBLISH_ACTION, command.work_item, command.run, command.assignment,
            command.attempt, plan_revision=command.source_manifest.plan_revision,
        )

    def canonical_payload(self, command: _PublishFinding) -> Mapping[str, object]:
        return _publish_intent(command)

    def apply(self, context: MutationContext, command: _PublishFinding) -> CommandEffect:
        state = self.service._authorized_context(
            context._connection, context.authority, context.actor, "", command.work_item,
            command.run, command.assignment, command.attempt,
            action=CONTEXT_FINDING_PUBLISH_ACTION, expected_plan=command.source_manifest.plan_revision,
        )
        _validate_structural_texts(context._connection, (str(command.finding_id),))
        validate_bounded_text(command.summary, field="finding summary", max_bytes=1000,
                              connection=context._connection, allow_multiline=False)
        current_manifest, _current_fragments = self.service._render_complete_state(
            context._connection, context.authority, state,
        )
        self.service._check_source_manifest(command.source_manifest, current_manifest, command.source_fragments)
        row = context.execute(
            "SELECT version, summary, source_manifest_digest, source_fragments_json, work_item_id, "
            "definition_revision_id, run_id, assignment_id, attempt_id FROM context_finding_versions "
            "WHERE finding_id = ? ORDER BY version DESC LIMIT 1",
            (str(command.finding_id),),
        ).fetchone()
        if row is None:
            if command.expected_finding_version is not None:
                raise ContextFindingConflictError("finding version changed before publication")
            version = 1
        else:
            if (
                row["work_item_id"] != str(command.work_item.entity_id)
                or row["definition_revision_id"] != str(command.work_item.definition_revision_id)
                or row["run_id"] != (None if command.run is None else str(command.run.entity_id))
                or row["assignment_id"] != (None if command.assignment is None else str(command.assignment.entity_id))
                or row["attempt_id"] != (None if command.attempt is None else str(command.attempt.entity_id))
            ):
                raise ContextFindingConflictError("finding ID is already bound to another exact work context")
            if type(command.expected_finding_version) is not int or row["version"] != command.expected_finding_version:
                raise ContextFindingConflictError("finding version changed before publication")
            version = int(row["version"]) + 1
            if (row["summary"] == command.summary
                    and row["source_manifest_digest"] == current_manifest.source_digest.hex
                    and row["source_fragments_json"] == _canonical([
                        _fragment_ref_payload(item) for item in command.source_fragments
                    ])):
                invalidated = context.execute(
                    "SELECT 1 FROM context_finding_invalidations WHERE finding_id = ? AND finding_version = ?",
                    (str(command.finding_id), int(row["version"])),
                ).fetchone()
                if invalidated is None:
                    intent_digest = hashlib.sha256(_canonical(_publish_intent(command)).encode()).hexdigest()
                    return CommandEffect(False, {"finding_id": str(command.finding_id),
                                                 "version": int(row["version"]), "no_op": True,
                                                 "intent_digest": intent_digest})
        created_at = command.created_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
        context.execute(
            "INSERT INTO context_finding_versions(finding_id, version, work_item_id, definition_revision_id, "
            "plan_revision_id, run_id, assignment_id, attempt_id, summary, source_manifest_digest, "
            "source_fragments_json, actor_id, actor_incarnation_id, semantic_revision, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(command.finding_id), version, str(command.work_item.entity_id),
             str(command.work_item.definition_revision_id), str(command.source_manifest.plan_revision.entity_id),
             None if command.run is None else str(command.run.entity_id),
             None if command.assignment is None else str(command.assignment.entity_id),
             None if command.attempt is None else str(command.attempt.entity_id), command.summary,
             current_manifest.source_digest.hex,
             _canonical([_fragment_ref_payload(item) for item in command.source_fragments]),
             str(context.actor.entity_id), str(context.actor.incarnation_id), context.starting_revision + 1,
             created_at),
        )
        intent_digest = hashlib.sha256(_canonical(_publish_intent(command)).encode()).hexdigest()
        result = {"finding_id": str(command.finding_id), "version": version, "intent_digest": intent_digest}
        return CommandEffect(True, result, "todo.context.finding.published", {
            "intent_digest": intent_digest,
            "finding_id": str(command.finding_id), "version": version,
            "work_item_id": str(command.work_item.entity_id),
            "definition_revision_id": str(command.work_item.definition_revision_id),
            "run_id": None if command.run is None else str(command.run.entity_id),
        })


class _FindingInvalidationHandler:
    kind = FINDING_INVALIDATE_COMMAND
    command_type = _InvalidateFinding

    def __init__(self, service: ContextService) -> None:
        self.service = service

    def authorization_requirement(self, command: _InvalidateFinding) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            CONTEXT_FINDING_INVALIDATE_ACTION, command.work_item, command.run, command.assignment,
            command.attempt, plan_revision=command.source_manifest.plan_revision,
        )

    def canonical_payload(self, command: _InvalidateFinding) -> Mapping[str, object]:
        return _invalidate_intent(command)

    def apply(self, context: MutationContext, command: _InvalidateFinding) -> CommandEffect:
        state = self.service._authorized_context(
            context._connection, context.authority, context.actor, "", command.work_item,
            command.run, command.assignment, command.attempt,
            action=CONTEXT_FINDING_INVALIDATE_ACTION, expected_plan=command.source_manifest.plan_revision,
        )
        _validate_structural_texts(context._connection, (str(command.finding_id),))
        validate_bounded_text(command.reason, field="invalidation reason", max_bytes=1000,
                              connection=context._connection, allow_multiline=False)
        current_manifest, _fragments = self.service._render_complete_state(
            context._connection, context.authority, state,
        )
        self.service._check_source_manifest(command.source_manifest, current_manifest, None)
        row = context.execute(
            "SELECT work_item_id, definition_revision_id, plan_revision_id, run_id, assignment_id, attempt_id, "
            "source_fragments_json "
            "FROM context_finding_versions WHERE finding_id = ? AND version = ?",
            (str(command.finding_id), command.finding_version),
        ).fetchone()
        if row is None or (
            row["work_item_id"] != str(command.work_item.entity_id)
            or row["definition_revision_id"] != str(command.work_item.definition_revision_id)
            or row["plan_revision_id"] != str(command.source_manifest.plan_revision.entity_id)
            or row["run_id"] != (None if command.run is None else str(command.run.entity_id))
            or row["assignment_id"] != (None if command.assignment is None else str(command.assignment.entity_id))
            or row["attempt_id"] != (None if command.attempt is None else str(command.attempt.entity_id))
        ):
            raise ContextUnavailableError("finding is not available in this exact context")
        latest = context.execute(
            "SELECT MAX(version) FROM context_finding_versions WHERE finding_id = ?",
            (str(command.finding_id),),
        ).fetchone()[0]
        if latest != command.finding_version:
            raise ContextFindingConflictError("only the current finding version can be invalidated")
        existing = context.execute(
            "SELECT reason, source_manifest_digest FROM context_finding_invalidations "
            "WHERE finding_id = ? AND finding_version = ?",
            (str(command.finding_id), command.finding_version),
        ).fetchone()
        if existing is not None:
            if existing["reason"] == command.reason and existing["source_manifest_digest"] == current_manifest.source_digest.hex:
                intent_digest = hashlib.sha256(_canonical(_invalidate_intent(command)).encode()).hexdigest()
                return CommandEffect(False, {"finding_id": str(command.finding_id),
                                             "version": command.finding_version, "no_op": True,
                                             "intent_digest": intent_digest})
            raise ContextFindingConflictError("finding version has already been invalidated")
        created_at = command.created_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
        context.execute(
            "INSERT INTO context_finding_invalidations(finding_id, finding_version, reason, "
            "source_manifest_digest, source_fragments_json, actor_id, actor_incarnation_id, "
            "semantic_revision, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(command.finding_id), command.finding_version, command.reason,
             current_manifest.source_digest.hex, row["source_fragments_json"],
             str(context.actor.entity_id), str(context.actor.incarnation_id),
             context.starting_revision + 1, created_at),
        )
        intent_digest = hashlib.sha256(_canonical(_invalidate_intent(command)).encode()).hexdigest()
        return CommandEffect(True, {"finding_id": str(command.finding_id), "version": command.finding_version,
                                    "intent_digest": intent_digest},
                             "todo.context.finding.invalidated", {
            "intent_digest": intent_digest,
            "finding_id": str(command.finding_id), "version": command.finding_version,
            "work_item_id": str(command.work_item.entity_id),
            "definition_revision_id": str(command.work_item.definition_revision_id),
            "run_id": None if command.run is None else str(command.run.entity_id),
        })


class ContextService:
    """Read and publish exact, bounded task context using current authority facts."""

    def __init__(self, auth: AuthorityAuthService, *, clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable or None")
        self.auth = auth
        self.clock = clock or auth._now
        for handler in (_FindingHandler(self), _FindingInvalidationHandler(self)):
            try:
                auth.dispatcher.register(handler)
            except DuplicateCommandHandlerError:
                binding = auth.dispatcher._by_type.get(handler.command_type)
                if binding is None or type(binding.handler) is not type(handler):
                    raise

    def build_context(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        work_item: EntityRef,
        *,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
        attempt: EntityRef | None = None,
        previous_manifest: ContextManifest | None = None,
        since_revision: int | None = None,
        max_bytes: int = DEFAULT_CONTEXT_MAX_BYTES,
    ) -> ContextCapsule:
        self._validate_request(authority, work_item, run, assignment, attempt, max_bytes)
        if previous_manifest is not None and not isinstance(previous_manifest, ContextManifest):
            raise TypeError("previous_manifest must be a ContextManifest or None")
        if previous_manifest is not None and not _manifest_is_well_formed(previous_manifest):
            raise ContextScopeError("previous_manifest is malformed or does not use canonical fragment identities")
        if previous_manifest is not None and (
            previous_manifest.work_item.project_id != work_item.project_id
            or previous_manifest.work_item.entity_id != work_item.entity_id
        ):
            raise ContextScopeError("previous manifest belongs to another logical work item")
        if previous_manifest is not None and (
            previous_manifest.run != run or previous_manifest.assignment != assignment
            or previous_manifest.attempt != attempt
        ):
            raise ContextScopeError("previous manifest belongs to another run/assignment/attempt context")
        digest = _token_digest(bearer_token)
        actor, _capability_id = self.auth._actor_for_token(authority, digest)
        with authority.read_transaction() as connection:
            state = self._authorized_context(
                connection, authority, actor, digest, work_item, run, assignment, attempt,
                action=CONTEXT_READ_ACTION,
            )
            state["since_revision"] = since_revision
            current_revision = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            if since_revision is not None and (
                type(since_revision) is not int or since_revision < 0 or since_revision > current_revision
            ):
                raise ValueError("since_revision must be a semantic revision not newer than this authority")
            manifest, fragments = self._render_complete_state(connection, authority, state)
            _validate_manifest_texts(connection, manifest)
            if previous_manifest is not None:
                _validate_manifest_texts(connection, previous_manifest)
            changes = self._changes(previous_manifest, manifest)
        return self._bounded_capsule(manifest, current_revision, tuple(fragments), changes, max_bytes)

    def expand_fragment(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        work_item: EntityRef,
        *,
        fragment_id: StableId,
        expected_digest: Sha256Digest,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
        attempt: EntityRef | None = None,
        max_bytes: int = DEFAULT_CONTEXT_MAX_BYTES,
        offset: int | None = None,
        since_revision: int | None = None,
    ) -> ContextExpansion:
        self._validate_request(authority, work_item, run, assignment, attempt, max_bytes)
        if not isinstance(fragment_id, StableId) or not isinstance(expected_digest, Sha256Digest):
            raise TypeError("fragment_id and expected_digest must use their typed values")
        if offset is not None and (type(offset) is not int or offset < 0):
            raise ValueError("offset must be a non-negative byte offset or None")
        if since_revision is not None and (type(since_revision) is not int or since_revision < 0):
            raise ValueError("since_revision must be a non-negative semantic revision or None")
        digest = _token_digest(bearer_token)
        actor, _capability_id = self.auth._actor_for_token(authority, digest)
        with authority.read_transaction() as connection:
            state = self._authorized_context(
                connection, authority, actor, digest, work_item, run, assignment, attempt,
                action=CONTEXT_READ_ACTION,
            )
            semantic_revision = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            if since_revision is not None and since_revision > semantic_revision:
                raise ValueError("since_revision must not be newer than this authority")
            state["since_revision"] = since_revision
            manifest, fragments = self._render_complete_state(connection, authority, state)
            _validate_manifest_texts(connection, manifest)
        current = next((item for item in fragments if item.reference.fragment_id == fragment_id), None)
        if current is None:
            result = ContextExpansion(ContextExpansionStatus.UNAVAILABLE, manifest, None,
                                      "fragment is not available in this context")
        elif current.reference.digest != expected_digest:
            result = ContextExpansion(ContextExpansionStatus.STALE, manifest, None,
                                      "fragment version changed; use the current manifest")
        else:
            try:
                fallback = json.loads(current.payload_json)
            except ValueError:
                fallback = {}
            is_reference = isinstance(fallback, dict) and fallback.get("reference_only") is True
            if is_reference:
                descriptor = fallback.get("expansion")
                if not isinstance(descriptor, dict) or descriptor.get("fragment_id") != str(fragment_id):
                    result = ContextExpansion(ContextExpansionStatus.UNAVAILABLE, manifest, None,
                                              "fragment has no supported expansion route")
                else:
                    with authority.read_transaction() as connection:
                        state = self._authorized_context(
                            connection, authority, actor, digest, work_item, run, assignment, attempt,
                            action=CONTEXT_READ_ACTION,
                        )
                        state["since_revision"] = since_revision
                        fresh_manifest, _fresh_fragments = self._render_complete_state(
                            connection, authority, state,
                        )
                        if fresh_manifest.digest != manifest.digest:
                            return ContextExpansion(ContextExpansionStatus.STALE, fresh_manifest, None,
                                                    "fragment version changed; use the current manifest")
                        _fresh_manifest, expanded_fragments = self._render_complete_state(
                            connection, authority, state, expand_kind=current.reference.kind,
                        )
                    expanded = next((item for item in expanded_fragments
                                     if item.reference.fragment_id == fragment_id), None)
                    if expanded is None:
                        result = ContextExpansion(ContextExpansionStatus.UNAVAILABLE, manifest, None,
                                                  "fragment is not available in this context")
                    elif _sha(expanded.payload_json).hex != descriptor.get("content_digest"):
                        result = ContextExpansion(ContextExpansionStatus.STALE, manifest, None,
                                                  "fragment content changed; use the current manifest")
                    else:
                        result = _chunk_expansion(
                            manifest, current.reference, expanded.payload_json, _sha(expanded.payload_json),
                            0 if offset is None else offset, max_bytes,
                        )
            elif offset is not None:
                result = _chunk_expansion(manifest, current.reference, current.payload_json, current.reference.digest,
                                          offset, max_bytes)
            else:
                result = ContextExpansion(ContextExpansionStatus.READY, manifest, current)
                if len(serialize_context_expansion(result).encode("utf-8")) > max_bytes:
                    result = _chunk_expansion(
                        manifest, current.reference, current.payload_json, current.reference.digest, 0, max_bytes,
                    )
        if len(serialize_context_expansion(result).encode("utf-8")) > max_bytes:
            return ContextExpansion(ContextExpansionStatus.UNAVAILABLE, None, None,
                                     "expansion exceeds the requested byte budget")
        return result

    def publish_finding(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        work_item: EntityRef,
        summary: str,
        source_manifest: ContextManifest,
        source_fragments: tuple[ContextFragmentRef, ...],
        *,
        finding_id: StableId | None = None,
        expected_finding_version: int | None = None,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
        attempt: EntityRef | None = None,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        self._validate_context_tuple(authority, work_item, run, assignment, attempt)
        if not isinstance(source_manifest, ContextManifest) or not _manifest_is_well_formed(source_manifest):
            raise ContextStaleError("source manifest is malformed or has been altered")
        if source_manifest.work_item != work_item or (source_manifest.run, source_manifest.assignment, source_manifest.attempt) != (run, assignment, attempt):
            raise ContextScopeError("source manifest does not match the exact work and context")
        self._validate_source_refs(source_manifest, source_fragments)
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        if expected_finding_version is not None and (type(expected_finding_version) is not int or expected_finding_version < 1):
            raise ValueError("expected_finding_version must be positive or None")
        if finding_id is None:
            material = "\0".join((str(authority.project.project_id), str(work_item.entity_id), str(idempotency_key)))
            finding_id = StableId("finding-" + hashlib.sha256(material.encode("utf-8")).hexdigest())
        elif not isinstance(finding_id, StableId):
            raise TypeError("finding_id must be a StableId or None")
        # Static validation happens before the writer; token-aware validation is repeated in apply.
        summary = validate_bounded_text(summary, field="finding summary", max_bytes=1000, allow_multiline=False)
        command = _PublishFinding(
            work_item, run, assignment, attempt, source_manifest, source_fragments,
            finding_id, expected_finding_version, summary, self.clock(),
        )
        self._preflight_mutation(
            authority, bearer_token, work_item, run, assignment, attempt,
            source_manifest.plan_revision, CONTEXT_FINDING_PUBLISH_ACTION,
            (str(finding_id), str(idempotency_key)), source_manifest, source_fragments,
        )
        requirement = AuthorizationRequirement(
            CONTEXT_FINDING_PUBLISH_ACTION, work_item, run, assignment, attempt,
            plan_revision=source_manifest.plan_revision,
        )
        replay = self._replay_if_exact(
            authority, bearer_token, idempotency_key, requirement, FINDING_PUBLISH_COMMAND,
            "todo.context.finding.published", hashlib.sha256(_canonical(_publish_intent(command)).encode()).hexdigest(),
        )
        if replay is not None:
            return replay
        return self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                 expected_revision=expected_revision)

    def invalidate_finding(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        work_item: EntityRef,
        finding_id: StableId,
        finding_version: int,
        reason: str,
        source_manifest: ContextManifest,
        *,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
        attempt: EntityRef | None = None,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        self._validate_context_tuple(authority, work_item, run, assignment, attempt)
        if not isinstance(finding_id, StableId) or type(finding_version) is not int or finding_version < 1:
            raise ValueError("finding identity and version are invalid")
        if not isinstance(source_manifest, ContextManifest) or not _manifest_is_well_formed(source_manifest):
            raise ContextStaleError("source manifest is malformed or has been altered")
        if source_manifest.work_item != work_item or (source_manifest.run, source_manifest.assignment, source_manifest.attempt) != (run, assignment, attempt):
            raise ContextScopeError("source manifest does not match the exact work and context")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        reason = validate_bounded_text(reason, field="invalidation reason", max_bytes=1000, allow_multiline=False)
        command = _InvalidateFinding(
            work_item, run, assignment, attempt, source_manifest, finding_id, finding_version,
            reason, self.clock(),
        )
        self._preflight_mutation(
            authority, bearer_token, work_item, run, assignment, attempt,
            source_manifest.plan_revision, CONTEXT_FINDING_INVALIDATE_ACTION,
            (str(finding_id), str(idempotency_key)), source_manifest, None,
        )
        requirement = AuthorizationRequirement(
            CONTEXT_FINDING_INVALIDATE_ACTION, work_item, run, assignment, attempt,
            plan_revision=source_manifest.plan_revision,
        )
        replay = self._replay_if_exact(
            authority, bearer_token, idempotency_key, requirement, FINDING_INVALIDATE_COMMAND,
            "todo.context.finding.invalidated", hashlib.sha256(_canonical(_invalidate_intent(command)).encode()).hexdigest(),
        )
        if replay is not None:
            return replay
        return self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                 expected_revision=expected_revision)

    def _preflight_mutation(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        work_item: EntityRef,
        run: EntityRef | None,
        assignment: EntityRef | None,
        attempt: EntityRef | None,
        plan_revision: EntityRef,
        action: StableId,
        identifiers: tuple[str, ...],
        source_manifest: ContextManifest,
        source_fragments: tuple[ContextFragmentRef, ...] | None,
    ) -> None:
        digest = _token_digest(bearer_token)
        actor, _ = self.auth._actor_for_token(authority, digest)
        with authority.read_transaction() as connection:
            state = self._authorized_context(
                connection, authority, actor, digest, work_item, run, assignment, attempt,
                action=action, expected_plan=plan_revision,
            )
            _validate_structural_texts(connection, identifiers)
            current_manifest, _fragments = self._render_complete_state(connection, authority, state)
            _validate_manifest_texts(connection, source_manifest)
            _validate_manifest_texts(connection, current_manifest)
            self._check_source_manifest(source_manifest, current_manifest, source_fragments)

    def _replay_if_exact(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        idempotency_key: StableId,
        requirement: AuthorizationRequirement,
        command_kind: str,
        event_kind: str,
        intent_digest: str,
    ) -> CommandResult | None:
        def matches(_connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
            if row["event_kind"] == event_kind and isinstance(row["payload_json"], str):
                try:
                    payload = json.loads(row["payload_json"])
                except ValueError:
                    return False
                if isinstance(payload, dict) and payload.get("intent_digest") == intent_digest:
                    return True
            if row["event_kind"] is None:
                try:
                    result = json.loads(row["result_json"])
                except (TypeError, ValueError):
                    return False
                return isinstance(result, dict) and result.get("intent_digest") == intent_digest
            return False

        return self.auth.replay_authorized(
            authority, bearer_token, idempotency_key, requirement, command_kind, matches,
        )

    def _validate_request(
        self,
        authority: SQLiteAuthority,
        work_item: EntityRef,
        run: EntityRef | None,
        assignment: EntityRef | None,
        attempt: EntityRef | None,
        max_bytes: int,
    ) -> None:
        self._validate_context_tuple(authority, work_item, run, assignment, attempt)
        if type(max_bytes) is not int or not MIN_CONTEXT_MAX_BYTES <= max_bytes <= MAX_CONTEXT_MAX_BYTES:
            raise ValueError(f"max_bytes must be from {MIN_CONTEXT_MAX_BYTES} through {MAX_CONTEXT_MAX_BYTES}")

    @staticmethod
    def _validate_context_tuple(
        authority: SQLiteAuthority,
        work_item: EntityRef,
        run: EntityRef | None,
        assignment: EntityRef | None,
        attempt: EntityRef | None,
    ) -> None:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if (not isinstance(work_item, EntityRef) or work_item.kind is not EntityKind.WORK_ITEM
                or work_item.project_id != authority.project.project_id):
            raise ContextScopeError("work_item must be an exact project-local work definition")
        values = (run, assignment, attempt)
        if any(item is not None for item in values) and any(item is None for item in values):
            raise ContextScopeError("run, assignment, and attempt context must be supplied together")
        for item, kind in zip(values, (EntityKind.RUN, EntityKind.ASSIGNMENT, EntityKind.ATTEMPT)):
            if item is not None and (not isinstance(item, EntityRef) or item.kind is not kind
                                     or item.project_id != authority.project.project_id):
                raise ContextScopeError("context must contain project-local run/assignment/attempt references")

    def _authorized_context(
        self,
        connection: sqlite3.Connection,
        authority: SQLiteAuthority,
        actor: EntityRef,
        bearer_digest: str,
        work_item: EntityRef,
        run: EntityRef | None,
        assignment: EntityRef | None,
        attempt: EntityRef | None,
        *,
        action: StableId,
        expected_plan: EntityRef | None = None,
    ) -> dict[str, object]:
        plan_id: str | None = None
        if run is not None:
            run_row = connection.execute("SELECT plan_revision_id FROM runs WHERE run_id = ?", (str(run.entity_id),)).fetchone()
            if run_row is None:
                raise ContextUnavailableError("run is not available in this authority")
            plan_id = run_row["plan_revision_id"]
        else:
            plan_row = connection.execute(
                "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if plan_row is None:
                raise ContextUnavailableError("there is no accepted plan")
            plan_id = plan_row["plan_revision_id"]
        plan_ref = EntityRef(authority.project.project_id, EntityKind.PLAN_REVISION, StableId(plan_id))
        if expected_plan is not None and plan_ref != expected_plan:
            raise ContextStaleError("accepted plan changed since the finding manifest was produced")
        requirement = AuthorizationRequirement(
            action, work_item, run, assignment, attempt, plan_revision=plan_ref,
        )
        # Public readers pass the token digest here. Mutation handlers are
        # invoked only after CommandDispatcher's same-transaction auth check.
        if bearer_digest:
            self.auth._authorize_capability(connection, authority.project, bearer_digest, actor, requirement)
        structural = (
            str(authority.project.project_id), str(authority.project.authority_id),
            *_ref_identity_texts(actor), *_ref_identity_texts(plan_ref), *_ref_identity_texts(work_item),
            *_ref_identity_texts(run), *_ref_identity_texts(assignment), *_ref_identity_texts(attempt),
        )
        _validate_structural_texts(connection, tuple(value for value in structural if value))
        try:
            record = load_plan_revision_snapshot(connection, authority.project, plan_ref.entity_id)
            plan = decode_accepted_plan(record.canonical_json, authority.project, sequence=record.sequence)
        except (InvalidAuthorityError, TypeError, ValueError) as exc:
            raise ContextUnavailableError("accepted plan snapshot is unavailable or invalid") from exc
        planned_work = next((item for item in plan.work_items if item.definition.ref == work_item), None)
        if planned_work is None:
            raise ContextUnavailableError("exact work definition is not in this accepted plan")
        schedule = None
        attempt_row = None
        entry = None
        if run is not None and assignment is not None and attempt is not None:
            try:
                schedule = load_run_schedule(connection, authority.project, run.entity_id)
            except InvalidAuthorityError as exc:
                raise ContextUnavailableError("run schedule is invalid") from exc
            if schedule is None or schedule.run.ref != run or schedule.run.plan_revision != plan_ref:
                raise ContextUnavailableError("run is not bound to this exact accepted plan")
            entry = next((item for item in schedule.entries if item.assignment.assignment_id == assignment.entity_id), None)
            if entry is None or entry.assignment.run != run or entry.assignment.work_item != work_item:
                raise ContextScopeError("assignment does not schedule this exact work definition in the run")
            attempt_row = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),)
            ).fetchone()
            if attempt_row is None or (
                attempt_row["run_id"] != str(run.entity_id)
                or attempt_row["assignment_id"] != str(assignment.entity_id)
                or attempt_row["work_item_id"] != str(work_item.entity_id)
                or attempt_row["definition_revision_id"] != str(work_item.definition_revision_id)
            ):
                raise ContextScopeError("attempt does not belong to this exact assignment")
        return {
            "plan": plan, "plan_record": record, "work": planned_work, "plan_ref": plan_ref,
            "schedule": schedule, "entry": entry, "attempt_row": attempt_row,
            "actor": actor, "work_item": work_item, "run": run, "assignment": assignment, "attempt": attempt,
        }

    def _render_complete_state(
        self,
        connection: sqlite3.Connection,
        authority: SQLiteAuthority,
        state: dict[str, object],
        *,
        expand_kind: ContextFragmentKind | None = None,
    ) -> tuple[ContextManifest, tuple[ContextFragment, ...]]:
        fragments, findings = self._render_source_state(
            connection, authority, state, expand_kind=expand_kind,
        )
        complete = (*fragments, self._finding_fragment(
            connection, state, findings, include_large=expand_kind is ContextFragmentKind.FINDINGS,
        ))
        target = state["work_item"]
        return _make_manifest(
            state["plan"].revision.ref, target, state["run"], state["assignment"], state["attempt"],
            tuple(item.reference for item in complete), state.get("since_revision"),
        ), complete

    def _render_source_state(
        self,
        connection: sqlite3.Connection,
        authority: SQLiteAuthority,
        state: dict[str, object],
        *,
        expand_kind: ContextFragmentKind | None = None,
    ) -> tuple[tuple[ContextFragment, ...], tuple[ContextFinding, ...]]:
        plan = state["plan"]
        work_item = state["work_item"]
        assert isinstance(work_item, EntityRef)
        assert isinstance(plan.revision.ref, EntityRef)
        run, assignment, attempt = state["run"], state["assignment"], state["attempt"]
        anchor = "\0".join((str(authority.project.project_id), str(work_item.entity_id),
                            "" if run is None else str(run.entity_id),
                            "" if assignment is None else str(assignment.entity_id),
                            "" if attempt is None else str(attempt.entity_id)))
        work = state["work"]
        context = work.context
        requirements = []
        for item in plan.requirements:
            definition = item.definition
            if definition.work_item_id != work_item.entity_id:
                continue
            requirements.append({
                "id": definition.requirement_id,
                "kind": definition.kind,
                "description": definition.description,
                "target": definition.target,
                "check_key": definition.check_key,
                "verification": definition.verification,
                "required_evidence": definition.required_evidence,
            })
        plan_fragment = _make_fragment(connection, anchor, ContextFragmentKind.PLAN, {
            "plan_revision": plan.revision.ref,
            "sequence": plan.revision.sequence,
            "content_digest": plan.content_digest,
            "work_item_count": len(plan.work_items),
            "supplied_sections": plan.supplied_sections,
        }, include_large=expand_kind is ContextFragmentKind.PLAN)
        work_fragment = _make_fragment(connection, anchor, ContextFragmentKind.WORK_ITEM, {
            "definition": work.definition,
            "authored": {
                "objective": context.objective,
                "motivation": context.motivation,
                "scope": context.scope,
                "acceptance": context.acceptance,
                "alternatives": context.alternatives,
                "unknowns": context.unknowns,
                "delegated_judgment": context.delegated_judgment,
                "ownership": context.ownership,
            },
            "requirements": tuple(requirements),
        }, include_large=expand_kind is ContextFragmentKind.WORK_ITEM)
        fragments = [plan_fragment, work_fragment]
        if state["entry"] is not None:
            schedule = state["schedule"]
            entry = state["entry"]
            attempt_row = state["attempt_row"]
            fragments.append(_make_fragment(connection, anchor, ContextFragmentKind.ASSIGNMENT, {
                "run": schedule.run.ref,
                "run_state": schedule.run.state,
                "assignment": entry.assignment,
                "lane_id": entry.lane_id,
                "queue_position": entry.queue_position,
                "queue_policy": entry.queue_policy,
                "required_role_action": entry.required_role,
                "isolation_policy": entry.isolation_policy,
                "attempt": {
                    "attempt_id": attempt_row["attempt_id"],
                    "state": attempt_row["state"],
                    "lease_expires_at": attempt_row["lease_expires_at"],
                },
            }, include_large=expand_kind is ContextFragmentKind.ASSIGNMENT))
        blockers, decisions = native_declaration_facts(connection, plan)
        relevant_refs: set[EntityRef] = set()
        for item in plan.requirements:
            if item.definition.work_item_id == work_item.entity_id and item.definition.target is not None:
                relevant_refs.add(item.definition.target)
        for group in plan.blocking_groups:
            if group.source.reference == work_item:
                relevant_refs.update(edge.target.reference for edge in group.members)
        declaration_entity_kinds = {
            "checkpoints": EntityKind.CHECKPOINT,
            "interfaces": EntityKind.INTERFACE,
            "decisions": EntityKind.DECISION,
            "barriers": EntityKind.BARRIER,
            "rendezvous": EntityKind.BARRIER,
            "invariants": EntityKind.INVARIANT,
        }
        declaration_rows = []
        for declaration in plan.declarations:
            entity_kind = declaration_entity_kinds.get(declaration.kind)
            if entity_kind is None:
                continue
            target = EntityRef(authority.project.project_id, entity_kind, declaration.declaration_id)
            if target not in relevant_refs:
                continue
            fact = blockers.get(target)
            decision = decisions.get(str(target.entity_id)) if target.kind is EntityKind.DECISION else None
            section_to_kind = {
                "decisions": "decision", "interfaces": "interface", "checkpoints": "checkpoint",
                "barriers": "barrier", "rendezvous": "rendezvous", "invariants": "invariant",
            }
            canonical_fact = self._declaration_fact_view(
                connection, authority, plan, section_to_kind[declaration.kind], declaration.declaration_id,
                declaration.payload,
            )
            declaration_rows.append({
                "kind": declaration.kind,
                "declaration_id": declaration.declaration_id,
                "target": target,
                "authored": declaration.payload,
                "condition": None if not isinstance(fact, ConditionResult) else {
                    "status": fact.status,
                    "causes": fact.causes,
                },
                "decision_observation": decision,
                "canonical_fact": canonical_fact,
            })
        declaration_rows.sort(key=lambda item: (item["kind"], str(item["declaration_id"])))
        fragments.append(_make_fragment(connection, anchor, ContextFragmentKind.DECLARATIONS,
                                        {"declarations": tuple(declaration_rows)},
                                        include_large=expand_kind is ContextFragmentKind.DECLARATIONS))
        source_refs = self._source_references(plan, context)
        fragments.append(_make_fragment(connection, anchor, ContextFragmentKind.SOURCE_REFERENCES,
                                        {"references": source_refs},
                                        include_large=expand_kind is ContextFragmentKind.SOURCE_REFERENCES))
        semantic_revision = int(connection.execute(
            "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
        ).fetchone()[0])
        fragments.append(self._delta_fragment(
            connection, state, anchor, semantic_revision,
            include_large=expand_kind is ContextFragmentKind.SCOPED_DELTAS,
        ))
        findings = self._load_findings(connection, state)
        current_source_refs = {item.reference.fragment_id: item.reference for item in fragments
                               if item.reference.kind in _SOURCE_KINDS}
        adjusted_findings = tuple(
            ContextFinding(
                item.finding_id, item.version, item.work_item, item.plan_revision,
                item.run, item.assignment, item.attempt, item.summary,
                item.source_manifest_digest, item.source_fragments, item.actor,
                item.created_at, item.invalidated, item.invalidation_reason,
                any(current_source_refs.get(ref.fragment_id) != ref for ref in item.source_fragments),
            ) for item in findings
        )
        return tuple(fragments), adjusted_findings

    @staticmethod
    def _declaration_fact_view(
        connection: sqlite3.Connection,
        authority: SQLiteAuthority,
        plan: object,
        kind: str,
        declaration_id: StableId,
        authored_payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Expose the exact accepted declaration and its current canonical fact.

        Status alone is not enough provenance for a generated worker context.
        The view pins the immutable authored declaration digest and, when a
        native fact exists, its append-only identity/version and safe payload.
        """
        if kind == "invariant":
            declaration_digest = _sha(_canonical(_plain_context_value(authored_payload))).hex
            row = None
        else:
            record = load_plan_declaration(
                connection, authority.project, plan.revision.plan_revision_id, kind, declaration_id,
            )
            if record is None:
                raise ContextUnavailableError("accepted declaration is absent from its canonical plan")
            declaration_digest = record.digest
            row = connection.execute(
                "SELECT fact_id, fact_sequence, fact_kind, payload_json, semantic_revision, "
                "actor_id, actor_incarnation_id, occurred_at FROM declaration_facts "
                "WHERE plan_revision_id = ? AND declaration_kind = ? AND declaration_id = ? "
                "AND declaration_digest = ? ORDER BY fact_sequence DESC LIMIT 1",
                (str(plan.revision.plan_revision_id), kind, str(declaration_id), declaration_digest),
            ).fetchone()
        latest = None
        if row is not None:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError) as exc:
                raise ContextUnavailableError("canonical declaration fact is malformed") from exc
            if not isinstance(payload, dict):
                raise ContextUnavailableError("canonical declaration fact is malformed")
            latest = {
                "fact_id": StableId(row["fact_id"]),
                "fact_sequence": int(row["fact_sequence"]),
                "fact_kind": row["fact_kind"],
                "semantic_revision": int(row["semantic_revision"]),
                "payload_digest": _sha(row["payload_json"]),
                "actor": _actor_ref(
                    authority.project.project_id, row["actor_id"], row["actor_incarnation_id"],
                ),
                "occurred_at": row["occurred_at"],
                "payload": payload,
            }
        resolution = None
        if kind == "decision":
            resolved = connection.execute(
                "SELECT fact_id, fact_sequence, payload_json, semantic_revision, actor_id, "
                "actor_incarnation_id, occurred_at FROM declaration_facts "
                "WHERE plan_revision_id = ? AND declaration_kind = 'decision' AND declaration_id = ? "
                "AND declaration_digest = ? AND fact_kind = 'decision_resolved' "
                "ORDER BY fact_sequence DESC LIMIT 1",
                (str(plan.revision.plan_revision_id), str(declaration_id), declaration_digest),
            ).fetchone()
            if resolved is not None:
                try:
                    payload = json.loads(resolved["payload_json"])
                except (TypeError, ValueError) as exc:
                    raise ContextUnavailableError("canonical decision resolution is malformed") from exc
                if not isinstance(payload, dict):
                    raise ContextUnavailableError("canonical decision resolution is malformed")
                resolution = {
                    "fact_id": StableId(resolved["fact_id"]),
                    "fact_sequence": int(resolved["fact_sequence"]),
                    "semantic_revision": int(resolved["semantic_revision"]),
                    "payload_digest": _sha(resolved["payload_json"]),
                    "actor": _actor_ref(
                        authority.project.project_id, resolved["actor_id"], resolved["actor_incarnation_id"],
                    ),
                    "occurred_at": resolved["occurred_at"],
                    "option_id": payload.get("option_id"),
                    "rationale": payload.get("rationale"),
                }
        return {
            "accepted_plan_revision": plan.revision.ref,
            "accepted_plan_sequence": plan.revision.sequence,
            "accepted_declaration_digest": Sha256Digest(declaration_digest),
            "latest_fact": latest,
            "current_resolution": resolution,
        }

    def _source_references(self, plan: object, context: object) -> tuple[object, ...]:
        refs = tuple(context.references)
        linked_ids: set[str] = set()
        linked_locations: set[str] = set()
        for item in refs:
            if isinstance(item, Mapping):
                for key in ("source_id", "id"):
                    if isinstance(item.get(key), str):
                        linked_ids.add(item[key])
                if isinstance(item.get("uri"), str):
                    linked_locations.add(item["uri"])
        manifests = tuple(
            {"source_id": item.source_id, "location": item.location, "digest": item.digest}
            for item in plan.source_manifests
            if str(item.source_id) in linked_ids or item.location in linked_locations
        )
        return {"work_references": refs, "source_manifests": manifests}

    def _delta_fragment(
        self,
        connection: sqlite3.Connection,
        state: dict[str, object],
        anchor: str,
        current_revision: int,
        *,
        include_large: bool = False,
    ) -> ContextFragment:
        since_revision = state.get("since_revision")
        if since_revision is None:
            start_revision = max(0, current_revision - MAX_CONTEXT_EVENTS)
        else:
            start_revision = since_revision
        target = state["work_item"]
        anchors = {str(target.entity_id), str(target.definition_revision_id),
                   str(state["plan_ref"].entity_id)}
        for item in (state["run"], state["assignment"], state["attempt"]):
            if item is not None:
                anchors.add(str(item.entity_id))
        rows = connection.execute(
            "SELECT event_id, semantic_revision, event_ordinal, event_kind, payload_json, occurred_at, "
            "actor_id, actor_incarnation_id FROM authority_events WHERE semantic_revision > ? "
            "AND semantic_revision <= ? ORDER BY semantic_revision DESC, event_ordinal DESC LIMIT ?",
            (start_revision, current_revision, MAX_CONTEXT_EVENTS * 8),
        ).fetchall()
        selected = []
        truncated = False
        for row in rows:
            kind = row["event_kind"]
            if kind.startswith(("todo.message.", "todo.question.", "todo.context.finding.")):
                continue
            try:
                payload = json.loads(row["payload_json"])
            except ValueError:
                continue
            if not _contains_anchor(payload, anchors):
                continue
            selected.append({
                "event_id": row["event_id"],
                "semantic_revision": row["semantic_revision"],
                "ordinal": row["event_ordinal"],
                "kind": kind,
                "actor": _actor_ref(StableId(connection.execute(
                    "SELECT project_id FROM authority_meta WHERE singleton = 1"
                ).fetchone()[0]), row["actor_id"], row["actor_incarnation_id"]),
                "occurred_at": row["occurred_at"],
            })
            if len(selected) > MAX_CONTEXT_EVENTS:
                truncated = True
                break
        if len(rows) >= MAX_CONTEXT_EVENTS * 8:
            # The raw event scan itself has a hard limit. We cannot prove that
            # no older relevant event was outside that scan window.
            truncated = True
        selected = selected[:MAX_CONTEXT_EVENTS]
        selected.reverse()
        return _make_fragment(connection, anchor, ContextFragmentKind.SCOPED_DELTAS, {
            "after_revision": start_revision,
            "through_revision": current_revision,
            "metadata_only": True,
            "ordering": "ascending; when truncated, newest matching events are retained",
            "truncated": truncated,
            "events": tuple(selected),
        }, include_large=include_large)

    def _load_findings(self, connection: sqlite3.Connection, state: dict[str, object]) -> tuple[ContextFinding, ...]:
        target = state["work_item"]
        run, assignment, attempt = state["run"], state["assignment"], state["attempt"]
        rows = connection.execute(
            "SELECT v.*, i.reason AS invalidation_reason FROM context_finding_versions AS v "
            "LEFT JOIN context_finding_invalidations AS i "
            "ON i.finding_id = v.finding_id AND i.finding_version = v.version "
            "WHERE v.work_item_id = ? AND v.definition_revision_id = ? AND v.run_id IS ? "
            "AND v.assignment_id IS ? AND v.attempt_id IS ? AND v.version = ("
            "SELECT MAX(latest.version) FROM context_finding_versions AS latest WHERE latest.finding_id = v.finding_id) "
            "ORDER BY v.created_at, v.finding_id LIMIT ?",
            (str(target.entity_id), str(target.definition_revision_id),
             None if run is None else str(run.entity_id),
             None if assignment is None else str(assignment.entity_id),
             None if attempt is None else str(attempt.entity_id), MAX_CONTEXT_FINDINGS),
        ).fetchall()
        result = []
        for row in rows:
            try:
                encoded_refs = json.loads(row["source_fragments_json"])
                if not isinstance(encoded_refs, list):
                    raise ValueError("source references are not a list")
                refs = tuple(_fragment_ref_from_payload(item) for item in encoded_refs)
                result.append(ContextFinding(
                    StableId(row["finding_id"]), int(row["version"]), target,
                    EntityRef(target.project_id, EntityKind.PLAN_REVISION, StableId(row["plan_revision_id"])),
                    None if row["run_id"] is None else EntityRef(target.project_id, EntityKind.RUN, StableId(row["run_id"])),
                    None if row["assignment_id"] is None else EntityRef(target.project_id, EntityKind.ASSIGNMENT, StableId(row["assignment_id"])),
                    None if row["attempt_id"] is None else EntityRef(target.project_id, EntityKind.ATTEMPT, StableId(row["attempt_id"])),
                    row["summary"], Sha256Digest(row["source_manifest_digest"]), refs,
                    _actor_ref(target.project_id, row["actor_id"], row["actor_incarnation_id"]),
                    row["created_at"], row["invalidation_reason"] is not None,
                    row["invalidation_reason"], False,
                ))
            except (TypeError, ValueError, KeyError) as exc:
                raise ContextUnavailableError("stored context finding is malformed") from exc
        return tuple(result)

    def _finding_fragment(
        self, connection: sqlite3.Connection, state: dict[str, object], findings: tuple[ContextFinding, ...],
        *, include_large: bool = False,
    ) -> ContextFragment:
        target = state["work_item"]
        anchor = "\0".join((str(target.project_id), str(target.entity_id),
                            "" if state["run"] is None else str(state["run"].entity_id),
                            "" if state["assignment"] is None else str(state["assignment"].entity_id),
                            "" if state["attempt"] is None else str(state["attempt"].entity_id)))
        return _make_fragment(connection, anchor, ContextFragmentKind.FINDINGS,
                              {"findings": findings}, include_large=include_large)

    @staticmethod
    def _changes(previous: ContextManifest | None, current: ContextManifest) -> tuple[ContextFragmentChange, ...]:
        if previous is None:
            return tuple(ContextFragmentChange(item.fragment_id, ContextChangeKind.ADDED, None, item)
                         for item in current.fragments)
        previous_refs = {item.fragment_id: item for item in previous.fragments}
        current_refs = {item.fragment_id: item for item in current.fragments}
        result = []
        for fragment_id in sorted(set(previous_refs) | set(current_refs), key=str):
            old, new = previous_refs.get(fragment_id), current_refs.get(fragment_id)
            if old is None:
                change = ContextChangeKind.ADDED
            elif new is None:
                change = ContextChangeKind.INVALIDATED
            elif old.digest == new.digest:
                change = ContextChangeKind.UNCHANGED
            else:
                change = ContextChangeKind.CHANGED
            result.append(ContextFragmentChange(
                fragment_id, change, None if old is None else old.digest, new,
            ))
        return tuple(result)

    @staticmethod
    def _validate_source_refs(
        manifest: ContextManifest, source_fragments: tuple[ContextFragmentRef, ...],
    ) -> None:
        if not isinstance(source_fragments, tuple) or not source_fragments or any(
            not isinstance(item, ContextFragmentRef) for item in source_fragments
        ):
            raise ValueError("source_fragments must be a non-empty tuple of typed fragment references")
        if len({item.fragment_id for item in source_fragments}) != len(source_fragments):
            raise ValueError("source_fragments must be unique")
        known = {item.fragment_id: item for item in manifest.fragments}
        if any(item.kind not in _SOURCE_KINDS or known.get(item.fragment_id) != item for item in source_fragments):
            raise ContextStaleError("finding provenance must cite exact source fragments in the supplied manifest")

    @staticmethod
    def _check_source_manifest(
        submitted: ContextManifest,
        current: ContextManifest,
        source_fragments: tuple[ContextFragmentRef, ...] | None,
    ) -> None:
        if (submitted.plan_revision != current.plan_revision or submitted.work_item != current.work_item
                or submitted.run != current.run or submitted.assignment != current.assignment
                or submitted.attempt != current.attempt
                or submitted.source_digest != current.source_digest):
            raise ContextStaleError("accepted source context changed before the finding mutation")
        if source_fragments is not None:
            current_refs = {item.fragment_id: item for item in current.fragments}
            if any(current_refs.get(item.fragment_id) != item for item in source_fragments):
                raise ContextStaleError("one or more cited source fragments changed before publication")

    @staticmethod
    def _bounded_capsule(
        manifest: ContextManifest,
        semantic_revision: int,
        fragments: tuple[ContextFragment, ...],
        changes: tuple[ContextFragmentChange, ...],
        max_bytes: int,
    ) -> ContextCapsule:
        reported_changes = changes
        changes_truncated = False
        # The complete manifest already names every current fragment. If the
        # full delta cannot fit beside it, return an explicit partial reference
        # envelope instead of failing the whole context request.
        baseline = ContextCapsule(
            manifest, semantic_revision, (), tuple(item.reference for item in fragments),
            reported_changes, ContextCapsuleStatus.PARTIAL, 0,
        )
        if _capsule_size(baseline) > max_bytes and reported_changes:
            reported_changes = ()
            changes_truncated = True
            baseline = ContextCapsule(
                manifest, semantic_revision, (), tuple(item.reference for item in fragments),
                (), ContextCapsuleStatus.PARTIAL, 0, True,
            )
        if _capsule_size(baseline) > max_bytes:
            required_bytes = _capsule_size(baseline)
            raise ContextUnavailableError(
                f"context reference envelope requires at least {required_bytes} bytes; retry with a larger max_bytes",
                required_bytes=required_bytes,
            )

        included: list[ContextFragment] = []
        omitted: list[ContextFragmentRef] = []
        for fragment in sorted(fragments, key=lambda item: _FRAGMENT_ORDER.index(item.reference.kind)):
            candidate = [*included, fragment]
            tentative_omitted = [item.reference for item in fragments if item not in candidate]
            capsule = ContextCapsule(
                manifest, semantic_revision, tuple(candidate), tuple(tentative_omitted), reported_changes,
                ContextCapsuleStatus.PARTIAL if tentative_omitted or changes_truncated else ContextCapsuleStatus.READY,
                0, changes_truncated,
            )
            size = _capsule_size(capsule)
            if size <= max_bytes:
                included.append(fragment)
            else:
                omitted.append(fragment.reference)
        result = ContextCapsule(
            manifest, semantic_revision, tuple(included), tuple(omitted), reported_changes,
            ContextCapsuleStatus.PARTIAL if omitted or changes_truncated else ContextCapsuleStatus.READY,
            0, changes_truncated,
        )
        actual = _capsule_size(result)
        if actual > max_bytes:
            # The baseline envelope was checked above; this guards future DTO
            # fields and implementation drift.
            raise ContextUnavailableError("context reference envelope exceeds the byte budget")
        result = ContextCapsule(
            manifest, semantic_revision, tuple(included), tuple(omitted), reported_changes,
            result.status, actual, changes_truncated,
        )
        if _capsule_size(result) != actual:
            actual = _capsule_size(result)
            result = ContextCapsule(
                manifest, semantic_revision, tuple(included), tuple(omitted), reported_changes,
                result.status, actual, changes_truncated,
            )
        return result


def _contains_anchor(value: object, anchors: set[str]) -> bool:
    if isinstance(value, str):
        return value in anchors
    if isinstance(value, Mapping):
        return any(_contains_anchor(key, anchors) or _contains_anchor(item, anchors)
                   for key, item in value.items())
    if isinstance(value, (tuple, list)):
        return any(_contains_anchor(item, anchors) for item in value)
    return False


def _capsule_payload(capsule: ContextCapsule, encoded_bytes: int | None = None) -> dict[str, object]:
    manifest = capsule.manifest
    return {
        "format": "todo-orchestrator.context-capsule",
        "version": 1,
        "manifest": {
            "plan_revision": _ref_payload(manifest.plan_revision),
            "work_item": _ref_payload(manifest.work_item),
            "run": _ref_payload(manifest.run),
            "assignment": _ref_payload(manifest.assignment),
            "attempt": _ref_payload(manifest.attempt),
            "fragments": [_fragment_ref_payload(item) for item in manifest.fragments],
            "digest": manifest.digest.hex,
            "source_digest": manifest.source_digest.hex,
            "since_revision": manifest.since_revision,
        },
        "semantic_revision": capsule.semantic_revision,
        "fragments": [{"reference": _fragment_ref_payload(item.reference), "payload": json.loads(item.payload_json)}
                      for item in capsule.fragments],
        "omitted": [_fragment_ref_payload(item) for item in capsule.omitted],
        "changes": [{
            "fragment_id": str(item.fragment_id), "kind": item.kind.value,
            "previous_digest": None if item.previous_digest is None else item.previous_digest.hex,
            "current": None if item.current is None else _fragment_ref_payload(item.current),
        } for item in capsule.changes],
        "changes_truncated": capsule.changes_truncated,
        "status": capsule.status.value,
        "encoded_bytes": capsule.encoded_bytes if encoded_bytes is None else encoded_bytes,
    }


def serialize_context_capsule(capsule: ContextCapsule) -> str:
    if not isinstance(capsule, ContextCapsule):
        raise TypeError("capsule must be a ContextCapsule")
    return _canonical(_capsule_payload(capsule))


def _capsule_size(capsule: ContextCapsule) -> int:
    # encoded_bytes has a small self-reference; iterate until its decimal width settles.
    size = len(_canonical(_capsule_payload(capsule, 0)).encode("utf-8"))
    while True:
        updated = len(_canonical(_capsule_payload(capsule, size)).encode("utf-8"))
        if updated == size:
            return size
        size = updated


def _chunk_expansion(
    manifest: ContextManifest,
    reference: ContextFragmentRef,
    payload_json: str,
    content_digest: Sha256Digest,
    offset: int,
    max_bytes: int,
) -> ContextExpansion:
    content = payload_json.encode("utf-8")
    if offset >= len(content):
        raise ValueError("offset must identify a byte inside the expanded fragment")
    if _sha(payload_json) != content_digest:
        raise ContextUnavailableError("expanded fragment failed its content digest check")
    chunk_size = min(CONTEXT_EXPANSION_CHUNK_BYTES, len(content) - offset)
    while chunk_size > 0:
        end = offset + chunk_size
        result = ContextExpansion(
            ContextExpansionStatus.READY, manifest, None, None,
            base64.b64encode(content[offset:end]).decode("ascii"), offset, len(content),
            content_digest, end if end < len(content) else None, reference,
        )
        if len(serialize_context_expansion(result).encode("utf-8")) <= max_bytes:
            return result
        chunk_size //= 2
    raise ContextUnavailableError("context expansion envelope cannot fit the requested byte budget")


def serialize_context_expansion(expansion: ContextExpansion) -> str:
    if not isinstance(expansion, ContextExpansion):
        raise TypeError("expansion must be a ContextExpansion")
    manifest = expansion.manifest
    return _canonical({
        "format": "todo-orchestrator.context-expansion",
        "version": 1,
        "status": expansion.status.value,
        "manifest_digest": None if manifest is None else manifest.digest.hex,
        "since_revision": None if manifest is None else manifest.since_revision,
        "fragment": None if expansion.fragment is None else {
            "reference": _fragment_ref_payload(expansion.fragment.reference),
            "payload": json.loads(expansion.fragment.payload_json),
        },
        "chunk": None if expansion.chunk_base64 is None else {
            "reference": _fragment_ref_payload(expansion.reference),
            "encoding": "base64-utf8-bytes",
            "offset": expansion.offset,
            "total_bytes": expansion.total_bytes,
            "next_offset": expansion.next_offset,
            "content_digest": expansion.content_digest.hex,
            "data": expansion.chunk_base64,
        },
        "reason": expansion.reason,
    })


__all__ = [
    "CONTEXT_FINDING_INVALIDATE_ACTION", "CONTEXT_FINDING_PUBLISH_ACTION", "CONTEXT_READ_ACTION",
    "ContextError", "ContextFindingConflictError", "ContextScopeError", "ContextService",
    "ContextStaleError", "ContextUnavailableError", "DEFAULT_CONTEXT_MAX_BYTES",
    "FINDING_INVALIDATE_COMMAND", "FINDING_PUBLISH_COMMAND", "MAX_CONTEXT_MAX_BYTES",
    "MIN_CONTEXT_MAX_BYTES", "serialize_context_capsule", "serialize_context_expansion",
]
