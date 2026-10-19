"""Strict, bounded versioned wire values for the public Python application API."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import Enum
import json
import hashlib
import os
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.model import CommandReceipt, CommandResult, DispatchResult
from todo_orchestrator.planning import ChangeSet


API_DOCUMENT_FORMAT = "todo-orchestrator.api-document"
PLAN_PREVIEW_FORMAT = "todo-orchestrator.plan-preview"
API_DOCUMENT_VERSION = 1
MAX_API_DOCUMENT_BYTES = 512 * 1024
MAX_PLAN_PREVIEW_BYTES = 256 * 1024


class ApiSerializationError(ValueError):
    """A public API document is malformed, unsupported, or too large."""


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ApiSerializationError("value cannot be represented by the versioned API codec") from exc


def _check_size(encoded: str, limit: int) -> str:
    if len(encoded.encode("utf-8")) > limit:
        raise ApiSerializationError("versioned API document exceeds its byte limit")
    return encoded


def public_value(value: object) -> object:
    """Convert supported public DTO/domain values to JSON values.

    Fields marked `repr=False` are secret-bearing and omitted. This is a
    serializer boundary for known DTOs, not a general sanitizer for authored
    free text.
    """
    if isinstance(value, StableId):
        return str(value)
    if isinstance(value, Sha256Digest):
        return value.hex
    if isinstance(value, EntityRef):
        return {
            "project_id": str(value.project_id), "kind": value.kind.value,
            "entity_id": str(value.entity_id),
            "definition_revision_id": None if value.definition_revision_id is None else str(value.definition_revision_id),
            "incarnation_id": None if value.incarnation_id is None else str(value.incarnation_id),
        }
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ApiSerializationError("naive datetimes are not serializable")
        return value.isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return value.value
    if value is None or type(value) in {str, bool, int, float}:
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ApiSerializationError("API document object keys must be strings")
            result[key] = public_value(child)
        return result
    if isinstance(value, (tuple, list)):
        return [public_value(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: public_value(getattr(value, item.name))
            for item in fields(value)
            if item.repr and item.name not in {"bearer_token", "token", "password", "secret"}
        }
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return public_value(value.to_dict())
    raise ApiSerializationError(f"unsupported API value type: {type(value).__name__}")


@dataclass(frozen=True)
class ApiDocumentV1:
    """Generic versioned envelope for inspections and typed operation views."""

    kind: str
    payload: Mapping[str, object]
    format: str = API_DOCUMENT_FORMAT
    version: int = API_DOCUMENT_VERSION

    def __post_init__(self) -> None:
        if self.format != API_DOCUMENT_FORMAT or type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported API document format")
        if not isinstance(self.kind, str) or not self.kind.strip() or len(self.kind) > 80:
            raise ValueError("API document kind must be non-empty text of at most 80 characters")
        if not isinstance(self.payload, Mapping):
            raise TypeError("API document payload must be an object mapping")
        normalized = public_value(self.payload)
        if not isinstance(normalized, dict):
            raise TypeError("API document payload must be an object mapping")
        object.__setattr__(self, "payload", MappingProxyType(normalized))
        _check_size(self.to_json(), MAX_API_DOCUMENT_BYTES)

    def to_dict(self) -> dict[str, object]:
        return {"format": self.format, "version": self.version, "kind": self.kind,
                "payload": public_value(self.payload)}

    def to_json(self) -> str:
        return _check_size(_canonical(self.to_dict()), MAX_API_DOCUMENT_BYTES)

    @classmethod
    def from_json(cls, encoded: str, *, expected_kind: str | None = None) -> "ApiDocumentV1":
        value = _parse_canonical(encoded, MAX_API_DOCUMENT_BYTES)
        if not isinstance(value, dict) or set(value) != {"format", "version", "kind", "payload"}:
            raise ApiSerializationError("API document fields do not match version 1")
        if type(value["version"]) is not int or not isinstance(value["payload"], dict):
            raise ApiSerializationError("API document version or payload is invalid")
        if expected_kind is not None and value["kind"] != expected_kind:
            raise ApiSerializationError("API document has the wrong kind")
        return cls(value["kind"], value["payload"], value["format"], value["version"])


@dataclass(frozen=True)
class PlanPreviewV1:
    project_id: StableId
    authority_id: StableId
    expected_authority_revision: int
    expected_plan_revision_id: StableId | None
    proposed_revision_id: StableId
    package_digest: Sha256Digest
    change_digest: Sha256Digest
    operations: tuple[Mapping[str, object], ...]
    conflicts: tuple[Mapping[str, object], ...]
    warnings: tuple[str, ...]
    has_conflicts: bool
    format: str = PLAN_PREVIEW_FORMAT
    version: int = 1

    def __post_init__(self) -> None:
        if self.format != PLAN_PREVIEW_FORMAT or type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported plan preview format")
        if not isinstance(self.project_id, StableId) or not isinstance(self.authority_id, StableId):
            raise TypeError("preview identity must use StableId values")
        if type(self.expected_authority_revision) is not int or self.expected_authority_revision < 0:
            raise ValueError("expected_authority_revision must be non-negative")
        if self.expected_plan_revision_id is not None and not isinstance(self.expected_plan_revision_id, StableId):
            raise TypeError("expected_plan_revision_id must be StableId or None")
        if not isinstance(self.proposed_revision_id, StableId):
            raise TypeError("proposed_revision_id must be StableId")
        if not isinstance(self.package_digest, Sha256Digest) or not isinstance(self.change_digest, Sha256Digest):
            raise TypeError("preview digests must use Sha256Digest values")
        if type(self.has_conflicts) is not bool:
            raise TypeError("has_conflicts must be bool")
        if not isinstance(self.operations, tuple) or not isinstance(self.conflicts, tuple):
            raise TypeError("preview operations and conflicts must be tuples")
        if not isinstance(self.warnings, tuple) or any(not isinstance(item, str) for item in self.warnings):
            raise TypeError("preview warnings must be a tuple of strings")
        _check_size(_canonical(self.to_dict()), MAX_PLAN_PREVIEW_BYTES)

    @classmethod
    def from_changes(cls, changes: ChangeSet, package_json: str) -> "PlanPreviewV1":
        package_digest = Sha256Digest(hashlib.sha256(package_json.encode("utf-8")).hexdigest())
        operations = tuple({
            "kind": item.kind.value,
            "entity_kind": item.entity_kind,
            "entity_id": str(item.entity_id),
            "before": public_value(item.before),
            "after": public_value(item.after),
            "relation": item.relation,
            "related_before": public_value(item.related_before),
            "related_after": public_value(item.related_after),
        } for item in changes.operations)
        conflicts = tuple({
            "code": item.code,
            "subject": public_value(item.subject),
            "message": item.message,
            "related": public_value(item.related),
        } for item in changes.conflicts)
        return cls(
            changes.project_id, changes.authority_id, changes.expected_authority_revision,
            changes.expected_revision_id, changes.proposed_revision_id, package_digest,
            changes.digest, operations, conflicts, tuple(changes.warnings), bool(changes.conflicts),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format, "version": self.version,
            "project_id": str(self.project_id), "authority_id": str(self.authority_id),
            "expected_authority_revision": self.expected_authority_revision,
            "expected_plan_revision_id": None if self.expected_plan_revision_id is None else str(self.expected_plan_revision_id),
            "proposed_revision_id": str(self.proposed_revision_id),
            "package_digest": self.package_digest.hex, "change_digest": self.change_digest.hex,
            "operations": public_value(self.operations), "conflicts": public_value(self.conflicts),
            "warnings": list(self.warnings), "has_conflicts": self.has_conflicts,
        }

    def to_json(self) -> str:
        return _check_size(_canonical(self.to_dict()), MAX_PLAN_PREVIEW_BYTES)

    @classmethod
    def from_json(cls, encoded: str) -> "PlanPreviewV1":
        value = _parse_canonical(encoded, MAX_PLAN_PREVIEW_BYTES)
        expected = {
            "format", "version", "project_id", "authority_id", "expected_authority_revision",
            "expected_plan_revision_id", "proposed_revision_id", "package_digest", "change_digest",
            "operations", "conflicts", "warnings", "has_conflicts",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ApiSerializationError("plan preview fields do not match version 1")
        if (type(value["version"]) is not int or type(value["expected_authority_revision"]) is not int
                or type(value["has_conflicts"]) is not bool
                or not isinstance(value["operations"], list) or not isinstance(value["conflicts"], list)
                or not isinstance(value["warnings"], list)
                or any(not isinstance(item, dict) for item in value["operations"] + value["conflicts"])
                or any(not isinstance(item, str) for item in value["warnings"])):
            raise ApiSerializationError("plan preview fields have invalid types")
        try:
            return cls(
                StableId(value["project_id"]), StableId(value["authority_id"]),
                value["expected_authority_revision"],
                None if value["expected_plan_revision_id"] is None else StableId(value["expected_plan_revision_id"]),
                StableId(value["proposed_revision_id"]), Sha256Digest(value["package_digest"]),
                Sha256Digest(value["change_digest"]), tuple(value["operations"]),
                tuple(value["conflicts"]), tuple(value["warnings"]), value["has_conflicts"],
                value["format"], value["version"],
            )
        except (TypeError, ValueError) as exc:
            raise ApiSerializationError("plan preview identity or digest is invalid") from exc


@dataclass(frozen=True)
class ApiReceiptV1:
    command_kind: str
    semantic_revision: int
    changed: bool
    receipt_id: StableId
    event_id: StableId | None
    created_at: datetime
    result: Mapping[str, object]
    format: str = API_DOCUMENT_FORMAT
    version: int = 1

    def __post_init__(self) -> None:
        if self.format != API_DOCUMENT_FORMAT or type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported API receipt format")
        if not isinstance(self.command_kind, str) or not self.command_kind:
            raise ValueError("command_kind must be non-empty text")
        if type(self.semantic_revision) is not int or self.semantic_revision < 0 or type(self.changed) is not bool:
            raise ValueError("receipt revision or changed flag is invalid")
        if not isinstance(self.receipt_id, StableId):
            raise TypeError("receipt_id must be StableId")
        if self.event_id is not None and not isinstance(self.event_id, StableId):
            raise TypeError("event_id must be StableId or None")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise ValueError("receipt time must be timezone-aware")
        if not isinstance(self.result, Mapping):
            raise TypeError("receipt result must be an object mapping")

    @classmethod
    def from_result(cls, result: CommandResult | CommandReceipt) -> "ApiReceiptV1":
        receipt = result.receipt if isinstance(result, CommandResult) else result
        if not isinstance(receipt, CommandReceipt):
            raise TypeError("result must be a CommandResult or CommandReceipt")
        return cls(receipt.command_kind, receipt.semantic_revision, receipt.changed,
                   receipt.receipt_id, receipt.event_id, receipt.created_at,
                   MappingProxyType(dict(public_value(receipt.result))))

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format, "version": self.version, "kind": "command_receipt",
            "command_kind": self.command_kind, "semantic_revision": self.semantic_revision,
            "changed": self.changed, "receipt_id": str(self.receipt_id),
            "event_id": None if self.event_id is None else str(self.event_id),
            "created_at": public_value(self.created_at), "result": public_value(self.result),
        }

    def to_json(self) -> str:
        return _check_size(_canonical(self.to_dict()), MAX_API_DOCUMENT_BYTES)


@dataclass(frozen=True)
class DispatchReceiptV1:
    """One-time dispatch grant. Bearer is explicitly accessible, never serialized."""

    attempt_ref: EntityRef
    work_item_ref: EntityRef
    run_ref: EntityRef | None
    assignment_ref: EntityRef | None
    lease_id: StableId
    semantic_revision: int
    receipt: ApiReceiptV1
    bearer_token: str

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_ref, EntityRef) or self.attempt_ref.kind is not EntityKind.ATTEMPT:
            raise TypeError("attempt_ref must reference an attempt")
        if not isinstance(self.work_item_ref, EntityRef) or self.work_item_ref.kind is not EntityKind.WORK_ITEM:
            raise TypeError("work_item_ref must reference a work definition")
        if not isinstance(self.lease_id, StableId) or not isinstance(self.receipt, ApiReceiptV1):
            raise TypeError("dispatch receipt fields are invalid")
        if type(self.semantic_revision) is not int or self.semantic_revision < 0:
            raise ValueError("semantic_revision must be non-negative")
        if not isinstance(self.bearer_token, str) or not self.bearer_token:
            raise ValueError("bearer token is unavailable")

    def __repr__(self) -> str:
        return (f"DispatchReceiptV1(attempt_ref={self.attempt_ref!r}, work_item_ref={self.work_item_ref!r}, "
                f"run_ref={self.run_ref!r}, assignment_ref={self.assignment_ref!r}, lease_id={self.lease_id!r}, "
                f"semantic_revision={self.semantic_revision}, receipt={self.receipt!r}, bearer_token=<redacted>)")

    def write_bearer(self, path: str) -> None:
        _write_secret_no_replace(path, self.bearer_token)

    def to_dict(self) -> dict[str, object]:
        return {
            "format": API_DOCUMENT_FORMAT, "version": 1, "kind": "dispatch_receipt",
            "attempt_ref": public_value(self.attempt_ref), "work_item_ref": public_value(self.work_item_ref),
            "run_ref": public_value(self.run_ref), "assignment_ref": public_value(self.assignment_ref),
            "lease_id": str(self.lease_id), "semantic_revision": self.semantic_revision,
            "receipt": self.receipt.to_dict(),
        }

    def to_json(self) -> str:
        return _check_size(_canonical(self.to_dict()), MAX_API_DOCUMENT_BYTES)


@dataclass(frozen=True)
class CandidateReceiptV1:
    candidate_ref: EntityRef
    attempt_ref: EntityRef
    target: EntityRef
    disposition: str
    semantic_revision: int
    receipt: ApiReceiptV1

    def to_dict(self) -> dict[str, object]:
        return {"format": API_DOCUMENT_FORMAT, "version": 1, "kind": "candidate_receipt",
                "candidate_ref": public_value(self.candidate_ref), "attempt_ref": public_value(self.attempt_ref),
                "target": public_value(self.target), "disposition": self.disposition,
                "semantic_revision": self.semantic_revision, "receipt": self.receipt.to_dict()}

    def to_json(self) -> str:
        return _check_size(_canonical(self.to_dict()), MAX_API_DOCUMENT_BYTES)


def serialize_public_document(kind: str, value: object, *, max_bytes: int = MAX_API_DOCUMENT_BYTES) -> str:
    payload = public_value(value)
    if not isinstance(payload, dict):
        payload = {"value": payload}
    return _bounded_document(kind, payload, max_bytes)


def recovery_intent_from_json(encoded: str):
    """Decode a public recovery intent document without trusting its authority."""
    from todo_orchestrator.views.recovery import (
        RecoveryIntent, RecoveryIntentKind, RecoveryPrecondition,
    )

    document = ApiDocumentV1.from_json(encoded, expected_kind="recovery_intent")
    value = dict(document.payload)
    expected = {
        "kind", "attempt", "target", "operations", "expected_authority_revision",
        "expected_lease_id", "expected_source_digest", "workspace_id", "preconditions",
    }
    if set(value) != expected:
        raise ApiSerializationError("recovery intent fields do not match version 1")
    if (type(value["expected_authority_revision"]) is not int
            or not isinstance(value["operations"], list)
            or not isinstance(value["preconditions"], list)):
        raise ApiSerializationError("recovery intent values are invalid")
    try:
        return RecoveryIntent(
            RecoveryIntentKind(value["kind"]), _parse_ref(value["attempt"]),
            _parse_ref(value["target"]), tuple(_parse_ref(item) for item in value["operations"]),
            value["expected_authority_revision"],
            None if value["expected_lease_id"] is None else StableId(value["expected_lease_id"]),
            None if value["expected_source_digest"] is None else Sha256Digest(value["expected_source_digest"]),
            None if value["workspace_id"] is None else StableId(value["workspace_id"]),
            tuple(RecoveryPrecondition(
                item["code"], item["satisfied"], _parse_ref(item["subject"]), item["detail"],
            ) for item in value["preconditions"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiSerializationError("recovery intent values are malformed") from exc


def _parse_ref(value: object) -> EntityRef | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "project_id", "kind", "entity_id", "definition_revision_id", "incarnation_id",
    }:
        raise ValueError("reference fields do not match version 1")
    return EntityRef(
        StableId(value["project_id"]), EntityKind(value["kind"]), StableId(value["entity_id"]),
        None if value["definition_revision_id"] is None else StableId(value["definition_revision_id"]),
        None if value["incarnation_id"] is None else StableId(value["incarnation_id"]),
    )


def _bounded_document(kind: str, payload: Mapping[str, object], max_bytes: int) -> str:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    encoded = _canonical({"format": API_DOCUMENT_FORMAT, "version": 1, "kind": kind,
                          "payload": public_value(payload)})
    return _check_size(encoded, min(max_bytes, MAX_API_DOCUMENT_BYTES))


def _parse_canonical(encoded: str, limit: int) -> object:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > limit:
        raise ApiSerializationError("versioned API document is absent or exceeds its byte limit")
    try:
        value = json.loads(encoded, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
    except (TypeError, ValueError):
        raise ApiSerializationError("versioned API document is not valid JSON") from None
    if _canonical(value) != encoded:
        raise ApiSerializationError("versioned API document must use canonical JSON encoding")
    return value


def _write_secret_no_replace(path: str, secret: str) -> None:
    destination = Path(path).expanduser()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(destination, flags, 0o600)
    except FileExistsError:
        raise FileExistsError("credential destination already exists; refusing to replace it") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(secret)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise


__all__ = [
    "API_DOCUMENT_FORMAT", "API_DOCUMENT_VERSION", "MAX_API_DOCUMENT_BYTES",
    "ApiDocumentV1", "ApiReceiptV1", "ApiSerializationError", "CandidateReceiptV1",
    "DispatchReceiptV1", "PlanPreviewV1", "public_value", "recovery_intent_from_json",
    "serialize_public_document",
]
