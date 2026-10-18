"""Typed, bounded coordination-context views and authored findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any

from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId


class ContextFragmentKind(str, Enum):
    PLAN = "plan"
    WORK_ITEM = "work_item"
    ASSIGNMENT = "assignment"
    DECLARATIONS = "declarations"
    SOURCE_REFERENCES = "source_references"
    SCOPED_DELTAS = "scoped_deltas"
    FINDINGS = "findings"


class ContextChangeKind(str, Enum):
    ADDED = "added"
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    INVALIDATED = "invalidated"


class ContextCapsuleStatus(str, Enum):
    READY = "ready"
    PARTIAL = "partial"


class ContextExpansionStatus(str, Enum):
    READY = "ready"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ContextFragmentRef:
    """Stable fragment identity plus the digest of this immutable rendering."""

    fragment_id: StableId
    kind: ContextFragmentKind
    digest: Sha256Digest

    def __post_init__(self) -> None:
        if not isinstance(self.fragment_id, StableId) or not isinstance(self.kind, ContextFragmentKind):
            raise TypeError("fragment identity requires a StableId and ContextFragmentKind")
        if not isinstance(self.digest, Sha256Digest):
            raise TypeError("fragment digest must be a Sha256Digest")


@dataclass(frozen=True)
class ContextManifest:
    """Complete bounded manifest. Findings are excluded from source_digest."""

    plan_revision: EntityRef
    work_item: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    attempt: EntityRef | None
    fragments: tuple[ContextFragmentRef, ...]
    digest: Sha256Digest
    source_digest: Sha256Digest
    since_revision: int | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.plan_revision, EntityRef)
                or self.plan_revision.kind is not EntityKind.PLAN_REVISION):
            raise ValueError("plan_revision must be an exact plan revision reference")
        if (not isinstance(self.work_item, EntityRef)
                or self.work_item.kind is not EntityKind.WORK_ITEM
                or self.work_item.project_id != self.plan_revision.project_id):
            raise ValueError("work_item must be an exact work definition in the plan project")
        context = (self.run, self.assignment, self.attempt)
        if any(value is not None for value in context) and any(value is None for value in context):
            raise ValueError("run, assignment, and attempt context must be supplied together")
        for value, kind in zip(context, (EntityKind.RUN, EntityKind.ASSIGNMENT, EntityKind.ATTEMPT)):
            if value is not None and (value.kind is not kind or value.project_id != self.work_item.project_id):
                raise ValueError("context references must be project-local run/assignment/attempt values")
        if not isinstance(self.fragments, tuple) or any(
            not isinstance(item, ContextFragmentRef) for item in self.fragments
        ):
            raise TypeError("fragments must be a tuple of ContextFragmentRef values")
        if len(self.fragments) > len(ContextFragmentKind):
            raise ValueError("manifest contains more fragments than the supported fragment kinds")
        if len({item.fragment_id for item in self.fragments}) != len(self.fragments):
            raise ValueError("fragment IDs must be unique in a manifest")
        if len({item.kind for item in self.fragments}) != len(self.fragments):
            raise ValueError("manifest may contain only one version of each fragment kind")
        if not isinstance(self.digest, Sha256Digest) or not isinstance(self.source_digest, Sha256Digest):
            raise TypeError("manifest digests must be SHA-256 values")
        if self.since_revision is not None and (
            type(self.since_revision) is not int or self.since_revision < 0
        ):
            raise ValueError("since_revision must be a non-negative semantic revision or None")


@dataclass(frozen=True)
class ContextFragment:
    """Canonical JSON payload returned for one manifest entry."""

    reference: ContextFragmentRef
    payload_json: str

    def __post_init__(self) -> None:
        if not isinstance(self.reference, ContextFragmentRef) or not isinstance(self.payload_json, str):
            raise TypeError("fragment requires a typed reference and canonical JSON text")
        try:
            value = json.loads(self.payload_json)
            canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("fragment payload must be valid JSON") from exc
        if canonical != self.payload_json:
            raise ValueError("fragment payload must use canonical JSON encoding")
        if len(self.payload_json.encode("utf-8")) > 65536:
            raise ValueError("fragment payload exceeds the supported expanded limit")


@dataclass(frozen=True)
class ContextFragmentChange:
    fragment_id: StableId
    kind: ContextChangeKind
    previous_digest: Sha256Digest | None
    current: ContextFragmentRef | None

    def __post_init__(self) -> None:
        if not isinstance(self.fragment_id, StableId) or not isinstance(self.kind, ContextChangeKind):
            raise TypeError("fragment change requires a stable ID and change kind")
        if self.previous_digest is not None and not isinstance(self.previous_digest, Sha256Digest):
            raise TypeError("previous_digest must be a SHA-256 digest or None")
        if self.current is not None and (
            not isinstance(self.current, ContextFragmentRef) or self.current.fragment_id != self.fragment_id
        ):
            raise ValueError("current reference must identify the changed fragment")


@dataclass(frozen=True)
class ContextCapsule:
    manifest: ContextManifest
    semantic_revision: int
    fragments: tuple[ContextFragment, ...]
    omitted: tuple[ContextFragmentRef, ...]
    changes: tuple[ContextFragmentChange, ...]
    status: ContextCapsuleStatus
    encoded_bytes: int
    changes_truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, ContextManifest):
            raise TypeError("manifest must be a ContextManifest")
        if type(self.semantic_revision) is not int or self.semantic_revision < 0:
            raise ValueError("semantic_revision must be non-negative")
        if any(not isinstance(items, tuple) for items in (self.fragments, self.omitted, self.changes)):
            raise TypeError("fragments, omitted, and changes must be tuples")
        if any(not isinstance(item, ContextFragment) for item in self.fragments):
            raise TypeError("fragments must contain ContextFragment values")
        if any(not isinstance(item, ContextFragmentRef) for item in self.omitted):
            raise TypeError("omitted must contain ContextFragmentRef values")
        if any(not isinstance(item, ContextFragmentChange) for item in self.changes):
            raise TypeError("changes must contain ContextFragmentChange values")
        if (len(self.fragments) > len(ContextFragmentKind)
                or len(self.omitted) > len(ContextFragmentKind)
                or len(self.changes) > 2 * len(ContextFragmentKind)):
            raise ValueError("capsule exceeds the supported fragment and change counts")
        if not isinstance(self.status, ContextCapsuleStatus):
            raise TypeError("status must be a ContextCapsuleStatus")
        if type(self.changes_truncated) is not bool:
            raise TypeError("changes_truncated must be a bool")
        if self.status is ContextCapsuleStatus.READY and (self.omitted or self.changes_truncated):
            raise ValueError("ready capsule cannot omit fragments or truncate its change list")
        if type(self.encoded_bytes) is not int or self.encoded_bytes < 0:
            raise ValueError("encoded_bytes must be a non-negative integer")
        manifest_refs = {item.fragment_id: item for item in self.manifest.fragments}
        for item in self.fragments:
            if manifest_refs.get(item.reference.fragment_id) != item.reference:
                raise ValueError("included fragment must match a manifest entry")
        if any(manifest_refs.get(item.fragment_id) != item for item in self.omitted):
            raise ValueError("omitted fragment must match a manifest entry")


@dataclass(frozen=True)
class ContextExpansion:
    status: ContextExpansionStatus
    manifest: ContextManifest | None
    fragment: ContextFragment | None
    reason: str | None = None
    chunk_base64: str | None = None
    offset: int | None = None
    total_bytes: int | None = None
    content_digest: Sha256Digest | None = None
    next_offset: int | None = None
    reference: ContextFragmentRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ContextExpansionStatus):
            raise TypeError("status must be a ContextExpansionStatus")
        if self.manifest is not None and not isinstance(self.manifest, ContextManifest):
            raise TypeError("manifest must be a ContextManifest or None")
        if self.fragment is not None and not isinstance(self.fragment, ContextFragment):
            raise TypeError("fragment must be a ContextFragment or None")
        if self.status is ContextExpansionStatus.READY:
            has_fragment = self.fragment is not None
            has_chunk = self.chunk_base64 is not None
            if self.manifest is None or has_fragment == has_chunk:
                raise ValueError("ready expansion requires exactly one full fragment or content chunk")
            if has_chunk and (
                type(self.offset) is not int or self.offset < 0
                or type(self.total_bytes) is not int or self.total_bytes < 1
                or not isinstance(self.content_digest, Sha256Digest)
                or not isinstance(self.reference, ContextFragmentRef)
                or (self.next_offset is not None and (
                    type(self.next_offset) is not int or self.next_offset <= self.offset
                    or self.next_offset > self.total_bytes
                ))
            ):
                raise ValueError("chunk expansion requires bounded byte offsets and content identity")
            if not has_chunk and any(value is not None for value in (
                self.offset, self.total_bytes, self.content_digest, self.next_offset,
            )):
                raise ValueError("full fragment expansion cannot carry chunk metadata")
            if not has_chunk and self.reference is not None:
                raise ValueError("full fragment expansion cannot carry a separate reference")
        elif self.fragment is not None or self.chunk_base64 is not None:
            raise ValueError("stale or unavailable expansion cannot include fragment content")
        elif any(value is not None for value in (
            self.offset, self.total_bytes, self.content_digest, self.next_offset, self.reference,
        )):
            raise ValueError("stale or unavailable expansion cannot include chunk metadata")
        if self.chunk_base64 is not None and (not isinstance(self.chunk_base64, str) or not self.chunk_base64):
            raise ValueError("chunk_base64 must be non-empty text or None")
        if self.reason is not None and (not isinstance(self.reason, str) or not self.reason.strip()):
            raise ValueError("reason must be non-empty text or None")


@dataclass(frozen=True)
class ContextFinding:
    """One authored finding version and its current append-only invalidation state."""

    finding_id: StableId
    version: int
    work_item: EntityRef
    plan_revision: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    attempt: EntityRef | None
    summary: str
    source_manifest_digest: Sha256Digest
    source_fragments: tuple[ContextFragmentRef, ...]
    actor: EntityRef
    created_at: str
    invalidated: bool
    invalidation_reason: str | None = None
    stale_source: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.finding_id, StableId):
            raise TypeError("finding_id must be a StableId")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("finding version must be positive")
        if self.work_item.kind is not EntityKind.WORK_ITEM or self.plan_revision.kind is not EntityKind.PLAN_REVISION:
            raise ValueError("finding must bind an exact work item and plan revision")
        if not isinstance(self.summary, str) or not self.summary:
            raise ValueError("finding summary must be non-empty text")
        if len(self.summary.encode("utf-8")) > 1000:
            raise ValueError("finding summary exceeds the supported text limit")
        if not isinstance(self.source_manifest_digest, Sha256Digest):
            raise TypeError("source_manifest_digest must be a SHA-256 digest")
        if not isinstance(self.source_fragments, tuple) or any(
            not isinstance(item, ContextFragmentRef) for item in self.source_fragments
        ):
            raise TypeError("source_fragments must be a tuple of ContextFragmentRef values")
        if (not self.source_fragments or len(self.source_fragments) > 5
                or len({item.fragment_id for item in self.source_fragments}) != len(self.source_fragments)):
            raise ValueError("finding source fragments must be 1 to 5 unique references")
        if not isinstance(self.actor, EntityRef) or self.actor.kind is not EntityKind.ACTOR:
            raise ValueError("finding actor must be an actor incarnation")
        if type(self.invalidated) is not bool:
            raise TypeError("invalidated must be a bool")
        if type(self.stale_source) is not bool:
            raise TypeError("stale_source must be a bool")
        if self.invalidated != (self.invalidation_reason is not None):
            raise ValueError("invalidation reason must be present exactly for invalidated findings")


__all__ = [
    "ContextCapsule", "ContextCapsuleStatus", "ContextChangeKind", "ContextExpansion",
    "ContextExpansionStatus", "ContextFinding", "ContextFragment", "ContextFragmentChange",
    "ContextFragmentKind", "ContextFragmentRef", "ContextManifest",
]
