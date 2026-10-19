"""Typed results at the Project Control legacy-import boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from todo_orchestrator.contracts import StableId


@dataclass(frozen=True)
class LegacyAttention:
    """One source contract that needs fresh native attention before dispatch."""

    task_id: str
    source_kind: str
    source_id: str
    message: str
    decision_id: StableId


@dataclass(frozen=True)
class LegacyImportPreview:
    """Deterministic, authority-revision-bound legacy migration proposal."""

    project_id: StableId
    authority_revision: int
    accepted_plan_revision_id: StableId | None
    source_project_id: str
    source_authority_revision: int
    source_digest: str
    package_json: str
    included_task_ids: tuple[str, ...]
    completed_task_ids: tuple[str, ...]
    archive_only_task_ids: tuple[str, ...]
    attention: tuple[LegacyAttention, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, StableId):
            raise TypeError("project_id must be StableId")
        if type(self.authority_revision) is not int or self.authority_revision < 0:
            raise ValueError("authority_revision must be non-negative")
        if self.accepted_plan_revision_id is not None and not isinstance(self.accepted_plan_revision_id, StableId):
            raise TypeError("accepted_plan_revision_id must be StableId or None")
        if not isinstance(self.source_digest, str) or len(self.source_digest) != 64:
            raise ValueError("source_digest must be SHA-256 hex")
        if not isinstance(self.package_json, str):
            raise TypeError("package_json must be text")
        for values, name in (
            (self.included_task_ids, "included_task_ids"),
            (self.completed_task_ids, "completed_task_ids"),
            (self.archive_only_task_ids, "archive_only_task_ids"),
            (self.attention, "attention"),
        ):
            if not isinstance(values, tuple):
                raise TypeError(f"{name} must be a tuple")


@dataclass(frozen=True)
class LegacyImportReceipt:
    """Result of one atomic archive-plus-current-plan import."""

    import_id: StableId
    source_digest: str
    plan_revision_id: StableId | None
    semantic_revision: int
    imported_work_items: int
    completion_assertions: int
    history_records: int
    attention_items: int
    replayed: bool = False


@dataclass(frozen=True)
class LegacyHistoryCursor:
    """Stable keyset cursor for legacy history search."""

    source_revision: int
    occurred_at: str
    history_id: str


@dataclass(frozen=True)
class LegacyHistoryRecord:
    """One immutable imported source-history entry linked to native work."""

    import_id: StableId
    history_id: str
    source_table: str
    source_id: str
    entity_id: str | None
    source_revision: int
    occurred_at: str
    event_type: str
    payload: Mapping[str, Any]
    native_work_item_id: StableId | None
    definition_revision_id: StableId | None


@dataclass(frozen=True)
class LegacyHistoryPage:
    records: tuple[LegacyHistoryRecord, ...]
    next_cursor: LegacyHistoryCursor | None


@dataclass(frozen=True)
class LegacyCurrentTaskCursor:
    """Keyset cursor for imported current task identity/status mappings."""

    import_id: str
    source_task_id: str


@dataclass(frozen=True)
class LegacyCurrentTask:
    """Current imported task state, linked to its exact native definition when present."""

    import_id: StableId
    source_project_id: StableId
    source_task_id: str
    source_title: str
    source_status: str
    mapping_kind: str
    native_work_item_id: StableId | None
    definition_revision_id: StableId | None
    completion_asserted: bool
    completion_assertion_digest: str | None


@dataclass(frozen=True)
class LegacyCurrentTaskPage:
    records: tuple[LegacyCurrentTask, ...]
    next_cursor: LegacyCurrentTaskCursor | None


@dataclass(frozen=True)
class LegacyProjectContextCursor:
    """Keyset cursor for immutable imported project declarations and amendments."""

    import_id: str
    source_table: str
    source_id: str


@dataclass(frozen=True)
class LegacyProjectContextRecord:
    """Sanitized source project context row with import-level provenance."""

    import_id: StableId
    source_system: str
    source_project_id: StableId
    source_schema_version: int
    source_authority_revision: int
    source_digest: str
    source_project_name: str
    source_repository_id: str | None
    import_semantic_revision: int
    imported_at: str
    source_table: str
    source_id: str
    source_entity_id: str | None
    row_revision: int | None
    row: Mapping[str, Any]
    payload: Mapping[str, Any] | None


@dataclass(frozen=True)
class LegacyProjectContextPage:
    records: tuple[LegacyProjectContextRecord, ...]
    next_cursor: LegacyProjectContextCursor | None


__all__ = [
    "LegacyAttention", "LegacyCurrentTask", "LegacyCurrentTaskCursor", "LegacyCurrentTaskPage",
    "LegacyHistoryCursor", "LegacyHistoryPage", "LegacyHistoryRecord",
    "LegacyImportPreview", "LegacyImportReceipt",
    "LegacyProjectContextCursor", "LegacyProjectContextPage", "LegacyProjectContextRecord",
]
