"""Authenticated, atomic import of sanitized Project Control Todo snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from types import MappingProxyType
from typing import Any, Mapping

from todo_orchestrator.authority.auth import AuthorizationRequirement, AuthorityAuthService
from todo_orchestrator.authority.commands import (
    CommandEffect, DuplicateCommandHandlerError, MutationContext,
)
from todo_orchestrator.authority.sqlite import (
    AuthorityError, SQLiteAuthority, store_plan_revision_snapshot,
)
from todo_orchestrator.contracts import EntityKind, EntityRef, StableId
from todo_orchestrator.planning.changes import preview_changes
from todo_orchestrator.planning.package import compile_plan_json
from todo_orchestrator.planning.service import _snapshot as _read_plan_snapshot
from todo_orchestrator.planning.snapshot import (
    encode_accepted_snapshot, materialize_accepted_plan,
)
from todo_orchestrator.operations.export import AUTHORITY_READ_ACTION, _authenticate_read

from .contracts import (
    LegacyCurrentTask, LegacyCurrentTaskCursor, LegacyCurrentTaskPage,
    LegacyHistoryCursor, LegacyHistoryPage, LegacyHistoryRecord,
    LegacyImportPreview, LegacyImportReceipt, LegacyProjectContextCursor,
    LegacyProjectContextPage, LegacyProjectContextRecord,
)
from .snapshot import (
    LEGACY_SOURCE_SYSTEM, LegacySnapshotError, build_legacy_import_preview,
    parse_legacy_snapshot, _allocate_native_task_ids,
)


LEGACY_IMPORT_ACTION = StableId("todo.migration.import")
LEGACY_IMPORT_KIND = "migration.legacy.import"
_PROJECT_CONTEXT_TABLES = frozenset({
    "project_declarations", "project_amendments", "project_fragment_invalidations",
})


class LegacyImportConflictError(AuthorityError):
    """The import conflicts with current native state or an earlier import."""


@dataclass(frozen=True)
class _ImportLegacy:
    project_id: StableId
    authority_id: StableId
    snapshot_json: str
    snapshot_digest: str
    package_json: str
    package_digest: str
    expected_authority_revision: int
    expected_plan_revision_id: StableId | None


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _current_revision(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
    if row is None or type(row[0]) is not int:
        raise LegacyImportConflictError("authority semantic revision is unavailable")
    return row[0]


def _current_plan_id(connection: sqlite3.Connection) -> StableId | None:
    row = connection.execute(
        "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    return None if row is None else StableId(row[0])


class _ImportLegacyHandler:
    kind = LEGACY_IMPORT_KIND
    command_type = _ImportLegacy

    def authorization_requirement(self, command: _ImportLegacy) -> AuthorizationRequirement:
        project = EntityRef(command.project_id, EntityKind.PROJECT, command.project_id)
        return AuthorizationRequirement(LEGACY_IMPORT_ACTION, project)

    def canonical_payload(self, command: _ImportLegacy) -> Mapping[str, Any]:
        return {
            "project_id": str(command.project_id),
            "authority_id": str(command.authority_id),
            "snapshot_digest": command.snapshot_digest,
            "package_digest": command.package_digest,
            "expected_authority_revision": command.expected_authority_revision,
            "expected_plan_revision_id": (None if command.expected_plan_revision_id is None
                                          else str(command.expected_plan_revision_id)),
        }

    def apply(self, context: MutationContext, command: _ImportLegacy) -> CommandEffect:
        if command.project_id != context.project.project_id or command.authority_id != context.project.authority_id:
            raise LegacyImportConflictError("legacy import authority/project identity mismatch")
        if command.expected_authority_revision != context.starting_revision:
            raise LegacyImportConflictError("legacy import preview is stale")
        current_plan_id = _current_plan_id(context.authority.connection)
        if current_plan_id != command.expected_plan_revision_id:
            raise LegacyImportConflictError("accepted native plan changed after legacy import preview")
        duplicate = context.authority.connection.execute(
            "SELECT import_id, source_digest FROM legacy_imports WHERE source_system = ? AND source_project_id = ?",
            (LEGACY_SOURCE_SYSTEM, _source_project_id(command.snapshot_json)),
        ).fetchone()
        if duplicate is not None:
            raise LegacyImportConflictError(
                f"source project was already imported as {duplicate['import_id']} ({duplicate['source_digest']})"
            )

        envelope, normalized_snapshot_json = parse_legacy_snapshot(command.snapshot_json)
        if normalized_snapshot_json != command.snapshot_json or envelope["snapshot_digest"] != command.snapshot_digest:
            raise LegacySnapshotError("command snapshot does not match its canonical digest")
        native_snapshot = _read_plan_snapshot(context.authority.connection, context.project)
        reserved = frozenset(
            str(item.definition.work_item_id) for item in (native_snapshot.accepted_plan.work_items
                                                              if native_snapshot.accepted_plan is not None else ())
        )
        preview = build_legacy_import_preview(
            envelope, context.project, context.starting_revision, current_plan_id,
            reserved_work_item_ids=reserved,
        )
        native_ids = _allocate_native_task_ids(
            envelope["source"]["project_id"], set(preview.included_task_ids), set(reserved),
        )
        if preview.package_json != command.package_json or _sha256(preview.package_json) != command.package_digest:
            raise LegacyImportConflictError("reviewed legacy import plan does not match the sanitized source snapshot")

        plan_revision_id = current_plan_id
        native_refs: dict[str, EntityRef] = {}
        if preview.included_task_ids:
            compiled = compile_plan_json(preview.package_json, context.project)
            if not compiled.ok or compiled.plan is None:
                raise LegacySnapshotError("converted native plan failed revalidation")
            changes = preview_changes(compiled.plan, native_snapshot)
            if changes.conflicts or any(getattr(item, "severity", None).value == "error" for item in changes.diagnostics):
                detail = ", ".join([item.code for item in changes.conflicts]
                                    + [item.code for item in changes.diagnostics])
                raise LegacyImportConflictError("native plan change is blocked: " + detail)
            if changes.is_noop:
                raise LegacyImportConflictError("legacy work plan produces no native plan change")
            accepted = materialize_accepted_plan(compiled.plan, native_snapshot, changes)
            accepted_record = encode_accepted_snapshot(
                accepted,
                authority_id=context.project.authority_id,
                semantic_revision=context.starting_revision + 1,
                based_on_revision_id=native_snapshot.accepted_revision_id,
            )
            stored = store_plan_revision_snapshot(
                context, accepted_record, based_on_revision_id=native_snapshot.accepted_revision_id,
            )
            plan_revision_id = stored.plan_revision_id
            native_refs = {
                str(item.definition.work_item_id): item.definition.ref
                for item in accepted.work_items
            }

        import_id = StableId("legacy-import-" + command.snapshot_digest[:48])
        source = envelope["source"]
        project_data = envelope["project"]
        next_revision = context.starting_revision + 1
        now = _utc_now()
        context.execute(
            "INSERT INTO legacy_imports(import_id, source_system, source_project_id, source_schema_version, "
            "source_authority_revision, source_digest, exported_at, project_name, repository_id, envelope_json, "
            "plan_revision_id, imported_by_actor_id, imported_by_incarnation_id, semantic_revision, imported_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(import_id), source["system"], source["project_id"], source["schema_version"],
             source["authority_revision"], command.snapshot_digest, source["exported_at"], project_data["name"],
             project_data.get("repository_id"), normalized_snapshot_json,
             None if plan_revision_id is None else str(plan_revision_id),
             str(context.actor.entity_id), str(context.actor.incarnation_id), next_revision, now),
        )

        legacy_to_native = {
            legacy_id: native_refs.get(native_ids[legacy_id])
            for legacy_id in _task_ids(envelope)
            if legacy_id in native_ids
        }
        legacy_to_native.update({legacy_id: None for legacy_id in _task_ids(envelope) if legacy_id not in native_ids})
        task_records = {row["id"]: row for row in envelope["tables"]["tasks"] if isinstance(row.get("id"), str)}
        for legacy_id, native_ref in sorted(legacy_to_native.items()):
            mapping_kind = "work_item" if native_ref is not None else "archive_only"
            source_task = task_records[legacy_id]
            detail = {
                "source_status": str(source_task.get("status", "unknown")),
                "source_title": (source_task["title"].strip() if isinstance(source_task.get("title"), str)
                                 and source_task["title"].strip() else legacy_id),
            }
            context.execute(
                "INSERT INTO legacy_entity_links(import_id, source_table, source_id, source_entity_id, mapping_kind, "
                "native_work_item_id, definition_revision_id, detail_json) VALUES (?, 'tasks', ?, ?, ?, ?, ?, ?)",
                (str(import_id), legacy_id, legacy_id, mapping_kind,
                 None if native_ref is None else str(native_ref.entity_id),
                 None if native_ref is None else str(native_ref.definition_revision_id), _canonical(detail)),
            )

        for source_table in sorted(_PROJECT_CONTEXT_TABLES):
            for row in envelope["tables"].get(source_table, ()):
                source_id = _project_context_source_id(source_table, row)
                entity_id = next((row.get(key) for key in ("id", "operation_id", "entity_id")
                                  if isinstance(row.get(key), str)), None)
                context_detail = _canonical({"source_row": row})
                context_digest = _sha256(context_detail)
                context_detail = _canonical({
                    "source_row": row,
                    "source_row_digest": context_digest,
                })
                context_entity = "archive_only"
                # Context records are preserved as source rows. They deliberately
                # have no synthetic native entity identity or authority effect.
                context.execute(
                    "INSERT INTO legacy_entity_links(import_id, source_table, source_id, source_entity_id, mapping_kind, "
                    "native_work_item_id, definition_revision_id, detail_json) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)",
                    (str(import_id), source_table, source_id, entity_id, context_entity, context_detail),
                )

        completed_count = 0
        for legacy_id in preview.completed_task_ids:
            native_ref = legacy_to_native[legacy_id]
            if native_ref is None:
                continue
            source_task = task_records[legacy_id]
            source_revision = source_task.get("revision", 0)
            if type(source_revision) is not int or source_revision < 0:
                source_revision = 0
            assertion = {
                "source_digest": command.snapshot_digest,
                "source_project_id": source["project_id"],
                "source_task_id": legacy_id,
                "source_revision": source_revision,
                "source_status": "done",
            }
            assertion_digest = _sha256(_canonical(assertion))
            context.execute(
                "INSERT INTO legacy_completion_assertions(import_id, source_task_id, work_item_id, "
                "definition_revision_id, source_revision, source_status, assertion_digest) "
                "VALUES (?, ?, ?, ?, ?, 'done', ?)",
                (str(import_id), legacy_id, str(native_ref.entity_id),
                 str(native_ref.definition_revision_id), source_revision, assertion_digest),
            )
            completed_count += 1

        history_rows = []
        for item in envelope["history"]:
            source_table, source_id = item["source_table"], item["source_id"]
            history_id = hashlib.sha256(
                f"{import_id}\0{source_table}\0{source_id}".encode("utf-8")
            ).hexdigest()
            payload_json = _canonical(item["payload"])
            payload_digest = _sha256(payload_json)
            linked_ref = legacy_to_native.get(item["entity_id"]) if isinstance(item["entity_id"], str) else None
            history_rows.append((
                str(import_id), history_id, source_table, source_id, item["entity_id"], item["revision"],
                item["occurred_at"], item["event_type"], payload_json, payload_digest,
                None if linked_ref is None else str(linked_ref.entity_id),
                None if linked_ref is None else str(linked_ref.definition_revision_id),
            ))
        for row in history_rows:
            context.execute(
                "INSERT INTO legacy_history(import_id, history_id, source_table, source_id, entity_id, "
                "source_revision, occurred_at, event_type, payload_json, payload_digest, native_work_item_id, "
                "definition_revision_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", row,
            )

        result = {
            "import_id": str(import_id),
            "source_digest": command.snapshot_digest,
            "plan_revision_id": None if plan_revision_id is None else str(plan_revision_id),
            "semantic_revision": next_revision,
            "imported_work_items": len(preview.included_task_ids),
            "completion_assertions": completed_count,
            "history_records": len(history_rows),
            "attention_items": len(preview.attention),
        }
        return CommandEffect(True, result, "migration.legacy.imported", result)


def _source_project_id(snapshot_json: str) -> str:
    envelope, _ = parse_legacy_snapshot(snapshot_json)
    return envelope["source"]["project_id"]


def _task_ids(envelope: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(row["id"] for row in envelope["tables"]["tasks"] if isinstance(row.get("id"), str))


def _project_context_source_id(source_table: str, row: Mapping[str, Any]) -> str:
    if source_table == "project_declarations":
        identity = [row.get("kind"), row.get("id"), row.get("version")]
    elif source_table == "project_amendments":
        identity = [row.get("operation_id")]
    elif source_table == "project_fragment_invalidations":
        identity = [row.get("id"), row.get("kind"), row.get("entity_id"), row.get("revision")]
    else:
        raise LegacyImportConflictError(f"unsupported legacy project context table {source_table!r}")
    return _canonical(identity)


class LegacyMigrationService:
    """Preview, atomically apply, and search one-time legacy Todo imports."""

    def __init__(self, auth: AuthorityAuthService):
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be AuthorityAuthService")
        self.auth = auth
        try:
            auth.dispatcher.register(_ImportLegacyHandler())
        except DuplicateCommandHandlerError:
            binding = auth.dispatcher._by_type.get(_ImportLegacy)
            if binding is None or type(binding.handler) is not _ImportLegacyHandler:
                raise

    def preview(
        self, authority: SQLiteAuthority, bearer_token: str,
        snapshot: Mapping[str, Any] | str | bytes,
    ) -> LegacyImportPreview:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be SQLiteAuthority")
        with authority.read_transaction() as connection:
            _authenticate_read(self.auth, connection, authority, bearer_token, AUTHORITY_READ_ACTION)
            revision = _current_revision(connection)
            plan_id = _current_plan_id(connection)
            native_snapshot = _read_plan_snapshot(connection, authority.project)
            reserved = frozenset(
                str(item.definition.work_item_id) for item in (native_snapshot.accepted_plan.work_items
                                                                  if native_snapshot.accepted_plan is not None else ())
            )
            return build_legacy_import_preview(
                snapshot, authority.project, revision, plan_id, reserved_work_item_ids=reserved,
            )

    def import_snapshot(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        snapshot: Mapping[str, Any] | str | bytes,
        *,
        preview: LegacyImportPreview,
        idempotency_key: StableId,
    ) -> LegacyImportReceipt:
        if not isinstance(authority, SQLiteAuthority) or authority.readonly:
            raise TypeError("authority must be a writable SQLiteAuthority")
        if not isinstance(preview, LegacyImportPreview):
            raise TypeError("preview must be a LegacyImportPreview")
        envelope, snapshot_json = parse_legacy_snapshot(snapshot)
        if preview.project_id != authority.project.project_id or preview.source_digest != envelope["snapshot_digest"]:
            raise LegacyImportConflictError("preview does not match authority project or source snapshot")
        command = _ImportLegacy(
            authority.project.project_id,
            authority.project.authority_id,
            snapshot_json,
            preview.source_digest,
            preview.package_json,
            _sha256(preview.package_json),
            preview.authority_revision,
            preview.accepted_plan_revision_id,
        )
        result = self.auth.execute(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=preview.authority_revision,
        )
        data = result.receipt.result
        try:
            return LegacyImportReceipt(
                import_id=StableId(data["import_id"]),
                source_digest=data["source_digest"],
                plan_revision_id=(None if data["plan_revision_id"] is None else StableId(data["plan_revision_id"])),
                semantic_revision=data["semantic_revision"],
                imported_work_items=data["imported_work_items"],
                completion_assertions=data["completion_assertions"],
                history_records=data["history_records"],
                attention_items=data["attention_items"],
                replayed=result.replayed,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise LegacyImportConflictError("stored legacy import receipt is malformed") from exc

    def search_history(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        query: str = "",
        *,
        import_id: StableId | None = None,
        limit: int = 100,
        after: LegacyHistoryCursor | None = None,
    ) -> LegacyHistoryPage:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be SQLiteAuthority")
        if not authority.readonly:
            raise TypeError("history search requires an explicitly read-only authority")
        if not isinstance(query, str) or len(query) > 512:
            raise ValueError("history search query must be text of at most 512 characters")
        if import_id is not None and not isinstance(import_id, StableId):
            raise TypeError("import_id must be StableId or None")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("history search limit must be between 1 and 500")
        if after is not None and not isinstance(after, LegacyHistoryCursor):
            raise TypeError("after must be LegacyHistoryCursor or None")
        escaped = query.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        clauses = [
            "(? = '' OR lower(h.event_type) LIKE ? ESCAPE '\\' OR lower(h.source_table) LIKE ? ESCAPE '\\' "
            "OR lower(h.source_id) LIKE ? ESCAPE '\\' OR lower(coalesce(h.entity_id,'')) LIKE ? ESCAPE '\\' "
            "OR lower(h.payload_json) LIKE ? ESCAPE '\\')",
            "(? IS NULL OR i.import_id = ?)",
        ]
        params: list[object] = [query, pattern, pattern, pattern, pattern, pattern,
                                None if import_id is None else str(import_id),
                                None if import_id is None else str(import_id)]
        if after is not None:
            clauses.append(
                "(h.source_revision > ? OR (h.source_revision = ? AND h.occurred_at > ?) "
                "OR (h.source_revision = ? AND h.occurred_at = ? AND h.history_id > ?))"
            )
            params.extend((after.source_revision, after.source_revision, after.occurred_at,
                           after.source_revision, after.occurred_at, after.history_id))
        sql = (
            "SELECT h.*, i.import_id FROM legacy_history AS h JOIN legacy_imports AS i USING(import_id) WHERE "
            + " AND ".join(clauses)
            + " ORDER BY h.source_revision, h.occurred_at, h.history_id LIMIT ?"
        )
        params.append(limit + 1)
        with authority.read_transaction() as connection:
            _authenticate_read(self.auth, connection, authority, bearer_token, AUTHORITY_READ_ACTION)
            rows = connection.execute(sql, params).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        records = tuple(_history_record(row) for row in rows)
        next_cursor = None
        if has_more and records:
            last = rows[-1]
            next_cursor = LegacyHistoryCursor(last["source_revision"], last["occurred_at"], last["history_id"])
        return LegacyHistoryPage(records, next_cursor)

    def read_current_tasks(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        *,
        import_id: StableId | None = None,
        limit: int = 100,
        after: LegacyCurrentTaskCursor | None = None,
    ) -> LegacyCurrentTaskPage:
        """Read current source task IDs/statuses and their exact native links."""

        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be SQLiteAuthority")
        if not authority.readonly:
            raise TypeError("current legacy task reads require an explicitly read-only authority")
        if import_id is not None and not isinstance(import_id, StableId):
            raise TypeError("import_id must be StableId or None")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("current legacy task page limit must be between 1 and 500")
        if after is not None and not isinstance(after, LegacyCurrentTaskCursor):
            raise TypeError("after must be LegacyCurrentTaskCursor or None")

        clauses = ["l.source_table = 'tasks'", "(? IS NULL OR l.import_id = ?)"]
        params: list[object] = [
            None if import_id is None else str(import_id),
            None if import_id is None else str(import_id),
        ]
        if after is not None:
            clauses.append("(l.import_id > ? OR (l.import_id = ? AND l.source_id > ?))")
            params.extend((after.import_id, after.import_id, after.source_task_id))
        sql = (
            "SELECT i.import_id, i.source_project_id, l.source_id, l.mapping_kind, l.detail_json, "
            "l.native_work_item_id, l.definition_revision_id, c.assertion_digest "
            "FROM legacy_entity_links AS l JOIN legacy_imports AS i USING(import_id) "
            "LEFT JOIN legacy_completion_assertions AS c "
            "ON c.import_id = l.import_id AND c.source_task_id = l.source_id "
            "WHERE " + " AND ".join(clauses) + " "
            "ORDER BY l.import_id, l.source_id LIMIT ?"
        )
        params.append(limit + 1)
        with authority.read_transaction() as connection:
            _authenticate_read(self.auth, connection, authority, bearer_token, AUTHORITY_READ_ACTION)
            rows = connection.execute(sql, params).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        records = tuple(_current_task_record(row) for row in rows)
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = LegacyCurrentTaskCursor(last["import_id"], last["source_id"])
        return LegacyCurrentTaskPage(records, next_cursor)

    def read_project_context(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        *,
        import_id: StableId | None = None,
        limit: int = 100,
        after: LegacyProjectContextCursor | None = None,
    ) -> LegacyProjectContextPage:
        """Read sanitized project declarations/amendments without opening the archive envelope."""

        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be SQLiteAuthority")
        if not authority.readonly:
            raise TypeError("project context reads require an explicitly read-only authority")
        if import_id is not None and not isinstance(import_id, StableId):
            raise TypeError("import_id must be StableId or None")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("project context page limit must be between 1 and 200")
        if after is not None and not isinstance(after, LegacyProjectContextCursor):
            raise TypeError("after must be LegacyProjectContextCursor or None")

        clauses = [
            "l.source_table IN ('project_declarations', 'project_amendments', 'project_fragment_invalidations')",
            "(? IS NULL OR l.import_id = ?)",
        ]
        params: list[object] = [
            None if import_id is None else str(import_id),
            None if import_id is None else str(import_id),
        ]
        if after is not None:
            clauses.append(
                "(l.import_id > ? OR (l.import_id = ? AND l.source_table > ?) "
                "OR (l.import_id = ? AND l.source_table = ? AND l.source_id > ?))"
            )
            params.extend((after.import_id, after.import_id, after.source_table,
                           after.import_id, after.source_table, after.source_id))
        sql = (
            "SELECT i.import_id, i.source_system, i.source_project_id, i.source_schema_version, "
            "i.source_authority_revision, i.source_digest, i.project_name, i.repository_id, "
            "i.semantic_revision, i.imported_at, l.source_table, l.source_id, l.source_entity_id, l.detail_json "
            "FROM legacy_entity_links AS l JOIN legacy_imports AS i USING(import_id) WHERE "
            + " AND ".join(clauses)
            + " ORDER BY l.import_id, l.source_table, l.source_id LIMIT ?"
        )
        params.append(limit + 1)
        with authority.read_transaction() as connection:
            _authenticate_read(self.auth, connection, authority, bearer_token, AUTHORITY_READ_ACTION)
            rows = connection.execute(sql, params).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        records = tuple(_project_context_record(row) for row in rows)
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = LegacyProjectContextCursor(last["import_id"], last["source_table"], last["source_id"])
        return LegacyProjectContextPage(records, next_cursor)


def _history_record(row: sqlite3.Row) -> LegacyHistoryRecord:
    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, ValueError) as exc:
        raise LegacyImportConflictError("stored legacy history payload is malformed") from exc
    if not isinstance(payload, dict):
        raise LegacyImportConflictError("stored legacy history payload is not an object")
    native_id = row["native_work_item_id"]
    definition_id = row["definition_revision_id"]
    return LegacyHistoryRecord(
        StableId(row["import_id"]), row["history_id"], row["source_table"], row["source_id"],
        row["entity_id"], row["source_revision"], row["occurred_at"], row["event_type"],
        MappingProxyType(payload), None if native_id is None else StableId(native_id),
        None if definition_id is None else StableId(definition_id),
    )


def _current_task_record(row: sqlite3.Row) -> LegacyCurrentTask:
    try:
        detail = json.loads(row["detail_json"])
    except (TypeError, ValueError) as exc:
        raise LegacyImportConflictError("stored legacy task mapping detail is malformed") from exc
    if (not isinstance(detail, dict) or not isinstance(detail.get("source_status"), str)
            or not isinstance(detail.get("source_title"), str)):
        raise LegacyImportConflictError("stored legacy task mapping has no source status or title")
    native_id, definition_id = row["native_work_item_id"], row["definition_revision_id"]
    return LegacyCurrentTask(
        StableId(row["import_id"]), StableId(row["source_project_id"]), row["source_id"],
        detail["source_title"], detail["source_status"],
        "current" if row["mapping_kind"] == "work_item" else row["mapping_kind"],
        None if native_id is None else StableId(native_id),
        None if definition_id is None else StableId(definition_id),
        row["assertion_digest"] is not None, row["assertion_digest"],
    )


def _project_context_record(row: sqlite3.Row) -> LegacyProjectContextRecord:
    try:
        detail = json.loads(row["detail_json"])
    except (TypeError, ValueError) as exc:
        raise LegacyImportConflictError("stored legacy project context row is malformed") from exc
    source_row = detail.get("source_row") if isinstance(detail, dict) else None
    if not isinstance(source_row, dict):
        raise LegacyImportConflictError("stored legacy project context row has no source row")
    expected_digest = detail.get("source_row_digest")
    if (not isinstance(expected_digest, str)
            or _sha256(_canonical({"source_row": source_row})) != expected_digest):
        raise LegacyImportConflictError("stored legacy project context row digest does not match")
    payload = None
    if row["source_table"] == "project_declarations":
        try:
            decoded = json.loads(source_row["payload_json"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LegacyImportConflictError("stored project declaration payload is malformed") from exc
        if not isinstance(decoded, dict):
            raise LegacyImportConflictError("stored project declaration payload is not an object")
        payload = MappingProxyType(decoded)
    source_revision = source_row.get("revision")
    if source_revision is None:
        source_revision = source_row.get("version")
    if type(source_revision) is not int or source_revision < 0:
        source_revision = None
    return LegacyProjectContextRecord(
        import_id=StableId(row["import_id"]),
        source_system=row["source_system"],
        source_project_id=StableId(row["source_project_id"]),
        source_schema_version=row["source_schema_version"],
        source_authority_revision=row["source_authority_revision"],
        source_digest=row["source_digest"],
        source_project_name=row["project_name"],
        source_repository_id=row["repository_id"],
        import_semantic_revision=row["semantic_revision"],
        imported_at=row["imported_at"],
        source_table=row["source_table"],
        source_id=row["source_id"],
        source_entity_id=row["source_entity_id"],
        row_revision=source_revision,
        row=MappingProxyType(source_row),
        payload=payload,
    )


__all__ = [
    "LEGACY_IMPORT_ACTION", "LEGACY_IMPORT_KIND", "LegacyImportConflictError", "LegacyMigrationService",
]
