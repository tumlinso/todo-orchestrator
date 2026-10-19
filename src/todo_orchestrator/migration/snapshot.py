"""Validate a sanitized legacy snapshot and convert its current work to a plan.

The importer consumes only the versioned JSON boundary. It has no imports from
Project Control and never opens the legacy authority.
"""

from __future__ import annotations

from collections import defaultdict, deque
import hashlib
import json
import re
from typing import Any, Mapping

from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.contracts.verification import VerificationContract
from todo_orchestrator.planning.package import PLAN_FORMAT, PLAN_SCHEMA_VERSION, compile_plan_json

from .contracts import LegacyAttention, LegacyImportPreview


LEGACY_SNAPSHOT_FORMAT = "todo-orchestrator.legacy-project-snapshot"
LEGACY_SNAPSHOT_VERSION = 1
LEGACY_SOURCE_SYSTEM = "project-control.todo-v2"
LEGACY_PROJECT_SCHEMA_VERSION = 2

LEGACY_TABLES = frozenset({
    "tasks", "task_dependencies", "events", "decisions", "checkpoints", "barriers",
    "barrier_requirements", "interfaces", "interface_consumers", "checkpoint_interfaces",
    "invariants", "task_invariants", "ownership_scopes", "task_artifacts", "named_locks",
    "task_locks", "claims", "lock_leases", "resource_classes", "resource_instances",
    "resource_requests", "resource_leases", "gates", "checkpoint_gates", "evidence",
    "handoffs", "migration_warnings", "task_completion_gates", "child_executions",
    "child_scope_leases", "child_attempts", "live_recovery_approvals", "live_recovery_audit",
    "workflow_runs", "workflow_run_charters", "workflow_lanes", "workflow_lane_tasks",
    "workflow_workspaces", "workflow_dispatches", "workflow_capabilities", "workflow_messages",
    "workflow_message_recipients", "workflow_message_receipts", "workflow_rendezvous",
    "workflow_rendezvous_participants", "workflow_rendezvous_arrivals", "workflow_context_fragments",
    "workflow_integration_queue", "workflow_patch_artifacts", "workflow_child_result_candidates",
    "workflow_recovery_audit", "project_amendments", "project_declarations",
    "project_fragment_invalidations",
})
_REQUIRED_TABLES = frozenset({"tasks", "task_dependencies", "events"})
_HISTORY_TABLES = frozenset({"events", "handoffs", "live_recovery_audit", "workflow_recovery_audit"})
_TERMINAL_TASK_STATUSES = frozenset({"done", "superseded", "cancelled", "stale", "closed"})
_ARCHIVE_ONLY_TASK_STATUSES = frozenset({"superseded", "cancelled", "stale", "closed"})
_ALLOWED_NATIVE_DISPOSITIONS = frozenset({
    "completed", "accepted_negative", "no_change", "evaluated_not_promoted", "failed", "superseded",
})
_LEGACY_PRIVATE_FIELDS = frozenset({
    "recovery_approval", "recovery_token", "gpu_identifier", "model_endpoint",
    "packet", "packet_body", "child_packet", "raw_packet", "log", "logs", "raw_log", "raw_logs",
    "transcript", "transcripts", "stdout", "stderr", "traceback", "capability_lineage", "child_lineage",
    "authorization", "auth_header", "api_key", "api_key_hash", "access_key", "private_key",
})
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token(?:[_ -]?hash)?|recovery[_ -]?approval|secret|credential|"
    r"lease[_ -]?hash|authorization|api[_-]?key|access[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*(?:\"([^\"]*)\"|'([^']*)'|(\[REDACTED\])|([^,\s;\]}]+))"
)
_BEARER_CREDENTIAL = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]+=*)")


class LegacySnapshotError(ValueError):
    """The input is not a supported, self-consistent legacy snapshot."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LegacySnapshotError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _contains_secret(
    value: Any,
    path: str = "$",
    *,
    skip_string_keys: frozenset[str] = frozenset(),
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if ("token" in normalized or "password" in normalized or "secret" in normalized
                    or "passwd" in normalized or "credential" in normalized
                    or ("lease" in normalized and "hash" in normalized)
                    or normalized in _LEGACY_PRIVATE_FIELDS):
                raise LegacySnapshotError(f"snapshot contains a sensitive field at {path}/{key}")
            if key not in skip_string_keys or not isinstance(child, str):
                _contains_secret(child, f"{path}/{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _contains_secret(child, f"{path}/{index}")
    elif isinstance(value, str):
        bearer = _BEARER_CREDENTIAL.search(value)
        if bearer:
            raise LegacySnapshotError(f"snapshot contains an unredacted bearer credential at {path}")
        for match in _SECRET_ASSIGNMENT.finditer(value):
            secret_value = next((group for group in match.groups()[1:] if group is not None), "")
            if secret_value.casefold() != "[redacted]":
                raise LegacySnapshotError(f"snapshot contains an unredacted sensitive value at {path}")


def _json_value(value: Any, path: str) -> None:
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is float:
        if not value.is_integer():
            raise LegacySnapshotError(f"snapshot has a non-integral SQLite value at {path}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _json_value(child, f"{path}/{index}")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise LegacySnapshotError(f"snapshot object key is not text at {path}")
            _json_value(child, f"{path}/{key}")
        return
    raise LegacySnapshotError(f"snapshot contains a non-JSON value at {path}")


def parse_legacy_snapshot(value: Mapping[str, Any] | str | bytes) -> tuple[dict[str, Any], str]:
    """Validate the frozen snapshot envelope and return its canonical form."""

    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LegacySnapshotError("snapshot bytes must be UTF-8") from exc
    if isinstance(value, str):
        try:
            envelope = json.loads(value, object_pairs_hook=_pairs,
                                  parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
        except (ValueError, TypeError) as exc:
            raise LegacySnapshotError(f"snapshot is not valid canonical JSON: {exc}") from exc
    else:
        envelope = value
    if not isinstance(envelope, Mapping):
        raise LegacySnapshotError("snapshot envelope must be an object")
    envelope = dict(envelope)
    if set(envelope) != {"format", "version", "source", "project", "tables", "history", "snapshot_digest"}:
        raise LegacySnapshotError("snapshot envelope has unsupported or missing fields")
    if envelope["format"] != LEGACY_SNAPSHOT_FORMAT or envelope["version"] != LEGACY_SNAPSHOT_VERSION:
        raise LegacySnapshotError("snapshot format or version is unsupported")
    source = envelope["source"]
    if not isinstance(source, Mapping) or set(source) != {
        "system", "project_id", "schema_version", "authority_revision", "exported_at",
    }:
        raise LegacySnapshotError("snapshot source metadata has an unsupported shape")
    if source["system"] != LEGACY_SOURCE_SYSTEM or source["schema_version"] != LEGACY_PROJECT_SCHEMA_VERSION:
        raise LegacySnapshotError("snapshot source system or project schema version is unsupported")
    if not isinstance(source["project_id"], str) or not source["project_id"]:
        raise LegacySnapshotError("snapshot source project_id must be text")
    try:
        StableId(source["project_id"])
    except ValueError as exc:
        raise LegacySnapshotError("snapshot source project_id is invalid") from exc
    if type(source["authority_revision"]) is not int or source["authority_revision"] < 0:
        raise LegacySnapshotError("snapshot source authority_revision must be non-negative")
    if not isinstance(source["exported_at"], str) or not source["exported_at"].endswith("Z"):
        raise LegacySnapshotError("snapshot exported_at must be a UTC timestamp ending in Z")
    project = envelope["project"]
    if not isinstance(project, Mapping) or not {"name"} <= set(project) or set(project) - {"name", "repository_id"}:
        raise LegacySnapshotError("snapshot project metadata has an unsupported shape")
    if not isinstance(project["name"], str) or not project["name"].strip():
        raise LegacySnapshotError("snapshot project name must be non-empty text")
    if "repository_id" in project and not isinstance(project["repository_id"], str):
        raise LegacySnapshotError("snapshot repository_id must be text when supplied")
    _contains_secret(source, "$/source")
    _contains_secret(project, "$/project")
    tables = envelope["tables"]
    if not isinstance(tables, Mapping) or set(tables) - LEGACY_TABLES:
        raise LegacySnapshotError("snapshot tables contain an unsupported table name")
    missing = _REQUIRED_TABLES - set(tables)
    if missing:
        raise LegacySnapshotError("snapshot is missing required table data: " + ", ".join(sorted(missing)))
    normalized_tables: dict[str, list[dict[str, Any]]] = {}
    for name in sorted(tables):
        rows = tables[name]
        if not isinstance(rows, (tuple, list)):
            raise LegacySnapshotError(f"snapshot table {name} must be an array")
        normalized_rows = []
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping) or any(not isinstance(key, str) for key in row):
                raise LegacySnapshotError(f"snapshot table {name} row {index} must be an object")
            normalized = dict(row)
            _json_value(normalized, f"$/tables/{name}/{index}")
            json_string_columns = frozenset(
                column for column, cell in normalized.items()
                if column.endswith("_json") and isinstance(cell, str)
            )
            _contains_secret(
                normalized, f"$/tables/{name}/{index}", skip_string_keys=json_string_columns,
            )
            for column, cell in normalized.items():
                if not (column.endswith("_json") and isinstance(cell, str)):
                    continue
                try:
                    embedded = json.loads(
                        cell, object_pairs_hook=_pairs,
                        parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
                    )
                except (ValueError, TypeError):
                    # Opaque malformed source columns are retained byte for
                    # byte; parsers of fields that affect native conversion
                    # reject them at their specific contract boundary.
                    _contains_secret(cell, f"$/tables/{name}/{index}/{column}")
                    continue
                _contains_secret(embedded, f"$/tables/{name}/{index}/{column}")
            normalized_rows.append(normalized)
        normalized_tables[name] = normalized_rows
    if not isinstance(envelope["history"], (tuple, list)):
        raise LegacySnapshotError("snapshot history must be an array")
    history = []
    for index, item in enumerate(envelope["history"]):
        if not isinstance(item, Mapping) or set(item) != {
            "source_table", "source_id", "entity_id", "revision", "occurred_at", "event_type", "payload",
        }:
            raise LegacySnapshotError(f"snapshot history item {index} has an unsupported shape")
        if item["source_table"] not in _HISTORY_TABLES:
            raise LegacySnapshotError(f"snapshot history item {index} has an unsupported source table")
        if not isinstance(item["source_id"], str) or not isinstance(item["event_type"], str):
            raise LegacySnapshotError(f"snapshot history item {index} has invalid text fields")
        if item["entity_id"] is not None and not isinstance(item["entity_id"], str):
            raise LegacySnapshotError(f"snapshot history item {index} has invalid entity_id")
        if type(item["revision"]) is not int or item["revision"] < 0:
            raise LegacySnapshotError(f"snapshot history item {index} has invalid revision")
        if not isinstance(item["occurred_at"], str) or not isinstance(item["payload"], Mapping):
            raise LegacySnapshotError(f"snapshot history item {index} has invalid timestamp or payload")
        _contains_secret(item, f"$/history/{index}")
        history.append(dict(item))
    digest = envelope["snapshot_digest"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise LegacySnapshotError("snapshot_digest must be lowercase SHA-256 hex")
    body = dict(envelope)
    body.pop("snapshot_digest")
    actual = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    if actual != digest:
        raise LegacySnapshotError("snapshot_digest does not match canonical snapshot contents")
    normalized_envelope = {
        "format": envelope["format"], "version": envelope["version"],
        "source": dict(source), "project": dict(project), "tables": normalized_tables,
        "history": history, "snapshot_digest": digest,
    }
    # Every untrusted row, embedded JSON value, history item and metadata
    # object was checked above. Rewalking the normalized envelope here would
    # scan large serialized *_json cells a second time without checking new
    # information.
    return normalized_envelope, _canonical(normalized_envelope)


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:40]
    return f"{prefix}-{digest}"


def _native_task_id(
    source_project_id: str, task_id: str, *, force_hash: bool = False, collision_index: int = 0,
) -> str:
    if not force_hash:
        try:
            return str(StableId(task_id))
        except (TypeError, ValueError):
            pass
    suffix = "" if collision_index == 0 else f"\0{collision_index}"
    digest = hashlib.sha256(f"{source_project_id}\0{task_id}{suffix}".encode("utf-8")).hexdigest()[:40]
    return "legacy-task-" + digest


def _allocate_native_task_ids(
    source_project_id: str, task_ids: set[str], reserved_work_item_ids: set[str] | frozenset[str],
) -> dict[str, str]:
    native_ids: dict[str, str] = {}
    occupied = set(reserved_work_item_ids)
    candidates: dict[str, list[str]] = defaultdict(list)
    for task_id in sorted(task_ids):
        try:
            candidate = str(StableId(task_id))
        except (TypeError, ValueError):
            continue
        candidates[candidate].append(task_id)

    # Preserve every collision-free valid source ID before allocating fallback
    # IDs. This prevents an invalid source ID's hash from displacing a valid
    # source identity merely because it sorts first.
    fallback: list[str] = []
    for task_id in sorted(task_ids):
        try:
            candidate = str(StableId(task_id))
        except (TypeError, ValueError):
            fallback.append(task_id)
            continue
        if candidate in occupied or len(candidates[candidate]) > 1:
            fallback.append(task_id)
        else:
            native_ids[task_id] = candidate
            occupied.add(candidate)

    for task_id in fallback:
        collision_index = 0
        candidate = _native_task_id(
            source_project_id, task_id, force_hash=True, collision_index=collision_index,
        )
        while candidate in occupied:
            collision_index += 1
            candidate = _native_task_id(
                source_project_id, task_id, force_hash=True, collision_index=collision_index,
            )
        native_ids[task_id] = candidate
        occupied.add(candidate)
    return native_ids


def _text(value: Any, fallback: str) -> str:
    if not isinstance(value, str) or not value.strip():
        value = fallback
    value = " ".join(str(value).split())
    if not value:
        value = fallback
    return value


def _json_cell(value: Any, *, default: Any, where: str) -> Any:
    if value is None:
        return default
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str):
        return default
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        raise LegacySnapshotError(f"legacy JSON field {where} is malformed")
    return parsed


def _safe_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")) or "\\" in value:
        return False
    pieces = value.split("/")
    return not any(piece in {"", ".", ".."} or ":" in piece for piece in pieces)


def _glob_literal_prefix(value: str) -> str | None:
    """Return the concrete directory prefix preceding the first glob segment."""

    wildcard_positions = [position for position in (value.find(char) for char in "*?[") if position >= 0]
    if not wildcard_positions:
        return None
    prefix = value[: min(wildcard_positions)]
    if "/" not in prefix:
        return None
    return prefix.rsplit("/", 1)[0] or None


def _scope_paths_overlap(left: str, right: str) -> bool:
    return (left == right or left.startswith(right + "/") or right.startswith(left + "/"))


def _record_map(rows: list[dict[str, Any]], key: str, table: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        value = row.get(key)
        if not isinstance(value, str) or not value:
            raise LegacySnapshotError(f"legacy {table} row has no {key}")
        if value in result:
            raise LegacySnapshotError(f"legacy {table} repeats {key} {value!r}")
        result[value] = row
    return result


def _rows_by_key(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        value = row.get(key)
        if isinstance(value, str):
            result[value].append(row)
    return result


def _attention_id(source_project_id: str, task_id: str, source_kind: str, source_id: str) -> str:
    return _stable_id("legacy-recheck", source_project_id, task_id, source_kind, source_id)


def _add_attention(
    *, task_id: str, source_project_id: str, source_kind: str, source_id: str, message: str,
    tasks_by_legacy_id: Mapping[str, dict[str, Any]], native_ids: Mapping[str, str],
    attention: list[LegacyAttention], requirements: list[dict[str, Any]],
    requirement_groups: dict[str, list[str]], decisions: list[dict[str, Any]],
    blockers: dict[str, list[dict[str, Any]]],
) -> None:
    if task_id not in native_ids:
        return
    decision_id = _attention_id(source_project_id, task_id, source_kind, source_id)
    if any(item.decision_id == StableId(decision_id) for item in attention):
        return
    # Keep an attention/revalidation blocker distinct from any partially
    # representable source contract check for the same entity.
    check_id = _stable_id("legacy-attention", source_project_id, task_id, source_kind, source_id)
    detail = _text(message, f"Legacy {source_kind} requires native revalidation")
    attention.append(LegacyAttention(task_id, source_kind, source_id, detail, StableId(decision_id)))
    requirements.append({
        "id": check_id, "work_item_id": native_ids[task_id], "kind": "check",
        "description": detail, "check_key": check_id,
    })
    requirement_groups[task_id].append(check_id)
    decisions.append({
        "id": decision_id,
        "title": _text(f"Revalidate legacy {source_kind} {source_id}", f"Revalidate legacy {source_kind}"),
        "question": detail,
        "options": [{"id": "revalidated", "description": "The current native contract has been reviewed and revalidated."}],
        "selected_option_id": None,
        "unknowns": ["The legacy state is archived evidence, not a native verification or resolution."],
        "resolvers": [],
    })
    blockers[task_id].append({
        "relation": "decision_resolved",
        "target": {"project_id": "", "kind": "decision", "entity_id": decision_id},
        "condition": {"op": "decision_equals", "decision_id": decision_id, "option_id": "revalidated"},
    })


def build_legacy_import_preview(
    snapshot: Mapping[str, Any] | str | bytes,
    project: Project,
    authority_revision: int,
    accepted_plan_revision_id: StableId | None,
    *,
    reserved_work_item_ids: frozenset[str] | set[str] = frozenset(),
) -> LegacyImportPreview:
    """Create a native plan for every current task and link source completion.

    Legacy done status is retained as an immutable completion assertion tied to
    the imported definition. It is never emitted as native outcome or evidence.
    Unsupported terminal source statuses remain visible through archive links.
    """

    if not isinstance(project, Project):
        raise TypeError("project must be Project")
    if type(authority_revision) is not int or authority_revision < 0:
        raise ValueError("authority_revision must be non-negative")
    if accepted_plan_revision_id is not None and not isinstance(accepted_plan_revision_id, StableId):
        raise TypeError("accepted_plan_revision_id must be StableId or None")
    if not isinstance(reserved_work_item_ids, (frozenset, set)) or any(
        not isinstance(item, str) for item in reserved_work_item_ids
    ):
        raise TypeError("reserved_work_item_ids must be a set of strings")
    envelope, _ = parse_legacy_snapshot(snapshot)
    source_project_id = envelope["source"]["project_id"]
    tables = envelope["tables"]
    tasks = _record_map(tables["tasks"], "id", "tasks")
    dependencies = tables["task_dependencies"]

    parents: dict[str, str] = {}
    for task_id, task in tasks.items():
        parent = task.get("parent_id")
        if isinstance(parent, str) and parent in tasks:
            parents[task_id] = parent
    selected = {task_id for task_id, task in tasks.items()
                if str(task.get("status")) not in _ARCHIVE_ONLY_TASK_STATUSES}
    missing_task_dependencies: dict[str, list[dict[str, Any]]] = defaultdict(list)
    adjacency: dict[str, list[str]] = defaultdict(list)
    for dependency in dependencies:
        source_id = dependency.get("task_id")
        target_id = dependency.get("prerequisite_task_id")
        if dependency.get("type") != "task" or not isinstance(source_id, str):
            continue
        if source_id not in tasks:
            continue
        if tasks[source_id].get("status") == "done":
            continue
        if not isinstance(target_id, str) or target_id not in tasks:
            missing_task_dependencies[source_id].append(dependency)
            continue
        if tasks[target_id].get("status") in _ARCHIVE_ONLY_TASK_STATUSES:
            missing_task_dependencies[source_id].append(dependency)
            continue
        adjacency[source_id].append(target_id)

    checkpoint_owners = {
        row.get("id"): row.get("task_id")
        for row in tables.get("checkpoints", [])
        if isinstance(row.get("id"), str) and isinstance(row.get("task_id"), str)
    }
    gates_by_id = _record_map(tables.get("gates", []), "id", "gates")
    gates_by_task: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    def associate_gate(gate_id: Any, task_id: Any) -> None:
        if isinstance(gate_id, str) and isinstance(task_id, str) and task_id in tasks and gate_id in gates_by_id:
            gates_by_task[task_id][gate_id] = gates_by_id[gate_id]

    for gate in gates_by_id.values():
        owner = gate.get("task_id")
        if owner is None:
            owner = checkpoint_owners.get(gate.get("checkpoint_id"))
        associate_gate(gate.get("id"), owner)
    for row in tables.get("checkpoint_gates", []):
        associate_gate(row.get("gate_id"), checkpoint_owners.get(row.get("checkpoint_id")))
    for row in tables.get("task_completion_gates", []):
        associate_gate(row.get("gate_id"), row.get("task_id"))

    # A required task_state gate for plain "done" is precisely a native
    # completion dependency. Include the target in the current-work closure.
    # More specific legacy status/result predicates are handled as attention.
    for owner_id, owner_gates in gates_by_task.items():
        if tasks[owner_id].get("status") == "done":
            continue
        for gate in owner_gates.values():
            if not gate.get("required", 1) or gate.get("type") != "task_state":
                continue
            gate_id = str(gate.get("id", "unknown"))
            config = _json_cell(gate.get("config_json"), default={}, where=f"gates/{gate_id}/config_json")
            target_id = config.get("task_id") if isinstance(config, Mapping) else None
            if (isinstance(target_id, str) and target_id in tasks and target_id != owner_id
                    and config.get("status", "done") == "done" and not config.get("result")):
                adjacency[owner_id].append(target_id)
    pending = deque(sorted(selected))
    while pending:
        task_id = pending.popleft()
        task = tasks[task_id]
        parent_id = parents.get(task_id)
        required = list(adjacency.get(task_id, ()))
        if parent_id is not None and str(tasks[parent_id].get("status")) not in _TERMINAL_TASK_STATUSES:
            required.append(parent_id)
        for prerequisite in required:
            if prerequisite not in selected:
                selected.add(prerequisite)
                pending.append(prerequisite)
    native_ids = _allocate_native_task_ids(source_project_id, selected, reserved_work_item_ids)
    requirement_groups: dict[str, list[str]] = defaultdict(list)
    requirements: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    attention: list[LegacyAttention] = []
    blockers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    dependency_members: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    for dependency in dependencies:
        source_id = dependency.get("task_id")
        if source_id not in selected:
            continue
        if tasks[source_id].get("status") == "done":
            continue
        dependency_id = str(dependency.get("id", "unknown"))
        dependency_type = dependency.get("type")
        if dependency_type == "task":
            target_id = dependency.get("prerequisite_task_id")
            if isinstance(target_id, str) and target_id in selected:
                key = "completion:" + target_id
                dependency_members[source_id][key] = {
                    "relation": "completion",
                    "target": {"project_id": str(project.project_id), "kind": "work_item",
                               "entity_id": native_ids[target_id]},
                }
                condition = _json_cell(
                    dependency.get("condition_json"), default={},
                    where=f"task_dependencies/{dependency_id}/condition_json",
                )
                if condition:
                    _add_attention(
                        task_id=source_id, source_project_id=source_project_id,
                        source_kind="dependency condition", source_id=dependency_id,
                        message="The legacy task dependency has additional condition data beyond completion; review the archived condition before dispatch.",
                        tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                        requirements=requirements, requirement_groups=requirement_groups,
                        decisions=decisions, blockers=blockers,
                    )
            else:
                _add_attention(
                    task_id=source_id, source_project_id=source_project_id,
                    source_kind="dependency", source_id=dependency_id,
                    message=f"Legacy task dependency {dependency_id} points to a missing or non-current task and needs native review.",
                    tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                    requirements=requirements, requirement_groups=requirement_groups,
                    decisions=decisions, blockers=blockers,
                )
        else:
            target = next((dependency.get(key) for key in (
                "checkpoint_id", "interface_id", "barrier_id", "decision_id",
            ) if isinstance(dependency.get(key), str)), None)
            _add_attention(
                task_id=source_id, source_project_id=source_project_id,
                source_kind=f"{dependency_type or 'unknown'} dependency", source_id=dependency_id,
                message=(f"Legacy {dependency_type or 'unknown'} dependency {target or dependency_id} "
                         "is retained in the archive and needs an explicit native revalidation."),
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )

    if tables.get("gates"):
        for task_id, row_map in gates_by_task.items():
            if task_id not in selected or tasks[task_id].get("status") == "done":
                continue
            rows = [gate for gate in row_map.values() if gate.get("required", 1)]
            for gate in rows:
                gate_id = str(gate.get("id", "unknown"))
                gate_type = str(gate.get("type", "unknown"))
                config = _json_cell(gate.get("config_json"), default={}, where=f"gates/{gate_id}/config_json")
                if not isinstance(config, Mapping):
                    config = {}
                contract = None
                evidence_kind = None
                unsupported: list[str] = []
                if gate_type == "file_exists" and isinstance(config.get("path"), str) and _safe_path(config["path"]):
                    contract = {"kind": "file", "version": 1,
                                "config": {"path": config["path"], "predicate": "exists"}}
                    evidence_kind = "file_observation"
                elif gate_type == "command":
                    argv = config.get("argv")
                    if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or not arg for arg in argv):
                        unsupported.append("command argv is missing or invalid")
                    else:
                        timeout = config.get("timeout_seconds", config.get("timeout", 300))
                        expected_code = config.get("expected_exit_code", 0)
                        cwd = config.get("cwd")
                        native_config: dict[str, Any] = {
                            "argv": argv,
                            "timeout_seconds": timeout,
                            "expected_exit_codes": [expected_code],
                        }
                        if cwd is not None:
                            native_config["cwd"] = cwd
                        contract = {"kind": "command", "version": 1, "config": native_config}
                        evidence_kind = "command_result"
                    for key in config:
                        if key not in {"argv", "cwd", "timeout", "timeout_seconds", "expected_exit_code",
                                       "input_paths", "locks"}:
                            unsupported.append(f"field {key} has no exact native command equivalent")
                    input_paths = config.get("input_paths", [])
                    if isinstance(input_paths, list):
                        for path in input_paths:
                            if not _safe_path(path):
                                unsupported.append("input_paths contains an unsafe path")
                    elif input_paths:
                        unsupported.append("input_paths is not an array")
                    if config.get("locks") and (not isinstance(config["locks"], list)
                                                  or any(not isinstance(lock, str) or not lock for lock in config["locks"])):
                        unsupported.append("locks has no valid native representation")
                elif gate_type == "task_state":
                    target_id = config.get("task_id")
                    if (isinstance(target_id, str) and target_id in selected and target_id != task_id
                            and config.get("status", "done") == "done" and not config.get("result")):
                        dependency_members[task_id]["completion:" + target_id] = {
                            "relation": "completion",
                            "target": {"project_id": str(project.project_id), "kind": "work_item",
                                       "entity_id": native_ids[target_id]},
                        }
                    else:
                        unsupported.append(
                            "task_state requires a legacy status/result predicate without an exact native equivalent"
                        )
                else:
                    unsupported.append(f"legacy gate type {gate_type} has no exact native contract")

                if contract is not None:
                    try:
                        VerificationContract.from_mapping(contract)
                    except (TypeError, ValueError) as exc:
                        unsupported.append(f"native verification contract is invalid ({exc})")
                    else:
                        req_id = _stable_id("legacy-check", source_project_id, task_id, "gate", gate_id)
                        req = {
                            "id": req_id, "work_item_id": native_ids[task_id], "kind": "check",
                            "description": f"Re-run legacy gate {gate_id} using this fresh native {contract['kind']} check.",
                            "check_key": req_id, "verification": contract,
                            "required_evidence": [{"name": req_id, "kind": evidence_kind, "version": 1}],
                        }
                        requirements.append(req)
                        requirement_groups[task_id].append(req_id)
                if unsupported:
                    _add_attention(
                        task_id=task_id, source_project_id=source_project_id, source_kind="gate",
                        source_id=gate_id,
                        message=(f"Legacy gate {gate_id} needs native attention: " + "; ".join(unsupported) + "."),
                        tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                        requirements=requirements, requirement_groups=requirement_groups,
                        decisions=decisions, blockers=blockers,
                    )

    for task_id, rows in _rows_by_key(tables.get("task_artifacts", []), "task_id").items():
        if task_id not in selected or tasks[task_id].get("status") == "done":
            continue
        for index, artifact in enumerate(rows):
            artifact_id = str(artifact.get("id", f"{task_id}:{index}"))
            kind, path, content_hash = artifact.get("kind"), artifact.get("path"), artifact.get("content_hash")
            if not isinstance(kind, str) or not kind.strip():
                _add_attention(
                    task_id=task_id, source_project_id=source_project_id, source_kind="artifact",
                    source_id=artifact_id, message="A legacy artifact declaration is incomplete and needs native review.",
                    tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                    requirements=requirements, requirement_groups=requirement_groups,
                    decisions=decisions, blockers=blockers,
                )
                continue
            if content_hash is None:
                config = {"artifact_kind": kind, "predicate": "exists"}
            elif isinstance(content_hash, str) and re.fullmatch(r"[0-9a-f]{64}", content_hash):
                config = {"artifact_kind": kind, "predicate": "sha256", "sha256": content_hash}
            else:
                _add_attention(
                    task_id=task_id, source_project_id=source_project_id, source_kind="artifact",
                    source_id=artifact_id, message="A legacy artifact has an invalid content hash and requires native review.",
                    tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                    requirements=requirements, requirement_groups=requirement_groups,
                    decisions=decisions, blockers=blockers,
                )
                continue
            req_id = _stable_id("legacy-artifact", source_project_id, task_id, artifact_id)
            requirements.append({
                "id": req_id, "work_item_id": native_ids[task_id], "kind": "check",
                "description": f"Produce current native evidence for legacy artifact {kind}"
                + (f" at {path}" if isinstance(path, str) else ""),
                "check_key": req_id,
                "verification": {"kind": "artifact", "version": 1, "config": config},
                "required_evidence": [{"name": req_id, "kind": "artifact_reference", "version": 1}],
            })
            requirement_groups[task_id].append(req_id)

    legacy_invariants = _record_map(tables.get("invariants", []), "id", "invariants")
    invariant_declarations: dict[str, dict[str, Any]] = {}
    for row in tables.get("task_invariants", []):
        task_id, old_invariant_id = row.get("task_id"), row.get("invariant_id")
        if task_id not in selected or tasks[task_id].get("status") == "done":
            continue
        old = legacy_invariants.get(old_invariant_id)
        if old is None or not isinstance(old.get("rule"), str) or not old["rule"].strip():
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="invariant",
                source_id=str(old_invariant_id or task_id),
                message="A legacy task invariant is missing its rule and needs native review.",
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
            continue
        native_invariant_id = _stable_id("legacy-invariant", source_project_id, str(old_invariant_id))
        statement = old["rule"].strip()
        severity = old.get("severity")
        enforcement = old.get("enforcement")
        if severity is not None or enforcement is not None:
            statement += f" [legacy severity={severity or 'unspecified'}; enforcement={enforcement or 'unspecified'}]"
        invariant_declarations.setdefault(native_invariant_id, {
            "id": native_invariant_id, "statement": statement, "applies_to": [],
        })["applies_to"].append({
            "project_id": str(project.project_id), "kind": "work_item", "entity_id": native_ids[task_id],
        })
        _add_attention(
            task_id=task_id, source_project_id=source_project_id, source_kind="invariant",
            source_id=str(old_invariant_id),
            message=f"Legacy invariant {old_invariant_id} is retained as a native declaration; revalidate its enforcement before dispatch.",
            tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
            requirements=requirements, requirement_groups=requirement_groups,
            decisions=decisions, blockers=blockers,
        )

    for task_id, rows in _rows_by_key(tables.get("resource_requests", []), "task_id").items():
        if task_id not in selected or tasks[task_id].get("status") == "done":
            continue
        for row in rows:
            if row.get("required", 1):
                request_id = str(row.get("id", "unknown"))
                _add_attention(
                    task_id=task_id, source_project_id=source_project_id, source_kind="resource request",
                    source_id=request_id,
                    message=(f"Legacy resource request {request_id} ({row.get('selector', 'unknown selector')}) "
                             "has no equivalent native admission contract and needs a deliberate resource plan."),
                    tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                    requirements=requirements, requirement_groups=requirement_groups,
                    decisions=decisions, blockers=blockers,
                )

    work_items = []
    scopes_by_task: dict[str, dict[str, Any]] = defaultdict(lambda: {"paths": {}, "locks": {}})
    translated_globs: dict[str, dict[str, str]] = defaultdict(dict)
    for row in tables.get("ownership_scopes", []):
        task_id, path, mode = row.get("task_id"), row.get("path"), row.get("mode")
        if task_id not in selected:
            continue
        if isinstance(path, str) and any(char in path for char in "*?["):
            if tasks[task_id].get("status") == "done":
                # Current imported completion is an assertion for this exact
                # definition. Its old path pattern is preserved in the
                # immutable source archive and will not grant dispatch rights.
                continue
            prefix = _glob_literal_prefix(path)
            if mode == "forbidden" and prefix is not None and _safe_path(prefix):
                overlaps = any(
                    _scope_paths_overlap(prefix, existing_path)
                    for existing_path in scopes_by_task[task_id]["paths"]
                )
                if not overlaps:
                    scopes_by_task[task_id]["paths"][prefix] = {"path": prefix, "access": "forbidden"}
                    translated_globs[task_id][prefix] = path
                    continue
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="ownership scope",
                source_id=f"{task_id}:{path}",
                message=(f"Legacy ownership glob {path!r} cannot be represented exactly without expanding "
                         "worker path rights; the archived pattern requires native scope review."),
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
            continue
        if _safe_path(path) and mode in {"read", "exclusive", "forbidden"}:
            access = {"read": "read", "exclusive": "write", "forbidden": "forbidden"}[mode]
            for prefix, original_glob in tuple(translated_globs[task_id].items()):
                if _scope_paths_overlap(prefix, path):
                    scopes_by_task[task_id]["paths"].pop(prefix, None)
                    del translated_globs[task_id][prefix]
                    _add_attention(
                        task_id=task_id, source_project_id=source_project_id, source_kind="ownership scope",
                        source_id=f"{task_id}:{original_glob}",
                        message=(f"Legacy ownership glob {original_glob!r} overlaps another native path scope; "
                                 "the archived pattern requires native scope review."),
                        tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                        requirements=requirements, requirement_groups=requirement_groups,
                        decisions=decisions, blockers=blockers,
                    )
            if path in scopes_by_task[task_id]["paths"]:
                previous = scopes_by_task[task_id]["paths"][path]
                if previous["access"] != access:
                    _add_attention(
                        task_id=task_id, source_project_id=source_project_id, source_kind="ownership scope",
                        source_id=f"{task_id}:{path}",
                        message="Conflicting legacy path access declarations require native scope review.",
                        tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                        requirements=requirements, requirement_groups=requirement_groups,
                        decisions=decisions, blockers=blockers,
                    )
                continue
            scopes_by_task[task_id]["paths"][path] = {"path": path, "access": access}
        else:
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="ownership scope",
                source_id=f"{task_id}:{path}", message="An unsafe or unsupported legacy ownership scope requires native review.",
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
    for row in tables.get("task_locks", []):
        task_id = row.get("task_id")
        if task_id not in selected:
            continue
        name = row.get("name", row.get("lock_name"))
        mode = row.get("mode", "exclusive")
        if isinstance(name, str) and name.strip():
            scopes_by_task[task_id]["locks"][name] = {"name": name, "mode": "shared" if mode == "shared" else "exclusive"}
        else:
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="task lock",
                source_id=str(row), message="A legacy lock declaration is incomplete and requires native review.",
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )

    for task_id in sorted(selected):
        task = tasks[task_id]
        status = str(task.get("status", "unknown"))
        title = _text(task.get("title"), f"Legacy task {task_id}")
        objective = _text(task.get("objective"), title)
        outcome = _text(task.get("result"), f"Complete the intended outcome for {title}.")
        policy = _json_cell(task.get("result_policy_json"), default={}, where=f"tasks/{task_id}/result_policy_json")
        legacy_dispositions = policy.get("allowed_dispositions", []) if isinstance(policy, Mapping) else []
        if not isinstance(legacy_dispositions, list):
            legacy_dispositions = []
        known = [item for item in legacy_dispositions if isinstance(item, str) and item in _ALLOWED_NATIVE_DISPOSITIONS]
        unsupported_dispositions = [item for item in legacy_dispositions
                                     if isinstance(item, str) and item not in _ALLOWED_NATIVE_DISPOSITIONS]
        scope = scopes_by_task[task_id]
        work = {
            "id": native_ids[task_id],
            "title": title,
            "objective": objective,
            "outcome": outcome,
            "motivation": f"Imported from Project Control Todo task {task_id} in legacy status {status}.",
            "scope": {
                "paths": sorted(scope["paths"].values(), key=lambda item: item["path"]),
                "concepts": ["legacy-todo-import"] + (
                    ["legacy-forbidden-glob-prefix-translation"] if translated_globs[task_id] else []
                ),
                "locks": sorted(scope["locks"].values(), key=lambda item: item["name"]),
            },
            "acceptance": {
                "assertions": ["Record a fresh native result and evidence for this work."]
                + (["Legacy allowed result terms requiring review: " + ", ".join(unsupported_dispositions)]
                   if unsupported_dispositions else []),
                "required_evidence": [],
                "allowed_dispositions": known or ["completed"],
            },
            "ownership": {"mode": "any", "actors": []},
            "references": [],
            "alternatives": [],
            "unknowns": [],
            "delegated_judgment": [],
            "parent_id": native_ids.get(parents.get(task_id, "")),
        }
        work_items.append(work)
        if unsupported_dispositions and status != "done":
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="result policy",
                source_id=task_id,
                message=("Legacy allowed completion terms have no exact native result disposition: "
                         + ", ".join(unsupported_dispositions) + ". Review the archived result policy."),
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
        if status == "attention_required":
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="task status",
                source_id=task_id,
                message=_text(task.get("attention_reason"), "Legacy task requires attention before it can be dispatched."),
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
        elif status not in _TERMINAL_TASK_STATUSES | {"planned", "in_progress", "blocked", "review"}:
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="task status",
                source_id=task_id,
                message=f"Legacy task status {status!r} has no safe native equivalent and requires review.",
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
        if status == "blocked" and not adjacency.get(task_id):
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="blocked task",
                source_id=task_id,
                message=_text(task.get("attention_reason"), "The legacy task was blocked without a typed task dependency; review its archived reason."),
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )
        for dep in missing_task_dependencies.get(task_id, ()):
            _add_attention(
                task_id=task_id, source_project_id=source_project_id, source_kind="dependency",
                source_id=str(dep.get("id", "unknown")),
                message="A legacy task dependency references unavailable state and needs native review.",
                tasks_by_legacy_id=tasks, native_ids=native_ids, attention=attention,
                requirements=requirements, requirement_groups=requirement_groups,
                decisions=decisions, blockers=blockers,
            )

    for task_id, req_ids in requirement_groups.items():
        if task_id in native_ids and req_ids:
            next(work for work in work_items if work["id"] == native_ids[task_id])["requirement_groups"] = [
                {"kind": "check", "mode": "all", "members": sorted(set(req_ids))}
            ]

    dependency_groups = []
    for task_id in sorted(set(dependency_members) | set(blockers)):
        members = list(dependency_members.get(task_id, {}).values())
        for member in blockers.get(task_id, []):
            member["target"]["project_id"] = str(project.project_id)
            members.append(member)
        dedup = {_canonical(member): member for member in members}
        if dedup:
            dependency_groups.append({
                "source": {"project_id": str(project.project_id), "kind": "work_item",
                           "entity_id": native_ids[task_id]},
                "mode": "all", "members": [dedup[key] for key in sorted(dedup)],
            })

    plan = {
        "format": PLAN_FORMAT,
        "schema_version": PLAN_SCHEMA_VERSION,
        "package_id": _stable_id("legacy-plan", source_project_id, envelope["snapshot_digest"]),
        "project": {"project_id": str(project.project_id), "authority_id": str(project.authority_id)},
        "provenance": {"source": "project-control.todo-v2", "producer": "todo-orchestrator.legacy-import-v1"},
        "work_items": work_items,
        "requirements": sorted(requirements, key=lambda item: item["id"]),
        "decisions": sorted(decisions, key=lambda item: item["id"]),
        "dependencies": dependency_groups,
        "invariants": sorted(invariant_declarations.values(), key=lambda item: item["id"]),
    }
    package_json = _canonical(plan)
    compiled = compile_plan_json(package_json, project)
    if not compiled.ok or compiled.plan is None:
        reasons = "; ".join(f"{item.code}: {item.message}" for item in compiled.diagnostics)
        raise LegacySnapshotError(f"converted native plan is invalid: {reasons}")
    completed = tuple(sorted(task_id for task_id in selected if tasks[task_id].get("status") == "done"))
    archive_only = tuple(sorted(set(tasks) - selected))
    return LegacyImportPreview(
        project.project_id, authority_revision, accepted_plan_revision_id,
        source_project_id, envelope["source"]["authority_revision"], envelope["snapshot_digest"],
        package_json, tuple(sorted(selected)), completed, archive_only,
        tuple(sorted(attention, key=lambda item: (item.task_id, item.source_kind, item.source_id))),
    )


__all__ = [
    "LEGACY_PROJECT_SCHEMA_VERSION", "LEGACY_SNAPSHOT_FORMAT", "LEGACY_SNAPSHOT_VERSION",
    "LEGACY_SOURCE_SYSTEM", "LEGACY_TABLES", "LegacySnapshotError", "build_legacy_import_preview",
    "parse_legacy_snapshot", "_allocate_native_task_ids",
]
