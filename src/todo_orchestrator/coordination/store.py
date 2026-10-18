"""Canonical serialization and strict reads for persisted schedules."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from todo_orchestrator.contracts import Assignment, EntityKind, EntityRef, Project, Run, RunState, StableId
from todo_orchestrator.model import (
    IsolationPolicy,
    LaneSpec,
    QueueEntry,
    QueuePolicy,
    RunCharter,
    RunScheduleView,
)

from todo_orchestrator.authority.sqlite import InvalidAuthorityError


SCHEDULE_FORMAT = "todo-orchestrator.run-schedule"
SCHEDULE_SCHEMA_VERSION = 1


def _ref_payload(ref: EntityRef | None) -> dict[str, str | None] | None:
    if ref is None:
        return None
    return {
        "project_id": str(ref.project_id),
        "kind": ref.kind.value,
        "entity_id": str(ref.entity_id),
        "revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def canonical_schedule_json(view: RunScheduleView) -> str:
    """Return the normalized, versioned representation covered by the digest."""
    document = {
        "format": SCHEDULE_FORMAT,
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "project_id": str(view.run.project_id),
        "run_id": str(view.run.run_id),
        "plan_revision_id": str(view.run.plan_revision.entity_id),
        "charter": None if view.charter is None else {
            "objective": view.charter.objective,
            "boundaries": list(view.charter.boundaries),
            "acceptance_conditions": list(view.charter.acceptance_conditions),
        },
        "lanes": [
            {
                "lane_id": str(lane.lane_id),
                "queue_policy": lane.queue_policy.value,
                "required_role": None if lane.required_role is None else str(lane.required_role),
                "isolation_policy": lane.isolation_policy.value,
            }
            for lane in view.lanes
        ],
        "entries": [
            {
                "assignment_id": str(entry.assignment.assignment_id),
                "work_item": _ref_payload(entry.assignment.work_item),
                "assignee": _ref_payload(entry.assignment.assignee),
                "lane_id": str(entry.lane_id),
                "queue_position": entry.queue_position,
            }
            for entry in view.entries
        ],
    }
    return json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def schedule_digest(encoded: str) -> str:
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def load_run_schedule(
    connection: sqlite3.Connection, project: Project, run_id: StableId
) -> RunScheduleView | None:
    """Load a run schedule and verify normalized rows against its immutable digest."""
    schedule = connection.execute(
        "SELECT schedule_json, schedule_digest FROM run_schedules WHERE run_id = ?",
        (str(run_id),),
    ).fetchone()
    if schedule is None:
        return None
    run_row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (str(run_id),)).fetchone()
    if run_row is None:
        raise InvalidAuthorityError("stored run schedule has no corresponding run")
    try:
        run = Run(
            StableId(run_row["run_id"]), project.project_id,
            EntityRef(project.project_id, EntityKind.PLAN_REVISION, StableId(run_row["plan_revision_id"])),
            RunState(run_row["state"]),
            None if run_row["created_by_actor_id"] is None else EntityRef(
                project.project_id, EntityKind.ACTOR, StableId(run_row["created_by_actor_id"]),
                incarnation_id=StableId(run_row["created_by_incarnation_id"]),
            ),
        )
        lane_rows = connection.execute(
            "SELECT * FROM run_lanes WHERE run_id = ? ORDER BY lane_ordinal",
            (str(run_id),),
        ).fetchall()
        if [row["lane_ordinal"] for row in lane_rows] != list(range(len(lane_rows))):
            raise ValueError("lane ordinals are not contiguous from zero")
        lanes = tuple(LaneSpec(
            StableId(row["lane_id"]), QueuePolicy(row["queue_policy"]),
            None if row["required_role"] is None else StableId(row["required_role"]),
            IsolationPolicy(row["isolation_policy"]),
        ) for row in lane_rows)
        lane_by_id = {str(lane.lane_id): lane for lane in lanes}
        queue_rows = connection.execute(
            "SELECT q.lane_id, q.queue_position, l.lane_ordinal, a.assignment_id, a.work_item_id, "
            "a.definition_revision_id, a.assignee_actor_id, a.assignee_incarnation_id, a.run_id "
            "FROM run_queue AS q JOIN assignments AS a ON a.assignment_id = q.assignment_id "
            "JOIN run_lanes AS l ON l.run_id = q.run_id AND l.lane_id = q.lane_id "
            "WHERE q.run_id = ? ORDER BY l.lane_ordinal, q.queue_position",
            (str(run_id),),
        ).fetchall()
        entries = []
        expected_positions: dict[str, int] = {}
        for row in queue_rows:
            lane = lane_by_id.get(row["lane_id"])
            if lane is None:
                raise ValueError("queue entry refers to a missing lane")
            if row["run_id"] != str(run_id):
                raise ValueError("queue entry assignment belongs to a different run")
            expected = expected_positions.get(row["lane_id"], 0)
            if row["queue_position"] != expected:
                raise ValueError("queue positions are not contiguous from zero")
            expected_positions[row["lane_id"]] = expected + 1
            assignment = Assignment(
                StableId(row["assignment_id"]), project.project_id,
                EntityRef(project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                          definition_revision_id=StableId(row["definition_revision_id"])),
                None if row["assignee_actor_id"] is None else EntityRef(
                    project.project_id, EntityKind.ACTOR, StableId(row["assignee_actor_id"]),
                    incarnation_id=StableId(row["assignee_incarnation_id"]),
                ),
                run.ref,
            )
            entries.append(QueueEntry(
                assignment, lane.lane_id, row["queue_position"], lane.queue_policy,
                lane.required_role, lane.isolation_policy,
            ))
        if not lanes or not entries or {entry.lane_id for entry in entries} != {lane.lane_id for lane in lanes}:
            raise ValueError("a scheduled run must have at least one lane and one assignment")
        stored_document = json.loads(schedule["schedule_json"])
        raw_charter = stored_document.get("charter")
        charter = None
        if raw_charter is not None:
            if not isinstance(raw_charter, dict) or set(raw_charter) != {
                "objective", "boundaries", "acceptance_conditions",
            }:
                raise ValueError("stored run charter fields are invalid")
            charter = RunCharter(
                raw_charter["objective"], tuple(raw_charter["boundaries"]),
                tuple(raw_charter["acceptance_conditions"]),
            )
        view = RunScheduleView(run, lanes, tuple(entries), charter)
        encoded = canonical_schedule_json(view)
        if encoded != schedule["schedule_json"] or schedule_digest(encoded) != schedule["schedule_digest"]:
            raise ValueError("stored schedule rows do not match their canonical digest")
        document = json.loads(encoded)
        if document["plan_revision_id"] != str(run.plan_revision.entity_id):
            raise ValueError("stored schedule plan identity does not match its run")
        return view
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidAuthorityError(f"stored run schedule is invalid: {exc}") from exc


def load_all_queue_entries(connection: sqlite3.Connection, project: Project) -> dict[EntityRef, QueueEntry]:
    """Load and verify all durable assignment policy facts for eligibility."""
    result: dict[EntityRef, QueueEntry] = {}
    rows = connection.execute("SELECT run_id FROM run_schedules ORDER BY run_id").fetchall()
    for row in rows:
        view = load_run_schedule(connection, project, StableId(row["run_id"]))
        if view is None:  # Defensive: the row was selected from the same snapshot.
            raise InvalidAuthorityError("run schedule disappeared while reading one SQLite snapshot")
        for entry in view.entries:
            if entry.assignment.ref in result:
                raise InvalidAuthorityError("assignment appears in more than one run schedule")
            result[entry.assignment.ref] = entry
    return result


__all__ = [
    "SCHEDULE_FORMAT", "SCHEDULE_SCHEMA_VERSION", "canonical_schedule_json",
    "load_all_queue_entries", "load_run_schedule", "schedule_digest",
]
