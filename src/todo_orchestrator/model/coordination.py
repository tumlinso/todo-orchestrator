"""Typed scheduling policies and persisted run queue views."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from todo_orchestrator.contracts import Attempt, Assignment, Capability, EntityKind, EntityRef, Run, StableId
from .commands import CommandReceipt


class QueuePolicy(str, Enum):
    """Whether a lane admits its assignments in order or concurrently."""

    SERIAL = "serial"
    PARALLEL = "parallel"


class IsolationPolicy(str, Enum):
    """Additional lane-level admission requirements; never an auth grant."""

    SHARED_SCOPES = "shared_scopes"
    QUALIFIED_WORKSPACES = "qualified_workspaces"


@dataclass(frozen=True)
class LaneSpec:
    """Immutable lane policy. A role is a grant action ID, never an actor label."""

    lane_id: StableId
    queue_policy: QueuePolicy = QueuePolicy.SERIAL
    required_role: StableId | None = None
    isolation_policy: IsolationPolicy = IsolationPolicy.SHARED_SCOPES

    def __post_init__(self) -> None:
        if not isinstance(self.lane_id, StableId):
            raise TypeError("lane_id must be a StableId")
        if not isinstance(self.queue_policy, QueuePolicy):
            raise TypeError("queue_policy must be a QueuePolicy")
        if self.required_role is not None and not isinstance(self.required_role, StableId):
            raise TypeError("required_role must be a StableId action or None")
        if not isinstance(self.isolation_policy, IsolationPolicy):
            raise TypeError("isolation_policy must be an IsolationPolicy")


@dataclass(frozen=True)
class ScheduledWork:
    """One exact accepted work definition and its optional scheduling context."""

    work_item: EntityRef
    lane_id: StableId | None = None
    assignee: EntityRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.work_item, EntityRef) or self.work_item.kind is not EntityKind.WORK_ITEM:
            raise ValueError("work_item must reference an exact work-item definition")
        if self.lane_id is not None and not isinstance(self.lane_id, StableId):
            raise TypeError("lane_id must be a StableId or None")
        if self.assignee is not None and (
            not isinstance(self.assignee, EntityRef) or self.assignee.kind is not EntityKind.ACTOR
            or self.assignee.project_id != self.work_item.project_id
        ):
            raise ValueError("assignee must be a same-project actor incarnation reference")


@dataclass(frozen=True)
class RunCharter:
    """Bounded intent and boundaries for schedules that coordinate workers."""

    objective: str
    boundaries: tuple[str, ...]
    acceptance_conditions: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, name in ((self.objective, "objective"),):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{name} must be non-empty trimmed text")
        if len(self.objective) > 2000:
            raise ValueError("objective must be at most 2000 characters")
        for values, name in (
            (self.boundaries, "boundaries"),
            (self.acceptance_conditions, "acceptance_conditions"),
        ):
            if not isinstance(values, tuple) or not values:
                raise ValueError(f"{name} must be a non-empty tuple of text values")
            if any(
                not isinstance(value, str) or not value.strip() or value != value.strip()
                or len(value) > 1000
                for value in values
            ):
                raise ValueError(f"{name} values must be non-empty trimmed text of at most 1000 characters")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} values must be unique")


@dataclass(frozen=True)
class RunSchedule:
    """Requested immutable schedule for an accepted plan revision."""

    run_id: StableId
    plan_revision: EntityRef
    lanes: tuple[LaneSpec, ...] = ()
    work: tuple[ScheduledWork, ...] = ()
    charter: RunCharter | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, StableId):
            raise TypeError("run_id must be a StableId")
        if not isinstance(self.plan_revision, EntityRef) or self.plan_revision.kind is not EntityKind.PLAN_REVISION:
            raise ValueError("plan_revision must reference a plan revision")
        if not isinstance(self.lanes, tuple) or any(not isinstance(item, LaneSpec) for item in self.lanes):
            raise TypeError("lanes must be a tuple of LaneSpec values")
        if len({item.lane_id for item in self.lanes}) != len(self.lanes):
            raise ValueError("lane IDs must be unique")
        if not isinstance(self.work, tuple) or any(not isinstance(item, ScheduledWork) for item in self.work):
            raise TypeError("work must be a tuple of ScheduledWork values")
        if len({item.work_item for item in self.work}) != len(self.work):
            raise ValueError("scheduled work references must be unique")
        if len({item.work_item.entity_id for item in self.work}) != len(self.work):
            raise ValueError("a schedule cannot include multiple definitions of one work item")
        if any(item.work_item.project_id != self.plan_revision.project_id for item in self.work):
            raise ValueError("scheduled work must belong to the plan project")
        if self.charter is not None and not isinstance(self.charter, RunCharter):
            raise TypeError("charter must be a RunCharter or None")


@dataclass(frozen=True)
class QueueEntry:
    """Stored queue position and policy for one immutable Assignment."""

    assignment: Assignment
    lane_id: StableId
    queue_position: int
    queue_policy: QueuePolicy
    required_role: StableId | None
    isolation_policy: IsolationPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.assignment, Assignment) or self.assignment.run is None:
            raise ValueError("queue entry assignment must belong to a run")
        if not isinstance(self.lane_id, StableId):
            raise TypeError("lane_id must be a StableId")
        if type(self.queue_position) is not int or self.queue_position < 0:
            raise ValueError("queue_position must be a non-negative integer")
        if not isinstance(self.queue_policy, QueuePolicy):
            raise TypeError("queue_policy must be a QueuePolicy")
        if self.required_role is not None and not isinstance(self.required_role, StableId):
            raise TypeError("required_role must be a StableId or None")
        if not isinstance(self.isolation_policy, IsolationPolicy):
            raise TypeError("isolation_policy must be an IsolationPolicy")


@dataclass(frozen=True)
class RunScheduleView:
    """Durable run, lane, and queue state reconstructed from authority rows."""

    run: Run
    lanes: tuple[LaneSpec, ...]
    entries: tuple[QueueEntry, ...]
    charter: RunCharter | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run, Run):
            raise TypeError("run must be a Run")
        if not isinstance(self.lanes, tuple) or any(not isinstance(item, LaneSpec) for item in self.lanes):
            raise TypeError("lanes must be a tuple of LaneSpec values")
        if not isinstance(self.entries, tuple) or any(not isinstance(item, QueueEntry) for item in self.entries):
            raise TypeError("entries must be a tuple of QueueEntry values")
        if self.charter is not None and not isinstance(self.charter, RunCharter):
            raise TypeError("charter must be a RunCharter or None")
        lane_ids = {lane.lane_id for lane in self.lanes}
        if len(lane_ids) != len(self.lanes):
            raise ValueError("run view lane IDs must be unique")
        if any(
            entry.assignment.run != self.run.ref
            or entry.assignment.project_id != self.run.project_id
            or entry.lane_id not in lane_ids
            for entry in self.entries
        ):
            raise ValueError("queue entries must belong to a lane and run in this view")
        if len({entry.assignment.ref for entry in self.entries}) != len(self.entries):
            raise ValueError("run view assignments must be unique")


@dataclass(frozen=True)
class DispatchResult:
    """One-time delivery of an attempt-scoped grant from an atomic dispatch."""

    attempt: Attempt
    capability: Capability
    bearer_token: str = field(repr=False)
    receipt: CommandReceipt = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.attempt, Attempt) or self.attempt.lease is None:
            raise ValueError("dispatched attempt must carry its current lease")
        if not isinstance(self.capability, Capability):
            raise TypeError("capability must be a Capability")
        if not isinstance(self.bearer_token, str) or not self.bearer_token:
            raise ValueError("bearer_token must be the one-time non-empty capability secret")
        if not isinstance(self.receipt, CommandReceipt):
            raise TypeError("receipt must be a CommandReceipt")
        if (
            self.capability.actor != self.attempt.actor
            or self.capability.scope != self.attempt.work_item
            or self.capability.run != self.attempt.run
            or self.capability.assignment != self.attempt.assignment
            or self.capability.attempt != self.attempt.ref
            or self.capability.expires_at is None
            or self.capability.expires_at > self.attempt.lease.expires_at
        ):
            raise ValueError("dispatch capability must be fenced to the exact attempt and lease lifetime")


__all__ = [
    "DispatchResult", "IsolationPolicy", "LaneSpec", "QueueEntry", "QueuePolicy", "RunSchedule",
    "RunScheduleView", "RunCharter", "ScheduledWork",
]
