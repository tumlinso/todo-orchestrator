"""Typed coordination APIs for durable run scheduling."""

from todo_orchestrator.model.coordination import (
    DispatchResult,
    IsolationPolicy,
    LaneSpec,
    QueueEntry,
    QueuePolicy,
    RunCharter,
    RunSchedule,
    RunScheduleView,
    ScheduledWork,
)

__all__ = [
    "ATTEMPT_FINISH_ACTION", "AmbiguousDispatchError", "CoordinationError",
    "CoordinationService", "DispatchResult", "DispatchSelectionError", "IsolationPolicy", "LaneSpec",
    "QueueEntry", "QueuePolicy", "RUN_SCHEDULE_ACTION", "RunCharter", "RunSchedule",
    "RUN_DISPATCH_ACTION",
    "RunScheduleConflictError", "RunScheduleNotFoundError", "RunScheduleView",
    "ScheduledWork",
]


def __getattr__(name: str):
    if name in {
        "ATTEMPT_FINISH_ACTION", "AmbiguousDispatchError", "CoordinationError",
        "CoordinationService", "DispatchSelectionError", "RUN_DISPATCH_ACTION", "RUN_SCHEDULE_ACTION",
        "RunScheduleConflictError", "RunScheduleNotFoundError",
    }:
        from . import service

        return getattr(service, name)
    raise AttributeError(name)
