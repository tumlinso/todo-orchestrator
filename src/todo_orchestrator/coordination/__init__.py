"""Typed coordination APIs for durable schedules, messages, and task context."""

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
    "AnswerConflictError", "CursorError", "InboxPage", "InboxStatus", "MESSAGE_READ_ACTION",
    "MESSAGE_SEND_ACTION", "MESSAGE_TYPES", "MessageContentRef", "MessageNotFoundError",
    "MessageScopeError", "MessageType", "MessageView", "MessagingError", "MessagingService",
    "PayloadRejectedError",
    "QUESTION_ANSWER_ACTION",
    "CONTEXT_FINDING_INVALIDATE_ACTION", "CONTEXT_FINDING_PUBLISH_ACTION", "CONTEXT_READ_ACTION",
    "ContextError", "ContextFindingConflictError", "ContextScopeError", "ContextService",
    "ContextStaleError", "ContextUnavailableError", "DEFAULT_CONTEXT_MAX_BYTES",
    "MAX_CONTEXT_MAX_BYTES", "MIN_CONTEXT_MAX_BYTES", "serialize_context_capsule",
    "serialize_context_expansion",
]


def __getattr__(name: str):
    if name in {
        "ATTEMPT_FINISH_ACTION", "AmbiguousDispatchError", "CoordinationError",
        "CoordinationService", "DispatchSelectionError", "RUN_DISPATCH_ACTION", "RUN_SCHEDULE_ACTION",
        "RunScheduleConflictError", "RunScheduleNotFoundError",
    }:
        from . import service

        return getattr(service, name)
    if name in {
        "CONTEXT_FINDING_INVALIDATE_ACTION", "CONTEXT_FINDING_PUBLISH_ACTION", "CONTEXT_READ_ACTION",
        "ContextError", "ContextFindingConflictError", "ContextScopeError", "ContextService",
        "ContextStaleError", "ContextUnavailableError", "DEFAULT_CONTEXT_MAX_BYTES",
        "MAX_CONTEXT_MAX_BYTES", "MIN_CONTEXT_MAX_BYTES", "serialize_context_capsule",
        "serialize_context_expansion",
    }:
        from . import context

        return getattr(context, name)
    if name in {
        "AnswerConflictError", "CursorError", "InboxPage", "InboxStatus", "MESSAGE_READ_ACTION",
        "MESSAGE_SEND_ACTION", "MESSAGE_TYPES", "MessageContentRef", "MessageNotFoundError",
        "MessageScopeError", "MessageType", "MessageView", "MessagingError", "MessagingService",
        "PayloadRejectedError",
        "QUESTION_ANSWER_ACTION",
    }:
        from . import messaging

        return getattr(messaging, name)
    raise AttributeError(name)
