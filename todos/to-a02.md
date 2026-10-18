<!-- todo-orchestrator:v2-managed:start -->
# TO-A02: Implement atomic transitions, revisions, idempotency and history

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Define typed command execution and revisioned state transitions in one transaction, with receipt identity, event history and derived read models; avoid a redundant event-sourced database architecture.

## State
- Lifecycle: `planned`
- Execution: `ready`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/authority`
- `exclusive`: `src/todo_orchestrator/model`
- `exclusive`: `tests/authority`

## Dependencies
- `task`: `TO-A01`
<!-- todo-orchestrator:v2-managed:end -->
