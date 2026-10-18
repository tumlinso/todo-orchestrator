

<!-- todo-orchestrator:v2-managed:start -->
# TO-P04: Commit plan revisions and replan safely

Task revision: `81`; current project revision is in `todo-status.md`.

## Objective
Commit typed change sets transactionally with optimistic authority preconditions, explicit actor authorization and stable idempotency. Treat mutation of active or completed work as a guarded lifecycle change.

## State
- Lifecycle: `done`
- Execution: `closed`
- Parallel policy: `serial`
- Result: `implemented`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/planning`
- `exclusive`: `tests/planning`

## Dependencies
- `task`: `TO-P03`
- `task`: `TO-A03`
<!-- todo-orchestrator:v2-managed:end -->
