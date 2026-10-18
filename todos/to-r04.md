<!-- todo-orchestrator:v2-managed:start -->
# TO-R04: Add trustworthy export, projections and explicit restoration

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Expose stable versioned read models and derived human-readable views; snapshots are backups/interchange artifacts, not silent startup restoration. Require explicit identity and revision checks for restoration.

## State
- Lifecycle: `planned`
- Execution: `ready`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/operations`
- `exclusive`: `src/todo_orchestrator/views`
- `exclusive`: `tests/recovery`

## Dependencies
- `task`: `TO-A02`
- `task`: `TO-R02`
<!-- todo-orchestrator:v2-managed:end -->
