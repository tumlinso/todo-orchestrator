

<!-- todo-orchestrator:v2-managed:start -->
# TO-R01: Create unified inspection of interrupted and uncertain operations

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Determine authoritative reconciliation from attempt, lease, workspace, evidence and external-effect records. Distinguish expired, unknown-live, dirty, irrecoverable and safely retryable states.

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
- `task`: `TO-C02`
- `task`: `TO-V02`
- `task`: `TO-V04`
<!-- todo-orchestrator:v2-managed:end -->
