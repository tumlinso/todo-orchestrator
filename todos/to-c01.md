

<!-- todo-orchestrator:v2-managed:start -->
# TO-C01: Define runs, assignments and optional worker lanes

Task revision: `60`; current project revision is in `todo-status.md`.

## Objective
Schedule accepted work through Runs and Assignments, with deterministic queues, role constraints and optional lane structure for parallel work. No dependency on an agent/model scheduler.

## State
- Lifecycle: `in_progress`
- Execution: `idle`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/coordination`
- `exclusive`: `tests/coordination`

## Dependencies
- `task`: `TO-A02`
- `task`: `TO-P02`
<!-- todo-orchestrator:v2-managed:end -->
