

<!-- todo-orchestrator:v2-managed:start -->
# TO-A03: Unify eligibility, authorization and conflict evaluation

Task revision: `55`; current project revision is in `todo-status.md`.

## Objective
Provide one deterministic decision engine for structural prerequisites, role/capability rights, source scopes, leases and safe parallelism. Use the same rule set for advisory reads and atomic admission, distinguishing observed eligibility from reservation.

## State
- Lifecycle: `done`
- Execution: `closed`
- Parallel policy: `serial`
- Result: `implemented`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/authority`
- `exclusive`: `src/todo_orchestrator/model`
- `exclusive`: `tests/authority`

## Dependencies
- `task`: `TO-A02`
- `task`: `TO-P02`
<!-- todo-orchestrator:v2-managed:end -->
