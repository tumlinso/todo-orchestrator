<!-- todo-orchestrator:v2-managed:start -->
# TO-R03: Supersede, retire and replace work without history loss

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Make plan supersession and quiescent run retirement explicit, with successor lineage, preserving accepted work and user-authorized handoffs. Avoid special-purpose SQL rewriting as the only route.

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
- `task`: `TO-R02`
- `task`: `TO-P04`
<!-- todo-orchestrator:v2-managed:end -->
