<!-- todo-orchestrator:v2-managed:start -->
# TO-A05: Rework claim and lease transactions around attempts

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Attach exclusive ownership, filesystem scopes, named locks and lifecycle to attempts. Preserve dirty-work quarantine, process-unknown semantics and one-active-claim invariants; external resource reservations remain provider owned.

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
- `task`: `TO-A03`
- `task`: `TO-A04`
<!-- todo-orchestrator:v2-managed:end -->
