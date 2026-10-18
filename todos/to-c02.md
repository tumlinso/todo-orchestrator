

<!-- todo-orchestrator:v2-managed:start -->
# TO-C02: Implement atomic dispatch, resumption and release

Task revision: `89`; current project revision is in `todo-status.md`.

## Objective
Join assignment selection, authoritative claim, bounded capability issuance and dispatch in a coherent transaction. Make resumption stable under connection/process restart and ambiguous task/run selection.

## State
- Lifecycle: `in_progress`
- Execution: `claimed`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/coordination`
- `exclusive`: `tests/coordination`

## Dependencies
- `task`: `TO-C01`
- `task`: `TO-A05`
<!-- todo-orchestrator:v2-managed:end -->
