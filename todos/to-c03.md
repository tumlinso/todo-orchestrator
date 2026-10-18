

<!-- todo-orchestrator:v2-managed:start -->
# TO-C03: Provide typed durable communication and decision synchronization

Task revision: `131`; current project revision is in `todo-status.md`.

## Objective
Keep bounded messages, questions/answers, decisions, interface changes, rendezvous and blockers, with explicit recipient and authority scopes; do not turn the ledger into a transcript store.

## State
- Lifecycle: `done`
- Execution: `closed`
- Parallel policy: `serial`
- Result: `implemented`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/coordination`
- `exclusive`: `tests/coordination`

## Dependencies
- `task`: `TO-C01`
- `task`: `TO-A02`
<!-- todo-orchestrator:v2-managed:end -->
