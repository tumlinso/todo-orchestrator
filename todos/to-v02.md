

<!-- todo-orchestrator:v2-managed:start -->
# TO-V02: Track verification attempts and external execution receipts

Task revision: `110`; current project revision is in `todo-status.md`.

## Objective
Use durable gate-attempt identities and prepared/executing/observed/finalized lifecycle. Call trusted provider interfaces for actual commands/resources; correlate completion with source identity, operation identity and receipts.

## State
- Lifecycle: `done`
- Execution: `closed`
- Parallel policy: `serial`
- Result: `implemented`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/providers/git`
- `exclusive`: `src/todo_orchestrator/verification`
- `exclusive`: `tests/verification`

## Dependencies
- `task`: `TO-V01`
- `task`: `TO-A02`
- `task`: `TO-F04`
<!-- todo-orchestrator:v2-managed:end -->
