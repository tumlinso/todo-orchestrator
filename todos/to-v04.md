

<!-- todo-orchestrator:v2-managed:start -->
# TO-V04: Isolate and qualify Git workspace/integration operations

Task revision: `117`; current project revision is in `todo-status.md`.

## Objective
Adapt existing conservative Git-worktree, artifact and integration behavior behind a trusted repository-effects provider. Preserve operation-intent, idempotent receipt and conflict-recovery semantics without coupling the domain engine to subprocess Git details.

## State
- Lifecycle: `in_progress`
- Execution: `claimed`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/providers/git`
- `exclusive`: `src/todo_orchestrator/verification`
- `exclusive`: `tests/verification`

## Dependencies
- `task`: `TO-F04`
- `task`: `TO-C02`
- `task`: `TO-V03`
<!-- todo-orchestrator:v2-managed:end -->
