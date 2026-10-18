

<!-- todo-orchestrator:v2-managed:start -->
# TO-I04: Define standalone external execution and resource providers

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Define how standalone Todo requests externally owned resource permits and execution receipts. Keep background worker supervision and CUDA-specific paths outside the canonical engine.

## State
- Lifecycle: `planned`
- Execution: `ready`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `SKILL.md`
- `exclusive`: `references`
- `exclusive`: `src/todo_orchestrator/api`
- `exclusive`: `src/todo_orchestrator/providers/execution`
- `exclusive`: `src/todo_orchestrator/providers/resources`

## Dependencies
- `task`: `TO-I01`
- `task`: `TO-V02`
<!-- todo-orchestrator:v2-managed:end -->
