<!-- todo-orchestrator:v2-managed:start -->
# TO-A01: Define project-local SQLite authority and durable schema

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Design one local transactional store for canonical work, plans, attempts, capabilities, coordination, evidence and effect intents. Maintain schema migration discipline and explicit read-only opens.

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
- `task`: `TO-F02`
- `task`: `TO-F03`
<!-- todo-orchestrator:v2-managed:end -->
