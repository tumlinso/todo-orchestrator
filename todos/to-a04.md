

<!-- todo-orchestrator:v2-managed:start -->
# TO-A04: Introduce host-agnostic actors, grants, and scoped capabilities

Task revision: `64`; current project revision is in `todo-status.md`.

## Objective
Replace Codex environment-variable identity and hardwired skill names with trusted host-supplied actor identity and bounded, revocable capability grants. Authorize parent and child delegation without implicit privilege escalation.

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
- `task`: `TO-A01`
- `task`: `TO-F04`
<!-- todo-orchestrator:v2-managed:end -->
