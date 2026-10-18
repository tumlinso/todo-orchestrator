

<!-- todo-orchestrator:v2-managed:start -->
# TO-C05: Support restricted delegation and parent-mediated acceptance

Task revision: `137`; current project revision is in `todo-status.md`.

## Objective
Allow an authorized parent attempt to delegate bounded read/write work and receive candidate results. Children cannot become independent plan/run authorities or self-accept final outcomes.

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
- `task`: `TO-C02`
- `task`: `TO-C03`
<!-- todo-orchestrator:v2-managed:end -->
