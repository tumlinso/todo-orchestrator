<!-- todo-orchestrator:v2-managed:start -->
# TO-P03: Produce deterministic, inspectable change sets

Task revision: `2`; current project revision is in `todo-status.md`.

## Objective
Diff compiled declarations against accepted definitions without simulating arbitrary writes on a copied database. Produce precise additions, updates, retirements, impacts and conflicts, preserving historical intent and omitted fields.

## State
- Lifecycle: `planned`
- Execution: `ready`
- Parallel policy: `serial`
- Result: `-`

## Next Action
_None._

## Ownership
- `exclusive`: `src/todo_orchestrator/planning`
- `exclusive`: `tests/planning`

## Dependencies
- `task`: `TO-P02`
- `task`: `TO-A02`
<!-- todo-orchestrator:v2-managed:end -->
