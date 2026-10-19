

<!-- todo-orchestrator:v2-managed:start -->
# TO-Q03: Qualify validation, external effects and crash recovery

Task revision: `204`; current project revision is in `todo-status.md`.

## Objective
Inject failures at each external-operation stage, changing file contents during gates, interrupted workspace creation and conflicting integration. Prove quarantine and historical proof invariants.

## State
- Lifecycle: `done`
- Execution: `closed`
- Parallel policy: `serial`
- Result: `validated`

## Next Action
_None._

## Ownership
- `exclusive`: `docs/qualification`
- `exclusive`: `tests/qualification`
- `exclusive`: `tests/system`

## Dependencies
- `task`: `TO-V04`
- `task`: `TO-R04`
- `task`: `TO-Q01`
<!-- todo-orchestrator:v2-managed:end -->
