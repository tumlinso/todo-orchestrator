# TO-P04 — Commit plan revisions and replan safely
**Workstream:** Machine planning and controlled revision
**Prerequisites:** TO-P03, TO-A03
**Initial ownership:** src/todo/planning, tests/planning

## Deliverable

Commit typed change sets transactionally with optimistic authority preconditions, explicit actor authorization and stable idempotency. Treat mutation of active or completed work as a guarded lifecycle change.

## Acceptance evidence

- Active claims cannot be silently weakened by plan updates.
- Retries cannot duplicate tasks, events, or successful operations.
- Revisions, supersession and downstream rewrites preserve accepted historical evidence.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
