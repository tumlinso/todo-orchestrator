# TO-R01 — Create unified inspection of interrupted and uncertain operations
**Workstream:** Recovery and lifecycle
**Prerequisites:** TO-C02, TO-V02, TO-V04
**Initial ownership:** src/todo/operations, src/todo/views, tests/recovery

## Deliverable

Determine authoritative reconciliation from attempt, lease, workspace, evidence and external-effect records. Distinguish expired, unknown-live, dirty, irrecoverable and safely retryable states.

## Acceptance evidence

- Inspection is read-only and reports exact preconditions and blockers.
- Unprovable process or source state remains uncertain, not automatically clean.
- Recovery intent references original attempts and effects.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
