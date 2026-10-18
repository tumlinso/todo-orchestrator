# TO-A02 — Implement atomic transitions, revisions, idempotency and history
**Workstream:** Authority, transactions, and eligibility
**Prerequisites:** TO-A01
**Initial ownership:** src/todo/model, src/todo/authority, tests/authority

## Deliverable

Define typed command execution and revisioned state transitions in one transaction, with receipt identity, event history and derived read models; avoid a redundant event-sourced database architecture.

## Acceptance evidence

- A semantic mutation and its event/receipt commit atomically.
- No-op operations and exact retries do not create accidental revision churn.
- History and logical fingerprints are stable independently of SQLite WAL page layout.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
