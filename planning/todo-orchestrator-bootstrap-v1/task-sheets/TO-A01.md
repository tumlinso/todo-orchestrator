# TO-A01 — Define project-local SQLite authority and durable schema
**Workstream:** Authority, transactions, and eligibility
**Prerequisites:** TO-F02, TO-F03
**Initial ownership:** src/todo/model, src/todo/authority, tests/authority

## Deliverable

Design one local transactional store for canonical work, plans, attempts, capabilities, coordination, evidence and effect intents. Maintain schema migration discipline and explicit read-only opens.

## Acceptance evidence

- Single-writer consistency and multiple read-only connections operate correctly.
- Read methods never initialize, migrate, restore, or write a missing authority.
- Schema evolution has bounded migration/rollback-or-backup policies.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
