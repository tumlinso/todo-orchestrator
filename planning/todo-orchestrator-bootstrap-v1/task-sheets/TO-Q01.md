# TO-Q01 — Capture pre-redesign reference fixtures and safety expectations
**Workstream:** Qualification, migration, and release
**Prerequisites:** TO-F01, TO-F03
**Initial ownership:** tests/system, tests/qualification, docs/qualification

## Deliverable

Build disposable fixtures from the old implementation for plans, claim contention, delegation, gates, integration, dirty recovery, semantics and PC adapters. Classify intentional behavior changes explicitly.

## Acceptance evidence

- A versioned parity matrix identifies preserved, intentionally changed and unsupported legacy contracts.
- Regression fixtures require no live project authority or hardware.
- Uncertain legacy cases are documented rather than silently normalized.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
