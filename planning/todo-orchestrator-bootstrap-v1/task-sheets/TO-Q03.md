# TO-Q03 — Qualify validation, external effects and crash recovery
**Workstream:** Qualification, migration, and release
**Prerequisites:** TO-V04, TO-R04, TO-Q01
**Initial ownership:** tests/system, tests/qualification, docs/qualification

## Deliverable

Inject failures at each external-operation stage, changing file contents during gates, interrupted workspace creation and conflicting integration. Prove quarantine and historical proof invariants.

## Acceptance evidence

- No stale evidence can be accepted as current success.
- Uncertain external effects cannot be blindly reexecuted.
- Dirty work survives expired claims, recovery and integration conflicts.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
