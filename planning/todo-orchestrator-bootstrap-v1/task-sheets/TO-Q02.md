# TO-Q02 — Qualify planning, admission and multi-agent safety properties
**Workstream:** Qualification, migration, and release
**Prerequisites:** TO-P04, TO-A05, TO-C05, TO-Q01
**Initial ownership:** tests/system, tests/qualification, docs/qualification

## Deliverable

Exercise property-based or model-based tests of graph validity, no-op ingestion, competing claims, capability revocation, lane scheduling and decision consistency.

## Acceptance evidence

- No two active conflicting claims can be admitted.
- Observed eligibility and transactional admission share the same predicates.
- Idempotent retry and stale-plan rejection are reproducible.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
