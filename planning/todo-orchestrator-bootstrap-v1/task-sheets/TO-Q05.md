# TO-Q05 — Deliver qualified release and operator documentation
**Workstream:** Qualification, migration, and release
**Prerequisites:** TO-I04, TO-Q04, TO-Q02
**Initial ownership:** tests/system, tests/qualification, docs/qualification

## Deliverable

Complete README, API/CLI/skill reference, schema/migration docs, operational guide, versioned PC adapter contract, release/source pin and qualification evidence; certify the standalone product.

## Acceptance evidence

- End-to-end scenario runs on a disposable project and produces inspectable receipts.
- Package/version identity independent of PC install layout is tested.
- Release gate explicitly documents unsupported providers and remaining risks.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
