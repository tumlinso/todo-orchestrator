# TO-P03 — Produce deterministic, inspectable change sets
**Workstream:** Machine planning and controlled revision
**Prerequisites:** TO-P02, TO-A02
**Initial ownership:** src/todo/planning, tests/planning

## Deliverable

Diff compiled declarations against accepted definitions without simulating arbitrary writes on a copied database. Produce precise additions, updates, retirements, impacts and conflicts, preserving historical intent and omitted fields.

## Acceptance evidence

- Repeated ingestion of the same logical package is a no-op.
- Partial/omitted definitions are not interpreted as deletion.
- Diffs identify affected tasks, requirements, attempts and downstream consumers.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
