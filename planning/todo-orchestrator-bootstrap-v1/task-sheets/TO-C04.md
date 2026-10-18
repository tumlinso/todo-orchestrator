# TO-C04 — Derive bounded, provenance-aware worker context
**Workstream:** Runs, assignments, and collaboration
**Prerequisites:** TO-C01, TO-P03, TO-C03
**Initial ownership:** src/todo/coordination, tests/coordination

## Deliverable

Generate a task/assignment context capsule from the accepted plan, current decisions and source references. Version contextual findings separately; do not copy previously authored prose into successive task briefs as a source of truth.

## Acceptance evidence

- One authored fact has one canonical authority and generated views cite its version.
- Context refresh identifies changed/invalidated fragments.
- Large source bodies remain referenced in external content stores.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
