# TO-C05 — Support restricted delegation and parent-mediated acceptance
**Workstream:** Runs, assignments, and collaboration
**Prerequisites:** TO-C02, TO-C03
**Initial ownership:** src/todo/coordination, tests/coordination

## Deliverable

Allow an authorized parent attempt to delegate bounded read/write work and receive candidate results. Children cannot become independent plan/run authorities or self-accept final outcomes.

## Acceptance evidence

- Child scope and permissions are strict subsets of the parent grant.
- Child retries, cancellation and acceptance have explicit stable identities.
- The parent or authorized validator must accept a child candidate before promoting it.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
