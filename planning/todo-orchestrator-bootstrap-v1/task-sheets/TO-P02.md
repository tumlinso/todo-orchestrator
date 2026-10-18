# TO-P02 — Validate the complete typed dependency and condition graph
**Workstream:** Machine planning and controlled revision
**Prerequisites:** TO-P01
**Initial ownership:** src/todo/planning, tests/planning

## Deliverable

Unify tasks, checkpoints, interfaces, decisions, barriers, rendezvous and result requirements under one typed dependency engine. Verify whole-graph cycles and explain unsatisfied, unavailable, and unresolved states.

## Acceptance evidence

- Direct and indirect dependency cycles are rejected with an actionable witness path.
- Condition logic is bounded, typed and deterministic; arbitrary evaluated code is forbidden.
- Cross-project references need explicitly qualified contracts/receipts, not fake local edges.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
