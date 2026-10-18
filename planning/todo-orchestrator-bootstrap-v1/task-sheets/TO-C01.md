# TO-C01 — Define runs, assignments and optional worker lanes
**Workstream:** Runs, assignments, and collaboration
**Prerequisites:** TO-A02, TO-P02
**Initial ownership:** src/todo/coordination, tests/coordination

## Deliverable

Schedule accepted work through Runs and Assignments, with deterministic queues, role constraints and optional lane structure for parallel work. No dependency on an agent/model scheduler.

## Acceptance evidence

- A simple run can claim work without hand-authoring a lane hierarchy.
- Complex runs can assign serial and parallel work with explicit role and isolation policy.
- A work item, assignment and attempt have distinct identities.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
