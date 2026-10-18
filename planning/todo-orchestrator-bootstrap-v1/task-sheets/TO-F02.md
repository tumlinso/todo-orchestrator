# TO-F02 — Ratify one canonical model of work and its invariants
**Workstream:** Foundation and product contracts
**Prerequisites:** TO-F01
**Initial ownership:** docs/product, docs/architecture, src/todo/contracts, pyproject.toml, AGENTS.md

## Deliverable

Specify PlanRevision, WorkItem, Requirement, Run, Assignment, Attempt, Actor, Authorization, Evidence, Outcome and ExternalOperation, including references and lifecycle boundaries. Separate declarations from execution records and separate current applicability from historical proof.

## Acceptance evidence

- Each entity has a unique owner and unambiguous identity/lifecycle.
- State/transition invariants and forbidden transitions are documented with examples.
- Simple single-worker tasks need no ceremonial run/lane configuration.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
