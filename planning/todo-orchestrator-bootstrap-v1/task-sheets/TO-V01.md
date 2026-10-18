# TO-V01 — Specify typed verification and acceptance requirements
**Workstream:** Verification and safe integration
**Prerequisites:** TO-P02, TO-F04
**Initial ownership:** src/todo/verification, src/todo/providers/git, tests/verification

## Deliverable

Retain declared gates, checkpoints and evidence contracts without embedding concrete runners. Make required evidence and accepted negative results first-class, distinguishing acceptance from runtime exit status.

## Acceptance evidence

- Requirement types and predicate semantics are versioned and validated.
- Acceptable no-change and evaluated-not-promoted outcomes are representable without being called failures.
- Required checks cannot be weakened by an untrusted worker.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
