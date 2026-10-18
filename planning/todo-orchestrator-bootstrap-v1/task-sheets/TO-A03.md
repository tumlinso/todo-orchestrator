# TO-A03 — Unify eligibility, authorization and conflict evaluation
**Workstream:** Authority, transactions, and eligibility
**Prerequisites:** TO-A02, TO-P02
**Initial ownership:** src/todo/model, src/todo/authority, tests/authority

## Deliverable

Provide one deterministic decision engine for structural prerequisites, role/capability rights, source scopes, leases and safe parallelism. Use the same rule set for advisory reads and atomic admission, distinguishing observed eligibility from reservation.

## Acceptance evidence

- Readiness and claim-time checks cannot disagree by using different policy implementations.
- Blockers are typed and explain causal prerequisites, unknowns and conflicts.
- Admission rechecks preconditions and fails closed under races.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
