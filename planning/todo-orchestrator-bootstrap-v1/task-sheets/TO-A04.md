# TO-A04 — Introduce host-agnostic actors, grants, and scoped capabilities
**Workstream:** Authority, transactions, and eligibility
**Prerequisites:** TO-A01, TO-F04
**Initial ownership:** src/todo/model, src/todo/authority, tests/authority

## Deliverable

Replace Codex environment-variable identity and hardwired skill names with trusted host-supplied actor identity and bounded, revocable capability grants. Authorize parent and child delegation without implicit privilege escalation.

## Acceptance evidence

- Raw role names in client payloads confer no authority.
- Capabilities bind project, run, assignment, attempt, permissions and incarnation as applicable.
- Revocation/expiry and child-right subset constraints are enforced.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
