# TO-C02 — Implement atomic dispatch, resumption and release
**Workstream:** Runs, assignments, and collaboration
**Prerequisites:** TO-C01, TO-A05
**Initial ownership:** src/todo/coordination, tests/coordination

## Deliverable

Join assignment selection, authoritative claim, bounded capability issuance and dispatch in a coherent transaction. Make resumption stable under connection/process restart and ambiguous task/run selection.

## Acceptance evidence

- Claim/dispatch/capability are atomic or leave no partial authority.
- Resumption cannot adopt expired, foreign or revoked work.
- Terminal finish revokes its authority family and preserves accepted results.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
