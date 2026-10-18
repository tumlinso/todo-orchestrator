# TO-A05 — Rework claim and lease transactions around attempts
**Workstream:** Authority, transactions, and eligibility
**Prerequisites:** TO-A03, TO-A04
**Initial ownership:** src/todo/model, src/todo/authority, tests/authority

## Deliverable

Attach exclusive ownership, filesystem scopes, named locks and lifecycle to attempts. Preserve dirty-work quarantine, process-unknown semantics and one-active-claim invariants; external resource reservations remain provider owned.

## Acceptance evidence

- Two competing claimants produce at most one successful claim.
- Parallel-safe assignments overlap only with proven isolation contracts.
- Expiry never erases dirty or potentially live work.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
