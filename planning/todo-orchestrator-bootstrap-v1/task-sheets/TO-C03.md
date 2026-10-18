# TO-C03 — Provide typed durable communication and decision synchronization
**Workstream:** Runs, assignments, and collaboration
**Prerequisites:** TO-C01, TO-A02
**Initial ownership:** src/todo/coordination, tests/coordination

## Deliverable

Keep bounded messages, questions/answers, decisions, interface changes, rendezvous and blockers, with explicit recipient and authority scopes; do not turn the ledger into a transcript store.

## Acceptance evidence

- Read/unread/sync cursor semantics are deterministic.
- Blocking communications affect progress only through declared requirements.
- Messages cannot embed secrets, uncontrolled logs, or grant new privileges.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
