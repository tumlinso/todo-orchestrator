# TO-R02 — Apply safe and auditable recovery transitions
**Workstream:** Recovery and lifecycle
**Prerequisites:** TO-R01
**Initial ownership:** src/todo/operations, src/todo/views, tests/recovery

## Deliverable

Prepare approved recovery actions, revalidate the exact authority inside the mutation transaction, and preserve state, workspaces and tokens that cannot be safely revoked.

## Acceptance evidence

- No unauthorized actor can force recovery by asserting a role.
- Repeat requests are idempotent and each transition is auditable.
- Recoverable work is requeued without losing uncommitted source changes.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
