# TO-R04 — Add trustworthy export, projections and explicit restoration
**Workstream:** Recovery and lifecycle
**Prerequisites:** TO-A02, TO-R02
**Initial ownership:** src/todo/operations, src/todo/views, tests/recovery

## Deliverable

Expose stable versioned read models and derived human-readable views; snapshots are backups/interchange artifacts, not silent startup restoration. Require explicit identity and revision checks for restoration.

## Acceptance evidence

- Read-only operation never creates or repairs state.
- Export/import preserve semantic identity, evidence references and version compatibility.
- Missing SQLite state reports unavailable until explicit qualified restore.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
