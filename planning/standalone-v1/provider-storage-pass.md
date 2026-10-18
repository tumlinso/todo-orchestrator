# Provider and storage continuation

The first pass was committed and pushed as `e453740` on 2026-10-18 before this continuation. The work below stays within standalone Todo Orchestrator; Project Control source, configuration, service, other tools, and legacy/production authorities were not modified.

## Accepted outcomes

- **TO-F04:** versioned provider contracts for trusted host context, source observations, Git effects, command execution, external permits, and verification receipts. Read-only inspection binds uncertain effects to original operation/idempotency/request identity under current recovery authority, without repeating effects. Providers do not accept outcomes or own Todo grants. Only contracts and disposable fakes are implemented.
- **TO-FOUNDATION:** closed after all four foundation outcomes passed their bound checks and review.
- **TO-A01:** schema-v1 SQLite store with explicit initialization, identity/version/structural-schema validation, read-only opens, serialized writer transactions and rollback, and stable reader snapshots. Qualified target project IDs are retained. Initialization publishes without overwriting; directory-sync failure preserves the valid published database and reports uncertain durability. Unsupported platforms are refused before initialization creates files.

## Validation and limits

The final isolated source suite passed 61 tests and the separate reference suite passed four: **65 tests total**. These include 29 contract tests, 24 disposable authority tests, six package tests, two disposable fixture tests, and four reference-integrity tests. Independent review reproduced and drove fixes for missing effect inspection, incomplete schema validation, and an internal-name filter wildcard. Source/test fingerprints of both original implementations still match the captured baseline.

The development Todo authority accepted required gates for F04 and A01; A01 completed at revision 35. No task claim remains active at this checkpoint. No new package was installed into an existing runtime. POSIX initialization and the current SQLite/Python environment were tested; other operating systems and real power-loss recovery were not qualified. Migration supports only a current-v1 no-op and rejects other versions without repair.

Next is **TO-A02**, typed atomic commands, semantic revisions, idempotency receipts, and history. The current store is a trusted low-level persistence component, not a public workflow command or authorization engine.
