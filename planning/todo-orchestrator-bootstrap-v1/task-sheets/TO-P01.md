# TO-P01 — Specify and compile first-class machine plan packages
**Workstream:** Machine planning and controlled revision
**Prerequisites:** TO-F02
**Initial ownership:** src/todo/planning, tests/planning

## Deliverable

Implement a documented, expressive plan input that supports authored objectives, structured work, scope, decisions, acceptance, alternatives, provenance and explicit unknowns. Compile deterministically to the canonical domain model, independent of running workers.

## Acceptance evidence

- Equivalent inputs compile to stable logical content and diagnostics.
- The format does not expose SQLite or agent scheduling internals.
- Ambiguous paths, foreign references and unsupported conditions are reported rather than guessed.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
