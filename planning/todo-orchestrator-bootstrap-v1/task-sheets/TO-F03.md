# TO-F03 — Establish standalone package boundaries and development harness
**Workstream:** Foundation and product contracts
**Prerequisites:** TO-F01
**Initial ownership:** docs/product, docs/architecture, src/todo/contracts, pyproject.toml, AGENTS.md

## Deliverable

Ensure distribution todo-orchestrator, ergonomic Python module/CLI/skill entry points, versioned contracts, tests, no hard dependency on Project Control, and no reliance on a sibling source directory. Work with the new repository scaffold rather than overwriting it.

## Acceptance evidence

- Project Control is not imported by the standalone core.
- Isolated import/CLI and disposable SQLite/Git smoke fixtures are specified and subsequently runnable.
- Existing README/AGENTS/project settings are preserved and amended deliberately.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
