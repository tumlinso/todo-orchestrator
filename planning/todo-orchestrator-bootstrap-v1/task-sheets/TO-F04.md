# TO-F04 — Define explicit trust and provider contracts
**Workstream:** Foundation and product contracts
**Prerequisites:** TO-F02, TO-F03
**Initial ownership:** docs/product, docs/architecture, src/todo/contracts, pyproject.toml, AGENTS.md

## Deliverable

Define interfaces for identity/authorization supplied by trusted hosts, repository/source observation, Git workspace effects, process execution, resource reservations, and evidence receipts. Todo retains semantic authority; providers own mechanisms.

## Acceptance evidence

- Provider contracts specify inputs, authority provenance, receipts, failure/unknown states and versioning.
- GPU interlocks, inference and job execution are expressly external, without duplicate ownership ledgers.
- Provider absence blocks only operations that require it.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
