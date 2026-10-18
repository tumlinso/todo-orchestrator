# TO-F01 — Inventory the original contracts and construct a behavioral baseline
**Workstream:** Foundation and product contracts
**Prerequisites:** None
**Initial ownership:** docs/product, docs/architecture, src/todo/contracts, pyproject.toml, AGENTS.md

## Deliverable

Read the original Todo implementation and current Project Control adapters as reference material. Identify observable invariants, integration contracts, tests and historical compatibility layers. Record which behavior is product-essential and which is incidental or obsolete.

## Acceptance evidence

- An explicit source-to-capability inventory exists, with decisions to retain, adapt, isolate or retire.
- Representative current behaviors and safety invariants have reproducible fixtures or test descriptions.
- Original repositories and live authorities remain unmodified.

## Risks / guidance

- Confusing historical behavior with a required public contract.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
