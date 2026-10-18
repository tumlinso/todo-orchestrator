# L-FOUNDATION — Foundation and product contracts

**Role:** coordinator  
**Workstream:** `TO-FOUNDATION`  
**Initial scoped ownership:** docs/product, docs/architecture, src/todo/contracts, pyproject.toml, AGENTS.md

Define the product, baseline semantics, and standalone trust boundaries before changing source.

## Assigned outcomes
- `TO-F01` — Inventory the original contracts and construct a behavioral baseline
- `TO-F02` — Ratify one canonical model of work and its invariants
- `TO-F03` — Establish standalone package boundaries and development harness
- `TO-F04` — Define explicit trust and provider contracts

The lane ends with formal workstream closure `TO-FOUNDATION`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
