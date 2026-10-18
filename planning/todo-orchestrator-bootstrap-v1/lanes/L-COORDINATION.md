# L-COORDINATION — Runs, assignments, and collaboration

**Role:** implementer  
**Workstream:** `TO-COORDINATION`  
**Initial scoped ownership:** src/todo/coordination, tests/coordination

Coordinate concurrent human or automated workers without adopting an agent runtime.

## Assigned outcomes
- `TO-C01` — Define runs, assignments and optional worker lanes
- `TO-C02` — Implement atomic dispatch, resumption and release
- `TO-C03` — Provide typed durable communication and decision synchronization
- `TO-C04` — Derive bounded, provenance-aware worker context
- `TO-C05` — Support restricted delegation and parent-mediated acceptance

The lane ends with formal workstream closure `TO-COORDINATION`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
