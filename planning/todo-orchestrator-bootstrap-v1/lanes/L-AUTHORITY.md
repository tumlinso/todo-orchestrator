# L-AUTHORITY — Authority, transactions, and eligibility

**Role:** implementer  
**Workstream:** `TO-AUTHORITY`  
**Initial scoped ownership:** src/todo/model, src/todo/authority, tests/authority

Own project-local transactional state, authorization, resource-independent admission, and history.

## Assigned outcomes
- `TO-A01` — Define project-local SQLite authority and durable schema
- `TO-A02` — Implement atomic transitions, revisions, idempotency and history
- `TO-A03` — Unify eligibility, authorization and conflict evaluation
- `TO-A04` — Introduce host-agnostic actors, grants, and scoped capabilities
- `TO-A05` — Rework claim and lease transactions around attempts

The lane ends with formal workstream closure `TO-AUTHORITY`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
