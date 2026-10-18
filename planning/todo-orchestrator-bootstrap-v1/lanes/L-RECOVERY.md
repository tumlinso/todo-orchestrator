# L-RECOVERY — Recovery and lifecycle

**Role:** specialist  
**Workstream:** `TO-RECOVERY`  
**Initial scoped ownership:** src/todo/operations, src/todo/views, tests/recovery

Reconcile interruptions and preserve work, evidence, and authoritative provenance.

## Assigned outcomes
- `TO-R01` — Create unified inspection of interrupted and uncertain operations
- `TO-R02` — Apply safe and auditable recovery transitions
- `TO-R03` — Supersede, retire and replace work without history loss
- `TO-R04` — Add trustworthy export, projections and explicit restoration

The lane ends with formal workstream closure `TO-RECOVERY`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
