# L-VERIFICATION — Verification and safe integration

**Role:** specialist  
**Workstream:** `TO-VERIFICATION`  
**Initial scoped ownership:** src/todo/verification, src/todo/providers/git, tests/verification

Verify outputs against precise source/input identities and use external providers for effects.

## Assigned outcomes
- `TO-V01` — Specify typed verification and acceptance requirements
- `TO-V02` — Track verification attempts and external execution receipts
- `TO-V03` — Implement provenance-preserving acceptance of work outcomes
- `TO-V04` — Isolate and qualify Git workspace/integration operations

The lane ends with formal workstream closure `TO-VERIFICATION`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
