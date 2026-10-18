# L-PLANNING — Machine planning and controlled revision

**Role:** implementer  
**Workstream:** `TO-PLANNING`  
**Initial scoped ownership:** src/todo/planning, tests/planning

Make structured plan compilation, dependency validation, and safe change-set application first-class.

## Assigned outcomes
- `TO-P01` — Specify and compile first-class machine plan packages
- `TO-P02` — Validate the complete typed dependency and condition graph
- `TO-P03` — Produce deterministic, inspectable change sets
- `TO-P04` — Commit plan revisions and replan safely
- `TO-P05` — Absorb legacy machine-plan import as a compatibility frontend

The lane ends with formal workstream closure `TO-PLANNING`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
