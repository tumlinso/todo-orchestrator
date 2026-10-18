# L-INTEGRATION — Standalone interfaces and host integration

**Role:** implementer  
**Workstream:** `TO-INTEGRATION`  
**Initial scoped ownership:** src/todo/api, src/todo/providers/execution, src/todo/providers/resources, SKILL.md, references

Expose independent Python/CLI/skill interfaces and keep Project Control thin.

## Assigned outcomes
- `TO-I01` — Expose stable standalone Python, CLI and skill interfaces
- `TO-I02` — Replace direct Project Control internals with a thin adapter
- `TO-I03` — Move plan ingestion responsibility out of Project Control
- `TO-I04` — Integrate external execution and resource providers without double authority

The lane ends with formal workstream closure `TO-INTEGRATION`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
