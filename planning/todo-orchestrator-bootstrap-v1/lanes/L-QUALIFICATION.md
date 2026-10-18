# L-QUALIFICATION — Qualification, migration, and release

**Role:** specialist  
**Workstream:** `TO-QUALIFICATION`  
**Initial scoped ownership:** tests/system, tests/qualification, docs/qualification

Prove safety, compatibility, packaging and opt-in cutover with disposable fixtures.

## Assigned outcomes
- `TO-Q01` — Capture pre-redesign reference fixtures and safety expectations
- `TO-Q02` — Qualify planning, admission and multi-agent safety properties
- `TO-Q03` — Qualify validation, external effects and crash recovery
- `TO-Q04` — Rehearse migration and opt-in cutover in isolated clones
- `TO-Q05` — Deliver qualified release and operator documentation

The lane ends with formal workstream closure `TO-QUALIFICATION`. Do not treat this as a script to perform every listed action sequentially outside the authority: respect the plan DAG, current claims, actual workspace isolation and release/review gates. Reconcile source scopes before editing beyond the listed areas. The current plan uses a simple exclusive-workspace mode; it does **not** authorize broad concurrent writes to one shared checkout without isolation qualification.
