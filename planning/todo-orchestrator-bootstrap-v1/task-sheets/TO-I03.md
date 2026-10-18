# TO-I03 — Move plan ingestion responsibility out of Project Control
**Workstream:** Standalone interfaces and host integration
**Prerequisites:** TO-P05, TO-I02
**Initial ownership:** src/todo/api, src/todo/providers/execution, src/todo/providers/resources, SKILL.md, references

## Deliverable

Route native and legacy machine-plan compilation into Todo; simplify PC to permissioned plan submission, preview and result presentation with explicit authority preconditions.

## Acceptance evidence

- PC no longer hosts an independent plan compiler as its canonical ingress.
- Historical supported inputs pass through one typed validation/change-set path.
- Apply remains an explicit operator-authorized action, not a side effect of read or package import.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
