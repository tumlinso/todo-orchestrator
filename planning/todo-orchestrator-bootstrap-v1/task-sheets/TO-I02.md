# TO-I02 — Replace direct Project Control internals with a thin adapter
**Workstream:** Standalone interfaces and host integration
**Prerequisites:** TO-I01, TO-F04
**Initial ownership:** src/todo/api, src/todo/providers/execution, src/todo/providers/resources, SKILL.md, references

## Deliverable

Allow Project Control to select a registered authority by workspace ID, provide trusted actor/permission context, and map Todo read/command interfaces to MCP. Keep Project Control source intelligence separate from Todo semantic truth.

## Acceptance evidence

- PC need not import Todo database tables or private plan functions.
- Project ID versus repository root selection is consistent at the PC boundary.
- Read profiles never gain mutation or initialization authority.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
