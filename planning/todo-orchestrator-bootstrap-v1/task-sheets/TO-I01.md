# TO-I01 — Expose stable standalone Python, CLI and skill interfaces
**Workstream:** Standalone interfaces and host integration
**Prerequisites:** TO-P04, TO-C02, TO-F03
**Initial ownership:** src/todo/api, src/todo/providers/execution, src/todo/providers/resources, SKILL.md, references

## Deliverable

Build clean domain-oriented application APIs, `todo` CLI entry points and a standalone SKILL.md that teaches agents how to plan and execute. Expose bounded receipts, errors and actionable next steps; keep internal state machines private.

## Acceptance evidence

- Todo works without Project Control installed.
- Simple create/preview/claim/report/finish workflows are concise.
- Public contracts are versioned; legacy names live only in adapters where necessary.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
