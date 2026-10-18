# TO-I04 — Integrate external execution and resource providers without double authority
**Workstream:** Standalone interfaces and host integration
**Prerequisites:** TO-I02, TO-V02
**Initial ownership:** src/todo/api, src/todo/providers/execution, src/todo/providers/resources, SKILL.md, references

## Deliverable

Define how standalone Todo and PC adapters request externally-owned resource permits and execution receipts. Strip Todo background worker/host coordinator and CUDA-specific paths from canonical code.

## Acceptance evidence

- No duplicate physical GPU/resource ownership state is introduced.
- Unavailable providers have narrow, typed effects; normal planning still works.
- Execution outputs, secrets and model runtimes are not embedded in Todo events.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
