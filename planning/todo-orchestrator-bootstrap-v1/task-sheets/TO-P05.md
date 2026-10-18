# TO-P05 — Absorb legacy machine-plan import as a compatibility frontend
**Workstream:** Machine planning and controlled revision
**Prerequisites:** TO-P04, TO-F01
**Initial ownership:** src/todo/planning, tests/planning

## Deliverable

Copy or adapt relevant original preledger compilation behavior into a separate import converter, retaining source/provenance and explicit repository selection; lower into the new same typed plan representation.

## Acceptance evidence

- Old project-control-preledger and proposed_todos.json cases used in fixtures are ingestible or diagnosed precisely.
- The canonical new package format does not inherit legacy path-string heuristics.
- No old compatibility path is allowed to bypass standard validation and changeset review.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
