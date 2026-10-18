# TO-Q04 — Rehearse migration and opt-in cutover in isolated clones
**Workstream:** Qualification, migration, and release
**Prerequisites:** TO-I03, TO-R04, TO-Q03
**Initial ownership:** tests/system, tests/qualification, docs/qualification

## Deliverable

Test conversion from original Todo authority and Project Control integration, comparing semantic exports, accepted completions, evidence and run status. Do not move or overwrite live state during qualification.

## Acceptance evidence

- Dry-run migrator yields exact parity/intentional-difference report.
- Ambiguous or unrepresentable states halt cutover with a recovery path.
- Existing runtime remains usable until explicit sign-off; no automatic live state restoration.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
