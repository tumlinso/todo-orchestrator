# TO-V03 — Implement provenance-preserving acceptance of work outcomes
**Workstream:** Verification and safe integration
**Prerequisites:** TO-V02, TO-C02
**Initial ownership:** src/todo/verification, src/todo/providers/git, tests/verification

## Deliverable

Require current applicable evidence for successful dispositions at the final commit, while preserving immutable historical acceptance records. Recheck dependency/requirement inputs after external execution and at acceptance.

## Acceptance evidence

- An input change during validation cannot produce a falsely current pass.
- Accepted completion captures requirements, artifacts, source identity and evidence IDs.
- Later source changes invalidate current applicability but do not erase historical success.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
