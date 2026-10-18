# TO-V04 — Isolate and qualify Git workspace/integration operations
**Workstream:** Verification and safe integration
**Prerequisites:** TO-F04, TO-C02, TO-V03
**Initial ownership:** src/todo/verification, src/todo/providers/git, tests/verification

## Deliverable

Adapt existing conservative Git-worktree, artifact and integration behavior behind a trusted repository-effects provider. Preserve operation-intent, idempotent receipt and conflict-recovery semantics without coupling the domain engine to subprocess Git details.

## Acceptance evidence

- Overlapping edits require actual workspace isolation and a qualified integration destination.
- Dirty work, ambiguous commits and conflicts are preserved for owner review.
- Injected crashes between intent, filesystem effect, and receipt cannot cause silent duplication or loss.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
