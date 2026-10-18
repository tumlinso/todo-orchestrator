# TO-V02 — Track verification attempts and external execution receipts
**Workstream:** Verification and safe integration
**Prerequisites:** TO-V01, TO-A02, TO-F04
**Initial ownership:** src/todo/verification, src/todo/providers/git, tests/verification

## Deliverable

Use durable gate-attempt identities and prepared/executing/observed/finalized lifecycle. Call trusted provider interfaces for actual commands/resources; correlate completion with source identity, operation identity and receipts.

## Acceptance evidence

- Interrupted external checks are recognized and reconciled; no blind replay.
- Evidence attempts retain exact input identity, verifier version and authorized effect.
- External GPU locks remain in separate GPU interlock provider.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
