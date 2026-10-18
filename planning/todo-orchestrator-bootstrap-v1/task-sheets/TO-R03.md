# TO-R03 — Supersede, retire and replace work without history loss
**Workstream:** Recovery and lifecycle
**Prerequisites:** TO-R02, TO-P04
**Initial ownership:** src/todo/operations, src/todo/views, tests/recovery

## Deliverable

Make plan supersession and quiescent run retirement explicit, with successor lineage, preserving accepted work and user-authorized handoffs. Avoid special-purpose SQL rewriting as the only route.

## Acceptance evidence

- Completed work and provenance remain accessible after supersession.
- Live work cannot be retired under stale or incomplete expectations.
- Downstream requirements are retargeted or explicitly unresolved, never implicitly dropped.

## Risks / guidance

- No special risk beyond the global product invariants.

These are acceptance outcomes, **not instructions for one commit per assertion**. Implementers may choose detailed methods and combine changes where safe. Claims and real verification gates must be bound and exercised in the actual authority before terminal acceptance.
