# Planning workstream acceptance

TO-P01 through TO-P04 are complete in the development authority. The standalone
library now provides strict typed compilation, whole-graph validation and typed
condition evaluation, pure deterministic change previews, and authenticated
transactional plan commits with durable accepted snapshots.

Evidence: the integrated source suite passed 177 tests, followed by a passing
split/merge lineage regression in the six-test service suite. The final required
P04 gate passed all 50 planning tests. The four reference tests, captured original
source fingerprints, compilation checks, and whitespace checks also passed.
Independent commit tests cover reopen/no-op behavior, revoked exact retries,
stale/tampered review refusal without churn, and preserved historical references
and accepted outcomes while guarding active or completed work.

Runtime and safety limits remain explicit:

- Fixtures use disposable standalone authorities. This does not qualify a
  complete coordination, verification, Git integration, or recovery workflow.
- Active and accepted definition changes are refused. Authorized exceptional
  transitions and broader retirement/supersession recovery belong to TO-R03.
- Explicit retirement currently requires a valid final graph; historical data
  remains stored. Foreign adoption facts are trusted composition inputs, not
  independently verified remote observations.
- Schema v7 rejects older standalone schemas. No production migration, legacy
  import, Project Control adapter, service change, or cutover was performed.
- The public CLI still provides help/version. Workflow-facing commands and skill
  guidance remain TO-I01; end-to-end release qualification remains TO-Q05.

Implementation: `src/todo_orchestrator/planning/`, authority storage and
membership checks in `src/todo_orchestrator/authority/`, and the accepted-history
contract in `docs/architecture/plan-revisions.md`.
