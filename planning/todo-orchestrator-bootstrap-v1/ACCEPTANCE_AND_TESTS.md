# Cross-cutting acceptance and test strategy

## Product-level release gates

The release is qualified only when all are demonstrably true:

**P-01 Standalone:** import/CLI works without Project Control or Codex; package identity/version are independent of monorepo layout.

**P-02 Ingestion:** machine package and handwritten plan compile deterministically; type errors and whole-graph cycles are explained; unchanged reimport is no-op.

**P-03 Safe revision:** plan commit uses expected authority and typed changesets; active scopes/gates/completion cannot be silently weakened; selective replanning preserves lineage.

**P-04 Concurrency:** no double claim, no unproven overlapping writes; observed eligibility and atomic admission share one rule engine; recovered attempts are never mistaken for current owners.

**P-05 Delegation:** actor/grants are trusted, revocable and bounded; child rights remain subset; child candidate is not final accepted outcome.

**P-06 Evidence:** source-bound checks plus final applicability; stale changed inputs cannot be accepted. Historical acceptance and valid negative result semantics persist.

**P-07 External effects:** Git/repository operations have durable intents/receipts and fail-injection reconciliation; all dirty/conflict cases preserve source work.

**P-08 Recovery:** unknown-live and dirty cases quarantine; inspection never writes; restoration is explicit with identity/revision checks; retirement preserves successors and history.

**P-09 PC integration:** one semantic writer; PC source views combine with normalized Todo read models without database imports; MCP profile restrictions remain server enforced.

**P-10 Migration:** dry-run parity report on representative legacy fixtures, explicit opt-in cutover, no unapproved live DB edits or repo changes.

**P-11 Ergonomics:** one small single-worker workflow demonstrates planning, claim, evidence and completion without manual run/lane ceremony; one multi-worker workflow demonstrates safe independence and coordinated integration.

## Required deterministic test matrix

| Scenario | Expected outcome | Key invariants |
|---|---|---|
| Same package imported twice | No additional work or semantic revision | I-02, I-03 |
| Rewrite actively claimed scope | Reject or require explicit transition | I-03, I-05 |
| Task → checkpoint → producing task cycle | Reject with witness | I-04 |
| Concurrent claim race | One admits, other has typed blocker | I-05 |
| Concurrent overlapping scopes | Reject without exact isolation proof | I-05, I-07 |
| Stale cap/child escalation | Refuse, no state mutation | I-06 |
| Publish secret/unbounded message | Refuse and retain no raw content | I-13 |
| Gate input changes during verification | Historical evidence retained; current acceptance blocked | I-08, I-09 |
| Accepted negative benchmark outcome | Policy-valid, distinct from process failure | I-09 |
| Workspace side effect with missing DB receipt | Report uncertain and reconcile, not blind replay | I-10 |
| Claim expires with dirty changes | Preserve/quarantine source | I-10 |
| Process status unavailable | Treat as unknown, not dead | I-10 |
| Absent authority on read path | No initialization/restoration | I-11 |
| GPU resource provider disconnected | Only affected work blocked | I-12 |
| Legacy schema conversion | Classified parity/intentional delta; no live write | I-01, I-11 |
| PC read-only profile calls mutation | Refused before Todo mutation | I-06, P-09 |

## Test harness

Use ephemeral repo roots and SQLite DBs, isolated Git worktrees and deterministic test clocks, simulated external process/GPU/resource providers, and fault injection between each step of external operations. Live GPU hardware is optional and tested by the external provider, not Todo core. Keep a parity corpus of original cases plus deliberate new-model behavior. Record both successful and refused operations and their revision/event effects.

At least one end-to-end scenario should exercise: compile plan → preview change set → authorize commit → claim two safe parallel tasks → report a failed candidate → retry → verify current evidence → accept outcome → close workstream → export semantic state. A second scenario should interrupt an effect, restart, inspect, reconcile and prove no work loss. A third should import a versioned legacy fixture and produce a dry-run mapping.

## Package validation vs implementation tests

`scripts/validate_package.py` validates **this bootstrap archive**, not the future product. Its checks cannot prove the actual Todo package's `plan validate` semantics or the security guarantees above. Before applying the native plan to the new registered authority, run the actual current Project Control validation on that host. Before product cutover, run the new product suite and an isolated legacy migration rehearsal.
