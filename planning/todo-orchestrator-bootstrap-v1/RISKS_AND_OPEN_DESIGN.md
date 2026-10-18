# Risks, design decisions and stop conditions

This package intentionally establishes **product semantics and invariants** more strongly than private implementation details. Choices below are for the implementing agent to investigate and record, not invitations to weaken acceptance criteria.

## Choices requiring evidence

- **Python import name:** `todo` is convenient; distribution/repo/skill name is unequivocally `todo-orchestrator`. Confirm import namespace conflict and choose a stable public package before substantive porting. A temporary legacy alias may exist at the PC adapter boundary.
- **State representation:** Decide exactly which authoritative entity stores attempt, assignment and work outcome state, and which statuses are derived. Reject write-path complexity that creates another duplicated status field without clear ownership.
- **Ingestion representation:** Final canonical JSON schema, stable ID policy, typed Boolean/quorum conditions and explicit unknown handling must be specified. This package's legacy schema-v3 plan is for bootstrapping the implementation effort, **not** the target product's new plan format.
- **Conflict granularity:** A whole-project optimistic revision may initially be safest. Scoped expected versions can improve concurrency once correctness is proven; premature fine-grained concurrency is not required.
- **Event/receipt durability:** Keep relational state + append-only history, not mandatory event replay. Define what reconstructability and auditing actually require.
- **Persistence/migration:** Existing DB schema has numerous compatibility migrations. New schema can be clean, but conversion must not discard source/evidence/completion identity. No automatic live migration.
- **Git effects:** Worktree manager can remain a default adapter inside the distribution; its public provider contract should be independent. Do not split it into a new service merely for architectural symmetry.
- **Context:** Source references are facts from trusted providers; source/content blobs remain external. The context assembly API should be small and bounded rather than storing a second narrative knowledge base.
- **Tests/gates:** Avoid encoding a literal `pytest` command in every imported bootstrap task before implementation. The task acceptance catalog is a specification; the implementation and validator must introduce appropriate executable gates before accepted completion.

## Serious risks and mitigations

1. **Unsafe compatibility mapping.** The old implementation accepts several lifecycle representations. Build golden fixtures, classify intentional semantic changes, and refuse unmappable states.
2. **Split-brain admission.** Advisory read code currently has parallelism checks separate from claim-time ownership checks. Remove duplicate policy implementations and test read/admit races.
3. **Plan changes rewiring live work.** Explicit work definitions and guarded changesets are required before broad plan import.
4. **External effects falsely represented as atomic.** Use durable operation state, uncertain dispositions and reconstruction from observed effects; never delete ambiguous work.
5. **Stale evidence accepted.** Bind evidence to exact inputs/contract and recheck applicability at finish.
6. **Resource double ownership.** GPU interlocks are external. Store receipt references, not local competing resource leases.
7. **Unqualified parallel agents.** Plan lanes are advisory until real Git/workspace and workflow authorization constraints are established. Start conservatively.
8. **Scope or package overwriting.** Existing scaffold, `.todo-orchestrator` state, AGENTS and README must be reconciled, not overwritten blindly by this archive.
9. **Premature PC cutover.** Keep original implementation and live authoritative state intact until isolated parity, migration dry-run and independent release certification.

## Stop lines

No copy/write into original Project Control checkout. No real authority migration, plan apply, worker dispatch, destructive Git command or live-source cleanup without explicit current authorization. No fallback to role strings or unknown-process assumptions on permission errors. No silent skipping of acceptance conditions because a validator provider is missing.

## Explicitly permitted creativity

The implementing agent may streamline module boundaries, switch from redundant per-task statuses to a coherent attempt model, simplify result/grant encodings, derive rather than duplicate contexts, optimize SQL, or choose a better typed API. For each nontrivial change, state the eliminated inconsistency, the preserved invariants, and the tests that demonstrate equivalent or intentionally improved behavior. Changing a name or introducing a framework alone is not progress.
