# Scheduling, attempts, authorization and collaboration

## Why the old model should be consolidated

The original implementation has durable task rows; separately persisted run/charter, lane queues, claims, workflow dispatches, sessions and capabilities; child attempts; and multiple read views that infer readiness. That is an understandable evolutionary design, but it leaves several records representing aspects of the same active execution. The new model should give each entity exactly one purpose and make combined state a derived view.

## One admission policy

Implement a deterministic rule evaluator that can explain `allowed`, `blocked`, or `unknown`, together with typed, attributable causes and revision/freshness context. Apply the **same** domain decision logic to previewing ready work and authorizing a claim under a write transaction. A read-time candidate is not reserved; resource availability is observational until a trusted provider grants a permit. Claim admission always rechecks canonical blockers, scope exclusivity, actor grants, run/assignment state, and relevant leases.

The policy covers task/checkpoint/interface/decision/barrier prerequisites, owner restrictions, path read/write conflicts, named locks, child scope leases, and proven workspace isolation. It must not contain two implementations of `safe_parallel`, one for read views and one for claims. A conservative answer is better than misleading green status. Use typed blocker codes and explain causal chains.

## Run and assignment behavior

An accepted plan can execute as a simple single-worker queue with implicit default run/assignment semantics. Multi-worker runs have charters and versioned assignments, optional lanes and role policies, independent serial queues, and exact worktree/isolation constraints. Do not conflate a worker *role* with a named model, transport session, or filesystem process. Roles guide allowed actions but cannot bypass grants.

A work item is durable; an assignment says where its work is scheduled; an attempt is the particular, time-bounded actor occupancy. Releasing, failing, or crashing an attempt never destroys the underlying work definition. Retry/resume/replace attempt semantics must be explicit and protect accepted evidence and partial artifacts.

## Actor and capability model

Actor identities come from trusted host configuration, local credential verification, or another defined authenticating adapter—not arbitrary MCP request arguments or environment variables standing alone. Capabilities are opaque, hashed at rest if stored, scoped to project/authority, run/assignment, attempt or subordinate execution, allowed actions, and an incarnation. Expiry, revocation and principal identity must be enforced on every mutating call. Returning a `role='coordinator'` string is not an authorization mechanism.

Subordinate children receive only a subset of the current parent's authorized task scope and action set. They may return candidate code/verification/research results but cannot publish project-wide decisions, alter a run's scheduling, or promote their own candidate as the accepted parent outcome.

## Coordination and context

Keep durable typed messages (question, answer, decision, interface change, status, artifact, conflict, handoff), recipients and delivery cursors; preserve explicit blocking semantics rather than allowing arbitrary message urgency to impede work. Rendezvous/quorum/all-of barriers and typed decisions must reuse the same condition evaluator as plan prerequisites. Concurrent messages cannot create a second source of truth for project decisions: promoting a decision is a separate authorized mutation.

Generate bounded worker context by assembling the accepted plan revision, assignment, relevant canonical decisions, known caveats, source refs and fresh deltas. Preserve a versioned provenance chain for contextual findings, but keep large source bodies, raw logs and agent transcripts outside Todo. Context errors return a bounded reference/expansion action, not a false task failure.

## Isolation

Different lanes are not necessarily safe to edit the same worktree. Safe overlapping ownership requires *verified* independent workspaces with qualified common base and an integration destination; a branch name alone does not constitute isolation. Existing Git worktree handling may be copied and adapted behind a provider boundary once its crash and dirty-work behavior is characterized.

## Required tests

1. Two unrelated workers competing for one task produce one claim and one conflict.
2. Scope overlap is refused without proven worktree isolation, even if both are in different lanes.
3. A read model that advertises eligible work matches the shared policy, but can become stale before reservation; transactional admission safely refuses.
4. Claim expiry with dirty source, unknown-live worker or active child is preserved/quarantined.
5. A revoked/expired capability cannot mutate; a child cannot expand authority.
6. A simple task is claimable without manually constructing a full lane hierarchy.
7. Messages and context sync are deterministic, bounded, non-secret and versioned.
