# Canonical domain, authorization and state invariants

## Entities

`Project` owns one SQLite authority and project identity. `PlanRevision` is immutable authored intent with source provenance and stable change identity. `WorkItem` is a stable intended outcome with parent, requirements, acceptance contract, scope and successor lineage. `Requirement` represents a typed prerequisite or check, optionally grouped as all/any/quorum. `Run` is a runtime execution context, `Assignment` schedules work, and `Attempt` records one worker incarnation and its grants/leases. `Actor` originates from a trusted host or standalone local authentication. `Capability` permits a bounded action on a named authority/scope. `Artifact` and `Evidence` describe identified outputs and checks; `Outcome` is an accepted, versioned result. `ExternalOperation` records the planned and observed lifecycle of an effect outside SQLite.

Avoid storing an independent mutable copy of `work_item.status`, `assignment.status`, `claim.status` and `dispatch.status` and treating all four as authoritative. Keep necessary persisted lifecycle states for atomic queries and diagnostics, but define exactly which one owns a transition and derive combined presentation from the records. Likewise, keep acceptance result types distinct from task lifecycle and verification-attempt status.

## Normative invariants

**I-01 Single semantic writer:** one project-local transactional authority owns definitions, claims, capabilities, decisions, completion and run lineage; projection caches are not authoritative.

**I-02 Atomic mutations:** mutation, revision/event/receipt and idempotency record either commit together or none commit. An exact idempotent retry cannot duplicate an outcome or advance semantic revision unnecessarily.

**I-03 Separation of intent and effects:** a new plan revision never silently edits an active attempt, changes frozen acceptance requirements, or rewrites a completed outcome. Such changes require explicit authorization and lifecycle transitions.

**I-04 Full graph safety:** detect cycles over all blocking relations (task, checkpoint, interface, barrier, decision dependencies and synchronization conditions). A conditional branch can be unresolved rather than false. No arbitrary code evaluation inside conditions.

**I-05 Atomic claim admission:** only one permitted active attempt holds incompatible work. Advisory readiness and transactional admission evaluate the same policy, but only admission makes a reservation. Leases/claims are not released merely because a process identity is unknown.

**I-06 Bounded authority:** grants bind project identity, actor/incarnation, scope, action set and relevant run/assignment/attempt. Client-submitted role labels do not confer authority; delegated child rights form a strict subset of parent rights. Terminal transitions revoke relevant capability families atomically.

**I-07 Explicit source and provider trust:** a source fingerprint or Git HEAD is evidence from a trusted observer with scope; an opaque arbitrary caller string cannot prove repository identity. Cross-project dependencies are qualified and explicitly adopted, not guessed from IDs.

**I-08 Evidence provenance:** record each verification attempt and exact input/contract/verifier identity. A passing historical result is not automatically current proof after source or acceptance contract changes.

**I-09 Accepted outcome integrity:** success is an authorized result with satisfied required checks and accepted/available artifacts at the final commit. Valid negative results can be accepted under explicit policies; a process return code is insufficient.

**I-10 Preserve uncertain work:** expired claims with dirty source, live/unknown processes, ambiguous external effects and conflicts enter quarantine/attention or explicit reconciliation. No blind destructive cleanups, reset or auto-replay.

**I-11 Explicit recovery and restoration:** inspection is read-only. Recovery requires a principal-bound or otherwise trusted grant and fresh expected authority. A missing database never triggers automatic snapshot restore on ordinary service construction.

**I-12 Resource ownership boundary:** physical GPU/CPU/memory ownership and preemption are outside Todo. Todo may retain semantic resource requirements and correlating permits, never a parallel physical lock database.

**I-13 Typed communication:** durable messages and derived contexts are bounded, scoped, non-secret and provenance-aware; they cannot mutate project facts or source files by the mere fact of being published.

**I-14 No forced ceremony:** a simple single-worker plan is executable without manually constructing run/lane/child hierarchies. Advanced synchronization and isolation activate only if required by the plan.

## Model transitions to define and test

- Plan: proposed → validated → accepted; revised/retired through explicit new revisions, not in-place mutable text.
- Work: intended → eligible/blocked (derived) → attempted (separate Attempt) → completed/failed/superseded (accepted outcome). A failed attempt need not terminalize the WorkItem.
- Attempt: admitted → active → reported → accepted / rejected / released; expired/uncertain/quarantined are genuine states with inspection and recovery transitions.
- Verification: pending → authorized → running → observed → accepted / rejected / stale / uncertain. Re-acceptance requires current input proof.
- External effect: prepared → executing → observed → finalized, with error/unknown reconciliation branches. No false database↔filesystem atomicity.

The implementing team may refine names and state granularity, but **every normative invariant must have at least one deterministic test, and every exceptional transition must have an explicit actor, expected revision and receipt**.
