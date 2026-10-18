# Domain model contract

This document defines the standalone Todo Orchestrator domain vocabulary at
`DOMAIN_CONTRACT_VERSION = 1` in `todo_orchestrator.contracts.domain`. IDs and
references identify records; they do not establish that a record exists or that
the caller may use it. The model contains immutable values and transition
catalogues, not a workflow engine or a persistence schema.

## Records and ownership

| Record | Identity and content | Lifecycle owner |
|---|---|---|
| `Project` | `project_id` identifies one project; `authority_id` names its semantic authority. | Project authority enforces one transactional owner and uniqueness. |
| `PlanRevision` | `plan_revision_id` is stable; `sequence` orders revisions within a project. The immutable content lists revision-scoped work item definitions and optional source provenance. | Planning authority records proposed → validated → accepted. Accepted content is terminal. A change is a new revision, never an in-place edit. |
| `WorkItem` | `work_item_id` is the durable intended outcome. Its definition is scoped by `definition_revision_id`; parent and supersession links preserve lineage. | Planning authority owns definition changes. Readiness and blocked/eligible status are derived; attempts and outcomes do not mutate the definition. |
| `Requirement` | `requirement_id` identifies a typed prerequisite or named check owned by one revision of one work item. Prerequisites can target work items, checkpoints, interfaces, barriers, or decisions. `RequirementGroup` combines IDs with all, any, or quorum semantics. | Planning authority owns definition; admission/verification services evaluate it. The service resolves referenced records and detects cycles across the full blocking graph. |
| `Run` | Optional context bound to a project and plan revision. | Coordination service opens, closes, or retires it. A Run is not required for a simple task. |
| `Assignment` | Immutable scheduling decision for one work item, with optional assignee and Run. | Coordination service creates or cancels scheduling facts. Assignment is not a reservation; claim admission creates an Attempt. A reassignment is another fact. |
| `Attempt` | Unique worker incarnation for a work item, with optional assignment, Run, capability IDs, and lease. | Authority owns the attempt state transition under transactional admission and expected-version checks. |
| `Actor` | Stable actor identity plus incarnation and broad kind. | A trusted host or local-authentication boundary supplies and verifies it. A DTO, label, or actor kind is not authentication. |
| `Capability` | Opaque grant identity, actor, bounded scope, action names, and optional Run/Assignment/Attempt binding and expiry. | Authorization service issues, resolves, checks, attenuates, and revokes grants. A capability value alone grants no right. |
| `Evidence` | Immutable verifier result bound to an Attempt, named input digests, contract digest, verifier identity/version, observation time, and optional requirement/artifact references. | Trusted verification/provider boundary establishes observation provenance. Acceptance service decides whether it is still applicable to current inputs and contract. |
| `Outcome` | Immutable accepted disposition and version for a work item, linked to the accepting actor and evidence IDs. | Authority appends it only after authorization and required checks. A worker report, process exit code, or passing historical evidence is not an accepted Outcome. |
| `ExternalOperation` | Durable intent/observation identity, idempotency key, request digest, state, and optional receipt digest/reference. | Operations service records transitions; provider observes the external effect. A timeout or missing receipt is not proof of failure, and database state cannot make the external effect atomic. |

`EntityRef` carries project scope, distinguishes a revisioned work item or
requirement definition by `definition_revision_id`, and identifies an actor
incarnation by `incarnation_id`. Attempt, capability, and lease references
therefore bind to one immutable actor incarnation. Resolving a reference,
proving project membership, checking cross-project adoption, and checking
uniqueness are service/authority responsibilities.

## State ownership and allowed transitions

The exported transition maps are contract data only. They do not change records,
compare revisions, check actors, or write receipts. The authority that owns the
record must enforce a transition atomically and append its durable history. A
state change should create a new immutable value/event snapshot; callers must
not treat `dataclasses.replace` or a state enum as permission to transition.
Every exceptional transition also requires an authorized actor, an expected
authority revision, and a durable receipt; the DTOs do not supply or verify
those facts.

| State owner | Allowed transitions |
|---|---|
| Plan revision authority | proposed → validated → accepted; accepted is terminal. Editing intent or replacing an accepted plan creates a new revision. |
| Run coordinator | open → closed or retired; closed → retired; retired is terminal. |
| Attempt authority | admitted → active, released, expired, or uncertain; active → reported, released, expired, or uncertain; reported → accepted, rejected, released, or uncertain; expired/uncertain → active, released, or quarantined; quarantined → active or released. Accepted, rejected, and released are terminal. Resumption from uncertainty requires explicit reconciliation. |
| External operation coordinator | prepared → executing or unknown; executing → observed, failed, or unknown; observed → finalized, failed, or unknown; unknown → observed or failed. Finalized and failed are terminal. Unknown effects are reconciled by observation, never assumed safe to replay. |

Other records are immutable facts or definitions. In particular, WorkItem has no
mutable `ready`, `blocked`, `running`, or `complete` status; Assignment does not
own a claim; Capability revocation is an authority event; Evidence remains
historical when its current applicability becomes stale; and Outcome is not the
Attempt's status. `AttemptState.ACCEPTED` closes that attempt after review; the
Outcome alone owns the accepted disposition of the intended work. Do not add
parallel authoritative status copies for the same fact.

## Examples of forbidden shortcuts

- Editing the title or requirements of an accepted PlanRevision in place. Create
  a new revision and explicitly resolve its effect on active assignments and
  accepted outcomes.
- Treating `eligible` from a read as a reservation, or treating an Assignment
  as exclusive ownership. Only an atomic admission decision creates an Attempt.
- Turning a failed Attempt into a failed WorkItem automatically. The work item
  remains available for another authorized attempt unless an accepted Outcome
  establishes a terminal disposition.
- Marking work complete because an actor reported success or a process returned
  zero. The acceptance service checks authorization, required current evidence,
  and required artifacts before appending an Outcome.
- Reusing a passing Evidence record after its input or requirement contract
  changes. Keep the old Evidence and mark its applicability stale; require a
  fresh observation when policy requires it.
- Trusting an `Actor.kind`, caller-supplied role, Capability object, arbitrary
  Git hash, or claimed provider name as proof of identity or authority. A trusted
  boundary must establish the subject, scope, provenance, revocation state, and
  freshness.
- Treating an external operation timeout as failure and blindly replaying it.
  Preserve an unknown state, observe the external system, then record a
  revision-checked reconciliation decision.

## Value validation and service responsibilities

The standard-library dataclasses reject malformed local values: empty or
whitespace IDs, malformed SHA-256 digests, naive timestamps, invalid quorum
ranges, duplicate references, inconsistent project/reference kinds, invalid
revision-local references, and locally impossible state/receipt shapes. Tuples
and frozen dataclasses prevent accidental in-memory mutation.

They do **not** establish global identity uniqueness, referential existence,
cycle freedom, trusted actors/providers, capability issuance or rights-subset
delegation, revocation, lease ownership against live processes, source identity,
evidence freshness, atomic claims, idempotency, crash durability, or accepted
completion. The future services and project-local authority must enforce those
invariants. Transition maps are not a substitute for those checks.

`Evidence` stores historic provenance inputs; it intentionally has no mutable
`current` flag. Applicability is evaluated against the current source,
requirement contract, and verifier policy at acceptance time. `Outcome` records
the accepted result and its version without rewriting earlier acceptance
history.
