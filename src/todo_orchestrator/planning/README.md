# Plan package v1

`todo-orchestrator.plan` schema version 1 is a strict UTF-8 JSON input to the
pure compiler in `todo_orchestrator.planning`. Parsing does not read an
authority, inspect a workspace, or execute conditions. Compilation requires an
explicit `Project` target and returns immutable domain definitions plus authored
planning metadata and diagnostics.

The document requires `format`, `schema_version`, `package_id`, `project`
(`project_id` and `authority_id`), and `work_items`. It may include
`provenance`, `requirements`, `checkpoints`, `interfaces`, `decisions`,
`barriers`, `rendezvous`, `invariants`, and `dependencies`. Unknown keys fail
closed. Records are normalized by identifier; semantically equivalent object
key and record ordering produces the same content digest. Provenance and raw
source digest remain available separately. Optional `source_manifests` entries
bind a stable source ID and location to a SHA-256 digest; they are sorted and
included in semantic identity. Optional structured `generation_metadata` is
bounded to 32 top-level fields, 256 values, and 8 nested levels. It is retained
for audit context but excluded from semantic identity.

For each optional definition array, omission means no supplied definition set;
an explicit empty array means the package supplied an empty set. The compiler
retains this distinction in `supplied_sections` and in its canonical proposal.
Neither form implies removal or retirement of existing authority records.

Each work item has a stable `id`, `title`, `objective`, `outcome`, `scope`, and
`acceptance`. Scope uses relative POSIX paths with explicit read/write/forbidden
access, concepts, and optional named locks (`name` plus `shared` or `exclusive`
mode). Optional ownership constraints name exact actor incarnations with
qualified references and `any`/`all` mode. Acceptance records assertions,
required evidence types, and allowed outcome dispositions. Motivation,
references, alternatives, unknowns, and delegated judgment are retained as
authored context.

References carry `project_id`, `kind`, and `entity_id`; work-item and
requirement references also need `revision_id` when they refer outside this
package. Actor references require `incarnation_id`. Any cross-project reference
requires an explicit `adoption_receipt` containing receipt and authority IDs and
a contract digest. A receipt is not proof by itself: `compile_plan` requires a
matching caller-supplied `VerifiedAdoption` fact for every foreign reference
and retains those facts on the compiled proposal. Foreign references retain
their project-qualified identity and are never rewritten as local IDs. The
compiler preserves declared `rendezvous` kind even though its entity reference
uses the barrier identity kind. Invariants have their own typed
`EntityKind.INVARIANT` identity.

Dependencies are source-scoped `all`, `any`, or bounded `quorum` groups. Every
member declares a typed relation and target; optional conditions use only the
bounded `all`, `any`, `not`, and `decision_equals` expression forms. Interface
version blockers carry an `expected_version`; frozen interfaces require an
exact match, while evolvable interfaces accept a numeric major/minor/patch
version at least as new as expected within the same major version.

Compilation validates one deterministic graph across work, requirements,
checkpoints and their producers, interface producers/consumers, decisions and
resolvers, barriers, rendezvous, and conditional decision references. It
returns stable cycle witnesses and withholds the compiled plan on any blocking
or lineage cycle. Parent and supersession relations are checked as a separate
lineage graph, so ordinary parent completion dependencies remain valid. The
pure `evaluate_condition` and `evaluate_blocking_group` functions share
four-valued `satisfied`, `unsatisfied`, `unresolved`, and `unavailable`
semantics with typed causes; they consume supplied facts and do not read
authority state or determine runtime readiness. A false condition deactivates
that member; inactive members never count as positive `any` or quorum votes. A
group with no active members is vacuously satisfied, while a quorum retains its
authored threshold among active members. V1 graph compilation is bounded to 512
nodes and 4096 edges. Unsupported operators and implicit/ambiguous references
are errors rather than guesses.

`preview_changes(proposal, snapshot)` is a pure comparison against an explicit
`AcceptedSnapshot`; it never opens or writes an authority. The snapshot binds
the accepted project and authority IDs, the authority semantic revision, the
accepted compiled plan, exact attempts/outcomes, and optional locked or
downstream references. The resulting `ChangeSet` carries those revision
preconditions, an immutable deterministic digest, exact effective definition
references, typed create/revise/link/unlink/supersede/retarget/retire
operations, impacts, conflicts, and merged-graph diagnostics. Record field
masks preserve omitted optional fields; omitted records and empty arrays do not
retire accepted definitions. Retirement is explicit through an exact typed
`ExplicitRetirement` input. Work-item, requirement, and outgoing dependency
changes revise one work-definition bundle, and the owned requirements use the
same definition revision. Active attempts, scope locks, accepted outcomes, and
frozen interface edits are surfaced as conflicts. Preview output is review
data only; guarded commit and authority integration are not part of this API.
