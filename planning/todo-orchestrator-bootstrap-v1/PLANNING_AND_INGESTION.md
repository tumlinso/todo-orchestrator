# Planning, machine ingestion and controlled change

## Goals

A machine plan package is authored intent, not an encoded sequence of SQL writes. It should be usable by a planning agent that knows nothing about Todo's physical schema, and by a human writing a small plan. The compiler makes malformed or ambiguous meaning explicit; it does not invent repository paths, dependency identities or implicit completion claims.

**Single pipeline:** source package → structural parsing → typed normalization → reference/condition resolution → graph validation → immutable compiled proposal → deterministic change set → guarded commit → accepted `PlanRevision`.

The existing PC `preledger.py` and Todo `plan.py` are source references for capabilities, not two parallel future compilers. `project-control-preledger` and `proposed_todos.json` are legacy input adapters; their ambiguous path heuristics must not define the canonical language. Plan compilation belongs in Todo.

## Input requirements

- Explicit format/schema version, package ID, target project/authority selection, source manifests, provenance and optional generation metadata. Idempotency derives from normalized semantic content plus stable request identity, not file modification time.
- Work records with IDs, titles, objectives, outcomes, references, ownership constraints and acceptance policies. Preserve motivation, desired end state, uncertainties, alternatives, delegated judgment, and reasons as authored context.
- Dependencies that explicitly distinguish task completion, accepted checkpoint, frozen interface version, verified evidence, decision condition, and rendezvous/barrier state; use a bounded typed condition language (no arbitrary eval).
- A plan can describe alternatives or unresolved choices **without** committing hypothetical branches as immediately runnable tasks. Unknown decisions remain visible and block only their actual dependents.
- Cross-authority constraints use exact typed project/entity references and explicit proof/adoption receipts. Separate projects must never treat a foreign task ID as a local FK.
- Source paths and scope claims must be typed and normalized; reject malformed/traversal paths, and preserve conceptual locations as concepts rather than turning them into guessed files.

## Compiler guarantees

- Deterministic canonical representation with stable IDs and hashes for logically identical packages, independent of field ordering or cosmetic JSON formatting.
- Schema/type checking, duplicate/conflicting ID detection, condition type checking, referential integrity, all blocking dependency-cycle detection with a witness path, and interface/consumer compatibility.
- Structured warnings vs hard errors; unknown unsupported semantics are rejected rather than silently accepted or discarded.
- The compiler and `preview` are **pure with respect to project authority**; they neither initialize a missing DB nor mutate production state. They can read a stable existing snapshot as an explicit input.

## Change-set semantics

Represent `create`, `revise`, `link`, `unlink`, `supersede`, `retarget`, `retire` or comparable typed operations. The change-set output includes object-level before/after identity, authority preconditions, dependency impact, locked/in-flight conflicts, and warnings. It is reviewable, resumable, and optionally signed/approved by a trusted principal.

Absent definitions mean **not supplied**, never implied deletion; explicit empty and explicit removal have distinct semantics. No-op exact reimports do not churn revisions, update timestamps or invalidate unchanged context. Changes to active ownership scope, gates, interface contracts, or already accepted results are never an unconditional upsert. Offer a safe revised plan/new assignment, explicit suspension/supersession, or refuse with blockers.

## Commit and replan

Under one SQLite write transaction: revalidate expected project identity and relevant revision/preconditions, check all affected work and downstream consumers, commit normalized definitions and links plus receipt/event/idempotency. Do not replay a trial mutation on a copied full DB merely to see whether something changed. Use typed proposed operations to calculate differences and apply exactly once.

Replan should support splitting, merging, retargeting, and retiring idle work and proposing revisions to active work via explicit transition/owner approval. Preserve predecessor-successor lineage, historical acceptance, and affected downstream requirements. Avoid in-place mutation that makes accepted source/evidence lie.

## Compatibility ingestion

Implement the supported old machine-plan formats as versioned *importers* and maintain old fixtures in the qualification suite. Qualify exact semantics that can be mapped, report ambiguous legacy values and unsupported constructs, and require explicit operator resolution. Do not require all legacy formats to remain public indefinitely. Legacy project-specific prefixes and `compat-v2` fabricated runs are import concerns, not an inference used in the canonical runtime.

## Definition of done

- Real self-contained machine plan and simple handwritten plan compile to the same typed model.
- Whole dependency DAG invalid inputs (including cross-type cycles) are diagnosed with paths.
- Preview/commit are deterministic and revision-guarded; active/terminal constraints cannot be weakened silently.
- Identical re-import is a semantic no-op.
- Legacy importer converts tested reference cases through the new compiler, retaining provenance and losses explicitly.
