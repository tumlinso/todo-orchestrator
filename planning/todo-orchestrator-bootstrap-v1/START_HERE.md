# todo-orchestrator — implementation bootstrap v1

**Prepared:** 2026-10-18  
**Purpose:** A complete, inert handoff for implementing a standalone `todo-orchestrator` product in its newly initialized repository.  
**Status:** Planning package only. No code has been migrated or run, no live Todo authority changed, and no agent was launched.

## What to build

`todo-orchestrator` is a **standalone, local-first transactional planning and multi-worker workflow authority**. It accepts machine-generated or human-authored plans, guards changes to the accepted plan, schedules and authorizes work, records evidence-backed outcomes, and recovers interrupted operations without destroying uncommitted work. It can run via a Python API, `todo` CLI, and agent-facing skill; Project Control is one privileged host/consumer, not its dependency.

Read `PRODUCT_SPEC.md` (normative product requirements), `ARCHITECTURE.md` (module boundaries), `DOMAIN_AND_INVARIANTS.md` (state/authority rules), and `CODEX_HANDOFF.md` (implementation posture) before importing the plan. Supporting documents resolve the acceptance and migration constraints.

## Package anatomy

| Path | Use |
|---|---|
| `PRODUCT_SPEC.md` | Product definition, required behavior, anti-goals and non-goals |
| `ARCHITECTURE.md` | Modules, dependency direction, external provider boundaries |
| `DOMAIN_AND_INVARIANTS.md` | Canonical work model, state transitions, concurrency and security invariants |
| `PLANNING_AND_INGESTION.md` | Machine-plan language, compiler, change sets, controlled replanning |
| `WORKFLOW_AND_AUTHORITY.md` | Eligibility, assignments, attempts, communication and delegation |
| `VERIFICATION_AND_RECOVERY.md` | Evidence validity, external effects, acceptance, quarantine and restoration |
| `INTEGRATION_AND_CUTOVER.md` | Python/CLI/skill, thin PC adapter, source-copy strategy and safe cutover |
| `ACCEPTANCE_AND_TESTS.md` | Product-wide tests and release gates |
| `MIGRATION_MAP.md` | Old implementation source map, reuse/retire decisions |
| `RISKS_AND_OPEN_DESIGN.md` | Material remaining design choices and stop conditions |
| `CODEX_HANDOFF.md` | Clear start instruction and implementation autonomy |
| `machine/todo-orchestrator.todo-plan.json` | **Sole planned native Todo schema-v3 apply input**; 45 records in 8 lanes |
| `machine/proposed_todos.json` | Rich human/machine source catalog for 36 feature-sized deliverables |
| `machine/{workstreams,lanes,contracts}.json` | Source catalogs/working contracts (advisory, not separately imported) |
| `machine/{dependencies,acceptance}.csv` | Cross-referenced indexes; projections of plan/task sheets |
| `task-sheets/*.md`, `lanes/*.md` | Per-deliverable acceptance and per-lane context |
| `scripts/validate_package.py` | Offline package consistency + manifest validator; not Todo implementation |
| `VALIDATION_REPORT.json`, `MANIFEST.sha256` | Report and SHA-256 package inventory |

## Manual bootstrap, separated from execution

1. **Place** this package in `planning/todo-orchestrator-bootstrap-v1/` under the new repository (or in an external staging directory). Do not replace pre-existing `AGENTS.md`, `README.md` or project metadata.
2. **Review** the normative specification and the 36 outcome-sized task sheets. Confirm the source checkout(s) of the original Project Control and bundled Todo are accessible **read-only** to Codex; do not assume their paths are stable.
3. **Check** the archive independently: `python planning/todo-orchestrator-bootstrap-v1/scripts/validate_package.py planning/todo-orchestrator-bootstrap-v1` (adjust the path if staged elsewhere).
4. **Validate only**, after Project Control recognizes the *new repository's* Todo authority:

   ```bash
   project-control plan validate --project todo-orchestrator \
     --file planning/todo-orchestrator-bootstrap-v1/machine/todo-orchestrator.todo-plan.json
   ```

   The literal `todo-orchestrator` workspace ID must be verified locally; do not infer it from the Git repository name. Any validation failure is a stop line to repair the package or local registration. The offline report is not a substitute for this test.
5. **Apply only after an explicit operator decision**, after reviewing the actual plan diff, existing authority revision, and generated changes:

   ```bash
   project-control plan apply --project todo-orchestrator \
     --file planning/todo-orchestrator-bootstrap-v1/machine/todo-orchestrator.todo-plan.json
   ```

   This is **not** part of package creation or automatic Codex startup. Do not add a shell script that runs this command without review.
6. **Implementation** begins as a separate authorized step. First perform reference qualification and domain/API design, then copy/adapt source progressively; do not move or delete the original implementation in the source checkout.

## What is / isn't verified here

The package includes deterministic offline checks for JSON/CSV agreement, task IDs, DAG consistency, scope declarations, lane assignment, manifest integrity and normative-document presence. The new `todo-orchestrator` workspace could not be inspected from the current Project Control observer connection (`project_not_permitted`); therefore **no claim of live `plan validate`, import, authority bootstrap state, or runtime qualification is made**. That check belongs at the recipient host before apply.

## Interpretation of the 8 implementation lanes

They express **future assignment/ownership**, not a command to launch eight agents immediately. The pre-existing scaffold and live environment determine when worktrees, tools and reviews are qualified. Until independent isolation is proven, execute serially or in explicitly non-overlapping qualified workspaces. Prefer fulfilling a cohesive outcome to creating many trivial tasks.
