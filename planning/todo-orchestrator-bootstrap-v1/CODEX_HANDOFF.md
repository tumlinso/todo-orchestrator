# Codex implementation handoff

## Mission

Build the **new standalone `todo-orchestrator` product** in the new repository, using the accompanying normative specification and native work-plan package. Treat existing Todo as a *read-only source of qualified behaviors and potentially reusable algorithms*, not the architecture. **COPY over implementation selectively as new modules become ready; never move or modify the original runtime or live authorities.** The product must eventually replace the existing Todo's responsibilities while preserving safety invariants and simplifying the data/authority model.

## Priority sources

1. `PRODUCT_SPEC.md` — what the finished product must do.
2. `DOMAIN_AND_INVARIANTS.md` — constraints that may not be weakened.
3. `ARCHITECTURE.md` and feature specs — recommended division of ownership and interactions.
4. `ACCEPTANCE_AND_TESTS.md` — how you prove completion.
5. `MIGRATION_MAP.md` — where to inspect the original implementation and what to reuse.
6. `machine/todo-orchestrator.todo-plan.json`, task/lanes sheets — outcome-sized implementation plan and dependencies.

## First authorized development pass

Confirm the new repo's `AGENTS.md`, README, planning directory, Todo project identity and Project Control registration. Inventory the actual old-source checkout, report discrepancies with the reference map and identify the existing tests. Read the specifications and propose a brief architectural decision record for the canonical entities and API seam. Keep the first pass to contracts, fixtures and scaffolding; do not start broad copy-paste or multiple uncontrolled agents. Ask for authorization if the current operator has only approved package staging/validation.

Once the native plan is reviewed, validated in the actual recipient authority and explicitly applied, follow its dependency graph. Use outcome-sized tasks and meaningful tests. Implement each feature with scope discipline and preserve good original algorithms where they fit. A worker may decide *how* to implement a task, but cannot change the core invariants, trust boundary or acceptance conditions without explicit review.

## Working rules

- Single semantic writer. No direct SQL mutations from the PC adapter. No second host-global physical GPU-resource ledger in Todo.
- Model plan definitions separately from attempts/outcomes. One shared admission policy. Evidence validity rechecked when results are accepted.
- Git integration, process execution and physical interlocks via trusted provider interfaces; no source deletion on uncertain effects.
- Explicit, qualified state migration; no auto-restore on reads/startup or unprompted update of live Todo state.
- Existing project/agent development files are retained and merged, not overwritten from this package.
- Always test concrete claims about parity. Record intentional behavior changes, rationale and test evidence.
- Do not split into extra repositories or services unless a genuinely independent operational owner requires it.
- A native v3 bootstrap task's textual `completion_contract` is not an executable gate. Bind/execute necessary independent checks before asserting success.

## Desired end state

A standalone Python package, CLI and skill that can compile/import plans, show a safe frontier, admit and coordinate worker attempts, accept source-bound evidence, preserve work through failures, and integrate through thin Project Control adapters without importing PC. The original Todo remains usable until qualified, explicitly approved cutover.

## Short launch prompt (after staging and authorization)

> Read `planning/todo-orchestrator-bootstrap-v1/START_HERE.md` and the normative specs. Validate the package and inspect the new Todo authority and existing source references. Do not alter old Project Control/Todo source or live state. Present your understanding and any material conflicts. After explicit plan import and implementation authorization, execute the native work graph incrementally, copying/adapting original algorithms where justified, preserving safety invariants, and qualifying each outcome against its task sheet. Do not launch broad parallel agents until workspace isolation and claims are verified.
