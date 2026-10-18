# Standalone Todo Orchestrator v1 plan

This directory contains the standalone execution plan derived from the supplied bootstrap package. It is scoped to building Todo Orchestrator as an independently usable workflow engine. The original package remains unchanged at `planning/todo-orchestrator-bootstrap-v1/`.

The derived native plan is `todo-orchestrator-standalone-v1.todo-plan.json`. Following the operator's "Bootstrap and begin" instruction, it was validated and applied only to this repository's development Todo authority on 2026-10-18 (revision 1 to 2, 41 additions, zero modifications, no warnings). `validation.json` and `application.json` record the supported runtime's responses. The Project Control service, its configuration and source, other tools, and legacy/production Todo authorities remain outside this plan. The original Todo implementation is reference material and must remain unchanged; use disposable fixtures for behavioral comparison and recovery work.

## What changed from the supplied plan

- Removed **TO-I02** (rewire Project Control to a thin adapter), **TO-I03** (move Project Control plan ingestion), **TO-Q04** (Project Control migration/cutover rehearsal), and optional legacy importer **TO-P05**.
- Narrowed **TO-I04** to Todo's trusted external execution and resource provider interfaces. Its prerequisites are now **TO-I01** and **TO-V02**; Project Control adapter work is not a prerequisite.
- Narrowed **TO-Q05** to standalone release and operator documentation. It retains prerequisites **TO-I04**, **TO-Q02**, and **TO-Q03**; migration/cutover rehearsal is removed.
- Reworded the charter, root outcome, and mixed foundation and qualification descriptions to remove host integration and cutover deliverables. Mentions of Project Control in standalone tests/contracts only state that the standalone core has no such dependency.
- Rebased package scopes from `src/todo/` to `src/todo_orchestrator/`, avoiding the generic `todo` import namespace.
- Set every task's policy to `serial`. In the recipient runtime this enforces seriality within a lane, not across lanes. The root must keep only one development task claimed at a time until isolation is qualified; the eight lane declarations do not authorize concurrent work in this checkout.
- Replaced broad foundation scopes with bounded ownership: **TO-F01** covers product/architecture docs and reference checks; **TO-F02** covers model contracts; **TO-F03** covers the package, isolated import/CLI harness, metadata, README, and AGENTS; **TO-F04** covers trust/provider contracts. **TO-Q05** owns release and operator docs, skill references, and qualification evidence.

The derived plan has **41 records** (8 workstreams, 29 tasks, 3 validations, and 1 root epic) and **65 dependency edges**, down from 45 records and 74 edges. No remaining dependency points to an excluded task. The eight original workstream/lane groupings are retained for traceability with lane-local serial policies; global serial execution is an explicit root orchestration constraint, not a schema guarantee.

## Start boundary

Begin with **TO-F01**: read the original Todo source as a read-only reference and record the Todo behavior baseline in this repository. Then proceed through the plan's dependencies; do not begin broad runtime implementation or concurrent lane work before the foundation and source-isolation qualification authorize it. Any source copying is incremental and stays in this standalone repository. No task here authorizes edits to Project Control, its service, live authority, other tools, or the original implementation.

This draft does not settle open design decisions that the package leaves unresolved, including the canonical plan format and long-term compatibility policy. Legacy plan import remains excluded from this v1 scope. Backup/export and explicit restore interfaces remain in scope for Todo's own authority; they do not authorize converting or restoring any live Project Control state.

## Reproduce and inspect

The generator reads the preserved machine plan and writes the derived plan deterministically:

```sh
python planning/standalone-v1/derive_plan.py
python planning/standalone-v1/derive_plan.py --check
```

The source plan's SHA-256 when this draft was derived was `80ad975a8a3a835bd7ba352c34d84f99ee28f46847cb5c199575fab9e72ff722`. The generator does not apply a plan or contact Project Control. The receiving Todo runtime must validate this draft before any separately authorized import or application.
