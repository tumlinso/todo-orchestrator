# Architecture and module boundaries

## Dependency direction

**Host / application** → **Todo public API** → **domain/policy + transactional store** → **trusted provider contracts**.

Project Control owns MCP registration, startup profiles, workspace/repository lookup, source-reading and investigation. `todo-orchestrator` owns plan ingestion, semantic state, rights, readiness, claims, workflows, evidence acceptance, and recovery decisions. Providers own Git process details, external execution, physical resources and source observation. The core never imports `project_control`, model runtimes, or an accelerator controller. A host can inject a provider; clients cannot supply arbitrary executable/provider paths as part of a plan.

## Recommended internal organization (adapt as justified)

```text
todo-orchestrator/
  pyproject.toml
  README.md
  AGENTS.md
  SKILL.md
  planning/
  references/
  src/todo/
    model/         # typed plans, work, conditions, outcomes
    planning/      # input/legacy import, compile, changesets
    authority/     # SQLite, mutations, history, capabilities, admission
    coordination/  # runs, assignments, attempts, messages, context
    verification/  # gate policy, evidence, acceptance
    operations/    # external intents/receipts, recovery
    providers/     # narrow Git/source/execution/resource interfaces
    views/         # versioned read models, projections, export
    api/           # Python service, CLI, optional compatibility adapters
  tests/
```

This tree is deliberately descriptive, not a required file-by-file rewrite. Feature modules can be combined. Keep a **single project-local transactional authority**; do not split plan/claims/outcomes into independently inconsistent stores. A host-global resource coordinator, if present, is not part of this DB.

## Domains and ownership

**Planning** owns the authored plan and typed change-set compiler; it cannot mutate execution state directly. **Authority** owns state transitions, revision checks and grants. **Coordination** owns assignments/attempts and asks Authority for admission; it cannot forge validation success. **Verification** owns evidence requirements and acceptance policy; trusted execution providers produce observations. **Operations** owns interruptible external-effect records, but providers execute effects. **Views** are read-only projections and may be rebuilt; they never become a competing authoritative ledger.

## Working vocabulary

| Concept | Meaning | Not to confuse with |
|---|---|---|
| Work item | Durable intended outcome | One run of a worker |
| Plan revision | Immutable accepted set of definitions | Mutable current assignment state |
| Run | Execution context for a plan | Model process or OS job |
| Assignment | Work scheduled for a role/queue | A lease/claim |
| Attempt | A particular actor's authorized execution | Permanent ownership of the work item |
| Capability | Revocable grant over a bounded attempt | Caller-provided role string |
| Evidence | Observation tied to exact inputs | Accepted completion |
| Outcome | Authorized, evidence-backed work disposition | Exit code alone |
| External operation | Tracked effect that can be uncertain | An atomic SQLite operation |

## Canonical state vs observed state

Internal state is the authority for what was accepted and who has leases. Source/Git/process facts are observations with time, identity and freshness. A stable typed `AdmissionDecision` is produced by the same evaluator for `explain()` and transactional `claim()`, but read-time `eligible=true` must never be advertised as a reservation. Actual admission repeats relevant guards inside the transaction and coordinates external permits without claiming database atomicity with external providers.

## Provider interface design principles

- Narrow capabilities and explicit versioning, trusted construction, input/result validation.
- Each effect includes idempotency key, expected source state, operation scope, deterministic result identity when possible, and a receipt; unknown outcomes are not presumed failures.
- Git provider must prove worktree identity, base, clean/dirty source and immutable artifact identity. It must preserve conflicts/working tree edits.
- Execution provider runs checks but cannot mark a requirement accepted; its signed/trusted receipt or separately validated evidence is input to Todo acceptance.
- Physical resource permits remain with the external provider; Todo stores only stable logical references and freshness/expiry, not a competing GPU allocation.
- Providers may be absent. Abstract planning and state inspection continue; operations requiring missing providers report blocked/unavailable with typed reasons.

## Public interface

Expose versioned, domain-oriented Python service calls and a CLI. Example **conceptual operations**: `plans.compile/preview/commit`, `work.explain/claim/report/finish`, `coordination.assign/delegate/message`, `verification.evaluate/accept`, `recovery.inspect/prepare/execute`, `state.snapshot/delta`. These are not prescribed method names or an MCP tool count. PC adapts them to its own MCP profiles. Internal rows, helper functions and migration-era aliases should not be public contracts.

## Architectural gates

A design change is worth making if it reduces duplicated state/policy, makes authority boundaries enforceable, removes a direct reverse dependency, or makes evidence and recovery correctness testable. Replacing a stable local algorithm with a new framework just because the code is old is not sufficient.
