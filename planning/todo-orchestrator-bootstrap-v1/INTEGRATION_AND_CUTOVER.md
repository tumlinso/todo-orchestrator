# Standalone API, Project Control integration, migration and cutover

## Standalone product

The distribution/Git repository/skill name is `todo-orchestrator`. Use a valid Python import name such as `todo`; do not force historical `todo_orchestrator` imports on the new product. Offer an efficient CLI (`todo`) and Python application interface for explicit project initialization, plan compilation/preview/commit, claim/inspect/coordinate/finish, evidence, status/history, diagnostics/recovery and export. A standalone `SKILL.md` explains when and how an agent should use these operations, not the invariants that executable code must enforce.

A modest source tree is preferable to duplicated frontdoors. Avoid shipping a Todo-owned MCP server as the only public API; one may be added later if needed, but Project Control already has its own MCP profile system. Structured operation responses should report semantic outcomes (`eligible`, `reserved`, `blocked`, `completed`, `stale`, `uncertain`, etc.) without mapping unrelated statuses to synthetic `claimed` states.

## Project Control's exact responsibility

Project Control selects the workspace/repository authority from its trusted registry, enforces MCP profile exposure and host principal permissions, supplies trusted actor/source-provider context, and presents Todo views alongside independent source and inquiry evidence. Todo is the *sole semantic writer* of its plan/claim/workflow/acceptance database. PC must not call Todo-private SQL or `apply_plan()` directly in the final integration; instead it invokes a versioned public application service.

The existing PC surface contains `plan`, `frontier`, `overview`, `delta`, `next_task`, `inspect_task`, `coordinate_task`, `finish_task`, `maintain_execution`, and project amendments. Retain useful ergonomic behavior but do not freeze the old four workflow calls just because they existed; map them cleanly to public domain commands, with explicit compatibility transition and contract tests. Registered project ID resolution should be consistent on PC's interface; standalone Todo can accept a trusted local repository selection. Avoid hardcoded sibling `src/todo_orchestrator` layout and reverse import from Todo into PC runtime identity.

## Source copying strategy

Treat the old `project-control/src/todo_orchestrator/` as read-only reference. **COPY**, do not move or delete; port a tested behavior or algorithm into a new module after its requirements and acceptance checks are understood. Do not create a wholesale copied legacy package and call the extraction complete. Preserve useful mature logic for SQLite, source fingerprinting, claims, gates, worktree safety, recovery and migrations where it aligns with the new model; retire compatibility machinery in a well-scoped importer/shim.

Prioritize behavioral parity for essential invariants and explicitly list intentional differences. Keep the original Project Control runtime and all live Todo authorities operational during development. Never point an unfinished kernel at live state or run migrations on production authorities. The new product can be built and tested on disposable clones with simulated provider receipts; it does not require live GPU hardware.

## Migration requirements

Provide a read-only audit of a legacy authority and a dry-run conversion report with exact old/new entity mappings, provenance, incompatible records, preserved dirty/worktree state and semantic deltas. Qualify fixtures for completed work, in-flight work, child executions, recovery approvals, integration queues and history before considering actual import. Historical/source identity cannot be silently minted or reinterpreted; unsupported states halt migration and require explicit owner resolution.

A cutover sequence must be operator-controlled: backup + freeze/stop mutators → qualified import into fresh authority → check parity, unresolved effects and source identities → test PC adapter and CLI → explicitly switch host binding → monitor errors with a defined rollback condition. Never silently downgrade/overwrite the original DB. A rollback may mean restoring the old runtime/authority, not attempting an impossible schema downgrade.

## Delivery and release contracts

- `pyproject.toml` package/version, CLI smoke, import under no-PC environment, installation instructions.
- Versioned read/command schemas; explicit API compatibility behavior; Project Control release-pinned dependency identity.
- Standalone skill with bounded, scope-aware examples and no hidden mutation on reads.
- Qualified Git provider and provider-missing graceful degradation; GPU interlock provider external.
- Migration/cutover guide, regression matrix and release notes documenting intentional changes.

## Cutover stop lines

Stop if the new host points at an unqualified authority; if migration cannot preserve historical acceptance/dirty work; if new and old source identities diverge without an explanation; if a gate can accept stale inputs; if an external effect can replay destructively; or if profile restrictions are weaker than the previous deployment. Do not improvise around these failures by loosening authorization.
