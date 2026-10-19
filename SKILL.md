---
name: todo-orchestrator
description: Use the standalone Todo Orchestrator CLI to inspect workflow state, review plan changes, execute authorized work, recover interrupted operations, and export or explicitly restore an authority.
---

# Todo Orchestrator

Use the repository's `todo` command and public application interface for workflow
operations. Start with `todo --help` and read
[the command guide](references/command-guide.md) for exact syntax and examples.
The CLI is an explicit interface to the standalone authority; it does not
discover provider code from project metadata, plan content, or the selected
project directory. Commands that require host, source, verifier, or Git
observations need a trusted provider composition. The Python API accepts one
directly. The CLI can also receive an explicit installed factory through
`--provider-factory package.module:factory`; that factory receives the resolved
project root and validated metadata and returns `ProviderComposition`. Treat
the selected factory as trusted executable configuration. Without a provider,
keep the operation unavailable rather than manufacturing evidence.

Keep the Todo authority as the semantic source of truth. Do not edit its SQLite
database or generated Markdown/JSON projections directly. Reads do not initialize,
repair, migrate, or restore missing state. Initialize only when explicitly setting
up a new authority; select the project and authority identities deliberately.

For plan changes, inspect and explain the preview before committing its exact
reviewed digest and expected revision. Claim or dispatch only work whose declared
prerequisites are satisfied. Preserve provider receipts and evidence provenance;
reporting a candidate is separate from accepting its result. Finish work through
the supported lifecycle operation.

For interrupted work, inspect first and apply only a current, explicitly authorized
recovery intent. For backups, distinguish the sanitized read model from the full
SQLite backup. Restore only to a new path with an explicit manifest and expected
project, authority, and revision. A restored backup reflects authentication state
at backup time and cannot prove later revocation or external source freshness.

This skill covers the standalone Todo Orchestrator. It does not authorize changes
to Project Control, its services or other tools, legacy Todo implementations, or
production authorities.
