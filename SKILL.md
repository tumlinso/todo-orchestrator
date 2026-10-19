---
name: todo-orchestrator
description: Use the standalone Todo Orchestrator CLI to inspect workflow state, review plan changes, execute authorized work, recover interrupted operations, and export or explicitly restore an authority.
---

# Todo Orchestrator

## Project Control workspaces

For a repository registered in Project Control, use the compact Project Control
workflow: `next_task` prepares or resumes work, `inspect_task` returns bounded
context, `coordinate_task` handles typed coordination, and `finish_task`
completes, hands off, blocks, or releases work. Continue with the opaque
workflow handle and actions returned by the host. The host binds the workspace,
registered repository, identity, profile, credentials, and providers; routine
agents do not manage native authority IDs, leases, credentials, or retry keys.
Use the live host manifest for exact schemas and permissions.

Use Project Control's established read tools for registered workspace context
and migrated Todo status/history; observer reads do not require a task claim and
cannot mutate workflow state. Privileged plan and operational recovery remain
on their established Project Control tools. Imported completion assertions do
not constitute native verification, and unknown external effects require
attention rather than replay. Project Control handles snapshot import through
its explicit privileged procedure.

The standalone CLI and public application interface below apply only when
operating a separately managed standalone authority. They do not select or
open a Project Control workspace authority.

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
reporting a candidate is separate from accepting its result. Verify, report and
accept the result before integrating the exact accepted source. Acceptance is
terminal. Use `todo_finish_attempt` to release work without an accepted outcome;
it is not post-acceptance cleanup.

For authored command checks, use the versioned command contract and an explicitly
configured `command_execution_provider`. The command adapter passes a tool ID and
argument vector to that trusted provider; it does not construct or execute a shell
string. Raw stdout and stderr are not stored in Todo evidence. An allowed exit
code can satisfy the check, a disallowed exit code fails it, and timeout or
unknown execution remains inconclusive. Passing a check is not outcome acceptance.

Resource permits are external-provider operations. Through the Python session
API, use `reserve_resource`, `inspect_resource`, `reconcile_resource`,
`retry_resource`, and `release_resource`. The configured resource provider owns
physical capacity; Todo records a bounded logical permit and receipt. An unknown
or ambiguous permit remains unresolved and blocks attempt release and outcome
reporting or acceptance. Inspect before retry; the service retries a reserve
only after proving the same request absent, or a release only while the same
permit is still held. Permit expiry alone does not prove release. A delegated
worker receives a provider action only when its parent capability explicitly
includes that action. These methods are not CLI subcommands.

For interrupted work, inspect first and apply only a current, explicitly authorized
recovery intent. For backups, distinguish the sanitized read model from the full
SQLite backup. Restore only to a new path with an explicit manifest and expected
project, authority, and revision. A restored backup reflects authentication state
at backup time and cannot prove later revocation or external source freshness.

This skill documents standalone operations and the Project Control native Todo
client boundary. Production changes still require the active operator scope and
the qualification and rollback records in `planning/cutover-v1/`.
