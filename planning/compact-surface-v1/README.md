# Compact Project Control workflow surface

## Purpose

Restore the established, small agent-facing Project Control workflow over the
standalone Todo engine. Project Control helps agents make progress across long
horizons by carrying context, authorization, and routine sequencing. The engine
may change internally; agents should not have to learn its full operation list.

## Surface and behavior

Keep the four routine workflow tools and their previous shapes as the baseline:

- `next_task(project, repository?, task_id?, run_id?)` selects a registered
  workspace and prepares or resumes work, returning bounded context, a workflow
  handle, and usable next steps.
- `inspect_task(handle, ...)` returns bounded information about the current
  task or related workflow subject.
- `coordinate_task(handle, ...)` performs a typed coordination
  action and returns its outcome and next useful step.
- `finish_task(handle, ...)` supports complete, handoff, block, and
  release while preserving existing completion and recovery guarantees.

Only `next_task` selects the registered workspace. The other three tools use
the returned handle; agents do not pass raw repository paths as selectors.

Keep privileged `plan`, `maintain_execution`, and `amend_project` on their
established routes. Preserve the observer's existing 11 read-only tool names and
permissions; use its existing project reads for current workspace context and
migrated Todo status/history. The current profile catalogs are observer 11,
coder 12, and mutator 16 tools. The active host manifest remains authoritative
for exact schemas and profile permissions.

Route engine capabilities through focused inspection kinds, typed coordination
actions, workflow completion, or privileged operations as appropriate. Keep
internal transaction details, identifiers, leases, credentials, and retry
bookkeeping inside the host. Do not hide supported functionality behind stubs.
The standalone package retains its granular API and CLI for clients that use an
independently managed Todo authority.

## Constraints

- Preserve the established user-facing simplicity; do not run a separate
  optimization campaign.
- Keep verification, evidence provenance, authorization, effect uncertainty,
  and physical resource guarantees truthful. A worker completion is not an
  acceptance decision, and unresolved effects remain visible.
- Preserve existing approval boundaries. Do not add review or approval steps
  merely to match engine internals; return a bounded review-pending result when
  an existing role must decide.
- Keep observer access read-only and usable without acquiring a task claim.
- Preserve original Project Control source and Todo authorities. Implement and
  qualify through an isolated checkout before deployment.

## Acceptance

The compact workflow must support preparation/resume, bounded inspection,
typed coordination, truthful completion/handoff/block/release, and safe
continuation after interruption without requiring routine agents to manage
native IDs or leases. Focused tests and fresh Codex/observer MCP sessions must
confirm the surface, role boundaries, migrated reads, persistent-agent handback,
and retry safety. Reuse unchanged engine qualification evidence. Live deployment
is complete only after the root controller records service and MCP qualification;
this document alone does not claim deployment.
