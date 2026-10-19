# Project Control replacement

Operator-approved continuation of the completed standalone epic, 2026-10-19.
This scope supersedes the earlier standalone-only integration exclusion.

Use the [cutover operator notes](../../docs/operations/cutover-operator-notes.md)
for authority boundaries, backup references, rollback conditions, and the live
deployment evidence record. The live bindings and all 20 registered repository roots have now been verified;
the qualification receipt records their parity, runtime identities and MCP checks.

## Accepted decisions

- Replace the bundled Todo engine across all registered workspaces. Project
  Control mutation, service changes, integration, and cutover are authorized.
- Use native engine contracts and update clients and skills together.
- Migrate current task state and unfinished work. Preserve all legacy history
  as searchable immutable linked records; do not fabricate native verification.
- Pilot on todo-orchestrator, then migrate every existing registered authority.
- Other development is paused. Favor focused necessary checks and prompt delivery.
- Preserve other Project Control tools, dirty source, worktrees, and old authority
  data. Keep the original engine runnable for rollback.

## Delivery sequence

1. Commit and back up registered source and existing worktrees before editing.
2. Add supported native migration and host authorization interfaces.
3. Replace Project Control runtime binding, workflow surfaces, and private Todo
   consumers; keep physical host and observer infrastructure in Project Control.
4. Rehearse all authority conversions and qualify native workflow and profile
   boundaries on disposable state.
5. Freeze old writers, take final backups, migrate the pilot and remaining
   authorities, switch service/client bindings, and check real MCP behavior.
6. Preserve rollback artifacts and new writes, document actual evidence, commit
   and push integrated source changes.

## Initial backup checkpoint

All 20 registered repository roots and 212 present worktree snapshots were
backed up before implementation. Nineteen repository roots have verified remote
backup branches; the codex workspace is local-only by operator direction.
Existing branch positions, indexes, and working files were preserved. Missing
historical worktree registrations are listed in the private backup manifest.
Codex is intentionally receiving a fresh native Todo authority and has no prior
legacy authority database to export. The Skills workspace has a separate
primary supplement backup. Thus the migration target set is 19 existing Todo
authorities plus the fresh Codex workspace, for 20 registered roots total.

Private authority, configuration, and source bundles are retained under
`/mnt/block/todo-orchestrator-cutover/20261019T114102Z/` with a local copy in
the ignored `.cutover-backups/` directory. Backup branches use the prefix
`backup/todo-cutover-20261019T114102Z/`. Credentials and databases remain local.
The manifest records original and snapshot commit IDs and remote verification.

Project Control implementation starts from its complete source snapshot
`68621d6f4e4e2285424528da8b37781965f6cef2` in an isolated worktree; this includes
the pre-existing uncommitted work without altering the live source deployment.

## Completed cutover

On 2026-10-19, Project Control 0.4.0 switched to the separately installed Todo
Orchestrator 0.2.0 engine. All 20 native authorities are active; public reads
matched 2,253 task mappings, 15,231 history records and 1,933 legacy completion
assertions. Both services and fresh MCP clients passed live checks. See
[`cutover-live.v1.json`](../../docs/qualification/cutover-live.v1.json) and the
operator notes for exact artifacts, rollback boundaries and retained limitations.
