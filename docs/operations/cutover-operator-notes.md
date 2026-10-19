# Todo Orchestrator cutover operator notes

The native Todo cutover completed on 2026-10-19. The live qualification record is
[`cutover-live.v1.json`](../qualification/cutover-live.v1.json). Project Control
0.4.0 now uses the separately installed Todo Orchestrator 0.2.0 package.

## Preserved sources and backups

- The original Project Control Todo implementation and existing authority files
  remain the rollback source. Do not upgrade, rewrite, or replay them in place.
- The preimplementation bundle is
  `/mnt/block/todo-orchestrator-cutover/20261019T114102Z/`; its local copy is
  `todo-orchestrator/.cutover-backups/20261019T114102Z/`. The inventory is
  [`cutover-backup.v1.json`](../qualification/cutover-backup.v1.json): 20
  registered repository roots and 212 present worktree snapshots; remote
  backup branches are verified for 19 roots, while the Codex root is local-only
  by operator direction. The Codex workspace is intentionally starting with a
  fresh native authority; it has no previous legacy Todo database to export,
  and this does not block the 20-workspace cutover. The Skills workspace has a
  separate primary supplement backup. At the final writer freeze, every source authority was re-exported
  read-only and matched its frozen semantic digest and verified backup coverage
  before activation; no source authority was rewritten.
- Durable v4 snapshots and their verified index are retained in `exports-v4/`
  beneath that backup directory. The prepared candidates, activation journals,
  private credentials, pinned wheels and qualification evidence are retained
  separately beneath the same private directory. Codex received a fresh native
  authority; the other 19 received imports.
- Original runnable source is in `rollback-source/` at backup commit
  `68621d6f4e4e2285424528da8b37781965f6cef2`; the old `.dev-venv` is retained.
  The original engine is also preserved under Project Control's
  `legacy/todo_orchestrator-reference/`, outside active imports and packaging.

## Authority boundary and import meaning

Each registered repository receives a separate native Todo authority selected
by Project Control's trusted host binding. The old authority remains unchanged.
The import creates native work definitions for representable current tasks and
stores source task IDs/statuses and sanitized linked history in the new
authority. Legacy `done` is an immutable assertion tied to the exact imported
definition, not a native outcome or verification receipt. History remains
searchable through `todo_search_legacy_history`; historical events are not
replayed as native mutations. Current task mappings and preserved project
declarations are read with `todo_read_legacy_current_tasks` and
`todo_read_legacy_project_context`.

Unrepresentable current contracts create actionable attention and block the
affected work. Unknown external effects, child executions, or uncertain Git
operations are never assumed complete and never replayed by import. Inspect
and reconcile them using a fresh, supported native provider action. Preserve
the legacy Markdown/JSON projections and other repository files in a
timestamped private archive before switching clients. The original legacy
SQLite authorities and their directories are read-only. Unchanged authored plans
and historical projections were restored into the new root metadata directory
without replacing its native identity or database; they remain archival files.

## Deployment gates and rollback

Before switching any live writer, record the final source freeze, authority
backup and digest, exact native source fingerprint, per-repository import
receipt, task/status parity, attention count, history count, service binding,
Codex profile/tool manifest, and real MCP smoke results. Keep the prior host
binding and old authorities intact until all checks pass. A pre-switch failure
means abort deployment and resume the prior binding; do not clean workspaces or
change old authorities.

After the native authority has accepted writes, rollback is not a database
downgrade. Freeze native writers, take a private native backup, record all
post-cutover work and external receipts, then choose an explicit recovery path:
retain the native binding and repair forward, or restore the old runtime while
preserving the new authority for reconciliation. Never discard new writes or
replay their external effects automatically.

## Completed deployment

- Writers froze at **2026-10-19 13:31:32 UTC** after confirming zero active jobs,
  execution slots, GPU compute applications, admissions, leases and resident
  slots. The HTTP and inference services and old stdio MCP writers stopped.
- Pilot activation journal: `prepared-v2/activation-journal-20261019T133218Z.json`;
  public observer reads matched **41 tasks and 265 history records**.
- Remaining activation journal: `prepared-v2/activation-journal-20261019T133349Z.json`;
  all **20 roots** now use native authorities. Final public reads matched
  **2,253 current task mappings, 15,231 history records and 1,933 legacy completion
  assertions**. Old source databases remain intact and read-only. Per-root
  identities, status counts and counts are in the qualification JSON.
- Todo source: `d217e8c08f54a30bd58b346a843b3104774f5e20`; wheel SHA-256:
  `8e0f100e208a7880ee246daa0fc401f6b0889ff3daf8e14b333e79682b612ea1`.
  Project Control integration source: `cad955e733e2ab8cc207fc3d9a1a6824f4cfa470`;
  wheel SHA-256:
  `68c177a7d304d4ad112ec31bae0822f6fa73d39e731d4b4123baf1cb95a39fef`.
  Wheels and installed Python source fingerprints were independently matched.
- Project Control `.venv` now selects `.native-todo-venv`; source imports use
  Project Control's checkout and Todo imports use the independently installed
  package. Both services restarted. `/healthz` is `ok`; `/readyz` is `ready`;
  version is **0.4.0**, tool schema **11**. The 20 new authority directories have
  narrow systemd WAL grants; legacy supplemental grants were preserved disabled.
- A disposable real MCP workflow exercised plan, workspace, configured Luna
  producer, verification, expired-lease recovery, outcome acceptance, accepted
  Git integration and fresh observer persistence reads. The observer denied
  mutation. Evidence is in `qualification/native-mcp-fixture/`.
- Fresh live Codex stdio exposed **61 tools (53 native Todo)**; live observer HTTP
  exposed **22 tools** and denied a mutation probe. The full public observer
  parity/readiness check is in `qualification/live-cutover.json`.
- Acceptance finalizes an outcome; integrate **after acceptance**.
  `todo_finish_attempt` releases unaccepted work and is not post-acceptance
  cleanup. Existing Codex sessions must reconnect to refresh their tool schema.

The existing assistance registry still contains ten stale historical ownership
rows and reports pending physical cleanup. That pre-existing condition was
preserved; it is separate from Todo readiness. Demand-only assistance was
restored with automatic work disabled and no active jobs or resident models.
Native physical resource permits remain unavailable without a separately
configured trusted adapter; existing Project Control resource tools remain.

The cutover is accepted on this evidence. Repair forward after new native
writes, or follow the explicit rollback boundary above; do not silently resume
old writers against diverged history.
