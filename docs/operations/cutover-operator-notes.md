# Todo Orchestrator cutover operator notes

This is a deployment checklist and rollback boundary, not evidence that live
cutover has occurred. Exact deployment and service evidence must be recorded
below before declaring completion.

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
  separate primary supplement backup. These are initial backups, not a
  substitute for the final writer-quiescence backup immediately before
  deployment.
- The current sanitized export index was generated at
  `/tmp/todo-cutover-exports/reindex-v4/index.json`. It is temporary staging
  data for the 19 pre-existing Todo authorities: copy it and its snapshots into
  a durable, access-controlled deployment area, verify every digest, and record
  that area before using it. Treat the fresh Codex authority as a native
  workspace initialization, not a legacy import.

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
timestamped read-only archive before switching clients; the archive destination
and per-root manifests are deployment evidence and remain pending below.

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

## Deployment record — pending

- Final writer freeze and backup: **PENDING** — time, paths, source digests.
- Durable v4 snapshot staging and all registered-source exports: **PENDING** —
  19 existing authorities plus the separately initialized fresh Codex authority.
- Native engine source fingerprint and package identity: **PENDING**.
- Per-repository import receipts, current task/status parity, linked history,
  and attention review: **PENDING**.
- Archived old projections and per-root archive manifests: **PENDING**.
- Project Control service/client binding, restart, readiness, and live MCP
  smoke results: **PENDING**.
- Operator acceptance or rollback decision: **PENDING**.
