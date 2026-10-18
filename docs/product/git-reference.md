# Conservative Git behavior reference

Read-only inspection on 2026-10-18 used the `skills_dev` checkout at
`bfa9238985dfeb2368bad076f1cc51bfdadbae92`. The inspected source is
`todo-orchestrator/todo_orchestrator/workflow/workspaces.py`, SHA-256
`87351319cc603dfc51858279073b1b0b4a23c9828d9feff6b3297792ebf4367e`.
Selected source/test paths were clean; unrelated existing checkout dirt was
preserved. The original tests and effects were not executed for this inspection.

Useful behavior to preserve:

- `create_workspace` (lines 190–320) reserves provisioning before `worktree add`,
  checks canonical repository/base/path identities, and preserves the created
  worktree if database activation fails. Parallel participants require the same
  base. A random workspace UUID alone does not establish effect idempotence.
- `enqueue_artifact` (948–1029) checks the integration owner, exclusive
  destination, repository and common base. `apply_next` (1178–1326) reserves
  applying, refuses dirty destinations, checks artifact content, records the
  pre-apply HEAD and preserves conflicting files/index state.
- Commit freezing and HEAD advancement (138–179) separate commit creation from
  expected-old ref advancement. Final gates reject a changed destination.
- Cleanup checks (2600–2637) establish eligibility only; they do not delete work.

An adaptation must be more conservative than the historical conflict retry
fallback (1328–1402), which can restore tracked paths to the pre-apply HEAD.
Never automatically reset, restore, abort or delete owner-modified or uncertain
work. A missing receipt requires observation of the actual effect before any
explicit retry; semantic artifact deduplication is not effect reconciliation.

The existing new-engine workspace tests use trusted in-memory qualification
fixtures. Physical qualification still requires disposable real linked worktrees
with separate roots/indexes/refs and a qualified exclusive integration
destination. Required evidence includes overlapping admission; dirty tracked,
staged and untracked preservation; actual conflict preservation; stale destination
refusal; and crashes before/after Git effects and receipt finalization followed
by restart inspection without duplication or loss. Linked worktrees share Git
object/ref storage, so separate `.git` directories are not the isolation proof.

Reference tests inspected: `tests/test_workflow_workspaces.py` (SHA-256
`148415fed412602a0bded7df482d359d9e15c2027f840f26d0c51ccba5f3a3be`)
and `tests/test_workflow_integration.py` (SHA-256
`519774fc2cc3708642948f26a382f785f76c13f06db66bf500ee7fb6ea51ef3d`).
Their successful/conflict/gate cases inform the later provider tests; they do not
prove crash reconciliation for the new engine.
