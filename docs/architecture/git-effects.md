# Local Git effects

`todo_orchestrator.providers.git` separates `GitEffectService`, which owns
authorization and durable authority transitions, from `GitRepositoryProvider`,
which observes files and performs Git operations. Abstract planning and authority
operations do not require a Git provider. V04 was accepted at development
authority revision 123; the verification workstream closed at revision 125.

The trusted configuration names one repository, an immutable base, an integration
branch, and separate worktree and journal roots. Integration uses a branch that
is not checked out in any worktree. It creates immutable Git objects and advances
the destination with an expected-old compare-and-set; it does not reset or
rewrite a checked-out index or tree. Conflicts retain a pinned tree for owner
inspection. Worktree deletion and automatic conflict cleanup are not provided.

Workspace qualification binds the actual root, index, branch, common repository
and managed worktree incarnation. Admission re-observes overlapping live peers
under the guarded writer and compares their original bindings. Distinct names
and cached claim-time receipts are insufficient. Process and child liveness
remain unknown unless a trusted host observer establishes them.

Source observation includes working files, index contents, file modes, untracked
and ignored files, and the configured selection policy. Git metadata is excluded.
Any additional exclusions are explicit trusted configuration and affect identity;
authored configuration is not silently treated as generated state. Observations
also retain the concrete Git revision. Integration requires the exact accepted
outcome and its immutable source provenance, rather than merely an accepted
attempt or a currently clean worktree.

The public service supports workspace creation and integration of an accepted
attempt. Other effect kinds in the generic provider vocabulary do not imply
implemented local operations. Each service operation persists an immutable
request before execution and reserves execution in SQLite before calling Git.
Exact public retries return the persisted operation after current authorization;
changed intent cannot reuse the same identity. Uncertain effects require
inspection. Only definitive absence and fresh effect authorization permit an
explicit retry.

An execution receipt and an inspection receipt are distinct facts. Inspection
binds the current query and recovery principal while naming the original effect.
A crash before an execution receipt does not justify fabricating one. A current
read or reconcile grant may inspect an earlier actor's operation after its grant
expires; that authority does not permit new effects. Git commits created before
publication retain their exact identities. Reconciliation must use those
identities; matching parent commits alone cannot establish operation attribution.

Tests use disposable authorities, Git repositories and provider stores. The
independent service suite includes a real subprocess exit after workspace
creation, reopen and inspection without duplicate worktrees, exact retry without
event churn, query-bound receipts and recovery after original-grant expiry.
These checks alone do not qualify the complete standalone workflow or release.
The integrated isolated source suite passed 290 tests, and the required V04
verification gate passed before task acceptance. Development checkout claims
remain serial; disposable product isolation tests do not qualify concurrent
engineering in the current checkout.
