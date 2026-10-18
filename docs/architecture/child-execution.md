# Restricted child execution

C05 was accepted in the development authority at revision 142. Its required
coordination gate passed at revision 141. The integrated isolated source suite
passed 345 tests, including public child flows, scope policy, and credential
identity regressions. Review also exercised restart replay, expired/revoked
parent grants, and unresolved-child occupancy using disposable authorities.

Child execution delegates bounded implementation work from an admitted parent
attempt. A child keeps the parent's exact work, run, assignment, and attempt
context; it receives no plan or scheduling authority. The parent or an
authorized validator reviews its candidate, while accepting the child result
does not accept the parent work-item outcome or merge source changes.

`ChildExecutionService` exposes `start_child`, `read_execution`,
`submit_candidate`, `review_candidate`, `request_cancel`, and
`reconcile_stopped`. Starting a child requires the parent's current
`todo.child.delegate` grant (or `todo.child.retry` for a retry), an
authenticated child principal, a caller-supplied stable execution and logical
child identity, a restricted `AttemptScopeSnapshot`, and an explicit action
set. Child actions are limited to read, write, and candidate submission, and
must be a strict subset of the parent's current actions. A parent heartbeat
renews an active child capability only up to the renewed parent lease and the
expiry of every live ancestor; it never revives an expired or revoked child.

Path and lock attenuation is checked by
`require_child_scope_subset(parent, child)`. Positive path grants are
additive: a broad read grant does not cancel a narrower write grant. An
explicit forbidden-path overlap denies the request. Child paths must be
covered by an ancestor parent grant with sufficient access; locks must be
inherited without widening shared access to exclusive. Equality of effective
rights is rejected, including a parent scope whose redundant path descriptors
would otherwise make the same rights appear narrower. `child_scopes_conflict`
uses path ancestry plus write access, and treats a shared lock as conflicting
only when either request is exclusive.

The authority stores child executions, candidates, reviews, cancellation
requests, and stop observations as durable records. Execution identity binds
the parent attempt, exact target definition, child actor incarnation,
capability, scope, and action set. A logical child has at most three ordered
executions; retries use fresh execution identities and credentials and are
available only after the prior execution is rejected and stopped, or canceled
and stopped. Cancellation and candidate review do not prove the process has
stopped.

Child candidates contain a bounded summary and optional same-project artifact
references with content digests. A parent or authorized validator records an
accepted or rejected review. Parent release, finish, and outcome finalization
remain guarded while a child is active, has an unresolved candidate, or lacks
a current clean stop observation; host-reported absence of children does not
erase native child occupancy. `reconcile_stopped` records a fresh observation
bound to the parent lease and workspace before marking the child stopped and
revoking its capability family.

Schema v19 adds the immutable child identity and review history plus guarded
state transitions. Earlier alpha schemas are not migrated; disposable test
authorities must be recreated with the current schema. These checks qualify
the local authority model and injected host-provider contract; they do not
claim that a child process or Git workspace was launched by this library.
