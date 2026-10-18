# Runs and assignments

A work item names an intended outcome and an exact immutable definition. An
assignment schedules that definition in a run. An attempt records one actor
incarnation's leased occupancy. Their identities and histories remain distinct.

`CoordinationService.open_run` authenticates `todo.run.schedule`, verifies the
stored accepted plan, and atomically records an immutable schedule, assignments,
and the usual command receipt/event. Exact retries return the original receipt.
Reusing a run ID for different scheduling intent is a conflict. Reopening the
database reconstructs the schedule from normalized rows and validates its
canonical digest.

Without lane declarations, a run receives one default serial lane. Work can
also remain run-free. Explicit lanes support serial or parallel queues with
deterministic positions, optional exact assignees, required role grant actions,
and an isolation policy. Coordinated runs can carry a bounded typed charter;
parallel multi-item or multi-assignee schedules require one.

The shared eligibility evaluator enforces the persisted scheduling policy both
for advisory reads and transactional claims. Serial queues require predecessor
outcomes permitted by their accepted contracts and retain unresolved occupancy
until safe reconciliation. A role label does not authorize a claim: the actor
must satisfy the required grant action as well as the normal action, scope,
incarnation, expiry, revocation, and context checks.

Different lanes and runs do not establish source isolation. All claims still
pass the common scope/lock policy, and lanes can additionally require qualified
workspaces. A default serial lane is local to its run, not a global lock.
Trusted fixture observations prove policy behavior only; actual Git isolation
requires separate provider qualification.

Scheduling does not execute a worker or select a model. Dispatch, resumption,
handoff, and finalization are separate lifecycle operations.
