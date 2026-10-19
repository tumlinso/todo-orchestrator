# Work and run lifecycle

R03 was accepted at development authority revision 166 after required gate
revision 165 passed. All 378 isolated source tests passed in 131.979 seconds;
the focused lifecycle suite passed eight tests. Independent disposable probes
also qualified exact superseding-definition handoff and unrelated-work refusal.
These are temporary SQLite/Git and trusted-provider fixtures, not external host
runtime qualification.

Plan changes and run retirement are separate operations. A work definition is
immutable once accepted; a successor records exact `supersedes` references to
the definitions it replaces. Retiring a definition requires an explicit
`ExplicitRetirement` in the reviewed plan change. Downstream parents and
requirements must be retargeted to the intended successor. Any remaining
reference to retired work is a blocking validation diagnostic rather than an
implicit unlink. Omitted records remain part of the effective plan; retiring
an old requirement therefore requires its own exact retirement reference.

An accepted outcome, its evidence, and its provenance stay bound to the exact
definition and attempt that produced them. Supersession does not transfer or
rewrite those records. The previous plan revision remains readable after the
new membership is committed. Revisions that weaken accepted work or alter
definitions with in-flight execution remain guarded by planning conflicts.

`RunLifecycleService` provides authenticated `close_run` and `retire_run`
operations. Each command binds to the run's canonical schedule digest and the
expected authority revision, then rechecks both in the writer transaction.
Closing requires an accepted outcome for every scheduled assignment. Closing
or retiring also requires quiescence: active or uncertain attempts, unresolved
child executions, pending candidates, and nonterminal Git or verification
operations block the transition.

Retirement records a disposition for every unfinished assignment. A handoff
names an exact assignment in an open successor run; if the work definition
changes, the successor's accepted plan must explicitly supersede the exact
source definition. Otherwise, the unfinished assignment remains unresolved
with a bounded reason. Completed assignments cannot be reclassified.
`todo.run.handoff` is required in addition to `todo.run.retire` for mapped
successor assignments.

Lifecycle events are durable audit records. Run schedules and assignment
identities are not rewritten, and retirement does not delete work history or
accept a work outcome. A retired run cannot be reopened or used to resume its
old execution; future work uses an explicit successor schedule.
