# Recovery inspection

R01 was accepted in the development authority at revision 153 after its
required gate passed at revision 152. The integrated isolated source suite
passed 361 tests. Qualification used disposable SQLite authorities and real
temporary Git repositories, including before/after-effect interruption,
clean/dirty workspaces, moved base refs, advancing clocks, native child
occupancy, and pending candidate acceptance boundaries. Inspection remains
read-only; approved recovery mutations belong to R02.

`todo_orchestrator.operations.RecoveryInspectionService` provides a read-only
view of an interrupted attempt and the durable external operations linked to
it. `inspect_attempt()` requires
an open read-only `SQLiteAuthority`, a current `todo.recovery.inspect` grant,
and the exact attempt reference. Authorization is scoped to the stored work
item and its run, assignment, and attempt context. `inspect_effect()` inspects
an exact durable operation; a Git workspace-creation intent that predates an
attempt is scoped to its target work item without inventing an attempt context.

The service combines the persisted attempt, lease, workspace qualification,
and effect records with a fresh trusted host observation for that exact
attempt and workspace. Effect inspection uses injected read-only provider
inspectors. Inspection does not call attempt reconciliation, verification
reconciliation, Git-effect reconciliation, effect execution, or any recovery
transition. It writes no receipts or other records, clears no state, and does
not repair records. A returned host/provider inspection receipt is current
evidence, not a durable authority receipt.

`RecoveryStatus` distinguishes active, expired, unknown-live, dirty,
irrecoverable, safely-retryable, complete, and uncertain states. Missing,
stale, contradictory, or unprovable process/source evidence remains blocked
or uncertain; inspection does not infer that a process stopped or a workspace
is clean. Linked external operations retain their exact operation references,
durable states, and request/receipt digests. An interrupted or unknown effect
remains uncertain unless the authority already contains a definitive
not-applied observation.

Any `RecoveryIntent` is a preview only. For an expired safely stopped attempt,
the release intent names the original attempt and reports preconditions pinned
to the authority revision, lease, workspace, and host observation. Other
unresolved operation intents retain exact operation references. Inspection
does not perform those actions. Host/provider unavailability or mismatches
produce an uncertain result with a blocker; authorization, missing-entity, and
observation-binding errors use `RecoveryInspectionError` subclasses. These
checks cover the authority model and injected observation boundary; they do not
prove that a real process or workspace is safe unless the configured trusted
provider supplies fresh, matching evidence.
