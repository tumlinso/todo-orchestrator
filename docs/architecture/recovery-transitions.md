# Recovery transitions

R02 was accepted at development authority revision 160 after required gate
revision 159 passed. The isolated source suite passed all 370 tests in
131.022 seconds; independent recovery discovery passed 21 tests. Qualification
uses temporary SQLite/Git authorities and trusted injected providers, not a
live external host runtime.

Focused coverage includes exact release/requeue intents, stale and forged
previews, distinct authenticated recovery principals, Git and verification
retry after trusted not-started observations, observed-effect reconcile and
replay, and dirty workspace preservation.

R02 applies recovery intents from the read-only inspection API. Inspection
describes an observed state; it does not authorize or perform a transition.
`RecoveryExecutionService.apply()` requires a current bearer with both
`todo.recovery.inspect` and `todo.recovery.apply` for the exact work target and
stored run, assignment, and attempt (or exact target for an unattached effect).
Actor labels are not authority. The applying actor is recorded as the recovery
principal and is not substituted for the original worker or verifier.

The caller supplies the exact `RecoveryIntent` returned by inspection, an
idempotency key, and optionally the expected authority revision. The service
rechecks authorization, current revision, and a fresh inspection, then requires
the complete intent to match. This binds the action to the inspected attempt,
lease, workspace, source identity, operation references, and preconditions.
Attempt release and dirty handoff also compare the approved source digest with
a second trusted host observation inside the writer path. Verification and Git
retries obtain a fresh provider proof at the guarded transition; an inspection
view by itself does not authorize blind re-execution. Stale or altered previews
are refused before the transition. Each accepted transition retains its
durable command receipt and audit event.

The supported transitions are:

- `release_expired_attempt` relinquishes an expired attempt only when the
  writer is freshly observed stopped, its workspace is clean, no child is
  active, and linked external operations are resolved.
- `handoff_dirty_workspace` relinquishes an expired attempt only after a fresh
  exact observation proves the writer stopped and children absent, with no
  pending candidate or ambiguous external operation. It keeps the same
  registered workspace and all Git bytes, including staged, unstaged, and
  untracked content. The old attempt's capability family is revoked; a normal
  later claim may reuse the preserved workspace.
- `retry_original_operation` retries only the exact durable operation that
  inspection proved not to have started. The retry keeps the original
  operation identity and request binding.
- `reconcile_observed_effect` asks the existing operation service to persist a
  fresh observation of the exact effect. It does not repeat the original
  effect.

Unknown or unavailable host/provider results, a live or unprovable writer,
dirty source without a valid handoff, active/unknown child occupancy, a pending
candidate, changed source/base identity, or an ambiguous effect do not produce
an applicable intent. Dirty handoff is a scoped ownership transfer, not a
workspace cleanup, copy, reset, merge, or acceptance of the work's outcome.
Outcome acceptance remains a distinct operation.

The inspection/provider evidence is an observation at a time, not an atomic
lock on an external process or Git ref. The service checks the exact evidence
and authority preconditions before applying its guarded transition. A host
that cannot prove the required state leaves the work blocked for later review.

Qualification uses disposable SQLite authorities and temporary Git
repositories. It establishes the modeled authorization, audit, stale-preview,
idempotency, and preservation behavior for the injected providers; it does not
prove process-stop or repository safety for hosts that lack trusted observers.
