# Dispatch and resumption

`CoordinationService.dispatch` selects an exact scheduled assignment or a run-free
work item, rechecks the presented capability and shared eligibility policy, and
records the attempt and its bounded capability in one SQLite writer transaction.
A run selector scans the persisted queue order for eligible work; blocked or
unknown entries do not prevent unrelated eligible work. Ambiguous or inconsistent
selectors fail without creating authority.

The host provider supplies a correlated, read-only workspace qualification for
the selected target. This is a trusted observation, not proof that SQLite and an
external workspace can change atomically. Physical Git isolation remains a
separate provider qualification.

The issued bearer is delivered once and only its digest is persisted. Its scope,
actor incarnation, run, assignment and attempt are exact; its actions cover
heartbeat, release and finish. Expiry is bounded by both the parent capability
and the lease. A replay returns the original command receipt through
`CapabilityDeliveryUncertainError`, rather than manufacturing a replacement
secret or a second attempt.

`resume` uses the persisted attempt and expected lease identity. Reconstructing a
service or restarting a process confers no new authority: actor incarnation,
capability validity, lease freshness and supplied selectors still have to match.
Heartbeat rotates the lease and renews its live attempt capability within all
ancestor expiry and revocation bounds. Higher delegation ancestors may belong
to a different actor; the direct parent and attempt capability identify the
attempt owner.

`finish` performs a guarded safe release. Clean, stopped work without outstanding
children releases the attempt and revokes its capability family, preserving the
original parent grant and existing outcome/evidence records. Dirty or uncertain
work remains quarantined or uncertain for explicit reconciliation. This operation
does not accept a candidate result or promote a work outcome; those decisions
require the separate verification and acceptance lifecycle.

Source tests cover atomic rollback after claim but before capability issuance,
secret non-persistence, selector conflicts, reconstructed and subprocess resume,
lease and capability rejection, delegated renewal and safe release. Temporary
provider fixtures establish policy behavior; they do not qualify physical cleanup.
