# Candidate reports and accepted outcomes

`OutcomeAcceptanceService` separates a worker's candidate report from a durable
accepted result. Reporting captures the exact attempt, proposed disposition and
observed source; it does not complete the work. A failed candidate can be safely
rejected and retried without creating a failed work outcome.

Accepting or rejecting a candidate requires separate scoped authority. A
dispatched worker may receive report rights only within its parent's action
ceiling; acceptance rights are not part of that worker session. Manual-owner
criteria additionally bind the selected approver's exact human incarnation and
trusted role action. A role label supplied by a caller grants nothing.

Acceptance checks the current accepted work definition, its requirement versions,
authored all/any/quorum groups and ungrouped checks. Evidence must bind the exact
contract, verifier, source and selected inputs, with the required named evidence
and identified artifacts. Relevant prerequisite and interface facts are checked
again. A stored passing result is historical evidence until its current
applicability is established.

Checkpoint, interface and synchronization declarations are intent. Producer
completion alone is not an accepted checkpoint or a barrier arrival. A
configured declaration observer supplies fresh, exact-version state receipts;
without one, those conditions remain unresolved.

Source and host observations carry expected identity and correlated provider
receipts. The writer checks current lease time and observation freshness after
acquiring the transaction, rather than trusting a timestamp collected before a
writer wait. External observations are not atomic filesystem locks: acceptance
records their identity and observation boundary, and refuses mismatches or stale
proof instead of asserting cross-system atomicity.

Finalization requires clean source, a stopped process and no outstanding child
activity. Dirty, live or uncertain ownership is preserved. A safe terminal
decision records its receipt and revokes the attempt's derived capability family
while preserving the original parent grant.

Accepted provenance retains exact requirements, evidence, source observations,
artifacts, dependencies and the accepting actor. Later source or contract changes
affect current applicability, not the immutable historical outcome. The read-only
applicability operation must distinguish that history from proof for current
inputs and must not repair or rewrite authority state.
External applicability observations require a current scoped read grant and use
its genuine capability reference in provider requests. Historical provenance
does not mint a new grant or revive a revoked worker session.

`no_change`, `evaluated_not_promoted` and `accepted_negative` are explicit
policy-controlled results. They do not excuse a failed required correctness
check. Process failure, an unavailable verifier and a valid negative evaluation
remain distinct observations.
