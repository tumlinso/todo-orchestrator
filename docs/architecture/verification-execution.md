# Durable verification execution

`VerificationService` uses injected source and verification providers with
explicit trusted identities. The service loads the exact accepted requirement
and persisted attempt workspace; a caller does not supply a replacement plan,
contract, source digest or provider implementation.

`execute` first authenticates the attempt owner and verification action, then
observes source inputs and commits a prepared intent. The stored operation binds
the attempt, work and requirement versions, accepted plan, normalized contract,
verifier version, source identity, named inputs and exact canonical request.
An executing transition commits before calling the verifier outside the SQLite
writer transaction. Only the caller that newly acquired that transition may
perform the effect; a replayed receipt is not permission to execute again.

The provider result is an observation, not an accepted work outcome. Its
identity, correlation, request digest, operation, contract, source, inputs and
named typed evidence must agree with the prepared operation. Definitive results
retain receipts and evidence provenance. A final source observation distinguishes
current evidence from historical evidence made stale by changed inputs.
Verification failure and provider failure have separate lifecycle meanings.

`reconcile` inspects an existing external operation. An unavailable, running or
ambiguous result does not authorize a second effect. A completed inspection
retains the original execution receipt as well as the inspection-query receipt.
Only a definitive not-started observation permits `retry_not_started`, which
requires explicit current authorization and reuses the original effect identity.
`read_operation` provides the persisted state without executing a provider.

Verification execution and reconciliation rights are distinct from outcome
acceptance. Dispatch may attenuate verification rights only when the presented
parent grant has them; lease renewal cannot expand that action ceiling. Pending
acceptance checks do not block claiming the attempt that will perform them.
Prerequisites, scope conflicts and the other shared admission rules still apply.

Source providers own how actual file and interface contents become identified
inputs, including relevant untracked content. A provider-shaped digest alone is
not physical source qualification. The engine tests use disposable authorities
and injected providers; real Git workspace/source qualification belongs to the
repository provider. Large output and binary artifacts remain external, with
identified references and digests retained in the authority.

This lifecycle records verification evidence. Final source applicability,
candidate acceptance and accepted outcome history are separate responsibilities.
