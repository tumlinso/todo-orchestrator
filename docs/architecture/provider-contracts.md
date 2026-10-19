# Provider contracts

`todo_orchestrator.contracts.providers` defines small, versioned Python contracts for facts and effects owned outside Todo's authority. Hosts inject provider instances; plans and other caller data never select import paths or executable providers. Providers own mechanisms and return observations. Todo alone checks grants, applies semantic transitions, and decides whether evidence or an outcome is accepted.

## Common envelope and trust boundary

`ProviderIdentity` identifies an implementation and its version. Each call returns a `ProviderResult` correlated to the request. A definitive observation includes a `ProviderReceipt` with provider identity, request digest, provenance reference, and observation time. The outer status describes whether the provider produced a definitive result; an inner value can still report a negative domain result such as a conflict, nonzero exit code, or failed verification:

| Status | Required fields | Meaning |
|---|---|---|
| `OBSERVED_SUCCESS` | provider, value, receipt | A definitive observation was returned. It does not mean the requested work passed. |
| `OBSERVED_FAILURE` | provider, reason, receipt; value optional | A definitive provider failure was observed. Optional value is diagnostic detail. |
| `UNKNOWN` | provider, reason; receipt optional | The call or external effect may have happened, but its result is not established. Reconcile by observation; do not assume failure or replay blindly. |
| `UNAVAILABLE` | reason; provider optional | No result was obtained because the provider could not be used. No observation or effect receipt is asserted. |

Receipts and references are provider-supplied data, not signatures or proof of authenticity. The contracts validate local shapes and correlation fields, not provider identity, request digests, receipt provenance, expiry, freshness, rights, or cross-record existence. The host must authenticate trusted providers, canonicalize and hash the exact request, compare returned correlation/provider/version and request bindings, verify provenance as required, and recheck source and authority revisions at the semantic commit. External effects cannot be made atomic with Todo's transaction.

Effectful ports also expose read-only `inspect` methods using `EffectInspectionRequest`. Its `context` is the current, separately authorized recovery/read context; it need not be the original actor's possibly expired or revoked capability. `operation_id`, `idempotency_key`, and `original_request_digest` bind the exact original call (including its original context); `correlation_id` identifies this inspection query. The response envelope correlates to the query, while its value identifies the original operation. Inspection must not repeat the effect. A provider may report `NOT_STARTED` or `ABSENT` only when its lookup and retention guarantees establish that conclusion; an incomplete index, expired receipt, or uncertain live process/permit remains `UNKNOWN`. Todo decides whether any later retry is authorized; a generic `UNKNOWN` never makes replay safe.

`TrustedContextProvider` resolves a host context reference into a project-scoped actor incarnation, scope, expiry, and host action ceiling. The host must authenticate that assertion and the service must check freshness and map the ceiling through Todo policy. `ProviderCallContext` is built by the service after authorization; its `capability` is an opaque reference to a Todo grant, not a self-validating token. Providers must not infer rights from role labels or these dataclasses alone.

## Contracts

- `SourceObserver` reports repository identity, source/base digests, named content/interface inputs, and clean/dirty working-tree state. Requests can bind an exact attempt/workspace/target and an optional authored verification contract, or use a base-only request that names one exact configured repository ref before an attempt or workspace exists. Base-only observations return the resolved commit and policy-qualified tree digest, with the exact ref as receipt provenance; they do not create or inspect a workspace. Exact artifact expectations require fresh availability and digest observations under the same correlated receipt. The service compares the result with expected source and persisted workspace scope.
- `DeclarationObserver` reports accepted checkpoint, published interface, barrier or rendezvous state for an exact plan/declaration payload. Requests and observations bind the target, kind, payload digest, optional interface version and provider receipt. Missing observations remain unresolved; declarations and completed producers do not prove publication or arrival.
- `GitEffectsProvider` receives an operation and idempotency identity, expected source and authority revision, and optional workspace reference. Its disposition reports applied, conflict, dirty, or rejected effects; `OBSERVED_SUCCESS` means the disposition is known, not that it was applied. Unknown effects require reconciliation and preservation of conflicting or dirty work.
- `GitEffectsProvider.inspect` resolves a prior effect to its observed disposition, including `NOT_APPLIED` only when absence is definitive.
- `CommandExecutionProvider` receives an attempt-bound tool ID, argument vector, timeout, expected source/revision, and idempotency identity. It does not accept a shell command string. Exit code and output digests are observations only: they cannot accept requirements or outcomes. Its inspection distinguishes `RUNNING`, `COMPLETED`, and proven `NOT_STARTED`; a running result carries no fabricated exit code or completion time. A timeout or lookup without known process state remains `UNKNOWN`.
- `ResourcePermitProvider` reserves and releases externally owned permits. Inspection reports a held, absent, or released permit for the original operation; it never reserves or releases. Todo may keep a correlated logical reference and expiry, but this API is not a physical lock ledger and grants no GPU, CPU, memory, or job capacity by itself.
- `VerificationProvider` returns a verdict bound to the requested requirement, source, contract digest, inputs, verifier identity, and artifacts. Its inspection distinguishes running, completed, and proven not-started work without starting verification again. Todo still checks current applicability, required checks, authorization, and acceptance transactionally; a `PASS` is not an accepted outcome.

Provider contract version 2 adds typed benchmark sample values, units and sample
counts alongside their evidence digests. An explicit allowed negative evaluation
can retain a definitive benchmark miss; failed command execution and
inconclusive/provider failures do not become passing checks.

Provider contract version 5 added source observations that retain an
exact source revision. Git requests bind the target, attempt, scheduling context
and accepted outcome/source provenance. Git inspection receipts bind the current
inspection query; an existing original execution receipt is carried separately
in the observation and must retain its original identity. If no execution
receipt was durably recorded, inspection does not invent one. See
[local Git effects](git-effects.md) for the implemented provider and service.

Provider contract version 7 allowed source observations for an exact workspace
and target before an attempt is attached. Provider contract version 8 added
base-ref-only source observations. A base-ref-only source observation can establish the current qualified
commit and tree for a pre-effect recovery preview; its request digest includes
the ref, and its receipt is correlated to that query. It is a read-only
observation, not a durable effect receipt or a guarantee that the ref cannot
move afterward. Declaration observation requests
carry the actual caller's read or accept action alongside its actor and
capability. The native observer checks current scope, context, expiry and
revocation, allowing an independent authorized approver without borrowing the
worker's grant. An omitted authorization action yields unknown native status.

Provider contract version 9 binds command checks to their selected workspace,
repository-relative working directory, and expected authority revision. It
also carries the exact original typed verification or resource-permit request
inside provider inspection queries. Resource reservation requests can bind the
current attempt lease and authority revision; inspection remains read-only.
Command completion contains only exit/timing fields and stdout/stderr digests,
not output text. See [external execution and resource permits](external-providers.md)
for the adapter and public service behavior.

The contracts use `PROVIDER_CONTRACT_VERSION` for this interface and carry provider-specific versions in identities and receipts. A host decides which versions it trusts. `SourceObservationRequest` supports an attempt plus exact workspace/target, an unattached exact workspace/target, or a base-only exact ref; these forms cannot be mixed. A workspace is never accepted without its target. Provider instances are optional: abstract planning and other operations that need no external observation/effect remain usable when a provider is absent. An operation that requires an unavailable provider returns a typed `UNAVAILABLE` result. These contracts add no Project Control adapter, discovery registry, process/Git implementation, network runner, or hardware authority.
