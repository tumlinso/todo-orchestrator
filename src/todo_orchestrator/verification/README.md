# Verification operations

`VerificationService` runs a typed check only for an authenticated, live attempt
and an exact check requirement in its accepted plan. Injected trusted source and
verification providers observe inputs and execute the authored contract. Provider
calls run outside the SQLite writer; an immutable operation and an `executing`
intent are committed before verification begins.

The authority stores the exact request, verifier identity, source and selected
input digests, provider receipts, typed evidence facts, and final source
observation. Recovery inspects an uncertain operation and never replays it
automatically. A provider must return the original verification receipt with a
completed inspection. `NOT_STARTED` permits a separate explicit authorized
retry. Stale-source evidence is retained as historical evidence. These records
do not accept or promote work outcomes. `OutcomeAcceptanceService` separately
reports candidates and accepts or rejects them under current scoped authority.
It rechecks source/artifact identity and declaration receipts at the guarded
writer boundary, records immutable outcome provenance and revokes the derived
attempt family only after safe finalization. Applicability reads require
`todo.outcome.read` and preserve historical acceptance when inputs later change.

`SourceObserver` is a trust boundary: its implementation must bind the exact
attempt workspace and authored contract, enumerate relevant tracked and
untracked content (including interface inputs), and provide content digests.
This package defines the receipt shape and validates its correlation, provider,
scope, freshness, and digest; it does not implement a Git or filesystem
observer, authenticate a receipt cryptographically, or qualify a live host.
