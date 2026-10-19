# External execution and resource permits

Todo accepts trusted provider instances through `ProviderComposition`. Providers
are selected by the host, not by a plan, message, or worker. An empty
composition remains sufficient for planning and authority reads; an operation
that requires an absent port fails with a typed unavailable error before it
changes authority state.

## Command checks

An accepted requirement can author a versioned `command` verification contract
with an argument vector, repository-relative working directory, timeout, and
allowed exit codes. `CommandExecutionVerifier` adapts that contract to
`CommandExecutionProvider` and invokes the existing V02 verification lifecycle.
The provider receives the exact attempt, selected workspace, source digest,
authority revision, tool ID, arguments, timeout, and operation/idempotency IDs.
It receives no shell command string. The host decides which provider identity
is trusted to interpret the tool ID and run the argv.

The command provider returns typed completion data and output digests. Raw
stdout/stderr are never part of the contract. An allowed exit code can produce
a passing verification observation; a disallowed code is a failed check and a
timeout is inconclusive. None of these outcomes accepts a work item. Evidence
still passes through normal V02 persistence and independent outcome acceptance.

The adapter does not execute processes. It delegates to the injected provider,
which may be a remote executor, a separately managed process service, or a
bounded test provider. V02 persists its intent before invoking the provider,
records the exact observation and provider identities, and uses read-only
inspection after an interruption. `inspect_effect` diagnoses the operation;
only an explicitly authorized recovery intent can reconcile or retry it. An
unknown or running operation never triggers blind replay.

## Resource permits

`ResourcePermitProvider` owns permit reservation, release, and read-only
inspection. `ProviderComposition.resource_permit_provider` and its explicit
identity are required to use the API. A permit binds an attempt, target,
resource class, unit count, derived scope, provider issuer, receipt, and expiry
bounded by the attempt lease. Todo stores a hashed permit ID in public views and
the opaque provider reference only in its private authority table.

The worker-facing `TodoSession` methods are:

- `reserve_resource(attempt, resource_class, units, idempotency_key=...)`
- `inspect_resource(operation)` for read-only provider inspection
- `reconcile_resource(operation, idempotency_key=...)` to persist a definitive
  inspection result
- `release_resource(operation, idempotency_key=...)`
- `retry_resource(operation, idempotency_key=...)` for an explicit same-request
  retry after definitive no-effect proof

Current capability scope and attempt ownership are checked for each action.
Dispatch gives a worker each optional resource action only when the parent
grant contains it. Resource retry also requires the reconcile action: it
re-inspects the original request and only retries a reserve proven `ABSENT` or
a release proven still `HELD`. The original operation, provider request,
attempt, and permit are reused, and the fresh inspection receipt is checked
again inside the authority writer before the provider effect begins.

`UNKNOWN`, unavailable inspection, a missing previously held permit, or an
ambiguous release keeps the durable external operation unresolved. Such an
operation blocks attempt release and outcome reporting/acceptance. A successful
release requires a correlated provider receipt or a definitive `RELEASED`
inspection. Expiry alone does not prove release. Todo records logical permits;
it does not manage physical capacity, GPU allocation, or hardware locks.

## Boundaries

Provider identities and typed receipts are trust inputs that the application
host must qualify. They are not signatures. Todo validates identity, exact
request digest, correlation, provenance, timestamps, attempt/lease binding,
and current authorization before applying state changes. Filesystem/process
supervision, resource scheduling, command implementation, provider discovery,
and Project Control integration are outside this adapter layer.

## Qualification evidence

The integrated isolated source suite passed **420/420 tests in 161.793s**
(`PYTHONPATH=src python -S -m unittest discover -s tests -p 'test_*.py' -v`).
The log is `/tmp/todo-orchestrator-i04-qualified-tests.log`. This includes 12
provider tests: authored command execution and interruption inspection, missing
provider isolation, exact request/receipt binding, permit reserve/release/retry,
stale receipt refusal, and unresolved-permit report/finish guards. Independent
review reproduced the stale-release bug before the timestamp checks were added.

The qualified source, tests, package metadata, skill, and references are captured
in `/tmp/todo-orchestrator-i04-qualified-source-manifest.json` (149 files;
aggregate SHA-256
`91a879def05ce93ed9f71bd4d2d0aabc340040f40065f0568d84398ef97fcb0d`).
The skill validator, whitespace checks, preserved original source fingerprints,
and derived-plan consistency check passed. These are temporary-authority and
trusted fake-provider tests; no real command executor or hardware resource
runtime is qualified. I04 was accepted at development revision 210 after owner-approved recovery
(revisions 205–206), which preserved all implementation files. The later
integrated qualification passed 427 tests; see the release evidence matrix.
