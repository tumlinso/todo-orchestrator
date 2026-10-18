# SQLite authority v12

Each project owns one SQLite file. The file contains a single `authority_meta`
identity row with the project ID, authority ID, semantic revision, and creation
time. SQLite's `application_id` identifies Todo Orchestrator files and
`user_version` identifies the schema version. Semantic revision belongs to
`authority_meta`; `user_version` is schema metadata only.

Schema v12 uses frozen DDL. Each open compares the full application schema
signature against the signature compiled in memory from the trusted v12
statements. This checks table definitions (including columns, keys, foreign
keys, checks, and uniqueness), generated and named indexes, and append-only
triggers; missing, altered, or extra application objects are rejected. V1 has
no schema normalizer or compatibility aliases: any DDL change requires an
explicit new schema version and supported migration.

The schema separates immutable plan and work definitions from runs,
assignments, actor incarnations, attempts, capabilities, evidence, artifacts,
accepted outcomes, and external operation intents. A work item's lifecycle is
not copied into another status column. Attempt, run, and plan states are stored
only on their owning rows. `authority_events` records committed semantic
changes; it is an immutable history stream, not a replay log. Event payloads
identify the change and its subject rather than duplicating full entity rows.
Command receipts and idempotency bindings are separately append-only records.

Prerequisite rows preserve the full qualified target identity, including the
referenced project ID, kind, entity ID, and definition revision where required.
The storage layer does not adopt or authorize cross-project references; a later
compiler or command layer must validate those policies. Attempt workspace
qualifications retain the provider, repository, exact common base and
destination, and provider receipt. A separate immutable scope snapshot records
the attempt's repository-relative paths and named locks at claim time, so
admission after restart does not reconstruct current ownership from a newly
supplied plan. Both are immutable provenance, not proof of host trust. A
partial unique index permits at most one admitted,
active, or reported attempt for each exact work-item definition.

An accepted plan has one immutable canonical snapshot bound by SHA-256 to its
plan row. The snapshot stores the complete effective authored plan, including
declarations, dependencies, provenance, adoption facts, and exact mixed
definition references. `work_items` is the immutable version registry keyed by
`(work_item_id, definition_revision_id)` and stores each complete canonical
definition bundle. `plan_revision_work_items` selects the exact version for
each work item, so a later plan can retain unchanged definitions while adding
newly revised ones. Requirements are owned by their work-definition version;
the normalized rows are checked against the canonical bundle on snapshot load.
Reusing an exact definition reference requires identical bundle bytes, digest,
and normalized projections. Snapshot, membership, and definition corruption
fails closed; the reader does not repair or infer missing authority state.

`SQLiteAuthority.initialize()` is the only creation path. It builds schema v13
in a private same-directory temporary database, commits and checks it, then
publishes it atomically without replacing an existing path. After publication,
it syncs the parent directory on POSIX systems. If that sync fails, it raises
`AuthorityPublicationDurabilityUncertainError` and leaves the published file
intact; inspect that file before retrying initialization. A failed build before
publication removes its temporary database and WAL sidecars. Initialization
never adopts an existing empty, foreign, or partially initialized file.
Initialization is available only on POSIX because publication durability relies
on syncing the containing directory; unsupported platforms are rejected before
a temporary database is created.

Durability depends on the filesystem and storage stack honoring SQLite's sync
requests and the POSIX directory sync. This foundation has fixture-level checks,
not power-loss or boot durability qualification.

`open_reader()` uses SQLite `mode=ro`, validates application/schema/project
identity, and enables `query_only`. `open_writer()` first performs the same
validation through a read-only connection, then opens `mode=rw` and checks the
identity again before connection pragmas. Neither open path creates, restores,
or migrates a missing or unsupported authority. Writers use finite busy
timeouts, full synchronous durability, and `BEGIN IMMEDIATE`; SQLite serializes
competing writers while WAL readers retain stable snapshots.
Each writer connection verifies that SQLite reports `synchronous=FULL` and
fails closed if that setting is not active; opening a writer does not change it.

Schema v12 is the only implemented version. `migrate()` is an explicit current
version no-op and rejects schema v1 through v11 or any other unsupported version
without writable access. Earlier disposable fixtures are unsupported and must
be recreated; no v1-v11 migration is provided. A future migration must preserve
definition identity and full accepted-snapshot meaning; it cannot infer mixed
membership from matching revision IDs.

Schema v8 introduced immutable run-schedule snapshots, lane policies, and queue
positions attached to immutable assignments. A schedule can omit lane
hierarchy, in which case one serial `default` lane is persisted. Role
constraints are required action IDs on the same capability that grants a
claim; actor labels do not satisfy them. `shared_scopes` always uses the common
source-scope admission rules, and `qualified_workspaces` adds a requirement for
distinct provider-qualified workspaces with matching common base and
destination. Lane and queue policy never bypass capability, assignment, or
shared admission checks. Direct assignment-free claims remain available for
work that is not scheduled in a run.
Schema v9 introduced typed verification/evidence contracts to requirement projections
and the distinct `evaluated_not_promoted` outcome disposition. Their exact
canonical forms remain bound to the immutable accepted definition bundle.
Schema v10 adds durable verification operations, source and receipt provenance,
and named typed evidence facts. These records do not accept work outcomes.
Schemas v11 and v12 add candidate reports, immutable accepted outcome provenance
and typed benchmark measurement payloads. They preserve the distinction between
verification observations, candidate reports and separately authorized outcomes.
For a future supported migration, first validate the source identity/version
read-only, create a non-overwriting adjacent backup with SQLite's online backup
API, and apply the versioned DDL in one transaction with the version marker
updated last. On failure, roll back and retain the backup for inspection;
never restore it automatically. Backup retention and deletion require a
separate explicit maintenance action.

`EligibilityAdapter.evaluate_read()` evaluates an advisory decision from one
read-only SQLite snapshot; `evaluate_in_transaction()` re-reads authority
facts under the active writer transaction and checks the caller's observed
semantic revision before returning. Both use the same pure policy, and the
transactional form does not reserve work or mutate state. Capability expiry
uses the adapter's injected clock, not caller-supplied time. Provider workspace
qualifications, condition observations, candidate scope contexts, and participant
approvals are trusted adapter inputs; active attempt scopes come from immutable
claim snapshots in this authority. This layer does not authenticate external
observation sources. A later trust boundary must bind those observations and the actor to the
actual caller and operation. Unknown or inconsistent current facts fail closed
as `UNKNOWN` or `BLOCKED`, with typed causes and the observed authority
revision.

`CommandDispatcher` executes trusted typed handlers inside one writer
transaction. A changed command advances the semantic revision once and stores
one event, receipt, and idempotency binding atomically. A no-op stores a receipt
and binding without advancing the revision or adding an event. Exact retries
return the durable original receipt, while reusing the key for a different
request or submitting a distinct stale request is rejected without churn.
Actors are registered by identity and incarnation to preserve provenance;
these values do not authenticate or authorize callers.

Handlers receive `MutationContext`, which runs one bound SQL statement at a
time and blocks transaction controls, PRAGMAs, schema changes, and writes to
dispatcher-owned metadata, events, receipts, or idempotency records. Handlers
are trusted engine code and must report a semantic change honestly. Any handler
exception or mismatch between affected semantic rows and its declared effect
rolls the whole command back.

`CommandDispatcher.history()` and `delta()` read immutable events in semantic
revision order. `logical_fingerprint()` hashes normalized domain rows and
authority identity/revision, excluding receipts, event storage, and SQLite/WAL
page layout. It is a comparison aid, not a content-authentication mechanism.

`AuthorityAuthService` is the public local authentication boundary. The first
owner is enrolled once through an atomic, revisioned bootstrap command; the
process that can write the unowned authority is the bootstrap trust boundary.
The credential is stored as a salted scrypt digest. Owner login authenticates
that credential, creates a fresh actor incarnation, and issues an explicitly
scoped capability. Optional child identities come only from an injected
`PrincipalAuthenticator` trusted by the service composition; callers submit
credentials and never supply an `Actor` or a role label as proof.

Capabilities store only SHA-256 digests of random 256-bit bearer tokens.
`IssuedCapability` returns the plaintext bearer once alongside its durable
receipt; a replayed issuance raises `CapabilityDeliveryUncertainError` because
the plaintext is intentionally absent from events, receipts, idempotency data,
and storage. Delegated grants are restricted to the parent scope, action set,
context, and expiry, and record parent lineage. Family revocation updates the
grant and all descendants in one authority transaction. Authenticated command
checks read current token, revocation, expiry, actor incarnation, action,
scope, and context inside the writer transaction before idempotency replay.
The raw `CommandDispatcher.execute()` entry point is trusted internal code and
does not authenticate clients; the Python service boundary does not protect
against hostile code already running inside the trusted engine process.
Exact retries must retain the original `expected_revision`; omitting it reads
the latest revision and makes a later call a different idempotency request.

`AttemptService` registers authenticated `todo.attempt.claim`,
`todo.attempt.heartbeat`, `todo.attempt.release`, and
`todo.attempt.reconcile_expired` commands on the supplied dispatcher. Claims
re-evaluate the shared eligibility policy and write the attempt, initial lease,
immutable workspace qualification, and immutable scope snapshot in one
revisioned transaction. The live
attempt index is a database guard in addition to that policy check. Heartbeats
re-evaluate eligibility under the same writer lock and rotate the fencing lease
ID. Release and expiry reconciliation inspect the host outside the writer
transaction, then compare the observation's attempt state, lease ID, expiry,
and exact persisted workspace under the lock. A changed snapshot is rejected.
Dirty sources, live processes, or active children are quarantined; missing or
uncertain evidence remains uncertain. Expiry never removes files, kills
processes, or automatically releases ownership. Releasing a reconciled attempt
requires a separate fresh clean/stopped/no-children observation.

The host provider and injected clock are trusted composition inputs. Stored
provider receipts preserve provenance but are not cryptographic attestations,
and this service does not prove that a provider is trustworthy or that the
filesystem honors a particular isolation mechanism. Exact retries still pass
through current authentication and return the original durable command receipt
without requiring a new provider observation.
