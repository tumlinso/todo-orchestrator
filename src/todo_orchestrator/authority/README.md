# SQLite authority v1

Each project owns one SQLite file. The file contains a single `authority_meta`
identity row with the project ID, authority ID, semantic revision, and creation
time. SQLite's `application_id` identifies Todo Orchestrator files and
`user_version` identifies the schema version. Semantic revision belongs to
`authority_meta`; `user_version` is schema metadata only.

Schema v1 uses frozen DDL. Each open compares the full application schema
signature against the signature compiled in memory from the trusted v1
statements. This checks table definitions (including columns, keys, foreign
keys, checks, and uniqueness), generated and named indexes, and append-only
triggers; missing, altered, or extra application objects are rejected. V1 has
no schema normalizer or compatibility aliases: any DDL change requires an
explicit new schema version and supported migration.

The schema separates immutable plan and work definitions from runs,
assignments, actor incarnations, attempts, capabilities, evidence, artifacts,
accepted outcomes, and external operation intents. A work item's lifecycle is
not copied into another status column. Attempt, run, and plan states are stored
only on their owning rows. Event and command receipt tables are empty schema
foundations for later command work; SQLite rows remain authoritative and events
are not a replay log. Event payloads should identify the change and its subject,
not duplicate full entity rows.

Prerequisite rows preserve the full qualified target identity, including the
referenced project ID, kind, entity ID, and definition revision where required.
The storage layer does not adopt or authorize cross-project references; a later
compiler or command layer must validate those policies.

`SQLiteAuthority.initialize()` is the only creation path. It builds schema v1
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

Schema v1 is the only implemented version. `migrate()` is an explicit current
version no-op and rejects every unsupported version without writable access.
For a future supported migration, first validate the source identity/version
read-only, create a non-overwriting adjacent backup with SQLite's online backup
API, and apply the versioned DDL in one transaction with the version marker
updated last. On failure, roll back and retain the backup for inspection;
never restore it automatically. Backup retention and deletion require a
separate explicit maintenance action.

Domain command execution, semantic revision changes, receipts, idempotency,
and event insertion are outside this storage foundation and belong to TO-A02.
