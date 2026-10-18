"""A small, explicit SQLite authority for one Todo Orchestrator project.

Opening a store never creates or migrates it. Initialization publishes a fully
created schema atomically, and migrations are an explicit operation. This
module owns SQLite connection and transaction mechanics only; semantic
commands, revision changes, receipts, and event payloads belong to later
authority services.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Iterator

from todo_orchestrator.contracts import Project


APPLICATION_ID = 0x544F444F  # ASCII "TODO"
SCHEMA_VERSION = 1
DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0
MAX_BUSY_TIMEOUT_SECONDS = 60.0


class AuthorityError(RuntimeError):
    """Base class for authority open and initialization errors."""


class AuthorityNotFoundError(AuthorityError, FileNotFoundError):
    """The requested authority file does not exist."""


class AuthorityAlreadyExistsError(AuthorityError, FileExistsError):
    """Initialization cannot replace an existing file."""


class AuthorityPublicationDurabilityUncertainError(AuthorityError):
    """The authority was published, but its directory entry could not be synced."""


class UnsupportedAuthorityPlatformError(AuthorityError):
    """This platform cannot provide the POSIX directory-sync initialization contract."""


class AuthorityIdentityMismatchError(AuthorityError):
    """The file belongs to a different project or authority identity."""


class UnsupportedSchemaVersionError(AuthorityError):
    """The file's schema version is not supported by this package."""


class InvalidAuthorityError(AuthorityError):
    """The file is not a valid Todo Orchestrator authority."""


class ReadOnlyAuthorityError(AuthorityError):
    """A write transaction was requested from a read-only connection."""


@dataclass(frozen=True)
class MigrationResult:
    """Result of the explicit migration check supported by this version."""

    from_version: int
    to_version: int


_SCHEMA_STATEMENTS = (
    """CREATE TABLE authority_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        project_id TEXT NOT NULL,
        authority_id TEXT NOT NULL,
        semantic_revision INTEGER NOT NULL DEFAULT 0 CHECK (semantic_revision >= 0),
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE plan_revisions (
        plan_revision_id TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
        based_on_revision_id TEXT,
        state TEXT NOT NULL CHECK (state IN ('proposed', 'validated', 'accepted')),
        source TEXT,
        content_digest TEXT,
        producer TEXT,
        authored_by_actor_id TEXT,
        authored_by_incarnation_id TEXT,
        CHECK ((authored_by_actor_id IS NULL) = (authored_by_incarnation_id IS NULL)),
        CHECK (content_digest IS NULL OR (length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*')),
        FOREIGN KEY (based_on_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (authored_by_actor_id, authored_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE work_items (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        title TEXT NOT NULL,
        outcome TEXT NOT NULL,
        parent_work_item_id TEXT,
        parent_definition_revision_id TEXT,
        PRIMARY KEY (work_item_id, definition_revision_id),
        CHECK ((parent_work_item_id IS NULL) = (parent_definition_revision_id IS NULL)),
        CHECK (parent_work_item_id IS NULL OR parent_work_item_id <> work_item_id
               OR parent_definition_revision_id <> definition_revision_id),
        FOREIGN KEY (definition_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (parent_work_item_id, parent_definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE plan_revision_work_items (
        plan_revision_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        PRIMARY KEY (plan_revision_id, work_item_id),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (work_item_id, plan_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE work_item_supersessions (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        superseded_work_item_id TEXT NOT NULL,
        superseded_definition_revision_id TEXT NOT NULL,
        PRIMARY KEY (work_item_id, definition_revision_id,
                     superseded_work_item_id, superseded_definition_revision_id),
        CHECK (work_item_id <> superseded_work_item_id
               OR definition_revision_id <> superseded_definition_revision_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (superseded_work_item_id, superseded_definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE requirements (
        requirement_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('prerequisite', 'check')),
        description TEXT NOT NULL,
        target_project_id TEXT,
        target_kind TEXT,
        target_entity_id TEXT,
        target_definition_revision_id TEXT,
        check_key TEXT,
        PRIMARY KEY (requirement_id, definition_revision_id),
        UNIQUE (work_item_id, definition_revision_id, requirement_id),
        CHECK (
            (kind = 'prerequisite' AND target_project_id IS NOT NULL
             AND target_kind IS NOT NULL AND target_entity_id IS NOT NULL
             AND check_key IS NULL AND target_kind IN ('work_item', 'checkpoint', 'interface', 'barrier', 'decision')
             AND ((target_kind = 'work_item' AND target_definition_revision_id IS NOT NULL)
                  OR (target_kind <> 'work_item' AND target_definition_revision_id IS NULL)))
            OR
            (kind = 'check' AND target_project_id IS NULL AND target_kind IS NULL AND target_entity_id IS NULL
             AND target_definition_revision_id IS NULL AND check_key IS NOT NULL)
        ),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE requirement_groups (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        group_ordinal INTEGER NOT NULL CHECK (group_ordinal >= 0),
        kind TEXT NOT NULL CHECK (kind IN ('prerequisite', 'check')),
        mode TEXT NOT NULL CHECK (mode IN ('all', 'any', 'quorum')),
        quorum INTEGER,
        PRIMARY KEY (work_item_id, definition_revision_id, group_ordinal),
        CHECK ((mode = 'quorum' AND quorum IS NOT NULL AND quorum > 0)
               OR (mode <> 'quorum' AND quorum IS NULL)),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE requirement_group_members (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        group_ordinal INTEGER NOT NULL,
        member_ordinal INTEGER NOT NULL CHECK (member_ordinal >= 0),
        requirement_id TEXT NOT NULL,
        PRIMARY KEY (work_item_id, definition_revision_id, group_ordinal, member_ordinal),
        UNIQUE (work_item_id, definition_revision_id, group_ordinal, requirement_id),
        FOREIGN KEY (work_item_id, definition_revision_id, group_ordinal)
            REFERENCES requirement_groups(work_item_id, definition_revision_id, group_ordinal),
        FOREIGN KEY (work_item_id, definition_revision_id, requirement_id)
            REFERENCES requirements(work_item_id, definition_revision_id, requirement_id)
    )""",
    """CREATE TABLE actors (
        actor_id TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('human', 'automation', 'service')),
        label TEXT,
        PRIMARY KEY (actor_id, incarnation_id)
    )""",
    """CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        plan_revision_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'retired')),
        created_by_actor_id TEXT,
        created_by_incarnation_id TEXT,
        CHECK ((created_by_actor_id IS NULL) = (created_by_incarnation_id IS NULL)),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (created_by_actor_id, created_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE assignments (
        assignment_id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        assignee_actor_id TEXT,
        assignee_incarnation_id TEXT,
        run_id TEXT,
        CHECK ((assignee_actor_id IS NULL) = (assignee_incarnation_id IS NULL)),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (assignee_actor_id, assignee_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )""",
    """CREATE TABLE attempts (
        attempt_id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN (
            'admitted', 'active', 'reported', 'accepted', 'rejected', 'released',
            'expired', 'uncertain', 'quarantined'
        )),
        assignment_id TEXT,
        run_id TEXT,
        lease_id TEXT,
        lease_expires_at TEXT,
        CHECK ((lease_id IS NULL) = (lease_expires_at IS NULL)),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (actor_id, actor_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )""",
    """CREATE TABLE capabilities (
        capability_id TEXT PRIMARY KEY,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        scope_kind TEXT NOT NULL CHECK (scope_kind IN (
            'project', 'plan_revision', 'work_item', 'requirement', 'run', 'assignment',
            'attempt', 'actor', 'capability', 'evidence', 'artifact', 'outcome',
            'external_operation', 'checkpoint', 'interface', 'barrier', 'decision'
        )),
        scope_entity_id TEXT NOT NULL,
        scope_definition_revision_id TEXT,
        scope_incarnation_id TEXT,
        run_id TEXT,
        assignment_id TEXT,
        attempt_id TEXT,
        expires_at TEXT,
        CHECK ((scope_kind IN ('work_item', 'requirement')) = (scope_definition_revision_id IS NOT NULL)),
        CHECK ((scope_kind = 'actor') = (scope_incarnation_id IS NOT NULL)),
        FOREIGN KEY (actor_id, actor_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id),
        FOREIGN KEY (assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TABLE capability_actions (
        capability_id TEXT NOT NULL,
        action_ordinal INTEGER NOT NULL CHECK (action_ordinal >= 0),
        action TEXT NOT NULL,
        PRIMARY KEY (capability_id, action_ordinal),
        UNIQUE (capability_id, action),
        FOREIGN KEY (capability_id) REFERENCES capabilities(capability_id)
    )""",
    """CREATE TABLE attempt_capabilities (
        attempt_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        PRIMARY KEY (attempt_id, capability_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (capability_id) REFERENCES capabilities(capability_id)
    )""",
    """CREATE TABLE artifacts (
        artifact_id TEXT PRIMARY KEY,
        provider_id TEXT NOT NULL,
        external_ref TEXT NOT NULL,
        content_digest TEXT,
        UNIQUE (provider_id, external_ref),
        CHECK (content_digest IS NULL OR (length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'))
    )""",
    """CREATE TABLE evidence (
        evidence_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        requirement_id TEXT,
        requirement_definition_revision_id TEXT,
        result TEXT NOT NULL CHECK (result IN ('pass', 'fail', 'inconclusive')),
        verifier_id TEXT NOT NULL,
        verifier_version TEXT NOT NULL,
        contract_digest TEXT NOT NULL CHECK (length(contract_digest) = 64 AND contract_digest NOT GLOB '*[^0-9a-f]*'),
        observed_at TEXT NOT NULL,
        CHECK ((requirement_id IS NULL) = (requirement_definition_revision_id IS NULL)),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (requirement_id, requirement_definition_revision_id)
            REFERENCES requirements(requirement_id, definition_revision_id)
    )""",
    """CREATE TABLE evidence_inputs (
        evidence_id TEXT NOT NULL,
        input_name TEXT NOT NULL,
        input_digest TEXT NOT NULL CHECK (length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*'),
        PRIMARY KEY (evidence_id, input_name),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
    )""",
    """CREATE TABLE evidence_artifacts (
        evidence_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        PRIMARY KEY (evidence_id, artifact_id),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
        FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
    )""",
    """CREATE TABLE outcomes (
        outcome_id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version > 0),
        disposition TEXT NOT NULL CHECK (disposition IN (
            'completed', 'accepted_negative', 'no_change', 'failed', 'superseded'
        )),
        accepted_by_actor_id TEXT NOT NULL,
        accepted_by_incarnation_id TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        attempt_id TEXT,
        UNIQUE (work_item_id, definition_revision_id, version),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (accepted_by_actor_id, accepted_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TABLE outcome_evidence (
        outcome_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        PRIMARY KEY (outcome_id, evidence_id),
        FOREIGN KEY (outcome_id) REFERENCES outcomes(outcome_id),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
    )""",
    """CREATE TABLE external_operations (
        operation_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
        state TEXT NOT NULL CHECK (state IN ('prepared', 'executing', 'observed', 'finalized', 'failed', 'unknown')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        attempt_id TEXT,
        external_ref TEXT,
        receipt_digest TEXT,
        CHECK (receipt_digest IS NULL OR (length(receipt_digest) = 64 AND receipt_digest NOT GLOB '*[^0-9a-f]*')),
        CHECK (state NOT IN ('observed', 'finalized') OR receipt_digest IS NOT NULL),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TABLE authority_events (
        event_id TEXT PRIMARY KEY,
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision > 0),
        event_ordinal INTEGER NOT NULL CHECK (event_ordinal >= 0),
        event_kind TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        UNIQUE (semantic_revision, event_ordinal)
    )""",
    """CREATE TABLE command_receipts (
        receipt_id TEXT PRIMARY KEY,
        command_kind TEXT NOT NULL,
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision >= 0),
        result_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE command_idempotency (
        idempotency_key TEXT PRIMARY KEY,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
        receipt_id TEXT NOT NULL UNIQUE,
        FOREIGN KEY (receipt_id) REFERENCES command_receipts(receipt_id)
    )""",
    """CREATE TRIGGER authority_events_no_update
        BEFORE UPDATE ON authority_events
        BEGIN SELECT RAISE(ABORT, 'authority events are append-only'); END""",
    """CREATE TRIGGER authority_events_no_delete
        BEFORE DELETE ON authority_events
        BEGIN SELECT RAISE(ABORT, 'authority events are append-only'); END""",
)


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE (type = 'index' AND name GLOB 'sqlite_autoindex_*') OR substr(name, 1, 7) <> 'sqlite_' "
        "ORDER BY type, name, tbl_name"
    ).fetchall()
    return tuple(tuple(row) for row in rows)


def _compile_schema_v1_signature() -> tuple[tuple[object, ...], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        return _schema_signature(connection)
    finally:
        connection.close()


# Schema v1 is frozen. Compare SQLite definitions with a signature compiled
# once from the trusted source DDL rather than validating table names alone.
_SCHEMA_V1_SIGNATURE = _compile_schema_v1_signature()

_REQUIRED_TABLES = frozenset({
    "authority_meta", "plan_revisions", "work_items", "plan_revision_work_items",
    "work_item_supersessions", "requirements", "requirement_groups", "requirement_group_members",
    "actors", "runs", "assignments", "attempts", "capabilities", "capability_actions",
    "attempt_capabilities", "artifacts", "evidence", "evidence_inputs", "evidence_artifacts",
    "outcomes", "outcome_evidence", "external_operations", "authority_events",
    "command_receipts", "command_idempotency",
})


def _project_identity(project: Project) -> tuple[str, str]:
    if not isinstance(project, Project):
        raise TypeError("project must be a contracts.Project")
    return str(project.project_id), str(project.authority_id)


def _path(path: str | os.PathLike[str]) -> Path:
    try:
        raw = Path(os.fspath(path)).expanduser()
    except TypeError as exc:
        raise TypeError("path must be path-like") from exc
    if raw.is_symlink():
        raise InvalidAuthorityError("authority path must not be a symbolic link")
    absolute = Path(os.path.abspath(raw))
    if not absolute.parent.is_dir():
        raise FileNotFoundError(f"authority parent directory does not exist: {absolute.parent}")
    return absolute


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("busy_timeout must be a number of seconds")
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= MAX_BUSY_TIMEOUT_SECONDS:
        raise ValueError(f"busy_timeout must be finite and between 0 and {MAX_BUSY_TIMEOUT_SECONDS} seconds")
    return result


def _sync_directory(path: Path) -> None:
    """Ask the POSIX filesystem to make a published directory entry durable."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _connect(path: Path, mode: str, timeout: float) -> sqlite3.Connection:
    uri = f"{path.as_uri()}?mode={mode}"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=timeout, isolation_level=None)
    except sqlite3.Error as exc:
        if mode == "ro" and not path.exists():
            raise AuthorityNotFoundError(f"authority does not exist: {path}") from exc
        raise InvalidAuthorityError(f"cannot open authority at {path}: {exc}") from exc
    connection.row_factory = sqlite3.Row
    return connection


def _pragma_int(connection: sqlite3.Connection, name: str) -> int:
    row = connection.execute(f"PRAGMA {name}").fetchone()
    if row is None or type(row[0]) is not int:
        raise InvalidAuthorityError(f"authority has no valid PRAGMA {name}")
    return row[0]


def _validate(connection: sqlite3.Connection, project: Project) -> None:
    expected_project_id, expected_authority_id = _project_identity(project)
    try:
        application_id = _pragma_int(connection, "application_id")
        schema_version = _pragma_int(connection, "user_version")
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"cannot read SQLite authority identity: {exc}") from exc

    if application_id != APPLICATION_ID:
        raise InvalidAuthorityError("SQLite file is not a Todo Orchestrator authority")
    if schema_version != SCHEMA_VERSION:
        raise UnsupportedSchemaVersionError(
            f"authority schema version {schema_version} is unsupported; this package supports {SCHEMA_VERSION}"
        )

    try:
        row = connection.execute(
            "SELECT project_id, authority_id, semantic_revision FROM authority_meta WHERE singleton = 1"
        ).fetchone()
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority metadata is unreadable: {exc}") from exc
    if row is None:
        raise InvalidAuthorityError("authority metadata row is missing")
    if row["project_id"] != expected_project_id or row["authority_id"] != expected_authority_id:
        raise AuthorityIdentityMismatchError("authority project or authority identity does not match the requested project")
    if type(row["semantic_revision"]) is not int or row["semantic_revision"] < 0:
        raise InvalidAuthorityError("authority semantic revision is invalid")

    try:
        if _schema_signature(connection) != _SCHEMA_V1_SIGNATURE:
            raise InvalidAuthorityError("authority schema does not match the frozen schema-v1 definition")
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority schema is unreadable: {exc}") from exc

    try:
        tables = frozenset(
            item[0]
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND substr(name, 1, 7) <> 'sqlite_'"
            )
        )
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority schema is unreadable: {exc}") from exc
    missing = _REQUIRED_TABLES - tables
    if missing:
        raise InvalidAuthorityError("authority schema is incomplete: " + ", ".join(sorted(missing)))
    try:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority journal mode is unreadable: {exc}") from exc
    if str(journal_mode).lower() != "wal":
        raise InvalidAuthorityError("authority is not using the required WAL journal mode")


def _configure(connection: sqlite3.Connection, *, readonly: bool, timeout: float) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
    if readonly:
        connection.execute("PRAGMA query_only = ON")
    # A new SQLite connection defaults to FULL. Do not issue a synchronous
    # write-affecting pragma here: it can wait behind another active writer.


class SQLiteAuthority:
    """One validated connection to one project-local authority.

    Connections are deliberately thread-confined by sqlite3. Open one writer
    connection per writer thread; SQLite serializes `BEGIN IMMEDIATE` writers
    while WAL readers retain a consistent snapshot.
    """

    def __init__(
        self,
        path: Path,
        project: Project,
        connection: sqlite3.Connection,
        *,
        readonly: bool,
    ) -> None:
        self.path = path
        self.project = project
        self.readonly = readonly
        self._connection = connection
        self._closed = False

    @classmethod
    def initialize(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> None:
        """Create a new schema-v1 authority without replacing an existing path.

        The database is built in a private same-directory temporary file and
        published with an atomic hard link, so readers see either no authority
        or a fully committed one. Only this explicit method creates a database.
        """

        if os.name != "posix":
            raise UnsupportedAuthorityPlatformError(
                "authority initialization requires POSIX directory fsync support"
            )
        project_id, authority_id = _project_identity(project)
        timeout = _timeout(busy_timeout)
        destination = _path(path)
        if destination.exists() or destination.is_symlink():
            raise AuthorityAlreadyExistsError(f"authority already exists: {destination}")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.init-", suffix=".sqlite3", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect(temporary, "rw", timeout)
            connection.execute("PRAGMA foreign_keys = ON")
            journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise InvalidAuthorityError("SQLite refused WAL journal mode during initialization")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            connection.execute(
                "INSERT INTO authority_meta(singleton, project_id, authority_id, semantic_revision, created_at) "
                "VALUES (1, ?, ?, 0, ?)",
                (project_id, authority_id, created_at),
            )
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.execute("COMMIT")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise InvalidAuthorityError(f"new authority failed integrity check: {integrity}")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or checkpoint[0] != 0:
                raise InvalidAuthorityError("new authority could not checkpoint its initialization WAL")
            connection.close()
            connection = None

            # The hard link is atomic and refuses to replace a concurrent winner.
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise AuthorityAlreadyExistsError(f"authority already exists: {destination}") from exc
            try:
                _sync_directory(destination.parent)
            except OSError as exc:
                raise AuthorityPublicationDurabilityUncertainError(
                    f"authority was published at {destination}, but syncing its parent directory failed; "
                    f"publication durability is uncertain: {exc}"
                ) from exc
        except BaseException:
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                connection.close()
            raise
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(str(temporary) + suffix).unlink()
                except FileNotFoundError:
                    pass

    @classmethod
    def open_reader(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> SQLiteAuthority:
        """Open an existing authority using SQLite `mode=ro` and `query_only`."""

        timeout = _timeout(busy_timeout)
        authority_path = _path(path)
        if not authority_path.exists():
            raise AuthorityNotFoundError(f"authority does not exist: {authority_path}")
        connection = _connect(authority_path, "ro", timeout)
        try:
            _validate(connection, project)
            _configure(connection, readonly=True, timeout=timeout)
        except BaseException:
            connection.close()
            raise
        return cls(authority_path, project, connection, readonly=True)

    @classmethod
    def open_writer(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> SQLiteAuthority:
        """Open an existing authority for explicit write transactions.

        A read-only preflight validates application, schema, and project
        identity before a read-write connection is opened. Metadata is checked
        again on the writer connection before any write-affecting PRAGMA.
        """

        timeout = _timeout(busy_timeout)
        authority_path = _path(path)
        if not authority_path.exists():
            raise AuthorityNotFoundError(f"authority does not exist: {authority_path}")
        preflight = _connect(authority_path, "ro", timeout)
        try:
            _validate(preflight, project)
        finally:
            preflight.close()

        connection = _connect(authority_path, "rw", timeout)
        try:
            _validate(connection, project)
            _configure(connection, readonly=False, timeout=timeout)
            try:
                synchronous = _pragma_int(connection, "synchronous")
            except sqlite3.Error as exc:
                raise InvalidAuthorityError(f"cannot read writer SQLite synchronous mode: {exc}") from exc
            if synchronous != 2:  # SQLite defines 2 as FULL.
                raise InvalidAuthorityError("writer SQLite connection is not using FULL synchronous durability")
        except BaseException:
            connection.close()
            raise
        return cls(authority_path, project, connection, readonly=False)

    @classmethod
    def migrate(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> MigrationResult:
        """Validate the current schema; no schema migration is implemented yet.

        Schema v1 is the only supported version. A current v1 authority is a
        no-op. Older or newer versions are rejected without opening the file
        writable; this method never guesses a conversion or restores a backup.
        """

        with cls.open_reader(path, project, busy_timeout=busy_timeout) as authority:
            version = _pragma_int(authority.connection, "user_version")
        return MigrationResult(version, version)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._closed:
            raise AuthorityError("authority connection is closed")
        return self._connection

    @contextmanager
    def read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Hold a consistent SQLite read snapshot for a group of queries."""

        connection = self.connection
        if connection.in_transaction:
            raise AuthorityError("nested authority transactions are not supported")
        connection.execute("BEGIN")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Acquire SQLite's single-writer reservation and roll back on failure."""

        if self.readonly:
            raise ReadOnlyAuthorityError("cannot write through a read-only authority connection")
        connection = self.connection
        if connection.in_transaction:
            raise AuthorityError("nested authority transactions are not supported")
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteAuthority:
        if self._closed:
            raise AuthorityError("authority connection is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


__all__ = [
    "APPLICATION_ID",
    "SCHEMA_VERSION",
    "DEFAULT_BUSY_TIMEOUT_SECONDS",
    "MAX_BUSY_TIMEOUT_SECONDS",
    "AuthorityAlreadyExistsError",
    "AuthorityError",
    "AuthorityIdentityMismatchError",
    "AuthorityNotFoundError",
    "InvalidAuthorityError",
    "MigrationResult",
    "ReadOnlyAuthorityError",
    "SQLiteAuthority",
    "UnsupportedAuthorityPlatformError",
    "UnsupportedSchemaVersionError",
]
