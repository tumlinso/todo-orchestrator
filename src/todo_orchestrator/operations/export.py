"""Authenticated read-only authority exports and explicit private backups."""

from __future__ import annotations

import base64
import hashlib
from html import escape as html_escape
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Mapping

from todo_orchestrator.authority.auth import (
    AuthenticationFailedError,
    AuthorizationRequirement,
    AuthorityAuthService,
    _token_digest,
)
from todo_orchestrator.authority.commands import (
    _FINGERPRINT_TABLES,
    _fingerprint_value,
    _json_value,
)
from todo_orchestrator.authority.sqlite import (
    SCHEMA_VERSION,
    AuthorityError,
    AuthorityIdentityMismatchError,
    AuthorityNotFoundError,
    AuthorityPublicationDurabilityUncertainError,
    InvalidAuthorityError,
    SQLiteAuthority,
    UnsupportedAuthorityPlatformError,
    UnsupportedSchemaVersionError,
    _path,
    _sync_directory,
)
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, Sha256Digest, StableId
from todo_orchestrator.views.export import (
    AUTHORITY_BACKUP_FORMAT,
    AUTHORITY_READ_MODEL_FORMAT,
    AuthorityBackupManifest,
    AuthorityBackupResult,
    AuthorityReadModelV1,
)


AUTHORITY_READ_ACTION = StableId("todo.authority.read")
AUTHORITY_BACKUP_ACTION = StableId("todo.authority.backup")
_READ_MODEL_SECTIONS: tuple[tuple[str, str], ...] = (
    ("plan_revisions", "SELECT p.plan_revision_id, p.sequence, p.based_on_revision_id, p.state, "
     "p.content_digest, s.snapshot_digest FROM plan_revisions AS p "
     "LEFT JOIN plan_revision_snapshots AS s USING (plan_revision_id) "
     "ORDER BY p.sequence, p.plan_revision_id"),
    ("plan_membership", "SELECT plan_revision_id, work_item_id, definition_revision_id "
     "FROM plan_revision_work_items ORDER BY plan_revision_id, work_item_id"),
    ("work_definitions", "SELECT work_item_id, definition_revision_id, title, outcome, "
     "json_extract(canonical_json, '$.work.objective') AS objective, "
     "json_extract(canonical_json, '$.work.motivation') AS motivation, content_digest, "
     "parent_work_item_id, parent_definition_revision_id FROM work_items "
     "ORDER BY work_item_id, definition_revision_id"),
    ("requirements", "SELECT requirement_id, definition_revision_id, work_item_id, kind, description, check_key, "
     "target_project_id, target_kind, target_entity_id, target_definition_revision_id "
     "FROM requirements ORDER BY work_item_id, definition_revision_id, requirement_id"),
    ("declaration_facts", "SELECT fact_sequence, fact_id, plan_revision_id, declaration_kind, "
     "declaration_id, declaration_digest, fact_kind, participant_project_id, participant_kind, "
     "participant_entity_id, participant_definition_revision_id, participant_incarnation_id, payload_json, "
     "semantic_revision, actor_id, actor_incarnation_id, occurred_at "
     "FROM declaration_facts ORDER BY fact_sequence"),
    ("runs", "SELECT run_id, plan_revision_id, state, created_by_actor_id, "
     "created_by_incarnation_id FROM runs ORDER BY run_id"),
    ("run_lanes", "SELECT run_id, lane_id, lane_ordinal, queue_policy, required_role, isolation_policy "
     "FROM run_lanes ORDER BY run_id, lane_ordinal"),
    ("assignments", "SELECT assignment_id, work_item_id, definition_revision_id, "
     "assignee_actor_id, assignee_incarnation_id, run_id FROM assignments ORDER BY assignment_id"),
    ("run_queue", "SELECT run_id, lane_id, assignment_id, queue_position "
     "FROM run_queue ORDER BY run_id, lane_id, queue_position"),
    ("attempts", "SELECT attempt_id, work_item_id, definition_revision_id, actor_id, actor_incarnation_id, "
     "state, assignment_id, run_id, lease_id, lease_expires_at FROM attempts ORDER BY attempt_id"),
    ("workspace_qualifications", "SELECT attempt_id, workspace_id, repository_id, base_project_id, "
     "base_ref, base_digest, destination_project_id, destination_ref, provider_id, provider_version, "
     "provider_contract_version, receipt_id, correlation_id, request_digest, observed_at, isolation_digest "
     "FROM attempt_workspace_qualifications ORDER BY attempt_id"),
    ("child_executions", "SELECT execution_id, parent_attempt_id, logical_id, ordinal, retry_of_execution_id, "
     "work_item_id, definition_revision_id, child_actor_id, child_incarnation_id, capability_id, "
     "scope_digest, actions_digest, state, created_at, updated_at FROM child_executions ORDER BY execution_id"),
    ("child_candidates", "SELECT candidate_id, execution_id, submitted_by_actor_id, "
     "submitted_by_incarnation_id, submitted_at FROM child_candidates ORDER BY candidate_id"),
    ("artifacts", "SELECT artifact_id, provider_id, content_digest FROM artifacts ORDER BY artifact_id"),
    ("evidence", "SELECT evidence_id, attempt_id, requirement_id, requirement_definition_revision_id, "
     "operation_id, result, verifier_id, verifier_version, contract_digest, source_digest, observed_at "
     "FROM evidence ORDER BY evidence_id"),
    ("evidence_inputs", "SELECT evidence_id, input_name, input_digest FROM evidence_inputs "
     "ORDER BY evidence_id, input_name"),
    ("evidence_artifacts", "SELECT evidence_id, artifact_id FROM evidence_artifacts "
     "ORDER BY evidence_id, artifact_id"),
    ("evidence_facts", "SELECT evidence_id, fact_kind, fact_version, fact_digest, artifact_id "
     "FROM evidence_facts ORDER BY evidence_id, fact_kind, fact_version, fact_digest"),
    ("outcomes", "SELECT outcome_id, work_item_id, definition_revision_id, version, disposition, "
     "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at, attempt_id "
     "FROM outcomes ORDER BY work_item_id, definition_revision_id, version"),
    ("outcome_evidence", "SELECT outcome_id, evidence_id FROM outcome_evidence ORDER BY outcome_id, evidence_id"),
    ("outcome_candidates", "SELECT candidate_id, attempt_id, work_item_id, definition_revision_id, "
     "disposition, reported_by_actor_id, reported_by_incarnation_id, reported_at, state, outcome_id "
     "FROM outcome_candidates ORDER BY candidate_id"),
    ("outcome_provenance", "SELECT outcome_id, candidate_id, content_digest FROM outcome_provenance "
     "ORDER BY outcome_id"),
    ("external_operations", "SELECT operation_id, kind, request_digest, state, created_at, updated_at, "
     "attempt_id, receipt_digest FROM external_operations ORDER BY operation_id"),
    ("git_effect_operations", "SELECT operation_id, request_digest, state, updated_at "
     "FROM git_effect_operations ORDER BY operation_id"),
    ("verification_attempts", "SELECT operation_id, attempt_id, work_item_id, definition_revision_id, "
     "requirement_id, requirement_definition_revision_id, plan_revision_id, verifier_id, verifier_version, "
     "contract_digest, source_digest, request_digest, state, evidence_id, "
     "created_at, updated_at, finalized_at FROM verification_attempts ORDER BY operation_id"),
    ("authority_history", "SELECT event_id, semantic_revision, event_ordinal, event_kind, occurred_at, "
     "actor_id, actor_incarnation_id FROM authority_events "
     "ORDER BY semantic_revision, event_ordinal, event_id"),
)


class AuthorityExportError(AuthorityError):
    """Base error for authority export and backup operations."""


class UnsafePublicProjectionError(AuthorityExportError):
    """A projected scalar exactly collides with a known authentication value."""


class StaleExportRevisionError(AuthorityExportError):
    """The authority revision differs from the explicitly requested revision."""


class AuthorityBackupError(AuthorityError):
    """Base error for explicit backup restoration failures."""


class BackupIntegrityError(AuthorityBackupError):
    """A backup hash, SQLite integrity, foreign key, or semantic fingerprint failed."""


class BackupIdentityMismatchError(AuthorityBackupError):
    """The backup does not match the exact requested project and authority IDs."""


class BackupRevisionMismatchError(AuthorityBackupError):
    """The backup revision does not match the exact requested revision."""


class BackupSchemaVersionError(AuthorityBackupError):
    """The backup schema version is not supported by this engine version."""


class BackupDestinationExistsError(AuthorityBackupError):
    """Restore or backup refuses to replace any existing destination."""


def _logical_fingerprint(connection: sqlite3.Connection) -> str:
    meta = connection.execute(
        "SELECT project_id, authority_id, semantic_revision FROM authority_meta WHERE singleton = 1"
    ).fetchone()
    if meta is None:
        raise BackupIntegrityError("authority metadata is missing")
    tables: list[dict[str, object]] = []
    try:
        for table in _FINGERPRINT_TABLES:
            columns = [row["name"] for row in connection.execute(f'PRAGMA table_info("{table}")')]
            if not columns:
                raise BackupIntegrityError("authority schema is missing a required semantic table")
            quoted = ", ".join('"' + name.replace('"', '""') + '"' for name in columns)
            rows = connection.execute(f'SELECT {quoted} FROM "{table}" ORDER BY {quoted}').fetchall()
            tables.append({
                "name": table,
                "columns": columns,
                "rows": [[_fingerprint_value(value) for value in tuple(row)] for row in rows],
            })
    except sqlite3.Error as exc:
        raise BackupIntegrityError("cannot read authority semantic rows") from exc
    state = {
        "schema_version": SCHEMA_VERSION,
        "project_id": meta["project_id"],
        "authority_id": meta["authority_id"],
        "semantic_revision": meta["semantic_revision"],
        "tables": tables,
    }
    encoded = json.dumps(_json_value(state, "logical state"), ensure_ascii=True, allow_nan=False,
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _read_sections(connection: sqlite3.Connection) -> Mapping[str, tuple[Mapping[str, object], ...]]:
    sections: dict[str, tuple[Mapping[str, object], ...]] = {}
    for name, query in _READ_MODEL_SECTIONS:
        rows: list[Mapping[str, object]] = []
        for row in connection.execute(query):
            record: dict[str, object] = {}
            for key in row.keys():
                value = row[key]
                if isinstance(value, (bytes, bytearray)):
                    raise AuthorityExportError("public projection encountered an unsupported binary value")
                if isinstance(value, float) and not value.is_integer():
                    value = str(value)
                record[key] = value
            rows.append(record)
        sections[name] = tuple(rows)
    return sections


def _json_string_scalars(value: object):
    """Yield exact strings embedded in JSON-valued public fields."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _json_string_scalars(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _json_string_scalars(item)


def _reject_authentication_collisions(
    connection: sqlite3.Connection,
    sections: Mapping[str, tuple[Mapping[str, object], ...]],
) -> None:
    """Fail closed if a public scalar is itself a known auth secret/hash.

    This exact-value guard protects structural identities and JSON-encoded
    declaration fields that could otherwise serialize an issued bearer. It is
    not a scanner for arbitrary authored prose or unknown credentials.
    """
    issued_digests = frozenset(
        row[0] for row in connection.execute("SELECT token_digest FROM capability_tokens")
    )
    exact_auth_values = set(issued_digests)
    owner = connection.execute(
        "SELECT salt, password_digest FROM local_owner_credentials WHERE singleton = 1"
    ).fetchone()
    if owner is not None:
        for raw in (bytes(owner["salt"]), bytes(owner["password_digest"])):
            exact_auth_values.add(raw.hex())
            exact_auth_values.add(base64.b64encode(raw).decode("ascii"))
            exact_auth_values.add(base64.urlsafe_b64encode(raw).decode("ascii"))
            try:
                exact_auth_values.add(raw.decode("ascii"))
            except UnicodeDecodeError:
                pass
    for rows in sections.values():
        for row in rows:
            values: list[str] = []
            for key, value in row.items():
                if isinstance(value, str):
                    values.append(value)
                    if key.endswith("_json"):
                        try:
                            parsed = json.loads(value)
                        except (TypeError, ValueError):
                            continue
                        values.extend(_json_string_scalars(parsed))
            for value in values:
                if value in exact_auth_values:
                    raise UnsafePublicProjectionError(
                        "public projection contains an unsafe authentication value"
                    )
                try:
                    digest = _token_digest(value)
                except AuthenticationFailedError:
                    continue
                if digest in issued_digests:
                    raise UnsafePublicProjectionError(
                        "public projection contains an unsafe authentication value"
                    )


def _authenticate_read(
    auth: AuthorityAuthService,
    connection: sqlite3.Connection,
    authority: SQLiteAuthority,
    bearer_token: str,
    action: StableId,
) -> StableId:
    digest = _token_digest(bearer_token)
    row = connection.execute(
        "SELECT c.actor_id, c.actor_incarnation_id FROM capability_tokens AS t "
        "JOIN capabilities AS c USING (capability_id) WHERE t.token_digest = ?",
        (digest,),
    ).fetchone()
    if row is None:
        raise AuthenticationFailedError("bearer token is unknown")
    actor = EntityRef(authority.project.project_id, EntityKind.ACTOR,
                      StableId(row["actor_id"]), incarnation_id=StableId(row["actor_incarnation_id"]))
    capability_id = auth._authorize_capability(
        connection, authority.project, digest, actor,
        AuthorizationRequirement(action, authority.project.ref),
    )
    return capability_id


def _revision(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
    if row is None or type(row[0]) is not int:
        raise AuthorityExportError("authority revision is unavailable")
    return row[0]


def _require_revision(connection: sqlite3.Connection, expected_revision: int | None) -> int:
    current = _revision(connection)
    if expected_revision is not None:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        if expected_revision != current:
            raise StaleExportRevisionError(
                f"expected authority revision {expected_revision}; current revision is {current}"
            )
    return current


def _sha256_file(path: Path) -> Sha256Digest:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise BackupIntegrityError("cannot read backup artifact") from exc
    return Sha256Digest(digest.hexdigest())


def _check_sqlite_integrity(authority: SQLiteAuthority, expected_fingerprint: str) -> int:
    with authority.read_transaction() as connection:
        integrity = tuple(row[0] for row in connection.execute("PRAGMA integrity_check"))
        if integrity != ("ok",):
            raise BackupIntegrityError("backup SQLite integrity check failed")
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_keys:
            raise BackupIntegrityError("backup contains foreign key violations")
        actual_fingerprint = _logical_fingerprint(connection)
        if actual_fingerprint != expected_fingerprint:
            raise BackupIntegrityError("backup logical fingerprint does not match its manifest")
        return _revision(connection)


def _remove_staging(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(str(path) + suffix).unlink()
        except FileNotFoundError:
            pass


def _destination_available(path: Path) -> bool:
    if path.exists() or path.is_symlink():
        return False
    # SQLite may interpret these siblings as part of a database even when the
    # main path is missing. Treat the complete file namespace as occupied.
    return not any(
        sidecar.exists() or sidecar.is_symlink()
        for sidecar in (Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal"))
    )


def _publish_no_replace(staging: Path, destination: Path) -> None:
    if not _destination_available(destination):
        raise BackupDestinationExistsError("destination or SQLite sidecar already exists; refusing to publish")
    try:
        os.link(staging, destination)
    except FileExistsError as exc:
        raise BackupDestinationExistsError("destination already exists; refusing to replace it") from exc
    try:
        _sync_directory(destination.parent)
    except OSError as exc:
        raise AuthorityPublicationDurabilityUncertainError(
            "backup was published, but syncing its parent directory failed; publication durability is uncertain"
        ) from exc


class AuthorityExportService:
    """Authenticated, non-mutating read model and explicit private backup API."""

    def __init__(self, auth: AuthorityAuthService) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        self.auth = auth

    def read_model(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        *,
        expected_revision: int | None = None,
    ) -> AuthorityReadModelV1:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        with authority.read_transaction() as connection:
            _authenticate_read(self.auth, connection, authority, bearer_token, AUTHORITY_READ_ACTION)
            revision = _require_revision(connection, expected_revision)
            sections = _read_sections(connection)
            _reject_authentication_collisions(connection, sections)
            meta = connection.execute(
                "SELECT project_id, authority_id FROM authority_meta WHERE singleton = 1"
            ).fetchone()
            if meta is None:
                raise AuthorityExportError("authority identity is unavailable")
        return AuthorityReadModelV1(
            AUTHORITY_READ_MODEL_FORMAT, 1, StableId(meta["project_id"]), StableId(meta["authority_id"]),
            SCHEMA_VERSION, revision, sections,
        )

    @staticmethod
    def render_markdown(model: AuthorityReadModelV1) -> str:
        if not isinstance(model, AuthorityReadModelV1):
            raise TypeError("model must be an AuthorityReadModelV1")
        lines = [
            "# Todo Orchestrator authority",
            "",
            f"- Project: `{_markdown_cell(model.project_id)}`",
            f"- Authority: `{_markdown_cell(model.authority_id)}`",
            f"- Schema: v{model.schema_version}",
            f"- Semantic revision: {model.semantic_revision}",
            "",
            "This is a sanitized metadata projection. Use an explicit private backup for full state.",
            "",
            "## Records",
            "",
        ]
        for section, rows in sorted(model.sections.items()):
            lines.append(f"### {section.replace('_', ' ').title()} ({len(rows)})")
            lines.append("")
            if not rows:
                lines.extend(("_None._", ""))
                continue
            keys = tuple(rows[0].keys())
            lines.append("| " + " | ".join(keys) + " |")
            lines.append("| " + " | ".join("---" for _ in keys) + " |")
            for row in rows:
                values = []
                for key in keys:
                    value = row.get(key)
                    values.append(_markdown_cell("" if value is None else value))
                lines.append("| " + " | ".join(values) + " |")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def backup(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        destination: str | os.PathLike[str],
        *,
        expected_revision: int,
    ) -> AuthorityBackupResult:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        if os.name != "posix":
            raise UnsupportedAuthorityPlatformError("authority backups require POSIX directory fsync support")
        target = _path(destination)
        if target == authority.path:
            raise ValueError("backup destination must differ from the authority path")
        if not _destination_available(target):
            raise BackupDestinationExistsError("destination or SQLite sidecar already exists; refusing to replace it")
        descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.backup-", suffix=".sqlite3", dir=target.parent)
        os.close(descriptor)
        staging = Path(name)
        try:
            with authority.read_transaction() as source:
                _authenticate_read(self.auth, source, authority, bearer_token, AUTHORITY_BACKUP_ACTION)
                revision = _require_revision(source, expected_revision)
                fingerprint = _logical_fingerprint(source)
                meta = source.execute(
                    "SELECT project_id, authority_id FROM authority_meta WHERE singleton = 1"
                ).fetchone()
                if meta is None:
                    raise AuthorityExportError("authority identity is unavailable")
                destination_connection = sqlite3.connect(staging, isolation_level=None)
                try:
                    destination_connection.execute("PRAGMA synchronous = FULL")
                    source.backup(destination_connection, pages=256, sleep=0.01)
                    if str(destination_connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal":
                        checkpoint = destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                        if checkpoint is None or checkpoint[0] != 0:
                            raise BackupIntegrityError("backup staging WAL could not be checkpointed")
                finally:
                    destination_connection.close()

            project = Project(StableId(meta["project_id"]), StableId(meta["authority_id"]))
            with SQLiteAuthority.open_reader(staging, project) as staged:
                staged_revision = _check_sqlite_integrity(staged, fingerprint)
            if staged_revision != revision:
                raise BackupIntegrityError("backup semantic revision changed during snapshot creation")
            artifact_digest = _sha256_file(staging)
            manifest = AuthorityBackupManifest(
                AUTHORITY_BACKUP_FORMAT, 1, project.project_id, project.authority_id, SCHEMA_VERSION,
                revision, Sha256Digest(fingerprint), artifact_digest,
            )
            _publish_no_replace(staging, target)
            return AuthorityBackupResult(manifest, target)
        except BaseException:
            _remove_staging(staging)
            raise
        finally:
            _remove_staging(staging)


def restore_backup(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    manifest: AuthorityBackupManifest,
    expected_project_id: StableId,
    expected_authority_id: StableId,
    expected_semantic_revision: int,
) -> SQLiteAuthority:
    """Explicitly restore a verified backup to a new path, returning a reader.

    Restore never replaces an existing file and is never called by open/read
    paths. Reinstated capability rows are exactly those at backup time; this
    cannot prove subsequent revocation or external provider/workspace freshness.
    """
    if not isinstance(manifest, AuthorityBackupManifest):
        raise TypeError("manifest must be an AuthorityBackupManifest")
    if not isinstance(expected_project_id, StableId) or not isinstance(expected_authority_id, StableId):
        raise TypeError("expected project and authority IDs must be StableId values")
    if type(expected_semantic_revision) is not int or expected_semantic_revision < 0:
        raise ValueError("expected_semantic_revision must be a non-negative integer")
    if manifest.project_id != expected_project_id or manifest.authority_id != expected_authority_id:
        raise BackupIdentityMismatchError("backup identity does not match the explicitly requested project and authority")
    if manifest.semantic_revision != expected_semantic_revision:
        raise BackupRevisionMismatchError("backup revision does not match the explicitly requested revision")
    if manifest.schema_version != SCHEMA_VERSION:
        raise BackupSchemaVersionError("backup schema version is unsupported by this engine")
    if os.name != "posix":
        raise UnsupportedAuthorityPlatformError("authority restoration requires POSIX directory fsync support")
    source_path = _path(source)
    target = _path(destination)
    if source_path == target:
        raise ValueError("restore source and destination must differ")
    if not _destination_available(target):
        raise BackupDestinationExistsError("destination or SQLite sidecar already exists; refusing to replace it")
    if not source_path.is_file():
        raise AuthorityNotFoundError("backup artifact is not a regular file")
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(source_path) + suffix)
        if sidecar.exists():
            raise BackupIntegrityError("backup must be a self-contained SQLite artifact without sidecar state")
    if _sha256_file(source_path) != manifest.artifact_digest:
        raise BackupIntegrityError("backup artifact digest does not match its manifest")

    project = Project(expected_project_id, expected_authority_id)
    try:
        with SQLiteAuthority.open_reader(source_path, project) as original:
            actual_revision = _check_sqlite_integrity(original, manifest.logical_fingerprint.hex)
            if actual_revision != expected_semantic_revision:
                raise BackupRevisionMismatchError("backup database semantic revision does not match its manifest")
    except UnsupportedSchemaVersionError as exc:
        raise BackupSchemaVersionError("backup schema version is unsupported by this engine") from exc
    except AuthorityIdentityMismatchError as exc:
        raise BackupIdentityMismatchError("backup database identity does not match its manifest") from exc
    except (InvalidAuthorityError, sqlite3.Error) as exc:
        if isinstance(exc, BackupIntegrityError):
            raise
        raise BackupIntegrityError("backup database failed authority validation") from exc

    descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.restore-", suffix=".sqlite3", dir=target.parent)
    os.close(descriptor)
    staging = Path(name)
    try:
        try:
            with source_path.open("rb") as source_stream, staging.open("wb") as staging_stream:
                while True:
                    chunk = source_stream.read(1024 * 1024)
                    if not chunk:
                        break
                    staging_stream.write(chunk)
                staging_stream.flush()
                os.fsync(staging_stream.fileno())
        except OSError as exc:
            raise BackupIntegrityError("cannot stage the validated backup artifact") from exc
        if _sha256_file(staging) != manifest.artifact_digest:
            raise BackupIntegrityError("staged backup digest changed during restoration")
        with SQLiteAuthority.open_reader(staging, project) as staged:
            actual_revision = _check_sqlite_integrity(staged, manifest.logical_fingerprint.hex)
            if actual_revision != expected_semantic_revision:
                raise BackupRevisionMismatchError("staged backup semantic revision changed")
        _publish_no_replace(staging, target)
    except BaseException:
        _remove_staging(staging)
        raise
    finally:
        _remove_staging(staging)
    return SQLiteAuthority.open_reader(target, project)


__all__ = [
    "AUTHORITY_BACKUP_ACTION", "AUTHORITY_READ_ACTION", "AuthorityBackupError", "AuthorityExportError",
    "AuthorityExportService", "BackupDestinationExistsError", "BackupIdentityMismatchError",
    "BackupIntegrityError", "BackupRevisionMismatchError", "BackupSchemaVersionError",
    "StaleExportRevisionError", "UnsafePublicProjectionError", "restore_backup",
]


def _markdown_cell(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace("`", "\\`")
    text = text.replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return html_escape(text, quote=False)
