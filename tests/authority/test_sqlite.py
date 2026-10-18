from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import traceback
from threading import Barrier, Event
import unittest
from unittest.mock import patch

from todo_orchestrator.authority import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    AuthorityError,
    AuthorityAlreadyExistsError,
    AuthorityIdentityMismatchError,
    AuthorityNotFoundError,
    InvalidAuthorityError,
    AuthorityPublicationDurabilityUncertainError,
    ReadOnlyAuthorityError,
    SQLiteAuthority,
    UnsupportedAuthorityPlatformError,
    UnsupportedSchemaVersionError,
)
from todo_orchestrator.contracts import Project, StableId


def project(project_id: str = "project-1", authority_id: str = "authority-1") -> Project:
    return Project(StableId(project_id), StableId(authority_id))


def work_bundle(work_id: str, revision_id: str, title: str, outcome: str) -> tuple[str, str]:
    value = {
        "format": "todo-orchestrator.work-bundle",
        "schema_version": 1,
        "work_item_id": work_id,
        "definition_revision_id": revision_id,
        "work": {
            "id": work_id, "title": title, "outcome": outcome,
            "parent_id": None, "parent_ref": None, "supersedes": [], "requirement_groups": [],
        },
        "requirements": {},
        "outgoing_blockers": [],
    }
    canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return canonical, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SQLiteAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "authority.sqlite3"
        self.project = project()
        SQLiteAuthority.initialize(self.path, self.project)

    def open_reader(self, *, project_value: Project | None = None) -> SQLiteAuthority:
        return SQLiteAuthority.open_reader(self.path, project_value or self.project)

    def open_writer(self, *, project_value: Project | None = None, busy_timeout: float = 5) -> SQLiteAuthority:
        return SQLiteAuthority.open_writer(self.path, project_value or self.project, busy_timeout=busy_timeout)

    def test_initialization_records_identity_and_schema_v17_in_normalized_tables(self):
        with self.open_reader() as authority:
            connection = authority.connection
            self.assertEqual(connection.execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            meta = connection.execute(
                "SELECT project_id, authority_id, semantic_revision FROM authority_meta"
            ).fetchone()
            self.assertEqual(tuple(meta), ("project-1", "authority-1", 0))
            names = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            self.assertTrue({"work_items", "attempts", "capabilities", "capability_tokens",
                             "local_owner_credentials", "attempt_scope_snapshots", "evidence", "outcomes",
                             "external_operations"} <= names)
            for table in (
                "plan_revisions", "work_items", "assignments", "attempts", "capabilities", "evidence",
                "outcomes", "external_operations", "authority_events", "command_receipts", "command_idempotency",
            ):
                with self.subTest(table=table):
                    self.assertEqual(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_revisioned_definitions_attempts_and_accepted_outcomes_have_distinct_ownership(self):
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                    ("reviewer", "incarnation-1", "human", "reviewer"),
                )
                connection.execute(
                    "INSERT INTO plan_revisions(plan_revision_id, sequence, state, source, content_digest, producer, "
                    "authored_by_actor_id, authored_by_incarnation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("plan-1", 1, "accepted", "plan.json", "a" * 64, "fixture", "reviewer", "incarnation-1"),
                )
                connection.execute(
                    "INSERT INTO work_items(work_item_id, definition_revision_id, title, outcome, canonical_json, content_digest) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    ("work-1", "plan-1", "Inspect behavior", "Record the result",
                     *work_bundle("work-1", "plan-1", "Inspect behavior", "Record the result")),
                )
                connection.execute(
                    "INSERT INTO plan_revision_work_items(plan_revision_id, work_item_id, definition_revision_id) "
                    "VALUES (?, ?, ?)",
                    ("plan-1", "work-1", "plan-1"),
                )
                connection.execute(
                    "INSERT INTO attempts(attempt_id, work_item_id, definition_revision_id, actor_id, "
                    "actor_incarnation_id, state) VALUES (?, ?, ?, ?, ?, ?)",
                    ("attempt-1", "work-1", "plan-1", "reviewer", "incarnation-1", "rejected"),
                )
                connection.execute(
                    "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, disposition, "
                    "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at, attempt_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("outcome-1", "work-1", "plan-1", 1, "accepted_negative", "reviewer", "incarnation-1",
                     "2026-10-18T00:00:00+00:00", "attempt-1"),
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO attempts(attempt_id, work_item_id, definition_revision_id, actor_id, "
                        "actor_incarnation_id, state) VALUES (?, ?, ?, ?, ?, ?)",
                        ("attempt-2", "work-1", "plan-1", "missing", "incarnation", "active"),
                    )
        with self.open_reader() as authority:
            stored = authority.connection.execute(
                "SELECT attempts.state, outcomes.disposition FROM attempts "
                "JOIN outcomes ON outcomes.attempt_id = attempts.attempt_id"
            ).fetchone()
            self.assertEqual(tuple(stored), ("rejected", "accepted_negative"))

    def test_prerequisite_targets_preserve_project_qualified_identity(self):
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO plan_revisions(plan_revision_id, sequence, state) VALUES (?, ?, ?)",
                    ("plan-1", 1, "accepted"),
                )
                connection.execute(
                    "INSERT INTO work_items(work_item_id, definition_revision_id, title, outcome, canonical_json, content_digest) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    ("work-1", "plan-1", "Wait on qualified work", "Preserve the complete target ref",
                     *work_bundle("work-1", "plan-1", "Wait on qualified work", "Preserve the complete target ref")),
                )
                for requirement_id, target_project_id in (
                    ("requirement-a", "project-a"),
                    ("requirement-b", "project-b"),
                ):
                    connection.execute(
                        "INSERT INTO requirements(requirement_id, definition_revision_id, work_item_id, kind, "
                        "description, target_project_id, target_kind, target_entity_id, "
                        "target_definition_revision_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (requirement_id, "plan-1", "work-1", "prerequisite", "External prerequisite",
                         target_project_id, "work_item", "shared-target", "external-revision"),
                    )

        with self.open_reader() as authority:
            targets = authority.connection.execute(
                "SELECT target_project_id, target_kind, target_entity_id, target_definition_revision_id "
                "FROM requirements ORDER BY target_project_id"
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in targets],
                [
                    ("project-a", "work_item", "shared-target", "external-revision"),
                    ("project-b", "work_item", "shared-target", "external-revision"),
                ],
            )

    def test_initializer_never_replaces_existing_files(self):
        original = self.path.read_bytes()
        with self.assertRaises(AuthorityAlreadyExistsError):
            SQLiteAuthority.initialize(self.path, self.project)
        self.assertEqual(self.path.read_bytes(), original)

    def test_initialization_failure_leaves_no_partial_authority_or_temp_files(self):
        import todo_orchestrator.authority.sqlite as authority_module

        with tempfile.TemporaryDirectory() as directory:
            failed_path = Path(directory) / "failed.sqlite3"
            invalid_schema = (*authority_module._SCHEMA_STATEMENTS, "CREATE TABL malformed")
            with patch.object(authority_module, "_SCHEMA_STATEMENTS", invalid_schema):
                with self.assertRaises(sqlite3.OperationalError):
                    SQLiteAuthority.initialize(failed_path, self.project)
            self.assertFalse(failed_path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_initializer_syncs_parent_directory_after_publication(self):
        import todo_orchestrator.authority.sqlite as authority_module

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "durable.sqlite3"
            with patch.object(authority_module, "_sync_directory", wraps=authority_module._sync_directory) as sync:
                SQLiteAuthority.initialize(path, self.project)
            sync.assert_called_once_with(path.parent)
            with SQLiteAuthority.open_reader(path, self.project) as authority:
                self.assertEqual(authority.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_directory_sync_failure_reports_uncertain_publication_and_preserves_authority(self):
        import todo_orchestrator.authority.sqlite as authority_module

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "uncertain.sqlite3"
            with patch.object(authority_module, "_sync_directory", side_effect=OSError("simulated fsync failure")):
                with self.assertRaisesRegex(
                    AuthorityPublicationDurabilityUncertainError,
                    "published.*durability is uncertain",
                ):
                    SQLiteAuthority.initialize(path, self.project)

            self.assertTrue(path.is_file())
            with SQLiteAuthority.open_reader(path, self.project) as authority:
                self.assertEqual(authority.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            original = path.read_bytes()
            with self.assertRaises(AuthorityAlreadyExistsError):
                SQLiteAuthority.initialize(path, self.project)
            self.assertEqual(path.read_bytes(), original)

    def test_concurrent_initializers_publish_only_one_complete_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "race.sqlite3"
            barrier = Barrier(2)

            def initialize():
                barrier.wait(timeout=2)
                try:
                    SQLiteAuthority.initialize(path, self.project)
                    return "created"
                except AuthorityAlreadyExistsError:
                    return "already-existed"

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: initialize(), range(2)))
            self.assertCountEqual(results, ["created", "already-existed"])
            with SQLiteAuthority.open_reader(path, self.project) as authority:
                self.assertEqual(authority.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_missing_read_write_and_migrate_paths_do_not_create_authority(self):
        missing = self.root / "missing.sqlite3"
        for operation in (
            lambda: SQLiteAuthority.open_reader(missing, self.project),
            lambda: SQLiteAuthority.open_writer(missing, self.project),
            lambda: SQLiteAuthority.migrate(missing, self.project),
        ):
            with self.subTest(operation=operation), self.assertRaises(AuthorityNotFoundError):
                operation()
            self.assertFalse(missing.exists())

    def test_readers_are_query_only_and_do_not_modify_the_authority_file(self):
        original = self.path.read_bytes()
        with self.open_reader() as first, self.open_reader() as second:
            self.assertEqual(first.connection.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(second.connection.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(first.connection.execute("SELECT count(*) FROM work_items").fetchone()[0], 0)
            self.assertEqual(second.connection.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)
            with self.assertRaises(sqlite3.OperationalError):
                first.connection.execute(
                    "INSERT INTO authority_events(event_id, semantic_revision, event_ordinal, event_kind, payload_json, occurred_at) "
                    "VALUES ('event', 1, 0, 'test', '{}', '2026-10-18T00:00:00+00:00')"
                )
        self.assertEqual(self.path.read_bytes(), original)

    def test_reader_snapshot_remains_stable_while_writer_commits(self):
        with self.open_reader() as reader, self.open_reader() as second_reader, self.open_writer() as writer:
            with reader.read_transaction() as read_snapshot:
                self.assertEqual(
                    read_snapshot.execute("SELECT semantic_revision FROM authority_meta").fetchone()[0], 0
                )
                with writer.write_transaction() as write:
                    write.execute(
                        "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                        ("writer", "writer-incarnation", "automation", "writer"),
                    )
                    write.execute("UPDATE authority_meta SET semantic_revision = 1 WHERE singleton = 1")
                    write.execute(
                        "INSERT INTO authority_events(event_id, semantic_revision, event_ordinal, event_kind, "
                        "payload_json, occurred_at, actor_id, actor_incarnation_id) "
                        "VALUES ('event-1', 1, 0, 'test', '{}', '2026-10-18T00:00:00+00:00', 'writer', 'writer-incarnation')"
                    )
                self.assertEqual(
                    read_snapshot.execute("SELECT semantic_revision FROM authority_meta").fetchone()[0], 0
                )
            self.assertEqual(
                reader.connection.execute("SELECT semantic_revision FROM authority_meta").fetchone()[0], 1
            )
            self.assertEqual(
                second_reader.connection.execute("SELECT count(*) FROM authority_events").fetchone()[0], 1
            )

    def test_writers_serialize_and_failed_transactions_roll_back(self):
        acquired = Event()
        entered = Event()
        errors: list[str] = []

        def second_writer():
            try:
                with self.open_writer() as writer:
                    entered.set()
                    with writer.write_transaction() as connection:
                        acquired.set()
                        connection.execute("UPDATE authority_meta SET semantic_revision = semantic_revision + 1")
            except BaseException:  # reported in the test thread
                errors.append(traceback.format_exc())

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with self.open_writer() as first:
                self.assertEqual(first.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
                with first.write_transaction() as connection:
                    connection.execute("UPDATE authority_meta SET semantic_revision = semantic_revision + 1")
                    future = executor.submit(second_writer)
                    self.assertTrue(entered.wait(timeout=2))
                    self.assertFalse(acquired.wait(timeout=0.1))
                future.result(timeout=3)
        finally:
            executor.shutdown(wait=True)
        self.assertEqual(errors, [], "\n".join(errors))
        with self.open_reader() as reader:
            self.assertEqual(reader.connection.execute("SELECT semantic_revision FROM authority_meta").fetchone()[0], 2)

        with self.open_writer() as writer:
            with self.assertRaisesRegex(RuntimeError, "rollback probe"):
                with writer.write_transaction() as connection:
                    connection.execute("UPDATE authority_meta SET semantic_revision = 99")
                    raise RuntimeError("rollback probe")
        with self.open_reader() as reader:
            self.assertEqual(reader.connection.execute("SELECT semantic_revision FROM authority_meta").fetchone()[0], 2)

    def test_foreign_identity_is_rejected_before_writable_open_changes_file(self):
        foreign = project("different-project", "different-authority")
        original = self.path.read_bytes()
        with self.assertRaises(AuthorityIdentityMismatchError):
            SQLiteAuthority.open_writer(self.path, foreign)
        self.assertEqual(self.path.read_bytes(), original)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_foreign_file_identity_does_not_change_its_journal_mode(self):
        foreign_path = self.root / "foreign.sqlite3"
        with closing(sqlite3.connect(foreign_path)) as connection:
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.execute(
                "CREATE TABLE authority_meta(singleton INTEGER PRIMARY KEY, project_id TEXT, authority_id TEXT, "
                "semantic_revision INTEGER, created_at TEXT)"
            )
            connection.execute(
                "INSERT INTO authority_meta VALUES(1, 'foreign', 'foreign-authority', 0, 'now')"
            )
            connection.commit()
        original = foreign_path.read_bytes()
        with self.assertRaises(AuthorityIdentityMismatchError):
            SQLiteAuthority.open_writer(foreign_path, self.project)
        self.assertEqual(foreign_path.read_bytes(), original)
        with closing(sqlite3.connect(foreign_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")

    def test_unmarked_sqlite_file_is_rejected_without_mutation(self):
        unmarked = self.root / "unmarked.sqlite3"
        with closing(sqlite3.connect(unmarked)) as connection:
            connection.execute("CREATE TABLE sentinel(value TEXT)")
            connection.execute("INSERT INTO sentinel VALUES ('preserve')")
            connection.commit()
        original = unmarked.read_bytes()
        with self.assertRaises(InvalidAuthorityError):
            SQLiteAuthority.open_writer(unmarked, self.project)
        self.assertEqual(unmarked.read_bytes(), original)

    def test_same_named_but_malformed_schema_is_rejected_without_mutation(self):
        import todo_orchestrator.authority.sqlite as authority_module

        malformed = self.root / "same-names.sqlite3"
        with closing(sqlite3.connect(malformed)) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            for table in authority_module._REQUIRED_TABLES:
                if table == "authority_meta":
                    connection.execute(
                        "CREATE TABLE authority_meta(singleton INTEGER PRIMARY KEY, project_id TEXT, "
                        "authority_id TEXT, semantic_revision INTEGER, created_at TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO authority_meta VALUES (1, 'project-1', 'authority-1', 0, 'now')"
                    )
                else:
                    connection.execute(f'CREATE TABLE "{table}" (dummy TEXT)')
            connection.commit()
        original = malformed.read_bytes()
        for operation in (
            lambda: SQLiteAuthority.open_reader(malformed, self.project),
            lambda: SQLiteAuthority.open_writer(malformed, self.project),
            lambda: SQLiteAuthority.migrate(malformed, self.project),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                InvalidAuthorityError, "frozen schema-v17"
            ):
                operation()
            self.assertEqual(malformed.read_bytes(), original)

    def test_sqlite_like_application_name_cannot_bypass_schema_validation(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE sqliteXevil (payload TEXT)")
            connection.commit()
        original = self.path.read_bytes()
        for operation in (
            lambda: SQLiteAuthority.open_reader(self.path, self.project),
            lambda: SQLiteAuthority.open_writer(self.path, self.project),
            lambda: SQLiteAuthority.migrate(self.path, self.project),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                InvalidAuthorityError, "frozen schema-v17"
            ):
                operation()
            self.assertEqual(self.path.read_bytes(), original)

    def test_missing_append_only_trigger_is_rejected_without_mutation(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TRIGGER authority_events_no_update")
            connection.commit()
        original = self.path.read_bytes()
        for operation in (
            lambda: SQLiteAuthority.open_reader(self.path, self.project),
            lambda: SQLiteAuthority.open_writer(self.path, self.project),
            lambda: SQLiteAuthority.migrate(self.path, self.project),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                InvalidAuthorityError, "frozen schema-v17"
            ):
                operation()
            self.assertEqual(self.path.read_bytes(), original)

    def test_missing_check_constraint_is_rejected_without_mutation(self):
        import todo_orchestrator.authority.sqlite as authority_module

        malformed = self.root / "missing-check.sqlite3"
        changed_schema = tuple(
            statement.replace(
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1)",
                "singleton INTEGER PRIMARY KEY",
            )
            for statement in authority_module._SCHEMA_STATEMENTS
        )
        self.assertNotEqual(changed_schema, authority_module._SCHEMA_STATEMENTS)
        with patch.object(authority_module, "_SCHEMA_STATEMENTS", changed_schema):
            SQLiteAuthority.initialize(malformed, self.project)

        original = malformed.read_bytes()
        for operation in (
            lambda: SQLiteAuthority.open_reader(malformed, self.project),
            lambda: SQLiteAuthority.open_writer(malformed, self.project),
            lambda: SQLiteAuthority.migrate(malformed, self.project),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                InvalidAuthorityError, "frozen schema-v17"
            ):
                operation()
            self.assertEqual(malformed.read_bytes(), original)

    def test_writer_rejects_non_full_synchronous_mode_without_mutation(self):
        import todo_orchestrator.authority.sqlite as authority_module

        original_configure = authority_module._configure

        def configure_with_normal_synchronous(connection, *, readonly, timeout):
            original_configure(connection, readonly=readonly, timeout=timeout)
            if not readonly:
                connection.execute("PRAGMA synchronous = NORMAL")

        original = self.path.read_bytes()
        with patch.object(authority_module, "_configure", side_effect=configure_with_normal_synchronous):
            with self.assertRaisesRegex(InvalidAuthorityError, "FULL synchronous"):
                SQLiteAuthority.open_writer(self.path, self.project)
        self.assertEqual(self.path.read_bytes(), original)

    def test_initializer_rejects_unsupported_platform_before_creating_files(self):
        import todo_orchestrator.authority.sqlite as authority_module

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsupported.sqlite3"
            with patch.object(authority_module.os, "name", "nt"):
                with self.assertRaises(UnsupportedAuthorityPlatformError):
                    SQLiteAuthority.initialize(path, self.project)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unsupported_schema_is_rejected_without_migration_or_mutation(self):
        unsupported = self.root / "unsupported.sqlite3"
        with closing(sqlite3.connect(unsupported)) as connection:
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute("PRAGMA user_version = 99")
            connection.execute("CREATE TABLE sentinel(value TEXT)")
            connection.execute("INSERT INTO sentinel VALUES ('preserve')")
            connection.commit()
        original = unsupported.read_bytes()
        for operation in (
            lambda: SQLiteAuthority.open_reader(unsupported, self.project),
            lambda: SQLiteAuthority.open_writer(unsupported, self.project),
            lambda: SQLiteAuthority.migrate(unsupported, self.project),
        ):
            with self.subTest(operation=operation), self.assertRaises(UnsupportedSchemaVersionError):
                operation()
            self.assertEqual(unsupported.read_bytes(), original)

    def test_earlier_schema_versions_are_refused_without_automatic_migration_or_mutation(self):
        for version in (1, 2, 3, 4, 5, 6, 7):
            earlier = self.root / f"earlier-v{version}.sqlite3"
            SQLiteAuthority.initialize(earlier, self.project)
            with closing(sqlite3.connect(earlier)) as connection:
                connection.execute(f"PRAGMA user_version = {version}")
            original = earlier.read_bytes()
            for operation in (
                lambda: SQLiteAuthority.open_reader(earlier, self.project),
                lambda: SQLiteAuthority.open_writer(earlier, self.project),
                lambda: SQLiteAuthority.migrate(earlier, self.project),
            ):
                with self.subTest(version=version, operation=operation), self.assertRaises(UnsupportedSchemaVersionError):
                    operation()
                self.assertEqual(earlier.read_bytes(), original)

    def test_current_schema_migration_check_is_explicit_noop(self):
        original = self.path.read_bytes()
        result = SQLiteAuthority.migrate(self.path, self.project)
        self.assertEqual((result.from_version, result.to_version), (SCHEMA_VERSION, SCHEMA_VERSION))
        self.assertEqual(self.path.read_bytes(), original)

    def test_unknown_external_operation_resumes_only_with_executing_verification_row(self):
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO external_operations(operation_id, kind, idempotency_key, request_digest, state, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, 'prepared', ?, ?)",
                    ("external-op-retry-guard", "todo.verification", "external-op-retry-guard-key",
                     "b" * 64, "2026-10-18T00:00:00+00:00", "2026-10-18T00:00:00+00:00"),
                )
                connection.execute(
                    "UPDATE external_operations SET state = 'unknown' WHERE operation_id = ?",
                    ("external-op-retry-guard",),
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "state transition is invalid"):
                    connection.execute(
                        "UPDATE external_operations SET state = 'executing' WHERE operation_id = ?",
                        ("external-op-retry-guard",),
                    )

    def test_read_only_store_rejects_write_transaction_and_nested_transactions(self):
        with self.open_reader() as reader:
            with self.assertRaises(ReadOnlyAuthorityError):
                with reader.write_transaction():
                    pass
            with reader.read_transaction():
                with self.assertRaisesRegex(AuthorityError, "nested"):
                    with reader.read_transaction():
                        pass


if __name__ == "__main__":
    unittest.main()
