"""Authenticated authority backup guarantees on disposable SQLite files."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import tempfile
from threading import Event, Lock
import unittest
from unittest.mock import patch

from todo_orchestrator.authority import (
    AuthenticationFailedError,
    CapabilityDeniedError,
    SQLiteAuthority,
)
from todo_orchestrator.contracts import StableId
from todo_orchestrator.operations import export as export_module
from todo_orchestrator.operations.export import (
    AUTHORITY_BACKUP_ACTION,
    AUTHORITY_READ_ACTION,
    AuthorityExportService,
    StaleExportRevisionError,
)

from tests.verification import test_acceptance_independent as acceptance_fixture
from tests.verification.test_execution_independent import PROJECT


class AuthorityBackupPublicTests(unittest.TestCase):
    """Use public capability and command APIs to test private backups."""

    def setUp(self):
        self.acceptance = acceptance_fixture.IndependentOutcomeAcceptanceTests()
        self.acceptance.setUp()
        self.addCleanup(self.acceptance.doCleanups)
        self.f = self.acceptance.fixture
        self.service = AuthorityExportService(self.f.auth)
        self.root = self._login_owner(
            (
                AUTHORITY_BACKUP_ACTION,
                AUTHORITY_READ_ACTION,
                StableId("todo.capability.delegate"),
                StableId("todo.capability.revoke"),
            ),
            "r04-backup-root",
        )

    def _login_owner(self, actions, key):
        f = self.f
        with f.open_writer() as authority:
            return f.auth.login_local_owner(
                authority,
                acceptance_fixture.OWNER_PASSWORD,
                actions=tuple(dict.fromkeys(actions)),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def _delegate(self, credential, actions, key):
        f = self.f
        with f.open_writer() as authority:
            return f.auth.delegate(
                authority,
                self.root.bearer_token,
                credential,
                actions=tuple(actions),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(minutes=30),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def _authority_state(self):
        f = self.f
        with f.open_reader() as authority:
            return (
                f.dispatcher.logical_fingerprint(authority),
                authority.connection.execute(
                    "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
                ).fetchone()[0],
                tuple(
                    (table, authority.connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
                    for table in (
                        "capabilities", "capability_tokens", "command_idempotency",
                        "command_receipts", "authority_events",
                    )
                ),
            )

    @staticmethod
    def _directory_state(path: Path):
        return tuple(sorted((item.name, item.stat().st_size) for item in path.iterdir()))

    def test_backup_refuses_read_only_revoked_and_stale_grants_without_churn(self):
        read_grant = self._delegate(
            "worker-verify", (AUTHORITY_READ_ACTION,), "r04-read-only-grant",
        )
        backup_grant = self._delegate(
            "worker-missing", (AUTHORITY_BACKUP_ACTION,), "r04-revoked-grant",
        )
        f = self.f
        with f.open_writer() as authority:
            f.auth.revoke_family(
                authority,
                self.root.bearer_token,
                backup_grant.capability.capability_id,
                idempotency_key=StableId("r04-revoke-backup-grant"),
                expected_revision=f.revision(),
            )

        with tempfile.TemporaryDirectory(prefix="todo-r04-refused-backup-") as temporary:
            directory = Path(temporary)
            destinations = {
                "read": directory / "read.sqlite3",
                "revoked": directory / "revoked.sqlite3",
                "stale": directory / "stale.sqlite3",
            }
            empty = self._directory_state(directory)

            before = self._authority_state()
            with f.open_reader() as authority:
                with self.assertRaises(CapabilityDeniedError):
                    self.service.backup(
                        authority,
                        read_grant.bearer_token,
                        destinations["read"],
                        expected_revision=f.revision(),
                    )
            self.assertEqual(self._authority_state(), before)
            self.assertEqual(self._directory_state(directory), empty)

            before = self._authority_state()
            with f.open_reader() as authority:
                with self.assertRaises(AuthenticationFailedError):
                    self.service.backup(
                        authority,
                        backup_grant.bearer_token,
                        destinations["revoked"],
                        expected_revision=f.revision(),
                    )
            self.assertEqual(self._authority_state(), before)
            self.assertEqual(self._directory_state(directory), empty)

            valid_backup = self._delegate(
                "worker-other", (AUTHORITY_BACKUP_ACTION,), "r04-valid-stale-grant",
            )
            before = self._authority_state()
            current_revision = before[1]
            with f.open_reader() as authority:
                with self.assertRaises(StaleExportRevisionError):
                    self.service.backup(
                        authority,
                        valid_backup.bearer_token,
                        destinations["stale"],
                        expected_revision=max(0, current_revision - 1),
                    )
            self.assertEqual(self._authority_state(), before)
            self.assertEqual(self._directory_state(directory), empty)

    def test_backup_captures_one_point_in_time_while_a_public_writer_commits(self):
        f = self.f
        backup_grant = self._delegate(
            "worker-verify", (AUTHORITY_BACKUP_ACTION,), "r04-racing-backup-grant",
        )
        with f.open_reader() as authority:
            expected_revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            expected_fingerprint = f.dispatcher.logical_fingerprint(authority)
            prior_receipts = tuple(tuple(row) for row in authority.connection.execute(
                "SELECT i.idempotency_key, r.receipt_id, r.semantic_revision "
                "FROM command_idempotency AS i JOIN command_receipts AS r USING (receipt_id) "
                "ORDER BY i.idempotency_key"
            ).fetchall())

        with tempfile.TemporaryDirectory(prefix="todo-r04-racing-backup-") as temporary:
            directory = Path(temporary)
            destination = directory / "point-in-time.sqlite3"
            snapshot_ready = Event()
            continue_backup = Event()
            guard = Lock()
            paused = False
            original_fingerprint = export_module._logical_fingerprint

            def pause_after_snapshot_fingerprint(connection):
                nonlocal paused
                value = original_fingerprint(connection)
                with guard:
                    should_pause = not paused
                    paused = True
                if should_pause:
                    snapshot_ready.set()
                    if not continue_backup.wait(10):
                        raise TimeoutError("concurrent writer did not complete during backup")
                return value

            def export_from_reader():
                with f.open_reader() as authority:
                    return self.service.backup(
                        authority,
                        backup_grant.bearer_token,
                        destination,
                        expected_revision=expected_revision,
                    )

            with patch.object(export_module, "_logical_fingerprint", pause_after_snapshot_fingerprint):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending_backup = pool.submit(export_from_reader)
                    try:
                        self.assertTrue(snapshot_ready.wait(10), "backup never established its snapshot")
                        with f.open_writer() as authority:
                            racing_receipt = f.auth.login_local_owner(
                                authority,
                                acceptance_fixture.OWNER_PASSWORD,
                                actions=(AUTHORITY_READ_ACTION,),
                                scope=PROJECT.ref,
                                expires_at=f.clock() + timedelta(minutes=30),
                                idempotency_key=StableId("r04-racing-writer-receipt"),
                                expected_revision=expected_revision,
                            ).receipt
                    finally:
                        continue_backup.set()
                    result = pending_backup.result(timeout=15)

            current = self._authority_state()
            self.assertEqual(current[1], expected_revision + 1)
            self.assertNotEqual(current[0], expected_fingerprint)
            self.assertEqual(racing_receipt.semantic_revision, expected_revision + 1)

            manifest = result.manifest
            self.assertEqual(manifest.project_id, PROJECT.project_id)
            self.assertEqual(manifest.authority_id, PROJECT.authority_id)
            self.assertEqual(manifest.semantic_revision, expected_revision)
            self.assertEqual(manifest.logical_fingerprint.hex, expected_fingerprint)
            self.assertEqual(self._directory_state(directory), ((destination.name, destination.stat().st_size),))
            with SQLiteAuthority.open_reader(destination, PROJECT) as snapshot:
                metadata = snapshot.connection.execute(
                    "SELECT project_id, authority_id, semantic_revision "
                    "FROM authority_meta WHERE singleton = 1"
                ).fetchone()
                self.assertEqual(
                    (metadata["project_id"], metadata["authority_id"], metadata["semantic_revision"]),
                    (str(PROJECT.project_id), str(PROJECT.authority_id), expected_revision),
                )
                copied_receipts = tuple(tuple(row) for row in snapshot.connection.execute(
                    "SELECT i.idempotency_key, r.receipt_id, r.semantic_revision "
                    "FROM command_idempotency AS i JOIN command_receipts AS r USING (receipt_id) "
                    "ORDER BY i.idempotency_key"
                ).fetchall())
                self.assertEqual(copied_receipts, prior_receipts)
                self.assertNotIn(
                    "r04-racing-writer-receipt",
                    {row[0] for row in copied_receipts},
                )
                self.assertEqual(
                    f.dispatcher.logical_fingerprint(snapshot),
                    manifest.logical_fingerprint.hex,
                )


if __name__ == "__main__":
    unittest.main()
