"""No-clobber filesystem checks for backup and explicit restore."""

from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import InvalidAuthorityError
from todo_orchestrator.operations.export import (
    AuthorityExportService,
    BackupDestinationExistsError,
    restore_backup,
)

from tests.recovery.test_export_independent import ExportIndependentTests
from tests.verification.test_execution_independent import PROJECT


class AuthorityExportFilesystemTests(unittest.TestCase):
    """Ensure sibling SQLite artifacts are treated as occupied destinations."""

    def setUp(self):
        self.fixture = ExportIndependentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture.f

    @staticmethod
    def _add_sidecars(target: Path) -> dict[str, bytes]:
        values = {
            "-wal": b"orphan-wal-must-be-preserved",
            "-shm": b"orphan-shm-must-be-preserved",
            "-journal": b"orphan-journal-must-be-preserved",
        }
        for suffix, content in values.items():
            Path(f"{target}{suffix}").write_bytes(content)
        return values

    def _assert_sidecars_preserved(self, target: Path, values: dict[str, bytes]) -> None:
        self.assertFalse(target.exists(), "a rejected publication must leave the main path absent")
        self.assertEqual(
            {suffix: Path(f"{target}{suffix}").read_bytes() for suffix in values},
            values,
        )

    def test_backup_and_restore_refuse_orphan_sidecar_namespaces(self):
        read_grant, backup_grant = self.fixture._export_grants()
        service = AuthorityExportService(self.f.auth)

        with tempfile.TemporaryDirectory(prefix="todo-r04-sidecars-") as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            with self.f.open_reader() as authority:
                backup = service.backup(
                    authority,
                    backup_grant.bearer_token,
                    source,
                    expected_revision=self.f.revision(),
                )

            backup_dir = root / "backup-target"
            backup_dir.mkdir()
            backup_target = backup_dir / "authority.sqlite3"
            backup_sidecars = self._add_sidecars(backup_target)
            backup_names = set(backup_dir.iterdir())
            with self.f.open_reader() as authority:
                with self.assertRaises(BackupDestinationExistsError):
                    service.backup(
                        authority,
                        backup_grant.bearer_token,
                        backup_target,
                        expected_revision=self.f.revision(),
                    )
            self._assert_sidecars_preserved(backup_target, backup_sidecars)
            self.assertEqual(set(backup_dir.iterdir()), backup_names)

            restore_dir = root / "restore-target"
            restore_dir.mkdir()
            restore_target = restore_dir / "authority.sqlite3"
            restore_sidecars = self._add_sidecars(restore_target)
            restore_names = set(restore_dir.iterdir())
            with self.assertRaises(BackupDestinationExistsError):
                restore_backup(
                    source,
                    restore_target,
                    manifest=backup.manifest,
                    expected_project_id=backup.manifest.project_id,
                    expected_authority_id=backup.manifest.authority_id,
                    expected_semantic_revision=backup.manifest.semantic_revision,
                )
            self._assert_sidecars_preserved(restore_target, restore_sidecars)
            self.assertEqual(set(restore_dir.iterdir()), restore_names)

            # The successful backup is readable and unchanged; failed attempts
            # above did not affect the source authority or its private snapshot.
            with self.f.open_reader() as authority:
                projected = service.read_model(
                    authority, read_grant.bearer_token,
                    expected_revision=self.f.revision(),
                )
            self.assertEqual(projected.semantic_revision, backup.manifest.semantic_revision)

    def test_dangling_main_symlinks_are_not_publication_targets(self):
        _read_grant, backup_grant = self.fixture._export_grants()
        service = AuthorityExportService(self.f.auth)

        with tempfile.TemporaryDirectory(prefix="todo-r04-dangling-") as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            with self.f.open_reader() as authority:
                backup = service.backup(
                    authority,
                    backup_grant.bearer_token,
                    source,
                    expected_revision=self.f.revision(),
                )

            for operation in ("backup", "restore"):
                with self.subTest(operation=operation):
                    target = root / f"{operation}.sqlite3"
                    referent = root / f"missing-{operation}.sqlite3"
                    target.symlink_to(referent)
                    before = set(root.iterdir())
                    if operation == "backup":
                        with self.f.open_reader() as authority:
                            with self.assertRaises(InvalidAuthorityError):
                                service.backup(
                                    authority,
                                    backup_grant.bearer_token,
                                    target,
                                    expected_revision=self.f.revision(),
                                )
                    else:
                        with self.assertRaises(InvalidAuthorityError):
                            restore_backup(
                                source,
                                target,
                                manifest=backup.manifest,
                                expected_project_id=PROJECT.project_id,
                                expected_authority_id=PROJECT.authority_id,
                                expected_semantic_revision=backup.manifest.semantic_revision,
                            )
                    self.assertTrue(target.is_symlink())
                    self.assertFalse(referent.exists())
                    self.assertEqual(set(root.iterdir()), before)


def load_tests(loader, _tests, _pattern):
    # The imported independent fixture is itself a TestCase; keep this module's
    # discovery focused on the filesystem-specific regressions below.
    return loader.loadTestsFromTestCase(AuthorityExportFilesystemTests)


if __name__ == "__main__":
    unittest.main()
