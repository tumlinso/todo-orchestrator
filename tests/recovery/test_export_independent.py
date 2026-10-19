"""Public export and explicit-restore checks using disposable authority files."""

from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AuthorityNotFoundError,
    CapabilityDeniedError,
    SQLiteAuthority,
)
from todo_orchestrator.contracts import StableId
from todo_orchestrator.operations.export import (
    AUTHORITY_BACKUP_ACTION,
    AUTHORITY_READ_ACTION,
    BackupDestinationExistsError,
    BackupIntegrityError,
    BackupIdentityMismatchError,
    BackupRevisionMismatchError,
    BackupSchemaVersionError,
    AuthorityExportService,
    restore_backup,
)
from todo_orchestrator.verification.acceptance import ACCEPT_OUTCOME_ACTION

from tests.verification import test_acceptance_independent as acceptance_fixtures
from tests.verification.test_execution_independent import PROJECT


class ExportIndependentTests(unittest.TestCase):
    """Exercise semantic views and SQLite recovery via supported public APIs."""

    def setUp(self):
        self.fixture = acceptance_fixtures.IndependentOutcomeAcceptanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture.fixture

    def _export_grants(self):
        f = self.f
        with f.open_writer() as authority:
            read = f.auth.login_local_owner(
                authority,
                acceptance_fixtures.OWNER_PASSWORD,
                actions=(AUTHORITY_READ_ACTION,),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId("r04-export-read-owner"),
                expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            backup = f.auth.login_local_owner(
                authority,
                acceptance_fixtures.OWNER_PASSWORD,
                actions=(AUTHORITY_BACKUP_ACTION,),
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId("r04-export-backup-owner"),
                expected_revision=f.revision(),
            )
        return read, backup

    def _create_accepted_evidence(self):
        f = self.f
        self.fixture.require_artifact_fact()
        f.verification.provider = acceptance_fixtures.ArtifactVerifier(f.ledger_path, f.clock)
        dispatched = self.fixture.dispatch("verify", "r04-evidence-dispatch")
        with f.open_writer() as authority:
            verified = f.verification.execute(
                authority,
                dispatched.bearer_token,
                dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("r04-evidence-verify"),
                expected_revision=f.revision(),
            )
        self.assertEqual(verified.state, "finalized")
        _, candidate = self.fixture.report(
            dispatched.bearer_token,
            dispatched.attempt.ref,
            acceptance_fixtures.OutcomeDisposition.COMPLETED,
            "r04-evidence-report",
        )
        approver = self.fixture.delegate(
            "worker-other",
            (ACCEPT_OUTCOME_ACTION,),
            f.work_ref("verify"),
            "r04-evidence-approver",
        )
        accepted = self.fixture.accept(
            approver.bearer_token,
            dispatched.attempt.ref,
            candidate,
            "r04-evidence-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        with f.open_reader() as authority:
            outcome_id = authority.connection.execute(
                "SELECT outcome_id FROM outcomes WHERE work_item_id = 'verify'"
            ).fetchone()[0]
            provenance = json.loads(authority.connection.execute(
                "SELECT canonical_json FROM outcome_provenance WHERE outcome_id = ?",
                (outcome_id,),
            ).fetchone()[0])
        return verified, StableId(outcome_id), provenance

    def _authority_state(self):
        f = self.f
        with f.open_reader() as authority:
            return (
                f.dispatcher.logical_fingerprint(authority),
                f.revision(),
                authority.connection.execute(
                    "SELECT count(*) FROM authority_events"
                ).fetchone()[0],
            )

    def test_read_model_and_backup_restore_preserve_evidence_and_event_history(self):
        f = self.f
        verified, outcome_id, provenance = self._create_accepted_evidence()
        read_grant, backup_grant = self._export_grants()
        service = AuthorityExportService(f.auth)
        before_read = self._authority_state()
        with f.open_reader() as authority:
            model = service.read_model(
                authority, read_grant.bearer_token, expected_revision=f.revision(),
            )
        self.assertEqual(self._authority_state(), before_read)
        self.assertEqual(model.format, "todo-orchestrator.authority-read-model")
        self.assertEqual(model.version, 1)
        self.assertEqual(model.project_id, PROJECT.project_id)
        self.assertEqual(model.authority_id, PROJECT.authority_id)
        model_json = model.to_json()
        self.assertEqual(model_json, json.dumps(
            model.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ))
        self.assertIn(str(outcome_id), model_json)
        self.assertIn(str(verified.evidence_id), model_json)
        artifact_id = provenance["artifacts"][0]["artifact_id"]
        self.assertIn(artifact_id, model_json)
        # The read model is semantic output, not an authentication export.
        self.assertNotIn(read_grant.bearer_token, model_json)
        self.assertNotIn(backup_grant.bearer_token, model_json)
        with f.open_reader() as authority:
            secrets = [row[0] for row in authority.connection.execute(
                "SELECT token_digest FROM capability_tokens"
            ).fetchall()]
        self.assertTrue(secrets)
        self.assertTrue(all(secret not in model_json for secret in secrets))

        denied_backup_path = f.path.parent / "r04-read-only-must-not-backup.sqlite3"
        before_denial = self._authority_state()
        with f.open_reader() as authority:
            with self.assertRaises(CapabilityDeniedError):
                service.backup(
                    authority, read_grant.bearer_token, denied_backup_path,
                    expected_revision=f.revision(),
                )
        self.assertFalse(denied_backup_path.exists())
        with f.open_reader() as authority:
            with self.assertRaises(CapabilityDeniedError):
                service.read_model(
                    authority, backup_grant.bearer_token,
                    expected_revision=f.revision(),
                )
        self.assertEqual(self._authority_state(), before_denial)

        with tempfile.TemporaryDirectory(prefix="todo-r04-") as temporary:
            root = Path(temporary)
            backup_path = root / "authority.backup.sqlite3"
            restored_path = root / "restored.sqlite3"
            before_backup = self._authority_state()
            with f.open_reader() as authority:
                backup = service.backup(
                    authority,
                    backup_grant.bearer_token,
                    backup_path,
                    expected_revision=f.revision(),
                )
            self.assertEqual(self._authority_state(), before_backup)
            self.assertEqual(backup.destination, backup_path)
            manifest = backup.manifest
            self.assertEqual(manifest.project_id, PROJECT.project_id)
            self.assertEqual(manifest.authority_id, PROJECT.authority_id)
            self.assertEqual(manifest.semantic_revision, model.semantic_revision)
            self.assertEqual(
                manifest.artifact_digest.hex,
                hashlib.sha256(backup_path.read_bytes()).hexdigest(),
            )
            restored = restore_backup(
                backup_path,
                restored_path,
                manifest=manifest,
                expected_project_id=PROJECT.project_id,
                expected_authority_id=PROJECT.authority_id,
                expected_semantic_revision=model.semantic_revision,
            )
            with restored:
                restored_model = service.read_model(
                    restored, read_grant.bearer_token,
                    expected_revision=model.semantic_revision,
                )
                self.assertEqual(restored_model.to_dict(), model.to_dict())
                self.assertEqual(
                    f.dispatcher.logical_fingerprint(restored),
                    manifest.logical_fingerprint.hex,
                )

    def test_missing_authority_read_does_not_create_or_restore_from_a_backup(self):
        f = self.f
        read_grant, _backup_grant = self._export_grants()
        service = AuthorityExportService(f.auth)
        with tempfile.TemporaryDirectory(prefix="todo-r04-missing-") as temporary:
            root = Path(temporary)
            missing = root / "missing.sqlite3"
            before = tuple(sorted(path.name for path in root.iterdir()))
            with self.assertRaises(AuthorityNotFoundError):
                with SQLiteAuthority.open_reader(missing, PROJECT) as authority:
                    service.read_model(authority, read_grant.bearer_token)
            self.assertFalse(missing.exists())
            self.assertEqual(tuple(sorted(path.name for path in root.iterdir())), before)

    def test_restore_rejects_wrong_identity_revision_version_and_tampered_bytes(self):
        f = self.f
        _read_grant, backup_grant = self._export_grants()
        service = AuthorityExportService(f.auth)
        with tempfile.TemporaryDirectory(prefix="todo-r04-invalid-") as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            with f.open_reader() as authority:
                result = service.backup(
                    authority, backup_grant.bearer_token, source,
                    expected_revision=f.revision(),
                )
            manifest = result.manifest

            wrong_identity_target = root / "wrong-identity.sqlite3"
            with self.assertRaises(BackupIdentityMismatchError):
                restore_backup(
                    source, wrong_identity_target, manifest=manifest,
                    expected_project_id=StableId("different-project"),
                    expected_authority_id=PROJECT.authority_id,
                    expected_semantic_revision=manifest.semantic_revision,
                )
            self.assertFalse(wrong_identity_target.exists())

            wrong_revision_target = root / "wrong-revision.sqlite3"
            with self.assertRaises(BackupRevisionMismatchError):
                restore_backup(
                    source, wrong_revision_target, manifest=manifest,
                    expected_project_id=PROJECT.project_id,
                    expected_authority_id=PROJECT.authority_id,
                    expected_semantic_revision=manifest.semantic_revision + 1,
                )
            self.assertFalse(wrong_revision_target.exists())

            wrong_schema_target = root / "wrong-schema.sqlite3"
            with self.assertRaises(BackupSchemaVersionError):
                restore_backup(
                    source, wrong_schema_target,
                    manifest=replace(manifest, schema_version=manifest.schema_version + 1),
                    expected_project_id=PROJECT.project_id,
                    expected_authority_id=PROJECT.authority_id,
                    expected_semantic_revision=manifest.semantic_revision,
                )
            self.assertFalse(wrong_schema_target.exists())

            wrong_version_target = root / "wrong-version.sqlite3"
            with self.assertRaisesRegex(ValueError, "unsupported authority backup manifest"):
                replace(manifest, version=manifest.version + 1)
            self.assertFalse(wrong_version_target.exists())

            tampered = root / "tampered.sqlite3"
            tampered.write_bytes(source.read_bytes() + b"tampered")
            tampered_target = root / "tampered-target.sqlite3"
            with self.assertRaises(BackupIntegrityError):
                restore_backup(
                    tampered, tampered_target, manifest=manifest,
                    expected_project_id=PROJECT.project_id,
                    expected_authority_id=PROJECT.authority_id,
                    expected_semantic_revision=manifest.semantic_revision,
                )
            self.assertFalse(tampered_target.exists())

    def test_backup_and_restore_never_replace_an_existing_target(self):
        f = self.f
        _read_grant, backup_grant = self._export_grants()
        service = AuthorityExportService(f.auth)
        with tempfile.TemporaryDirectory(prefix="todo-r04-no-overwrite-") as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            with f.open_reader() as authority:
                result = service.backup(
                    authority, backup_grant.bearer_token, source,
                    expected_revision=f.revision(),
                )
            source_bytes = source.read_bytes()
            with f.open_reader() as authority:
                with self.assertRaises(BackupDestinationExistsError):
                    service.backup(
                        authority, backup_grant.bearer_token, source,
                        expected_revision=f.revision(),
                    )
            self.assertEqual(source.read_bytes(), source_bytes)

            existing = root / "existing-target.sqlite3"
            marker = b"preserve existing target"
            existing.write_bytes(marker)
            with self.assertRaises(BackupDestinationExistsError):
                restore_backup(
                    source, existing, manifest=result.manifest,
                    expected_project_id=PROJECT.project_id,
                    expected_authority_id=PROJECT.authority_id,
                    expected_semantic_revision=result.manifest.semantic_revision,
                )
            self.assertEqual(existing.read_bytes(), marker)


if __name__ == "__main__":
    unittest.main()
