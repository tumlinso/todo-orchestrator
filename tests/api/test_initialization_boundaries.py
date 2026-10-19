"""Explicit project initialization preserves existing and missing-state projects."""

import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest

from todo_orchestrator.api import (
    ProjectMetadataExistsError, ProjectUnavailableError, ProviderComposition, TodoApplication,
)
from todo_orchestrator.contracts import StableId


CREDENTIAL = "temporary native owner credential 937"


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        kind = "link" if path.is_symlink() else "directory" if path.is_dir() else "file"
        value = str(path.readlink()) if kind == "link" else (
            hashlib.sha256(path.read_bytes()).hexdigest() if kind == "file" else None
        )
        result[str(path.relative_to(root))] = (kind, stat.S_IMODE(mode), value)
    return result


class InitializationBoundaryTests(unittest.TestCase):
    def initialize(self, root):
        return TodoApplication.initialize(
            root, project_id=StableId("native-boundary-project"),
            authority_id=StableId("native-boundary-authority"),
            repository_id=StableId("native-boundary-repository"),
            owner_credential=CREDENTIAL, providers=ProviderComposition(),
        )

    def test_legacy_metadata_and_unknown_files_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / ".todo-orchestrator"
            metadata.mkdir()
            (metadata / "project.json").write_text(json.dumps({
                "project_id": "preserved-legacy-project",
                "configuration": {"workflow_front_door": "coding-workflow"},
            }))
            (metadata / "state.snapshot.json").write_bytes(b"preserved legacy projection\n")
            (root / "unknown.bin").write_bytes(b"preserve\x00these\xffbytes")
            before = snapshot(root)
            with self.assertRaises(ProjectMetadataExistsError):
                with self.initialize(root):
                    pass
            self.assertEqual(snapshot(root), before)

    def test_invalid_owner_credential_is_refused_before_project_state_is_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = snapshot(root)
            with self.assertRaises(ValueError):
                TodoApplication.initialize(
                    root, project_id=StableId("invalid-credential-project"),
                    repository_id=StableId("invalid-credential-repository"),
                    owner_credential="short", providers=ProviderComposition(),
                )
            self.assertEqual(snapshot(root), before)

    def test_missing_native_database_cannot_be_replaced_by_empty_reinitialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            with self.initialize(root) as session:
                token_path = Path(temporary) / "owner.token"
                session.write_bearer(token_path)
            bearer = token_path.read_text().strip()
            database = root / ".todo-orchestrator" / "authority.sqlite3"
            self.assertTrue(database.is_file())
            database.unlink()  # Simulate loss only inside this disposable fixture.
            before = snapshot(root)
            with self.assertRaises(ProjectMetadataExistsError):
                with self.initialize(root):
                    pass
            self.assertEqual(snapshot(root), before)
            for open_session in (
                lambda: TodoApplication.open(root, bearer_token=bearer, providers=ProviderComposition()),
                lambda: TodoApplication.login_owner(
                    root, owner_credential=CREDENTIAL, providers=ProviderComposition(),
                ),
            ):
                with self.assertRaises(ProjectUnavailableError):
                    with open_session():
                        pass
                self.assertEqual(snapshot(root), before)
