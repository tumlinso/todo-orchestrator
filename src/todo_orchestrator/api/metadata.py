"""Versioned project-local metadata for the standalone application API."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile

from todo_orchestrator.contracts import Project, StableId


PROJECT_METADATA_FORMAT = "todo-orchestrator.project-metadata"
PROJECT_METADATA_VERSION = 1
PROJECT_METADATA_RELATIVE_PATH = Path(".todo-orchestrator") / "project.json"
AUTHORITY_RELATIVE_PATH = Path(".todo-orchestrator") / "authority.sqlite3"
MAX_METADATA_BYTES = 16 * 1024


class ProjectMetadataError(RuntimeError):
    """Project metadata is missing, malformed, or from an unsupported version."""


class ProjectMetadataExistsError(ProjectMetadataError, FileExistsError):
    """Initialization refuses to replace an existing project record."""


@dataclass(frozen=True)
class ProjectMetadataV1:
    format: str
    version: int
    project_id: StableId
    repository_id: StableId
    authority_id: StableId
    authority_path: str = AUTHORITY_RELATIVE_PATH.as_posix()

    def __post_init__(self) -> None:
        if self.format != PROJECT_METADATA_FORMAT or type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported project metadata format")
        for value in (self.project_id, self.repository_id, self.authority_id):
            if not isinstance(value, StableId):
                raise TypeError("project metadata identities must use StableId values")
        if self.authority_path != AUTHORITY_RELATIVE_PATH.as_posix():
            raise ValueError("authority_path must use the fixed project-local authority location")

    @property
    def project(self) -> Project:
        return Project(self.project_id, self.authority_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "version": self.version,
            "project_id": str(self.project_id),
            "repository_id": str(self.repository_id),
            "authority_id": str(self.authority_id),
            "authority_path": self.authority_path,
        }

    def to_json(self) -> str:
        encoded = json.dumps(self.to_dict(), ensure_ascii=True, allow_nan=False,
                             sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError("project metadata exceeds its size limit")
        return encoded

    @classmethod
    def from_json(cls, encoded: str) -> "ProjectMetadataV1":
        if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ProjectMetadataError("project metadata is absent or exceeds its size limit")
        try:
            value = json.loads(encoded, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
        except (TypeError, ValueError):
            raise ProjectMetadataError("project metadata is not valid JSON") from None
        expected = {"format", "version", "project_id", "repository_id", "authority_id", "authority_path"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ProjectMetadataError("project metadata fields do not match version 1")
        if type(value["version"]) is not int:
            raise ProjectMetadataError("project metadata version must be an integer")
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        if canonical != encoded:
            raise ProjectMetadataError("project metadata must use canonical JSON encoding")
        try:
            return cls(value["format"], value["version"], StableId(value["project_id"]),
                       StableId(value["repository_id"]), StableId(value["authority_id"]),
                       value["authority_path"])
        except (TypeError, ValueError) as exc:
            raise ProjectMetadataError("project metadata identity is invalid") from exc


def project_metadata_path(project_root: str | os.PathLike[str]) -> Path:
    root = Path(project_root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ProjectMetadataError("project root must be an existing directory")
    return root / PROJECT_METADATA_RELATIVE_PATH


def authority_path(project_root: str | os.PathLike[str], metadata: ProjectMetadataV1) -> Path:
    if not isinstance(metadata, ProjectMetadataV1):
        raise TypeError("metadata must be ProjectMetadataV1")
    root = Path(project_root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ProjectMetadataError("project root must be an existing directory")
    candidate = (root / metadata.authority_path).resolve(strict=False)
    if candidate != root / AUTHORITY_RELATIVE_PATH:
        raise ProjectMetadataError("authority metadata escaped the project-local data directory")
    return candidate


def read_project_metadata(project_root: str | os.PathLike[str]) -> ProjectMetadataV1:
    path = project_metadata_path(project_root)
    if path.is_symlink() or not path.is_file():
        raise ProjectMetadataError("standalone project metadata is missing or is not a regular file")
    try:
        encoded = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProjectMetadataError("standalone project metadata could not be read") from exc
    return ProjectMetadataV1.from_json(encoded)


def write_project_metadata_no_replace(project_root: str | os.PathLike[str], metadata: ProjectMetadataV1) -> Path:
    path = project_metadata_path(project_root)
    directory = path.parent
    if directory.is_symlink():
        raise ProjectMetadataError("project metadata directory must not be a symbolic link")
    directory.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ProjectMetadataExistsError("project metadata already exists; refusing to replace it")
    encoded = metadata.to_json().encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=".project-metadata-", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ProjectMetadataExistsError("project metadata already exists; refusing to replace it") from exc
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


__all__ = [
    "AUTHORITY_RELATIVE_PATH", "PROJECT_METADATA_FORMAT", "PROJECT_METADATA_RELATIVE_PATH",
    "PROJECT_METADATA_VERSION", "ProjectMetadataError", "ProjectMetadataExistsError",
    "ProjectMetadataV1", "authority_path", "project_metadata_path", "read_project_metadata",
    "write_project_metadata_no_replace",
]
