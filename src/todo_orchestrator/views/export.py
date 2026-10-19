"""Versioned, sanitized authority read models and private backup manifests."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from todo_orchestrator.contracts import Sha256Digest, StableId


AUTHORITY_READ_MODEL_FORMAT = "todo-orchestrator.authority-read-model"
AUTHORITY_BACKUP_FORMAT = "todo-orchestrator.sqlite-backup"


class _FrozenDict(dict):
    """JSON-compatible immutable mapping that remains dataclasses.asdict-safe."""

    def __init__(self, values=(), **kwargs):
        dict.__init__(self, values, **kwargs)

    def _immutable(self, *args, **kwargs):
        raise TypeError("authority read model values are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _immutable


def _freeze_row(row: Mapping[str, object]) -> dict[str, object]:
    frozen: dict[str, object] = {}
    for key, value in row.items():
        if not isinstance(key, str) or value is not None and type(value) not in {str, int, bool}:
            raise TypeError("read model rows may contain only string keys and scalar JSON values")
        frozen[key] = value
    return _FrozenDict(frozen)


@dataclass(frozen=True)
class AuthorityReadModelV1:
    """Sanitized stable projection of project authority state.

    `sections` contains structured plan meaning and metadata, but deliberately
    omits capability tokens, credential verifiers, message bodies, contextual
    finding text, and provider request/receipt payloads. Complete private state
    belongs in the explicit SQLite backup operation instead.
    """

    format: str
    version: int
    project_id: StableId
    authority_id: StableId
    schema_version: int
    semantic_revision: int
    sections: Mapping[str, tuple[Mapping[str, object], ...]]

    def __post_init__(self) -> None:
        if self.format != AUTHORITY_READ_MODEL_FORMAT or type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported authority read model format")
        if not isinstance(self.project_id, StableId) or not isinstance(self.authority_id, StableId):
            raise TypeError("read model identity must use StableId values")
        if type(self.schema_version) is not int or self.schema_version <= 0:
            raise ValueError("schema_version must be positive")
        if type(self.semantic_revision) is not int or self.semantic_revision < 0:
            raise ValueError("semantic_revision must be non-negative")
        if not isinstance(self.sections, Mapping):
            raise TypeError("sections must be a mapping")
        normalized: dict[str, tuple[Mapping[str, object], ...]] = {}
        for name, rows in self.sections.items():
            if not isinstance(name, str) or not name or not isinstance(rows, tuple):
                raise TypeError("read model sections must map names to tuples of rows")
            # Store ordinary dictionaries so standard dataclass tooling such
            # as `dataclasses.asdict` can serialize this public DTO.
            normalized[name] = tuple(_freeze_row(row) for row in rows)
        object.__setattr__(self, "sections", _FrozenDict(normalized))

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "version": self.version,
            "project_id": str(self.project_id),
            "authority_id": str(self.authority_id),
            "schema_version": self.schema_version,
            "semantic_revision": self.semantic_revision,
            "sections": {
                name: [dict(row) for row in rows]
                for name, rows in sorted(self.sections.items())
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, encoded: str) -> AuthorityReadModelV1:
        try:
            value = json.loads(encoded, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
        except (TypeError, ValueError) as exc:
            raise ValueError("authority read model is not valid JSON") from exc
        expected = {
            "format", "version", "project_id", "authority_id", "schema_version",
            "semantic_revision", "sections",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("authority read model fields do not match version 1")
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        if canonical != encoded:
            raise ValueError("authority read model must use canonical JSON encoding")
        for key in ("version", "schema_version", "semantic_revision"):
            if type(value[key]) is not int:
                raise ValueError(f"authority read model {key} must be an integer")
        raw_sections = value["sections"]
        if not isinstance(raw_sections, dict):
            raise ValueError("authority read model sections must be an object")
        sections: dict[str, tuple[Mapping[str, object], ...]] = {}
        for name, rows in raw_sections.items():
            if not isinstance(name, str) or not isinstance(rows, list):
                raise ValueError("authority read model section rows must be arrays")
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError("authority read model rows must be objects")
            sections[name] = tuple(rows)
        return cls(
            value["format"], value["version"], StableId(value["project_id"]),
            StableId(value["authority_id"]), value["schema_version"], value["semantic_revision"], sections,
        )


@dataclass(frozen=True)
class AuthorityBackupManifest:
    """External verification record for a private SQLite authority backup.

    Keep this manifest with the backup artifact. Its hashes detect accidental
    corruption when the manifest is trusted; the record is not a signature.
    """

    format: str
    version: int
    project_id: StableId
    authority_id: StableId
    schema_version: int
    semantic_revision: int
    logical_fingerprint: Sha256Digest
    artifact_digest: Sha256Digest

    def __post_init__(self) -> None:
        if self.format != AUTHORITY_BACKUP_FORMAT or type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported authority backup manifest format")
        if not isinstance(self.project_id, StableId) or not isinstance(self.authority_id, StableId):
            raise TypeError("backup identity must use StableId values")
        if type(self.schema_version) is not int or self.schema_version <= 0:
            raise ValueError("schema_version must be positive")
        if type(self.semantic_revision) is not int or self.semantic_revision < 0:
            raise ValueError("semantic_revision must be non-negative")
        if not isinstance(self.logical_fingerprint, Sha256Digest) or not isinstance(self.artifact_digest, Sha256Digest):
            raise TypeError("backup hashes must use Sha256Digest values")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "version": self.version,
            "project_id": str(self.project_id),
            "authority_id": str(self.authority_id),
            "schema_version": self.schema_version,
            "semantic_revision": self.semantic_revision,
            "logical_fingerprint": self.logical_fingerprint.hex,
            "artifact_digest": self.artifact_digest.hex,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, encoded: str) -> AuthorityBackupManifest:
        try:
            value = json.loads(encoded, parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
        except (TypeError, ValueError) as exc:
            raise ValueError("backup manifest is not valid JSON") from exc
        expected = {
            "format", "version", "project_id", "authority_id", "schema_version",
            "semantic_revision", "logical_fingerprint", "artifact_digest",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("backup manifest fields do not match version 1")
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        if canonical != encoded:
            raise ValueError("backup manifest must use canonical JSON encoding")
        if type(value["version"]) is not int or type(value["schema_version"]) is not int or type(value["semantic_revision"]) is not int:
            raise ValueError("backup manifest numeric fields must be integers")
        return cls(
            value["format"], value["version"], StableId(value["project_id"]),
            StableId(value["authority_id"]), value["schema_version"], value["semantic_revision"],
            Sha256Digest(value["logical_fingerprint"]), Sha256Digest(value["artifact_digest"]),
        )


@dataclass(frozen=True)
class AuthorityBackupResult:
    manifest: AuthorityBackupManifest
    destination: Path


__all__ = [
    "AUTHORITY_BACKUP_FORMAT", "AUTHORITY_READ_MODEL_FORMAT", "AuthorityBackupManifest",
    "AuthorityBackupResult", "AuthorityReadModelV1",
]
