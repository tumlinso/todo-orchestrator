"""Versioned, data-only verification criteria authored by trusted plans.

These values describe what must be checked. They deliberately contain no
runner, callback, import path, shell expression, or executable predicate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import re
from types import MappingProxyType
from typing import Any, Mapping

from .domain import Sha256Digest, StableId


VERIFICATION_CONTRACT_VERSION = 1
MAX_VERIFICATION_JSON_NODES = 256
MAX_VERIFICATION_DEPTH = 8


class VerificationKind(str, Enum):
    COMMAND = "command"
    FILE = "file"
    ARTIFACT = "artifact"
    BENCHMARK = "benchmark"
    PREDICATE = "predicate"
    INTERFACE = "interface"
    CHECKPOINT = "checkpoint"
    MANUAL_OWNER = "manual_owner"
    DOMAIN_PROVIDER = "domain_provider"


class EvidenceKind(str, Enum):
    COMMAND_RESULT = "command_result"
    FILE_OBSERVATION = "file_observation"
    ARTIFACT_REFERENCE = "artifact_reference"
    BENCHMARK_SAMPLE = "benchmark_sample"
    PREDICATE_RESULT = "predicate_result"
    INTERFACE_OBSERVATION = "interface_observation"
    CHECKPOINT_RECEIPT = "checkpoint_receipt"
    MANUAL_ATTESTATION = "manual_attestation"
    PROVIDER_RECEIPT = "provider_receipt"


def _freeze(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [MAX_VERIFICATION_JSON_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_VERIFICATION_DEPTH:
        raise ValueError("verification configuration exceeds its size limit")
    if value is None or type(value) in {bool, int, str}:
        if isinstance(value, str) and (len(value) > 4096 or any(0xD800 <= ord(c) <= 0xDFFF for c in value)):
            raise ValueError("verification text is invalid or too long")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("verification numbers must be finite")
        return value
    if isinstance(value, list) or isinstance(value, tuple):
        return tuple(_freeze(item, depth=depth + 1, budget=budget) for item in value)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("verification object keys must be strings")
        return MappingProxyType({key: _freeze(item, depth=depth + 1, budget=budget) for key, item in sorted(value.items())})
    raise ValueError("verification configuration must contain JSON values only")


def _mapping(value: Any, required: set[str], optional: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{where} must be an object")
    missing = required - set(value)
    extra = set(value) - required - optional
    if missing:
        raise ValueError(f"{where} is missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{where} has unsupported fields: {', '.join(sorted(extra))}")
    return value


def _text(value: Any, name: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > max_length:
        raise ValueError(f"{name} must be non-empty trimmed text of at most {max_length} characters")
    if any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"{name} contains an unsupported character")
    return value


def _stable_text(value: Any, name: str) -> str:
    return str(StableId(_text(value, name, max_length=128)))


def _relative_path(value: Any, name: str) -> str:
    path = _text(value, name, max_length=1024)
    if name == "command cwd" and path == ".":
        return path
    if path.startswith(("/", "\\")) or "\\" in path or re.match(r"^[A-Za-z]:", path):
        raise ValueError(f"{name} must be a repository-relative POSIX path")
    pieces = path.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise ValueError(f"{name} must not contain empty, dot, or parent path segments")
    return path


def _config(kind: VerificationKind, raw: Any) -> Mapping[str, Any]:
    if kind is VerificationKind.COMMAND:
        item = _mapping(raw, {"argv"}, {"cwd", "timeout_seconds", "expected_exit_codes"}, "command config")
        argv = item["argv"]
        if not isinstance(argv, (list, tuple)) or not argv or len(argv) > 128:
            raise ValueError("command argv must be a non-empty bounded argument array")
        argv = tuple(_text(arg, "command argv item", max_length=2048) for arg in argv)
        cwd = None if "cwd" not in item else _relative_path(item["cwd"], "command cwd")
        timeout = item.get("timeout_seconds", 300)
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 86400:
            raise ValueError("command timeout_seconds must be in (0, 86400]")
        exits = item.get("expected_exit_codes", [0])
        if not isinstance(exits, (list, tuple)) or not exits or len(exits) > 32 or any(type(code) is not int or not 0 <= code <= 255 for code in exits):
            raise ValueError("expected_exit_codes must be a non-empty array of exit codes from 0 to 255")
        if len(set(exits)) != len(exits):
            raise ValueError("expected_exit_codes must not contain duplicates")
        normalized = {"argv": list(argv), "timeout_seconds": timeout, "expected_exit_codes": list(exits)}
        if cwd is not None:
            normalized["cwd"] = cwd
        return _freeze(normalized)
    if kind is VerificationKind.FILE:
        item = _mapping(raw, {"path", "predicate"}, {"sha256"}, "file config")
        predicate = item["predicate"]
        if predicate not in {"exists", "absent", "sha256"}:
            raise ValueError("file predicate must be exists, absent, or sha256")
        if (predicate == "sha256") != ("sha256" in item):
            raise ValueError("file sha256 is required only when predicate is sha256")
        if "sha256" in item:
            Sha256Digest(item["sha256"])
        return _freeze({"path": _relative_path(item["path"], "file path"), "predicate": predicate, **({"sha256": item["sha256"]} if "sha256" in item else {})})
    if kind is VerificationKind.ARTIFACT:
        item = _mapping(raw, {"artifact_kind", "predicate"}, {"sha256"}, "artifact config")
        predicate = item["predicate"]
        if predicate not in {"exists", "sha256"} or ((predicate == "sha256") != ("sha256" in item)):
            raise ValueError("artifact predicate must be exists or sha256 with a matching digest")
        if "sha256" in item:
            Sha256Digest(item["sha256"])
        return _freeze({"artifact_kind": _text(item["artifact_kind"], "artifact_kind"), "predicate": predicate, **({"sha256": item["sha256"]} if "sha256" in item else {})})
    if kind is VerificationKind.BENCHMARK:
        item = _mapping(raw, {"metric", "operator", "threshold", "unit"}, {"minimum_samples"}, "benchmark config")
        if item["operator"] not in {"lt", "lte", "eq", "gte", "gt"}:
            raise ValueError("benchmark operator must be lt, lte, eq, gte, or gt")
        threshold = item["threshold"]
        if type(threshold) not in {int, float} or not math.isfinite(threshold):
            raise ValueError("benchmark threshold must be a finite number")
        samples = item.get("minimum_samples", 1)
        if type(samples) is not int or not 1 <= samples <= 100000:
            raise ValueError("minimum_samples must be an integer from 1 to 100000")
        return _freeze({"metric": _text(item["metric"], "benchmark metric"), "operator": item["operator"], "threshold": threshold, "unit": _text(item["unit"], "benchmark unit"), "minimum_samples": samples})
    if kind is VerificationKind.PREDICATE:
        item = _mapping(raw, {"name", "semantics_version", "operator", "expected"}, {"path"}, "predicate config")
        if item["semantics_version"] != 1 or type(item["semantics_version"]) is not int:
            raise ValueError("predicate semantics_version must be 1")
        if item["operator"] not in {"equals", "not_equals", "contains", "nonempty", "count_at_least", "sha256_equals"}:
            raise ValueError("predicate operator is not supported by semantics version 1")
        normalized = {"name": _text(item["name"], "predicate name"), "semantics_version": 1, "operator": item["operator"], "expected": _freeze(item["expected"])}
        if "path" in item:
            normalized["path"] = _relative_path(item["path"], "predicate path")
        if item["operator"] in {"count_at_least"} and (type(item["expected"]) is not int or item["expected"] < 0):
            raise ValueError("count_at_least expected value must be a non-negative integer")
        if item["operator"] == "sha256_equals":
            Sha256Digest(item["expected"])
        return _freeze(normalized)
    if kind is VerificationKind.INTERFACE:
        item = _mapping(raw, {"interface_id", "version", "compatibility"}, set(), "interface config")
        if item["compatibility"] not in {"frozen", "evolvable"}:
            raise ValueError("interface compatibility must be frozen or evolvable")
        version = _text(item["version"], "interface version")
        if re.fullmatch(r"(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?", version) is None:
            raise ValueError("interface version must use numeric major[.minor[.patch]] notation")
        return _freeze({"interface_id": _stable_text(item["interface_id"], "interface_id"), "version": version, "compatibility": item["compatibility"]})
    if kind is VerificationKind.CHECKPOINT:
        item = _mapping(raw, {"checkpoint_id", "required_state"}, set(), "checkpoint config")
        if item["required_state"] not in {"reached", "accepted"}:
            raise ValueError("checkpoint required_state must be reached or accepted")
        return _freeze({"checkpoint_id": _stable_text(item["checkpoint_id"], "checkpoint_id"), "required_state": item["required_state"]})
    if kind is VerificationKind.MANUAL_OWNER:
        item = _mapping(raw, {"approver_role", "actor_id", "incarnation_id"}, set(), "manual_owner config")
        if item["approver_role"] not in {"owner", "maintainer", "reviewer", "project_admin"}:
            raise ValueError("manual approver_role is unsupported")
        return _freeze({"approver_role": item["approver_role"], "actor_id": _stable_text(item["actor_id"], "actor_id"), "incarnation_id": _stable_text(item["incarnation_id"], "incarnation_id")})
    if kind is VerificationKind.DOMAIN_PROVIDER:
        item = _mapping(raw, {"provider_id", "provider_version", "contract_id", "contract_version", "parameters"}, set(), "domain_provider config")
        provider_version = _text(item["provider_version"], "provider_version")
        if type(item["contract_version"]) is not int or item["contract_version"] < 1:
            raise ValueError("contract_version must be a positive integer")
        if not isinstance(item["parameters"], Mapping):
            raise ValueError("domain provider parameters must be a bounded JSON object")
        return _freeze({"provider_id": _stable_text(item["provider_id"], "provider_id"), "provider_version": provider_version, "contract_id": _stable_text(item["contract_id"], "contract_id"), "contract_version": item["contract_version"], "parameters": item["parameters"]})
    raise ValueError(f"unsupported verification kind {kind.value}")


@dataclass(frozen=True)
class VerificationContract:
    kind: VerificationKind
    version: int
    config: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, VerificationKind):
            raise TypeError("kind must be a VerificationKind")
        if type(self.version) is not int or self.version != VERIFICATION_CONTRACT_VERSION:
            raise ValueError(f"verification contract version must be {VERIFICATION_CONTRACT_VERSION}")
        normalized = _config(self.kind, dict(self.config))
        object.__setattr__(self, "config", normalized)

    @classmethod
    def from_mapping(cls, value: Any) -> "VerificationContract":
        item = _mapping(value, {"kind", "version", "config"}, set(), "verification contract")
        try:
            kind = VerificationKind(item["kind"])
        except (TypeError, ValueError) as error:
            raise ValueError("verification kind is unsupported") from error
        return cls(kind, item["version"], item["config"])

    def to_mapping(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "version": self.version, "config": _thaw(self.config)}


@dataclass(frozen=True)
class EvidenceRequirement:
    name: StableId
    kind: EvidenceKind
    version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.name, StableId) or not isinstance(self.kind, EvidenceKind):
            raise TypeError("evidence name and kind must use their declared types")
        _text(str(self.name), "evidence name", max_length=128)
        if type(self.version) is not int or self.version != 1:
            raise ValueError("evidence contract version must be 1")

    @classmethod
    def from_mapping(cls, value: Any) -> "EvidenceRequirement":
        item = _mapping(value, {"name", "kind", "version"}, set(), "required evidence")
        try:
            kind = EvidenceKind(item["kind"])
        except (TypeError, ValueError) as error:
            raise ValueError("required evidence kind is unsupported") from error
        return cls(StableId(_text(item["name"], "evidence name", max_length=128)), kind, item["version"])

    def to_mapping(self) -> dict[str, Any]:
        return {"name": str(self.name), "kind": self.kind.value, "version": self.version}


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


__all__ = [
    "VERIFICATION_CONTRACT_VERSION", "EvidenceKind", "EvidenceRequirement",
    "VerificationContract", "VerificationKind",
]
