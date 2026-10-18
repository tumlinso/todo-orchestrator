"""Pure parser and compiler for versioned Todo Orchestrator plan packages."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
import unicodedata
from types import MappingProxyType
from typing import Any, Mapping

from todo_orchestrator.contracts.domain import (
    EntityKind,
    EntityRef,
    OutcomeDisposition,
    PlanRevision,
    Project,
    Requirement,
    RequirementGroup,
    RequirementKind,
    RequirementMode,
    Sha256Digest,
    SourceProvenance,
    StableId,
    WorkItem,
)


PLAN_FORMAT = "todo-orchestrator.plan"
PLAN_SCHEMA_VERSION = 1
MAX_CONDITION_DEPTH = 16
MAX_CONDITION_NODES = 256


class DiagnosticSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class PlanDiagnostic:
    code: str
    message: str
    path: str
    severity: DiagnosticSeverity = DiagnosticSeverity.ERROR


@dataclass(frozen=True)
class ParseResult:
    package: PlanPackageInput | None
    diagnostics: tuple[PlanDiagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return self.package is not None and not any(
            item.severity is DiagnosticSeverity.ERROR for item in self.diagnostics
        )


@dataclass(frozen=True)
class CompileResult:
    plan: CompiledPlan | None
    diagnostics: tuple[PlanDiagnostic, ...] = ()
    graph_validation: GraphValidation | None = None

    @property
    def ok(self) -> bool:
        return self.plan is not None and not any(
            item.severity is DiagnosticSeverity.ERROR for item in self.diagnostics
        )


@dataclass(frozen=True)
class PlanPackageInput:
    """Validated, normalized input independent of any authority or database."""

    document: Mapping[str, Any]
    source: str
    source_digest: Sha256Digest
    content_digest: Sha256Digest
    supplied_sections: tuple[str, ...]
    source_manifests_supplied: bool
    generation_metadata_supplied: bool
    record_field_masks: Mapping[str, Mapping[str, tuple[str, ...]]]


@dataclass(frozen=True)
class SourceManifest:
    source_id: StableId
    location: str
    digest: Sha256Digest


@dataclass(frozen=True)
class AdoptionReceipt:
    receipt_id: StableId
    authority_id: StableId
    contract_digest: Sha256Digest


@dataclass(frozen=True)
class VerifiedAdoption:
    """Trusted caller-supplied fact binding a receipt to one exact foreign ref."""

    verification_id: StableId
    declared_kind: str
    reference: EntityRef
    receipt: AdoptionReceipt
    interface_version: str | None = None
    compatibility: str | None = None


@dataclass(frozen=True)
class QualifiedReference:
    reference: EntityRef
    declared_kind: str
    adoption_receipt: AdoptionReceipt | None = None


@dataclass(frozen=True)
class WorkItemContext:
    """Authored fields kept beside the canonical domain WorkItem value."""

    objective: str
    motivation: str | None
    references: tuple[Mapping[str, str], ...]
    scope: Mapping[str, Any]
    acceptance: Mapping[str, Any]
    alternatives: tuple[Mapping[str, Any], ...]
    unknowns: tuple[str, ...]
    delegated_judgment: tuple[str, ...]
    ownership: OwnershipConstraint


@dataclass(frozen=True)
class OwnershipConstraint:
    mode: str
    actors: tuple[QualifiedReference, ...]


@dataclass(frozen=True)
class PlannedWorkItem:
    definition: WorkItem
    context: WorkItemContext


@dataclass(frozen=True)
class PlannedRequirement:
    definition: Requirement
    target: QualifiedReference | None


@dataclass(frozen=True)
class PlanDeclaration:
    """Versioned non-work declaration retained as immutable authored data."""

    kind: str
    declaration_id: StableId
    payload: Mapping[str, Any]


class BlockerRelation(str, Enum):
    COMPLETION = "completion"
    CHECKPOINT_ACCEPTED = "checkpoint_accepted"
    INTERFACE_VERSION = "interface_version"
    EVIDENCE_VERIFIED = "evidence_verified"
    DECISION_RESOLVED = "decision_resolved"
    BARRIER_RELEASED = "barrier_released"
    RENDEZVOUS_MET = "rendezvous_met"


@dataclass(frozen=True)
class ConditionExpression:
    """A bounded, typed condition tree; it is never evaluated as Python code."""

    op: str
    arguments: tuple[tuple[str, Any], ...]


def _compile_condition(value: Mapping[str, Any]) -> ConditionExpression:
    arguments = []
    for key, item in value.items():
        if key == "op":
            continue
        if key == "condition":
            item = _compile_condition(item)
        elif key == "conditions":
            item = tuple(_compile_condition(child) for child in item)
        arguments.append((key, item))
    return ConditionExpression(value["op"], tuple(arguments))


@dataclass(frozen=True)
class BlockingEdge:
    relation: BlockerRelation
    target: QualifiedReference
    expected_version: str | None = None
    condition: ConditionExpression | None = None


@dataclass(frozen=True)
class BlockingGroup:
    source: QualifiedReference
    mode: RequirementMode
    quorum: int | None
    members: tuple[BlockingEdge, ...]


@dataclass(frozen=True)
class CompiledPlan:
    """Deterministic typed proposal for a later authority preview/commit."""

    package_id: StableId
    project: Project
    revision: PlanRevision
    work_items: tuple[PlannedWorkItem, ...]
    requirements: tuple[PlannedRequirement, ...]
    declarations: tuple[PlanDeclaration, ...]
    blocking_groups: tuple[BlockingGroup, ...]
    source_manifests: tuple[SourceManifest, ...]
    generation_metadata: Mapping[str, Any] | None
    source_manifests_supplied: bool
    generation_metadata_supplied: bool
    supplied_sections: tuple[str, ...]
    verified_adoptions: tuple[VerifiedAdoption, ...]
    canonical_json: str
    content_digest: Sha256Digest
    record_field_masks: Mapping[str, Mapping[str, tuple[str, ...]]]


class _InputFailure(Exception):
    def __init__(self, code: str, path: str, message: str):
        super().__init__(message)
        self.diagnostic = PlanDiagnostic(code, message, path)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """Convert immutable compiler values back to JSON-compatible containers."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _fail(code: str, path: str, message: str) -> None:
    raise _InputFailure(code, path, message)


def _object(value: Any, path: str, *, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("expected_object", path, "expected an object")
    unknown = sorted(set(value) - required - optional)
    if unknown:
        _fail("unknown_field", f"{path}/{unknown[0]}", f"unsupported field {unknown[0]!r}")
    missing = sorted(required - set(value))
    if missing:
        _fail("missing_field", f"{path}/{missing[0]}", f"required field {missing[0]!r} is missing")
    return value


def _string(value: Any, path: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        _fail("expected_string", path, "expected a string")
    # Join valid JSON surrogate pairs and reject lone surrogates before UTF-8 encoding.
    normalized: list[str] = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 >= len(value) or not 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
                _fail("invalid_unicode", path, "string contains an unpaired Unicode surrogate")
            low = ord(value[index + 1])
            normalized.append(chr(0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)))
            index += 2
            continue
        if 0xDC00 <= codepoint <= 0xDFFF:
            _fail("invalid_unicode", path, "string contains an unpaired Unicode surrogate")
        normalized.append(value[index])
        index += 1
    value = "".join(normalized)
    if nonempty and (not value or value != value.strip()):
        _fail("invalid_string", path, "string must be non-empty and have no surrounding whitespace")
    if any(unicodedata.category(char) == "Cc" for char in value):
        _fail("invalid_string", path, "string must not contain control characters")
    return value


def _generation_metadata(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("expected_object", path, "generation metadata must be a structured object")
    if len(value) > 32:
        _fail("metadata_too_large", path, "generation metadata may contain at most 32 top-level fields")
    count = [0]

    def visit(item: Any, item_path: str, depth: int) -> Any:
        count[0] += 1
        if count[0] > 256:
            _fail("metadata_too_large", path, "generation metadata may contain at most 256 values")
        if depth > 8:
            _fail("metadata_too_deep", item_path, "generation metadata is limited to 8 nested levels")
        if isinstance(item, dict):
            output = {}
            for key, nested in item.items():
                normalized_key = _string(key, f"{item_path}/<key>")
                output[normalized_key] = visit(nested, f"{item_path}/{normalized_key}", depth + 1)
            return output
        if isinstance(item, list):
            return [visit(nested, f"{item_path}/{index}", depth + 1) for index, nested in enumerate(item)]
        if item is None or isinstance(item, (bool, int, float, str)):
            if isinstance(item, float) and (item != item or item in (float("inf"), float("-inf"))):
                _fail("invalid_number", item_path, "non-finite numbers are not supported")
            return _string(item, item_path, nonempty=False) if isinstance(item, str) else item
        _fail("invalid_json_value", item_path, "value is not representable in JSON")

    return visit(value, path, 0)


def _id(value: Any, path: str) -> str:
    text = _string(value, path)
    try:
        StableId(text)
    except (TypeError, ValueError) as error:
        _fail("invalid_id", path, str(error))
    return text


def _string_list(value: Any, path: str, *, unique: bool = False) -> list[str]:
    if not isinstance(value, list):
        _fail("expected_array", path, "expected an array of strings")
    result = [_string(item, f"{path}/{index}") for index, item in enumerate(value)]
    if unique and len(set(result)) != len(result):
        _fail("duplicate_value", path, "array values must be unique")
    return result


def _json_value(value: Any, path: str, depth: int = 0) -> Any:
    if depth > 32:
        _fail("value_too_deep", path, "JSON values are limited to 32 nested levels")
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            _fail("invalid_number", path, "non-finite numbers are not supported")
        if isinstance(value, str):
            _string(value, path, nonempty=False)
        return value
    if isinstance(value, list):
        return [_json_value(item, f"{path}/{index}", depth + 1) for index, item in enumerate(value)]
    if isinstance(value, dict):
        for key in value:
            _string(key, f"{path}/<key>")
        return {key: _json_value(item, f"{path}/{key}", depth + 1) for key, item in value.items()}
    _fail("invalid_json_value", path, "value is not representable in JSON")


def _safe_path(value: Any, path: str) -> str:
    text = _string(value, path)
    if text.startswith("/") or "\\" in text or re.match(r"^[A-Za-z]:", text):
        _fail("unsafe_path", path, "scope path must be a relative POSIX path")
    if unicodedata.normalize("NFC", text) != text:
        _fail("noncanonical_path", path, "scope path must use Unicode NFC normalization")
    if any(char in text for char in "*?[]"):
        _fail("ambiguous_path", path, "glob patterns are not valid scope paths")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail("unsafe_path", path, "scope path must not contain empty, '.' or '..' segments")
    if any(":" in part for part in parts):
        _fail("ambiguous_path", path, "scope path segments must not contain ':'")
    return "/".join(parts)


def _validate_scope(value: Any, path: str) -> dict[str, Any]:
    scope = _object(value, path, required={"paths", "concepts"}, optional={"locks"})
    if not isinstance(scope["paths"], list):
        _fail("expected_array", f"{path}/paths", "expected an array of typed paths")
    paths: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(scope["paths"]):
        p = f"{path}/paths/{index}"
        item = _object(raw, p, required={"path", "access"})
        scoped_path = _safe_path(item["path"], f"{p}/path")
        access = _string(item["access"], f"{p}/access")
        if access not in {"read", "write", "forbidden"}:
            _fail("unsupported_scope_access", f"{p}/access", "access must be read, write, or forbidden")
        if scoped_path in seen:
            _fail("ambiguous_scope", f"{p}/path", "a path may appear only once in a scope")
        seen.add(scoped_path)
        paths.append({"path": scoped_path, "access": access})
    paths.sort(key=lambda item: item["path"])
    concepts = _string_list(scope["concepts"], f"{path}/concepts", unique=True)
    locks_raw = scope.get("locks", [])
    if not isinstance(locks_raw, list):
        _fail("expected_array", f"{path}/locks", "expected an array of named locks")
    locks: list[dict[str, str]] = []
    lock_names: set[str] = set()
    for index, raw in enumerate(locks_raw):
        lock_path = f"{path}/locks/{index}"
        lock = _object(raw, lock_path, required={"name", "mode"})
        name = _id(lock["name"], f"{lock_path}/name")
        mode = _string(lock["mode"], f"{lock_path}/mode")
        if mode not in {"shared", "exclusive"}:
            _fail("unsupported_lock_mode", f"{lock_path}/mode", "lock mode must be shared or exclusive")
        if name in lock_names:
            _fail("duplicate_lock", f"{lock_path}/name", f"named lock {name!r} is repeated")
        lock_names.add(name)
        locks.append({"name": name, "mode": mode})
    locks.sort(key=lambda item: item["name"])
    return {"paths": paths, "concepts": sorted(concepts), "locks": locks}


def _validate_acceptance(value: Any, path: str) -> dict[str, Any]:
    acceptance = _object(
        value,
        path,
        required={"assertions", "required_evidence", "allowed_dispositions"},
    )
    assertions = _string_list(acceptance["assertions"], f"{path}/assertions")
    evidence = _string_list(acceptance["required_evidence"], f"{path}/required_evidence", unique=True)
    dispositions = _string_list(acceptance["allowed_dispositions"], f"{path}/allowed_dispositions", unique=True)
    allowed = {item.value for item in OutcomeDisposition}
    unsupported = sorted(set(dispositions) - allowed)
    if unsupported:
        _fail("unsupported_disposition", f"{path}/allowed_dispositions", f"unsupported disposition {unsupported[0]!r}")
    return {
        "assertions": assertions,
        "required_evidence": sorted(evidence),
        "allowed_dispositions": sorted(dispositions),
    }


def _validate_reference(value: Any, path: str, project_id: str) -> dict[str, Any]:
    ref = _object(
        value,
        path,
        required={"project_id", "kind", "entity_id"},
        optional={"revision_id", "incarnation_id", "adoption_receipt"},
    )
    ref_project = _id(ref["project_id"], f"{path}/project_id")
    kind = _string(ref["kind"], f"{path}/kind")
    try:
        entity_kind = EntityKind.BARRIER if kind == "rendezvous" else EntityKind(kind)
    except ValueError:
        _fail("unsupported_reference_kind", f"{path}/kind", f"unsupported entity kind {kind!r}")
    if kind == "rendezvous":
        entity_kind = EntityKind.BARRIER
    entity_id = _id(ref["entity_id"], f"{path}/entity_id")
    revision_id = ref.get("revision_id")
    if revision_id is not None:
        revision_id = _id(revision_id, f"{path}/revision_id")
    revisioned = entity_kind in {EntityKind.WORK_ITEM, EntityKind.REQUIREMENT}
    if revisioned and revision_id is None and ref_project != project_id:
        _fail("ambiguous_reference", f"{path}/revision_id", "work item and requirement references require revision_id")
    if not revisioned and revision_id is not None:
        _fail("invalid_reference", f"{path}/revision_id", "revision_id is only valid for work item and requirement references")
    incarnation_id = ref.get("incarnation_id")
    if entity_kind is EntityKind.ACTOR:
        if incarnation_id is None:
            _fail("ambiguous_actor_reference", f"{path}/incarnation_id", "actor references require an exact incarnation_id")
        incarnation_id = _id(incarnation_id, f"{path}/incarnation_id")
    elif incarnation_id is not None:
        _fail("invalid_reference", f"{path}/incarnation_id", "incarnation_id is only valid for actor references")
    receipt_raw = ref.get("adoption_receipt")
    receipt = None
    if ref_project != project_id:
        if receipt_raw is None:
            _fail("foreign_reference_unadopted", path, "cross-project references require an explicit adoption_receipt")
        receipt_obj = _object(
            receipt_raw,
            f"{path}/adoption_receipt",
            required={"receipt_id", "authority_id", "contract_digest"},
        )
        digest = _string(receipt_obj["contract_digest"], f"{path}/adoption_receipt/contract_digest")
        try:
            Sha256Digest(digest)
        except ValueError as error:
            _fail("invalid_digest", f"{path}/adoption_receipt/contract_digest", str(error))
        receipt = {
            "receipt_id": _id(receipt_obj["receipt_id"], f"{path}/adoption_receipt/receipt_id"),
            "authority_id": _id(receipt_obj["authority_id"], f"{path}/adoption_receipt/authority_id"),
            "contract_digest": digest,
        }
    elif receipt_raw is not None:
        _fail("unexpected_adoption_receipt", f"{path}/adoption_receipt", "local references must not carry an adoption receipt")
    return {
        "project_id": ref_project,
        "kind": kind,
        "entity_id": entity_id,
        "revision_id": revision_id,
        "incarnation_id": incarnation_id,
        "adoption_receipt": receipt,
    }


def _validate_condition(value: Any, path: str, decision_options: Mapping[str, set[str]], depth: int = 0, count: list[int] | None = None) -> dict[str, Any]:
    if count is None:
        count = [0]
    count[0] += 1
    if depth > MAX_CONDITION_DEPTH:
        _fail("condition_too_deep", path, f"condition depth exceeds {MAX_CONDITION_DEPTH}")
    if count[0] > MAX_CONDITION_NODES:
        _fail("condition_too_large", path, f"condition has more than {MAX_CONDITION_NODES} nodes")
    if not isinstance(value, dict):
        _fail("invalid_condition", path, "condition must be a typed object")
    op = value.get("op")
    if not isinstance(op, str):
        _fail("invalid_condition", f"{path}/op", "condition op must be a string")
    if op in {"all", "any"}:
        obj = _object(value, path, required={"op", "conditions"})
        conditions = obj["conditions"]
        if not isinstance(conditions, list) or not conditions:
            _fail("invalid_condition", f"{path}/conditions", "all/any conditions must be a non-empty array")
        return {
            "op": op,
            "conditions": [
                _validate_condition(item, f"{path}/conditions/{index}", decision_options, depth + 1, count)
                for index, item in enumerate(conditions)
            ],
        }
    if op == "not":
        obj = _object(value, path, required={"op", "condition"})
        return {"op": op, "condition": _validate_condition(obj["condition"], f"{path}/condition", decision_options, depth + 1, count)}
    if op == "decision_equals":
        obj = _object(value, path, required={"op", "decision_id", "option_id"})
        decision_id = _id(obj["decision_id"], f"{path}/decision_id")
        option_id = _id(obj["option_id"], f"{path}/option_id")
        if decision_id not in decision_options:
            _fail("unknown_decision", f"{path}/decision_id", f"decision {decision_id!r} is not declared in this package")
        if option_id not in decision_options[decision_id]:
            _fail("unknown_decision_option", f"{path}/option_id", f"option {option_id!r} is not declared for decision {decision_id!r}")
        return {"op": op, "decision_id": decision_id, "option_id": option_id}
    _fail("unsupported_condition", f"{path}/op", f"unsupported condition operator {op!r}")


def _version_tuple(value: str, path: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?", value)
    if match is None:
        _fail("invalid_interface_version", path, "version must be numeric major[.minor[.patch]]")
    return tuple(int(part or 0) for part in match.groups())


def _compatible_interface_version(actual: str, expected: str, compatibility: str, path: str) -> bool:
    if compatibility == "frozen":
        return actual == expected
    actual_tuple = _version_tuple(actual, f"{path}/actual")
    expected_tuple = _version_tuple(expected, f"{path}/expected_version")
    return actual_tuple[0] == expected_tuple[0] and actual_tuple >= expected_tuple


def _id_records(value: Any, path: str, allowed: set[str], project_id: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail("expected_array", path, "expected an array")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        p = f"{path}/{index}"
        if not isinstance(raw, dict):
            _fail("expected_object", p, "expected an object")
        declaration_id = _id(raw.get("id"), f"{p}/id")
        if declaration_id in seen:
            _fail("duplicate_id", f"{p}/id", f"duplicate identifier {declaration_id!r} in {path}")
        seen.add(declaration_id)
        record = _validate_record(raw, p, path.rsplit("/", 1)[-1], allowed, project_id)
        records.append(record)
    records.sort(key=lambda item: item["id"])
    return records


def _validate_record(raw: dict[str, Any], path: str, kind: str, allowed: set[str], project_id: str) -> dict[str, Any]:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        _fail("unknown_field", f"{path}/{unknown[0]}", f"unsupported field {unknown[0]!r}")
    result = dict(raw)
    result["id"] = _id(raw["id"], f"{path}/id")

    if kind == "work_items":
        required = {"id", "title", "objective", "outcome", "scope", "acceptance"}
        missing = sorted(required - set(raw))
        if missing:
            _fail("missing_field", f"{path}/{missing[0]}", f"required field {missing[0]!r} is missing")
        for field in ("title", "objective", "outcome"):
            result[field] = _string(raw[field], f"{path}/{field}")
        for field in ("motivation",):
            if field in raw:
                result[field] = _string(raw[field], f"{path}/{field}")
        result["scope"] = _validate_scope(raw["scope"], f"{path}/scope")
        result["acceptance"] = _validate_acceptance(raw["acceptance"], f"{path}/acceptance")
        for field in ("unknowns", "delegated_judgment"):
            result[field] = _string_list(raw.get(field, []), f"{path}/{field}")
        ownership = raw.get("ownership", {"mode": "any", "actors": []})
        ownership_obj = _object(ownership, f"{path}/ownership", required={"mode", "actors"})
        owner_mode = _string(ownership_obj["mode"], f"{path}/ownership/mode")
        if owner_mode not in {"any", "all"}:
            _fail("unsupported_owner_mode", f"{path}/ownership/mode", "owner mode must be any or all")
        if not isinstance(ownership_obj["actors"], list):
            _fail("expected_array", f"{path}/ownership/actors", "actors must be typed actor references")
        actors = [
            _validate_reference(actor, f"{path}/ownership/actors/{index}", project_id)
            for index, actor in enumerate(ownership_obj["actors"])
        ]
        if any(actor["kind"] != EntityKind.ACTOR.value for actor in actors):
            _fail("invalid_owner_kind", f"{path}/ownership/actors", "ownership constraints must reference actors")
        actor_keys = [(actor["project_id"], actor["entity_id"], actor["incarnation_id"]) for actor in actors]
        if len(actor_keys) != len(set(actor_keys)):
            _fail("duplicate_owner", f"{path}/ownership/actors", "ownership constraints must not repeat an actor incarnation")
        actors.sort(key=_canonical_json)
        result["ownership"] = {"mode": owner_mode, "actors": actors}
        references = raw.get("references", [])
        if not isinstance(references, list):
            _fail("expected_array", f"{path}/references", "expected an array of references")
        normalized_references = []
        for index, reference in enumerate(references):
            p = f"{path}/references/{index}"
            ref_obj = _object(reference, p, required={"label", "uri"})
            normalized_references.append({
                "label": _string(ref_obj["label"], f"{p}/label"),
                "uri": _string(ref_obj["uri"], f"{p}/uri"),
            })
        result["references"] = normalized_references
        alternatives = raw.get("alternatives", [])
        result["alternatives"] = _validate_alternatives(alternatives, f"{path}/alternatives")
        parent = raw.get("parent_id")
        result["parent_id"] = None if parent is None else _id(parent, f"{path}/parent_id")
        supersedes = raw.get("supersedes", [])
        if not isinstance(supersedes, list):
            _fail("expected_array", f"{path}/supersedes", "supersedes must be an array of qualified references")
        result["supersedes"] = [
            _validate_reference(item, f"{path}/supersedes/{index}", project_id)
            for index, item in enumerate(supersedes)
        ]
        groups = raw.get("requirement_groups", [])
        result["requirement_groups"] = _validate_requirement_groups(groups, f"{path}/requirement_groups")
        return result

    if kind == "requirements":
        required = {"id", "work_item_id", "kind", "description"}
        missing = sorted(required - set(raw))
        if missing:
            _fail("missing_field", f"{path}/{missing[0]}", f"required field {missing[0]!r} is missing")
        result["work_item_id"] = _id(raw["work_item_id"], f"{path}/work_item_id")
        result["kind"] = _string(raw["kind"], f"{path}/kind")
        if result["kind"] not in {item.value for item in RequirementKind}:
            _fail("unsupported_requirement_kind", f"{path}/kind", f"unsupported requirement kind {result['kind']!r}")
        result["description"] = _string(raw["description"], f"{path}/description")
        if result["kind"] == RequirementKind.PREREQUISITE.value:
            if "target" not in raw or "check_key" in raw:
                _fail("invalid_requirement", path, "prerequisite requires target and must not declare check_key")
            result["target"] = _validate_reference(raw["target"], f"{path}/target", project_id)
        else:
            if "check_key" not in raw or "target" in raw:
                _fail("invalid_requirement", path, "check requires check_key and must not declare target")
            result["check_key"] = _id(raw["check_key"], f"{path}/check_key")
        return result

    if kind in {"checkpoints", "interfaces", "decisions", "barriers", "rendezvous", "invariants"}:
        return _validate_declaration(raw, path, kind, allowed, project_id)
    _fail("unsupported_record_kind", path, f"unsupported record kind {kind!r}")


def _validate_alternatives(value: Any, path: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail("expected_array", path, "expected an array of alternatives")
    result = []
    seen = set()
    for index, raw in enumerate(value):
        p = f"{path}/{index}"
        item = _object(raw, p, required={"id", "description"}, optional={"tradeoffs"})
        identifier = _id(item["id"], f"{p}/id")
        if identifier in seen:
            _fail("duplicate_id", f"{p}/id", f"duplicate alternative identifier {identifier!r}")
        seen.add(identifier)
        entry = {"id": identifier, "description": _string(item["description"], f"{p}/description")}
        if "tradeoffs" in item:
            entry["tradeoffs"] = _string_list(item["tradeoffs"], f"{p}/tradeoffs")
        result.append(entry)
    return result


def _validate_requirement_groups(value: Any, path: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail("expected_array", path, "expected an array of requirement groups")
    groups = []
    for index, raw in enumerate(value):
        p = f"{path}/{index}"
        item = _object(raw, p, required={"kind", "mode", "members"}, optional={"quorum"})
        kind = _string(item["kind"], f"{p}/kind")
        mode = _string(item["mode"], f"{p}/mode")
        if kind not in {value.value for value in RequirementKind}:
            _fail("unsupported_requirement_kind", f"{p}/kind", f"unsupported requirement kind {kind!r}")
        if mode not in {value.value for value in RequirementMode}:
            _fail("unsupported_requirement_mode", f"{p}/mode", f"unsupported requirement mode {mode!r}")
        members = _string_list(item["members"], f"{p}/members", unique=True)
        if not members:
            _fail("empty_requirement_group", f"{p}/members", "requirement groups must not be empty")
        quorum = item.get("quorum")
        if mode == RequirementMode.QUORUM.value:
            if type(quorum) is not int or not 1 <= quorum <= len(members):
                _fail("invalid_quorum", f"{p}/quorum", "quorum must be an integer between one and member count")
        elif quorum is not None:
            _fail("invalid_quorum", f"{p}/quorum", "quorum is only valid with mode 'quorum'")
        groups.append({"kind": kind, "mode": mode, "members": sorted(members), "quorum": quorum})
    groups.sort(key=_canonical_json)
    return groups


def _validate_declaration(raw: dict[str, Any], path: str, kind: str, allowed: set[str], project_id: str) -> dict[str, Any]:
    result = dict(raw)
    if kind in {"checkpoints", "interfaces", "decisions", "barriers", "rendezvous"}:
        if "title" not in raw:
            _fail("missing_field", f"{path}/title", "required field 'title' is missing")
        result["title"] = _string(raw["title"], f"{path}/title")
    if kind == "checkpoints":
        if "acceptance" not in raw:
            _fail("missing_field", f"{path}/acceptance", "required field 'acceptance' is missing")
        result["acceptance"] = _validate_acceptance(raw["acceptance"], f"{path}/acceptance")
        result["unknowns"] = _string_list(raw.get("unknowns", []), f"{path}/unknowns")
        producers = raw.get("producers", [])
        if not isinstance(producers, list):
            _fail("expected_array", f"{path}/producers", "checkpoint producers must be qualified work-item references")
        result["producers"] = [
            _validate_reference(item, f"{path}/producers/{index}", project_id)
            for index, item in enumerate(producers)
        ]
    elif kind == "interfaces":
        required = {"version", "contract", "producers", "consumers", "compatibility"}
        missing = sorted(required - set(raw))
        if missing:
            _fail("missing_field", f"{path}/{missing[0]}", f"required field {missing[0]!r} is missing")
        result["version"] = _string(raw["version"], f"{path}/version")
        if not isinstance(raw["contract"], dict):
            _fail("expected_object", f"{path}/contract", "interface contract must be a structured object")
        result["contract"] = _json_value(raw["contract"], f"{path}/contract")
        for field in ("producers", "consumers"):
            if not isinstance(raw[field], list):
                _fail("expected_array", f"{path}/{field}", "expected an array of qualified references")
            result[field] = [
                _validate_reference(item, f"{path}/{field}/{index}", project_id)
                for index, item in enumerate(raw[field])
            ]
        result["compatibility"] = _string(raw["compatibility"], f"{path}/compatibility")
        if result["compatibility"] not in {"frozen", "evolvable"}:
            _fail("unsupported_compatibility", f"{path}/compatibility", "compatibility must be frozen or evolvable")
    elif kind == "decisions":
        required = {"question", "options"}
        missing = sorted(required - set(raw))
        if missing:
            _fail("missing_field", f"{path}/{missing[0]}", f"required field {missing[0]!r} is missing")
        result["question"] = _string(raw["question"], f"{path}/question")
        result["options"] = _validate_alternatives(raw["options"], f"{path}/options")
        if not result["options"]:
            _fail("empty_decision", f"{path}/options", "decision must declare at least one option")
        selected = raw.get("selected_option_id")
        if selected is not None:
            selected = _id(selected, f"{path}/selected_option_id")
            if selected not in {item["id"] for item in result["options"]}:
                _fail("unknown_decision_option", f"{path}/selected_option_id", "selected option must be declared")
        result["selected_option_id"] = selected
        result["unknowns"] = _string_list(raw.get("unknowns", []), f"{path}/unknowns")
        resolvers = raw.get("resolvers", [])
        if not isinstance(resolvers, list):
            _fail("expected_array", f"{path}/resolvers", "decision resolvers must be qualified work-item references")
        result["resolvers"] = [
            _validate_reference(item, f"{path}/resolvers/{index}", project_id)
            for index, item in enumerate(resolvers)
        ]
    elif kind in {"barriers", "rendezvous"}:
        required = {"participants", "mode"}
        missing = sorted(required - set(raw))
        if missing:
            _fail("missing_field", f"{path}/{missing[0]}", f"required field {missing[0]!r} is missing")
        participants = raw["participants"]
        if not isinstance(participants, list):
            _fail("expected_array", f"{path}/participants", "participants must be qualified references")
        result["participants"] = [
            _validate_reference(item, f"{path}/participants/{index}", project_id)
            for index, item in enumerate(participants)
        ]
        if not result["participants"]:
            _fail("empty_participants", f"{path}/participants", "participants must not be empty")
        mode = _string(raw["mode"], f"{path}/mode")
        if mode not in {item.value for item in RequirementMode}:
            _fail("unsupported_requirement_mode", f"{path}/mode", f"unsupported mode {mode!r}")
        result["mode"] = mode
        quorum = raw.get("quorum")
        if mode == RequirementMode.QUORUM.value:
            if type(quorum) is not int or not 1 <= quorum <= len(result["participants"]):
                _fail("invalid_quorum", f"{path}/quorum", "quorum must be an integer between one and participants count")
        elif quorum is not None:
            _fail("invalid_quorum", f"{path}/quorum", "quorum is only valid with mode 'quorum'")
        result["quorum"] = quorum
    elif kind == "invariants":
        if "statement" not in raw:
            _fail("missing_field", f"{path}/statement", "required field 'statement' is missing")
        result["statement"] = _string(raw["statement"], f"{path}/statement")
        applies_to = raw.get("applies_to", [])
        if not isinstance(applies_to, list):
            _fail("expected_array", f"{path}/applies_to", "applies_to must be qualified references")
        result["applies_to"] = [
            _validate_reference(item, f"{path}/applies_to/{index}", project_id)
            for index, item in enumerate(applies_to)
        ]
    return result


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def parse_plan_json(
    source: str | bytes,
    *,
    source_name: str = "inline:json",
    _allow_exact_local_refs: bool = False,
) -> ParseResult:
    """Parse and strictly validate a v1 package without consulting any authority."""
    try:
        try:
            raw_bytes = source.encode("utf-8") if isinstance(source, str) else source
        except UnicodeEncodeError as error:
            _fail("invalid_unicode", "$", f"plan input contains an unpaired Unicode surrogate at character {error.start}")
        if not isinstance(raw_bytes, bytes):
            _fail("invalid_input", "$", "plan input must be UTF-8 text or bytes")
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            _fail("invalid_encoding", "$", f"plan input is not UTF-8 at byte {error.start}")
        try:
            document = json.loads(raw_text, object_pairs_hook=_pairs, parse_constant=lambda value: _fail("invalid_number", "$", f"unsupported JSON number {value}"))
        except json.JSONDecodeError as error:
            _fail("invalid_json", f"$@{error.lineno}:{error.colno}", error.msg)
        except ValueError as error:
            if isinstance(error, _InputFailure):
                raise
            _fail("duplicate_json_key", "$", str(error))
        if not isinstance(document, dict):
            _fail("expected_object", "$", "plan document must be an object")
        top = _object(
            document,
            "$",
            required={"format", "schema_version", "package_id", "project", "work_items"},
            optional={"provenance", "source_manifests", "generation_metadata", "requirements", "checkpoints", "interfaces", "decisions", "barriers", "rendezvous", "dependencies", "invariants"},
        )
        if top["format"] != PLAN_FORMAT:
            _fail("unsupported_format", "$/format", f"format must be {PLAN_FORMAT!r}")
        if type(top["schema_version"]) is not int or top["schema_version"] != PLAN_SCHEMA_VERSION:
            _fail("unsupported_schema_version", "$/schema_version", f"schema_version must be {PLAN_SCHEMA_VERSION}")
        package_id = _id(top["package_id"], "$/package_id")
        project_obj = _object(top["project"], "$/project", required={"project_id", "authority_id"})
        project = {
            "project_id": _id(project_obj["project_id"], "$/project/project_id"),
            "authority_id": _id(project_obj["authority_id"], "$/project/authority_id"),
        }
        provenance_raw = top.get("provenance", {})
        provenance_obj = _object(provenance_raw, "$/provenance", required=set(), optional={"source", "producer"})
        provenance = {}
        if "source" in provenance_obj:
            provenance["source"] = _string(provenance_obj["source"], "$/provenance/source")
        if "producer" in provenance_obj:
            provenance["producer"] = _string(provenance_obj["producer"], "$/provenance/producer")
        source_manifests_raw = top.get("source_manifests", [])
        if not isinstance(source_manifests_raw, list):
            _fail("expected_array", "$/source_manifests", "expected an array of source manifests")
        source_manifests = []
        source_ids: set[str] = set()
        for index, raw_manifest in enumerate(source_manifests_raw):
            path = f"$/source_manifests/{index}"
            manifest = _object(raw_manifest, path, required={"id", "location", "sha256"})
            source_id = _id(manifest["id"], f"{path}/id")
            if source_id in source_ids:
                _fail("duplicate_source_manifest", f"{path}/id", f"source manifest {source_id!r} is repeated")
            source_ids.add(source_id)
            digest = _string(manifest["sha256"], f"{path}/sha256")
            try:
                Sha256Digest(digest)
            except ValueError as error:
                _fail("invalid_digest", f"{path}/sha256", str(error))
            source_manifests.append({
                "id": source_id,
                "location": _string(manifest["location"], f"{path}/location"),
                "sha256": digest,
            })
        source_manifests.sort(key=lambda item: item["id"])
        generation_metadata = None
        if "generation_metadata" in top:
            generation_metadata = _generation_metadata(top["generation_metadata"], "$/generation_metadata")

        work_allowed = {
        "id", "title", "objective", "motivation", "outcome", "references", "scope", "acceptance", "ownership",
            "alternatives", "unknowns", "delegated_judgment", "parent_id", "supersedes", "requirement_groups",
        }
        records: dict[str, list[dict[str, Any]]] = {}
        records["work_items"] = _id_records(top["work_items"], "$/work_items", work_allowed, project["project_id"])
        record_specs = {
            "requirements": {"id", "work_item_id", "kind", "description", "target", "check_key"},
            "checkpoints": {"id", "title", "acceptance", "unknowns", "producers"},
            "interfaces": {"id", "title", "version", "contract", "producers", "consumers", "compatibility"},
            "decisions": {"id", "title", "question", "options", "selected_option_id", "unknowns", "resolvers"},
            "barriers": {"id", "title", "participants", "mode", "quorum"},
            "rendezvous": {"id", "title", "participants", "mode", "quorum"},
            "invariants": {"id", "statement", "applies_to"},
        }
        supplied_sections = tuple(sorted(
            section for section in (*record_specs, "dependencies") if section in top
        ))
        for kind, allowed in record_specs.items():
            records[kind] = _id_records(top.get(kind, []), f"$/{kind}", allowed, project["project_id"])

        # Keep authored field presence separately from normalized defaults. Preview
        # uses these masks to distinguish an omitted field from an explicit value.
        record_field_masks = {
            section: {
                str(raw["id"]): tuple(sorted(raw.keys()))
                for raw in top.get(section, [])
            }
            for section in ("work_items", *record_specs)
        }

        declared_by_kind = {
            "work_item": {item["id"] for item in records["work_items"]},
            "requirement": {item["id"] for item in records["requirements"]},
            "checkpoint": {item["id"] for item in records["checkpoints"]},
            "interface": {item["id"] for item in records["interfaces"]},
            "decision": {item["id"] for item in records["decisions"]},
            "barrier": {item["id"] for item in records["barriers"]},
            "rendezvous": {item["id"] for item in records["rendezvous"]},
            "invariant": {item["id"] for item in records["invariants"]},
        }
        work_ids = declared_by_kind["work_item"]
        requirement_ids = declared_by_kind["requirement"]
        decisions = {item["id"]: {option["id"] for option in item["options"]} for item in records["decisions"]}

        def check_reference_binding(reference: Mapping[str, Any], path: str) -> None:
            if reference["project_id"] != project["project_id"]:
                return
            kind_name = reference["kind"]
            is_declared_here = reference["entity_id"] in declared_by_kind.get(kind_name, set())
            revisioned = kind_name in {"work_item", "requirement"}
            if is_declared_here and revisioned and reference["revision_id"] is not None and not _allow_exact_local_refs:
                _fail("ambiguous_local_reference", f"{path}/revision_id", "references to definitions in this package omit revision_id; the compiler binds the new revision")
            if not is_declared_here and revisioned and reference["revision_id"] is None:
                _fail("ambiguous_reference", f"{path}/revision_id", "references to existing definitions require an exact revision_id")

        for kind in ("work_items", "requirements", "checkpoints", "interfaces", "decisions", "barriers", "rendezvous", "invariants"):
            for record_index, record in enumerate(records[kind]):
                p = f"$/{kind}/{record_index}"
                references: list[tuple[Mapping[str, Any], str]] = []
                if kind == "requirements" and record["kind"] == RequirementKind.PREREQUISITE.value:
                    references.append((record["target"], f"{p}/target"))
                elif kind == "interfaces":
                    references.extend((ref, f"{p}/producers/{i}") for i, ref in enumerate(record["producers"]))
                    references.extend((ref, f"{p}/consumers/{i}") for i, ref in enumerate(record["consumers"]))
                elif kind in {"barriers", "rendezvous"}:
                    references.extend((ref, f"{p}/participants/{i}") for i, ref in enumerate(record["participants"]))
                elif kind == "invariants":
                    references.extend((ref, f"{p}/applies_to/{i}") for i, ref in enumerate(record["applies_to"]))
                elif kind == "work_items":
                    references.extend((ref, f"{p}/ownership/actors/{i}") for i, ref in enumerate(record["ownership"]["actors"]))
                    references.extend((ref, f"{p}/supersedes/{i}") for i, ref in enumerate(record["supersedes"]))
                elif kind == "checkpoints":
                    references.extend((ref, f"{p}/producers/{i}") for i, ref in enumerate(record["producers"]))
                elif kind == "decisions":
                    references.extend((ref, f"{p}/resolvers/{i}") for i, ref in enumerate(record["resolvers"]))
                for reference, reference_path in references:
                    check_reference_binding(reference, reference_path)
                    if kind in {"checkpoints", "interfaces", "decisions", "barriers", "rendezvous"} and reference["kind"] != "work_item":
                        _fail("invalid_graph_participant", f"{reference_path}/kind", f"{kind} graph links must reference work items")

        for index, work in enumerate(records["work_items"]):
            path = f"$/work_items/{index}"
            if work["parent_id"] is not None and work["parent_id"] not in work_ids:
                _fail("unknown_parent", f"{path}/parent_id", f"parent work item {work['parent_id']!r} is not declared in this package")
            for superseded in work["supersedes"]:
                check_reference_binding(superseded, f"{path}/supersedes")
                if superseded["kind"] != "work_item":
                    _fail("invalid_supersedes_kind", f"{path}/supersedes", "supersedes references must identify work items")
            for group_index, group in enumerate(work["requirement_groups"]):
                for member in group["members"]:
                    if member not in requirement_ids:
                        _fail("unknown_requirement", f"{path}/requirement_groups/{group_index}/members", f"requirement {member!r} is not declared in this package")
                    req = next(item for item in records["requirements"] if item["id"] == member)
                    if req["work_item_id"] != work["id"] or req["kind"] != group["kind"]:
                        _fail("invalid_requirement_group", f"{path}/requirement_groups/{group_index}", "group members must belong to this work item and match group kind")
        for index, requirement in enumerate(records["requirements"]):
            if requirement["work_item_id"] not in work_ids:
                _fail("unknown_requirement_owner", f"$/requirements/{index}/work_item_id", "requirement owner must be a work item declared in this package")

        if not isinstance(top.get("dependencies", []), list):
            _fail("expected_array", "$/dependencies", "expected an array of dependency groups")
        dependencies = []
        seen_sources: set[str] = set()
        for index, raw in enumerate(top.get("dependencies", [])):
            p = f"$/dependencies/{index}"
            group = _object(raw, p, required={"source", "mode", "members"}, optional={"quorum"})
            source_ref = _validate_reference(group["source"], f"{p}/source", project["project_id"])
            if source_ref["project_id"] != project["project_id"]:
                _fail("foreign_dependency_source", f"{p}/source", "dependency sources must be declared by this project")
            check_reference_binding(source_ref, f"{p}/source")
            if source_ref["entity_id"] not in declared_by_kind.get(source_ref["kind"], set()):
                _fail("unknown_dependency_source", f"{p}/source", "dependency source must be a declared local plan entity")
            mode = _string(group["mode"], f"{p}/mode")
            try:
                req_mode = RequirementMode(mode)
            except ValueError:
                _fail("unsupported_requirement_mode", f"{p}/mode", f"unsupported dependency mode {mode!r}")
            members = group["members"]
            if not isinstance(members, list) or not members:
                _fail("empty_dependency_group", f"{p}/members", "dependency group must have at least one member")
            quorum = group.get("quorum")
            if req_mode is RequirementMode.QUORUM:
                if type(quorum) is not int or not 1 <= quorum <= len(members):
                    _fail("invalid_quorum", f"{p}/quorum", "quorum must be an integer between one and member count")
            elif quorum is not None:
                _fail("invalid_quorum", f"{p}/quorum", "quorum is only valid with mode 'quorum'")
            normalized_members = []
            seen_members = set()
            for member_index, raw_member in enumerate(members):
                mp = f"{p}/members/{member_index}"
                member = _object(raw_member, mp, required={"relation", "target"}, optional={"condition", "expected_version"})
                relation = _string(member["relation"], f"{mp}/relation")
                try:
                    relation_type = BlockerRelation(relation)
                except ValueError:
                    _fail("unsupported_blocker_relation", f"{mp}/relation", f"unsupported blocker relation {relation!r}")
                target = _validate_reference(member["target"], f"{mp}/target", project["project_id"])
                check_reference_binding(target, f"{mp}/target")
                expected_kind = {
                    BlockerRelation.COMPLETION: {"work_item"},
                    BlockerRelation.CHECKPOINT_ACCEPTED: {"checkpoint"},
                    BlockerRelation.INTERFACE_VERSION: {"interface"},
                    BlockerRelation.EVIDENCE_VERIFIED: {"evidence"},
                    BlockerRelation.DECISION_RESOLVED: {"decision"},
                    BlockerRelation.BARRIER_RELEASED: {"barrier"},
                    BlockerRelation.RENDEZVOUS_MET: {"rendezvous"},
                }[relation_type]
                if target["kind"] not in expected_kind:
                    _fail("relation_target_mismatch", f"{mp}/target/kind", f"relation {relation!r} requires target kind {sorted(expected_kind)}")
                expected_version = member.get("expected_version")
                if relation_type is BlockerRelation.INTERFACE_VERSION:
                    if expected_version is None:
                        _fail("missing_interface_version", f"{mp}/expected_version", "interface_version blockers require an expected_version")
                    expected_version = _string(expected_version, f"{mp}/expected_version")
                    local_interface = next((item for item in records["interfaces"] if item["id"] == target["entity_id"] and target["project_id"] == project["project_id"]), None)
                    if local_interface is not None and not _compatible_interface_version(local_interface["version"], expected_version, local_interface["compatibility"], f"{mp}/expected_version"):
                        _fail("incompatible_interface_version", f"{mp}/expected_version", f"interface version {local_interface['version']!r} is incompatible with expected version {expected_version!r}")
                elif expected_version is not None:
                    _fail("unexpected_interface_version", f"{mp}/expected_version", "expected_version is only valid for interface_version blockers")
                member_key = (relation, target["project_id"], target["kind"], target["entity_id"], target["revision_id"])
                if member_key in seen_members:
                    _fail("duplicate_dependency", mp, "dependency group repeats a blocker")
                seen_members.add(member_key)
                entry = {"relation": relation, "target": target}
                if expected_version is not None:
                    entry["expected_version"] = expected_version
                if "condition" in member:
                    entry["condition"] = _validate_condition(member["condition"], f"{mp}/condition", decisions)
                normalized_members.append(entry)
            normalized_members.sort(key=_canonical_json)
            source_key = _canonical_json(source_ref)
            if source_key in seen_sources:
                _fail("duplicate_dependency_group", p, "each source must have one combined dependency group")
            seen_sources.add(source_key)
            dependencies.append({"source": source_ref, "mode": mode, "quorum": quorum, "members": normalized_members})
        dependencies.sort(key=lambda item: _canonical_json(item["source"]))

        normalized: dict[str, Any] = {
            "format": PLAN_FORMAT,
            "schema_version": PLAN_SCHEMA_VERSION,
            "package_id": package_id,
            "project": project,
            "provenance": provenance,
            "source_manifests": source_manifests,
            "generation_metadata": generation_metadata,
            **records,
            "dependencies": dependencies,
        }
        semantic_content = {key: value for key, value in normalized.items() if key not in {"provenance", "generation_metadata"}}
        semantic_content["supplied_sections"] = list(supplied_sections)
        semantic_content["record_field_masks"] = {
            section: {identifier: list(fields) for identifier, fields in sorted(records.items())}
            for section, records in sorted(record_field_masks.items())
        }
        content_digest = Sha256Digest(hashlib.sha256(_canonical_json(semantic_content).encode("utf-8")).hexdigest())
        package = PlanPackageInput(
            document=_freeze(normalized),
            source=_string(source_name, "$/source_name"),
            source_digest=Sha256Digest(hashlib.sha256(raw_bytes).hexdigest()),
            content_digest=content_digest,
            supplied_sections=supplied_sections,
            source_manifests_supplied="source_manifests" in top,
            generation_metadata_supplied="generation_metadata" in top,
            record_field_masks=_freeze(record_field_masks),
        )
        return ParseResult(package)
    except _InputFailure as error:
        return ParseResult(None, (error.diagnostic,))


def _domain_ref(raw: Mapping[str, Any], revision_id: StableId, local_project: StableId) -> QualifiedReference:
    project_id = StableId(raw["project_id"])
    declared_kind = raw["kind"]
    kind = EntityKind.BARRIER if declared_kind == "rendezvous" else EntityKind(declared_kind)
    entity_id = StableId(raw["entity_id"])
    ref_revision = raw.get("revision_id")
    if kind is EntityKind.WORK_ITEM and project_id == local_project and ref_revision is None:
        ref_revision = str(revision_id)
    if kind is EntityKind.REQUIREMENT and project_id == local_project and ref_revision is None:
        ref_revision = str(revision_id)
    reference = EntityRef(
        project_id=project_id,
        kind=kind,
        entity_id=entity_id,
        definition_revision_id=None if ref_revision is None else StableId(ref_revision),
        incarnation_id=None if raw.get("incarnation_id") is None else StableId(raw["incarnation_id"]),
    )
    receipt_raw = raw.get("adoption_receipt")
    receipt = None if receipt_raw is None else AdoptionReceipt(
        receipt_id=StableId(receipt_raw["receipt_id"]),
        authority_id=StableId(receipt_raw["authority_id"]),
        contract_digest=Sha256Digest(receipt_raw["contract_digest"]),
    )
    return QualifiedReference(reference, declared_kind, receipt)


def compile_plan(
    package: PlanPackageInput,
    target: Project,
    *,
    revision_sequence: int = 1,
    based_on_revision_id: StableId | None = None,
    adoption_facts: tuple[VerifiedAdoption, ...] = (),
) -> CompileResult:
    """Compile normalized input into immutable canonical values, without I/O."""
    try:
        document = package.document
        project_data = document["project"]
        if target.project_id != StableId(project_data["project_id"]) or target.authority_id != StableId(project_data["authority_id"]):
            _fail("target_mismatch", "$/project", "package project/authority identity does not match the explicit compile target")
        if type(revision_sequence) is not int or revision_sequence < 1:
            _fail("invalid_revision_sequence", "$/compile/revision_sequence", "revision_sequence must be a positive integer")
        revision_id = StableId(f"plan-{package.content_digest.hex}")
        foreign_references: dict[tuple[str, str, str, str, str], QualifiedReference] = {}

        def collect_foreign(value: Any) -> None:
            if isinstance(value, Mapping):
                if {"project_id", "kind", "entity_id"}.issubset(value) and value["project_id"] != str(target.project_id):
                    qualified = _domain_ref(value, revision_id, target.project_id)
                    reference = qualified.reference
                    key = (str(reference.project_id), qualified.declared_kind, str(reference.entity_id),
                           "" if reference.definition_revision_id is None else str(reference.definition_revision_id),
                           "" if reference.incarnation_id is None else str(reference.incarnation_id))
                    foreign_references[key] = qualified
                for nested in value.values():
                    collect_foreign(nested)
            elif isinstance(value, (tuple, list)):
                for nested in value:
                    collect_foreign(nested)

        collect_foreign(document)
        fact_keys = {
            (str(fact.reference.project_id), fact.declared_kind, str(fact.reference.entity_id),
             "" if fact.reference.definition_revision_id is None else str(fact.reference.definition_revision_id),
             "" if fact.reference.incarnation_id is None else str(fact.reference.incarnation_id)): fact
            for fact in adoption_facts
        }
        missing_adoptions = []
        for key, qualified in sorted(foreign_references.items()):
            fact = fact_keys.get(key)
            if fact is None or fact.receipt != qualified.adoption_receipt:
                missing_adoptions.append(PlanDiagnostic(
                    "foreign_reference_unverified",
                    f"foreign reference {qualified.declared_kind}:{qualified.reference.entity_id} lacks a matching trusted adoption fact",
                    "$/references",
                ))
        if missing_adoptions:
            return CompileResult(None, tuple(missing_adoptions))
        for group_index, group in enumerate(document["dependencies"]):
            for member_index, member in enumerate(group["members"]):
                target_ref = member["target"]
                if member["relation"] != BlockerRelation.INTERFACE_VERSION.value or target_ref["project_id"] == str(target.project_id):
                    continue
                qualified = _domain_ref(target_ref, revision_id, target.project_id)
                ref = qualified.reference
                key = (str(ref.project_id), qualified.declared_kind, str(ref.entity_id),
                       "" if ref.definition_revision_id is None else str(ref.definition_revision_id),
                       "" if ref.incarnation_id is None else str(ref.incarnation_id))
                fact = fact_keys[key]
                if fact.interface_version is None or fact.compatibility not in {"frozen", "evolvable"}:
                    _fail("external_interface_contract_missing", f"$/dependencies/{group_index}/members/{member_index}", "verified adoption fact must include interface_version and compatibility")
                if not _compatible_interface_version(fact.interface_version, member["expected_version"], fact.compatibility, f"$/dependencies/{group_index}/members/{member_index}"):
                    _fail("incompatible_interface_version", f"$/dependencies/{group_index}/members/{member_index}/expected_version", f"adopted interface version {fact.interface_version!r} is incompatible with expected version {member['expected_version']!r}")
        provenance_data = document["provenance"]
        source_name = provenance_data.get("source", package.source)
        producer = provenance_data.get("producer")
        provenance = SourceProvenance(source_name, package.source_digest, producer)

        requirement_data = {item["id"]: item for item in document["requirements"]}
        compiled_requirements: dict[str, PlannedRequirement] = {}
        for raw in document["requirements"]:
            target_ref = None
            if raw["kind"] == RequirementKind.PREREQUISITE.value:
                target_ref = _domain_ref(raw["target"], revision_id, target.project_id)
            definition = Requirement(
                requirement_id=StableId(raw["id"]),
                project_id=target.project_id,
                definition_revision_id=revision_id,
                work_item_id=StableId(raw["work_item_id"]),
                kind=RequirementKind(raw["kind"]),
                description=raw["description"],
                target=None if target_ref is None else target_ref.reference,
                check_key=None if raw["kind"] == RequirementKind.PREREQUISITE.value else StableId(raw["check_key"]),
            )
            compiled_requirements[raw["id"]] = PlannedRequirement(definition, target_ref)

        planned_work = []
        for raw in document["work_items"]:
            groups = tuple(
                RequirementGroup(
                    kind=RequirementKind[group["kind"].upper()],
                    mode=RequirementMode(group["mode"]),
                    requirement_ids=tuple(StableId(identifier) for identifier in group["members"]),
                    quorum=group["quorum"],
                )
                for group in raw["requirement_groups"]
            )
            parent = None if raw["parent_id"] is None else EntityRef(
                target.project_id, EntityKind.WORK_ITEM, StableId(raw["parent_id"]), revision_id
            )
            supersedes = tuple(
                _domain_ref(identifier, revision_id, target.project_id).reference
                for identifier in raw["supersedes"]
            )
            definition = WorkItem(
                work_item_id=StableId(raw["id"]),
                project_id=target.project_id,
                definition_revision_id=revision_id,
                title=raw["title"],
                outcome=raw["outcome"],
                requirement_groups=groups,
                parent=parent,
                supersedes=supersedes,
            )
            context = WorkItemContext(
                objective=raw["objective"],
                motivation=raw.get("motivation"),
                references=tuple(_freeze(item) for item in raw["references"]),
                scope=_freeze(raw["scope"]),
                acceptance=_freeze(raw["acceptance"]),
                alternatives=tuple(_freeze(item) for item in raw["alternatives"]),
                unknowns=tuple(raw["unknowns"]),
                delegated_judgment=tuple(raw["delegated_judgment"]),
                ownership=OwnershipConstraint(
                    raw["ownership"]["mode"],
                    tuple(_domain_ref(actor, revision_id, target.project_id) for actor in raw["ownership"]["actors"]),
                ),
            )
            planned_work.append(PlannedWorkItem(definition, context))

        declaration_kinds = ("checkpoints", "interfaces", "decisions", "barriers", "rendezvous", "invariants")
        declarations = tuple(
            PlanDeclaration(kind, StableId(raw["id"]), _freeze(raw))
            for kind in declaration_kinds
            for raw in document[kind]
        )

        blocking_groups = []
        for group in document["dependencies"]:
            source_ref = _domain_ref(group["source"], revision_id, target.project_id)
            members = tuple(
                BlockingEdge(
                    relation=BlockerRelation(member["relation"]),
                    target=_domain_ref(member["target"], revision_id, target.project_id),
                    expected_version=member.get("expected_version"),
                    condition=None if "condition" not in member else _compile_condition(member["condition"]),
                )
                for member in group["members"]
            )
            blocking_groups.append(BlockingGroup(
                source=source_ref,
                mode=RequirementMode(group["mode"]),
                quorum=group["quorum"],
                members=members,
            ))

        revision = PlanRevision(
            plan_revision_id=revision_id,
            project_id=target.project_id,
            sequence=revision_sequence,
            work_items=tuple(item.definition.ref for item in planned_work),
            based_on_revision_id=based_on_revision_id,
            provenance=provenance,
        )
        canonical_document = _thaw(document)
        optional_sections = {"requirements", "checkpoints", "interfaces", "decisions", "barriers", "rendezvous", "invariants", "dependencies"}
        for section in optional_sections - set(package.supplied_sections):
            canonical_document.pop(section, None)
        if not package.source_manifests_supplied:
            canonical_document.pop("source_manifests", None)
        if not package.generation_metadata_supplied:
            canonical_document.pop("generation_metadata", None)
        canonical = _canonical_json(canonical_document)
        manifests = tuple(
            SourceManifest(StableId(raw["id"]), raw["location"], Sha256Digest(raw["sha256"]))
            for raw in document["source_manifests"]
        )
        generation = document["generation_metadata"]
        compiled = CompiledPlan(
            package_id=StableId(document["package_id"]),
            project=target,
            revision=revision,
            work_items=tuple(planned_work),
            requirements=tuple(compiled_requirements[key] for key in sorted(compiled_requirements)),
            declarations=declarations,
            blocking_groups=tuple(blocking_groups),
            source_manifests=manifests,
            generation_metadata=None if generation is None else _freeze(generation),
            source_manifests_supplied=package.source_manifests_supplied,
            generation_metadata_supplied=package.generation_metadata_supplied,
            supplied_sections=package.supplied_sections,
            verified_adoptions=tuple(sorted(adoption_facts, key=lambda fact: (str(fact.reference.project_id), fact.declared_kind, str(fact.reference.entity_id), str(fact.verification_id)))),
            canonical_json=canonical,
            content_digest=package.content_digest,
            record_field_masks=package.record_field_masks,
        )
        from .graph import validate_plan_graph

        graph_validation = validate_plan_graph(compiled)
        if not graph_validation.ok:
            return CompileResult(None, graph_validation.diagnostics, graph_validation)
        return CompileResult(compiled, (), graph_validation)
    except _InputFailure as error:
        return CompileResult(None, (error.diagnostic,))
    except (TypeError, ValueError, KeyError) as error:
        return CompileResult(None, (PlanDiagnostic("domain_validation", str(error), "$/compile"),))


def compile_plan_json(
    source: str | bytes,
    target: Project,
    *,
    source_name: str = "inline:json",
    revision_sequence: int = 1,
    based_on_revision_id: StableId | None = None,
    adoption_facts: tuple[VerifiedAdoption, ...] = (),
    _allow_exact_local_refs: bool = False,
) -> CompileResult:
    """Convenience parser/compiler entry point with typed diagnostics."""
    parsed = parse_plan_json(source, source_name=source_name, _allow_exact_local_refs=_allow_exact_local_refs)
    if not parsed.ok:
        return CompileResult(None, parsed.diagnostics)
    assert parsed.package is not None
    return compile_plan(
        parsed.package,
        target,
        revision_sequence=revision_sequence,
        based_on_revision_id=based_on_revision_id,
        adoption_facts=adoption_facts,
    )


__all__ = [
    "AdoptionReceipt", "VerifiedAdoption", "BlockerRelation", "BlockingEdge", "BlockingGroup", "CompileResult",
    "CompiledPlan", "ConditionExpression", "DiagnosticSeverity", "OwnershipConstraint", "ParseResult", "PlanDeclaration",
    "PlanDiagnostic", "PlanPackageInput", "PlannedRequirement", "PlannedWorkItem", "QualifiedReference", "SourceManifest",
    "compile_plan", "compile_plan_json", "parse_plan_json", "PLAN_FORMAT", "PLAN_SCHEMA_VERSION",
]
