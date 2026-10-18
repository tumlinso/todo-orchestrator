"""Canonical, versioned encoding of complete accepted planning snapshots.

The codec contains JSON data only. It never loads pickle, imports qualified
Python objects from input, reads paths, or performs authority I/O.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Any, Mapping

from todo_orchestrator.contracts.domain import EntityKind, EntityRef, PlanRevision, Project, Sha256Digest, SourceProvenance, StableId

from .changes import AcceptedSnapshot, ChangeSet, _blocking_members, _declaration_value, _entity_ref_from_payload, _manifest_payload, _qualified_from_payload, _requirement_value, _work_value
from .package import (
    AdoptionReceipt, CompiledPlan, OwnershipConstraint, PlannedRequirement,
    PlannedWorkItem, QualifiedReference, VerifiedAdoption, _freeze, _thaw,
    compile_plan_json,
)

SNAPSHOT_FORMAT = "todo-orchestrator.accepted-snapshot"
SNAPSHOT_SCHEMA_VERSION = 1


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def accepted_plan_payload(plan: CompiledPlan) -> dict[str, Any]:
    """Return the complete effective plan payload, including omission masks."""
    work_items = []
    work_refs: dict[str, str] = {}
    parent_refs: dict[str, dict[str, Any] | None] = {}
    for item in plan.work_items:
        work = _work_value(item)
        work.pop("parent_ref", None)
        if work["motivation"] is None:
            work.pop("motivation")
        work_items.append(work)
        work_refs[str(item.definition.work_item_id)] = str(item.definition.definition_revision_id)
        parent_refs[str(item.definition.work_item_id)] = None if item.definition.parent is None else _ref_payload(item.definition.parent)

    requirements = []
    for item in plan.requirements:
        value = _requirement_value(item)
        if value["target"] is None:
            value.pop("target")
        if value["check_key"] is None:
            value.pop("check_key")
        requirements.append(value)
    requirement_refs = {
        str(item.definition.requirement_id): str(item.definition.definition_revision_id)
        for item in plan.requirements
    }


    declarations = [_declaration_value(item) for item in plan.declarations]
    dependencies = []
    for group in plan.blocking_groups:
        dependencies.append({
            "source": _qualified_payload(group.source),
            "mode": group.mode.value,
            "quorum": group.quorum,
            "members": [
                {
                    "relation": member.relation.value,
                    "target": _qualified_payload(member.target),
                    **({} if member.expected_version is None else {"expected_version": member.expected_version}),
                    **({} if member.condition is None else {"condition": _condition_payload(member.condition)}),
                }
                for member in group.members
            ],
        })

    package = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": str(plan.package_id),
        "project": {"project_id": str(plan.project.project_id), "authority_id": str(plan.project.authority_id)},
        "provenance": _provenance_payload(plan),
        "work_items": work_items,
        "requirements": requirements,
        "checkpoints": [_declaration_of_kind(item, "checkpoints") for item in plan.declarations if item.kind == "checkpoints"],
        "interfaces": [_declaration_of_kind(item, "interfaces") for item in plan.declarations if item.kind == "interfaces"],
        "decisions": [_declaration_of_kind(item, "decisions") for item in plan.declarations if item.kind == "decisions"],
        "barriers": [_declaration_of_kind(item, "barriers") for item in plan.declarations if item.kind == "barriers"],
        "rendezvous": [_declaration_of_kind(item, "rendezvous") for item in plan.declarations if item.kind == "rendezvous"],
        "invariants": [_declaration_of_kind(item, "invariants") for item in plan.declarations if item.kind == "invariants"],
        "dependencies": dependencies,
        "source_manifests": [_manifest_payload(item) for item in plan.source_manifests],
    }
    if plan.generation_metadata is not None:
        package["generation_metadata"] = _thaw(plan.generation_metadata)
    return {
        "package": package,
        "definition_refs": {"work_items": work_refs, "requirements": requirement_refs, "parents": parent_refs},
        "record_field_masks": _thaw(plan.record_field_masks),
        "supplied_sections": list(plan.supplied_sections),
        "source_manifests_supplied": plan.source_manifests_supplied,
        "generation_metadata_supplied": plan.generation_metadata_supplied,
        "source_provenance": _provenance_full_payload(plan),
        "verified_adoptions": [_adoption_payload(item) for item in plan.verified_adoptions],
    }


def encode_accepted_plan(
    plan: CompiledPlan,
    *,
    authority_id: StableId,
    semantic_revision: int,
    based_on_revision_id: StableId | None,
) -> str:
    if type(semantic_revision) is not int or semantic_revision < 1:
        raise ValueError("accepted snapshot semantic_revision must be a positive integer")
    body = {
        "format": SNAPSHOT_FORMAT,
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "authority_id": str(authority_id),
        "project_id": str(plan.project.project_id),
        "semantic_revision": semantic_revision,
        "plan_revision_id": str(plan.revision.plan_revision_id),
        "based_on_revision_id": None if based_on_revision_id is None else str(based_on_revision_id),
        "effective_plan": accepted_plan_payload(plan),
    }
    return _canonical(body)


def encode_accepted_snapshot(
    plan: CompiledPlan,
    *,
    authority_id: StableId,
    semantic_revision: int,
    based_on_revision_id: StableId | None,
) -> Any:
    """Create the exact immutable store record for a materialized plan."""
    from todo_orchestrator.authority.sqlite import DefinitionVersionRecord, PlanRevisionSnapshotRecord, PlanWorkMembership
    canonical = encode_accepted_plan(
        plan, authority_id=authority_id, semantic_revision=semantic_revision,
        based_on_revision_id=based_on_revision_id,
    )
    definitions = tuple(DefinitionVersionRecord(
        StableId(item["definition_revision_id"]), StableId(item["entity_id"]),
        item["canonical_json"], item["content_digest"],
    ) for item in definition_bundle_payloads(plan))
    memberships = tuple(PlanWorkMembership(
        item.definition.work_item_id, item.definition.definition_revision_id
    ) for item in plan.work_items)
    return PlanRevisionSnapshotRecord(
        plan.revision.plan_revision_id,
        canonical,
        hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        definitions,
        memberships,
    )


def decode_accepted_plan(canonical_json: str, project: Project, *, sequence: int) -> CompiledPlan:
    """Strictly validate and reconstruct one complete accepted compiled plan."""
    try:
        body = json.loads(canonical_json)
    except (TypeError, ValueError) as exc:
        raise ValueError("accepted snapshot is not valid JSON") from exc
    if not isinstance(body, dict) or _canonical(body) != canonical_json:
        raise ValueError("accepted snapshot must be a canonical JSON object")
    expected = {"format", "schema_version", "authority_id", "project_id", "semantic_revision", "plan_revision_id", "based_on_revision_id", "effective_plan"}
    if set(body) != expected or body["format"] != SNAPSHOT_FORMAT or body["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise ValueError("accepted snapshot format, version, or fields are invalid")
    if body["authority_id"] != str(project.authority_id) or body["project_id"] != str(project.project_id):
        raise ValueError("accepted snapshot authority/project identity mismatch")
    if type(body["semantic_revision"]) is not int or body["semantic_revision"] < 1 or type(sequence) is not int or sequence < 1:
        raise ValueError("accepted snapshot revision metadata is invalid")
    payload = body["effective_plan"]
    if not isinstance(payload, dict) or set(payload) != {
        "package", "definition_refs", "record_field_masks", "supplied_sections",
        "source_manifests_supplied", "generation_metadata_supplied", "source_provenance", "verified_adoptions",
    }:
        raise ValueError("accepted effective plan has an unsupported shape")
    if type(payload["source_manifests_supplied"]) is not bool or type(payload["generation_metadata_supplied"]) is not bool:
        raise ValueError("accepted supplied-field metadata is invalid")
    definitions = payload["definition_refs"]
    if not isinstance(definitions, dict) or set(definitions) != {"work_items", "requirements", "parents"}:
        raise ValueError("accepted definition reference map is invalid")
    if any(not isinstance(definitions[key], dict) for key in definitions):
        raise ValueError("accepted definition reference map entries are invalid")
    for key in ("work_items", "requirements"):
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in definitions[key].items()):
            raise ValueError("accepted definition version map entries are invalid")
    facts = tuple(_adoption_from_payload(item) for item in payload["verified_adoptions"])
    source = _canonical(payload["package"])
    result = compile_plan_json(
        source,
        project,
        revision_sequence=sequence,
        based_on_revision_id=None if body["based_on_revision_id"] is None else StableId(body["based_on_revision_id"]),
        adoption_facts=facts,
        _allow_exact_local_refs=True,
    )
    if not result.ok or result.plan is None:
        raise ValueError("accepted effective plan failed compilation: " + "; ".join(item.code for item in result.diagnostics))
    plan = result.plan
    work_ids = {str(item.definition.work_item_id) for item in plan.work_items}
    requirement_ids = {str(item.definition.requirement_id) for item in plan.requirements}
    if set(definitions["work_items"]) != work_ids or set(definitions["requirements"]) != requirement_ids:
        raise ValueError("accepted definition reference map does not match plan membership")
    if set(definitions["parents"]) != work_ids:
        raise ValueError("accepted parent reference map does not match work membership")
    for item in plan.requirements:
        requirement_id = str(item.definition.requirement_id)
        owner_revision = definitions["work_items"][str(item.definition.work_item_id)]
        if definitions["requirements"][requirement_id] != owner_revision:
            raise ValueError("accepted requirement version is not bound to its exact owner definition")
    revision_id = StableId(body["plan_revision_id"])
    work_ref_map = {key: EntityRef(project.project_id, EntityKind.WORK_ITEM, StableId(key), StableId(value)) for key, value in definitions["work_items"].items()}
    compiled_revision = replace(
        plan.revision,
        plan_revision_id=revision_id,
        sequence=sequence,
        based_on_revision_id=None if body["based_on_revision_id"] is None else StableId(body["based_on_revision_id"]),
        work_items=tuple(work_ref_map[key] for key in sorted(work_ref_map)),
    )
    work = []
    for item in plan.work_items:
        identifier = str(item.definition.work_item_id)
        current_ref = work_ref_map[identifier]
        definition = replace(item.definition, definition_revision_id=current_ref.definition_revision_id)
        parent_payload = definitions["parents"][identifier]
        if definition.parent is None and parent_payload is not None:
            raise ValueError("accepted parent reference exists without an authored parent")
        if definition.parent is not None and parent_payload is None:
            raise ValueError("accepted authored parent is missing its exact reference")
        if parent_payload is not None:
            parent = _entity_ref_from_payload(parent_payload)
            if parent.project_id != project.project_id or parent.kind is not EntityKind.WORK_ITEM or parent.entity_id != definition.parent.entity_id:
                raise ValueError("accepted parent reference does not match the authored parent")
            definition = replace(definition, parent=parent)
        context = item.context
        work.append(PlannedWorkItem(definition, context))
    requirement_owner_revs = {
        str(item.definition.requirement_id): work_ref_map[str(item.definition.work_item_id)].definition_revision_id
        for item in plan.requirements
    }
    requirements = tuple(
        PlannedRequirement(
            replace(item.definition, definition_revision_id=requirement_owner_revs[str(item.definition.requirement_id)]),
            item.target,
        )
        for item in plan.requirements
    )
    masks = payload["record_field_masks"]
    if not isinstance(masks, dict):
        raise ValueError("accepted field masks must be an object")
    from .package import _freeze as freeze
    restored = replace(
        plan,
        revision=replace(compiled_revision, provenance=_provenance_from_payload(payload["source_provenance"])),
        work_items=tuple(work),
        requirements=requirements,
        supplied_sections=tuple(payload["supplied_sections"]),
        source_manifests_supplied=payload["source_manifests_supplied"],
        generation_metadata_supplied=payload["generation_metadata_supplied"],
        record_field_masks=freeze(masks),
        canonical_json=_canonical(payload["package"]),
        content_digest=Sha256Digest(hashlib.sha256(_canonical(payload["package"]).encode("utf-8")).hexdigest()),
    )
    from .graph import validate_plan_graph
    validation = validate_plan_graph(restored)
    if not validation.ok:
        raise ValueError("accepted exact-reference graph is invalid: " + "; ".join(item.code for item in validation.diagnostics))
    return restored


def materialize_accepted_plan(proposal: CompiledPlan, snapshot: AcceptedSnapshot, changes: ChangeSet) -> CompiledPlan:
    """Bind a reviewed effective proposal to a unique immutable plan revision."""
    if changes.authority_id != snapshot.authority_id or changes.project_id != snapshot.project_id:
        raise ValueError("reviewed change set does not match the accepted snapshot")
    if changes.expected_authority_revision != snapshot.authority_revision or changes.expected_revision_id != snapshot.accepted_revision_id:
        raise ValueError("reviewed change set preconditions do not match the accepted snapshot")
    if proposal.project != changes.effective_plan.project:
        raise ValueError("proposal does not match the reviewed effective plan project")
    if changes.conflicts or any(getattr(item, "severity", None).value == "error" for item in changes.diagnostics):
        raise ValueError("a conflicted or invalid change set cannot be materialized")
    if changes.is_noop:
        raise ValueError("a semantic no-op has no new accepted plan revision")
    revision = replace(
        changes.effective_plan.revision,
        plan_revision_id=StableId("accepted-" + changes.digest.hex),
        sequence=1 if snapshot.accepted_plan is None else snapshot.accepted_plan.revision.sequence + 1,
        based_on_revision_id=snapshot.accepted_revision_id,
        work_items=tuple(item.definition.ref for item in changes.effective_plan.work_items),
    )
    accepted = replace(changes.effective_plan, revision=revision)
    from .graph import validate_plan_graph
    validation = validate_plan_graph(accepted)
    if not validation.ok:
        raise ValueError("materialized accepted graph is invalid: " + "; ".join(item.code for item in validation.diagnostics))
    return accepted


def _ref_payload(ref: EntityRef) -> dict[str, Any]:
    return {
        "project_id": str(ref.project_id), "kind": ref.kind.value, "entity_id": str(ref.entity_id),
        "revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def definition_bundle_payloads(plan: CompiledPlan) -> tuple[dict[str, Any], ...]:
    """Canonical immutable work-version payloads for normalized store rows."""
    work_refs = {str(item.definition.work_item_id): item.definition.ref for item in plan.work_items}
    requirements_by_owner: dict[str, dict[str, Any]] = {}
    for item in plan.requirements:
        requirements_by_owner.setdefault(str(item.definition.work_item_id), {})[str(item.definition.requirement_id)] = _requirement_value(
            item, {(EntityKind.WORK_ITEM.value, key): value for key, value in work_refs.items()},
            plan.project.project_id, plan.revision.plan_revision_id,
        )
    groups = _blocking_members(plan, {(EntityKind.WORK_ITEM.value, key): value for key, value in work_refs.items()})
    result = []
    for item in plan.work_items:
        ref = item.definition.ref
        work = _work_value(item)
        work["parent_ref"] = None if item.definition.parent is None else _ref_payload(item.definition.parent)
        source_key = _canonical({"project_id": str(ref.project_id), "kind": "work_item", "entity_id": str(ref.entity_id)})
        body = {
            "format": "todo-orchestrator.work-bundle", "schema_version": 1,
            "work_item_id": str(ref.entity_id), "definition_revision_id": str(ref.definition_revision_id),
            "work": work, "requirements": {
                key: requirements_by_owner[str(ref.entity_id)][key]
                for key in sorted(requirements_by_owner.get(str(ref.entity_id), {}))
            },
            "outgoing_blockers": [] if source_key not in groups else [groups[source_key]],
        }
        canonical = _canonical(body)
        result.append({
            "definition_revision_id": str(ref.definition_revision_id), "entity_id": str(ref.entity_id),
            "canonical_json": canonical, "content_digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        })
    return tuple(result)


def _qualified_payload(ref: QualifiedReference) -> dict[str, Any]:
    payload = _ref_payload(ref.reference)
    payload["kind"] = ref.declared_kind
    if ref.adoption_receipt is not None:
        payload["adoption_receipt"] = _adoption_receipt_payload(ref.adoption_receipt)
    return payload


def _declaration_of_kind(item: Any, kind: str) -> dict[str, Any]:
    if item.kind != kind:
        raise ValueError("declaration kind mismatch")
    return _thaw(item.payload)


def _condition_payload(condition: Any) -> dict[str, Any]:
    output = {"op": condition.op}
    for key, value in condition.arguments:
        if hasattr(value, "op") and hasattr(value, "arguments"):
            output[key] = _condition_payload(value)
        elif isinstance(value, tuple):
            output[key] = [_condition_payload(item) if hasattr(item, "op") else _thaw(item) for item in value]
        else:
            output[key] = _thaw(value)
    return output


def _provenance_payload(plan: CompiledPlan) -> dict[str, Any]:
    provenance = plan.revision.provenance
    if provenance is None:
        return {"source": "accepted-snapshot"}
    result = {"source": provenance.source}
    if provenance.producer is not None:
        result["producer"] = provenance.producer
    return result


def _provenance_full_payload(plan: CompiledPlan) -> dict[str, Any] | None:
    provenance = plan.revision.provenance
    if provenance is None:
        return None
    return {
        "source": provenance.source,
        "content_digest": provenance.content_digest.hex,
        "producer": provenance.producer,
    }


def _provenance_from_payload(value: Any) -> SourceProvenance | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"source", "content_digest", "producer"}:
        raise ValueError("accepted source provenance is invalid")
    return SourceProvenance(value["source"], Sha256Digest(value["content_digest"]), value["producer"])


def _adoption_receipt_payload(receipt: AdoptionReceipt) -> dict[str, str]:
    return {"receipt_id": str(receipt.receipt_id), "authority_id": str(receipt.authority_id), "contract_digest": receipt.contract_digest.hex}


def _adoption_payload(fact: VerifiedAdoption) -> dict[str, Any]:
    return {
        "verification_id": str(fact.verification_id), "declared_kind": fact.declared_kind,
        "reference": _ref_payload(fact.reference), "receipt": _adoption_receipt_payload(fact.receipt),
        "interface_version": fact.interface_version, "compatibility": fact.compatibility,
    }


def _adoption_from_payload(value: Any) -> VerifiedAdoption:
    if not isinstance(value, dict) or set(value) != {"verification_id", "declared_kind", "reference", "receipt", "interface_version", "compatibility"}:
        raise ValueError("accepted adoption fact is invalid")
    receipt = value["receipt"]
    reference = value["reference"]
    if not isinstance(receipt, dict) or not isinstance(reference, dict):
        raise ValueError("accepted adoption proof is invalid")
    return VerifiedAdoption(
        StableId(value["verification_id"]), value["declared_kind"], _entity_ref_from_payload(reference),
        AdoptionReceipt(StableId(receipt["receipt_id"]), StableId(receipt["authority_id"]), Sha256Digest(receipt["contract_digest"])),
        value["interface_version"], value["compatibility"],
    )
