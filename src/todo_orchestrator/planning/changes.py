"""Pure deterministic preview of plan changes against an accepted snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from dataclasses import replace
from typing import Any, Mapping

from todo_orchestrator.contracts.domain import (
    Attempt,
    AttemptState,
    EntityKind,
    EntityRef,
    Outcome,
    PlanRevision,
    RequirementGroup,
    RequirementKind,
    RequirementMode,
    Sha256Digest,
    StableId,
)

from .package import (
    CompiledPlan, OwnershipConstraint, PlanDeclaration, PlannedRequirement,
    PlannedWorkItem, QualifiedReference, WorkItemContext, _freeze, _thaw,
)


class ChangeKind(str, Enum):
    CREATE = "create"
    REVISE = "revise"
    LINK = "link"
    UNLINK = "unlink"
    SUPERSEDE = "supersede"
    RETARGET = "retarget"
    RETIRE = "retire"


@dataclass(frozen=True)
class ExplicitRetirement:
    """An explicit typed request to retire one exact accepted definition."""

    reference: EntityRef

    def __post_init__(self) -> None:
        if not isinstance(self.reference, EntityRef):
            raise TypeError("retirement requires an exact EntityRef")
        if self.reference.kind not in {
            EntityKind.WORK_ITEM, EntityKind.REQUIREMENT, EntityKind.CHECKPOINT,
            EntityKind.INTERFACE, EntityKind.DECISION, EntityKind.BARRIER,
            EntityKind.INVARIANT,
        }:
            raise ValueError("this entity kind cannot be retired by plan preview")


@dataclass(frozen=True)
class AcceptedSnapshot:
    """Caller-provided immutable authority facts; constructing it performs no I/O."""

    authority_id: StableId
    project_id: StableId
    authority_revision: int
    accepted_plan: CompiledPlan | None
    attempts: tuple[Attempt, ...] = ()
    outcomes: tuple[Outcome, ...] = ()
    locked_work_items: tuple[EntityRef, ...] = ()
    downstream_refs: tuple[EntityRef, ...] = ()

    def __post_init__(self) -> None:
        if self.accepted_plan is not None:
            if self.accepted_plan.project.project_id != self.project_id:
                raise ValueError("accepted plan project does not match snapshot project")
            if self.accepted_plan.project.authority_id != self.authority_id:
                raise ValueError("accepted plan authority does not match snapshot authority")
        if type(self.authority_revision) is not int or self.authority_revision < 0:
            raise ValueError("snapshot authority revision must be a non-negative integer")
        for name, value, expected in (
            ("attempts", self.attempts, Attempt),
            ("outcomes", self.outcomes, Outcome),
            ("locked_work_items", self.locked_work_items, EntityRef),
            ("downstream_refs", self.downstream_refs, EntityRef),
        ):
            if not isinstance(value, tuple) or any(not isinstance(item, expected) for item in value):
                raise TypeError(f"snapshot {name} must be a tuple of {expected.__name__} values")
        for item in self.attempts:
            if item.project_id != self.project_id:
                raise ValueError("snapshot attempts must belong to the snapshot project")
        for item in self.outcomes:
            if item.project_id != self.project_id:
                raise ValueError("snapshot outcomes must belong to the snapshot project")

    @property
    def accepted_revision_id(self) -> StableId | None:
        return None if self.accepted_plan is None else self.accepted_plan.revision.plan_revision_id


@dataclass(frozen=True)
class ChangeOperation:
    kind: ChangeKind
    entity_kind: str
    entity_id: StableId
    before: EntityRef | None
    after: EntityRef | None
    before_value: Mapping[str, Any] | None = None
    after_value: Mapping[str, Any] | None = None
    relation: str | None = None
    related_before: EntityRef | None = None
    related_after: EntityRef | None = None


@dataclass(frozen=True)
class ChangeConflict:
    code: str
    subject: EntityRef
    message: str
    related: EntityRef | None = None


@dataclass(frozen=True)
class AffectedWork:
    work_item: EntityRef
    requirements: tuple[EntityRef, ...] = ()
    consumers: tuple[EntityRef, ...] = ()
    attempts: tuple[EntityRef, ...] = ()
    outcomes: tuple[EntityRef, ...] = ()


@dataclass(frozen=True)
class ChangeSet:
    authority_id: StableId
    project_id: StableId
    expected_revision_id: StableId | None
    expected_authority_revision: int
    proposed_revision_id: StableId
    operations: tuple[ChangeOperation, ...]
    effective_definitions: tuple[EntityRef, ...]
    affected: tuple[AffectedWork, ...]
    conflicts: tuple[ChangeConflict, ...]
    warnings: tuple[str, ...]
    diagnostics: tuple[Any, ...]
    digest: Sha256Digest
    effective_plan: CompiledPlan

    @property
    def is_noop(self) -> bool:
        return not self.operations


_IN_FLIGHT = {
    AttemptState.ADMITTED,
    AttemptState.ACTIVE,
    AttemptState.REPORTED,
    AttemptState.EXPIRED,
    AttemptState.UNCERTAIN,
    AttemptState.QUARANTINED,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _ref_payload(ref: EntityRef | None) -> Any:
    if ref is None:
        return None
    return {
        "project_id": str(ref.project_id),
        "kind": ref.kind.value,
        "entity_id": str(ref.entity_id),
        "revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _qualified_payload(
    ref: QualifiedReference | None,
    effective_refs: Mapping[tuple[str, str], EntityRef] | None = None,
    local_project_id: StableId | None = None,
    source_revision_id: StableId | None = None,
) -> Any:
    if ref is None:
        return None
    reference = ref.reference
    if (effective_refs is not None and reference.project_id == local_project_id
            and (reference.definition_revision_id is None
                 or reference.definition_revision_id == source_revision_id)):
        replacement = effective_refs.get((ref.declared_kind, str(reference.entity_id)))
        if replacement is not None:
            reference = replacement
    payload = _ref_payload(reference)
    payload["kind"] = ref.declared_kind
    receipt = ref.adoption_receipt
    if receipt is not None:
        payload["adoption_receipt"] = {
            "receipt_id": str(receipt.receipt_id),
            "authority_id": str(receipt.authority_id),
            "contract_digest": receipt.contract_digest.hex,
        }
    return payload


def _work_value(item: PlannedWorkItem) -> dict[str, Any]:
    definition = item.definition
    return {
        "id": str(definition.work_item_id),
        "title": definition.title,
        "outcome": definition.outcome,
        "objective": item.context.objective,
        "motivation": item.context.motivation,
        "references": _thaw(item.context.references),
        "scope": _thaw(item.context.scope),
        "acceptance": _thaw(item.context.acceptance),
        "alternatives": _thaw(item.context.alternatives),
        "unknowns": list(item.context.unknowns),
        "delegated_judgment": list(item.context.delegated_judgment),
        "ownership": {
            "mode": item.context.ownership.mode,
            "actors": [_qualified_payload(actor) for actor in item.context.ownership.actors],
        },
        "parent_id": None if definition.parent is None else str(definition.parent.entity_id),
        "parent_ref": None if definition.parent is None else _ref_payload(definition.parent),
        "supersedes": [_ref_payload(ref) for ref in definition.supersedes],
        "requirement_groups": [
            {
                "kind": group.kind.value,
                "mode": group.mode.value,
                "members": [str(identifier) for identifier in group.requirement_ids],
                "quorum": group.quorum,
            }
            for group in definition.requirement_groups
        ],
    }


def _manifest_payload(item: Any) -> dict[str, str]:
    return {"id": str(item.source_id), "location": item.location, "sha256": item.digest.hex}


def _requirement_value(
    item: PlannedRequirement,
    effective_refs: Mapping[tuple[str, str], EntityRef] | None = None,
    local_project_id: StableId | None = None,
    source_revision_id: StableId | None = None,
) -> dict[str, Any]:
    definition = item.definition
    value = {
        "id": str(definition.requirement_id),
        "work_item_id": str(definition.work_item_id),
        "kind": definition.kind.value,
        "description": definition.description,
        "target": _qualified_payload(item.target, effective_refs, local_project_id, source_revision_id),
        "check_key": None if definition.check_key is None else str(definition.check_key),
    }
    if definition.verification is not None:
        value["verification"] = definition.verification.to_mapping()
    if definition.required_evidence:
        value["required_evidence"] = [item.to_mapping() for item in definition.required_evidence]
    return value


def _declaration_value(item: PlanDeclaration) -> dict[str, Any]:
    return _thaw(item.payload)


def _definition_ref(plan: CompiledPlan, kind: EntityKind, identifier: StableId, revision: StableId | None = None) -> EntityRef:
    return EntityRef(plan.project.project_id, kind, identifier, revision)


def _new_definition_revision(kind: str, value: Mapping[str, Any]) -> StableId:
    digest = hashlib.sha256(_canonical({"kind": kind, "value": value}).encode("utf-8")).hexdigest()
    return StableId(f"definition-{digest}")


def _same_target(a: EntityRef | None, b: EntityRef | None) -> bool:
    return a == b


def _work_by_id(plan: CompiledPlan) -> dict[str, PlannedWorkItem]:
    return {str(item.definition.work_item_id): item for item in plan.work_items}


def _requirements_by_id(plan: CompiledPlan) -> dict[str, PlannedRequirement]:
    return {str(item.definition.requirement_id): item for item in plan.requirements}


def _declarations_by_key(plan: CompiledPlan) -> dict[tuple[str, str], PlanDeclaration]:
    return {(item.kind, str(item.declaration_id)): item for item in plan.declarations}


def _masks(plan: CompiledPlan, section: str, identifier: str, all_fields: set[str]) -> set[str]:
    mask = plan.record_field_masks.get(section, {}).get(identifier)
    return set(all_fields if mask is None else mask)


def _merge_patch(old: Mapping[str, Any], new: Mapping[str, Any], mask: set[str]) -> dict[str, Any]:
    merged = dict(old)
    for key in mask:
        if key in new:
            merged[key] = new[key]
    return merged


def _source_version(plan: CompiledPlan) -> tuple[str, str]:
    return str(plan.project.project_id), str(plan.revision.plan_revision_id)


def _blocking_members(plan: CompiledPlan, effective_refs: Mapping[tuple[str, str], EntityRef] | None = None) -> dict[str, dict[str, Any]]:
    output = {}
    for group in plan.blocking_groups:
        source_payload = _qualified_payload(group.source, effective_refs, plan.project.project_id, plan.revision.plan_revision_id)
        source_key = _canonical({key: source_payload[key] for key in ("project_id", "kind", "entity_id")})
        output[source_key] = {
            "source": source_payload,
            "mode": group.mode.value,
            "quorum": group.quorum,
            "members": [
                {
                    "relation": member.relation.value,
                    "target": _qualified_payload(member.target, effective_refs, plan.project.project_id, plan.revision.plan_revision_id),
                    "expected_version": member.expected_version,
                    "condition": None if member.condition is None else _condition_payload(member.condition),
                }
                for member in group.members
            ],
        }
    return output


def _condition_payload(condition: Any) -> Any:
    if condition is None:
        return None
    output = {"op": condition.op}
    for key, value in condition.arguments:
        if hasattr(value, "op") and hasattr(value, "arguments"):
            output[key] = _condition_payload(value)
        elif isinstance(value, tuple):
            output[key] = [_condition_payload(item) if hasattr(item, "op") else item for item in value]
        else:
            output[key] = value
    return output


def _blocking_target_key(member: Mapping[str, Any]) -> str:
    return _canonical({k: member[k] for k in ("relation", "target")})


def _replace_local_ref_revision(value: Any, revision: StableId, project_id: StableId) -> Any:
    if isinstance(value, dict):
        result = {key: _replace_local_ref_revision(item, revision, project_id) for key, item in value.items()}
        if result.get("project_id") == str(project_id) and result.get("kind") in {"work_item", "requirement"}:
            result["revision_id"] = str(revision)
        return result
    if isinstance(value, list):
        return [_replace_local_ref_revision(item, revision, project_id) for item in value]
    return value


def preview_changes(
    proposal: CompiledPlan,
    snapshot: AcceptedSnapshot,
    *,
    explicit_retirements: tuple[ExplicitRetirement, ...] = (),
) -> ChangeSet:
    """Compare authored intent with exact accepted facts without authority I/O."""
    if proposal.project.project_id != snapshot.project_id or proposal.project.authority_id != snapshot.authority_id:
        raise ValueError("proposal project/authority does not match the explicit accepted snapshot")
    if not isinstance(explicit_retirements, tuple) or any(not isinstance(item, ExplicitRetirement) for item in explicit_retirements):
        raise TypeError("explicit_retirements must be a tuple of ExplicitRetirement values")
    accepted = snapshot.accepted_plan or _empty_plan(proposal)
    operations: list[ChangeOperation] = []
    conflicts: list[ChangeConflict] = []
    warnings: list[str] = []
    old_work = _work_by_id(accepted)
    new_work = _work_by_id(proposal)
    resulting_refs: dict[str, EntityRef] = {
        identifier: item.definition.ref for identifier, item in old_work.items()
    }
    changed_work: set[str] = set()

    for identifier, proposed in sorted(new_work.items()):
        before_item = old_work.get(identifier)
        proposed_value = _work_value(proposed)
        after_ref = proposed.definition.ref
        if before_item is None:
            operations.append(ChangeOperation(
                ChangeKind.CREATE, EntityKind.WORK_ITEM.value, StableId(identifier), None, after_ref,
                None, _freeze(proposed_value),
            ))
            resulting_refs[identifier] = after_ref
            changed_work.add(identifier)
            continue
        before_ref = before_item.definition.ref
        before_value = _work_value(before_item)
        mask = _masks(proposal, "work_items", identifier, set(proposed_value)) - {"id"}
        merged_value = _merge_patch(before_value, proposed_value, mask)
        if _canonical(merged_value) == _canonical(before_value):
            resulting_refs[identifier] = before_ref
            continue
        new_revision = _new_definition_revision("work_item", merged_value)
        after_ref = _definition_ref(proposal, EntityKind.WORK_ITEM, StableId(identifier), new_revision)
        operations.append(ChangeOperation(
            ChangeKind.REVISE, EntityKind.WORK_ITEM.value, StableId(identifier), before_ref, after_ref,
            _freeze(before_value), _freeze(merged_value),
        ))
        if before_value.get("parent_id") != merged_value.get("parent_id"):
            old_parent_item = None if before_value.get("parent_id") is None else old_work.get(before_value["parent_id"])
            old_parent = None if old_parent_item is None else old_parent_item.definition.ref
            new_parent = None if merged_value.get("parent_id") is None else resulting_refs.get(merged_value["parent_id"])
            if new_parent is None and merged_value.get("parent_id") is not None:
                new_parent = EntityRef(proposal.project.project_id, EntityKind.WORK_ITEM, StableId(merged_value["parent_id"]), proposal.revision.plan_revision_id)
            if old_parent is not None:
                operations.append(ChangeOperation(ChangeKind.UNLINK, "parent", StableId(identifier), before_ref, after_ref, relation="parent", related_before=old_parent))
            if new_parent is not None:
                operations.append(ChangeOperation(ChangeKind.LINK, "parent", StableId(identifier), before_ref, after_ref, relation="parent", related_after=new_parent))
        old_supersedes = {_canonical(item): item for item in before_value.get("supersedes", [])}
        new_supersedes = {_canonical(item): item for item in merged_value.get("supersedes", [])}
        for key in sorted(old_supersedes.keys() - new_supersedes.keys()):
            ref = old_supersedes[key]
            related = EntityRef(StableId(ref["project_id"]), EntityKind.WORK_ITEM, StableId(ref["entity_id"]), None if ref["revision_id"] is None else StableId(ref["revision_id"]))
            operations.append(ChangeOperation(ChangeKind.UNLINK, "supersedes", StableId(identifier), before_ref, after_ref, relation="supersedes", related_before=related))
        for key in sorted(new_supersedes.keys() - old_supersedes.keys()):
            ref = new_supersedes[key]
            related = EntityRef(StableId(ref["project_id"]), EntityKind.WORK_ITEM, StableId(ref["entity_id"]), None if ref["revision_id"] is None else StableId(ref["revision_id"]))
            operations.append(ChangeOperation(ChangeKind.SUPERSEDE, "supersedes", StableId(identifier), before_ref, after_ref, relation="supersedes", related_after=related))
        old_groups = {
            (group["kind"], requirement_id)
            for group in before_value.get("requirement_groups", ())
            for requirement_id in group["members"]
        }
        new_groups = {
            (group["kind"], requirement_id)
            for group in merged_value.get("requirement_groups", ())
            for requirement_id in group["members"]
        }
        for group_kind, requirement_id in sorted(old_groups - new_groups):
            related = EntityRef(snapshot.project_id, EntityKind.REQUIREMENT, StableId(requirement_id), before_ref.definition_revision_id)
            operations.append(ChangeOperation(ChangeKind.UNLINK, "requirement_group", StableId(identifier), before_ref, after_ref, relation=group_kind, related_before=related))
        for group_kind, requirement_id in sorted(new_groups - old_groups):
            related = EntityRef(proposal.project.project_id, EntityKind.REQUIREMENT, StableId(requirement_id), proposal.revision.plan_revision_id)
            operations.append(ChangeOperation(ChangeKind.LINK, "requirement_group", StableId(identifier), before_ref, after_ref, relation=group_kind, related_after=related))
        resulting_refs[identifier] = after_ref
        changed_work.add(identifier)

    # Parent links bind exact immutable definitions. Rebind descendants after
    # a parent revision and revise the child bundle rather than changing its
    # parent pointer under the old identity.
    for _ in range(max(1, len(new_work))):
        parent_links_changed = False
        for identifier, candidate in sorted(new_work.items()):
            before_item = old_work.get(identifier)
            if before_item is None:
                value = _work_value(candidate)
            else:
                candidate_value = _work_value(candidate)
                value = _merge_patch(
                    _work_value(before_item), candidate_value,
                    _masks(proposal, "work_items", identifier, set(candidate_value)) - {"id"},
                )
            parent_id = value.get("parent_id")
            parent_ref = None if parent_id is None else resulting_refs.get(str(parent_id))
            if parent_id is not None and parent_ref is None:
                continue
            next_parent = None if parent_ref is None else _ref_payload(parent_ref)
            if value.get("parent_ref") == next_parent:
                continue
            value["parent_ref"] = next_parent
            new_revision = _new_definition_revision("work_item", value)
            after_ref = EntityRef(proposal.project.project_id, EntityKind.WORK_ITEM, StableId(identifier), new_revision)
            index = next((i for i, operation in enumerate(operations)
                          if operation.entity_kind == EntityKind.WORK_ITEM.value
                          and operation.entity_id == StableId(identifier)
                          and operation.kind in {ChangeKind.CREATE, ChangeKind.REVISE}), None)
            if index is None:
                operations.append(ChangeOperation(
                    ChangeKind.REVISE, EntityKind.WORK_ITEM.value, StableId(identifier),
                    before_item.definition.ref, after_ref, _freeze(_work_value(before_item)), _freeze(value),
                    relation="parent_definition_revision",
                ))
            else:
                operation = operations[index]
                operations[index] = replace(operation, after=after_ref, after_value=_freeze(value))
            if resulting_refs.get(identifier) != after_ref:
                resulting_refs[identifier] = after_ref
                changed_work.add(identifier)
                parent_links_changed = True
        if not parent_links_changed:
            break

    effective_work_refs = {
        (EntityKind.WORK_ITEM.value, identifier): reference
        for identifier, reference in resulting_refs.items()
    }
    _preview_requirements(proposal, accepted, operations, effective_work_refs)
    _preview_declarations(proposal, accepted, operations, effective_work_refs)
    _preview_blocking(proposal, accepted, operations, effective_work_refs)
    if proposal.source_manifests_supplied:
        before_manifests = [_manifest_payload(item) for item in accepted.source_manifests]
        after_manifests = [_manifest_payload(item) for item in proposal.source_manifests]
        if _canonical(before_manifests) != _canonical(after_manifests):
            operations.append(ChangeOperation(
                ChangeKind.REVISE, "plan_metadata", StableId("source_manifests"),
                None, None, _freeze({"source_manifests": before_manifests}),
                _freeze({"source_manifests": after_manifests}), relation="source_manifests",
            ))
    accepted_refs = _accepted_definition_refs(accepted)
    valid_retired_requirement_refs = {
        item.reference
        for item in explicit_retirements
        if item.reference.project_id == snapshot.project_id
        and item.reference.kind is EntityKind.REQUIREMENT
        and item.reference in accepted_refs
    }
    resulting_refs = _revise_owned_definition_bundles(
        proposal, accepted, operations, resulting_refs,
        explicitly_retired_requirements=valid_retired_requirement_refs,
    )

    for operation in operations:
        if operation.entity_kind == EntityKind.WORK_ITEM.value:
            changed_work.add(str(operation.entity_id))
        elif operation.entity_kind == EntityKind.REQUIREMENT.value:
            for payload in (operation.before_value, operation.after_value):
                if payload and payload.get("work_item_id"):
                    changed_work.add(str(payload["work_item_id"]))
        elif operation.entity_kind == "interface":
            for payload in (operation.before_value, operation.after_value):
                if payload:
                    changed_work.update(str(ref.get("entity_id")) for ref in payload.get("consumers", ()))

    effective_refs = _accepted_definition_refs(accepted)
    for operation in operations:
        if operation.kind is ChangeKind.RETIRE:
            if operation.before is not None:
                effective_refs.discard(operation.before)
        elif operation.kind in {ChangeKind.CREATE, ChangeKind.REVISE}:
            if operation.before is not None:
                effective_refs.discard(operation.before)
            if operation.after is not None:
                effective_refs.add(operation.after)

    # Explicit retirements are exact and fail closed when the named accepted
    # definition is absent, stale, or protected by attempts/outcomes/locks.
    for retirement in sorted(explicit_retirements, key=lambda item: (item.reference.kind.value, str(item.reference.entity_id), str(item.reference.definition_revision_id or ""))):
        ref = retirement.reference
        if ref.project_id != snapshot.project_id:
            raise ValueError("retirement reference must belong to the snapshot project")
        known = _accepted_definition_refs(accepted)
        if ref not in known:
            conflicts.append(ChangeConflict("retirement_reference_not_in_snapshot", ref, "retirement must name an exact definition in the accepted snapshot"))
            continue
        operations.append(ChangeOperation(ChangeKind.RETIRE, ref.kind.value, ref.entity_id, ref, None))
        changed_work.add(str(ref.entity_id)) if ref.kind is EntityKind.WORK_ITEM else None
        effective_refs.discard(ref)

    # Graph validation must observe the final membership, including explicit
    # retirements. A prior validation of the pre-retirement proposal could
    # otherwise approve references that become dangling in the committed plan.
    effective_graph = _effective_graph_plan(proposal, accepted, resulting_refs, operations)
    effective_graph = _without_retired_definitions(effective_graph, operations, proposal)
    from .graph import validate_plan_graph
    graph_validation = validate_plan_graph(effective_graph)
    diagnostics = list(graph_validation.diagnostics)
    retired_refs = tuple(
        operation.before for operation in operations
        if operation.kind is ChangeKind.RETIRE and operation.before is not None
    )
    diagnostics.extend(_retirement_diagnostics(graph_validation, snapshot.project_id, retired_refs))
    diagnostics = tuple(sorted(diagnostics, key=lambda item: (item.path, item.code, item.message)))

    # A proposed revision is a separate immutable definition. In-flight attempts,
    # accepted outcomes, and scope locks are surfaced as guards, never rewritten.
    attempts_by_work: dict[EntityRef, list[Attempt]] = {}
    for attempt in snapshot.attempts:
        attempts_by_work.setdefault(attempt.work_item, []).append(attempt)
    outcomes_by_work: dict[EntityRef, list[Outcome]] = {}
    for outcome in snapshot.outcomes:
        outcomes_by_work.setdefault(outcome.work_item, []).append(outcome)
    locked = set(snapshot.locked_work_items)
    for operation in operations:
        if operation.entity_kind != EntityKind.WORK_ITEM.value or operation.kind not in {ChangeKind.REVISE, ChangeKind.RETIRE}:
            continue
        if operation.before is None:
            continue
        active = sorted(attempts_by_work.get(operation.before, ()), key=lambda item: str(item.attempt_id))
        terminal = sorted(outcomes_by_work.get(operation.before, ()), key=lambda item: str(item.outcome_id))
        if operation.before in locked:
            conflicts.append(ChangeConflict("work_item_locked", operation.before, "changed work is protected by an active named scope lock"))
        for attempt in active:
            if attempt.state in _IN_FLIGHT:
                conflicts.append(ChangeConflict("active_attempt_requires_transition", operation.before, f"attempt in state {attempt.state.value} binds the exact prior definition", attempt.ref))
        for outcome in terminal:
            # A completed definition may leave current membership only through
            # explicit supersession. Its outcome and evidence remain attached
            # to the immutable predecessor; supersession does not rewrite or
            # transfer that provenance to the successor.
            preserved_by_successor = (
                operation.kind is ChangeKind.RETIRE
                and any(
                    item.definition.ref != operation.before
                    and operation.before in item.definition.supersedes
                    for item in effective_graph.work_items
                )
            )
            if not preserved_by_successor:
                conflicts.append(ChangeConflict("accepted_outcome_preserved", operation.before, "accepted outcome remains bound to the prior exact definition", outcome.ref))

    affected = _impacts(accepted, proposal, changed_work, snapshot, attempts_by_work, outcomes_by_work)
    # Retiring a frozen interface is never treated as a simple deletion.
    frozen = _frozen_interface_refs(accepted)
    for operation in operations:
        if operation.kind is ChangeKind.RETIRE and operation.before in frozen:
            conflicts.append(ChangeConflict("frozen_interface_retirement", operation.before, "frozen interface history cannot be retired by an unconditional plan change"))
        if operation.kind is ChangeKind.REVISE and operation.entity_kind == "interface" and operation.before in frozen:
            conflicts.append(ChangeConflict("frozen_interface_revision", operation.before, "a frozen interface contract cannot be revised in place"))

    operations.sort(key=lambda item: (
        item.entity_kind, str(item.entity_id), item.kind.value,
        "" if item.before is None else str(item.before.definition_revision_id or ""),
        "" if item.after is None else str(item.after.definition_revision_id or ""),
        "" if item.related_before is None else _canonical(_ref_payload(item.related_before)),
        "" if item.related_after is None else _canonical(_ref_payload(item.related_after)),
    ))
    conflicts = sorted(set(conflicts), key=_conflict_sort_key)
    affected = tuple(sorted(affected, key=lambda item: (str(item.work_item.entity_id), str(item.work_item.definition_revision_id or ""))))
    body = {
        "authority_id": str(snapshot.authority_id),
        "project_id": str(snapshot.project_id),
        "expected_revision_id": None if snapshot.accepted_revision_id is None else str(snapshot.accepted_revision_id),
        "expected_authority_revision": snapshot.authority_revision,
        "proposed_revision_id": str(proposal.revision.plan_revision_id),
        "operations": [_operation_payload(item) for item in operations],
        "effective_definitions": [_ref_payload(ref) for ref in sorted(effective_refs, key=lambda ref: (ref.kind.value, str(ref.entity_id), str(ref.definition_revision_id or "")))],
        "conflicts": [_conflict_payload(item) for item in conflicts],
        "affected": [_affected_payload(item) for item in affected],
        "warnings": warnings,
        "diagnostics": [
            {"code": item.code, "message": item.message, "path": item.path, "severity": item.severity.value}
            for item in diagnostics
        ],
    }
    digest = Sha256Digest(hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest())
    return ChangeSet(
        snapshot.authority_id, snapshot.project_id, snapshot.accepted_revision_id, snapshot.authority_revision,
        proposal.revision.plan_revision_id, tuple(operations), tuple(sorted(effective_refs, key=lambda ref: (ref.kind.value, str(ref.entity_id), str(ref.definition_revision_id or "")))), affected, tuple(conflicts),
        tuple(warnings), tuple(diagnostics), digest, effective_graph,
    )


def _empty_plan(template: CompiledPlan) -> CompiledPlan:
    """Build an ephemeral empty baseline for an authority with no accepted plan."""
    revision = PlanRevision(
        plan_revision_id=StableId("unaccepted-plan"),
        project_id=template.project.project_id,
        sequence=1,
        work_items=(),
    )
    return replace(
        template,
        package_id=StableId("empty-plan"),
        revision=revision,
        work_items=(),
        requirements=(),
        declarations=(),
        blocking_groups=(),
        source_manifests=(),
        generation_metadata=None,
        source_manifests_supplied=False,
        generation_metadata_supplied=False,
        supplied_sections=(),
        verified_adoptions=(),
        canonical_json="{}",
        content_digest=Sha256Digest(hashlib.sha256(b"{}").hexdigest()),
        record_field_masks={},
    )


def _preview_requirements(
    proposal: CompiledPlan,
    accepted: CompiledPlan,
    operations: list[ChangeOperation],
    effective_work_refs: Mapping[tuple[str, str], EntityRef],
) -> None:
    old = _requirements_by_id(accepted)
    new = _requirements_by_id(proposal)
    accepted_work_refs = {
        (EntityKind.WORK_ITEM.value, str(item.definition.work_item_id)): item.definition.ref
        for item in accepted.work_items
    }
    for identifier, item in sorted(new.items()):
        before_item = old.get(identifier)
        value = _requirement_value(item, effective_work_refs, proposal.project.project_id, proposal.revision.plan_revision_id)
        after_ref = item.definition.ref
        if before_item is None:
            operations.append(ChangeOperation(ChangeKind.CREATE, EntityKind.REQUIREMENT.value, StableId(identifier), None, after_ref, None, _freeze(value)))
            continue
        old_value = _requirement_value(before_item, accepted_work_refs, accepted.project.project_id, accepted.revision.plan_revision_id)
        mask = _masks(proposal, "requirements", identifier, set(value)) - {"id"}
        merged = _merge_patch(old_value, value, mask)
        if _canonical(merged) == _canonical(old_value):
            continue
        new_rev = _new_definition_revision("requirement", merged)
        after_ref = EntityRef(proposal.project.project_id, EntityKind.REQUIREMENT, StableId(identifier), new_rev)
        operations.append(ChangeOperation(ChangeKind.REVISE, EntityKind.REQUIREMENT.value, StableId(identifier), before_item.definition.ref, after_ref, _freeze(old_value), _freeze(merged)))
        old_target, new_target = old_value.get("target"), merged.get("target")
        if old_target != new_target:
            before_target = before_item.target.reference if before_item.target is not None else None
            after_target = item.target.reference if item.target is not None else None
            operations.append(ChangeOperation(ChangeKind.RETARGET, EntityKind.REQUIREMENT.value, StableId(identifier), before_item.definition.ref, after_ref, relation="requirement_target", related_before=before_target, related_after=after_target))


def _preview_declarations(
    proposal: CompiledPlan,
    accepted: CompiledPlan,
    operations: list[ChangeOperation],
    effective_work_refs: Mapping[tuple[str, str], EntityRef],
) -> None:
    old, new = _declarations_by_key(accepted), _declarations_by_key(proposal)
    local_work_refs = {
        identifier: reference
        for (kind, identifier), reference in effective_work_refs.items()
        if kind == EntityKind.WORK_ITEM.value
    }
    accepted_work_refs = {
        str(item.definition.work_item_id): item.definition.ref
        for item in accepted.work_items
    }
    for (kind, identifier), item in sorted(new.items()):
        previous = old.get((kind, identifier))
        value = _rebind_payload_refs(_declaration_value(item), proposal.project.project_id, local_work_refs, proposal.revision.plan_revision_id)
        reference = EntityRef(proposal.project.project_id, _entity_kind_for_decl(kind), item.declaration_id)
        if previous is None:
            operations.append(ChangeOperation(ChangeKind.CREATE, kind[:-1] if kind.endswith("s") else kind, item.declaration_id, None, reference, None, _freeze(value)))
        else:
            previous_value = _rebind_payload_refs(
                _declaration_value(previous), accepted.project.project_id, accepted_work_refs,
                accepted.revision.plan_revision_id,
            )
            mask = _masks(proposal, kind, identifier, set(value)) - {"id"}
            merged = _merge_patch(previous_value, value, mask)
            merged = _rebind_payload_refs(merged, proposal.project.project_id, local_work_refs, proposal.revision.plan_revision_id)
            if _canonical(previous_value) != _canonical(merged):
                operations.append(ChangeOperation(ChangeKind.REVISE, kind[:-1] if kind.endswith("s") else kind, item.declaration_id, EntityRef(accepted.project.project_id, _entity_kind_for_decl(kind), item.declaration_id), reference, _freeze(previous_value), _freeze(merged)))


def _entity_kind_for_decl(kind: str) -> EntityKind:
    return {
        "checkpoints": EntityKind.CHECKPOINT,
        "interfaces": EntityKind.INTERFACE,
        "decisions": EntityKind.DECISION,
        "barriers": EntityKind.BARRIER,
        "rendezvous": EntityKind.BARRIER,
        "invariants": EntityKind.INVARIANT,
    }[kind]


def _preview_blocking(
    proposal: CompiledPlan,
    accepted: CompiledPlan,
    operations: list[ChangeOperation],
    effective_work_refs: Mapping[tuple[str, str], EntityRef],
) -> None:
    old_refs = {(EntityKind.WORK_ITEM.value, str(item.definition.work_item_id)): item.definition.ref for item in accepted.work_items}
    old_groups = _blocking_members(accepted, old_refs)
    new_groups = _blocking_members(proposal, effective_work_refs)
    for source in sorted(set(old_groups) | set(new_groups)):
        before = old_groups.get(source)
        after = new_groups.get(source)
        if before is None or after is None:
            continue  # An omitted source is not an implicit unlink or retirement.
        old_members = {_blocking_target_key(item): item for item in before["members"]}
        new_members = {_blocking_target_key(item): item for item in after["members"]}
        source_ref = before["source"]
        source_ent = _entity_ref_from_payload(source_ref)
        if (before["mode"], before["quorum"]) != (after["mode"], after["quorum"]):
            operations.append(ChangeOperation(ChangeKind.REVISE, "dependency_group", source_ent.entity_id, source_ent, source_ent, _freeze(before), _freeze(after), relation="group_policy"))
        for key in sorted(old_members.keys() - new_members.keys()):
            target = _entity_ref_from_payload(old_members[key]["target"])
            operations.append(ChangeOperation(ChangeKind.UNLINK, "dependency", source_ent.entity_id, source_ent, source_ent, relation=old_members[key]["relation"], related_before=target))
        for key in sorted(new_members.keys() - old_members.keys()):
            target = _entity_ref_from_payload(new_members[key]["target"])
            operations.append(ChangeOperation(ChangeKind.LINK, "dependency", source_ent.entity_id, source_ent, source_ent, relation=new_members[key]["relation"], related_after=target))
        for key in sorted(old_members.keys() & new_members.keys()):
            old_member, new_member = old_members[key], new_members[key]
            if old_member != new_member:
                operations.append(ChangeOperation(ChangeKind.RETARGET, "dependency", source_ent.entity_id, source_ent, source_ent, relation=new_member["relation"], related_before=_entity_ref_from_payload(old_member["target"]), related_after=_entity_ref_from_payload(new_member["target"])))


def _revise_owned_definition_bundles(
    proposal: CompiledPlan,
    accepted: CompiledPlan,
    operations: list[ChangeOperation],
    resulting_refs: dict[str, EntityRef],
    *,
    explicitly_retired_requirements: set[EntityRef] | None = None,
) -> dict[str, EntityRef]:
    """Bind work, its requirements, and outgoing gates to one definition revision."""
    explicitly_retired_requirements = explicitly_retired_requirements or set()
    old_work, new_work = _work_by_id(accepted), _work_by_id(proposal)
    owners: set[str] = set()
    for operation in operations:
        if operation.entity_kind == EntityKind.WORK_ITEM.value and operation.kind in {ChangeKind.CREATE, ChangeKind.REVISE}:
            owners.add(str(operation.entity_id))
        if operation.entity_kind == EntityKind.REQUIREMENT.value:
            for payload in (operation.before_value, operation.after_value):
                if payload and payload.get("work_item_id"):
                    owners.add(str(payload["work_item_id"]))
        if operation.entity_kind in {"dependency", "dependency_group"}:
            source = operation.before or operation.after
            if source is not None and source.kind is EntityKind.WORK_ITEM:
                owners.add(str(source.entity_id))
    if not owners:
        return resulting_refs

    old_req, new_req = _requirements_by_id(accepted), _requirements_by_id(proposal)
    explicitly_retired_requirements = {
        str(operation.before.entity_id)
        for operation in operations
        if operation.kind is ChangeKind.RETIRE
        and operation.before is not None
        and operation.before.kind is EntityKind.REQUIREMENT
    }
    old_group_values = _blocking_members(
        accepted,
        {(EntityKind.WORK_ITEM.value, str(item.definition.work_item_id)): item.definition.ref for item in accepted.work_items},
    )
    new_group_values = _blocking_members(
        proposal,
        {(EntityKind.WORK_ITEM.value, identifier): ref for identifier, ref in resulting_refs.items()},
    )
    effective_groups = dict(old_group_values)
    if "dependencies" in proposal.supplied_sections:
        for source_key, value in new_group_values.items():
            effective_groups[source_key] = value

    for identifier in sorted(owners):
        old_item, new_item = old_work.get(identifier), new_work.get(identifier)
        if old_item is None and new_item is None:
            continue
        if old_item is not None and new_item is not None:
            old_value = _work_value(old_item)
            candidate = _rebind_payload_refs(
                _work_value(new_item), proposal.project.project_id, resulting_refs,
                proposal.revision.plan_revision_id,
            )
            mask = _masks(proposal, "work_items", identifier, set(candidate)) - {"id"}
            work_value = _merge_patch(old_value, candidate, mask)
        elif new_item is not None:
            work_value = _rebind_payload_refs(
                _work_value(new_item), proposal.project.project_id, resulting_refs,
                proposal.revision.plan_revision_id,
            )
            old_value = None
        else:
            work_value = _work_value(old_item)
            old_value = work_value

        requirements = {}
        for requirement_id, item in old_req.items():
            if (str(item.definition.work_item_id) == identifier
                    and item.definition.ref not in explicitly_retired_requirements):
                requirements[requirement_id] = _requirement_value(
                    item,
                    {(EntityKind.WORK_ITEM.value, key): ref for key, ref in resulting_refs.items()},
                    proposal.project.project_id,
                    accepted.revision.plan_revision_id,
                )
        for requirement_id, item in new_req.items():
            if str(item.definition.work_item_id) != identifier:
                continue
            value = _requirement_value(
                item,
                {(EntityKind.WORK_ITEM.value, key): ref for key, ref in resulting_refs.items()},
                proposal.project.project_id,
                proposal.revision.plan_revision_id,
            )
            previous = old_req.get(requirement_id)
            if previous is not None:
                prior = _requirement_value(
                    previous,
                    {(EntityKind.WORK_ITEM.value, key): ref for key, ref in resulting_refs.items()},
                    proposal.project.project_id,
                    accepted.revision.plan_revision_id,
                )
                value = _merge_patch(prior, value, _masks(proposal, "requirements", requirement_id, set(value)) - {"id"})
            requirements[requirement_id] = value

        outgoing = [
            value for value in effective_groups.values()
            if value["source"]["project_id"] == str(proposal.project.project_id)
            and value["source"]["kind"] == "work_item"
            and value["source"]["entity_id"] == identifier
        ]
        identity_payload = _revision_fingerprint({
            "work": work_value,
            "requirements": {key: requirements[key] for key in sorted(requirements)},
            "outgoing_blockers": outgoing,
        }, proposal.project.project_id)
        new_revision = _new_definition_revision("work_bundle", identity_payload)
        after_work = EntityRef(proposal.project.project_id, EntityKind.WORK_ITEM, StableId(identifier), new_revision)
        resulting_refs[identifier] = after_work

        work_operation_index = next((
            index for index, operation in enumerate(operations)
            if operation.entity_kind == EntityKind.WORK_ITEM.value
            and operation.entity_id == StableId(identifier)
            and operation.kind in {ChangeKind.CREATE, ChangeKind.REVISE}
        ), None)
        if work_operation_index is None:
            if old_item is not None:
                operations.append(ChangeOperation(
                    ChangeKind.REVISE, EntityKind.WORK_ITEM.value, StableId(identifier),
                    old_item.definition.ref, after_work, _freeze(old_value), _freeze(work_value),
                    relation="owned_definition_bundle",
                ))
            elif new_item is not None:
                operations.append(ChangeOperation(
                    ChangeKind.CREATE, EntityKind.WORK_ITEM.value, StableId(identifier),
                    None, after_work, None, _freeze(work_value), relation="owned_definition_bundle",
                ))
        else:
            operation = operations[work_operation_index]
            operations[work_operation_index] = replace(operation, after=after_work)

        for requirement_id in sorted(requirements):
            before_item = old_req.get(requirement_id)
            proposed_item = new_req.get(requirement_id)
            before_ref = None if before_item is None else before_item.definition.ref
            after_ref = EntityRef(proposal.project.project_id, EntityKind.REQUIREMENT, StableId(requirement_id), new_revision)
            requirement_value = requirements[requirement_id]
            index = next((
                i for i, operation in enumerate(operations)
                if operation.entity_kind == EntityKind.REQUIREMENT.value and operation.entity_id == StableId(requirement_id)
                and operation.kind in {ChangeKind.CREATE, ChangeKind.REVISE}
            ), None)
            if index is None:
                if before_ref is not None:
                    operations.append(ChangeOperation(ChangeKind.REVISE, EntityKind.REQUIREMENT.value, StableId(requirement_id), before_ref, after_ref, _freeze(requirement_value), _freeze(requirement_value), relation="owner_definition_revision"))
            else:
                operations[index] = replace(operations[index], after=after_ref)

        for index, operation in enumerate(operations):
            if operation.entity_id == StableId(identifier) and operation.entity_kind == EntityKind.WORK_ITEM.value:
                if operation.kind is not ChangeKind.CREATE:
                    operations[index] = replace(operation, after=after_work)
            elif operation.entity_kind in {"dependency", "dependency_group"} and operation.before is not None and operation.before.kind is EntityKind.WORK_ITEM and operation.before.entity_id == StableId(identifier):
                operations[index] = replace(operation, after=after_work)

    # Retarget local dependency/requirement/parent operations to the exact
    # effective definitions selected above, never to the proposal's whole-plan ID.
    for index, operation in enumerate(operations):
        if operation.related_after is not None and operation.related_after.project_id == proposal.project.project_id:
            replacement = resulting_refs.get(str(operation.related_after.entity_id)) if operation.related_after.kind is EntityKind.WORK_ITEM else None
            if replacement is not None:
                operations[index] = replace(operation, related_after=replacement)
    return resulting_refs


def _revision_fingerprint(value: Any, project_id: StableId, preserve_revision_lists: bool = False) -> Any:
    if isinstance(value, Mapping):
        output = {}
        for key, item in value.items():
            output[key] = _revision_fingerprint(item, project_id, preserve_revision_lists or key == "supersedes")
        return output
    if isinstance(value, tuple):
        return [_revision_fingerprint(item, project_id, preserve_revision_lists) for item in value]
    if isinstance(value, list):
        return [_revision_fingerprint(item, project_id, preserve_revision_lists) for item in value]
    return value


def _entity_ref_from_payload(payload: Mapping[str, Any]) -> EntityRef:
    kind_name = payload["kind"]
    if kind_name == "rendezvous":
        kind = EntityKind.BARRIER
    else:
        kind = EntityKind(kind_name)
    return EntityRef(
        StableId(payload["project_id"]), kind, StableId(payload["entity_id"]),
        None if payload.get("revision_id") is None else StableId(payload["revision_id"]),
        None if payload.get("incarnation_id") is None else StableId(payload["incarnation_id"]),
    )


def _qualified_from_payload(payload: Mapping[str, Any]) -> QualifiedReference:
    receipt_payload = payload.get("adoption_receipt")
    receipt = None if receipt_payload is None else AdoptionReceipt(
        StableId(receipt_payload["receipt_id"]),
        StableId(receipt_payload["authority_id"]),
        Sha256Digest(receipt_payload["contract_digest"]),
    )
    return QualifiedReference(_entity_ref_from_payload(payload), payload["kind"], receipt)


def _accepted_definition_refs(plan: CompiledPlan) -> set[EntityRef]:
    refs = {item.definition.ref for item in plan.work_items}
    refs.update(item.definition.ref for item in plan.requirements)
    refs.update(EntityRef(plan.project.project_id, _entity_kind_for_decl(item.kind), item.declaration_id) for item in plan.declarations)
    return refs


def _effective_graph_plan(
    proposal: CompiledPlan,
    accepted: CompiledPlan,
    effective_work_refs: Mapping[str, EntityRef],
    operations: list[ChangeOperation],
) -> CompiledPlan:
    """Validate the proposal graph after retaining omitted accepted records."""
    supplied = set(proposal.supplied_sections)
    old_work, new_work = _work_by_id(accepted), _work_by_id(proposal)
    effective_work = dict(old_work)
    for identifier, candidate in new_work.items():
        old = old_work.get(identifier)
        if old is None:
            parent_id = _work_value(candidate).get("parent_id")
            parent = effective_work_refs.get(parent_id) if parent_id is not None else None
            definition = replace(
                candidate.definition,
                definition_revision_id=effective_work_refs[identifier].definition_revision_id,
                parent=parent,
            )
            effective_work[identifier] = replace(candidate, definition=definition)
            continue
        mask = _masks(proposal, "work_items", identifier, set(_work_value(candidate)))
        merged_value = _merge_patch(_work_value(old), _work_value(candidate), mask)
        parent_id = merged_value.get("parent_id")
        parent = old.definition.parent if "parent_id" not in mask else candidate.definition.parent
        if "parent_id" in mask and parent_id is None:
            parent = None
        elif parent_id is not None and parent_id in effective_work_refs:
            parent = effective_work_refs[parent_id]
        merged_value["parent_ref"] = None if parent is None else _ref_payload(parent)
        definition = replace(
            candidate.definition,
            title=merged_value["title"],
            outcome=merged_value["outcome"],
            definition_revision_id=effective_work_refs[identifier].definition_revision_id,
            parent=parent,
            supersedes=tuple(_entity_ref_from_payload(item) for item in merged_value["supersedes"]),
            requirement_groups=tuple(RequirementGroup(
                RequirementKind[item["kind"].upper()],
                RequirementMode(item["mode"]),
                tuple(StableId(value) for value in item["members"]),
                item["quorum"],
            ) for item in merged_value["requirement_groups"]),
        )
        context = WorkItemContext(
            objective=merged_value["objective"],
            motivation=merged_value["motivation"],
            references=tuple(_freeze(item) for item in merged_value["references"]),
            scope=_freeze(merged_value["scope"]),
            acceptance=_freeze(merged_value["acceptance"]),
            alternatives=tuple(_freeze(item) for item in merged_value["alternatives"]),
            unknowns=tuple(merged_value["unknowns"]),
            delegated_judgment=tuple(merged_value["delegated_judgment"]),
            ownership=OwnershipConstraint(
                merged_value["ownership"]["mode"],
                tuple(_qualified_from_payload(actor) for actor in merged_value["ownership"]["actors"]),
            ),
        )
        effective_work[identifier] = PlannedWorkItem(definition, context)
    for identifier, item in tuple(effective_work.items()):
        if identifier in new_work:
            continue
        definition = replace(item.definition, definition_revision_id=effective_work_refs[identifier].definition_revision_id)
        effective_work[identifier] = replace(item, definition=definition)

    old_reqs, new_reqs = _requirements_by_id(accepted), _requirements_by_id(proposal)
    effective_reqs = dict(old_reqs)
    for identifier, candidate in new_reqs.items():
        owner_id = str(candidate.definition.work_item_id)
        owner_ref = effective_work_refs.get(owner_id)
        revision = candidate.definition.definition_revision_id if owner_ref is None else owner_ref.definition_revision_id
        target = candidate.definition.target
        if (target is not None and target.project_id == proposal.project.project_id
                and target.kind is EntityKind.WORK_ITEM
                and (target.definition_revision_id is None
                     or target.definition_revision_id == proposal.revision.plan_revision_id)):
            target = effective_work_refs.get(str(target.entity_id), target)
        definition = replace(candidate.definition, definition_revision_id=revision, target=target)
        qualified = candidate.target
        if qualified is not None and target != qualified.reference:
            qualified = replace(qualified, reference=target)
        effective_reqs[identifier] = replace(candidate, definition=definition, target=qualified)
    for identifier, candidate in tuple(effective_reqs.items()):
        if identifier in new_reqs:
            continue
        owner_id = str(candidate.definition.work_item_id)
        revision = effective_work_refs.get(owner_id)
        if revision is not None:
            definition = replace(candidate.definition, definition_revision_id=revision.definition_revision_id)
            effective_reqs[identifier] = replace(candidate, definition=definition)

    old_declarations, new_declarations = _declarations_by_key(accepted), _declarations_by_key(proposal)
    effective_declarations = dict(old_declarations)
    for key, candidate in new_declarations.items():
        kind, identifier = key
        previous = old_declarations.get(key)
        if previous is not None:
            candidate_payload = _declaration_value(candidate)
            previous_payload = _declaration_value(previous)
            mask = _masks(proposal, kind, identifier, set(candidate_payload))
            merged = _merge_patch(previous_payload, candidate_payload, mask)
            candidate = replace(candidate, payload=_freeze(merged))
        candidate = replace(candidate, payload=_freeze(_rebind_payload_refs(candidate.payload, proposal.project.project_id, effective_work_refs)))
        effective_declarations[key] = candidate

    old_groups = list(accepted.blocking_groups)
    candidate_sources = {_blocking_logical_source(item.source, proposal.project.project_id) for item in proposal.blocking_groups}
    if "dependencies" in supplied:
        old_groups = [item for item in old_groups if _blocking_logical_source(item.source, accepted.project.project_id) not in candidate_sources]
        # Candidate-local refs carry the proposal's compiler revision as a
        # placeholder. Bind only those refs to the effective exact versions;
        # retained accepted groups keep their historical exact targets.
        old_groups.extend(
            replace(
                group,
                source=_rebind_qualified(group.source, proposal.project.project_id, effective_work_refs, proposal.revision.plan_revision_id),
                members=tuple(replace(
                    member,
                    target=_rebind_qualified(member.target, proposal.project.project_id, effective_work_refs, proposal.revision.plan_revision_id),
                ) for member in group.members),
            )
            for group in proposal.blocking_groups
        )
    # Retained and newly authored groups must share the compiler's canonical
    # source order so the complete accepted snapshot round-trips unchanged.
    rebound_groups = sorted(
        old_groups, key=lambda group: _canonical(_qualified_payload(group.source)),
    )
    merged_masks: dict[str, dict[str, tuple[str, ...]]] = {
        section: {identifier: tuple(fields) for identifier, fields in records.items()}
        for section, records in accepted.record_field_masks.items()
    }
    for section, records in proposal.record_field_masks.items():
        target_records = merged_masks.setdefault(section, {})
        for identifier, fields in records.items():
            target_records[identifier] = tuple(sorted(set(target_records.get(identifier, ())) | set(fields)))

    return replace(
        proposal,
        revision=replace(proposal.revision, work_items=tuple(effective_work[key].definition.ref for key in sorted(effective_work))),
        work_items=tuple(effective_work[key] for key in sorted(effective_work)),
        requirements=tuple(effective_reqs[key] for key in sorted(effective_reqs)),
        declarations=tuple(effective_declarations[key] for key in sorted(effective_declarations)),
        blocking_groups=tuple(rebound_groups),
        source_manifests=(
            proposal.source_manifests
            if proposal.source_manifests_supplied
            else accepted.source_manifests
        ),
        source_manifests_supplied=proposal.source_manifests_supplied or accepted.source_manifests_supplied,
        generation_metadata=(
            proposal.generation_metadata
            if getattr(proposal, "generation_metadata_supplied", False)
            else accepted.generation_metadata
        ),
        generation_metadata_supplied=proposal.generation_metadata_supplied or accepted.generation_metadata_supplied,
        supplied_sections=tuple(sorted(set(proposal.supplied_sections) | set(accepted.supplied_sections))),
        record_field_masks=_freeze(merged_masks),
    )


def _without_retired_definitions(
    plan: CompiledPlan,
    operations: list[ChangeOperation],
    proposal: CompiledPlan,
) -> CompiledPlan:
    retired = {operation.before for operation in operations if operation.kind is ChangeKind.RETIRE and operation.before is not None}
    if not retired:
        return plan
    retired_requirements = {
        ref.entity_id for ref in retired if ref.kind is EntityKind.REQUIREMENT
    }
    # An explicitly retired exact requirement may be re-authored as a new
    # version in the same proposal. Otherwise, owner-bundle rebinding must not
    # accidentally resurrect it with the successor owner's revision.
    replacement_requirements = {
        item.definition.requirement_id for item in proposal.requirements
        if item.definition.requirement_id in retired_requirements
    }
    return replace(
        plan,
        revision=replace(plan.revision, work_items=tuple(
            item.definition.ref for item in plan.work_items if item.definition.ref not in retired
        )),
        work_items=tuple(item for item in plan.work_items if item.definition.ref not in retired),
        requirements=tuple(
            item for item in plan.requirements
            if item.definition.ref not in retired
            and not (
                item.definition.ref.kind is EntityKind.REQUIREMENT
                and item.definition.ref.entity_id in retired_requirements
                and item.definition.ref.entity_id not in replacement_requirements
            )
        ),
        declarations=tuple(
            item for item in plan.declarations
            if EntityRef(plan.project.project_id, _entity_kind_for_decl(item.kind), item.declaration_id) not in retired
        ),
    )


def _retirement_diagnostics(graph_validation: Any, project_id: StableId, retired_refs: tuple[EntityRef, ...]) -> tuple[Any, ...]:
    """Report local graph references whose exact definitions were retired."""
    from .graph import PlanNode
    from .package import DiagnosticSeverity, PlanDiagnostic

    diagnostics = []
    seen: set[tuple[str, str, str]] = set()
    retired = {
        (str(ref.project_id), ref.kind.value, str(ref.entity_id), str(ref.definition_revision_id or ""))
        for ref in retired_refs
    }
    for edge in (*graph_validation.edges, *graph_validation.lineage_edges):
        # A successor's exact supersedes edge is the durable lineage that
        # preserves a retired predecessor in history; it is not a dangling
        # dependency that must be retargeted.
        if edge.relation == "supersedes":
            continue
        for node in (edge.source, edge.target):
            if node.project_id != str(project_id) or node.kind == "evidence":
                continue
            exact = (node.project_id, node.kind, node.entity_id, node.revision_id)
            logical = (node.project_id, node.kind, node.entity_id, "")
            if exact not in retired and logical not in retired:
                continue
            marker = (node.kind, node.entity_id, edge.path)
            if marker in seen:
                continue
            seen.add(marker)
            diagnostics.append(PlanDiagnostic(
                "retired_definition_still_referenced",
                f"local {node.kind} {node.entity_id} is referenced but is absent from the final plan membership",
                edge.path,
                DiagnosticSeverity.ERROR,
            ))
    return tuple(diagnostics)


def _blocking_logical_source(reference: QualifiedReference, project_id: StableId) -> str:
    payload = _qualified_payload(reference, local_project_id=project_id)
    return _canonical({key: payload[key] for key in ("project_id", "kind", "entity_id")})


def _rebind_qualified(
    reference: QualifiedReference,
    project_id: StableId,
    work_refs: Mapping[str, EntityRef],
    source_revision_id: StableId | None = None,
) -> QualifiedReference:
    ref = reference.reference
    if (ref.project_id == project_id and reference.declared_kind == EntityKind.WORK_ITEM.value
            and (ref.definition_revision_id is None or ref.definition_revision_id == source_revision_id)):
        replacement = work_refs.get(str(ref.entity_id))
        if replacement is not None:
            return replace(reference, reference=replacement)
    return reference


def _rebind_payload_refs(
    value: Any,
    project_id: StableId,
    work_refs: Mapping[str, EntityRef],
    source_revision_id: StableId | None = None,
) -> Any:
    if isinstance(value, Mapping):
        output = {key: _rebind_payload_refs(item, project_id, work_refs, source_revision_id) for key, item in value.items()}
        if (output.get("project_id") == str(project_id)
                and output.get("kind") == EntityKind.WORK_ITEM.value
                and (output.get("revision_id") is None
                     or output.get("revision_id") == str(source_revision_id))):
            replacement = work_refs.get(str(output.get("entity_id")))
            if replacement is not None:
                output["revision_id"] = str(replacement.definition_revision_id)
        return output
    if isinstance(value, (tuple, list)):
        return [_rebind_payload_refs(item, project_id, work_refs, source_revision_id) for item in value]
    return value


def _frozen_interface_refs(plan: CompiledPlan) -> set[EntityRef]:
    return {
        EntityRef(plan.project.project_id, EntityKind.INTERFACE, item.declaration_id)
        for item in plan.declarations
        if item.kind == "interfaces" and item.payload.get("compatibility") == "frozen"
    }


def _impacts(
    accepted: CompiledPlan,
    proposal: CompiledPlan,
    changed: set[str],
    snapshot: AcceptedSnapshot,
    attempts_by_work: Mapping[EntityRef, list[Attempt]],
    outcomes_by_work: Mapping[EntityRef, list[Outcome]],
) -> tuple[AffectedWork, ...]:
    if not changed:
        return ()
    changed_ids = set(changed)
    impacted: dict[str, dict[str, set[EntityRef]]] = {}
    plans = (accepted, proposal)
    for plan in plans:
        for item in plan.requirements:
            target = item.target
            if target is not None and str(target.reference.entity_id) in changed_ids:
                owner = item.definition.owner
                bucket = impacted.setdefault(str(owner.entity_id), {"requirements": set(), "consumers": set()})
                bucket["requirements"].add(item.definition.ref)
        for declaration in plan.declarations:
            if declaration.kind == "interfaces":
                producers = declaration.payload.get("producers", ())
                for consumer in declaration.payload.get("consumers", ()):
                    if (
                        str(declaration.declaration_id) in changed_ids
                        or any(str(producer.get("entity_id")) in changed_ids for producer in producers)
                    ):
                        consumer_id = str(consumer["entity_id"])
                        bucket = impacted.setdefault(consumer_id, {"requirements": set(), "consumers": set()})
                        bucket["consumers"].add(EntityRef(plan.project.project_id, EntityKind.INTERFACE, declaration.declaration_id))
        for group in plan.blocking_groups:
            if str(group.source.reference.entity_id) in changed_ids:
                continue
            if any(str(member.target.reference.entity_id) in changed_ids for member in group.members):
                source = group.source.reference
                if source.kind is EntityKind.WORK_ITEM:
                    impacted.setdefault(str(source.entity_id), {"requirements": set(), "consumers": set()})
    for ref in snapshot.downstream_refs:
        if ref.kind is EntityKind.WORK_ITEM:
            impacted.setdefault(str(ref.entity_id), {"requirements": set(), "consumers": set()})
    old_work = _work_by_id(accepted)
    for identifier in changed_ids:
        if identifier in old_work:
            ref = old_work[identifier].definition.ref
            impacted.setdefault(identifier, {"requirements": set(), "consumers": set()})
    result = []
    for identifier, pieces in sorted(impacted.items()):
        item = old_work.get(identifier)
        if item is None:
            item = _work_by_id(proposal).get(identifier)
        if item is None:
            continue
        ref = item.definition.ref
        attempts = tuple(sorted((a.ref for a in attempts_by_work.get(ref, ())), key=lambda x: str(x.entity_id)))
        outcomes = tuple(sorted((o.ref for o in outcomes_by_work.get(ref, ())), key=lambda x: str(x.entity_id)))
        result.append(AffectedWork(
            ref,
            tuple(sorted(pieces["requirements"], key=lambda x: (str(x.entity_id), str(x.definition_revision_id or "")))),
            tuple(sorted(pieces["consumers"], key=lambda x: str(x.entity_id))),
            attempts,
            outcomes,
        ))
    return tuple(result)


def _operation_payload(item: ChangeOperation) -> dict[str, Any]:
    return {
        "kind": item.kind.value,
        "entity_kind": item.entity_kind,
        "entity_id": str(item.entity_id),
        "before": _ref_payload(item.before),
        "after": _ref_payload(item.after),
        "before_value": _thaw(item.before_value),
        "after_value": _thaw(item.after_value),
        "relation": item.relation,
        "related_before": _ref_payload(item.related_before),
        "related_after": _ref_payload(item.related_after),
    }


def _conflict_payload(item: ChangeConflict) -> dict[str, Any]:
    return {"code": item.code, "subject": _ref_payload(item.subject), "message": item.message, "related": _ref_payload(item.related)}


def _conflict_sort_key(item: ChangeConflict) -> tuple[str, str, str, str, str]:
    return (
        item.code,
        str(item.subject.project_id),
        item.subject.kind.value,
        str(item.subject.entity_id),
        "" if item.related is None else _canonical(_ref_payload(item.related)),
    )


def _affected_payload(item: AffectedWork) -> dict[str, Any]:
    return {
        "work_item": _ref_payload(item.work_item),
        "requirements": [_ref_payload(ref) for ref in item.requirements],
        "consumers": [_ref_payload(ref) for ref in item.consumers],
        "attempts": [_ref_payload(ref) for ref in item.attempts],
        "outcomes": [_ref_payload(ref) for ref in item.outcomes],
    }
