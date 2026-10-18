"""Shared containment of qualified capability scopes; no authentication here."""

import json
import sqlite3

from todo_orchestrator.contracts import EntityKind, EntityRef, Project, StableId

from .sqlite import load_plan_revision_snapshot


def plan_scope_membership(
    connection: sqlite3.Connection,
    project: Project,
    plan_revision: EntityRef,
) -> frozenset[EntityRef]:
    """Resolve exact work and requirement refs selected by a stored accepted plan."""

    if plan_revision.kind is not EntityKind.PLAN_REVISION or plan_revision.project_id != project.project_id:
        return frozenset()
    snapshot = load_plan_revision_snapshot(connection, project, plan_revision.entity_id)
    members: set[EntityRef] = set()
    for work in snapshot.work_items:
        members.add(EntityRef(project.project_id, EntityKind.WORK_ITEM,
                              work.work_item_id, work.definition_revision_id))
    for definition in snapshot.definitions:
        bundle = json.loads(definition.canonical_json)
        for requirement_id in bundle["requirements"]:
            members.add(EntityRef(project.project_id, EntityKind.REQUIREMENT,
                                  StableId(requirement_id), definition.definition_revision_id))
    # Plans scope their exact immutable declarations alongside work and
    # requirement definitions. This makes a plan-scoped capability useful for
    # the declaration commands without granting it project-wide reach.
    effective = json.loads(snapshot.canonical_json)["effective_plan"]
    # The accepted-snapshot envelope keeps declarations in the authored
    # package under ``effective_plan.package``. Keep compatibility with the
    # earlier in-development flat envelope while reading only validated
    # accepted snapshots.
    authored = effective.get("package", effective)
    declaration_kinds = {
        "checkpoints": EntityKind.CHECKPOINT,
        "interfaces": EntityKind.INTERFACE,
        "decisions": EntityKind.DECISION,
        "barriers": EntityKind.BARRIER,
        "rendezvous": EntityKind.BARRIER,
        "invariants": EntityKind.INVARIANT,
    }
    for section, kind in declaration_kinds.items():
        for declaration in authored.get(section, ()):
            members.add(EntityRef(project.project_id, kind, StableId(declaration["id"])))
    return frozenset(members)


def scope_covers(
    grant: EntityRef,
    target: EntityRef,
    *,
    plan_membership: frozenset[EntityRef] | None = None,
) -> bool:
    """Cover the project, one plan's definitions, or one exact qualified entity."""
    if grant.project_id != target.project_id:
        return False
    if grant.kind is EntityKind.PROJECT:
        return grant.entity_id == target.project_id
    if grant == target:
        return True
    if grant.kind is EntityKind.PLAN_REVISION and target.kind in {
        EntityKind.WORK_ITEM, EntityKind.REQUIREMENT, EntityKind.CHECKPOINT,
        EntityKind.INTERFACE, EntityKind.DECISION, EntityKind.BARRIER,
        EntityKind.INVARIANT,
    }:
        return plan_membership is not None and target in plan_membership
    return False


__all__ = ["plan_scope_membership", "scope_covers"]
