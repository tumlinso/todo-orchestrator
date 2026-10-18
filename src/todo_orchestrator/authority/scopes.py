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
        EntityKind.WORK_ITEM, EntityKind.REQUIREMENT,
    }:
        return plan_membership is not None and target in plan_membership
    return False


__all__ = ["plan_scope_membership", "scope_covers"]
