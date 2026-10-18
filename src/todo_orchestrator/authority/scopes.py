"""Shared containment of qualified capability scopes; no authentication here."""

from todo_orchestrator.contracts import EntityKind, EntityRef


def scope_covers(grant: EntityRef, target: EntityRef) -> bool:
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
        return target.definition_revision_id == grant.entity_id
    return False
