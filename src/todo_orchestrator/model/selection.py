"""Typed advisory candidate returned before workspace creation and dispatch."""

from __future__ import annotations

from dataclasses import dataclass

from todo_orchestrator.contracts import EntityKind, EntityRef

from .eligibility import EligibilityDecision


@dataclass(frozen=True)
class NextWorkSelection:
    """One bounded queue candidate and its native eligibility observation.

    Selection does not claim or reserve the target. Exact dispatch must still
    re-evaluate eligibility under its writer transaction after workspace
    qualification and the caller's revision check.
    """

    target: EntityRef
    plan_revision: EntityRef
    authority_revision: int
    eligibility: EligibilityDecision
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    workspace_qualification_required: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return the bounded mapping used by thin host/facade adapters."""
        return {
            "work_item_id": str(self.target.entity_id),
            "definition_revision_id": str(self.target.definition_revision_id),
            "run_id": None if self.run is None else str(self.run.entity_id),
            "assignment_id": None if self.assignment is None else str(self.assignment.entity_id),
            "plan_revision_id": str(self.plan_revision.entity_id),
            "authority_revision": self.authority_revision,
            "status": self.eligibility.status.value,
            "reasons": [
                {"code": cause.code, "message": cause.message}
                for cause in self.eligibility.causes
            ],
            "workspace_qualification_required": self.workspace_qualification_required,
        }

    def __post_init__(self) -> None:
        if not isinstance(self.target, EntityRef) or self.target.kind is not EntityKind.WORK_ITEM:
            raise TypeError("target must be a revision-qualified work-item reference")
        if (not isinstance(self.plan_revision, EntityRef)
                or self.plan_revision.kind is not EntityKind.PLAN_REVISION
                or self.plan_revision.project_id != self.target.project_id):
            raise TypeError("plan_revision must reference this target's project-local plan revision")
        if type(self.authority_revision) is not int or self.authority_revision < 0:
            raise ValueError("authority_revision must be a non-negative integer")
        if not isinstance(self.eligibility, EligibilityDecision):
            raise TypeError("eligibility must be a native EligibilityDecision")
        if self.eligibility.authority_revision != self.authority_revision:
            raise ValueError("selection and eligibility must use the same authority revision")
        if self.run is not None and (
            not isinstance(self.run, EntityRef) or self.run.kind is not EntityKind.RUN
            or self.run.project_id != self.target.project_id
        ):
            raise TypeError("run must be a same-project run reference")
        if self.assignment is not None and (
            not isinstance(self.assignment, EntityRef) or self.assignment.kind is not EntityKind.ASSIGNMENT
            or self.assignment.project_id != self.target.project_id
        ):
            raise TypeError("assignment must be a same-project assignment reference")
        if type(self.workspace_qualification_required) is not bool:
            raise TypeError("workspace_qualification_required must be bool")
        if (self.run is None) != (self.assignment is None):
            raise ValueError("a scheduled selection must include both run and assignment")


__all__ = ["NextWorkSelection"]
