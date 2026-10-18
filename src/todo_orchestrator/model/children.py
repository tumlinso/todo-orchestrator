"""Typed subordinate-execution records and child-scope eligibility facts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId
from .eligibility import AttemptScopeSnapshot
from .eligibility import WorkspaceQualification


CHILD_DELEGATE_ACTION = StableId("todo.child.delegate")
CHILD_RETRY_ACTION = StableId("todo.child.retry")
CHILD_REVIEW_ACTION = StableId("todo.child.review")
CHILD_CANCEL_ACTION = StableId("todo.child.cancel")
CHILD_STOP_RECONCILE_ACTION = StableId("todo.child.stop.reconcile")
CHILD_READ_ACTION = StableId("todo.child.read")
CHILD_WRITE_ACTION = StableId("todo.child.write")
CHILD_CANDIDATE_SUBMIT_ACTION = StableId("todo.child.candidate.submit")
CHILD_WORKER_ACTIONS = (CHILD_READ_ACTION, CHILD_WRITE_ACTION, CHILD_CANDIDATE_SUBMIT_ACTION)


class ChildExecutionState(str, Enum):
    ACTIVE = "active"
    CANDIDATE = "candidate"
    CANCEL_REQUESTED = "cancel_requested"
    STOPPED = "stopped"


class ChildCandidateDecision(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ChildArtifactRef:
    """An immutable same-project artifact identity and verified content digest."""

    ref: EntityRef
    digest: Sha256Digest

    def __post_init__(self) -> None:
        if not isinstance(self.ref, EntityRef) or self.ref.kind is not EntityKind.ARTIFACT:
            raise ValueError("child artifact ref must identify an artifact")
        if not isinstance(self.digest, Sha256Digest):
            raise TypeError("child artifact digest must be a Sha256Digest")


@dataclass(frozen=True)
class ChildCandidate:
    candidate_id: StableId
    execution_id: StableId
    summary: str
    artifacts: tuple[ChildArtifactRef, ...]
    submitted_by: EntityRef
    submitted_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, StableId) or not isinstance(self.execution_id, StableId):
            raise TypeError("candidate identity fields must be StableId values")
        if not isinstance(self.summary, str):
            raise TypeError("candidate summary must be text")
        if not isinstance(self.artifacts, tuple) or any(not isinstance(item, ChildArtifactRef) for item in self.artifacts):
            raise TypeError("candidate artifacts must be a tuple of ChildArtifactRef values")
        if not isinstance(self.submitted_by, EntityRef) or self.submitted_by.kind is not EntityKind.ACTOR:
            raise ValueError("candidate submitter must be an actor incarnation")
        if not isinstance(self.submitted_at, datetime) or self.submitted_at.tzinfo is None:
            raise ValueError("candidate submission time must be timezone-aware")


@dataclass(frozen=True)
class ChildReview:
    review_id: StableId
    candidate_id: StableId
    decision: ChildCandidateDecision
    reviewer: EntityRef
    reason: str | None
    reviewed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.review_id, StableId) or not isinstance(self.candidate_id, StableId):
            raise TypeError("review identity fields must be StableId values")
        if not isinstance(self.decision, ChildCandidateDecision):
            raise TypeError("decision must be a ChildCandidateDecision")
        if not isinstance(self.reviewer, EntityRef) or self.reviewer.kind is not EntityKind.ACTOR:
            raise ValueError("reviewer must be an actor incarnation")
        if self.reason is not None and not isinstance(self.reason, str):
            raise TypeError("review reason must be text or None")
        if not isinstance(self.reviewed_at, datetime) or self.reviewed_at.tzinfo is None:
            raise ValueError("review time must be timezone-aware")


@dataclass(frozen=True)
class ChildExecutionView:
    execution_id: StableId
    logical_id: StableId
    ordinal: int
    parent_attempt: EntityRef
    target: EntityRef
    actor: EntityRef
    scope: AttemptScopeSnapshot
    actions: tuple[StableId, ...]
    capability_id: StableId
    state: ChildExecutionState
    created_at: datetime
    expires_at: datetime
    retry_of: StableId | None = None
    candidate: ChildCandidate | None = None
    review: ChildReview | None = None

    def __post_init__(self) -> None:
        for value in (self.execution_id, self.logical_id, self.capability_id):
            if not isinstance(value, StableId):
                raise TypeError("child execution identities must be StableId values")
        if type(self.ordinal) is not int or self.ordinal < 1:
            raise ValueError("child execution ordinal must be positive")
        if not isinstance(self.parent_attempt, EntityRef) or self.parent_attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("parent_attempt must identify an attempt")
        if not isinstance(self.target, EntityRef) or self.target.kind is not EntityKind.WORK_ITEM:
            raise ValueError("child target must identify an exact work-item definition")
        if not isinstance(self.actor, EntityRef) or self.actor.kind is not EntityKind.ACTOR:
            raise ValueError("child actor must identify an actor incarnation")
        if self.actor.project_id != self.parent_attempt.project_id or self.target.project_id != self.parent_attempt.project_id:
            raise ValueError("child identities must belong to the parent project")
        if not isinstance(self.scope, AttemptScopeSnapshot):
            raise TypeError("child scope must be an AttemptScopeSnapshot")
        if not isinstance(self.actions, tuple) or not self.actions or any(not isinstance(item, StableId) for item in self.actions):
            raise TypeError("child actions must be a non-empty tuple of StableId values")
        if len(set(self.actions)) != len(self.actions):
            raise ValueError("child actions must be unique")
        if not isinstance(self.state, ChildExecutionState):
            raise TypeError("state must be a ChildExecutionState")
        for name, value in (("created_at", self.created_at), ("expires_at", self.expires_at)):
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.retry_of is not None and not isinstance(self.retry_of, StableId):
            raise TypeError("retry_of must be a StableId or None")
        if self.candidate is not None and self.candidate.execution_id != self.execution_id:
            raise ValueError("candidate must belong to this execution")
        if self.review is not None and (self.candidate is None or self.review.candidate_id != self.candidate.candidate_id):
            raise ValueError("review must belong to this execution's candidate")


@dataclass(frozen=True)
class ChildExecutionGrant:
    view: ChildExecutionView
    bearer_token: str = field(repr=False)
    receipt: object

    def __post_init__(self) -> None:
        if not isinstance(self.view, ChildExecutionView):
            raise TypeError("view must be a ChildExecutionView")
        if not isinstance(self.bearer_token, str) or not self.bearer_token:
            raise ValueError("child bearer token must be non-empty")


@dataclass(frozen=True)
class ChildScopeOccupancy:
    """Persisted child write scope that still blocks unsafe peer admission."""

    execution_id: StableId
    parent_attempt: EntityRef
    target: EntityRef
    scope: AttemptScopeSnapshot
    parent_workspace: WorkspaceQualification | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.execution_id, StableId):
            raise TypeError("execution_id must be a StableId")
        if not isinstance(self.parent_attempt, EntityRef) or self.parent_attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("parent_attempt must identify an attempt")
        if not isinstance(self.target, EntityRef) or self.target.kind is not EntityKind.WORK_ITEM:
            raise ValueError("target must identify an exact work-item definition")
        if not isinstance(self.scope, AttemptScopeSnapshot):
            raise TypeError("scope must be an AttemptScopeSnapshot")
        if self.parent_workspace is not None and not isinstance(self.parent_workspace, WorkspaceQualification):
            raise TypeError("parent_workspace must be a WorkspaceQualification or None")


__all__ = [
    "CHILD_CANDIDATE_SUBMIT_ACTION",
    "CHILD_CANCEL_ACTION",
    "CHILD_DELEGATE_ACTION",
    "CHILD_READ_ACTION",
    "CHILD_REVIEW_ACTION",
    "CHILD_RETRY_ACTION",
    "CHILD_STOP_RECONCILE_ACTION",
    "CHILD_WORKER_ACTIONS",
    "CHILD_WRITE_ACTION",
    "ChildArtifactRef",
    "ChildCandidate",
    "ChildCandidateDecision",
    "ChildExecutionGrant",
    "ChildExecutionState",
    "ChildExecutionView",
    "ChildReview",
    "ChildScopeOccupancy",
]
