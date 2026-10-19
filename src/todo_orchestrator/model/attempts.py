"""Typed host observations used by the durable attempt authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from todo_orchestrator.contracts import AttemptState, EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.contracts.providers import ProviderReceipt, provider_request_digest

from .eligibility import WorkspaceQualification


class SourceSafety(str, Enum):
    CLEAN = "clean"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


class ProcessLiveness(str, Enum):
    STOPPED = "stopped"
    LIVE = "live"
    UNKNOWN = "unknown"
    EXTERNAL_PRODUCER_QUIESCENT = "external_producer_quiescent"

    @property
    def quiescent(self) -> bool:
        """Whether the trusted host has evidence that this writer is quiescent.

        ``EXTERNAL_PRODUCER_QUIESCENT`` records a root/operator-observed
        producer lifecycle completion bound to the current attempt, lease and
        source. It is intentionally distinct from kernel-confirmed ``STOPPED``.
        """
        return self in {ProcessLiveness.STOPPED, ProcessLiveness.EXTERNAL_PRODUCER_QUIESCENT}


class ChildActivity(str, Enum):
    NONE = "none"
    ACTIVE = "active"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AttemptAuthoringHandoffRequest:
    """Authenticated attempt scope a trusted host is asked to pin and fence."""

    project_id: StableId
    authority_id: StableId
    attempt: EntityRef
    lease_id: StableId
    workspace_id: StableId
    idempotency_key: StableId

    def __post_init__(self) -> None:
        for value, name in (
            (self.project_id, "project_id"), (self.authority_id, "authority_id"),
            (self.lease_id, "lease_id"), (self.workspace_id, "workspace_id"),
            (self.idempotency_key, "idempotency_key"),
        ):
            if not isinstance(value, StableId):
                raise TypeError(f"{name} must be a StableId")
        if (not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT
                or self.attempt.project_id != self.project_id):
            raise ValueError("attempt must be a project-local attempt reference")


def authoring_handoff_request_digest(
    request: AttemptAuthoringHandoffRequest,
    source_commit: StableId,
    source_tree: StableId,
    source_digest: Sha256Digest,
) -> Sha256Digest:
    """Bind a host receipt to the authenticated handoff and exact pinned source."""
    if not isinstance(request, AttemptAuthoringHandoffRequest):
        raise TypeError("request must be an AttemptAuthoringHandoffRequest")
    if not isinstance(source_commit, StableId) or not isinstance(source_tree, StableId):
        raise TypeError("source commit and tree must be StableId values")
    if not isinstance(source_digest, Sha256Digest):
        raise TypeError("source_digest must be a Sha256Digest")
    return provider_request_digest({
        "request": {
            "project_id": request.project_id,
            "authority_id": request.authority_id,
            "attempt": request.attempt,
            "lease_id": request.lease_id,
            "workspace_id": request.workspace_id,
            "idempotency_key": request.idempotency_key,
        },
        "source_commit": source_commit,
        "source_tree": source_tree,
        "source_digest": source_digest,
    })


@dataclass(frozen=True)
class AttemptAuthoringHandoff:
    """Durable attempt-scoped source pin and authoring fence, not process death."""

    request: AttemptAuthoringHandoffRequest
    source_commit: StableId
    source_tree: StableId
    source_digest: Sha256Digest
    receipt: ProviderReceipt

    def __post_init__(self) -> None:
        if not isinstance(self.request, AttemptAuthoringHandoffRequest):
            raise TypeError("request must be an AttemptAuthoringHandoffRequest")
        if not isinstance(self.source_commit, StableId) or not isinstance(self.source_tree, StableId):
            raise TypeError("source commit and tree must be StableId values")
        if not isinstance(self.source_digest, Sha256Digest):
            raise TypeError("source_digest must be a Sha256Digest")
        if not isinstance(self.receipt, ProviderReceipt):
            raise TypeError("receipt must be a ProviderReceipt")
        if (self.receipt.correlation_id != self.request.attempt.entity_id
                or self.receipt.provenance_ref != self.source_commit
                or self.receipt.request_digest != authoring_handoff_request_digest(
                    self.request, self.source_commit, self.source_tree, self.source_digest
                )):
            raise ValueError("handoff receipt does not bind the request and exact pinned source")

    @property
    def attempt(self) -> EntityRef:
        return self.request.attempt

    @property
    def lease_id(self) -> StableId:
        return self.request.lease_id

    @property
    def workspace_id(self) -> StableId:
        return self.request.workspace_id


@dataclass(frozen=True)
class AttemptSafetyObservation:
    """Trusted provider result bound to one attempt, lease, and qualified source.

    This is deliberately not accepted directly by public command methods.
    ``AttemptService`` obtains it from its injected host provider and the
    command handler checks it against the current stored attempt.
    """

    attempt: EntityRef
    observed_state: AttemptState
    lease_id: StableId
    observed_lease_expires_at: datetime
    workspace: WorkspaceQualification
    source: SourceSafety
    process: ProcessLiveness
    children: ChildActivity
    receipt: ProviderReceipt
    source_digest: Sha256Digest | None = None
    authoring_handoff: AttemptAuthoringHandoff | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("attempt must reference an attempt")
        if not isinstance(self.observed_state, AttemptState):
            raise TypeError("observed_state must be an AttemptState")
        if not isinstance(self.lease_id, StableId):
            raise TypeError("lease_id must be a StableId")
        if (not isinstance(self.observed_lease_expires_at, datetime)
                or self.observed_lease_expires_at.tzinfo is None
                or self.observed_lease_expires_at.utcoffset() is None):
            raise ValueError("observed_lease_expires_at must be timezone-aware")
        if not isinstance(self.workspace, WorkspaceQualification):
            raise TypeError("workspace must be a WorkspaceQualification")
        if not isinstance(self.source, SourceSafety):
            raise TypeError("source must be a SourceSafety value")
        if not isinstance(self.process, ProcessLiveness):
            raise TypeError("process must be a ProcessLiveness value")
        if not isinstance(self.children, ChildActivity):
            raise TypeError("children must be a ChildActivity value")
        if not isinstance(self.receipt, ProviderReceipt):
            raise TypeError("receipt must be a ProviderReceipt")
        if self.source_digest is not None and not isinstance(self.source_digest, Sha256Digest):
            raise TypeError("source_digest must be a Sha256Digest or None")
        if self.authoring_handoff is not None:
            if not isinstance(self.authoring_handoff, AttemptAuthoringHandoff):
                raise TypeError("authoring_handoff must be an AttemptAuthoringHandoff or None")
            handoff = self.authoring_handoff
            if (handoff.attempt != self.attempt or handoff.lease_id != self.lease_id
                    or handoff.workspace_id != self.workspace.workspace_id
                    or handoff.source_digest != self.source_digest
                    or handoff.receipt.provider != self.workspace.receipt.provider):
                raise ValueError("authoring handoff must match the observed attempt, lease, workspace, and source")
        if self.receipt.correlation_id != self.attempt.entity_id:
            raise ValueError("safety receipt must correlate with the current attempt")
        if self.receipt.provenance_ref != self.workspace.common_base.ref:
            raise ValueError("safety receipt must identify the qualified source base")

    @property
    def safe_to_release(self) -> bool:
        return (
            self.source is SourceSafety.CLEAN
            and self.children is ChildActivity.NONE
            and (
                self.process.quiescent
                or self.authoring_handoff is not None
            )
        )


__all__ = [
    "AttemptSafetyObservation",
    "AttemptAuthoringHandoff",
    "AttemptAuthoringHandoffRequest",
    "ChildActivity",
    "ProcessLiveness",
    "SourceSafety",
    "authoring_handoff_request_digest",
]
