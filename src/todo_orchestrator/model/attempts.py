"""Typed host observations used by the durable attempt authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from todo_orchestrator.contracts import AttemptState, EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.contracts.providers import ProviderReceipt

from .eligibility import WorkspaceQualification


class SourceSafety(str, Enum):
    CLEAN = "clean"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


class ProcessLiveness(str, Enum):
    STOPPED = "stopped"
    LIVE = "live"
    UNKNOWN = "unknown"


class ChildActivity(str, Enum):
    NONE = "none"
    ACTIVE = "active"
    UNKNOWN = "unknown"


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
        if self.receipt.correlation_id != self.attempt.entity_id:
            raise ValueError("safety receipt must correlate with the current attempt")
        if self.receipt.provenance_ref != self.workspace.common_base.ref:
            raise ValueError("safety receipt must identify the qualified source base")

    @property
    def safe_to_release(self) -> bool:
        return (
            self.source is SourceSafety.CLEAN
            and self.process is ProcessLiveness.STOPPED
            and self.children is ChildActivity.NONE
        )


__all__ = [
    "AttemptSafetyObservation",
    "ChildActivity",
    "ProcessLiveness",
    "SourceSafety",
]
