"""Typed, non-mutating recovery inspection views."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from todo_orchestrator.contracts import EntityRef, ProviderReceipt, Sha256Digest, StableId
from todo_orchestrator.contracts.providers import (
    GitEffectObservation,
    SourceObservation,
    VerificationInspection,
)
from todo_orchestrator.model import AttemptSafetyObservation


class RecoveryStatus(str, Enum):
    COMPLETE = "complete"
    ACTIVE = "active"
    EXPIRED = "expired"
    UNKNOWN_LIVE = "unknown_live"
    DIRTY = "dirty"
    IRRECOVERABLE = "irrecoverable"
    SAFELY_RETRYABLE = "safely_retryable"
    UNCERTAIN = "uncertain"


class RecoveryOperationStatus(str, Enum):
    COMPLETE = "complete"
    PREPARED = "prepared"
    SAFELY_RETRYABLE = "safely_retryable"
    EFFECT_OBSERVED = "effect_observed"
    DIRTY = "dirty"
    IRRECOVERABLE = "irrecoverable"
    UNCERTAIN = "uncertain"


class RecoveryIntentKind(str, Enum):
    RELEASE_EXPIRED_ATTEMPT = "release_expired_attempt"
    HANDOFF_DIRTY_WORKSPACE = "handoff_dirty_workspace"
    RETRY_ORIGINAL_OPERATION = "retry_original_operation"
    RECONCILE_OBSERVED_EFFECT = "reconcile_observed_effect"


@dataclass(frozen=True)
class RecoveryPrecondition:
    code: str
    satisfied: bool
    subject: EntityRef | None = None
    detail: str = ""


@dataclass(frozen=True)
class RecoveryBlocker:
    code: str
    subject: EntityRef | None = None
    detail: str = ""


@dataclass(frozen=True)
class RecoveryChild:
    execution: StableId
    state: str
    candidate_pending_review: bool


@dataclass(frozen=True)
class RecoveryEvidence:
    evidence: EntityRef
    result: str
    verifier_id: StableId
    verifier_version: str
    contract_digest: Sha256Digest
    source_digest: Sha256Digest | None
    operation: EntityRef | None
    requirement: EntityRef | None
    observed_at: datetime


@dataclass(frozen=True)
class RecoveryOutcomeCandidate:
    candidate_id: StableId
    target: EntityRef
    disposition: str
    state: str
    reported_at: datetime
    outcome: EntityRef | None = None


@dataclass(frozen=True)
class RecoveryOperation:
    operation: EntityRef
    attempt: EntityRef | None
    target: EntityRef
    workspace_id: StableId | None
    kind: str
    state: str
    status: RecoveryOperationStatus
    request_digest: Sha256Digest
    receipt_digest: Sha256Digest | None
    inspection_state: str | None = None
    inspection_receipt: ProviderReceipt | None = None
    source_observation: SourceObservation | None = None
    source_receipt: ProviderReceipt | None = None
    git_observation: GitEffectObservation | None = None
    verification_inspection: VerificationInspection | None = None
    blockers: tuple[RecoveryBlocker, ...] = ()


@dataclass(frozen=True)
class RecoveryIntent:
    kind: RecoveryIntentKind
    attempt: EntityRef | None
    target: EntityRef
    operations: tuple[EntityRef, ...]
    expected_authority_revision: int
    expected_lease_id: StableId | None
    expected_source_digest: Sha256Digest | None
    workspace_id: StableId | None
    preconditions: tuple[RecoveryPrecondition, ...]


@dataclass(frozen=True)
class RecoveryInspection:
    attempt: EntityRef | None
    target: EntityRef
    workspace_id: StableId | None
    state: str
    lease_id: StableId | None
    lease_expires_at: datetime | None
    lease_expired: bool | None
    status: RecoveryStatus
    authority_revision: int
    observed_at: datetime
    host_observation: AttemptSafetyObservation | None
    source_observation: SourceObservation | None
    source_receipt: ProviderReceipt | None
    children: tuple[RecoveryChild, ...]
    operations: tuple[RecoveryOperation, ...]
    preconditions: tuple[RecoveryPrecondition, ...]
    blockers: tuple[RecoveryBlocker, ...]
    intents: tuple[RecoveryIntent, ...]
    evidence: tuple[RecoveryEvidence, ...] = ()
    outcome_candidates: tuple[RecoveryOutcomeCandidate, ...] = ()


__all__ = [
    "RecoveryBlocker", "RecoveryChild", "RecoveryEvidence", "RecoveryInspection", "RecoveryIntent",
    "RecoveryIntentKind", "RecoveryOperation", "RecoveryOperationStatus",
    "RecoveryOutcomeCandidate", "RecoveryPrecondition", "RecoveryStatus",
]
