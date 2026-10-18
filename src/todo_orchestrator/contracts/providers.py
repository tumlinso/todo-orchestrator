"""Small, injected contracts for host-owned observations and external effects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Generic, Protocol, TypeVar

from .domain import EntityKind, EntityRef, EvidenceInput, EvidenceResult, Sha256Digest, StableId


PROVIDER_CONTRACT_VERSION = 1
T = TypeVar("T")


def _id(value: StableId, name: str) -> None:
    if not isinstance(value, StableId):
        raise TypeError(f"{name} must be a StableId")


def _text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be non-empty text")


def _tuple(value: tuple[object, ...], name: str, item_type: type | None = None,
           *, nonempty: bool = False, unique: bool = False) -> None:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if nonempty and not value:
        raise ValueError(f"{name} must not be empty")
    if item_type is not None and any(not isinstance(item, item_type) for item in value):
        raise TypeError(f"{name} must contain {item_type.__name__} values")
    if unique and len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")


def _actor_ref(value: EntityRef, project_id: StableId, name: str = "actor") -> None:
    if not isinstance(value, EntityRef) or value.kind is not EntityKind.ACTOR:
        raise ValueError(f"{name} must reference an actor incarnation")
    if value.project_id != project_id or value.incarnation_id is None:
        raise ValueError(f"{name} must identify an actor incarnation in this project")


def _aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True)
class ProviderIdentity:
    provider_id: StableId
    version: str
    contract_version: int = PROVIDER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _id(self.provider_id, "provider_id")
        _text(self.version, "provider version")
        if type(self.contract_version) is not int or self.contract_version < 1:
            raise ValueError("contract_version must be a positive integer")


@dataclass(frozen=True)
class ProviderReceipt:
    """Provider-supplied observation identity, not a cryptographic attestation."""

    receipt_id: StableId
    provider: ProviderIdentity
    correlation_id: StableId
    request_digest: Sha256Digest
    provenance_ref: StableId
    observed_at: datetime

    def __post_init__(self) -> None:
        _id(self.receipt_id, "receipt_id")
        _id(self.correlation_id, "correlation_id")
        _id(self.provenance_ref, "provenance_ref")
        if not isinstance(self.provider, ProviderIdentity) or not isinstance(self.request_digest, Sha256Digest):
            raise TypeError("receipt requires a provider identity and request digest")
        _aware(self.observed_at, "observed_at")


class ProviderStatus(str, Enum):
    OBSERVED_SUCCESS = "observed_success"
    OBSERVED_FAILURE = "observed_failure"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ProviderResult(Generic[T]):
    """Typed provider outcome with correlation and, when observed, a receipt."""

    status: ProviderStatus
    correlation_id: StableId
    provider: ProviderIdentity | None = None
    value: T | None = None
    receipt: ProviderReceipt | None = None
    reason_code: StableId | None = None

    def __post_init__(self) -> None:
        _id(self.correlation_id, "correlation_id")
        if not isinstance(self.status, ProviderStatus):
            raise TypeError("status must be a ProviderStatus")
        if self.provider is not None and not isinstance(self.provider, ProviderIdentity):
            raise TypeError("provider must be a ProviderIdentity")
        if self.receipt is not None:
            if not isinstance(self.receipt, ProviderReceipt):
                raise TypeError("receipt must be a ProviderReceipt")
            if self.provider != self.receipt.provider or self.correlation_id != self.receipt.correlation_id:
                raise ValueError("receipt provider and correlation must match the result")
        observed = self.status in {ProviderStatus.OBSERVED_SUCCESS, ProviderStatus.OBSERVED_FAILURE}
        if observed and (self.provider is None or self.receipt is None):
            raise ValueError("observed results require provider and receipt")
        if self.status is ProviderStatus.OBSERVED_SUCCESS and self.reason_code is not None:
            raise ValueError("observed success cannot have a failure reason")
        if self.status is ProviderStatus.OBSERVED_SUCCESS and self.value is None:
            raise ValueError("observed success requires a value")
        if self.status in {ProviderStatus.OBSERVED_FAILURE, ProviderStatus.UNKNOWN, ProviderStatus.UNAVAILABLE}:
            _id(self.reason_code, "reason_code")
        if self.status is ProviderStatus.UNKNOWN and (self.provider is None or self.value is not None):
            raise ValueError("unknown results require a provider and cannot assert a value")
        if self.status is ProviderStatus.UNAVAILABLE and (self.value is not None or self.receipt is not None):
            raise ValueError("unavailable results cannot assert an observation or receipt")


@dataclass(frozen=True)
class ProviderCallContext:
    """Service-built host context; the capability is an opaque Todo grant reference."""

    project_id: StableId
    actor: EntityRef
    capability: EntityRef
    trusted_context_id: StableId
    scope_id: StableId

    def __post_init__(self) -> None:
        for value, name in (
            (self.project_id, "project_id"), (self.trusted_context_id, "trusted_context_id"),
            (self.scope_id, "scope_id"),
        ):
            _id(value, name)
        _actor_ref(self.actor, self.project_id)
        if not isinstance(self.capability, EntityRef) or self.capability.kind is not EntityKind.CAPABILITY:
            raise ValueError("capability must reference a Todo capability")
        if self.capability.project_id != self.project_id:
            raise ValueError("capability must belong to this project")


@dataclass(frozen=True)
class TrustedContextRequest:
    project_id: StableId
    host_context_ref: StableId
    scope_id: StableId
    correlation_id: StableId

    def __post_init__(self) -> None:
        for value, name in (
            (self.project_id, "project_id"), (self.host_context_ref, "host_context_ref"),
            (self.scope_id, "scope_id"), (self.correlation_id, "correlation_id"),
        ):
            _id(value, name)


@dataclass(frozen=True)
class TrustedActorContext:
    """Host-attested identity and action ceiling; it is not a Todo capability."""

    project_id: StableId
    actor: EntityRef
    context_id: StableId
    scope_id: StableId
    host_action_ceiling: tuple[StableId, ...]
    expires_at: datetime

    def __post_init__(self) -> None:
        for value, name in (
            (self.project_id, "project_id"), (self.context_id, "context_id"), (self.scope_id, "scope_id"),
        ):
            _id(value, name)
        _actor_ref(self.actor, self.project_id)
        _tuple(self.host_action_ceiling, "host_action_ceiling", StableId, unique=True)
        _aware(self.expires_at, "expires_at")


class TrustedContextProvider(Protocol):
    def resolve_context(self, request: TrustedContextRequest) -> ProviderResult[TrustedActorContext]: ...


@dataclass(frozen=True)
class SourceObservationRequest:
    context: ProviderCallContext
    correlation_id: StableId
    expected_source: Sha256Digest | None = None

    def __post_init__(self) -> None:
        _id(self.correlation_id, "correlation_id")
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        if self.expected_source is not None and not isinstance(self.expected_source, Sha256Digest):
            raise TypeError("expected_source must be a Sha256Digest")


class WorkingTreeState(str, Enum):
    CLEAN = "clean"
    DIRTY = "dirty"


@dataclass(frozen=True)
class SourceObservation:
    repository_id: StableId
    source_digest: Sha256Digest
    base_digest: Sha256Digest | None
    working_tree: WorkingTreeState

    def __post_init__(self) -> None:
        _id(self.repository_id, "repository_id")
        if not isinstance(self.source_digest, Sha256Digest):
            raise TypeError("source_digest must be a Sha256Digest")
        if self.base_digest is not None and not isinstance(self.base_digest, Sha256Digest):
            raise TypeError("base_digest must be a Sha256Digest")
        if not isinstance(self.working_tree, WorkingTreeState):
            raise TypeError("working_tree must be a WorkingTreeState")


class SourceObserver(Protocol):
    def observe(self, request: SourceObservationRequest) -> ProviderResult[SourceObservation]: ...


@dataclass(frozen=True)
class EffectInspectionRequest:
    """Read-only lookup; context is current recovery authority, digest binds original call."""

    context: ProviderCallContext
    operation_id: StableId
    idempotency_key: StableId
    original_request_digest: Sha256Digest
    correlation_id: StableId

    def __post_init__(self) -> None:
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        for value, name in (
            (self.operation_id, "operation_id"), (self.idempotency_key, "idempotency_key"),
            (self.correlation_id, "correlation_id"),
        ):
            _id(value, name)
        if not isinstance(self.original_request_digest, Sha256Digest):
            raise TypeError("original_request_digest must be a Sha256Digest")


class GitOperationKind(str, Enum):
    CREATE_WORKSPACE = "create_workspace"
    APPLY_CHANGE = "apply_change"
    COMMIT = "commit"
    INTEGRATE = "integrate"
    PUBLISH = "publish"
    RELEASE_WORKSPACE = "release_workspace"


class GitEffectDisposition(str, Enum):
    APPLIED = "applied"
    CONFLICT = "conflict"
    DIRTY = "dirty"
    REJECTED = "rejected"
    NOT_APPLIED = "not_applied"


@dataclass(frozen=True)
class GitEffectRequest:
    context: ProviderCallContext
    operation_id: StableId
    idempotency_key: StableId
    operation: GitOperationKind
    expected_source: Sha256Digest
    expected_authority_revision: int
    workspace_id: StableId | None = None

    def __post_init__(self) -> None:
        for value, name in ((self.operation_id, "operation_id"), (self.idempotency_key, "idempotency_key")):
            _id(value, name)
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        if not isinstance(self.operation, GitOperationKind):
            raise TypeError("operation must be a GitOperationKind")
        if not isinstance(self.expected_source, Sha256Digest):
            raise TypeError("expected_source must be a Sha256Digest")
        if type(self.expected_authority_revision) is not int or self.expected_authority_revision < 1:
            raise ValueError("expected_authority_revision must be positive")
        if self.workspace_id is not None:
            _id(self.workspace_id, "workspace_id")


@dataclass(frozen=True)
class GitEffectObservation:
    operation_id: StableId
    disposition: GitEffectDisposition
    resulting_source: Sha256Digest | None = None
    conflict_refs: tuple[StableId, ...] = ()

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.disposition, GitEffectDisposition):
            raise TypeError("disposition must be a GitEffectDisposition")
        if self.resulting_source is not None and not isinstance(self.resulting_source, Sha256Digest):
            raise TypeError("resulting_source must be a Sha256Digest")
        _tuple(self.conflict_refs, "conflict_refs", StableId, unique=True)
        if self.disposition is GitEffectDisposition.APPLIED and self.resulting_source is None:
            raise ValueError("an applied Git effect requires resulting_source")


class GitEffectsProvider(Protocol):
    def perform(self, request: GitEffectRequest) -> ProviderResult[GitEffectObservation]: ...

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[GitEffectObservation]: ...


@dataclass(frozen=True)
class CommandExecutionRequest:
    context: ProviderCallContext
    attempt: EntityRef
    operation_id: StableId
    idempotency_key: StableId
    expected_source: Sha256Digest
    expected_authority_revision: int
    tool_id: StableId
    argv: tuple[str, ...]
    timeout_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        if not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("attempt must reference an attempt")
        if self.attempt.project_id != self.context.project_id:
            raise ValueError("attempt must belong to the context project")
        for value, name in (
            (self.operation_id, "operation_id"), (self.idempotency_key, "idempotency_key"),
            (self.tool_id, "tool_id"),
        ):
            _id(value, name)
        if not isinstance(self.expected_source, Sha256Digest):
            raise TypeError("expected_source must be a Sha256Digest")
        if type(self.expected_authority_revision) is not int or self.expected_authority_revision < 1:
            raise ValueError("expected_authority_revision must be positive")
        _tuple(self.argv, "argv", str, nonempty=True)
        if any("\x00" in arg for arg in self.argv):
            raise ValueError("argv items must not contain NUL characters")
        if type(self.timeout_ms) is not int or self.timeout_ms < 1:
            raise ValueError("timeout_ms must be positive")


@dataclass(frozen=True)
class CommandObservation:
    operation_id: StableId
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    completed_at: datetime
    stdout_digest: Sha256Digest | None = None
    stderr_digest: Sha256Digest | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if type(self.timed_out) is not bool:
            raise TypeError("timed_out must be bool")
        if self.timed_out and self.exit_code is not None:
            raise ValueError("a timed-out command has no observed exit_code")
        if not self.timed_out and type(self.exit_code) is not int:
            raise ValueError("a completed command requires an integer exit_code")
        _aware(self.started_at, "started_at")
        _aware(self.completed_at, "completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        for value in (self.stdout_digest, self.stderr_digest):
            if value is not None and not isinstance(value, Sha256Digest):
                raise TypeError("output digests must be Sha256Digest values")


class CommandExecutionProvider(Protocol):
    def execute(self, request: CommandExecutionRequest) -> ProviderResult[CommandObservation]: ...

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[CommandExecutionInspection]: ...


class CommandInspectionState(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    NOT_STARTED = "not_started"


@dataclass(frozen=True)
class CommandExecutionInspection:
    operation_id: StableId
    state: CommandInspectionState
    observation: CommandObservation | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.state, CommandInspectionState):
            raise TypeError("state must be a CommandInspectionState")
        if self.state is CommandInspectionState.COMPLETED:
            if not isinstance(self.observation, CommandObservation):
                raise ValueError("completed inspection requires a CommandObservation")
            if self.observation.operation_id != self.operation_id:
                raise ValueError("observation must match the inspected operation")
        elif self.observation is not None:
            raise ValueError("running or not-started inspection cannot contain a completion observation")


@dataclass(frozen=True)
class ResourcePermitRequest:
    context: ProviderCallContext
    attempt: EntityRef
    operation_id: StableId
    idempotency_key: StableId
    resource_class: StableId
    units: int

    def __post_init__(self) -> None:
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        if not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("attempt must reference an attempt")
        if self.attempt.project_id != self.context.project_id:
            raise ValueError("attempt must belong to the context project")
        for value, name in (
            (self.operation_id, "operation_id"), (self.idempotency_key, "idempotency_key"),
            (self.resource_class, "resource_class"),
        ):
            _id(value, name)
        if type(self.units) is not int or self.units < 1:
            raise ValueError("units must be a positive integer")


@dataclass(frozen=True)
class ResourcePermitRef:
    """External permit reference only; Todo does not maintain resource ownership."""

    permit_id: StableId
    resource_class: StableId
    scope_id: StableId
    units: int
    expires_at: datetime
    issuer: ProviderIdentity
    receipt_id: StableId

    def __post_init__(self) -> None:
        for value, name in (
            (self.permit_id, "permit_id"), (self.resource_class, "resource_class"),
            (self.scope_id, "scope_id"), (self.receipt_id, "receipt_id"),
        ):
            _id(value, name)
        if type(self.units) is not int or self.units < 1:
            raise ValueError("units must be a positive integer")
        if not isinstance(self.issuer, ProviderIdentity):
            raise TypeError("issuer must be a ProviderIdentity")
        _aware(self.expires_at, "expires_at")


@dataclass(frozen=True)
class ResourcePermitReleaseRequest:
    context: ProviderCallContext
    attempt: EntityRef
    operation_id: StableId
    idempotency_key: StableId
    permit: ResourcePermitRef

    def __post_init__(self) -> None:
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        if not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("attempt must reference an attempt")
        if self.attempt.project_id != self.context.project_id:
            raise ValueError("attempt must belong to the context project")
        _id(self.operation_id, "operation_id")
        _id(self.idempotency_key, "idempotency_key")
        if not isinstance(self.permit, ResourcePermitRef):
            raise TypeError("permit must be a ResourcePermitRef")


@dataclass(frozen=True)
class ResourcePermitRelease:
    operation_id: StableId
    permit_id: StableId
    released: bool

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        _id(self.permit_id, "permit_id")
        if type(self.released) is not bool:
            raise TypeError("released must be bool")


class ResourcePermitInspectionState(str, Enum):
    HELD = "held"
    ABSENT = "absent"
    RELEASED = "released"


@dataclass(frozen=True)
class ResourcePermitInspection:
    operation_id: StableId
    state: ResourcePermitInspectionState
    permit: ResourcePermitRef | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.state, ResourcePermitInspectionState):
            raise TypeError("state must be a ResourcePermitInspectionState")
        if self.state is ResourcePermitInspectionState.ABSENT:
            if self.permit is not None:
                raise ValueError("absent inspection cannot contain a permit")
        elif not isinstance(self.permit, ResourcePermitRef):
            raise ValueError("held or released inspection requires the permit reference")


class ResourcePermitProvider(Protocol):
    def reserve(self, request: ResourcePermitRequest) -> ProviderResult[ResourcePermitRef]: ...

    def release(self, request: ResourcePermitReleaseRequest) -> ProviderResult[ResourcePermitRelease]: ...

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[ResourcePermitInspection]: ...


@dataclass(frozen=True)
class VerificationRequest:
    context: ProviderCallContext
    attempt: EntityRef
    requirement: EntityRef
    operation_id: StableId
    idempotency_key: StableId
    verifier_id: StableId
    expected_source: Sha256Digest
    contract_digest: Sha256Digest
    inputs: tuple[EvidenceInput, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        for value, kind, name in (
            (self.attempt, EntityKind.ATTEMPT, "attempt"),
            (self.requirement, EntityKind.REQUIREMENT, "requirement"),
        ):
            if not isinstance(value, EntityRef) or value.kind is not kind:
                raise ValueError(f"{name} must reference {kind.value}")
            if value.project_id != self.context.project_id:
                raise ValueError(f"{name} must belong to the context project")
        for value, name in (
            (self.operation_id, "operation_id"), (self.idempotency_key, "idempotency_key"),
            (self.verifier_id, "verifier_id"),
        ):
            _id(value, name)
        if not isinstance(self.expected_source, Sha256Digest) or not isinstance(self.contract_digest, Sha256Digest):
            raise TypeError("expected_source and contract_digest must be Sha256Digest values")
        _tuple(self.inputs, "inputs", EvidenceInput, unique=True)
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise ValueError("inputs must not repeat names")


@dataclass(frozen=True)
class VerificationObservation:
    operation_id: StableId
    verdict: EvidenceResult
    verifier_id: StableId
    verifier_version: str
    source_digest: Sha256Digest
    contract_digest: Sha256Digest
    inputs: tuple[EvidenceInput, ...]
    artifact_ids: tuple[StableId, ...]

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        _id(self.verifier_id, "verifier_id")
        if not isinstance(self.verdict, EvidenceResult):
            raise TypeError("verdict must be an EvidenceResult")
        _text(self.verifier_version, "verifier_version")
        if not isinstance(self.source_digest, Sha256Digest) or not isinstance(self.contract_digest, Sha256Digest):
            raise TypeError("source_digest and contract_digest must be Sha256Digest values")
        _tuple(self.inputs, "inputs", EvidenceInput, unique=True)
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise ValueError("inputs must not repeat names")
        _tuple(self.artifact_ids, "artifact_ids", StableId, unique=True)


class VerificationProvider(Protocol):
    def verify(self, request: VerificationRequest) -> ProviderResult[VerificationObservation]: ...

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[VerificationInspection]: ...


class VerificationInspectionState(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    NOT_STARTED = "not_started"


@dataclass(frozen=True)
class VerificationInspection:
    operation_id: StableId
    state: VerificationInspectionState
    observation: VerificationObservation | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.state, VerificationInspectionState):
            raise TypeError("state must be a VerificationInspectionState")
        if self.state is VerificationInspectionState.COMPLETED:
            if not isinstance(self.observation, VerificationObservation):
                raise ValueError("completed inspection requires a VerificationObservation")
            if self.observation.operation_id != self.operation_id:
                raise ValueError("observation must match the inspected operation")
        elif self.observation is not None:
            raise ValueError("running or not-started inspection cannot contain a completion observation")


__all__ = [
    "PROVIDER_CONTRACT_VERSION", "ProviderIdentity", "ProviderReceipt", "ProviderStatus", "ProviderResult",
    "ProviderCallContext", "TrustedContextRequest", "TrustedActorContext", "TrustedContextProvider",
    "SourceObservationRequest", "WorkingTreeState", "SourceObservation", "SourceObserver",
    "EffectInspectionRequest",
    "GitOperationKind", "GitEffectDisposition", "GitEffectRequest", "GitEffectObservation", "GitEffectsProvider",
    "CommandExecutionRequest", "CommandObservation", "CommandInspectionState", "CommandExecutionInspection",
    "CommandExecutionProvider", "ResourcePermitRequest", "ResourcePermitRef", "ResourcePermitReleaseRequest",
    "ResourcePermitRelease", "ResourcePermitInspectionState", "ResourcePermitInspection", "ResourcePermitProvider",
    "VerificationRequest", "VerificationObservation", "VerificationInspectionState", "VerificationInspection",
    "VerificationProvider",
]
