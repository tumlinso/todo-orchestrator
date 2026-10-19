"""Small, injected contracts for host-owned observations and external effects."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import math
from typing import Generic, Mapping, Protocol, TypeVar

from .domain import EntityKind, EntityRef, EvidenceInput, EvidenceResult, Sha256Digest, StableId
from .verification import EvidenceKind, EvidenceRequirement, VerificationContract


PROVIDER_CONTRACT_VERSION = 9
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


def _provider_value(value: object) -> object:
    if isinstance(value, StableId):
        return str(value)
    if isinstance(value, Sha256Digest):
        return value.hex
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds")
    if isinstance(value, Mapping):
        return {str(key): _provider_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [_provider_value(item) for item in value]
    if is_dataclass(value):
        return {field.name: _provider_value(getattr(value, field.name)) for field in fields(value)}
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise TypeError(f"unsupported provider request value: {type(value).__name__}")


def provider_request_digest(request: object) -> Sha256Digest:
    """Canonical digest providers must echo in receipts for an exact request."""
    material = json.dumps(
        _provider_value(request), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return Sha256Digest(hashlib.sha256(material).hexdigest())


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
class ArtifactExpectation:
    """Exact stored artifact whose current availability a trusted observer checks."""

    artifact_id: StableId
    expected_digest: Sha256Digest

    def __post_init__(self) -> None:
        _id(self.artifact_id, "artifact_id")
        if not isinstance(self.expected_digest, Sha256Digest):
            raise TypeError("expected_digest must be a Sha256Digest")


@dataclass(frozen=True)
class ArtifactAvailability:
    artifact_id: StableId
    available: bool
    content_digest: Sha256Digest | None

    def __post_init__(self) -> None:
        _id(self.artifact_id, "artifact_id")
        if type(self.available) is not bool:
            raise TypeError("available must be bool")
        if self.available != (self.content_digest is not None):
            raise ValueError("available artifacts require a digest and unavailable artifacts must omit it")
        if self.content_digest is not None and not isinstance(self.content_digest, Sha256Digest):
            raise TypeError("content_digest must be a Sha256Digest")


@dataclass(frozen=True)
class SourceObservationRequest:
    context: ProviderCallContext
    correlation_id: StableId
    expected_source: Sha256Digest | None = None
    attempt: EntityRef | None = None
    workspace_id: StableId | None = None
    target: EntityRef | None = None
    contract: VerificationContract | None = None
    artifacts: tuple[ArtifactExpectation, ...] = ()
    base_ref: StableId | None = None

    def __post_init__(self) -> None:
        _id(self.correlation_id, "correlation_id")
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        if self.expected_source is not None and not isinstance(self.expected_source, Sha256Digest):
            raise TypeError("expected_source must be a Sha256Digest")
        if self.attempt is not None and (
            not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT
            or self.attempt.project_id != self.context.project_id
        ):
            raise ValueError("attempt must be a project-local attempt reference")
        if self.workspace_id is not None:
            _id(self.workspace_id, "workspace_id")
        if self.base_ref is not None:
            _id(self.base_ref, "base_ref")
        if self.target is not None and (
            not isinstance(self.target, EntityRef) or self.target.kind is not EntityKind.WORK_ITEM
            or self.target.project_id != self.context.project_id
        ):
            raise ValueError("target must be a project-local qualified work-item reference")
        if self.contract is not None and not isinstance(self.contract, VerificationContract):
            raise TypeError("contract must be a VerificationContract")
        _tuple(self.artifacts, "artifacts", ArtifactExpectation, unique=True)
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("artifact expectations must not repeat identifiers")
        if (self.workspace_id is None) != (self.target is None):
            raise ValueError("workspace_id and target must be supplied together")
        if self.attempt is not None and (self.workspace_id is None or self.target is None):
            raise ValueError("attempt-bound source observation requires workspace_id and target")
        if self.base_ref is not None and any((
            self.attempt is not None,
            self.workspace_id is not None,
            self.target is not None,
            self.contract is not None,
            bool(self.artifacts),
        )):
            raise ValueError("base-ref observation cannot be combined with attempt, workspace, target, contract, or artifact expectations")


class WorkingTreeState(str, Enum):
    CLEAN = "clean"
    DIRTY = "dirty"


@dataclass(frozen=True)
class SourceObservation:
    repository_id: StableId
    source_digest: Sha256Digest
    base_digest: Sha256Digest | None
    working_tree: WorkingTreeState
    inputs: tuple[EvidenceInput, ...] = ()
    artifacts: tuple[ArtifactAvailability, ...] = ()
    source_revision: StableId | None = None

    def __post_init__(self) -> None:
        _id(self.repository_id, "repository_id")
        if not isinstance(self.source_digest, Sha256Digest):
            raise TypeError("source_digest must be a Sha256Digest")
        if self.base_digest is not None and not isinstance(self.base_digest, Sha256Digest):
            raise TypeError("base_digest must be a Sha256Digest")
        if self.source_revision is not None:
            _id(self.source_revision, "source_revision")
        if not isinstance(self.working_tree, WorkingTreeState):
            raise TypeError("working_tree must be a WorkingTreeState")
        _tuple(self.inputs, "inputs", EvidenceInput, unique=True)
        _tuple(self.artifacts, "artifacts", ArtifactAvailability, unique=True)
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise ValueError("source inputs must not repeat names")
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("source artifact observations must not repeat identifiers")


class SourceObserver(Protocol):
    def observe(self, request: SourceObservationRequest) -> ProviderResult[SourceObservation]: ...


class DeclarationKind(str, Enum):
    CHECKPOINT = "checkpoint"
    INTERFACE = "interface"
    BARRIER = "barrier"
    RENDEZVOUS = "rendezvous"


class DeclarationStatus(str, Enum):
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class DeclarationObservationRequest:
    """Fresh exact-version query for state not represented by an authored declaration."""

    context: ProviderCallContext
    correlation_id: StableId
    attempt: EntityRef
    workspace_id: StableId
    plan_revision_id: StableId
    target: EntityRef
    declaration_kind: DeclarationKind
    declaration_digest: Sha256Digest
    expected_version: str | None = None
    authorization_action: StableId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.context, ProviderCallContext):
            raise TypeError("context must be a ProviderCallContext")
        _id(self.correlation_id, "correlation_id")
        _id(self.workspace_id, "workspace_id")
        _id(self.plan_revision_id, "plan_revision_id")
        if not isinstance(self.attempt, EntityRef) or self.attempt.kind is not EntityKind.ATTEMPT:
            raise ValueError("attempt must reference an attempt")
        if self.attempt.project_id != self.context.project_id:
            raise ValueError("attempt must belong to the context project")
        kinds = {
            DeclarationKind.CHECKPOINT: EntityKind.CHECKPOINT,
            DeclarationKind.INTERFACE: EntityKind.INTERFACE,
            DeclarationKind.BARRIER: EntityKind.BARRIER,
            DeclarationKind.RENDEZVOUS: EntityKind.BARRIER,
        }
        if not isinstance(self.declaration_kind, DeclarationKind) or not isinstance(self.target, EntityRef):
            raise TypeError("declaration_kind and target must be typed values")
        if self.target.kind is not kinds[self.declaration_kind] or self.target.project_id != self.context.project_id:
            raise ValueError("target must be the exact project-local declaration reference")
        if not isinstance(self.declaration_digest, Sha256Digest):
            raise TypeError("declaration_digest must be a Sha256Digest")
        if self.expected_version is not None:
            _text(self.expected_version, "expected_version")
        if self.authorization_action is not None:
            _id(self.authorization_action, "authorization_action")


@dataclass(frozen=True)
class DeclarationObservation:
    target: EntityRef
    declaration_kind: DeclarationKind
    declaration_digest: Sha256Digest
    status: DeclarationStatus
    observed_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, EntityRef):
            raise TypeError("target must be an EntityRef")
        if not isinstance(self.declaration_kind, DeclarationKind):
            raise TypeError("declaration_kind must be a DeclarationKind")
        if not isinstance(self.declaration_digest, Sha256Digest):
            raise TypeError("declaration_digest must be a Sha256Digest")
        if not isinstance(self.status, DeclarationStatus):
            raise TypeError("status must be a DeclarationStatus")
        if self.observed_version is not None:
            _text(self.observed_version, "observed_version")


class DeclarationObserver(Protocol):
    def observe_declaration(self, request: DeclarationObservationRequest) -> ProviderResult[DeclarationObservation]: ...


@dataclass(frozen=True)
class EffectInspectionRequest:
    """Read-only lookup; context is current recovery authority, digest binds original call."""

    context: ProviderCallContext
    operation_id: StableId
    idempotency_key: StableId
    original_request_digest: Sha256Digest
    correlation_id: StableId
    git_effect_request: GitEffectRequest | None = None
    verification_request: VerificationRequest | None = None
    resource_permit_request: ResourcePermitRequest | None = None
    resource_permit_release_request: ResourcePermitReleaseRequest | None = None

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
        if self.git_effect_request is not None:
            if not isinstance(self.git_effect_request, GitEffectRequest):
                raise TypeError("git_effect_request must be a GitEffectRequest")
            if (self.git_effect_request.operation_id != self.operation_id
                    or self.git_effect_request.idempotency_key != self.idempotency_key
                    or provider_request_digest(self.git_effect_request) != self.original_request_digest):
                raise ValueError("git_effect_request must match the inspected operation identity and digest")
        if self.verification_request is not None:
            if not isinstance(self.verification_request, VerificationRequest):
                raise TypeError("verification_request must be a VerificationRequest")
            if (self.verification_request.operation_id != self.operation_id
                    or self.verification_request.idempotency_key != self.idempotency_key
                    or provider_request_digest(self.verification_request) != self.original_request_digest):
                raise ValueError("verification_request must match the inspected operation identity and digest")
        resource_requests = tuple(
            value for value in (self.resource_permit_request, self.resource_permit_release_request)
            if value is not None
        )
        if len(resource_requests) > 1:
            raise ValueError("only one original resource permit request may be supplied")
        if self.resource_permit_request is not None:
            if (self.resource_permit_request.operation_id != self.operation_id
                    or self.resource_permit_request.idempotency_key != self.idempotency_key
                    or provider_request_digest(self.resource_permit_request) != self.original_request_digest):
                raise ValueError("resource_permit_request must match the inspected operation and digest")
        if self.resource_permit_release_request is not None:
            if (self.resource_permit_release_request.operation_id != self.operation_id
                    or self.resource_permit_release_request.idempotency_key != self.idempotency_key
                    or provider_request_digest(self.resource_permit_release_request) != self.original_request_digest):
                raise ValueError("resource_permit_release_request must match the inspected operation and digest")


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
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GitEffectRequest:
    context: ProviderCallContext
    operation_id: StableId
    idempotency_key: StableId
    operation: GitOperationKind
    expected_source: Sha256Digest
    expected_authority_revision: int
    workspace_id: StableId | None = None
    base_ref: StableId | None = None
    source_commit: StableId | None = None
    destination_ref: StableId | None = None
    expected_destination: StableId | None = None
    target: EntityRef | None = None
    attempt: EntityRef | None = None
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    requested_at: datetime | None = None
    accepted_outcome_id: StableId | None = None
    accepted_candidate_id: StableId | None = None
    accepted_provenance_digest: Sha256Digest | None = None
    accepted_source_digest: Sha256Digest | None = None
    accepted_source_receipt_id: StableId | None = None

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
        for value, name in (
            (self.base_ref, "base_ref"), (self.source_commit, "source_commit"),
            (self.destination_ref, "destination_ref"), (self.expected_destination, "expected_destination"),
        ):
            if value is not None:
                _id(value, name)
        for value, kind, name in (
            (self.target, EntityKind.WORK_ITEM, "target"),
            (self.attempt, EntityKind.ATTEMPT, "attempt"),
            (self.run, EntityKind.RUN, "run"),
            (self.assignment, EntityKind.ASSIGNMENT, "assignment"),
        ):
            if value is not None and (not isinstance(value, EntityRef) or value.kind is not kind
                                      or value.project_id != self.context.project_id):
                raise ValueError(f"{name} must be a project-local {kind.value} reference")
        if self.requested_at is not None:
            _aware(self.requested_at, "requested_at")
        for value, name in (
            (self.accepted_outcome_id, "accepted_outcome_id"),
            (self.accepted_candidate_id, "accepted_candidate_id"),
            (self.accepted_source_receipt_id, "accepted_source_receipt_id"),
        ):
            if value is not None:
                _id(value, name)
        for value, name in (
            (self.accepted_provenance_digest, "accepted_provenance_digest"),
            (self.accepted_source_digest, "accepted_source_digest"),
        ):
            if value is not None and not isinstance(value, Sha256Digest):
                raise TypeError(f"{name} must be a Sha256Digest")


@dataclass(frozen=True)
class GitEffectObservation:
    operation_id: StableId
    disposition: GitEffectDisposition
    resulting_source: Sha256Digest | None = None
    conflict_refs: tuple[StableId, ...] = ()
    external_ref: StableId | None = None
    conflict_tree: StableId | None = None
    original_receipt: ProviderReceipt | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.disposition, GitEffectDisposition):
            raise TypeError("disposition must be a GitEffectDisposition")
        if self.resulting_source is not None and not isinstance(self.resulting_source, Sha256Digest):
            raise TypeError("resulting_source must be a Sha256Digest")
        if self.external_ref is not None:
            _id(self.external_ref, "external_ref")
        if self.conflict_tree is not None:
            _id(self.conflict_tree, "conflict_tree")
        if self.original_receipt is not None and not isinstance(self.original_receipt, ProviderReceipt):
            raise TypeError("original_receipt must be a ProviderReceipt when supplied")
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
    workspace_id: StableId | None = None
    cwd: str | None = None

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
        if self.workspace_id is not None:
            _id(self.workspace_id, "workspace_id")
        if self.cwd is not None:
            if (not isinstance(self.cwd, str) or not self.cwd or self.cwd != self.cwd.strip()
                    or self.cwd.startswith(("/", "\\")) or "\\" in self.cwd
                    or (self.cwd != "." and any(part in {"", ".", ".."} for part in self.cwd.split("/")))):
                raise ValueError("cwd must be a normalized repository-relative POSIX path")


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
    original_receipt: ProviderReceipt | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.state, CommandInspectionState):
            raise TypeError("state must be a CommandInspectionState")
        if self.state is CommandInspectionState.COMPLETED:
            if not isinstance(self.observation, CommandObservation):
                raise ValueError("completed inspection requires a CommandObservation")
            if self.observation.operation_id != self.operation_id:
                raise ValueError("observation must match the inspected operation")
            if not isinstance(self.original_receipt, ProviderReceipt):
                raise ValueError("completed inspection requires the original execution receipt")
        elif self.observation is not None:
            raise ValueError("running or not-started inspection cannot contain a completion observation")
        elif self.original_receipt is not None:
            raise ValueError("running or not-started inspection cannot contain an execution receipt")


@dataclass(frozen=True)
class ResourcePermitRequest:
    context: ProviderCallContext
    attempt: EntityRef
    operation_id: StableId
    idempotency_key: StableId
    resource_class: StableId
    units: int
    scope_id: StableId | None = None
    expected_authority_revision: int | None = None
    lease_id: StableId | None = None
    lease_expires_at: datetime | None = None

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
        if self.scope_id is not None:
            _id(self.scope_id, "scope_id")
        if type(self.units) is not int or self.units < 1:
            raise ValueError("units must be a positive integer")
        if self.expected_authority_revision is not None and (
            type(self.expected_authority_revision) is not int or self.expected_authority_revision < 1
        ):
            raise ValueError("expected_authority_revision must be positive when supplied")
        if self.lease_id is not None:
            _id(self.lease_id, "lease_id")
        if self.lease_expires_at is not None:
            _aware(self.lease_expires_at, "lease_expires_at")
        if (self.lease_id is None) != (self.lease_expires_at is None):
            raise ValueError("lease_id and lease_expires_at must be supplied together")


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
    expected_authority_revision: int | None = None

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
        if self.expected_authority_revision is not None and (
            type(self.expected_authority_revision) is not int or self.expected_authority_revision < 1
        ):
            raise ValueError("expected_authority_revision must be positive when supplied")


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
    contract: VerificationContract | None = None
    workspace_id: StableId | None = None
    verifier_version: str | None = None
    required_evidence: tuple[EvidenceRequirement, ...] = ()
    expected_authority_revision: int | None = None

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
        if self.contract is not None and not isinstance(self.contract, VerificationContract):
            raise TypeError("contract must be a VerificationContract")
        if self.workspace_id is not None:
            _id(self.workspace_id, "workspace_id")
        if self.verifier_version is not None:
            _text(self.verifier_version, "verifier_version")
        if (self.expected_authority_revision is not None
                and (type(self.expected_authority_revision) is not int or self.expected_authority_revision < 1)):
            raise ValueError("expected_authority_revision must be positive when supplied")
        _tuple(self.required_evidence, "required_evidence", EvidenceRequirement, unique=True)
        if len({item.name for item in self.required_evidence}) != len(self.required_evidence):
            raise ValueError("required_evidence must not repeat names")
        if (self.contract is None) != (self.workspace_id is None):
            raise ValueError("contract and workspace_id must be supplied together")
        if self.contract is not None:
            encoded = json.dumps(
                self.contract.to_mapping(), ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            )
            actual = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            if actual != self.contract_digest.hex:
                raise ValueError("contract_digest does not match the typed contract")
        _tuple(self.inputs, "inputs", EvidenceInput, unique=True)
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise ValueError("inputs must not repeat names")


@dataclass(frozen=True)
class VerificationEvidenceFact:
    """One named, versioned evidence value returned by a trusted verifier."""

    name: StableId
    kind: EvidenceKind
    version: int
    digest: Sha256Digest
    artifact_id: StableId | None = None
    benchmark_value: float | None = None
    unit: str | None = None
    sample_count: int | None = None

    def __post_init__(self) -> None:
        _id(self.name, "evidence fact name")
        if not isinstance(self.kind, EvidenceKind):
            raise TypeError("evidence fact kind must be an EvidenceKind")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("evidence fact version must be a positive integer")
        if not isinstance(self.digest, Sha256Digest):
            raise TypeError("evidence fact digest must be a Sha256Digest")
        if self.artifact_id is not None:
            _id(self.artifact_id, "evidence artifact_id")
            if self.kind is not EvidenceKind.ARTIFACT_REFERENCE:
                raise ValueError("artifact_id is only valid for artifact_reference evidence")
        benchmark_fields = (self.benchmark_value, self.unit, self.sample_count)
        if self.kind is EvidenceKind.BENCHMARK_SAMPLE:
            if (type(self.benchmark_value) not in {int, float} or not math.isfinite(self.benchmark_value)
                    or not isinstance(self.unit, str) or not self.unit or self.unit != self.unit.strip()
                    or type(self.sample_count) is not int or self.sample_count < 1):
                raise ValueError("benchmark_sample facts require a finite value, unit, and positive sample_count")
            if len(self.unit) > 128 or any(ord(char) < 32 for char in self.unit):
                raise ValueError("benchmark sample unit is invalid")
            object.__setattr__(self, "benchmark_value", float(self.benchmark_value))
        elif any(value is not None for value in benchmark_fields):
            raise ValueError("numeric benchmark fields belong only to benchmark_sample evidence")


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
    evidence_facts: tuple[VerificationEvidenceFact, ...] = ()
    command_observation: CommandObservation | None = None
    command_receipt: ProviderReceipt | None = None

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
        _tuple(self.evidence_facts, "evidence_facts", VerificationEvidenceFact, unique=True)
        if len({item.name for item in self.evidence_facts}) != len(self.evidence_facts):
            raise ValueError("evidence facts must not repeat names")
        artifact_refs = [item.artifact_id for item in self.evidence_facts if item.artifact_id is not None]
        if len(set(artifact_refs)) != len(artifact_refs) or any(item not in self.artifact_ids for item in artifact_refs):
            raise ValueError("evidence artifact references must be unique members of artifact_ids")
        if (self.command_observation is None) != (self.command_receipt is None):
            raise ValueError("command observation and execution receipt must be supplied together")
        if self.command_observation is not None:
            if not isinstance(self.command_observation, CommandObservation):
                raise TypeError("command_observation must be a CommandObservation")
            if self.command_observation.operation_id != self.operation_id:
                raise ValueError("command observation must match the verification operation")
            if not isinstance(self.command_receipt, ProviderReceipt):
                raise TypeError("command_receipt must be a ProviderReceipt")


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
    original_receipt: ProviderReceipt | None = None

    def __post_init__(self) -> None:
        _id(self.operation_id, "operation_id")
        if not isinstance(self.state, VerificationInspectionState):
            raise TypeError("state must be a VerificationInspectionState")
        if self.state is VerificationInspectionState.COMPLETED:
            if not isinstance(self.observation, VerificationObservation):
                raise ValueError("completed inspection requires a VerificationObservation")
            if not isinstance(self.original_receipt, ProviderReceipt):
                raise ValueError("completed inspection requires the original verification receipt")
            if self.observation.operation_id != self.operation_id:
                raise ValueError("observation must match the inspected operation")
        elif self.observation is not None or self.original_receipt is not None:
            raise ValueError("running or not-started inspection cannot contain completion evidence")


__all__ = [
    "PROVIDER_CONTRACT_VERSION", "ProviderIdentity", "ProviderReceipt", "ProviderStatus", "ProviderResult",
    "provider_request_digest",
    "ProviderCallContext", "TrustedContextRequest", "TrustedActorContext", "TrustedContextProvider",
    "ArtifactExpectation", "ArtifactAvailability", "SourceObservationRequest", "WorkingTreeState", "SourceObservation", "SourceObserver",
    "DeclarationKind", "DeclarationStatus", "DeclarationObservationRequest", "DeclarationObservation", "DeclarationObserver",
    "EffectInspectionRequest",
    "GitOperationKind", "GitEffectDisposition", "GitEffectRequest", "GitEffectObservation", "GitEffectsProvider",
    "CommandExecutionRequest", "CommandObservation", "CommandInspectionState", "CommandExecutionInspection",
    "CommandExecutionProvider", "ResourcePermitRequest", "ResourcePermitRef", "ResourcePermitReleaseRequest",
    "ResourcePermitRelease", "ResourcePermitInspectionState", "ResourcePermitInspection", "ResourcePermitProvider",
    "VerificationRequest", "VerificationEvidenceFact", "VerificationObservation", "VerificationInspectionState", "VerificationInspection",
    "VerificationProvider",
]
