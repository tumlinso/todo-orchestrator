"""Immutable domain values for standalone Todo Orchestrator.

These contracts describe records and local value invariants. They do not
implement persistence, workflow transitions, authentication, or authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from re import fullmatch
from types import MappingProxyType
from typing import Mapping
from unicodedata import category


DOMAIN_CONTRACT_VERSION = 1


def _ids(*values: StableId) -> None:
    if any(not isinstance(value, StableId) for value in values):
        raise TypeError("identity fields must be StableId values")


def _text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be non-empty text without surrounding whitespace")


def _items(value: tuple[object, ...], name: str, item_type: type | None = None,
           *, nonempty: bool = False, unique: bool = False) -> None:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")
    if nonempty and not value:
        raise ValueError(f"{name} must not be empty")
    if item_type is not None and any(not isinstance(item, item_type) for item in value):
        raise TypeError(f"{name} must contain {item_type.__name__} values")
    if unique and len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")


def _ref(value: EntityRef, kind: EntityKind, project_id: StableId | None = None,
         name: str = "reference") -> None:
    if not isinstance(value, EntityRef) or value.kind is not kind:
        raise ValueError(f"{name} must reference {kind.value}")
    if project_id is not None and value.project_id != project_id:
        raise ValueError(f"{name} must belong to this project")


def _aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")


@dataclass(frozen=True, order=True)
class StableId:
    """Opaque identifier; uniqueness and existence are authority responsibilities."""

    value: str

    def __post_init__(self) -> None:
        _text(self.value, "identifier")
        if len(self.value) > 128 or any(char.isspace() or category(char) == "Cc" for char in self.value):
            raise ValueError("identifier must be at most 128 characters and contain no whitespace/control characters")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class Sha256Digest:
    """Syntactically validated digest; its origin is not authenticated here."""

    hex: str

    def __post_init__(self) -> None:
        if not isinstance(self.hex, str) or fullmatch(r"[0-9a-f]{64}", self.hex) is None:
            raise ValueError("SHA-256 digest must be 64 lowercase hexadecimal characters")


class EntityKind(str, Enum):
    PROJECT = "project"
    PLAN_REVISION = "plan_revision"
    WORK_ITEM = "work_item"
    REQUIREMENT = "requirement"
    RUN = "run"
    ASSIGNMENT = "assignment"
    ATTEMPT = "attempt"
    ACTOR = "actor"
    CAPABILITY = "capability"
    EVIDENCE = "evidence"
    ARTIFACT = "artifact"
    OUTCOME = "outcome"
    EXTERNAL_OPERATION = "external_operation"
    CHECKPOINT = "checkpoint"
    INTERFACE = "interface"
    BARRIER = "barrier"
    DECISION = "decision"
    INVARIANT = "invariant"


@dataclass(frozen=True)
class EntityRef:
    """Project-scoped reference; work and requirement definitions are revisioned."""

    project_id: StableId
    kind: EntityKind
    entity_id: StableId
    definition_revision_id: StableId | None = None
    incarnation_id: StableId | None = None

    def __post_init__(self) -> None:
        _ids(self.project_id, self.entity_id)
        if not isinstance(self.kind, EntityKind):
            raise TypeError("kind must be an EntityKind")
        versioned = self.kind in {EntityKind.WORK_ITEM, EntityKind.REQUIREMENT}
        incarnated = self.kind is EntityKind.ACTOR
        if versioned != (self.definition_revision_id is not None):
            raise ValueError("only work item and requirement references carry a definition revision")
        if self.definition_revision_id is not None:
            _ids(self.definition_revision_id)
        if incarnated != (self.incarnation_id is not None):
            raise ValueError("actor references must carry an incarnation_id")
        if self.incarnation_id is not None:
            _ids(self.incarnation_id)
        if self.kind is EntityKind.PROJECT and self.entity_id != self.project_id:
            raise ValueError("a project reference must identify its project_id")


@dataclass(frozen=True)
class SourceProvenance:
    source: str
    content_digest: Sha256Digest
    producer: str | None = None

    def __post_init__(self) -> None:
        _text(self.source, "source")
        if self.producer is not None:
            _text(self.producer, "producer")
        if not isinstance(self.content_digest, Sha256Digest):
            raise TypeError("content_digest must be a Sha256Digest")


@dataclass(frozen=True)
class Project:
    """Identity boundary for one project-local semantic authority."""

    project_id: StableId
    authority_id: StableId

    def __post_init__(self) -> None:
        _ids(self.project_id, self.authority_id)

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.PROJECT, self.project_id)


class RequirementKind(str, Enum):
    PREREQUISITE = "prerequisite"
    CHECK = "check"


BLOCKING_ENTITY_KINDS = frozenset({
    EntityKind.WORK_ITEM, EntityKind.CHECKPOINT, EntityKind.INTERFACE,
    EntityKind.BARRIER, EntityKind.DECISION,
})


class RequirementMode(str, Enum):
    ALL = "all"
    ANY = "any"
    QUORUM = "quorum"


@dataclass(frozen=True)
class RequirementGroup:
    kind: RequirementKind
    mode: RequirementMode
    requirement_ids: tuple[StableId, ...]
    quorum: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RequirementKind) or not isinstance(self.mode, RequirementMode):
            raise TypeError("kind and mode must use their declared enums")
        _items(self.requirement_ids, "requirement_ids", StableId, nonempty=True, unique=True)
        if self.mode is RequirementMode.QUORUM:
            if type(self.quorum) is not int or not 1 <= self.quorum <= len(self.requirement_ids):
                raise ValueError("quorum must be between one and the group size")
        elif self.quorum is not None:
            raise ValueError("quorum is only valid for QUORUM mode")


@dataclass(frozen=True)
class WorkItem:
    """Immutable, revision-scoped statement of an intended outcome."""

    work_item_id: StableId
    project_id: StableId
    definition_revision_id: StableId
    title: str
    outcome: str
    requirement_groups: tuple[RequirementGroup, ...] = ()
    parent: EntityRef | None = None
    supersedes: tuple[EntityRef, ...] = ()

    def __post_init__(self) -> None:
        _ids(self.work_item_id, self.project_id, self.definition_revision_id)
        _text(self.title, "title")
        _text(self.outcome, "outcome")
        _items(self.requirement_groups, "requirement_groups", RequirementGroup, unique=True)
        refs = tuple(ref for group in self.requirement_groups for ref in group.requirement_ids)
        if len(set(refs)) != len(refs):
            raise ValueError("requirement groups must not repeat requirement IDs")
        _items(self.supersedes, "supersedes", EntityRef, unique=True)
        if self.parent is not None:
            _ref(self.parent, EntityKind.WORK_ITEM, self.project_id, "parent")
            if (self.parent.entity_id, self.parent.definition_revision_id) == (
                self.work_item_id, self.definition_revision_id
            ):
                raise ValueError("a work item cannot be its own parent")
        for ref in self.supersedes:
            _ref(ref, EntityKind.WORK_ITEM, self.project_id, "supersedes")
            if (ref.entity_id, ref.definition_revision_id) == (self.work_item_id, self.definition_revision_id):
                raise ValueError("a work item cannot supersede itself")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.WORK_ITEM, self.work_item_id, self.definition_revision_id)


@dataclass(frozen=True)
class Requirement:
    """Prerequisite or named check owned by one work-item definition."""

    requirement_id: StableId
    project_id: StableId
    definition_revision_id: StableId
    work_item_id: StableId
    kind: RequirementKind
    description: str
    target: EntityRef | None = None
    check_key: StableId | None = None

    def __post_init__(self) -> None:
        _ids(self.requirement_id, self.project_id, self.definition_revision_id, self.work_item_id)
        _text(self.description, "description")
        if self.kind is RequirementKind.PREREQUISITE:
            if not isinstance(self.target, EntityRef) or self.target.kind not in BLOCKING_ENTITY_KINDS:
                names = ", ".join(kind.value for kind in sorted(BLOCKING_ENTITY_KINDS, key=lambda kind: kind.value))
                raise ValueError(f"a prerequisite target must be one of: {names}")
            if self.check_key is not None:
                raise ValueError("a prerequisite cannot have a check_key")
        elif self.kind is RequirementKind.CHECK:
            if self.target is not None:
                raise ValueError("a check uses a check_key, not a work-item target")
            if not isinstance(self.check_key, StableId):
                raise ValueError("a check must have a StableId check_key")
        else:
            raise TypeError("kind must be a RequirementKind")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.REQUIREMENT, self.requirement_id, self.definition_revision_id)

    @property
    def owner(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.WORK_ITEM, self.work_item_id, self.definition_revision_id)


@dataclass(frozen=True)
class PlanRevision:
    """Immutable plan contents; proposed/validated/accepted state is a separate authority fact."""

    plan_revision_id: StableId
    project_id: StableId
    sequence: int
    work_items: tuple[EntityRef, ...]
    based_on_revision_id: StableId | None = None
    provenance: SourceProvenance | None = None
    authored_by: EntityRef | None = None

    def __post_init__(self) -> None:
        _ids(self.plan_revision_id, self.project_id)
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        if self.based_on_revision_id is not None:
            _ids(self.based_on_revision_id)
            if self.based_on_revision_id == self.plan_revision_id:
                raise ValueError("a plan revision cannot be based on itself")
        _items(self.work_items, "work_items", EntityRef, unique=True)
        for ref in self.work_items:
            _ref(ref, EntityKind.WORK_ITEM, self.project_id, "work item")
        if len({ref.entity_id for ref in self.work_items}) != len(self.work_items):
            raise ValueError("plan membership must select one definition per work item")
        if self.authored_by is not None:
            _ref(self.authored_by, EntityKind.ACTOR, self.project_id, "authored_by")
        if self.provenance is not None and not isinstance(self.provenance, SourceProvenance):
            raise TypeError("provenance must be SourceProvenance")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.PLAN_REVISION, self.plan_revision_id)


class PlanRevisionState(str, Enum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    ACCEPTED = "accepted"


PLAN_REVISION_TRANSITIONS: Mapping[PlanRevisionState, frozenset[PlanRevisionState]] = MappingProxyType({
    PlanRevisionState.PROPOSED: frozenset({PlanRevisionState.VALIDATED}),
    PlanRevisionState.VALIDATED: frozenset({PlanRevisionState.ACCEPTED}),
    PlanRevisionState.ACCEPTED: frozenset(),
})


class RunState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    RETIRED = "retired"


RUN_TRANSITIONS: Mapping[RunState, frozenset[RunState]] = MappingProxyType({
    RunState.OPEN: frozenset({RunState.CLOSED, RunState.RETIRED}),
    RunState.CLOSED: frozenset({RunState.RETIRED}),
    RunState.RETIRED: frozenset(),
})


@dataclass(frozen=True)
class Run:
    """Optional execution context; simple work does not require a Run."""

    run_id: StableId
    project_id: StableId
    plan_revision: EntityRef
    state: RunState = RunState.OPEN
    created_by: EntityRef | None = None

    def __post_init__(self) -> None:
        _ids(self.run_id, self.project_id)
        _ref(self.plan_revision, EntityKind.PLAN_REVISION, self.project_id, "plan_revision")
        if not isinstance(self.state, RunState):
            raise TypeError("state must be a RunState")
        if self.created_by is not None:
            _ref(self.created_by, EntityKind.ACTOR, self.project_id, "created_by")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.RUN, self.run_id)


@dataclass(frozen=True)
class Assignment:
    """Immutable scheduling fact; it is not a claim or reservation."""

    assignment_id: StableId
    project_id: StableId
    work_item: EntityRef
    assignee: EntityRef | None = None
    run: EntityRef | None = None

    def __post_init__(self) -> None:
        _ids(self.assignment_id, self.project_id)
        _ref(self.work_item, EntityKind.WORK_ITEM, self.project_id, "work_item")
        if self.assignee is not None:
            _ref(self.assignee, EntityKind.ACTOR, self.project_id, "assignee")
        if self.run is not None:
            _ref(self.run, EntityKind.RUN, self.project_id, "run")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.ASSIGNMENT, self.assignment_id)


class ActorKind(str, Enum):
    HUMAN = "human"
    AUTOMATION = "automation"
    SERVICE = "service"


@dataclass(frozen=True)
class Actor:
    """Host-supplied identity and incarnation; these fields do not authenticate it."""

    actor_id: StableId
    project_id: StableId
    incarnation_id: StableId
    kind: ActorKind
    label: str | None = None

    def __post_init__(self) -> None:
        _ids(self.actor_id, self.project_id, self.incarnation_id)
        if not isinstance(self.kind, ActorKind):
            raise TypeError("kind must be an ActorKind")
        if self.label is not None:
            _text(self.label, "label")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(
            self.project_id, EntityKind.ACTOR, self.actor_id, incarnation_id=self.incarnation_id
        )


@dataclass(frozen=True)
class Capability:
    """Bounded authorization grant data; the value itself confers no authority."""

    capability_id: StableId
    project_id: StableId
    actor: EntityRef
    scope: EntityRef
    actions: tuple[StableId, ...]
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    attempt: EntityRef | None = None
    expires_at: datetime | None = None
    parent_capability: EntityRef | None = None

    def __post_init__(self) -> None:
        _ids(self.capability_id, self.project_id)
        _ref(self.actor, EntityKind.ACTOR, self.project_id, "actor")
        if not isinstance(self.scope, EntityRef) or self.scope.project_id != self.project_id:
            raise ValueError("scope must belong to this project")
        _items(self.actions, "actions", StableId, nonempty=True, unique=True)
        for value, kind, name in (
            (self.run, EntityKind.RUN, "run"),
            (self.assignment, EntityKind.ASSIGNMENT, "assignment"),
            (self.attempt, EntityKind.ATTEMPT, "attempt"),
        ):
            if value is not None:
                _ref(value, kind, self.project_id, name)
        if self.expires_at is not None:
            _aware(self.expires_at, "expires_at")
        if self.parent_capability is not None:
            _ref(self.parent_capability, EntityKind.CAPABILITY, self.project_id, "parent_capability")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.CAPABILITY, self.capability_id)


@dataclass(frozen=True)
class Lease:
    lease_id: StableId
    owner: EntityRef
    expires_at: datetime

    def __post_init__(self) -> None:
        _ids(self.lease_id)
        _ref(self.owner, EntityKind.ACTOR, name="lease owner")
        _aware(self.expires_at, "expires_at")


class AttemptState(str, Enum):
    ADMITTED = "admitted"
    ACTIVE = "active"
    REPORTED = "reported"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    RELEASED = "released"
    EXPIRED = "expired"
    UNCERTAIN = "uncertain"
    QUARANTINED = "quarantined"


ATTEMPT_TRANSITIONS: Mapping[AttemptState, frozenset[AttemptState]] = MappingProxyType({
    AttemptState.ADMITTED: frozenset({AttemptState.ACTIVE, AttemptState.RELEASED, AttemptState.EXPIRED, AttemptState.UNCERTAIN, AttemptState.QUARANTINED}),
    AttemptState.ACTIVE: frozenset({AttemptState.REPORTED, AttemptState.RELEASED, AttemptState.EXPIRED, AttemptState.UNCERTAIN, AttemptState.QUARANTINED}),
    AttemptState.REPORTED: frozenset({AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED, AttemptState.UNCERTAIN, AttemptState.QUARANTINED}),
    AttemptState.ACCEPTED: frozenset(),
    AttemptState.REJECTED: frozenset(),
    AttemptState.RELEASED: frozenset(),
    AttemptState.EXPIRED: frozenset({AttemptState.ACTIVE, AttemptState.RELEASED, AttemptState.QUARANTINED}),
    AttemptState.UNCERTAIN: frozenset({AttemptState.ACTIVE, AttemptState.RELEASED, AttemptState.QUARANTINED}),
    AttemptState.QUARANTINED: frozenset({AttemptState.ACTIVE, AttemptState.RELEASED}),
})


@dataclass(frozen=True)
class Attempt:
    """One actor incarnation's execution record; acceptance is a separate Outcome."""

    attempt_id: StableId
    project_id: StableId
    work_item: EntityRef
    actor: EntityRef
    state: AttemptState
    capability_ids: tuple[StableId, ...] = ()
    assignment: EntityRef | None = None
    run: EntityRef | None = None
    lease: Lease | None = None

    def __post_init__(self) -> None:
        _ids(self.attempt_id, self.project_id)
        _ref(self.work_item, EntityKind.WORK_ITEM, self.project_id, "work_item")
        _ref(self.actor, EntityKind.ACTOR, self.project_id, "actor")
        if not isinstance(self.state, AttemptState):
            raise TypeError("state must be an AttemptState")
        _items(self.capability_ids, "capability_ids", StableId, unique=True)
        for value, kind, name in (
            (self.assignment, EntityKind.ASSIGNMENT, "assignment"),
            (self.run, EntityKind.RUN, "run"),
        ):
            if value is not None:
                _ref(value, kind, self.project_id, name)
        if self.lease is not None and self.lease.owner != self.actor:
            raise ValueError("attempt lease owner must match the attempt actor")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.ATTEMPT, self.attempt_id)


class EvidenceResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class EvidenceInput:
    name: StableId
    digest: Sha256Digest

    def __post_init__(self) -> None:
        _ids(self.name)
        if not isinstance(self.digest, Sha256Digest):
            raise TypeError("digest must be a Sha256Digest")


@dataclass(frozen=True)
class Evidence:
    """Immutable input-bound observation; current applicability is evaluated elsewhere."""

    evidence_id: StableId
    project_id: StableId
    attempt: EntityRef
    result: EvidenceResult
    verifier_id: StableId
    verifier_version: str
    contract_digest: Sha256Digest
    inputs: tuple[EvidenceInput, ...]
    observed_at: datetime
    requirement: EntityRef | None = None
    artifacts: tuple[EntityRef, ...] = ()

    def __post_init__(self) -> None:
        _ids(self.evidence_id, self.project_id, self.verifier_id)
        _ref(self.attempt, EntityKind.ATTEMPT, self.project_id, "attempt")
        if not isinstance(self.result, EvidenceResult):
            raise TypeError("result must be an EvidenceResult")
        _text(self.verifier_version, "verifier_version")
        if not isinstance(self.contract_digest, Sha256Digest):
            raise TypeError("contract_digest must be a Sha256Digest")
        _items(self.inputs, "inputs", EvidenceInput, unique=True)
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise ValueError("inputs must not repeat names")
        _aware(self.observed_at, "observed_at")
        if self.requirement is not None:
            _ref(self.requirement, EntityKind.REQUIREMENT, self.project_id, "requirement")
        _items(self.artifacts, "artifacts", EntityRef, unique=True)
        for artifact in self.artifacts:
            _ref(artifact, EntityKind.ARTIFACT, self.project_id, "artifact")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.EVIDENCE, self.evidence_id)


class OutcomeDisposition(str, Enum):
    COMPLETED = "completed"
    ACCEPTED_NEGATIVE = "accepted_negative"
    NO_CHANGE = "no_change"
    FAILED = "failed"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class Outcome:
    """Immutable accepted result, distinct from a worker report or attempt state."""

    outcome_id: StableId
    project_id: StableId
    work_item: EntityRef
    version: int
    disposition: OutcomeDisposition
    accepted_by: EntityRef
    accepted_at: datetime
    evidence_ids: tuple[StableId, ...] = ()
    attempt: EntityRef | None = None

    def __post_init__(self) -> None:
        _ids(self.outcome_id, self.project_id)
        _ref(self.work_item, EntityKind.WORK_ITEM, self.project_id, "work_item")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be a positive integer")
        if not isinstance(self.disposition, OutcomeDisposition):
            raise TypeError("disposition must be an OutcomeDisposition")
        _ref(self.accepted_by, EntityKind.ACTOR, self.project_id, "accepted_by")
        _aware(self.accepted_at, "accepted_at")
        _items(self.evidence_ids, "evidence_ids", StableId, unique=True)
        if self.attempt is not None:
            _ref(self.attempt, EntityKind.ATTEMPT, self.project_id, "attempt")

    @property
    def ref(self) -> EntityRef:
        return EntityRef(self.project_id, EntityKind.OUTCOME, self.outcome_id)


class ExternalOperationState(str, Enum):
    PREPARED = "prepared"
    EXECUTING = "executing"
    OBSERVED = "observed"
    FINALIZED = "finalized"
    FAILED = "failed"
    UNKNOWN = "unknown"


EXTERNAL_OPERATION_TRANSITIONS: Mapping[ExternalOperationState, frozenset[ExternalOperationState]] = MappingProxyType({
    ExternalOperationState.PREPARED: frozenset({ExternalOperationState.EXECUTING, ExternalOperationState.UNKNOWN}),
    ExternalOperationState.EXECUTING: frozenset({ExternalOperationState.OBSERVED, ExternalOperationState.FAILED, ExternalOperationState.UNKNOWN}),
    ExternalOperationState.OBSERVED: frozenset({ExternalOperationState.FINALIZED, ExternalOperationState.FAILED, ExternalOperationState.UNKNOWN}),
    ExternalOperationState.FINALIZED: frozenset(),
    ExternalOperationState.FAILED: frozenset(),
    ExternalOperationState.UNKNOWN: frozenset({ExternalOperationState.OBSERVED, ExternalOperationState.FAILED}),
})


@dataclass(frozen=True)
class ExternalOperation:
    """Durable intent/observation for an effect outside the project authority."""

    operation_id: StableId
    project_id: StableId
    kind: StableId
    idempotency_key: StableId
    request_digest: Sha256Digest
    state: ExternalOperationState
    created_at: datetime
    updated_at: datetime
    attempt: EntityRef | None = None
    external_ref: str | None = None
    receipt_digest: Sha256Digest | None = None

    def __post_init__(self) -> None:
        _ids(self.operation_id, self.project_id, self.kind, self.idempotency_key)
        if not isinstance(self.request_digest, Sha256Digest):
            raise TypeError("request_digest must be a Sha256Digest")
        if not isinstance(self.state, ExternalOperationState):
            raise TypeError("state must be an ExternalOperationState")
        _aware(self.created_at, "created_at")
        _aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.attempt is not None:
            _ref(self.attempt, EntityKind.ATTEMPT, self.project_id, "attempt")
        if self.external_ref is not None:
            _text(self.external_ref, "external_ref")
        if self.receipt_digest is not None and not isinstance(self.receipt_digest, Sha256Digest):
            raise TypeError("receipt_digest must be a Sha256Digest")
        if self.state in {ExternalOperationState.OBSERVED, ExternalOperationState.FINALIZED} and self.receipt_digest is None:
            raise ValueError("observed and finalized operations require a receipt digest")


__all__ = [
    "DOMAIN_CONTRACT_VERSION", "ATTEMPT_TRANSITIONS", "BLOCKING_ENTITY_KINDS", "EXTERNAL_OPERATION_TRANSITIONS",
    "PLAN_REVISION_TRANSITIONS", "RUN_TRANSITIONS", "Actor", "ActorKind", "Assignment",
    "Attempt", "AttemptState", "Capability", "EntityKind", "EntityRef", "Evidence",
    "EvidenceInput", "EvidenceResult", "ExternalOperation", "ExternalOperationState", "Lease",
    "Outcome", "OutcomeDisposition", "PlanRevision", "PlanRevisionState", "Project", "Requirement",
    "RequirementGroup", "RequirementKind", "RequirementMode", "Run", "RunState", "Sha256Digest",
    "SourceProvenance", "StableId", "WorkItem",
]
