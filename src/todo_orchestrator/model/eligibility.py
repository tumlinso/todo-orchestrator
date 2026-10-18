"""Typed inputs and results for deterministic work eligibility checks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId

from todo_orchestrator.contracts.providers import ProviderReceipt


class EligibilityStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EligibilityCause:
    """One attributable reason that affects the eligibility result."""

    code: str
    message: str
    subject: EntityRef | None = None
    related: tuple[EntityRef, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not self.code.strip():
            raise ValueError("cause code must be non-empty text")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("cause message must be non-empty text")
        if self.subject is not None and not isinstance(self.subject, EntityRef):
            raise TypeError("cause subject must be an EntityRef")
        if not isinstance(self.related, tuple) or any(not isinstance(ref, EntityRef) for ref in self.related):
            raise TypeError("cause related values must be a tuple of EntityRef values")


@dataclass(frozen=True)
class EligibilityRequest:
    """A revision-bound request to assess one actor's action on a work item.

    Time is deliberately obtained by an authority adapter, not supplied by the
    caller, so expiry checks cannot be backdated at admission time.
    """

    target: EntityRef
    actor: EntityRef
    action: StableId
    expected_revision: int
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    attempt: EntityRef | None = None
    participants: tuple[EntityRef, ...] = ()
    scope: EntityRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, EntityRef) or self.target.kind is not EntityKind.WORK_ITEM:
            raise ValueError("target must be a revision-qualified work-item reference")
        if not isinstance(self.actor, EntityRef) or self.actor.kind is not EntityKind.ACTOR:
            raise ValueError("actor must identify an actor incarnation")
        if self.actor.project_id != self.target.project_id:
            raise ValueError("actor and target must belong to the same project")
        if not isinstance(self.action, StableId):
            raise TypeError("action must be a StableId")
        if type(self.expected_revision) is not int or self.expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        for value, kind, name in (
            (self.run, EntityKind.RUN, "run"),
            (self.assignment, EntityKind.ASSIGNMENT, "assignment"),
            (self.attempt, EntityKind.ATTEMPT, "attempt"),
        ):
            if value is not None and (not isinstance(value, EntityRef) or value.kind is not kind):
                raise ValueError(f"{name} must reference {kind.value}")
            if value is not None and value.project_id != self.target.project_id:
                raise ValueError(f"{name} must belong to the target project")
        if self.scope is not None and (
            not isinstance(self.scope, EntityRef) or self.scope.project_id != self.target.project_id
        ):
            raise ValueError("scope must be a same-project EntityRef")
        if not isinstance(self.participants, tuple) or any(
            not isinstance(participant, EntityRef) or participant.kind is not EntityKind.ACTOR
            or participant.project_id != self.target.project_id
            for participant in self.participants
        ):
            raise TypeError("participants must be same-project actor incarnation references")
        if len(set(self.participants)) != len(self.participants):
            raise ValueError("participants must be unique")
        if self.actor not in self.participants and self.participants:
            raise ValueError("participants must include the requesting actor")


@dataclass(frozen=True)
class QualifiedSourceRevision:
    """A source commit qualified by project, repository, ref, and digest."""

    project_id: StableId
    repository_id: StableId
    ref: StableId
    digest: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, StableId) for value in (self.project_id, self.repository_id, self.ref)):
            raise TypeError("qualified source revision identities must be StableId values")
        if not isinstance(self.digest, str) or len(self.digest) != 64 or any(
            char not in "0123456789abcdef" for char in self.digest
        ):
            raise ValueError("source revision digest must be lowercase SHA-256 hex")


@dataclass(frozen=True)
class QualifiedDestination:
    """A qualified integration destination, such as a repository ref."""

    project_id: StableId
    repository_id: StableId
    ref: StableId

    def __post_init__(self) -> None:
        if not all(isinstance(value, StableId) for value in (self.project_id, self.repository_id, self.ref)):
            raise TypeError("qualified destination identities must be StableId values")


@dataclass(frozen=True)
class WorkspaceIsolation:
    """Provider-measured physical identities for one linked workspace.

    The path values are one-way identities, not caller supplied paths. A
    provider may claim overlap is safe only when the repository storage is
    shared while workspace roots, indexes, and refs are all distinct.
    """

    repository_storage: Sha256Digest
    workspace_root: Sha256Digest
    index_file: Sha256Digest
    head_ref: StableId

    def __post_init__(self) -> None:
        if not all(isinstance(value, Sha256Digest) for value in (
            self.repository_storage, self.workspace_root, self.index_file,
        )):
            raise TypeError("workspace isolation identities must be Sha256Digest values")
        if not isinstance(self.head_ref, StableId):
            raise TypeError("head_ref must be a StableId")


@dataclass(frozen=True)
class WorkspaceQualification:
    """Provider-observed workspace identity and its exact base/destination.

    Construct only from a successful trusted provider observation. This value
    is evidence supplied to policy, not authentication; a later trust adapter
    must bind it to the actual source operation and caller.
    """

    workspace_id: StableId
    repository_id: StableId
    common_base: QualifiedSourceRevision
    destination: QualifiedDestination
    receipt: ProviderReceipt
    isolation: WorkspaceIsolation | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_id, StableId) or not isinstance(self.repository_id, StableId):
            raise TypeError("workspace and repository IDs must be StableId values")
        if not isinstance(self.common_base, QualifiedSourceRevision):
            raise TypeError("common_base must be a QualifiedSourceRevision")
        if not isinstance(self.destination, QualifiedDestination):
            raise TypeError("destination must be a QualifiedDestination")
        if self.common_base.repository_id != self.repository_id or self.destination.repository_id != self.repository_id:
            raise ValueError("workspace, common base, and destination must identify the same repository")
        if self.common_base.project_id != self.destination.project_id:
            raise ValueError("common base and destination must belong to the same project")
        if not isinstance(self.receipt, ProviderReceipt):
            raise TypeError("workspace qualification must retain a provider receipt")
        if self.isolation is not None and not isinstance(self.isolation, WorkspaceIsolation):
            raise TypeError("isolation must be a WorkspaceIsolation value")


@dataclass(frozen=True)
class AttemptScopeSnapshot:
    """Immutable repository-relative paths and locks owned by one attempt."""

    paths: tuple[tuple[str, str], ...]
    locks: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.paths, tuple) or not isinstance(self.locks, tuple):
            raise TypeError("attempt scope paths and locks must be tuples")
        if any(not isinstance(pair, tuple) or len(pair) != 2 for pair in self.paths + self.locks):
            raise TypeError("attempt scope entries must be (name, mode) tuples")
        for path, access in self.paths:
            if (not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
                    or any(part in {"", ".", ".."} or ":" in part for part in path.split("/"))
                    or any(char in path for char in "*?[]")
                    or not isinstance(access, str) or access not in {"read", "write", "forbidden"}):
                raise ValueError("attempt scope paths must be safe repository-relative paths and access modes")
        for name, mode in self.locks:
            if not isinstance(name, str) or not name or not isinstance(mode, str) or mode not in {"shared", "exclusive"}:
                raise ValueError("attempt scope locks must have a name and shared/exclusive mode")


@dataclass(frozen=True)
class EligibilityDecision:
    """Deterministic result tied to the semantic revision actually observed."""

    status: EligibilityStatus
    authority_revision: int
    causes: tuple[EligibilityCause, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, EligibilityStatus):
            raise TypeError("status must be an EligibilityStatus")
        if type(self.authority_revision) is not int or self.authority_revision < 0:
            raise ValueError("authority_revision must be a non-negative integer")
        if not isinstance(self.causes, tuple) or any(not isinstance(cause, EligibilityCause) for cause in self.causes):
            raise TypeError("causes must be a tuple of EligibilityCause values")
        if self.status is EligibilityStatus.ALLOWED and self.causes:
            raise ValueError("allowed decisions must not contain blocking or unknown causes")
        if self.status is not EligibilityStatus.ALLOWED and not self.causes:
            raise ValueError("blocked and unknown decisions require attributable causes")

    @property
    def allowed(self) -> bool:
        return self.status is EligibilityStatus.ALLOWED


__all__ = [
    "EligibilityCause",
    "EligibilityDecision",
    "EligibilityRequest",
    "EligibilityStatus",
    "AttemptScopeSnapshot",
    "QualifiedDestination",
    "QualifiedSourceRevision",
    "WorkspaceQualification",
]
