"""Transactional attempt claims, leases, and conservative host reconciliation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from typing import Protocol

from todo_orchestrator.contracts import (
    ATTEMPT_TRANSITIONS,
    Attempt,
    AttemptState,
    EntityKind,
    EntityRef,
    Lease,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.contracts.providers import (
    ProviderIdentity,
    ProviderReceipt,
)
from todo_orchestrator.model import (
    CHILD_CANDIDATE_SUBMIT_ACTION,
    CHILD_CANCEL_ACTION,
    CHILD_DELEGATE_ACTION,
    CHILD_READ_ACTION,
    CHILD_REVIEW_ACTION,
    CHILD_RETRY_ACTION,
    CHILD_STOP_RECONCILE_ACTION,
    CHILD_WRITE_ACTION,
    AttemptSafetyObservation,
    AttemptAuthoringHandoff,
    AttemptAuthoringHandoffRequest,
    AttemptScopeSnapshot,
    ChildActivity,
    CommandEffect,
    CommandResult,
    EligibilityCause,
    EligibilityDecision,
    EligibilityRequest,
    EligibilityStatus,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceIsolation,
    WorkspaceQualification,
)
from todo_orchestrator.planning import CompiledPlan

from .auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeniedError,
    CONTEXT_FINDING_INVALIDATE_ACTION,
    CONTEXT_FINDING_PUBLISH_ACTION,
    CONTEXT_READ_ACTION,
    RECOVERY_APPLY_ACTION,
    RECOVERY_INSPECT_ACTION,
    RESOURCE_READ_ACTION,
    RESOURCE_RECONCILE_ACTION,
    RESOURCE_RELEASE_ACTION,
    RESOURCE_RESERVE_ACTION,
    _token_digest,
)
from .commands import MutationContext, StaleAuthorityRevisionError
from .eligibility import (
    EligibilityAdapter,
    _load_attempt_scope_snapshots,
    _path_overlaps,
    _scope_parts,
    _scope_snapshot_payload,
)
from .recovery_approval import (
    RecoveryApproval,
    _is_recovery_approval,
    _recovery_approval_digest,
)
from .sqlite import AuthorityError, SQLiteAuthority


CLAIM_ACTION = StableId("todo.attempt.claim")
HEARTBEAT_ACTION = StableId("todo.attempt.heartbeat")
RELEASE_ACTION = StableId("todo.attempt.release")
FINISH_ACTION = StableId("todo.attempt.finish")
RECONCILE_ACTION = StableId("todo.attempt.reconcile_expired")
VERIFICATION_ACTION = StableId("todo.verification.execute")
VERIFICATION_RECONCILE_ACTION = StableId("todo.verification.reconcile")
OUTCOME_REPORT_ACTION = StableId("todo.outcome.report")
ATTEMPT_SESSION_ACTIONS = (HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION)
ATTEMPT_SESSION_VERIFY_ACTIONS = (*ATTEMPT_SESSION_ACTIONS, VERIFICATION_ACTION)
ATTEMPT_SESSION_RECONCILE_ACTIONS = (*ATTEMPT_SESSION_ACTIONS, VERIFICATION_RECONCILE_ACTION)
ATTEMPT_SESSION_REPORT_ACTIONS = (*ATTEMPT_SESSION_ACTIONS, OUTCOME_REPORT_ACTION)
ATTEMPT_SESSION_VERIFICATION_ACTIONS = (
    *ATTEMPT_SESSION_ACTIONS, VERIFICATION_ACTION, VERIFICATION_RECONCILE_ACTION,
)
ATTEMPT_SESSION_VERIFY_REPORT_ACTIONS = (
    *ATTEMPT_SESSION_ACTIONS, VERIFICATION_ACTION, OUTCOME_REPORT_ACTION,
)
ATTEMPT_SESSION_RECONCILE_REPORT_ACTIONS = (
    *ATTEMPT_SESSION_ACTIONS, VERIFICATION_RECONCILE_ACTION, OUTCOME_REPORT_ACTION,
)
ATTEMPT_SESSION_VERIFICATION_REPORT_ACTIONS = (
    *ATTEMPT_SESSION_ACTIONS, VERIFICATION_ACTION, VERIFICATION_RECONCILE_ACTION, OUTCOME_REPORT_ACTION,
)
_ATTEMPT_SESSION_ACTION_CEILING = frozenset((
    *ATTEMPT_SESSION_ACTIONS, VERIFICATION_ACTION, VERIFICATION_RECONCILE_ACTION, OUTCOME_REPORT_ACTION,
    StableId("todo.message.send"), StableId("todo.message.read"), StableId("todo.question.answer"),
    CONTEXT_READ_ACTION, CONTEXT_FINDING_PUBLISH_ACTION, CONTEXT_FINDING_INVALIDATE_ACTION,
    RECOVERY_INSPECT_ACTION,
    RESOURCE_RESERVE_ACTION, RESOURCE_RELEASE_ACTION, RESOURCE_READ_ACTION, RESOURCE_RECONCILE_ACTION,
    CHILD_DELEGATE_ACTION, CHILD_RETRY_ACTION, CHILD_REVIEW_ACTION, CHILD_CANCEL_ACTION,
    CHILD_STOP_RECONCILE_ACTION, CHILD_READ_ACTION, CHILD_WRITE_ACTION,
    CHILD_CANDIDATE_SUBMIT_ACTION,
))
_LIVE_STATES = (AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED)
_TERMINAL_STATES = (AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED)


class AttemptError(AuthorityError):
    """Base class for attempt service failures."""


class AttemptNotFoundError(AttemptError):
    """The requested attempt does not exist in this project authority."""


class AttemptAdmissionDeniedError(AttemptError):
    """Shared eligibility policy refused the claim or heartbeat."""

    def __init__(self, decision: EligibilityDecision) -> None:
        self.decision = decision
        causes = "; ".join(f"{cause.code}: {cause.message}" for cause in decision.causes)
        super().__init__(f"attempt admission is {decision.status.value}: {causes}")


class AttemptHostUnavailableError(AttemptError):
    """The trusted host provider could not produce a usable observation."""


class AttemptObservationMismatchError(AttemptError):
    """An observation is stale, uncorrelated, or differs from stored authority state."""


class AttemptLeaseMismatchError(AttemptObservationMismatchError):
    """A fencing lease no longer matches the attempt's current lease."""


class AttemptOwnershipError(AttemptError):
    """A heartbeat was requested by a different actor incarnation."""


class AttemptTransitionError(AttemptError):
    """The requested lifecycle transition is not permitted."""


class AttemptHost(Protocol):
    """Trusted host-owned workspace and process observations.

    Implementations must verify workspace identity from host state. Caller
    supplied paths or boolean cleanliness flags are not sufficient evidence.
    """

    def qualify_workspace(
        self, workspace_id: StableId, target: EntityRef, correlation_id: StableId
    ) -> WorkspaceQualification:
        """Return exact repository/base/destination identity from a host provider."""

    def inspect_attempt(
        self, attempt: Attempt, workspace: WorkspaceQualification
    ) -> AttemptSafetyObservation:
        """Inspect the stored attempt's exact workspace, source, process, and children."""

    def handoff_authoring(
        self, request: AttemptAuthoringHandoffRequest
    ) -> AttemptAuthoringHandoff:
        """Pin/fence this task's source scope without claiming the process stopped."""


def _utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value, "timestamp").isoformat(timespec="microseconds")


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return _utc(parsed, "stored timestamp")


def _stable_id(prefix: str, seed: StableId) -> StableId:
    digest = hashlib.sha256(str(seed).encode("utf-8")).hexdigest()
    return StableId(f"{prefix}-{digest}")


def _target_in_plan(plan: CompiledPlan, target: EntityRef) -> bool:
    return any(item.definition.ref == target for item in plan.work_items)


def _plan_contexts(plan: CompiledPlan) -> Mapping[EntityRef, object]:
    return {item.definition.ref: item.context for item in plan.work_items}


def _workspace_values(qualification: WorkspaceQualification) -> tuple[object, ...]:
    base = qualification.common_base
    destination = qualification.destination
    receipt = qualification.receipt
    isolation = qualification.isolation
    isolation_json = json.dumps(
        None if isolation is None else {
            "repository_storage": isolation.repository_storage.hex,
            "workspace_root": isolation.workspace_root.hex,
            "index_file": isolation.index_file.hex,
            "head_ref": str(isolation.head_ref),
            "worktree_admin": None if isolation.worktree_admin is None else isolation.worktree_admin.hex,
        }, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"),
    )
    return (
        str(qualification.workspace_id), str(qualification.repository_id),
        str(base.project_id), str(base.ref), base.digest,
        str(destination.project_id), str(destination.ref),
        str(receipt.provider.provider_id), receipt.provider.version,
        receipt.provider.contract_version, str(receipt.receipt_id),
        str(receipt.correlation_id), receipt.request_digest.hex,
        str(receipt.provenance_ref), _iso(receipt.observed_at),
        isolation_json, hashlib.sha256(isolation_json.encode("ascii")).hexdigest(),
    )


def _workspace_from_row(project: Project, row: sqlite3.Row) -> WorkspaceQualification:
    provider = ProviderIdentity(
        StableId(row["provider_id"]), row["provider_version"], row["provider_contract_version"]
    )
    receipt = ProviderReceipt(
        StableId(row["receipt_id"]), provider, StableId(row["correlation_id"]),
        Sha256Digest(row["request_digest"]), StableId(row["provenance_ref"]),
        _parse_time(row["observed_at"]),
    )
    isolation_json = row["isolation_json"]
    isolation_digest = row["isolation_digest"]
    if hashlib.sha256(isolation_json.encode("ascii")).hexdigest() != isolation_digest:
        raise AttemptObservationMismatchError("stored workspace isolation digest does not match")
    try:
        isolation_value = json.loads(isolation_json)
        if isolation_value is None:
            isolation = None
        elif isinstance(isolation_value, dict) and set(isolation_value) == {
            "repository_storage", "workspace_root", "index_file", "head_ref", "worktree_admin",
        }:
            isolation = WorkspaceIsolation(
                Sha256Digest(isolation_value["repository_storage"]),
                Sha256Digest(isolation_value["workspace_root"]),
                Sha256Digest(isolation_value["index_file"]),
                StableId(isolation_value["head_ref"]),
                None if isolation_value["worktree_admin"] is None else Sha256Digest(isolation_value["worktree_admin"]),
            )
        else:
            raise ValueError("unexpected isolation fields")
        if json.dumps(
            isolation_value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"),
        ) != isolation_json:
            raise ValueError("isolation JSON is not canonical")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AttemptObservationMismatchError(f"stored workspace isolation is invalid: {exc}") from exc
    return WorkspaceQualification(
        StableId(row["workspace_id"]), StableId(row["repository_id"]),
        QualifiedSourceRevision(
            StableId(row["base_project_id"]), StableId(row["repository_id"]),
            StableId(row["base_ref"]), row["base_digest"],
        ),
        QualifiedDestination(
            StableId(row["destination_project_id"]), StableId(row["repository_id"]),
            StableId(row["destination_ref"]),
        ),
        receipt,
        isolation,
    )


def _attempt_from_row(project: Project, row: sqlite3.Row) -> Attempt:
    actor = EntityRef(
        project.project_id, EntityKind.ACTOR, StableId(row["actor_id"]),
        incarnation_id=StableId(row["actor_incarnation_id"]),
    )
    lease = None
    if row["lease_id"] is not None and row["lease_expires_at"] is not None:
        lease = Lease(StableId(row["lease_id"]), actor, _parse_time(row["lease_expires_at"]))
    return Attempt(
        StableId(row["attempt_id"]), project.project_id,
        EntityRef(
            project.project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
            definition_revision_id=StableId(row["definition_revision_id"]),
        ),
        actor, AttemptState(row["state"]), (),
        None if row["assignment_id"] is None else EntityRef(
            project.project_id, EntityKind.ASSIGNMENT, StableId(row["assignment_id"])
        ),
        None if row["run_id"] is None else EntityRef(
            project.project_id, EntityKind.RUN, StableId(row["run_id"])
        ),
        lease,
    )


def _stored_attempt(connection: sqlite3.Connection, project: Project, attempt_ref: EntityRef) -> tuple[Attempt, sqlite3.Row]:
    if not isinstance(attempt_ref, EntityRef) or attempt_ref.kind is not EntityKind.ATTEMPT:
        raise TypeError("attempt_ref must reference an attempt")
    if attempt_ref.project_id != project.project_id:
        raise ValueError("attempt_ref must belong to this authority project")
    row = connection.execute("SELECT * FROM attempts WHERE attempt_id = ?", (str(attempt_ref.entity_id),)).fetchone()
    if row is None:
        raise AttemptNotFoundError(f"attempt does not exist: {attempt_ref.entity_id}")
    return _attempt_from_row(project, row), row


def _require_children_resolved(connection: sqlite3.Connection, attempt_id: StableId) -> None:
    # Imported lazily to keep the generic attempt service independent of the
    # optional coordination API while still enforcing its durable occupancy.
    from .child_store import require_parent_children_resolved

    try:
        require_parent_children_resolved(connection, attempt_id)
    except ValueError as exc:
        raise AttemptTransitionError(str(exc)) from exc


def _require_recovery_operations_resolved(connection: sqlite3.Connection, attempt_id: StableId) -> None:
    """Refuse completion while an external operation can still change state.

    Definitive ``not_applied`` is resolved: it proves the external effect did
    not occur, though any retry still requires its own explicit authorization.
    """
    pending = connection.execute(
        "SELECT operation_id FROM external_operations WHERE attempt_id = ? "
        "AND state NOT IN ('finalized', 'failed', 'not_applied') ORDER BY operation_id LIMIT 1",
        (str(attempt_id),),
    ).fetchone()
    if pending is not None:
        raise AttemptTransitionError("external operation must be resolved before attempt recovery")


def _stored_workspace(
    connection: sqlite3.Connection, project: Project, attempt_ref: EntityRef
) -> WorkspaceQualification:
    row = connection.execute(
        "SELECT * FROM attempt_workspace_qualifications WHERE attempt_id = ?",
        (str(attempt_ref.entity_id),),
    ).fetchone()
    if row is None:
        raise AttemptObservationMismatchError("attempt has no persisted qualified workspace")
    try:
        return _workspace_from_row(project, row)
    except (TypeError, ValueError) as exc:
        raise AttemptObservationMismatchError(f"stored workspace qualification is invalid: {exc}") from exc


def _workspace_map(connection: sqlite3.Connection, project: Project) -> dict[EntityRef, WorkspaceQualification]:
    result: dict[EntityRef, WorkspaceQualification] = {}
    rows = connection.execute(
        "SELECT q.* FROM attempt_workspace_qualifications AS q "
        "JOIN attempts AS a ON a.attempt_id = q.attempt_id ORDER BY q.attempt_id"
    ).fetchall()
    for row in rows:
        try:
            attempt_ref = EntityRef(project.project_id, EntityKind.ATTEMPT, StableId(row["attempt_id"]))
            result[attempt_ref] = _workspace_from_row(project, row)
        except (TypeError, ValueError) as exc:
            raise AttemptObservationMismatchError(f"stored workspace qualification is invalid: {exc}") from exc
    return result


def _insert_workspace(
    context: MutationContext, attempt_id: StableId, qualification: WorkspaceQualification
) -> None:
    context.execute(
        "INSERT INTO attempt_workspace_qualifications(attempt_id, workspace_id, repository_id, "
        "base_project_id, base_ref, base_digest, destination_project_id, destination_ref, provider_id, "
        "provider_version, provider_contract_version, receipt_id, correlation_id, request_digest, "
        "provenance_ref, observed_at, isolation_json, isolation_digest) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(attempt_id), *_workspace_values(qualification)),
    )


def _observation_age(observation: AttemptSafetyObservation, now: datetime, max_age: timedelta) -> None:
    observed_at = _utc(observation.receipt.observed_at, "provider observation time")
    if observed_at > now or now - observed_at > max_age:
        raise AttemptObservationMismatchError("host safety observation is stale or from the future")


def _observation_audit(observation: AttemptSafetyObservation) -> dict[str, object]:
    """Return bounded structured provenance, excluding source text and host logs."""
    receipt = observation.receipt
    qualification = observation.workspace
    base = qualification.common_base
    destination = qualification.destination
    handoff = observation.authoring_handoff
    handoff_value = None if handoff is None else {
        "attempt_id": str(handoff.attempt.entity_id),
        "lease_id": str(handoff.lease_id),
        "workspace_id": str(handoff.workspace_id),
        "idempotency_key": str(handoff.request.idempotency_key),
        "source_commit": str(handoff.source_commit),
        "source_tree": str(handoff.source_tree),
        "source_digest": handoff.source_digest.hex,
        "receipt": {
            "receipt_id": str(handoff.receipt.receipt_id),
            "provider_id": str(handoff.receipt.provider.provider_id),
            "provider_version": handoff.receipt.provider.version,
            "provider_contract_version": handoff.receipt.provider.contract_version,
            "correlation_id": str(handoff.receipt.correlation_id),
            "request_digest": handoff.receipt.request_digest.hex,
            "provenance_ref": str(handoff.receipt.provenance_ref),
            "observed_at": _iso(handoff.receipt.observed_at),
        },
    }
    return {
        "source": observation.source.value,
        "source_digest": None if observation.source_digest is None else observation.source_digest.hex,
        "process": observation.process.value,
        "children": observation.children.value,
        "observed_state": observation.observed_state.value,
        "observed_lease_id": str(observation.lease_id),
        "observed_lease_expires_at": _iso(observation.observed_lease_expires_at),
        "workspace_id": str(qualification.workspace_id),
        "repository_id": str(qualification.repository_id),
        "common_base": {
            "project_id": str(base.project_id), "ref": str(base.ref), "digest": base.digest,
        },
        "destination": {
            "project_id": str(destination.project_id), "ref": str(destination.ref),
        },
        "receipt": {
            "receipt_id": str(receipt.receipt_id),
            "provider_id": str(receipt.provider.provider_id),
            "provider_version": receipt.provider.version,
            "provider_contract_version": receipt.provider.contract_version,
            "correlation_id": str(receipt.correlation_id),
            "request_digest": receipt.request_digest.hex,
            "provenance_ref": str(receipt.provenance_ref),
            "observed_at": _iso(receipt.observed_at),
        },
        "authoring_handoff": handoff_value,
    }


def _check_observation(
    observation: AttemptSafetyObservation | None,
    *,
    target: EntityRef,
    attempt_ref: EntityRef,
    row: sqlite3.Row,
    workspace: WorkspaceQualification,
    now: datetime,
    max_age: timedelta,
) -> AttemptSafetyObservation:
    if not isinstance(observation, AttemptSafetyObservation):
        raise AttemptHostUnavailableError("a fresh host safety observation is required")
    if observation.attempt != attempt_ref or observation.lease_id != StableId(row["lease_id"] or "_missing"):
        raise AttemptLeaseMismatchError("host observation is not bound to the current attempt lease")
    fresh_workspace = observation.workspace
    if (fresh_workspace.workspace_id != workspace.workspace_id
            or fresh_workspace.repository_id != workspace.repository_id
            or fresh_workspace.common_base != workspace.common_base
            or fresh_workspace.destination != workspace.destination
            or fresh_workspace.isolation != workspace.isolation
            or fresh_workspace.receipt.provider != workspace.receipt.provider):
        raise AttemptObservationMismatchError("host observation workspace differs from persisted qualification")
    if observation.observed_state is not AttemptState(row["state"]):
        raise AttemptObservationMismatchError("attempt state changed while the host observation was being collected")
    stored_expiry = None if row["lease_expires_at"] is None else _parse_time(row["lease_expires_at"])
    if stored_expiry is None or _utc(observation.observed_lease_expires_at, "observed lease expiry") != stored_expiry:
        raise AttemptObservationMismatchError("attempt lease expiry changed while the host observation was being collected")
    if row["work_item_id"] != str(target.entity_id) or row["definition_revision_id"] != str(target.definition_revision_id):
        raise AttemptObservationMismatchError("attempt target differs from the qualified request")
    handoff = observation.authoring_handoff
    if handoff is not None and (
        handoff.request.project_id != attempt_ref.project_id
        or handoff.workspace_id != workspace.workspace_id
        or handoff.receipt.provider != workspace.receipt.provider
        or handoff.source_digest != observation.source_digest
    ):
        raise AttemptObservationMismatchError("authoring handoff differs from the exact observed source scope")
    _observation_age(observation, now, max_age)
    return observation


class _ImmutableAttemptCommand:
    """Frozen command payloads retain shared immutable compiled domain values."""

    def __deepcopy__(self, memo):
        return self


@dataclass(frozen=True)
class _Claim(_ImmutableAttemptCommand):
    target: EntityRef
    plan: CompiledPlan
    workspace_id: StableId
    qualification: WorkspaceQualification | None
    correlation_id: StableId
    attempt_id: StableId
    lease_id: StableId
    run: EntityRef | None
    assignment: EntityRef | None


@dataclass(frozen=True)
class _HandbackAuthoring(_ImmutableAttemptCommand):
    target: EntityRef
    attempt_ref: EntityRef
    expected_lease_id: StableId
    run: EntityRef | None
    assignment: EntityRef | None
    request: AttemptAuthoringHandoffRequest
    handoff: AttemptAuthoringHandoff | None
    observation: AttemptSafetyObservation | None


class _HandbackAuthoringHandler:
    kind = "todo.attempt.authoring_handoff"
    command_type = _HandbackAuthoring

    def __init__(self, service: "AttemptService") -> None:
        self.service = service

    def authorization_requirement(self, command: _HandbackAuthoring) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            FINISH_ACTION, command.target, command.run,
            command.assignment, command.attempt_ref,
        )

    def canonical_payload(self, command: _HandbackAuthoring) -> dict[str, object]:
        # Bind the stable user intent, not a provider observation. A retry after
        # a committed handoff must reach the same command receipt even though
        # its fresh host inspection has a new timestamp and receipt ID.
        return {
            "attempt_id": str(command.attempt_ref.entity_id),
            "target": str(command.target.entity_id),
            "definition_revision_id": str(command.target.definition_revision_id),
            "lease_id": str(command.expected_lease_id),
            "workspace_id": str(command.request.workspace_id),
            "request_idempotency_key": str(command.request.idempotency_key),
        }

    def apply(self, context: MutationContext, command: _HandbackAuthoring) -> CommandEffect:
        attempt, row = _stored_attempt(context._connection, context.project, command.attempt_ref)
        if (attempt.work_item != command.target or attempt.actor != context.actor
                or attempt.run != command.run or attempt.assignment != command.assignment):
            raise AttemptOwnershipError("authoring handoff must match the exact owning attempt scope")
        if attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE} or attempt.lease is None:
            raise AttemptTransitionError("authoring handoff requires a live admitted or active attempt")
        if attempt.lease.lease_id != command.expected_lease_id:
            raise AttemptLeaseMismatchError("authoring handoff lease is no longer current")
        now = self.service._now()
        if attempt.lease.expires_at <= now:
            raise AttemptLeaseMismatchError("authoring handoff requires an unexpired lease")
        if (command.request.project_id != context.project.project_id
                or command.request.authority_id != context.project.authority_id
                or command.request.attempt != attempt.ref
                or command.request.lease_id != attempt.lease.lease_id
                or command.request.workspace_id != _stored_workspace(
                    context._connection, context.project, attempt.ref
                ).workspace_id
                or command.handoff is None
                or command.handoff.request != command.request):
            raise AttemptObservationMismatchError("authoring handoff request does not match the stored attempt")
        _require_children_resolved(context._connection, attempt.attempt_id)
        _require_recovery_operations_resolved(context._connection, attempt.attempt_id)
        workspace = _stored_workspace(context._connection, context.project, attempt.ref)
        observation = _check_observation(
            command.observation, target=attempt.work_item, attempt_ref=attempt.ref,
            row=row, workspace=workspace, now=now,
            max_age=self.service.max_observation_age,
        )
        if (observation.source is not SourceSafety.CLEAN
                or observation.children is not ChildActivity.NONE
                or observation.authoring_handoff != command.handoff
                or observation.source_digest != command.handoff.source_digest
                or command.handoff.receipt.provider != workspace.receipt.provider):
            raise AttemptObservationMismatchError(
                "host did not prove a clean, child-free workspace at the exact pinned source"
            )
        proof_time = _utc(command.handoff.receipt.observed_at, "handoff receipt timestamp")
        if proof_time > now:
            raise AttemptObservationMismatchError("authoring handoff receipt is from the future")
        # The host's immutable marker can outlive its initial receipt timestamp.
        # This command has already revalidated that marker through a fresh,
        # bounded safety observation above, so it is the observation that must
        # satisfy max_observation_age rather than the original marker receipt.
        return CommandEffect(
            # Host fencing is an external host effect. The authority records an
            # idempotent command receipt, but no Todo semantic row changes here.
            False,
            {"attempt_id": str(attempt.attempt_id), "state": attempt.state.value,
             "source_commit": str(command.handoff.source_commit),
             "source_digest": command.handoff.source_digest.hex},
        )


@dataclass(frozen=True)
class _Heartbeat(_ImmutableAttemptCommand):
    target: EntityRef
    attempt_ref: EntityRef
    expected_lease_id: StableId
    run: EntityRef | None
    assignment: EntityRef | None
    plan: CompiledPlan
    replacement_lease_id: StableId


@dataclass(frozen=True)
class _Release(_ImmutableAttemptCommand):
    target: EntityRef
    attempt_ref: EntityRef
    expected_lease_id: StableId
    run: EntityRef | None
    assignment: EntityRef | None
    observation: AttemptSafetyObservation | None


@dataclass(frozen=True)
class _ReconcileExpired(_ImmutableAttemptCommand):
    target: EntityRef
    attempt_ref: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    expected_lease_id: StableId | None
    expected_source_digest: Sha256Digest | None
    observation: AttemptSafetyObservation | None
    recovery: bool = False
    preserve_dirty_workspace: bool = False
    recovery_approval: RecoveryApproval | None = None


class _AttemptHandlerBase:
    def __init__(self, service: AttemptService) -> None:
        self.service = service

    def _decision(
        self, context: MutationContext, request: EligibilityRequest, plan: CompiledPlan,
        *, workspace_qualifications: Mapping[EntityRef, WorkspaceQualification],
    ) -> EligibilityDecision:
        return self.service.eligibility.evaluate_in_transaction(
            context.authority, context._connection, request, plan,
            scope_contexts=_plan_contexts(plan), workspace_qualifications=workspace_qualifications,
        )

    @staticmethod
    def _require_allowed(decision: EligibilityDecision) -> None:
        if decision.status is not EligibilityStatus.ALLOWED:
            raise AttemptAdmissionDeniedError(decision)

    @staticmethod
    def _transition(current: AttemptState, target: AttemptState) -> None:
        if target not in ATTEMPT_TRANSITIONS[current]:
            raise AttemptTransitionError(f"attempt cannot transition from {current.value} to {target.value}")

    @staticmethod
    def _event_payload(attempt_ref: EntityRef, state: AttemptState, **values: object) -> dict[str, object]:
        return {
            "attempt_id": str(attempt_ref.entity_id),
            "state": state.value,
            **values,
        }


class _ClaimHandler(_AttemptHandlerBase):
    kind = "todo.attempt.claim"
    command_type = _Claim

    def authorization_requirement(self, command: _Claim) -> AuthorizationRequirement:
        return AuthorizationRequirement(CLAIM_ACTION, command.target, command.run, command.assignment)

    def canonical_payload(self, command: _Claim) -> dict[str, object]:
        return {
            "target": [str(command.target.project_id), str(command.target.entity_id),
                       str(command.target.definition_revision_id)],
            "plan_digest": command.plan.content_digest.hex,
            "workspace_id": str(command.workspace_id),
            "run": None if command.run is None else str(command.run.entity_id),
            "assignment": None if command.assignment is None else str(command.assignment.entity_id),
        }

    @staticmethod
    def _overlapping_peers(
        context: MutationContext,
        project: Project,
        candidate_paths: tuple[tuple[str, str], ...],
        qualifications: Mapping[EntityRef, WorkspaceQualification],
    ) -> tuple[Attempt, ...]:
        snapshots = _load_attempt_scope_snapshots(context._connection, project.project_id)
        peers: list[Attempt] = []
        rows = context._connection.execute("SELECT * FROM attempts ORDER BY attempt_id").fetchall()
        for row in rows:
            attempt = _attempt_from_row(project, row)
            if attempt.state in _TERMINAL_STATES:
                continue
            snapshot = snapshots.get(attempt.ref)
            if snapshot is None or attempt.ref not in qualifications:
                continue
            if any(
                first_access != "forbidden" and second_access != "forbidden"
                and _path_overlaps(first_path, second_path)
                and (first_access == "write" or second_access == "write")
                for first_path, first_access in candidate_paths
                for second_path, second_access in snapshot.paths
            ):
                peers.append(attempt)
        return tuple(peers)

    def apply(self, context: MutationContext, command: _Claim) -> CommandEffect:
        if command.plan.project != context.project or not _target_in_plan(command.plan, command.target):
            raise AttemptAdmissionDeniedError(EligibilityDecision(
                EligibilityStatus.BLOCKED, context.starting_revision,
                (self.service._cause("target_not_in_plan", "claim target is not in the supplied compiled plan", command.target),),
            ))
        now = self.service._now()
        if command.qualification is None:
            raise AttemptHostUnavailableError("a trusted workspace qualification is required for a new claim")
        self.service._validate_qualification(command.qualification, command.workspace_id,
                                             command.target, command.correlation_id,
                                             now, require_fresh=True)
        qualification = command.qualification
        qualifications = _workspace_map(context._connection, context.project)
        qualifications[command.target] = qualification
        target_item = next(item for item in command.plan.work_items if item.definition.ref == command.target)
        raw_scope = _scope_parts(target_item.context)
        if raw_scope is None:
            raise AttemptAdmissionDeniedError(EligibilityDecision(
                EligibilityStatus.UNKNOWN, context.starting_revision,
                (self.service._cause("target_scope_unavailable", "claim scope cannot be safely snapshotted", command.target),),
            ))
        scope_snapshot = AttemptScopeSnapshot(*raw_scope)
        scope_json = _scope_snapshot_payload(scope_snapshot)
        scope_digest = hashlib.sha256(scope_json.encode("utf-8")).hexdigest()
        request = EligibilityRequest(
            command.target, context.actor, CLAIM_ACTION, context.starting_revision,
            command.run, command.assignment,
        )
        # First apply policy against the current authority snapshot. Obvious
        # refusals do not trigger host requalification or mutate authority.
        decision = self._decision(context, request, command.plan,
                                  workspace_qualifications=qualifications)
        self._require_allowed(decision)
        peers = self._overlapping_peers(context, context.project, scope_snapshot.paths, qualifications)
        if peers:
            try:
                qualification = self.service._requalify_binding(
                    command.qualification, command.target, command.correlation_id,
                )
                qualifications[command.target] = qualification
                for peer in peers:
                    original = qualifications[peer.ref]
                    correlation = StableId("peer-workspace-" + hashlib.sha256(
                        f"{command.correlation_id}:{peer.attempt_id}".encode("utf-8")
                    ).hexdigest())
                    qualifications[peer.ref] = self.service._requalify_binding(
                        original, peer.work_item, correlation,
                    )
            except (AttemptHostUnavailableError, AttemptObservationMismatchError) as exc:
                raise AttemptAdmissionDeniedError(EligibilityDecision(
                    EligibilityStatus.UNKNOWN, context.starting_revision,
                    (self.service._cause(
                        "overlapping_workspace_unverified",
                        f"overlapping workspace could not be freshly qualified: {exc}", command.target,
                    ),),
                )) from exc
            decision = self._decision(context, request, command.plan,
                                      workspace_qualifications=qualifications)
            self._require_allowed(decision)
        expires_at = self.service._now() + self.service.lease_duration
        try:
            context.execute(
                "INSERT INTO attempts(attempt_id, work_item_id, definition_revision_id, actor_id, "
                "actor_incarnation_id, state, assignment_id, run_id, lease_id, lease_expires_at) "
                "VALUES (?, ?, ?, ?, ?, 'admitted', ?, ?, ?, ?)",
                (str(command.attempt_id), str(command.target.entity_id),
                 str(command.target.definition_revision_id), str(context.actor.entity_id),
                 str(context.actor.incarnation_id),
                 None if command.assignment is None else str(command.assignment.entity_id),
                 None if command.run is None else str(command.run.entity_id),
                 str(command.lease_id), _iso(expires_at)),
            )
            _insert_workspace(context, command.attempt_id, qualification)
            context.execute(
                "INSERT INTO attempt_scope_snapshots(attempt_id, scope_json, scope_digest) VALUES (?, ?, ?)",
                (str(command.attempt_id), scope_json, scope_digest),
            )
        except sqlite3.IntegrityError as exc:
            raise AttemptAdmissionDeniedError(EligibilityDecision(
                EligibilityStatus.BLOCKED, context.starting_revision,
                (self.service._cause("attempt_claim_conflict", "another writer owns this work-item definition", command.target),),
            )) from exc
        attempt_ref = EntityRef(context.project.project_id, EntityKind.ATTEMPT, command.attempt_id)
        payload = self._event_payload(
            attempt_ref, AttemptState.ADMITTED, work_item_id=str(command.target.entity_id),
            definition_revision_id=str(command.target.definition_revision_id),
            actor_id=str(context.actor.entity_id), actor_incarnation_id=str(context.actor.incarnation_id),
            lease_id=str(command.lease_id), lease_expires_at=_iso(expires_at),
            workspace_id=str(command.workspace_id),
            scope_digest=scope_digest,
        )
        return CommandEffect(
            True,
            {"attempt_id": str(command.attempt_id), "lease_id": str(command.lease_id),
             "state": AttemptState.ADMITTED.value, "lease_expires_at": _iso(expires_at)},
            "todo.attempt.claimed", payload,
        )


class _HeartbeatHandler(_AttemptHandlerBase):
    kind = "todo.attempt.heartbeat"
    command_type = _Heartbeat

    def authorization_requirement(self, command: _Heartbeat) -> AuthorizationRequirement:
        return AuthorizationRequirement(HEARTBEAT_ACTION, command.target, command.run,
                                        command.assignment, command.attempt_ref)

    def canonical_payload(self, command: _Heartbeat) -> dict[str, object]:
        return {"target": str(command.target.entity_id),
                "attempt_id": str(command.attempt_ref.entity_id),
                "expected_lease_id": str(command.expected_lease_id),
                "run": None if command.run is None else str(command.run.entity_id),
                "assignment": None if command.assignment is None else str(command.assignment.entity_id),
                "plan_digest": command.plan.content_digest.hex}

    def apply(self, context: MutationContext, command: _Heartbeat) -> CommandEffect:
        attempt, row = _stored_attempt(context._connection, context.project, command.attempt_ref)
        if command.target != attempt.work_item:
            raise AttemptObservationMismatchError("heartbeat target differs from the stored attempt")
        if command.run != attempt.run or command.assignment != attempt.assignment:
            raise AttemptObservationMismatchError("heartbeat run or assignment differs from the stored attempt")
        if attempt.actor != context.actor:
            raise AttemptOwnershipError("only the owning actor incarnation may renew this attempt")
        if attempt.state not in _LIVE_STATES or attempt.lease is None:
            raise AttemptLeaseMismatchError("only an attempt with a current nonterminal lease can be renewed")
        if attempt.lease.lease_id != command.expected_lease_id:
            raise AttemptLeaseMismatchError("expected lease ID is no longer current")
        now = self.service._now()
        if attempt.lease.expires_at <= now:
            raise AttemptLeaseMismatchError("expired leases require reconciliation before renewal")
        qualifications = _workspace_map(context._connection, context.project)
        request = EligibilityRequest(
            attempt.work_item, context.actor, HEARTBEAT_ACTION, context.starting_revision,
            attempt.run, attempt.assignment, attempt.ref,
        )
        decision = self._decision(context, request, command.plan,
                                  workspace_qualifications=qualifications)
        self._require_allowed(decision)
        expires_at = self.service._now() + self.service.lease_duration
        changed = context.execute(
            "UPDATE attempts SET lease_id = ?, lease_expires_at = ? WHERE attempt_id = ? "
            "AND lease_id = ? AND lease_expires_at = ? AND state = ?",
            (str(command.replacement_lease_id), _iso(expires_at),
             str(command.attempt_ref.entity_id), str(command.expected_lease_id),
             row["lease_expires_at"], attempt.state.value),
        ).rowcount
        if changed != 1:
            raise AttemptLeaseMismatchError("attempt lease changed before renewal")
        renewed_capabilities = self.service.auth._renew_attempt_capability_expiries_in_transaction(
            context,
            attempt_id=attempt.attempt_id,
            expected_scope=attempt.work_item,
            expected_run=attempt.run,
            expected_assignment=attempt.assignment,
            expected_attempt=attempt.ref,
            expected_actions=None,
            expires_at=expires_at,
            now=now,
        )
        renewed_child_capabilities = self.service.auth._renew_child_execution_capability_expiries_in_transaction(
            context,
            attempt_id=attempt.attempt_id,
            expected_scope=attempt.work_item,
            expected_run=attempt.run,
            expected_assignment=attempt.assignment,
            expected_attempt=attempt.ref,
            expires_at=expires_at,
            now=now,
        )
        payload = self._event_payload(
            attempt.ref, attempt.state, previous_lease_id=str(command.expected_lease_id),
            lease_id=str(command.replacement_lease_id), lease_expires_at=_iso(expires_at),
            renewed_attempt_capabilities=renewed_capabilities,
            renewed_child_capabilities=renewed_child_capabilities,
        )
        return CommandEffect(
            True,
            {"attempt_id": str(attempt.attempt_id), "lease_id": str(command.replacement_lease_id),
             "state": attempt.state.value, "lease_expires_at": _iso(expires_at)},
            "todo.attempt.lease_renewed", payload,
        )


class _ReleaseHandler(_AttemptHandlerBase):
    kind = "todo.attempt.release"
    command_type = _Release

    def authorization_requirement(self, command: _Release) -> AuthorizationRequirement:
        return AuthorizationRequirement(RELEASE_ACTION, command.target, command.run,
                                        command.assignment, command.attempt_ref)

    def canonical_payload(self, command: _Release) -> dict[str, object]:
        return {"target": str(command.target.entity_id),
                "attempt_id": str(command.attempt_ref.entity_id),
                "run": None if command.run is None else str(command.run.entity_id),
                "assignment": None if command.assignment is None else str(command.assignment.entity_id),
                "expected_lease_id": str(command.expected_lease_id)}

    def apply(self, context: MutationContext, command: _Release) -> CommandEffect:
        attempt, row = _stored_attempt(context._connection, context.project, command.attempt_ref)
        if command.target != attempt.work_item:
            raise AttemptObservationMismatchError("release target differs from the stored attempt")
        if command.run != attempt.run or command.assignment != attempt.assignment:
            raise AttemptObservationMismatchError("release run or assignment differs from the stored attempt")
        if attempt.actor != context.actor:
            raise AttemptOwnershipError("only the owning actor incarnation may release this attempt")
        if attempt.state is AttemptState.RELEASED:
            return CommandEffect(False, {"attempt_id": str(attempt.attempt_id), "state": attempt.state.value})
        if attempt.state in {AttemptState.ACCEPTED, AttemptState.REJECTED}:
            raise AttemptTransitionError(f"cannot release an attempt already {attempt.state.value}")
        if attempt.lease is None or attempt.lease.lease_id != command.expected_lease_id:
            raise AttemptLeaseMismatchError("expected lease ID is no longer current")
        _require_children_resolved(context._connection, attempt.attempt_id)
        # A resource or command effect can outlive the worker lease. Releasing
        # the attempt while its external operation is unresolved would make
        # the work appear available while the provider may still act on it.
        _require_recovery_operations_resolved(context._connection, attempt.attempt_id)
        workspace = _stored_workspace(context._connection, context.project, attempt.ref)
        observation = _check_observation(
            command.observation, target=attempt.work_item, attempt_ref=attempt.ref, row=row,
            workspace=workspace, now=self.service._now(), max_age=self.service.max_observation_age,
        )
        state = self._safe_disposition(observation)
        self._transition(attempt.state, state)
        lease_id = None if state is AttemptState.RELEASED else row["lease_id"]
        expires_at = None if state is AttemptState.RELEASED else row["lease_expires_at"]
        updated = context.execute(
            "UPDATE attempts SET state = ?, lease_id = ?, lease_expires_at = ? "
            "WHERE attempt_id = ? AND state = ? AND lease_id = ? AND lease_expires_at = ?",
            (state.value, lease_id, expires_at, str(attempt.attempt_id), attempt.state.value,
             row["lease_id"], row["lease_expires_at"]),
        ).rowcount
        if updated != 1:
            raise AttemptLeaseMismatchError("attempt changed while applying the host observation")
        revoked_capabilities = (
            self.service.auth._revoke_attempt_capability_families_in_transaction(
                context, attempt.attempt_id
            )
            if state is AttemptState.RELEASED else 0
        )
        payload = self._event_payload(
            attempt.ref, state, previous_state=attempt.state.value,
            lease_id=lease_id, provider_receipt_id=str(observation.receipt.receipt_id),
            safety_observation=_observation_audit(observation),
            revoked_attempt_capabilities=revoked_capabilities,
        )
        return CommandEffect(
            True, {"attempt_id": str(attempt.attempt_id), "state": state.value},
            "todo.attempt.released" if state is AttemptState.RELEASED else "todo.attempt.quarantined",
            payload,
        )

    @staticmethod
    def _safe_disposition(observation: AttemptSafetyObservation) -> AttemptState:
        if observation.safe_to_release:
            return AttemptState.RELEASED
        if (observation.source is SourceSafety.DIRTY
                or observation.process is ProcessLiveness.LIVE
                or observation.children is ChildActivity.ACTIVE):
            return AttemptState.QUARANTINED
        return AttemptState.UNCERTAIN


class _ReconcileExpiredHandler(_AttemptHandlerBase):
    kind = "todo.attempt.reconcile_expired"
    command_type = _ReconcileExpired

    def authorization_requirement(self, command: _ReconcileExpired) -> AuthorizationRequirement:
        action = RECOVERY_APPLY_ACTION if command.recovery else RECONCILE_ACTION
        return AuthorizationRequirement(action, command.target, command.run,
                                        command.assignment, command.attempt_ref)

    def canonical_payload(self, command: _ReconcileExpired) -> dict[str, object]:
        return {"target": str(command.target.entity_id), "attempt_id": str(command.attempt_ref.entity_id),
                "run": None if command.run is None else str(command.run.entity_id),
                "assignment": None if command.assignment is None else str(command.assignment.entity_id),
                "expected_lease_id": None if command.expected_lease_id is None else str(command.expected_lease_id),
                "expected_source_digest": None if command.expected_source_digest is None
                    else command.expected_source_digest.hex,
                "recovery": command.recovery,
                "preserve_dirty_workspace": command.preserve_dirty_workspace,
                "recovery_approval": None if command.recovery_approval is None else {
                    "kind": command.recovery_approval.intent_kind,
                    "actor": str(command.recovery_approval.actor.entity_id),
                    "actor_incarnation": str(command.recovery_approval.actor.incarnation_id),
                    "capability": str(command.recovery_approval.capability_id),
                    "revision": command.recovery_approval.authority_revision,
                    "lease_expires_at": None if command.recovery_approval.expected_lease_expires_at is None
                        else _iso(command.recovery_approval.expected_lease_expires_at),
                    "digest": _recovery_approval_digest(command.recovery_approval),
                }}

    def apply(self, context: MutationContext, command: _ReconcileExpired) -> CommandEffect:
        attempt, row = _stored_attempt(context._connection, context.project, command.attempt_ref)
        if command.target != attempt.work_item:
            raise AttemptObservationMismatchError("reconciliation target differs from the stored attempt")
        if command.run != attempt.run or command.assignment != attempt.assignment:
            raise AttemptObservationMismatchError("reconciliation run or assignment differs from the stored attempt")
        approval = command.recovery_approval
        if command.recovery:
            if not _is_recovery_approval(approval):
                raise AttemptObservationMismatchError("recovery requires a freshly approved inspection intent")
            if (context.authorized_capability_id != approval.capability_id
                    or context.actor != approval.actor
                    or approval.authority_revision != context.starting_revision
                    or approval.intent_kind not in {"release_expired_attempt", "handoff_dirty_workspace"}
                    or approval.target != attempt.work_item
                    or approval.attempt != attempt.ref
                    or approval.run != attempt.run
                    or approval.assignment != attempt.assignment
                    or approval.operation is not None):
                raise AttemptObservationMismatchError("recovery approval no longer matches the authenticated command")
        if attempt.state in _TERMINAL_STATES:
            if command.recovery:
                raise AttemptTransitionError("terminal attempts cannot be recovered or requeued")
            return CommandEffect(False, {"attempt_id": str(attempt.attempt_id), "state": attempt.state.value})
        if attempt.lease is None:
            raise AttemptLeaseMismatchError("attempt has no lease to reconcile")
        if command.expected_lease_id is not None and attempt.lease.lease_id != command.expected_lease_id:
            raise AttemptLeaseMismatchError("recovery lease identity changed")
        if command.recovery and (
            approval.expected_lease_id != attempt.lease.lease_id
            or approval.expected_lease_expires_at != attempt.lease.expires_at
            or approval.expected_source_digest != command.expected_source_digest
        ):
            raise AttemptLeaseMismatchError("recovery approval lease or source binding changed")
        now = self.service._now()
        if attempt.lease.expires_at > now:
            raise AttemptLeaseMismatchError("attempt lease has not expired")
        _require_children_resolved(context._connection, attempt.attempt_id)
        if command.recovery:
            if attempt.state is AttemptState.REPORTED or context._connection.execute(
                "SELECT 1 FROM outcome_candidates WHERE attempt_id = ? AND state = 'pending' LIMIT 1",
                (str(attempt.attempt_id),),
            ).fetchone() is not None:
                raise AttemptTransitionError("reported work or a pending outcome candidate cannot be released for recovery")
            _require_recovery_operations_resolved(context._connection, attempt.attempt_id)
        workspace = _stored_workspace(context._connection, context.project, attempt.ref)
        observation = _check_observation(
            command.observation, target=attempt.work_item, attempt_ref=attempt.ref, row=row,
            workspace=workspace, now=now, max_age=self.service.max_observation_age,
        )
        if attempt.state is AttemptState.REPORTED:
            pending = context._connection.execute(
                "SELECT report_source_json FROM outcome_candidates "
                "WHERE attempt_id = ? AND state = 'pending' ORDER BY reported_at, candidate_id",
                (str(attempt.attempt_id),),
            ).fetchall()
            handoff = observation.authoring_handoff
            handoff_matches_report = False
            if handoff is not None:
                for candidate in pending:
                    try:
                        reported_source = json.loads(candidate["report_source_json"])
                        reported_digest = reported_source.get("source_digest")
                    except (TypeError, ValueError):
                        continue
                    if (reported_digest == handoff.source_digest.hex
                            and reported_source.get("source_revision") == str(handoff.source_commit)):
                        handoff_matches_report = True
                        break
            if (pending and handoff is not None and handoff.attempt == attempt.ref
                    and handoff.lease_id == attempt.lease.lease_id
                    and handoff.workspace_id == workspace.workspace_id
                    and observation.source is SourceSafety.CLEAN
                    and observation.children is ChildActivity.NONE
                    and handoff_matches_report):
                _require_recovery_operations_resolved(context._connection, attempt.attempt_id)
                # An attempt-scoped authoring fence preserves the reported
                # candidate for independent review after its execution lease
                # expires. It proves neither producer death nor physical
                # quiescence, so leave the REPORTED state and lease untouched.
                return CommandEffect(False, {
                    "attempt_id": str(attempt.attempt_id),
                    "state": AttemptState.REPORTED.value,
                    "authoring_handoff": True,
                })
        if command.recovery:
            approved_observation = approval.host_observation
            if (approved_observation is None
                    or approved_observation.attempt != attempt.ref
                    or approved_observation.lease_id != attempt.lease.lease_id
                    or approved_observation.observed_state is not attempt.state
                    or approved_observation.observed_lease_expires_at != attempt.lease.expires_at
                    or approved_observation.workspace.workspace_id != workspace.workspace_id
                    or approved_observation.source_digest != command.expected_source_digest
                    or observation.source_digest != command.expected_source_digest):
                raise AttemptObservationMismatchError("fresh host proof differs from the approved recovery source")
        handoff = observation.authoring_handoff
        if handoff is not None and (
            handoff.request.project_id != context.project.project_id
            or handoff.request.authority_id != context.project.authority_id
            or handoff.request.attempt != attempt.ref
            or handoff.request.lease_id != attempt.lease.lease_id
            or handoff.request.workspace_id != workspace.workspace_id
            or handoff.source_digest != observation.source_digest
        ):
            raise AttemptObservationMismatchError(
                "authoring handoff does not match the exact authority, attempt, lease, workspace, and source"
            )
        state = _ReleaseHandler._safe_disposition(observation)
        preserved_dirty_workspace = False
        if command.recovery and command.preserve_dirty_workspace:
            if not (observation.source is SourceSafety.DIRTY
                    and observation.process.quiescent
                    and observation.children is ChildActivity.NONE):
                raise AttemptObservationMismatchError(
                    "dirty workspace handoff requires a fresh dirty source and quiescent writer"
                )
            if (command.expected_source_digest is None
                    or observation.source_digest != command.expected_source_digest):
                raise AttemptObservationMismatchError(
                    "dirty workspace source identity changed after recovery inspection"
                )
            if attempt.state is AttemptState.REPORTED:
                raise AttemptTransitionError("reported work cannot be handed off for requeue")
            # Relinquish execution ownership, never source: the exact
            # provider-owned workspace and all of its bytes remain in place.
            state = AttemptState.RELEASED
            preserved_dirty_workspace = True
        elif command.recovery and state is not AttemptState.RELEASED:
            raise AttemptObservationMismatchError(
                "safe recovery release requires a fresh clean source and quiescent writer"
            )
        elif command.recovery and (
            command.expected_source_digest is None
            or observation.source_digest != command.expected_source_digest
        ):
            raise AttemptObservationMismatchError("clean source identity changed after recovery inspection")
        elif state is AttemptState.RELEASED and not command.recovery:
            # Reported attempts are already handed off for acceptance. Their
            # lease expiry cannot erase that boundary; retain an explicit
            # uncertain state until the report is resolved.
            state = AttemptState.UNCERTAIN if attempt.state is AttemptState.REPORTED else AttemptState.EXPIRED
        if state is attempt.state:
            return CommandEffect(False, {"attempt_id": str(attempt.attempt_id), "state": state.value})
        if attempt.state in {AttemptState.UNCERTAIN, AttemptState.QUARANTINED} and state is AttemptState.EXPIRED:
            return CommandEffect(False, {"attempt_id": str(attempt.attempt_id), "state": attempt.state.value})
        self._transition(attempt.state, state)
        updated = context.execute(
            "UPDATE attempts SET state = ?, lease_id = CASE WHEN ? = 'released' THEN NULL ELSE lease_id END, "
            "lease_expires_at = CASE WHEN ? = 'released' THEN NULL ELSE lease_expires_at END "
            "WHERE attempt_id = ? AND state = ? AND lease_id = ? AND lease_expires_at = ?",
            (state.value, state.value, state.value, str(attempt.attempt_id), attempt.state.value,
             row["lease_id"], row["lease_expires_at"]),
        ).rowcount
        if updated != 1:
            raise AttemptObservationMismatchError("attempt changed while reconciling its lease")
        revoked_capabilities = (
            self.service.auth._revoke_attempt_capability_families_in_transaction(context, attempt.attempt_id)
            if state is AttemptState.RELEASED else 0
        )
        payload = self._event_payload(
            attempt.ref, state, previous_state=attempt.state.value,
            lease_id=row["lease_id"], lease_expires_at=row["lease_expires_at"],
            provider_receipt_id=str(observation.receipt.receipt_id),
            safety_observation=_observation_audit(observation),
            recovery=command.recovery,
            workspace_preserved=preserved_dirty_workspace,
            workspace_id=str(workspace.workspace_id) if preserved_dirty_workspace else None,
            previous_lease_id=row["lease_id"],
            recovery_approval_digest=(None if approval is None else _recovery_approval_digest(approval)),
            recovery_intent_digest=(None if approval is None else approval.intent_digest.hex),
            expected_source_digest=None if command.expected_source_digest is None
                else command.expected_source_digest.hex,
            revoked_attempt_capabilities=revoked_capabilities,
        )
        return CommandEffect(
            True, {"attempt_id": str(attempt.attempt_id), "state": state.value,
                   "lease_id": None if state is AttemptState.RELEASED else row["lease_id"],
                   "lease_expires_at": None if state is AttemptState.RELEASED else row["lease_expires_at"],
                   "workspace_preserved": preserved_dirty_workspace,
                   "workspace_id": str(workspace.workspace_id) if preserved_dirty_workspace else None},
            "todo.attempt.recovery_workspace_handoff" if preserved_dirty_workspace else
            "todo.attempt.recovery_released" if command.recovery and state is AttemptState.RELEASED else
            "todo.attempt.expired" if state is AttemptState.EXPIRED else
            "todo.attempt.quarantined" if state is AttemptState.QUARANTINED else "todo.attempt.uncertain",
            payload,
        )


class AttemptService:
    """Authenticated claim and lease operations over one project-local SQLite authority.

    The host provider is the trust source for workspace qualification and safety
    observations. This service records those observations but cannot authenticate
    a host receipt by itself; composition must inject a trusted provider.
    """

    def __init__(
        self,
        auth: AuthorityAuthService,
        *,
        eligibility: EligibilityAdapter | None = None,
        host: AttemptHost,
        clock: Callable[[], datetime] | None = None,
        lease_duration: timedelta = timedelta(minutes=2),
        max_observation_age: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not callable(getattr(host, "qualify_workspace", None)) or not callable(
            getattr(host, "inspect_attempt", None)
        ):
            raise TypeError("host must implement qualify_workspace and inspect_attempt")
        if not isinstance(lease_duration, timedelta) or lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be positive")
        if not isinstance(max_observation_age, timedelta) or max_observation_age <= timedelta(0):
            raise ValueError("max_observation_age must be positive")
        self.auth = auth
        self.eligibility = eligibility or EligibilityAdapter(clock=clock or auth.clock)
        self.host = host
        self.clock = clock or auth.clock
        self.lease_duration = lease_duration
        self.max_observation_age = max_observation_age
        for handler in (
            _ClaimHandler(self), _HandbackAuthoringHandler(self), _HeartbeatHandler(self),
            _ReleaseHandler(self), _ReconcileExpiredHandler(self),
        ):
            self.auth.dispatcher.register(handler)

    def _now(self) -> datetime:
        return _utc(self.clock(), "attempt service clock")

    @staticmethod
    def _cause(code: str, message: str, subject: EntityRef) -> EligibilityCause:
        return EligibilityCause(code, message, subject)

    def _validate_qualification(
        self,
        qualification: WorkspaceQualification,
        workspace_id: StableId,
        target: EntityRef,
        correlation_id: StableId,
        now: datetime,
        *,
        require_fresh: bool,
    ) -> None:
        if not isinstance(qualification, WorkspaceQualification):
            raise AttemptHostUnavailableError("host did not return a workspace qualification")
        receipt = qualification.receipt
        if qualification.workspace_id != workspace_id:
            raise AttemptObservationMismatchError("host qualified a different workspace ID")
        if receipt.correlation_id != correlation_id:
            raise AttemptObservationMismatchError("workspace receipt correlation does not match this claim")
        if receipt.provenance_ref != qualification.common_base.ref:
            raise AttemptObservationMismatchError("workspace receipt does not identify its qualified base")
        if qualification.common_base.project_id != target.project_id:
            raise AttemptObservationMismatchError("workspace common base is not qualified to the target project")
        if qualification.destination.project_id != target.project_id:
            raise AttemptObservationMismatchError("workspace destination is not qualified to the target project")
        if require_fresh:
            observed_at = _utc(receipt.observed_at, "workspace qualification time")
            if observed_at > now or now - observed_at > self.max_observation_age:
                raise AttemptObservationMismatchError("workspace qualification is stale or from the future")

    @staticmethod
    def _workspace_binding(qualification: WorkspaceQualification) -> tuple[object, ...]:
        """Fields fixed when a workspace is first bound to an attempt."""
        return (
            qualification.workspace_id,
            qualification.repository_id,
            qualification.common_base,
            qualification.destination,
            qualification.receipt.provider,
            qualification.isolation,
        )

    def _requalify_binding(
        self,
        original: WorkspaceQualification,
        target: EntityRef,
        correlation_id: StableId,
    ) -> WorkspaceQualification:
        try:
            fresh = self.host.qualify_workspace(original.workspace_id, target, correlation_id)
        except Exception as exc:
            raise AttemptHostUnavailableError(f"workspace requalification failed: {exc}") from exc
        self._validate_qualification(
            fresh, original.workspace_id, target, correlation_id, self._now(), require_fresh=True,
        )
        if self._workspace_binding(fresh) != self._workspace_binding(original):
            raise AttemptObservationMismatchError(
                "fresh workspace qualification differs from its original immutable binding"
            )
        return fresh

    def _prepare_observation(
        self, authority: SQLiteAuthority, attempt_ref: EntityRef, idempotency_key: StableId
    ) -> AttemptSafetyObservation | None:
        # Existing keys still go through authenticated dispatch. Skipping the
        # provider read here allows exact retries after a terminal transition,
        # while auth and digest checking remain inside the dispatcher.
        with authority.read_transaction() as connection:
            replay = connection.execute(
                "SELECT 1 FROM command_idempotency WHERE idempotency_key = ?",
                (str(idempotency_key),),
            ).fetchone() is not None
            if replay:
                return None
            try:
                attempt, _ = _stored_attempt(connection, authority.project, attempt_ref)
                workspace = _stored_workspace(connection, authority.project, attempt_ref)
            except AttemptNotFoundError:
                return None
            if attempt.lease is None:
                return None
        try:
            observation = self.host.inspect_attempt(attempt, workspace)
        except Exception as exc:
            raise AttemptHostUnavailableError(f"host safety inspection failed: {exc}") from exc
        if not isinstance(observation, AttemptSafetyObservation):
            raise AttemptHostUnavailableError("host provider returned no typed safety observation")
        return observation

    @staticmethod
    def _has_idempotency_key(authority: SQLiteAuthority, idempotency_key: StableId) -> bool:
        with authority.read_transaction() as connection:
            return connection.execute(
                "SELECT 1 FROM command_idempotency WHERE idempotency_key = ?",
                (str(idempotency_key),),
            ).fetchone() is not None

    @staticmethod
    def _attempt_for_service(authority: SQLiteAuthority, attempt_ref: EntityRef) -> Attempt | None:
        with authority.read_transaction() as connection:
            try:
                attempt, _ = _stored_attempt(connection, authority.project, attempt_ref)
            except AttemptNotFoundError:
                # Authorization still runs before the handler returns not-found.
                return None
            return attempt

    def handback_authoring(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        attempt_ref: EntityRef,
        expected_lease_id: StableId,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        """Pin and fence one attempt's source while preserving process liveness."""
        if not isinstance(authority, SQLiteAuthority) or authority.readonly:
            raise ReadOnlyAuthorityError("authoring handback requires a writable authority")
        if (not isinstance(attempt_ref, EntityRef) or attempt_ref.kind is not EntityKind.ATTEMPT
                or attempt_ref.project_id != authority.project.project_id):
            raise TypeError("attempt_ref must reference an attempt in this authority")
        if not isinstance(expected_lease_id, StableId) or not isinstance(idempotency_key, StableId):
            raise TypeError("expected_lease_id and idempotency_key must be StableId values")
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision < 0):
            raise ValueError("expected_revision must be a non-negative integer or None")
        if not callable(getattr(self.host, "handoff_authoring", None)):
            raise AttemptHostUnavailableError("trusted host does not support scoped authoring handoff")

        replay = self._has_idempotency_key(authority, idempotency_key)
        bearer_digest = _token_digest(bearer_token)
        actor, _ = self.auth._actor_for_token(authority, bearer_digest)
        replay_revision = expected_revision
        with authority.read_transaction() as connection:
            revision_row = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()
            if revision_row is None:
                raise AttemptObservationMismatchError("authority semantic revision is missing")
            observed_revision = int(revision_row[0])
            if not replay and expected_revision is not None and expected_revision != observed_revision:
                raise StaleAuthorityRevisionError(
                    f"expected semantic revision {expected_revision}, current revision is {observed_revision}"
                )
            if replay and replay_revision is None:
                receipt_row = connection.execute(
                    "SELECT r.command_kind, r.semantic_revision, r.changed FROM command_idempotency AS i "
                    "JOIN command_receipts AS r USING(receipt_id) WHERE i.idempotency_key = ?",
                    (str(idempotency_key),),
                ).fetchone()
                if (receipt_row is not None
                        and receipt_row["command_kind"] == _HandbackAuthoringHandler.kind
                        and not receipt_row["changed"]):
                    # This command is deliberately a semantic no-op. Its
                    # stored receipt revision is therefore the original
                    # expected revision needed by the dispatcher digest.
                    replay_revision = int(receipt_row["semantic_revision"])
            attempt, row = _stored_attempt(connection, authority.project, attempt_ref)
            workspace = _stored_workspace(connection, authority.project, attempt_ref)
            requirement = AuthorizationRequirement(
                FINISH_ACTION, attempt.work_item, attempt.run, attempt.assignment, attempt.ref,
            )
            self.auth._authorize_capability(
                connection, authority.project, bearer_digest, actor, requirement,
            )
            if actor != attempt.actor:
                raise AttemptOwnershipError("only the owning actor incarnation may hand back authoring")
            if not replay:
                if (attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE}
                        or attempt.lease is None or attempt.lease.lease_id != expected_lease_id):
                    raise AttemptLeaseMismatchError("authoring handback requires the exact current attempt lease")
                if attempt.lease.expires_at <= self._now():
                    raise AttemptLeaseMismatchError("authoring handback requires an unexpired attempt lease")
                _require_children_resolved(connection, attempt.attempt_id)
                _require_recovery_operations_resolved(connection, attempt.attempt_id)

        request = AttemptAuthoringHandoffRequest(
            authority.project.project_id, authority.project.authority_id,
            attempt.ref, expected_lease_id, workspace.workspace_id, idempotency_key,
        )
        if replay:
            # The dispatcher authenticates and compares the stable intent digest
            # before it returns the exact durable receipt. Do not resample the
            # host or regenerate volatile proof fields on a committed retry.
            command = _HandbackAuthoring(
                attempt.work_item, attempt.ref, expected_lease_id, attempt.run,
                attempt.assignment, request, None, None,
            )
            return self.auth.execute(
                authority, bearer_token, command, idempotency_key=idempotency_key,
                expected_revision=(observed_revision if replay_revision is None else replay_revision),
            )
        try:
            handoff = self.host.handoff_authoring(request)
        except Exception as exc:
            raise AttemptHostUnavailableError(
                f"trusted host could not pin and fence attempt authoring: {type(exc).__name__}"
            ) from exc
        if not isinstance(handoff, AttemptAuthoringHandoff) or handoff.request != request:
            raise AttemptObservationMismatchError("host returned no matching typed authoring handoff")
        try:
            observation = self.host.inspect_attempt(attempt, workspace)
        except Exception as exc:
            raise AttemptHostUnavailableError(
                f"trusted host could not revalidate the authoring handoff: {type(exc).__name__}"
            ) from exc
        now = self._now()
        observation = _check_observation(
            observation, target=attempt.work_item, attempt_ref=attempt.ref, row=row,
            workspace=workspace, now=now, max_age=self.max_observation_age,
        )
        if (observation.source is not SourceSafety.CLEAN
                or observation.children is not ChildActivity.NONE
                or observation.authoring_handoff != handoff
                or observation.source_digest != handoff.source_digest):
            raise AttemptObservationMismatchError(
                "host did not revalidate a clean, child-free workspace at the pinned source"
            )
        command = _HandbackAuthoring(
            attempt.work_item, attempt.ref, expected_lease_id, attempt.run,
            attempt.assignment, request, handoff, observation,
        )
        return self.auth.execute(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=observed_revision if expected_revision is None else expected_revision,
        )

    def claim(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        target: EntityRef,
        plan: CompiledPlan,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
        workspace_id: StableId,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
    ) -> CommandResult:
        if not isinstance(target, EntityRef) or target.kind is not EntityKind.WORK_ITEM:
            raise TypeError("target must be a qualified work-item reference")
        if not isinstance(workspace_id, StableId):
            raise TypeError("workspace_id must be a StableId")
        if not isinstance(plan, CompiledPlan):
            raise TypeError("plan must be a CompiledPlan")
        if plan.project != authority.project or not _target_in_plan(plan, target):
            raise ValueError("target must be included in a compiled plan for this authority")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        attempt_id = _stable_id("attempt", idempotency_key)
        lease_id = _stable_id("lease", idempotency_key)
        correlation_id = attempt_id
        qualification = None
        if not self._has_idempotency_key(authority, idempotency_key):
            try:
                qualification = self.host.qualify_workspace(workspace_id, target, correlation_id)
            except Exception as exc:
                raise AttemptHostUnavailableError(f"workspace qualification failed: {exc}") from exc
            now = self._now()
            self._validate_qualification(qualification, workspace_id, target,
                                         correlation_id, now, require_fresh=True)
        command = _Claim(
            target, plan, workspace_id, qualification, correlation_id,
            attempt_id, lease_id, run, assignment,
        )
        return self.auth.execute(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision,
        )

    def heartbeat(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        attempt_ref: EntityRef,
        expected_lease_id: StableId,
        plan: CompiledPlan,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        if not isinstance(expected_lease_id, StableId):
            raise TypeError("expected_lease_id must be a StableId")
        if not isinstance(plan, CompiledPlan) or plan.project != authority.project:
            raise ValueError("plan must be a compiled plan for this authority")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        attempt = self._attempt_for_service(authority, attempt_ref)
        target = attempt.work_item if attempt is not None else attempt_ref
        command = _Heartbeat(
            target, attempt_ref, expected_lease_id,
            None if attempt is None else attempt.run,
            None if attempt is None else attempt.assignment,
            plan,
            _stable_id("lease", idempotency_key),
        )
        return self.auth.execute(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision,
        )

    def release(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        attempt_ref: EntityRef,
        expected_lease_id: StableId,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        if not isinstance(expected_lease_id, StableId):
            raise TypeError("expected_lease_id must be a StableId")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        attempt = self._attempt_for_service(authority, attempt_ref)
        target = attempt.work_item if attempt is not None else attempt_ref
        observation = self._prepare_observation(authority, attempt_ref, idempotency_key)
        return self.auth.execute(
            authority, bearer_token, _Release(
                target, attempt_ref, expected_lease_id,
                None if attempt is None else attempt.run,
                None if attempt is None else attempt.assignment,
                observation,
            ),
            idempotency_key=idempotency_key, expected_revision=expected_revision,
        )

    def reconcile_expired(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        attempt_ref: EntityRef,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
        _recovery: bool = False,
        _preserve_dirty_workspace: bool = False,
        expected_lease_id: StableId | None = None,
        expected_source_digest: Sha256Digest | None = None,
        _recovery_approval: RecoveryApproval | None = None,
    ) -> CommandResult:
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        if type(_recovery) is not bool or type(_preserve_dirty_workspace) is not bool:
            raise TypeError("recovery mode flags must be booleans")
        if _preserve_dirty_workspace and not _recovery:
            raise ValueError("dirty workspace handoff is available only through authorized recovery")
        attempt = self._attempt_for_service(authority, attempt_ref)
        if expected_lease_id is not None and not isinstance(expected_lease_id, StableId):
            raise TypeError("expected_lease_id must be a StableId")
        if _recovery and expected_lease_id is None:
            raise AttemptLeaseMismatchError("recovery requires the exact previously inspected lease ID")
        if expected_source_digest is not None and not isinstance(expected_source_digest, Sha256Digest):
            raise TypeError("expected_source_digest must be a Sha256Digest")
        if _preserve_dirty_workspace and expected_source_digest is None:
            raise AttemptObservationMismatchError("dirty workspace handoff requires a source digest")
        if _recovery and not _is_recovery_approval(_recovery_approval):
            raise AttemptObservationMismatchError("recovery requires an approved recovery intent")
        if not _recovery and _recovery_approval is not None:
            raise TypeError("recovery approval is only valid for recovery reconciliation")
        selected_lease_id = expected_lease_id if _recovery else (
            None if attempt is None or attempt.lease is None else attempt.lease.lease_id
        )
        target = attempt.work_item if attempt is not None else attempt_ref
        observation = self._prepare_observation(authority, attempt_ref, idempotency_key)
        return self.auth.execute(
            authority, bearer_token, _ReconcileExpired(
                target, attempt_ref,
                None if attempt is None else attempt.run,
                None if attempt is None else attempt.assignment,
                selected_lease_id,
                expected_source_digest,
                observation,
                _recovery,
                _preserve_dirty_workspace,
                _recovery_approval,
            ),
            idempotency_key=idempotency_key, expected_revision=expected_revision,
        )


__all__ = [
    "AttemptAdmissionDeniedError",
    "AttemptError",
    "AttemptHost",
    "AttemptHostUnavailableError",
    "AttemptLeaseMismatchError",
    "AttemptNotFoundError",
    "AttemptObservationMismatchError",
    "AttemptOwnershipError",
    "AttemptService",
    "AttemptTransitionError",
    "CLAIM_ACTION",
    "HEARTBEAT_ACTION",
    "RECONCILE_ACTION",
    "RELEASE_ACTION",
]
