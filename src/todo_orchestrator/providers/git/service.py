"""Authenticated intent, execution, and recovery for local Git effects.

SQLite records the immutable authorized request before Git is called. Git is
always invoked outside the authority transaction; a restart inspects the
provider journal and never blindly repeats an effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import sqlite3
from typing import Callable, Mapping

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    RECOVERY_APPLY_ACTION,
    _token_digest,
)
from todo_orchestrator.authority.recovery_approval import (
    RecoveryApproval,
    _is_recovery_approval,
    _recovery_approval_digest,
)
from todo_orchestrator.authority.commands import (
    DuplicateCommandHandlerError,
    IdempotencyConflictError,
    MutationContext,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.authority.sqlite import (
    AuthorityError,
    InvalidAuthorityError,
    SQLiteAuthority,
    load_plan_revision_snapshot,
)
from todo_orchestrator.authority.attempts import (
    _stored_attempt,
    _stored_workspace,
)
from todo_orchestrator.contracts import (
    ArtifactAvailability,
    ArtifactExpectation,
    AttemptState,
    EntityKind,
    EntityRef,
    EvidenceInput,
    EffectInspectionRequest,
    GitEffectDisposition,
    GitEffectObservation,
    GitEffectRequest,
    GitOperationKind,
    OutcomeDisposition,
    ProviderCallContext,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Project,
    Sha256Digest,
    SourceObservation,
    SourceObservationRequest,
    StableId,
    provider_request_digest,
)
from todo_orchestrator.model import (
    CommandEffect, CommandResult, QualifiedDestination, QualifiedSourceRevision, WorkspaceIsolation,
    WorkspaceQualification,
)

from .provider import GitProviderError, GitRepositoryProvider


CREATE_WORKSPACE_ACTION = StableId("todo.git.workspace.create")
INTEGRATE_ACTION = StableId("todo.git.integrate")
READ_ACTION = StableId("todo.git.operation.read")
RECONCILE_ACTION = StableId("todo.git.operation.reconcile")
_PREPARE_KIND = "todo.git.effect.prepare"
_TRANSITION_KIND = "todo.git.effect.transition"
_INTENT_FORMAT = "todo-orchestrator.git-effect-intent"
_INTENT_VERSION = 1
_UNSPECIFIED = object()


class GitEffectError(AuthorityError):
    """Base class for authenticated Git-effect service failures."""


class GitEffectDeniedError(GitEffectError):
    """Current authorization, accepted state, or source policy denies an effect."""


class GitEffectNotFoundError(GitEffectError):
    """No durable Git operation has the requested identity."""


class GitEffectStateError(GitEffectError):
    """A Git operation is in a state that does not permit the requested step."""


class GitEffectObservationMismatchError(GitEffectError):
    """A provider receipt or observation does not bind the immutable intent."""


class GitEffectProviderUnavailableError(GitEffectError):
    """A trusted Git effect or inspection could not be established."""


class GitEffectState(str, Enum):
    PREPARED = "prepared"
    EXECUTING = "executing"
    APPLIED = "applied"
    CONFLICT = "conflict"
    DIRTY = "dirty"
    REJECTED = "rejected"
    NOT_APPLIED = "not_applied"
    UNKNOWN = "unknown"
    FINALIZED = "finalized"


@dataclass(frozen=True)
class GitEffectOperationView:
    operation_id: StableId
    state: GitEffectState
    request: GitEffectRequest
    request_digest: Sha256Digest
    observation: GitEffectObservation | None
    provider_receipt: ProviderReceipt | None
    qualification: WorkspaceQualification | None = None
    reason_code: StableId | None = None
    source_observation: SourceObservation | None = None
    accepted_source_receipt: ProviderReceipt | None = None
    inspection_receipt: ProviderReceipt | None = None


@dataclass(frozen=True)
class _Prepare:
    intent_json: str
    request_digest: str
    created_at: str


@dataclass(frozen=True)
class _Transition:
    operation_id: StableId
    intent_json: str
    expected_state: str
    next_state: str
    observation_json: str | None
    provider_receipt_json: str | None
    updated_at: str
    recovery_approval: RecoveryApproval | None = None


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _now(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Git effect clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _digest(encoded: str) -> str:
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _id(prefix: str, material: str) -> StableId:
    return StableId(prefix + "-" + hashlib.sha256(material.encode("utf-8")).hexdigest())


def _ref_value(value: EntityRef | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "project_id": str(value.project_id), "kind": value.kind.value, "entity_id": str(value.entity_id),
        "definition_revision_id": None if value.definition_revision_id is None else str(value.definition_revision_id),
        "incarnation_id": None if value.incarnation_id is None else str(value.incarnation_id),
    }


def _ref_from(value: object) -> EntityRef | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "project_id", "kind", "entity_id", "definition_revision_id", "incarnation_id",
    }:
        raise ValueError("stored Git operation reference has an invalid shape")
    return EntityRef(
        StableId(value["project_id"]), EntityKind(value["kind"]), StableId(value["entity_id"]),
        None if value["definition_revision_id"] is None else StableId(value["definition_revision_id"]),
        None if value["incarnation_id"] is None else StableId(value["incarnation_id"]),
    )


def _request_value(request: GitEffectRequest) -> dict[str, object]:
    return {
        "context": {
            "project_id": str(request.context.project_id), "actor": _ref_value(request.context.actor),
            "capability": _ref_value(request.context.capability),
            "trusted_context_id": str(request.context.trusted_context_id),
            "scope_id": str(request.context.scope_id),
        },
        "operation_id": str(request.operation_id), "idempotency_key": str(request.idempotency_key),
        "operation": request.operation.value, "expected_source": request.expected_source.hex,
        "expected_authority_revision": request.expected_authority_revision,
        "workspace_id": None if request.workspace_id is None else str(request.workspace_id),
        "base_ref": None if request.base_ref is None else str(request.base_ref),
        "source_commit": None if request.source_commit is None else str(request.source_commit),
        "destination_ref": None if request.destination_ref is None else str(request.destination_ref),
        "expected_destination": None if request.expected_destination is None else str(request.expected_destination),
        "target": _ref_value(request.target), "attempt": _ref_value(request.attempt),
        "run": _ref_value(request.run), "assignment": _ref_value(request.assignment),
        "requested_at": None if request.requested_at is None else _iso(request.requested_at),
        "accepted_outcome_id": None if request.accepted_outcome_id is None else str(request.accepted_outcome_id),
        "accepted_candidate_id": None if request.accepted_candidate_id is None else str(request.accepted_candidate_id),
        "accepted_provenance_digest": None if request.accepted_provenance_digest is None else request.accepted_provenance_digest.hex,
        "accepted_source_digest": None if request.accepted_source_digest is None else request.accepted_source_digest.hex,
        "accepted_source_receipt_id": None if request.accepted_source_receipt_id is None else str(request.accepted_source_receipt_id),
    }


def _request_from(value: object) -> GitEffectRequest:
    if not isinstance(value, dict) or set(value) != {
        "context", "operation_id", "idempotency_key", "operation", "expected_source",
        "expected_authority_revision", "workspace_id", "base_ref", "source_commit", "destination_ref",
        "expected_destination", "target", "attempt", "run", "assignment", "requested_at",
        "accepted_outcome_id", "accepted_candidate_id", "accepted_provenance_digest",
        "accepted_source_digest", "accepted_source_receipt_id",
    }:
        raise ValueError("stored Git effect request has an invalid shape")
    context = value["context"]
    if not isinstance(context, dict) or set(context) != {
        "project_id", "actor", "capability", "trusted_context_id", "scope_id",
    }:
        raise ValueError("stored Git provider context has an invalid shape")
    actor = _ref_from(context["actor"])
    capability = _ref_from(context["capability"])
    if actor is None or capability is None:
        raise ValueError("stored Git provider context is incomplete")
    return GitEffectRequest(
        ProviderCallContext(
            StableId(context["project_id"]), actor, capability,
            StableId(context["trusted_context_id"]), StableId(context["scope_id"]),
        ),
        StableId(value["operation_id"]), StableId(value["idempotency_key"]),
        GitOperationKind(value["operation"]), Sha256Digest(value["expected_source"]),
        value["expected_authority_revision"],
        None if value["workspace_id"] is None else StableId(value["workspace_id"]),
        None if value["base_ref"] is None else StableId(value["base_ref"]),
        None if value["source_commit"] is None else StableId(value["source_commit"]),
        None if value["destination_ref"] is None else StableId(value["destination_ref"]),
        None if value["expected_destination"] is None else StableId(value["expected_destination"]),
        _ref_from(value["target"]), _ref_from(value["attempt"]), _ref_from(value["run"]),
        _ref_from(value["assignment"]),
        None if value["requested_at"] is None else datetime.fromisoformat(value["requested_at"]),
        None if value["accepted_outcome_id"] is None else StableId(value["accepted_outcome_id"]),
        None if value["accepted_candidate_id"] is None else StableId(value["accepted_candidate_id"]),
        None if value["accepted_provenance_digest"] is None else Sha256Digest(value["accepted_provenance_digest"]),
        None if value["accepted_source_digest"] is None else Sha256Digest(value["accepted_source_digest"]),
        None if value["accepted_source_receipt_id"] is None else StableId(value["accepted_source_receipt_id"]),
    )


def _receipt_value(receipt: ProviderReceipt | None) -> dict[str, object] | None:
    if receipt is None:
        return None
    return {
        "receipt_id": str(receipt.receipt_id),
        "provider": {"provider_id": str(receipt.provider.provider_id), "version": receipt.provider.version,
                     "contract_version": receipt.provider.contract_version},
        "correlation_id": str(receipt.correlation_id), "request_digest": receipt.request_digest.hex,
        "provenance_ref": str(receipt.provenance_ref), "observed_at": _iso(receipt.observed_at),
    }


def _receipt_from(value: object) -> ProviderReceipt | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "receipt_id", "provider", "correlation_id", "request_digest", "provenance_ref", "observed_at",
    }:
        raise ValueError("stored Git provider receipt has an invalid shape")
    provider = value["provider"]
    if not isinstance(provider, dict) or set(provider) != {"provider_id", "version", "contract_version"}:
        raise ValueError("stored Git provider identity has an invalid shape")
    return ProviderReceipt(
        StableId(value["receipt_id"]),
        ProviderIdentity(StableId(provider["provider_id"]), provider["version"], provider["contract_version"]),
        StableId(value["correlation_id"]), Sha256Digest(value["request_digest"]),
        StableId(value["provenance_ref"]), datetime.fromisoformat(value["observed_at"]),
    )


def _inspection_value(request: EffectInspectionRequest | None) -> dict[str, object] | None:
    if request is None:
        return None
    context = request.context
    return {
        "context": {
            "project_id": str(context.project_id), "actor": _ref_value(context.actor),
            "capability": _ref_value(context.capability),
            "trusted_context_id": str(context.trusted_context_id), "scope_id": str(context.scope_id),
        },
        "operation_id": str(request.operation_id), "idempotency_key": str(request.idempotency_key),
        "original_request_digest": request.original_request_digest.hex,
        "correlation_id": str(request.correlation_id),
    }


def _inspection_from(value: object, original: GitEffectRequest) -> EffectInspectionRequest:
    if not isinstance(value, dict) or set(value) != {
        "context", "operation_id", "idempotency_key", "original_request_digest", "correlation_id",
    }:
        raise ValueError("stored Git inspection request has an invalid shape")
    context = value["context"]
    if not isinstance(context, dict) or set(context) != {
        "project_id", "actor", "capability", "trusted_context_id", "scope_id",
    }:
        raise ValueError("stored Git inspection context has an invalid shape")
    actor = _ref_from(context["actor"])
    capability = _ref_from(context["capability"])
    if actor is None or capability is None:
        raise ValueError("stored Git inspection context is incomplete")
    query = EffectInspectionRequest(
        ProviderCallContext(
            StableId(context["project_id"]), actor, capability,
            StableId(context["trusted_context_id"]), StableId(context["scope_id"]),
        ),
        StableId(value["operation_id"]), StableId(value["idempotency_key"]),
        Sha256Digest(value["original_request_digest"]), StableId(value["correlation_id"]), original,
    )
    return query


def _observation_value(value: GitEffectObservation | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "operation_id": str(value.operation_id), "disposition": value.disposition.value,
        "resulting_source": None if value.resulting_source is None else value.resulting_source.hex,
        "conflict_refs": [str(item) for item in value.conflict_refs],
        "external_ref": None if value.external_ref is None else str(value.external_ref),
        "conflict_tree": None if value.conflict_tree is None else str(value.conflict_tree),
    }


def _observation_from(value: object) -> GitEffectObservation | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "operation_id", "disposition", "resulting_source", "conflict_refs", "external_ref", "conflict_tree",
    }:
        raise ValueError("stored Git effect observation has an invalid shape")
    return GitEffectObservation(
        StableId(value["operation_id"]), GitEffectDisposition(value["disposition"]),
        None if value["resulting_source"] is None else Sha256Digest(value["resulting_source"]),
        tuple(StableId(item) for item in value["conflict_refs"]),
        None if value["external_ref"] is None else StableId(value["external_ref"]),
        None if value["conflict_tree"] is None else StableId(value["conflict_tree"]),
    )


def _workspace_value(value: WorkspaceQualification | None) -> dict[str, object] | None:
    if value is None:
        return None
    isolation = value.isolation
    return {
        "workspace_id": str(value.workspace_id), "repository_id": str(value.repository_id),
        "common_base": {"project_id": str(value.common_base.project_id), "repository_id": str(value.common_base.repository_id),
                        "ref": str(value.common_base.ref), "digest": value.common_base.digest},
        "destination": {"project_id": str(value.destination.project_id), "repository_id": str(value.destination.repository_id),
                        "ref": str(value.destination.ref)},
        "receipt": _receipt_value(value.receipt),
        "isolation": None if isolation is None else {
            "repository_storage": isolation.repository_storage.hex, "workspace_root": isolation.workspace_root.hex,
            "index_file": isolation.index_file.hex, "head_ref": str(isolation.head_ref),
            "worktree_admin": None if isolation.worktree_admin is None else isolation.worktree_admin.hex,
        },
    }


def _workspace_from(value: object) -> WorkspaceQualification | None:
    if value is None:
        return None
    from todo_orchestrator.model import QualifiedDestination, QualifiedSourceRevision, WorkspaceIsolation

    if not isinstance(value, dict) or set(value) != {
        "workspace_id", "repository_id", "common_base", "destination", "receipt", "isolation",
    }:
        raise ValueError("stored workspace qualification has an invalid shape")
    base, dest = value["common_base"], value["destination"]
    if not isinstance(base, dict) or not isinstance(dest, dict):
        raise ValueError("stored workspace qualification is malformed")
    receipt = _receipt_from(value["receipt"])
    if receipt is None:
        raise ValueError("stored workspace qualification has no receipt")
    isolation_value = value["isolation"]
    isolation = None
    if isolation_value is not None:
        if not isinstance(isolation_value, dict) or set(isolation_value) != {
            "repository_storage", "workspace_root", "index_file", "head_ref", "worktree_admin",
        }:
            raise ValueError("stored workspace isolation has an invalid shape")
        isolation = WorkspaceIsolation(
            Sha256Digest(isolation_value["repository_storage"]), Sha256Digest(isolation_value["workspace_root"]),
            Sha256Digest(isolation_value["index_file"]), StableId(isolation_value["head_ref"]),
            None if isolation_value["worktree_admin"] is None else Sha256Digest(isolation_value["worktree_admin"]),
        )
    return WorkspaceQualification(
        StableId(value["workspace_id"]), StableId(value["repository_id"]),
        QualifiedSourceRevision(StableId(base["project_id"]), StableId(base["repository_id"]),
                                StableId(base["ref"]), base["digest"]),
        QualifiedDestination(StableId(dest["project_id"]), StableId(dest["repository_id"]), StableId(dest["ref"])),
        receipt, isolation,
    )


def _source_value(value: SourceObservation | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "repository_id": str(value.repository_id), "source_digest": value.source_digest.hex,
        "base_digest": None if value.base_digest is None else value.base_digest.hex,
        "source_revision": None if value.source_revision is None else str(value.source_revision),
        "working_tree": value.working_tree.value,
        "inputs": [{"name": str(item.name), "digest": item.digest.hex} for item in value.inputs],
        "artifacts": [{"artifact_id": str(item.artifact_id), "available": item.available,
                       "content_digest": None if item.content_digest is None else item.content_digest.hex}
                      for item in value.artifacts],
    }


def _intent(request: GitEffectRequest, *, source: SourceObservation | None = None,
            source_receipt: ProviderReceipt | None = None) -> dict[str, object]:
    return {
        "format": _INTENT_FORMAT, "schema_version": _INTENT_VERSION,
        "request": _request_value(request), "request_digest": provider_request_digest(request).hex,
        "source_observation": _source_value(source), "source_receipt": _receipt_value(source_receipt),
    }


def _intent_json(value: Mapping[str, object]) -> str:
    return _json(dict(value))


def _intent_from(encoded: str) -> tuple[GitEffectRequest, dict[str, object]]:
    value = json.loads(encoded)
    if not isinstance(value, dict) or set(value) != {
        "format", "schema_version", "request", "request_digest", "source_observation", "source_receipt",
    } or value["format"] != _INTENT_FORMAT or value["schema_version"] != _INTENT_VERSION:
        raise ValueError("stored Git effect intent has an unsupported format")
    request = _request_from(value["request"])
    if value["request_digest"] != provider_request_digest(request).hex:
        raise ValueError("stored Git effect request digest does not match its typed request")
    if _json(value) != encoded:
        raise ValueError("stored Git effect intent is not canonical JSON")
    return request, value


def _action(request: GitEffectRequest) -> StableId:
    if request.operation is GitOperationKind.CREATE_WORKSPACE:
        return CREATE_WORKSPACE_ACTION
    if request.operation is GitOperationKind.INTEGRATE:
        return INTEGRATE_ACTION
    raise GitEffectDeniedError("this service only supports workspace creation and accepted integration")


def _requirement(request: GitEffectRequest) -> AuthorizationRequirement:
    if request.target is None:
        raise GitEffectDeniedError("Git effect has no exact work-item target")
    return AuthorizationRequirement(_action(request), request.target, request.run, request.assignment, request.attempt)


def _plan_revision(connection: sqlite3.Connection, request: GitEffectRequest) -> StableId:
    if request.run is not None:
        row = connection.execute("SELECT plan_revision_id FROM run_schedules WHERE run_id = ?",
                                 (str(request.run.entity_id),)).fetchone()
        if row is None:
            raise GitEffectDeniedError("Git effect run has no persisted schedule")
        return StableId(row[0])
    row = connection.execute(
        "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1",
    ).fetchone()
    if row is None:
        raise GitEffectDeniedError("authority has no accepted plan")
    return StableId(row[0])


def _validate_target_membership(connection: sqlite3.Connection, project: Project,
                                request: GitEffectRequest) -> None:
    if request.target is None or request.target.project_id != project.project_id:
        raise GitEffectDeniedError("Git effect target is outside this project")
    revision = _plan_revision(connection, request)
    record = load_plan_revision_snapshot(connection, project, revision)
    if not any(item.work_item_id == request.target.entity_id
               and item.definition_revision_id == request.target.definition_revision_id for item in record.work_items):
        raise GitEffectDeniedError("exact Git effect target is absent from its accepted plan")
    if request.assignment is not None:
        row = connection.execute(
            "SELECT work_item_id, definition_revision_id, run_id FROM assignments WHERE assignment_id = ?",
            (str(request.assignment.entity_id),),
        ).fetchone()
        if (row is None or row["work_item_id"] != str(request.target.entity_id)
                or row["definition_revision_id"] != str(request.target.definition_revision_id)
                or request.run is None or row["run_id"] != str(request.run.entity_id)):
            raise GitEffectDeniedError("Git effect assignment does not match its exact target and run")


def _accepted_identity(connection: sqlite3.Connection, project: Project, request: GitEffectRequest,
                       source_identity: ProviderIdentity) -> tuple[dict[str, object], dict[str, object], str]:
    if (request.operation is not GitOperationKind.INTEGRATE or request.attempt is None or request.target is None
            or request.accepted_outcome_id is None or request.accepted_candidate_id is None
            or request.accepted_provenance_digest is None or request.accepted_source_digest is None
            or request.accepted_source_receipt_id is None or request.source_commit is None):
        raise GitEffectDeniedError("integration request lacks complete accepted-source identity")
    attempt, attempt_row = _stored_attempt(connection, project, request.attempt)
    if (attempt.state is not AttemptState.ACCEPTED or attempt.work_item != request.target
            or attempt.run != request.run or attempt.assignment != request.assignment
            or attempt_row["lease_id"] is not None):
        raise GitEffectDeniedError("integration requires the exact accepted, terminal attempt")
    _validate_target_membership(connection, project, request)
    row = connection.execute(
        "SELECT o.outcome_id, o.disposition, o.version, o.attempt_id, c.candidate_id, c.state, c.outcome_id AS candidate_outcome_id, "
        "c.report_source_json, p.canonical_json, p.content_digest FROM outcomes AS o "
        "JOIN outcome_provenance AS p USING(outcome_id) JOIN outcome_candidates AS c USING(outcome_id) "
        "WHERE o.outcome_id = ? AND o.attempt_id = ? AND o.work_item_id = ? AND o.definition_revision_id = ?",
        (str(request.accepted_outcome_id), str(request.attempt.entity_id),
         str(request.target.entity_id), str(request.target.definition_revision_id)),
    ).fetchone()
    if (row is None or row["candidate_id"] != str(request.accepted_candidate_id)
            or row["candidate_outcome_id"] != str(request.accepted_outcome_id) or row["state"] != "accepted"):
        raise GitEffectDeniedError("requested outcome is not the accepted candidate for this attempt")
    provenance_json = row["canonical_json"]
    if (_digest(provenance_json) != row["content_digest"]
            or row["content_digest"] != request.accepted_provenance_digest.hex):
        raise GitEffectDeniedError("accepted outcome provenance digest changed")
    try:
        provenance = json.loads(provenance_json)
        candidate_source = json.loads(row["report_source_json"])
        source = provenance["source"]
        source_receipt = provenance["source_receipt"]
        stored_outcome = provenance["outcome"]
        if (provenance.get("candidate_id") != row["candidate_id"]
                or provenance.get("attempt") != _ref_value(request.attempt)
                or provenance.get("work_item") != _ref_value(request.target)
                or stored_outcome.get("outcome_id") != row["outcome_id"]
                or candidate_source != source
                or source.get("source_revision") != str(request.source_commit)
                or source.get("source_digest") != request.accepted_source_digest.hex
                or request.expected_source != request.accepted_source_digest
                or source.get("working_tree") != "clean"
                or source_receipt.get("receipt_id") != str(request.accepted_source_receipt_id)
                or source_receipt.get("provider") != {
                    "provider_id": str(source_identity.provider_id), "version": source_identity.version,
                    "contract_version": source_identity.contract_version,
                }):
            raise ValueError("accepted candidate source does not match the immutable Git request")
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise GitEffectDeniedError(f"accepted outcome has no exact clean Git source identity: {exc}") from exc
    return provenance, source_receipt, row["content_digest"]


def _accepted_artifacts(provenance: Mapping[str, object]) -> tuple[ArtifactExpectation, ...]:
    values = provenance.get("artifacts")
    if not isinstance(values, list):
        raise GitEffectDeniedError("accepted outcome artifact identity is malformed")
    artifacts: list[ArtifactExpectation] = []
    for item in values:
        if not isinstance(item, dict) or not {"artifact_id", "content_digest"} <= set(item):
            raise GitEffectDeniedError("accepted outcome contains an artifact without an exact digest")
        try:
            artifacts.append(ArtifactExpectation(
                StableId(item["artifact_id"]), Sha256Digest(item["content_digest"]),
            ))
        except (TypeError, ValueError) as exc:
            raise GitEffectDeniedError("accepted outcome contains an invalid artifact identity") from exc
    return tuple(artifacts)


def _accepted_source_request(request: GitEffectRequest, provenance: Mapping[str, object],
                             correlation: StableId) -> SourceObservationRequest:
    if request.attempt is None or request.target is None or request.workspace_id is None:
        raise GitEffectDeniedError("accepted source observation requires the exact attempt workspace")
    if request.accepted_source_digest is None:
        raise GitEffectDeniedError("accepted source observation has no source digest")
    return SourceObservationRequest(
        request.context, correlation, request.accepted_source_digest, request.attempt,
        request.workspace_id, request.target, None, _accepted_artifacts(provenance),
    )


def _validate_persisted_source_intent(intent: Mapping[str, object], request: GitEffectRequest,
                                      provenance: Mapping[str, object], source_identity: ProviderIdentity,
                                      now: datetime, max_age: timedelta) -> None:
    source = intent.get("source_observation")
    receipt_value = intent.get("source_receipt")
    expected_source = provenance.get("source")
    if not isinstance(source, dict) or not isinstance(receipt_value, dict) or source != expected_source:
        raise GitEffectDeniedError("Git integration intent lacks its exact accepted source observation")
    try:
        receipt = _receipt_from(receipt_value)
        correlation = _id("gsrc", str(request.operation_id))
        source_request = _accepted_source_request(request, provenance, correlation)
        if (receipt is None or receipt.provider != source_identity or receipt.correlation_id != correlation
                or receipt.request_digest != provider_request_digest(source_request)
                or receipt.provenance_ref != request.workspace_id):
            raise ValueError("source receipt does not bind the accepted attempt workspace")
        observed_at = receipt.observed_at.astimezone(timezone.utc)
        requested_at = request.requested_at.astimezone(timezone.utc) if request.requested_at is not None else None
        if observed_at > now or now - observed_at > max_age or (requested_at is not None and observed_at < requested_at):
            raise ValueError("source receipt is stale or outside the operation interval")
    except (KeyError, TypeError, ValueError) as exc:
        raise GitEffectObservationMismatchError(f"Git integration source receipt is invalid: {exc}") from exc


def _validate_assignment_and_run(connection: sqlite3.Connection, request: GitEffectRequest) -> None:
    _validate_run_assignment(connection, request.target, request.run, request.assignment)


def _validate_run_assignment(connection: sqlite3.Connection, target: EntityRef | None,
                             run: EntityRef | None, assignment: EntityRef | None) -> None:
    if assignment is None:
        if run is not None:
            raise GitEffectDeniedError("run-bound Git effects must identify their exact assignment")
        return
    row = connection.execute(
        "SELECT run_id, work_item_id, definition_revision_id FROM assignments WHERE assignment_id = ?",
        (str(assignment.entity_id),),
    ).fetchone()
    if (row is None or run is None or row["run_id"] != str(run.entity_id)
            or target is None or row["work_item_id"] != str(target.entity_id)
            or row["definition_revision_id"] != str(target.definition_revision_id)):
        raise GitEffectDeniedError("run, assignment, and work-item selectors do not agree")


def _view_from_row(row: sqlite3.Row) -> GitEffectOperationView:
    try:
        request, intent_value = _intent_from(row["request_json"])
        if provider_request_digest(request).hex != row["request_digest"]:
            raise ValueError("provider digest column differs from stored request")
        observation_payload = None if row["observation_json"] is None else json.loads(row["observation_json"])
        if observation_payload is not None and _json(observation_payload) != row["observation_json"]:
            raise ValueError("stored observation envelope is not canonical")
        if observation_payload is None:
            observation = None
            qualification = None
            source_observation = None
            reason = None
        else:
            observation = _observation_from(observation_payload.get("observation"))
            qualification = _workspace_from(observation_payload.get("qualification"))
            source_value = observation_payload.get("source_after") or intent_value.get("source_observation")
            source_observation = _source_from(source_value)
            reason = None if observation_payload.get("reason_code") is None else StableId(observation_payload["reason_code"])
        receipt_payload = None if row["provider_receipt_json"] is None else json.loads(row["provider_receipt_json"])
        if receipt_payload is None:
            receipt = inspection_receipt = None
        elif (not isinstance(receipt_payload, dict)
              or set(receipt_payload) != {"receipt", "inspection_receipt"}):
            raise ValueError("stored Git receipt envelope has an invalid shape")
        else:
            receipt = _receipt_from(receipt_payload["receipt"])
            inspection_receipt = _receipt_from(receipt_payload["inspection_receipt"])
        return GitEffectOperationView(
            StableId(row["operation_id"]), GitEffectState(row["state"]), request,
            Sha256Digest(row["request_digest"]), observation, receipt, qualification, reason, source_observation,
            _receipt_from(intent_value.get("source_receipt")), inspection_receipt,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidAuthorityError(f"stored Git effect operation is invalid: {exc}") from exc


def _source_from(value: object) -> SourceObservation | None:
    if value is None:
        return None
    from todo_orchestrator.contracts import WorkingTreeState

    if not isinstance(value, dict) or set(value) != {
        "repository_id", "source_digest", "base_digest", "source_revision", "working_tree", "inputs", "artifacts",
    }:
        raise ValueError("stored Git source observation has an invalid shape")
    return SourceObservation(
        StableId(value["repository_id"]), Sha256Digest(value["source_digest"]),
        None if value["base_digest"] is None else Sha256Digest(value["base_digest"]),
        WorkingTreeState(value["working_tree"]),
        tuple(EvidenceInput(StableId(item["name"]), Sha256Digest(item["digest"]))
              for item in value["inputs"]),
        tuple(ArtifactAvailability(
            StableId(item["artifact_id"]), item["available"],
            None if item["content_digest"] is None else Sha256Digest(item["content_digest"]),
        ) for item in value["artifacts"]),
        None if value["source_revision"] is None else StableId(value["source_revision"]),
    )


def _state_from_result(result: ProviderResult[GitEffectObservation]) -> tuple[GitEffectState, GitEffectObservation | None]:
    if result.status in {ProviderStatus.UNKNOWN, ProviderStatus.UNAVAILABLE}:
        return GitEffectState.UNKNOWN, None
    if result.status not in {ProviderStatus.OBSERVED_SUCCESS, ProviderStatus.OBSERVED_FAILURE}:
        return GitEffectState.UNKNOWN, None
    observation = result.value
    if not isinstance(observation, GitEffectObservation):
        raise GitEffectObservationMismatchError("Git provider returned no typed effect observation")
    return {
        GitEffectDisposition.APPLIED: GitEffectState.FINALIZED,
        GitEffectDisposition.CONFLICT: GitEffectState.CONFLICT,
        GitEffectDisposition.DIRTY: GitEffectState.DIRTY,
        GitEffectDisposition.REJECTED: GitEffectState.REJECTED,
        GitEffectDisposition.NOT_APPLIED: GitEffectState.NOT_APPLIED,
        GitEffectDisposition.UNKNOWN: GitEffectState.UNKNOWN,
    }[observation.disposition], observation


def _phase_key(operation_id: StableId, phase: str) -> StableId:
    return _id("gitcmd", f"{operation_id}:{phase}")


def _operation_id(project_id: StableId, actor: EntityRef, operation_name: str,
                  idempotency_key: StableId) -> StableId:
    material = f"{project_id}:{actor.entity_id}:{actor.incarnation_id}:{operation_name}:{idempotency_key}"
    return _id("gop", material)


class _PrepareHandler:
    kind = _PREPARE_KIND
    command_type = _Prepare

    def __init__(self, service: "GitEffectService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Prepare) -> AuthorizationRequirement:
        request, _ = _intent_from(command.intent_json)
        return _requirement(request)

    def canonical_payload(self, command: _Prepare) -> dict[str, object]:
        return {"intent_json": command.intent_json, "request_digest": command.request_digest,
                "created_at": command.created_at}

    def apply(self, context: MutationContext, command: _Prepare) -> CommandEffect:
        request, intent = _intent_from(command.intent_json)
        if (request.context.actor != context.actor or request.context.project_id != context.project.project_id
                or provider_request_digest(request).hex != command.request_digest):
            raise GitEffectDeniedError("Git effect context or provider digest differs from authenticated intent")
        _validate_assignment_and_run(context._connection, request)
        if request.operation is GitOperationKind.CREATE_WORKSPACE:
            _validate_target_membership(context._connection, context.project, request)
        else:
            provenance, _source_receipt, _provenance_digest = _accepted_identity(
                context._connection, context.project, request, self.service.source_identity,
            )
            _validate_persisted_source_intent(
                intent, request, provenance, self.service.source_identity,
                _now(self.service.clock), self.service.max_observation_age,
            )
        existing = context._connection.execute(
            "SELECT e.request_digest, g.request_json FROM external_operations AS e "
            "JOIN git_effect_operations AS g USING(operation_id) WHERE e.idempotency_key = ?",
            (str(request.idempotency_key),),
        ).fetchone()
        if existing is not None:
            if existing["request_digest"] != command.request_digest or existing["request_json"] != command.intent_json:
                raise GitEffectDeniedError("Git idempotency key is already bound to another effect")
            return CommandEffect(False, {"operation_id": str(request.operation_id), "state": "prepared"})
        context.execute(
            "INSERT INTO external_operations(operation_id, kind, idempotency_key, request_digest, state, "
            "created_at, updated_at, attempt_id, external_ref, receipt_digest) "
            "VALUES (?, 'todo.git.effect', ?, ?, 'prepared', ?, ?, ?, NULL, NULL)",
            (str(request.operation_id), str(request.idempotency_key), command.request_digest,
             command.created_at, command.created_at,
             None if request.attempt is None else str(request.attempt.entity_id)),
        )
        context.execute(
            "INSERT INTO git_effect_operations(operation_id, request_json, request_digest, state, "
            "observation_json, provider_receipt_json, updated_at) VALUES (?, ?, ?, 'prepared', NULL, NULL, ?)",
            (str(request.operation_id), command.intent_json, command.request_digest, command.created_at),
        )
        return CommandEffect(True, {"operation_id": str(request.operation_id), "state": "prepared"},
                             "todo.git.effect.prepared", {
                                 "operation_id": str(request.operation_id), "operation": request.operation.value,
                                 "request_digest": command.request_digest,
                                 "target": _ref_value(request.target),
                                 "attempt": _ref_value(request.attempt),
                                 "accepted_outcome_id": None if request.accepted_outcome_id is None
                                 else str(request.accepted_outcome_id),
                             })


class _TransitionHandler:
    kind = _TRANSITION_KIND
    command_type = _Transition

    def __init__(self, service: "GitEffectService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Transition) -> AuthorizationRequirement:
        request, _ = _intent_from(command.intent_json)
        if command.recovery_approval is not None:
            return AuthorizationRequirement(
                RECOVERY_APPLY_ACTION, request.target, request.run, request.assignment, request.attempt,
            )
        if command.observation_json is not None:
            try:
                payload = json.loads(command.observation_json)
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = None
            if isinstance(payload, dict) and payload.get("inspection") is True:
                return AuthorizationRequirement(RECONCILE_ACTION, request.target, request.run, request.assignment)
        return _requirement(request)

    def canonical_payload(self, command: _Transition) -> dict[str, object]:
        return {
            "operation_id": str(command.operation_id), "intent_json": command.intent_json,
            "expected_state": command.expected_state, "next_state": command.next_state,
            "observation_json": command.observation_json,
            "provider_receipt_json": command.provider_receipt_json, "updated_at": command.updated_at,
            "recovery_approval_digest": None if command.recovery_approval is None else
                _recovery_approval_digest(command.recovery_approval),
        }

    def apply(self, context: MutationContext, command: _Transition) -> CommandEffect:
        request, _ = _intent_from(command.intent_json)
        if request.operation_id != command.operation_id:
            raise GitEffectDeniedError("Git transition targets another operation")
        current = context._connection.execute(
            "SELECT g.state, g.request_json, g.request_digest, e.state AS authority_state "
            "FROM git_effect_operations AS g JOIN external_operations AS e USING(operation_id) "
            "WHERE g.operation_id = ?", (str(command.operation_id),),
        ).fetchone()
        if (current is None or current["request_json"] != command.intent_json
                or current["request_digest"] != provider_request_digest(request).hex):
            raise GitEffectStateError("durable Git operation does not match its immutable request")
        if current["state"] != command.expected_state:
            raise GitEffectStateError(
                f"Git operation is {current['state']}, expected {command.expected_state}"
            )
        approval = command.recovery_approval
        approval_digest = None
        if approval is not None:
            if not _is_recovery_approval(approval):
                raise GitEffectDeniedError("recovery transition requires a freshly approved intent")
            approval_digest = _recovery_approval_digest(approval)
            if (context.authorized_capability_id != approval.capability_id
                    or context.actor != approval.actor
                    or approval.authority_revision > context.starting_revision
                    or approval.intent_kind not in {"retry_original_operation", "reconcile_observed_effect"}
                    or approval.target != request.target
                    or approval.attempt != request.attempt
                    or approval.run != request.run
                    or approval.assignment != request.assignment
                    or approval.operation != EntityRef(
                        context.project.project_id, EntityKind.EXTERNAL_OPERATION, command.operation_id,
                    )
                    or approval.expected_source_digest != request.expected_source):
                raise GitEffectDeniedError("recovery approval no longer matches the authenticated Git operation")
            same_revision = approval.authority_revision == context.starting_revision
            prior_start = False
            if not same_revision:
                rows = context._connection.execute(
                    "SELECT payload_json FROM authority_events WHERE event_kind = 'todo.git.effect.executing' "
                    "AND semantic_revision > ? ORDER BY semantic_revision DESC LIMIT 64",
                    (approval.authority_revision,),
                ).fetchall()
                for event in rows:
                    try:
                        payload = json.loads(event["payload_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if (payload.get("operation_id") == str(command.operation_id)
                            and payload.get("recovery_approval_digest") == approval_digest):
                        prior_start = True
                        break
            if not same_revision and not prior_start:
                raise GitEffectDeniedError("recovery approval is stale for this Git transition")
            if request.attempt is not None:
                attempt, attempt_row = _stored_attempt(context._connection, context.project, request.attempt)
                if (approval.expected_lease_id != (None if attempt.lease is None else attempt.lease.lease_id)
                        or approval.expected_lease_expires_at != (
                            None if attempt.lease is None else attempt.lease.expires_at
                        )):
                    raise GitEffectDeniedError("recovery attempt lease changed before the Git transition")
                from todo_orchestrator.authority.child_store import require_parent_children_resolved
                try:
                    require_parent_children_resolved(context._connection, attempt.attempt_id)
                except ValueError as exc:
                    raise GitEffectDeniedError("native child execution still blocks Git recovery") from exc
                if context._connection.execute(
                    "SELECT 1 FROM outcome_candidates WHERE attempt_id = ? AND state = 'pending' LIMIT 1",
                    (str(attempt.attempt_id),),
                ).fetchone() is not None:
                    raise GitEffectDeniedError("pending outcome review blocks Git recovery")
                if approval.host_observation is not None:
                    host = approval.host_observation
                    if (host.attempt != attempt.ref or host.lease_id != approval.expected_lease_id
                            or host.observed_lease_expires_at != approval.expected_lease_expires_at
                            or host.observed_state is not attempt.state
                            or attempt_row["work_item_id"] != str(approval.target.entity_id)):
                        raise GitEffectDeniedError("recovery host proof differs from the stored attempt")
            if command.next_state == GitEffectState.EXECUTING.value:
                if (approval.intent_kind != "retry_original_operation"
                        or command.expected_state != GitEffectState.NOT_APPLIED.value
                        or not same_revision):
                    raise GitEffectDeniedError("recovery retry must start from the approved NOT_APPLIED revision")
            elif approval.intent_kind == "retry_original_operation" and not prior_start:
                raise GitEffectDeniedError("Git retry result has no matching approved start event")
            elif approval.intent_kind == "reconcile_observed_effect" and command.next_state == GitEffectState.EXECUTING.value:
                raise GitEffectDeniedError("observed-effect reconciliation cannot start a new Git effect")
        if request.operation is GitOperationKind.INTEGRATE:
            _accepted_identity(context._connection, context.project, request, self.service.source_identity)
        if command.next_state == GitEffectState.EXECUTING.value:
            if command.expected_state not in {GitEffectState.PREPARED.value, GitEffectState.NOT_APPLIED.value}:
                raise GitEffectStateError("only prepared or definitively-not-applied effects may start")
            updated = context.execute(
                "UPDATE git_effect_operations SET state = 'executing', updated_at = ? "
                "WHERE operation_id = ? AND state = ?",
                (command.updated_at, str(command.operation_id), command.expected_state),
            ).rowcount
            if updated != 1:
                raise GitEffectStateError("Git operation changed before effect reservation")
            authority_state = current["authority_state"]
            if authority_state not in {"prepared", "not_applied"}:
                raise GitEffectStateError("authority external-operation state cannot start this effect")
            context.execute(
                "UPDATE external_operations SET state = 'executing', updated_at = ? "
                "WHERE operation_id = ? AND state = ?",
                (command.updated_at, str(command.operation_id), authority_state),
            )
            return CommandEffect(True, {"operation_id": str(command.operation_id), "state": "executing"},
                                 "todo.git.effect.executing", {
                                     "operation_id": str(command.operation_id), "request_digest": current["request_digest"],
                                     "retry": command.expected_state == GitEffectState.NOT_APPLIED.value,
                                     "recovery_approval_digest": approval_digest,
                                     "recovery_intent_digest": None if approval is None
                                         else approval.intent_digest.hex,
                                     "recovery_intent_kind": None if approval is None else approval.intent_kind,
                                 })

        if command.next_state not in {state.value for state in GitEffectState} - {
            GitEffectState.PREPARED.value, GitEffectState.EXECUTING.value,
        }:
            raise GitEffectStateError("unsupported Git effect result state")
        if command.expected_state not in {GitEffectState.EXECUTING.value, GitEffectState.UNKNOWN.value}:
            raise GitEffectStateError("Git effect result requires an executing or unknown operation")
        if command.observation_json is None:
            if command.next_state not in {GitEffectState.UNKNOWN.value}:
                raise GitEffectObservationMismatchError("definitive Git result requires a typed observation")
        else:
            payload = json.loads(command.observation_json)
            if not isinstance(payload, dict) or set(payload) != {
                "status", "reason_code", "disposition", "observation", "qualification", "source_after",
                "correlation_id", "inspection", "inspection_request",
            }:
                raise GitEffectObservationMismatchError("Git result envelope has an invalid shape")
            try:
                status = ProviderStatus(payload["status"])
                correlation = StableId(payload["correlation_id"])
                inspection = payload["inspection"]
                if type(inspection) is not bool:
                    raise ValueError("inspection flag must be bool")
                if payload["reason_code"] is not None:
                    StableId(payload["reason_code"])
                if payload["disposition"] is not None:
                    GitEffectDisposition(payload["disposition"])
            except (TypeError, ValueError) as exc:
                raise GitEffectObservationMismatchError("Git result status or correlation is invalid") from exc
            observation = _observation_from(payload.get("observation"))
            if observation is not None and observation.operation_id != request.operation_id:
                raise GitEffectObservationMismatchError("Git observation names another operation")
            if observation is None:
                if status in {ProviderStatus.OBSERVED_SUCCESS, ProviderStatus.OBSERVED_FAILURE}:
                    raise GitEffectObservationMismatchError("observed Git results require a typed disposition")
                expected_state = GitEffectState.UNKNOWN.value
            else:
                if payload["disposition"] != observation.disposition.value:
                    raise GitEffectObservationMismatchError("Git result disposition differs from its observation")
                expected_state = {
                    GitEffectDisposition.APPLIED: GitEffectState.FINALIZED.value,
                    GitEffectDisposition.CONFLICT: GitEffectState.CONFLICT.value,
                    GitEffectDisposition.DIRTY: GitEffectState.DIRTY.value,
                    GitEffectDisposition.REJECTED: GitEffectState.REJECTED.value,
                    GitEffectDisposition.NOT_APPLIED: GitEffectState.NOT_APPLIED.value,
                    GitEffectDisposition.UNKNOWN: GitEffectState.UNKNOWN.value,
                }[observation.disposition]
            if command.next_state != expected_state:
                raise GitEffectObservationMismatchError("Git transition state differs from provider observation")
            if command.provider_receipt_json is not None:
                receipt_payload = json.loads(command.provider_receipt_json)
                if not isinstance(receipt_payload, dict) or set(receipt_payload) != {
                    "receipt", "inspection_receipt",
                }:
                    raise GitEffectObservationMismatchError("Git receipt envelope has an invalid shape")
                effect_receipt = _receipt_from(receipt_payload["receipt"])
                inspection_receipt = _receipt_from(receipt_payload["inspection_receipt"])
                if payload["inspection"]:
                    inspection_request = _inspection_from(payload["inspection_request"], request)
                    if (inspection_request.operation_id != request.operation_id
                            or inspection_request.idempotency_key != request.idempotency_key
                            or inspection_request.original_request_digest != provider_request_digest(request)
                            or inspection_request.correlation_id != StableId(payload["correlation_id"])
                            or inspection_request.context.project_id != context.project.project_id
                            or inspection_request.context.actor != context.actor):
                        raise GitEffectObservationMismatchError("Git inspection query differs from its authorized operation")
                    if (inspection_receipt is None or inspection_receipt.request_digest != provider_request_digest(inspection_request)
                            or inspection_receipt.provider != self.service.provider.identity
                            or inspection_receipt.correlation_id != inspection_request.correlation_id
                            or inspection_receipt.provenance_ref != self.service.provider._provenance(request)):
                        raise GitEffectObservationMismatchError("Git inspection receipt does not bind the exact query")
                    if effect_receipt is not None and (
                        effect_receipt.request_digest != provider_request_digest(request)
                        or effect_receipt.provider != self.service.provider.identity
                        or effect_receipt.correlation_id != request.operation_id
                        or effect_receipt.provenance_ref != self.service.provider._provenance(request)
                    ):
                        raise GitEffectObservationMismatchError("preserved Git effect receipt is invalid")
                    receipt_times = (inspection_receipt.observed_at,)
                else:
                    if payload["inspection_request"] is not None or inspection_receipt is not None:
                        raise GitEffectObservationMismatchError("effect result contains an inspection receipt")
                    if (effect_receipt is None or effect_receipt.request_digest != provider_request_digest(request)
                            or effect_receipt.provider != self.service.provider.identity
                            or effect_receipt.correlation_id != request.operation_id
                            or effect_receipt.provenance_ref != self.service.provider._provenance(request)):
                        raise GitEffectObservationMismatchError("Git receipt does not bind the exact provider request")
                    receipt_times = (effect_receipt.observed_at,)
                observed_at = max(item.astimezone(timezone.utc) for item in receipt_times)
                updated_at = datetime.fromisoformat(command.updated_at).astimezone(timezone.utc)
                requested_at = request.requested_at
                if (observed_at > updated_at
                        or (requested_at is not None and observed_at < requested_at.astimezone(timezone.utc))):
                    raise GitEffectObservationMismatchError("Git provider receipt is outside the authorized operation interval")
            elif payload["status"] in {ProviderStatus.OBSERVED_SUCCESS.value,
                                       ProviderStatus.OBSERVED_FAILURE.value}:
                raise GitEffectObservationMismatchError("observed Git results require a durable provider receipt")
            if payload["inspection"] is True:
                if payload["correlation_id"] == str(request.operation_id):
                    raise GitEffectObservationMismatchError("inspection receipt must identify its query correlation")
            elif payload["correlation_id"] != str(request.operation_id):
                raise GitEffectObservationMismatchError("effect receipt must identify its operation correlation")

        final_result = command.next_state == GitEffectState.FINALIZED.value
        db_state = GitEffectState.APPLIED.value if final_result else command.next_state
        updated = context.execute(
            "UPDATE git_effect_operations SET state = ?, observation_json = ?, provider_receipt_json = ?, updated_at = ? "
            "WHERE operation_id = ? AND state = ?",
            (db_state, command.observation_json, command.provider_receipt_json,
             command.updated_at, str(command.operation_id), command.expected_state),
        ).rowcount
        if updated != 1:
            raise GitEffectStateError("Git operation changed before its observed result was recorded")
        if final_result:
            updated = context.execute(
                "UPDATE git_effect_operations SET state = 'finalized', updated_at = ? "
                "WHERE operation_id = ? AND state = 'applied'",
                (command.updated_at, str(command.operation_id)),
            ).rowcount
            if updated != 1:
                raise GitEffectStateError("Git operation could not be finalized after applying its result")

        if command.next_state == GitEffectState.UNKNOWN.value:
            external_state = "unknown"
        elif command.next_state == GitEffectState.NOT_APPLIED.value:
            external_state = "not_applied"
        elif command.next_state in {
            GitEffectState.FINALIZED.value, GitEffectState.CONFLICT.value,
            GitEffectState.DIRTY.value, GitEffectState.REJECTED.value,
        }:
            external_state = "finalized"
        else:
            raise GitEffectStateError("unsupported Git result state")
        existing_external_state = current["authority_state"]
        receipt_digest = None if command.provider_receipt_json is None else _digest(command.provider_receipt_json)
        if existing_external_state in {"executing", "unknown"} and external_state == "finalized":
            context.execute(
                "UPDATE external_operations SET state = 'observed', updated_at = ?, receipt_digest = ? "
                "WHERE operation_id = ? AND state = ?",
                (command.updated_at, receipt_digest, str(command.operation_id), existing_external_state),
            )
            existing_external_state = "observed"
        context.execute(
            "UPDATE external_operations SET state = ?, updated_at = ?, receipt_digest = COALESCE(?, receipt_digest) "
            "WHERE operation_id = ? AND state = ?",
            (external_state, command.updated_at, receipt_digest, str(command.operation_id), existing_external_state),
        )
        observation_payload = {} if command.observation_json is None else json.loads(command.observation_json)
        disposition = observation_payload.get("disposition", command.next_state)
        return CommandEffect(True, {"operation_id": str(command.operation_id), "state": command.next_state},
                             f"todo.git.effect.{command.next_state}", {
                                 "operation_id": str(command.operation_id), "request_digest": current["request_digest"],
                                 "state": command.next_state, "disposition": disposition,
                                 "receipt_digest": receipt_digest,
                                 "recovery_approval_digest": approval_digest,
                                 "recovery_intent_digest": None if approval is None
                                     else approval.intent_digest.hex,
                                 "recovery_intent_kind": None if approval is None else approval.intent_kind,
                             })


class GitEffectService:
    """Authenticate, persist, execute and reconcile a bounded set of Git effects."""

    def __init__(self, auth: AuthorityAuthService, provider: GitRepositoryProvider, *,
                 source_observer: object | None = None, source_identity: ProviderIdentity | None = None,
                 clock: Callable[[], datetime] | None = None,
                 max_observation_age: timedelta = timedelta(seconds=30)) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not isinstance(provider, GitRepositoryProvider):
            raise TypeError("provider must be a GitRepositoryProvider")
        if not isinstance(max_observation_age, timedelta) or max_observation_age <= timedelta(0):
            raise ValueError("max_observation_age must be positive")
        observer = provider if source_observer is None else source_observer
        if not callable(getattr(observer, "observe", None)):
            raise TypeError("source_observer must implement observe")
        self.auth = auth
        self.provider = provider
        self.source_observer = observer
        self.source_identity = source_identity or provider.identity
        self.clock = clock or auth.clock
        self.max_observation_age = max_observation_age
        if self.source_identity != provider.identity:
            raise ValueError("Git integration source identity must match the configured local Git provider")
        for handler in (_PrepareHandler(self), _TransitionHandler(self)):
            try:
                self.auth.dispatcher.register(handler)
            except DuplicateCommandHandlerError:
                binding = self.auth.dispatcher._by_type.get(handler.command_type)
                if binding is None or type(binding.handler) is not type(handler):
                    raise
                if binding.handler.service.provider.config != self.provider.config:
                    raise ValueError("Git effect command handlers are already bound to another repository")

    def _check_authority(self, authority: SQLiteAuthority) -> None:
        if not isinstance(authority, SQLiteAuthority) or authority.readonly:
            raise TypeError("Git effects require a writable SQLiteAuthority")
        if authority.project.project_id != self.provider.config.project_id:
            raise GitEffectDeniedError("Git provider project does not match the authority")

    def _current_requirement(self, authority: SQLiteAuthority, bearer_token: str,
                             request: GitEffectRequest) -> None:
        actor, _capability = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        if request.target is None:
            raise GitEffectDeniedError("Git request is missing its exact target")
        requirement = _requirement(request)
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, _token_digest(bearer_token), actor, requirement)

    def _intent_row(self, authority: SQLiteAuthority, operation_id: StableId) -> sqlite3.Row:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT g.*, e.state AS authority_state FROM git_effect_operations AS g "
                "JOIN external_operations AS e USING(operation_id) WHERE g.operation_id = ?",
                (str(operation_id),),
            ).fetchone()
        if row is None:
            raise GitEffectNotFoundError(f"Git operation does not exist: {operation_id}")
        return row

    def _maybe_intent_row(self, authority: SQLiteAuthority, operation_id: StableId) -> sqlite3.Row | None:
        with authority.read_transaction() as connection:
            return connection.execute(
                "SELECT g.*, e.state AS authority_state FROM git_effect_operations AS g "
                "JOIN external_operations AS e USING(operation_id) WHERE g.operation_id = ?",
                (str(operation_id),),
            ).fetchone()

    def _resume_existing(self, authority: SQLiteAuthority, bearer_token: str, operation_id: StableId, *,
                         operation: GitOperationKind, target: EntityRef | None | object = _UNSPECIFIED,
                         workspace_id: StableId | None | object = _UNSPECIFIED,
                         run: EntityRef | None | object = _UNSPECIFIED,
                         assignment: EntityRef | None | object = _UNSPECIFIED,
                         attempt: EntityRef | None | object = _UNSPECIFIED
                         ) -> GitEffectOperationView | None:
        row = self._maybe_intent_row(authority, operation_id)
        if row is None:
            return None
        request, _intent_value = _intent_from(row["request_json"])
        actor, _capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        if request.context.actor != actor:
            raise GitEffectDeniedError("stored Git operation belongs to another actor incarnation")
        if (request.operation is not operation
                or (target is not _UNSPECIFIED and request.target != target)
                or (run is not _UNSPECIFIED and request.run != run)
                or (assignment is not _UNSPECIFIED and request.assignment != assignment)
                or (attempt is not _UNSPECIFIED and request.attempt != attempt)
                or (workspace_id is not _UNSPECIFIED and workspace_id is not None
                    and request.workspace_id != workspace_id)):
            raise GitEffectDeniedError("Git idempotency key is bound to another effect intent")
        self._authorize_request(authority, bearer_token, request)
        view = _view_from_row(row)
        return self._continue_new_operation(
            authority, bearer_token, request, row["request_json"],
            expected_revision=self.auth._revision(authority, None),
        ) if view.state in {GitEffectState.PREPARED, GitEffectState.EXECUTING, GitEffectState.UNKNOWN} else view

    def _phase_replay(self, authority: SQLiteAuthority, bearer_token: str, request: GitEffectRequest,
                      phase: str, *, requirement: AuthorizationRequirement | None = None,
                      recovery_approval: RecoveryApproval | None = None) -> CommandResult | None:
        key = _phase_key(request.operation_id, phase)

        def matches(connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
            if row["event_id"] is None or row["event_kind"] is None:
                return False
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                return False
            return (
                row["event_kind"].startswith("todo.git.effect.")
                and isinstance(payload, dict)
                and payload.get("operation_id") == str(request.operation_id)
                and payload.get("request_digest") == provider_request_digest(request).hex
                and (recovery_approval is None or (
                    payload.get("recovery_approval_digest") == _recovery_approval_digest(recovery_approval)
                    and payload.get("recovery_intent_kind") == recovery_approval.intent_kind
                ))
            )

        return self.auth.replay_authorized(
            authority, bearer_token, key, requirement or _requirement(request), _TRANSITION_KIND, matches,
        )

    def _view(self, authority: SQLiteAuthority, operation_id: StableId) -> GitEffectOperationView:
        return _view_from_row(self._intent_row(authority, operation_id))

    def _create_request(self, authority: SQLiteAuthority, actor: EntityRef, capability_id: StableId,
                        target: EntityRef, *, workspace_id: StableId | None, idempotency_key: StableId,
                        expected_revision: int, run: EntityRef | None, assignment: EntityRef | None) -> tuple[GitEffectRequest, str]:
        if target.project_id != authority.project.project_id or target.kind is not EntityKind.WORK_ITEM:
            raise ValueError("target must be a work item in this authority")
        self.auth._revision(authority, expected_revision)
        operation_material = f"{authority.project.project_id}:{actor.entity_id}:{actor.incarnation_id}:workspace:{idempotency_key}"
        operation_id = _operation_id(authority.project.project_id, actor, "workspace", idempotency_key)
        external_idem = _id("gidem", operation_material)
        chosen_workspace = workspace_id or _id("gws", operation_material)
        qualified = self.provider.qualified_revision(self.provider.config.base_ref)
        request = GitEffectRequest(
            ProviderCallContext(authority.project.project_id, actor,
                                EntityRef(authority.project.project_id, EntityKind.CAPABILITY, capability_id),
                                _id("gctx", str(operation_id)), _id("gscope", json.dumps(_ref_value(target), sort_keys=True))),
            operation_id, external_idem, GitOperationKind.CREATE_WORKSPACE,
            Sha256Digest(qualified.digest), expected_revision, chosen_workspace,
            self.provider.config.base_ref, qualified.ref, None, None, target, None, run, assignment, _now(self.clock),
        )
        intent = _intent(request)
        return request, _intent_json(intent)

    def create_workspace(self, authority: SQLiteAuthority, bearer_token: str, target: EntityRef, *,
                         idempotency_key: StableId, workspace_id: StableId | None = None,
                         expected_revision: int | None = None, run: EntityRef | None = None,
                         assignment: EntityRef | None = None) -> GitEffectOperationView:
        self._check_authority(authority)
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        actor, capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        operation_material = (
            f"{authority.project.project_id}:{actor.entity_id}:"
            f"{actor.incarnation_id}:workspace:{idempotency_key}"
        )
        operation_id = _operation_id(authority.project.project_id, actor, "workspace", idempotency_key)
        existing = self._resume_existing(
            authority, bearer_token, operation_id, operation=GitOperationKind.CREATE_WORKSPACE,
            target=target, workspace_id=workspace_id, run=run, assignment=assignment, attempt=None,
        )
        if existing is not None:
            return existing
        requirement = AuthorizationRequirement(CREATE_WORKSPACE_ACTION, target, run, assignment)
        revision = self.auth._revision(authority, expected_revision)
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, _token_digest(bearer_token), actor, requirement)
            _validate_run_assignment(connection, target, run, assignment)
            # Validate the current plan before resolving external Git refs; the
            # mutation handler will repeat this check under its writer lock.
            accepted_plan = _plan_revision(connection, GitEffectRequest(
                ProviderCallContext(authority.project.project_id, actor,
                                    EntityRef(authority.project.project_id, EntityKind.CAPABILITY, capability_id),
                                    StableId("git-preflight"), StableId("git-preflight-scope")),
                operation_id, _id("gidem", operation_material), GitOperationKind.CREATE_WORKSPACE,
                Sha256Digest("0" * 64), max(1, revision), target=target, run=run, assignment=assignment,
            ))
            snapshot = load_plan_revision_snapshot(connection, authority.project, accepted_plan)
            if not any(item.work_item_id == target.entity_id
                       and item.definition_revision_id == target.definition_revision_id for item in snapshot.work_items):
                raise GitEffectDeniedError("exact Git effect target is absent from its accepted plan")
        request, intent_json = self._create_request(
            authority, actor, capability_id, target, workspace_id=workspace_id,
            idempotency_key=idempotency_key, expected_revision=revision, run=run, assignment=assignment,
        )
        try:
            result = self.auth.execute(
                authority, bearer_token, _Prepare(intent_json, provider_request_digest(request).hex, _iso(_now(self.clock))),
                idempotency_key=_phase_key(request.operation_id, "prepare"), expected_revision=revision,
            )
        except (IdempotencyConflictError, StaleAuthorityRevisionError):
            # A concurrent exact request may have won the reservation while
            # this caller was resolving Git. Read and authenticate that durable
            # intent before deciding that the caller supplied a conflicting one.
            existing = self._resume_existing(
                authority, bearer_token, operation_id, operation=GitOperationKind.CREATE_WORKSPACE,
                target=target, workspace_id=workspace_id, run=run, assignment=assignment, attempt=None,
            )
            if existing is None:
                raise
            return existing
        return self._continue_new_operation(authority, bearer_token, request, intent_json,
                                            expected_revision=result.receipt.semantic_revision)

    def _accepted_request(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef, *,
                          idempotency_key: StableId, expected_revision: int) -> tuple[GitEffectRequest, str]:
        actor, capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        with authority.read_transaction() as connection:
            attempt, _row = _stored_attempt(connection, authority.project, attempt_ref)
            if attempt.state is not AttemptState.ACCEPTED:
                raise GitEffectDeniedError("integration requires an accepted attempt")
            target = attempt.work_item
            workspace = _stored_workspace(connection, authority.project, attempt_ref)
            candidate = connection.execute(
                "SELECT o.outcome_id, c.candidate_id, p.content_digest FROM outcomes AS o "
                "JOIN outcome_provenance AS p USING(outcome_id) JOIN outcome_candidates AS c USING(outcome_id) "
                "WHERE o.attempt_id = ? AND o.work_item_id = ? AND o.definition_revision_id = ? "
                "AND c.state = 'accepted' AND c.outcome_id = o.outcome_id ORDER BY o.version DESC LIMIT 1",
                (str(attempt_ref.entity_id), str(target.entity_id), str(target.definition_revision_id)),
            ).fetchone()
            if candidate is None:
                raise GitEffectDeniedError("attempt has no accepted candidate outcome")
            provenance_json = connection.execute(
                "SELECT canonical_json FROM outcome_provenance WHERE outcome_id = ?",
                (candidate["outcome_id"],),
            ).fetchone()[0]
            if _digest(provenance_json) != candidate["content_digest"]:
                raise GitEffectDeniedError("accepted outcome provenance is corrupt")
            provenance = json.loads(provenance_json)
            source = provenance.get("source")
            source_receipt = provenance.get("source_receipt")
            if not isinstance(source, dict) or not isinstance(source_receipt, dict):
                raise GitEffectDeniedError("accepted outcome has no typed source provenance")
            source_commit = source.get("source_revision")
            source_digest = source.get("source_digest")
            receipt_id = source_receipt.get("receipt_id")
            if (not isinstance(source_commit, str) or len(source_commit) not in (40, 64)
                    or any(char not in "0123456789abcdef" for char in source_commit)
                    or not isinstance(source_digest, str) or len(source_digest) != 64
                    or any(char not in "0123456789abcdef" for char in source_digest)
                    or not isinstance(receipt_id, str)):
                raise GitEffectDeniedError("accepted outcome is missing a Git-qualified source commit or digest")
            self.auth._authorize_capability(
                connection, authority.project, _token_digest(bearer_token), actor,
                AuthorizationRequirement(INTEGRATE_ACTION, target, attempt.run, attempt.assignment, attempt_ref),
            )
        self.auth._revision(authority, expected_revision)
        operation_material = f"{authority.project.project_id}:{actor.entity_id}:{actor.incarnation_id}:integrate:{idempotency_key}"
        operation_id = _operation_id(authority.project.project_id, actor, "integrate", idempotency_key)
        external_idem = _id("gidem", operation_material)
        requested_at = _now(self.clock)
        context = ProviderCallContext(
            authority.project.project_id, actor, EntityRef(authority.project.project_id, EntityKind.CAPABILITY, capability_id),
            _id("gctx", str(operation_id)), _id("gscope", json.dumps(_ref_value(target), sort_keys=True)),
        )
        request = GitEffectRequest(
            context, operation_id, external_idem, GitOperationKind.INTEGRATE,
            Sha256Digest(source_digest), expected_revision, workspace.workspace_id,
            None, StableId(source_commit), self.provider.config.integration_ref,
            self.provider.integration_head(), target, attempt_ref, attempt.run, attempt.assignment, requested_at,
            StableId(candidate["outcome_id"]), StableId(candidate["candidate_id"]),
            Sha256Digest(candidate["content_digest"]), Sha256Digest(source_digest), StableId(receipt_id),
        )
        intent_value = _intent(request)
        return request, _intent_json(intent_value)

    def integrate_attempt(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef, *,
                          idempotency_key: StableId, expected_revision: int | None = None) -> GitEffectOperationView:
        self._check_authority(authority)
        if not isinstance(attempt_ref, EntityRef) or attempt_ref.kind is not EntityKind.ATTEMPT:
            raise TypeError("attempt_ref must identify an attempt")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        actor, _capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        operation_id = _operation_id(authority.project.project_id, actor, "integrate", idempotency_key)
        existing = self._resume_existing(
            authority, bearer_token, operation_id, operation=GitOperationKind.INTEGRATE,
            attempt=attempt_ref,
        )
        if existing is not None:
            return existing
        revision = self.auth._revision(authority, expected_revision)
        request, intent_json = self._accepted_request(
            authority, bearer_token, attempt_ref, idempotency_key=idempotency_key, expected_revision=revision,
        )
        intent_json = self._observe_accepted_source(authority, request, intent_json)
        try:
            result = self.auth.execute(
                authority, bearer_token, _Prepare(intent_json, provider_request_digest(request).hex, _iso(_now(self.clock))),
                idempotency_key=_phase_key(request.operation_id, "prepare"), expected_revision=revision,
            )
        except (IdempotencyConflictError, StaleAuthorityRevisionError):
            existing = self._resume_existing(
                authority, bearer_token, operation_id, operation=GitOperationKind.INTEGRATE,
                attempt=attempt_ref,
            )
            if existing is None:
                raise
            return existing
        return self._continue_new_operation(authority, bearer_token, request, intent_json,
                                            expected_revision=result.receipt.semantic_revision)

    def _observe_accepted_source(self, authority: SQLiteAuthority, request: GitEffectRequest,
                                 intent_json: str) -> str:
        if request.attempt is None or request.target is None or request.workspace_id is None:
            raise GitEffectDeniedError("accepted source observation requires the exact attempt workspace")
        with authority.read_transaction() as connection:
            provenance, _receipt, _digest_value = _accepted_identity(
                connection, authority.project, request, self.source_identity,
            )
        correlation = _id("gsrc", str(request.operation_id))
        source_request = _accepted_source_request(request, provenance, correlation)
        result = self.source_observer.observe(source_request)
        if not isinstance(result, ProviderResult) or result.status is not ProviderStatus.OBSERVED_SUCCESS:
            raise GitEffectProviderUnavailableError("Git source observer could not establish accepted inputs")
        receipt = result.receipt
        if (result.provider != self.source_identity or result.correlation_id != correlation or receipt is None
                or receipt.provider != self.source_identity or receipt.correlation_id != correlation
                or receipt.request_digest != provider_request_digest(source_request)
                or receipt.provenance_ref != request.workspace_id):
            raise GitEffectObservationMismatchError("fresh source receipt does not bind the exact attempt workspace")
        source = result.value
        if not isinstance(source, SourceObservation):
            raise GitEffectObservationMismatchError("Git source observer returned no typed source observation")
        expected = provenance["source"]
        actual = _source_value(source)
        if actual != expected or source.working_tree.value != "clean":
            raise GitEffectDeniedError("current workspace source differs from the exact accepted clean source identity")
        now = _now(self.clock)
        observed_at = receipt.observed_at.astimezone(timezone.utc)
        if observed_at > now or now - observed_at > self.max_observation_age:
            raise GitEffectObservationMismatchError("accepted-source observation is stale or from the future")
        # The initial intent stores this fresh, exact source receipt before Git
        # integration. It is part of the command payload and survives restart.
        intent = json.loads(intent_json)
        intent["source_observation"] = actual
        intent["source_receipt"] = _receipt_value(receipt)
        return _intent_json(intent)

    def _continue_new_operation(self, authority: SQLiteAuthority, bearer_token: str, request: GitEffectRequest,
                                intent_json: str, *, expected_revision: int) -> GitEffectOperationView:
        view = self._view(authority, request.operation_id)
        if view.state in {GitEffectState.FINALIZED, GitEffectState.APPLIED, GitEffectState.CONFLICT,
                          GitEffectState.DIRTY, GitEffectState.REJECTED, GitEffectState.NOT_APPLIED}:
            return view
        if view.state is GitEffectState.PREPARED:
            started = self._transition(authority, bearer_token, request, intent_json,
                                       GitEffectState.PREPARED, GitEffectState.EXECUTING,
                                       phase="start", expected_revision=expected_revision)
            if not started.replayed:
                result = self.provider.perform(request)
                return self._store_provider_result(authority, bearer_token, request, intent_json, result,
                                                   expected_revision=started.receipt.semantic_revision,
                                                   phase="perform")
        revision = self.auth._revision(authority, None)
        return self.reconcile(
            authority, bearer_token, request.operation_id,
            idempotency_key=_id("grecovery", f"{request.operation_id}:{revision}"),
            expected_revision=revision, _internal_request=request,
            _internal_intent=intent_json,
        )

    def _transition(self, authority: SQLiteAuthority, bearer_token: str, request: GitEffectRequest,
                    intent_json: str, expected_state: GitEffectState, next_state: GitEffectState, *,
                    phase: str, expected_revision: int | None,
                    observation_json: str | None = None, provider_receipt_json: str | None = None,
                    recovery_approval: RecoveryApproval | None = None) -> CommandResult:
        return self.auth.execute(
            authority, bearer_token,
            _Transition(request.operation_id, intent_json, expected_state.value, next_state.value,
                        observation_json, provider_receipt_json, _iso(_now(self.clock)), recovery_approval),
            idempotency_key=_phase_key(request.operation_id, phase), expected_revision=expected_revision,
        )

    def _provider_payload(self, request: GitEffectRequest, result: ProviderResult[GitEffectObservation], *,
                          correlation: StableId, inspection: bool,
                          inspection_request: EffectInspectionRequest | None = None,
                          preserved_effect_receipt: ProviderReceipt | None = None
                          ) -> tuple[GitEffectState, str, str | None]:
        if result.correlation_id != correlation:
            raise GitEffectObservationMismatchError("provider result has an unexpected correlation")
        if result.provider is not None and result.provider != self.provider.identity:
            raise GitEffectObservationMismatchError("provider result has an unexpected provider identity")
        if result.status is ProviderStatus.UNKNOWN and result.provider != self.provider.identity:
            raise GitEffectObservationMismatchError("unknown Git results must identify the configured provider")
        observation = result.value if isinstance(result.value, GitEffectObservation) else None
        if result.status in {ProviderStatus.OBSERVED_SUCCESS, ProviderStatus.OBSERVED_FAILURE}:
            if result.provider != self.provider.identity or observation is None:
                raise GitEffectObservationMismatchError("provider result identity or observation is invalid")
            if inspection and observation.original_receipt is not None:
                if (preserved_effect_receipt is not None
                        and preserved_effect_receipt != observation.original_receipt):
                    raise GitEffectObservationMismatchError(
                        "inspection provider receipt differs from the already persisted effect receipt"
                    )
                preserved_effect_receipt = observation.original_receipt
            receipt = result.receipt
            expected_provenance = self.provider._provenance(request)
            expected_digest = (provider_request_digest(inspection_request)
                               if inspection and inspection_request is not None
                               else provider_request_digest(request))
            if (receipt is None or receipt.provider != self.provider.identity or receipt.correlation_id != correlation
                    or receipt.request_digest != expected_digest
                    or receipt.provenance_ref != expected_provenance):
                raise GitEffectObservationMismatchError("provider receipt does not bind the exact Git request")
            now = _now(self.clock)
            observed_at = receipt.observed_at.astimezone(timezone.utc)
            requested_at = request.requested_at.astimezone(timezone.utc) if request.requested_at is not None else None
            if (observed_at > now or (requested_at is not None and observed_at < requested_at)):
                raise GitEffectObservationMismatchError("Git provider receipt is outside the authorized operation interval")
            if inspection:
                # The provider inspects the original operation; only the query
                # correlation differs from the original effect correlation.
                pass
        else:
            receipt = None
        state, typed_observation = _state_from_result(result)
        qualification = None
        source_after = None
        if (request.operation is GitOperationKind.CREATE_WORKSPACE and typed_observation is not None
                and typed_observation.disposition is GitEffectDisposition.APPLIED):
            if request.target is None or request.workspace_id is None:
                raise GitEffectObservationMismatchError("workspace effect omitted its target identity")
            qualification = self.provider.qualify_workspace(
                request.workspace_id, request.target, _id("gqual", str(request.operation_id)),
            )
            if (qualification.workspace_id != request.workspace_id
                    or qualification.repository_id != self.provider.config.repository_id
                    or qualification.common_base.ref != request.source_commit
                    or qualification.common_base.digest != request.expected_source.hex
                    or qualification.destination.ref != self.provider.config.integration_ref):
                raise GitEffectObservationMismatchError("new workspace qualification differs from its immutable request")
        if inspection and inspection_request is None:
            raise GitEffectObservationMismatchError("inspection result is missing its exact query request")
        if not inspection and inspection_request is not None:
            raise GitEffectObservationMismatchError("effect result unexpectedly contains an inspection request")
        payload = {
            "status": result.status.value,
            "reason_code": None if result.reason_code is None else str(result.reason_code),
            "disposition": None if typed_observation is None else typed_observation.disposition.value,
            "observation": _observation_value(typed_observation),
            "qualification": _workspace_value(qualification),
            "source_after": _source_value(source_after),
            "correlation_id": str(correlation),
            "inspection": inspection,
            "inspection_request": _inspection_value(inspection_request),
        }
        if inspection:
            receipt_json = None if receipt is None else _json({
                "receipt": _receipt_value(preserved_effect_receipt),
                "inspection_receipt": _receipt_value(receipt),
            })
        else:
            receipt_json = None if receipt is None else _json({
                "receipt": _receipt_value(receipt), "inspection_receipt": None,
            })
        return state, _json(payload), receipt_json

    def _store_provider_result(self, authority: SQLiteAuthority, bearer_token: str, request: GitEffectRequest,
                               intent_json: str, result: ProviderResult[GitEffectObservation], *,
                               expected_revision: int | None, phase: str,
                               inspection_correlation: StableId | None = None,
                               inspection_request: EffectInspectionRequest | None = None,
                               recovery_approval: RecoveryApproval | None = None) -> GitEffectOperationView:
        correlation = inspection_correlation or request.operation_id
        current = self._view(authority, request.operation_id)
        state, observation_json, receipt_json = self._provider_payload(
            request, result, correlation=correlation, inspection=inspection_correlation is not None,
            inspection_request=inspection_request,
            preserved_effect_receipt=current.provider_receipt if inspection_correlation is not None else None,
        )
        if current.state in {GitEffectState.FINALIZED, GitEffectState.APPLIED, GitEffectState.CONFLICT,
                             GitEffectState.DIRTY, GitEffectState.REJECTED}:
            return current
        if state is GitEffectState.FINALIZED:
            final = GitEffectState.FINALIZED
        else:
            final = state
        phase_key = (phase if recovery_approval is not None
                     else phase + ":" + _digest(observation_json)[:32])
        replay_requirement = (
            AuthorizationRequirement(RECOVERY_APPLY_ACTION, request.target, request.run,
                                     request.assignment, request.attempt)
            if recovery_approval is not None else
            AuthorizationRequirement(RECONCILE_ACTION, request.target, request.run, request.assignment)
            if inspection_correlation is not None else None
        )
        if self._phase_replay(authority, bearer_token, request, phase_key,
                              requirement=replay_requirement,
                              recovery_approval=recovery_approval) is not None:
            return self._view(authority, request.operation_id)
        self._transition(
            authority, bearer_token, request, intent_json, current.state, final,
            phase=phase_key, expected_revision=expected_revision,
            observation_json=observation_json, provider_receipt_json=receipt_json,
            recovery_approval=recovery_approval,
        )
        return self._view(authority, request.operation_id)

    def _authorize_request(self, authority: SQLiteAuthority, bearer_token: str,
                           request: GitEffectRequest) -> EntityRef:
        actor, _ = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        if actor != request.context.actor:
            raise GitEffectDeniedError("Git operation belongs to another actor incarnation")
        requirement = _requirement(request)
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, _token_digest(bearer_token), actor, requirement)
        return actor

    def _authorize_inspection(self, authority: SQLiteAuthority, bearer_token: str,
                              request: GitEffectRequest, action: StableId) -> tuple[EntityRef, StableId]:
        """Authorize a current inspector independently from the effect owner."""
        token_digest = _token_digest(bearer_token)
        actor, capability_id = self.auth._actor_for_token(authority, token_digest)
        requirement = AuthorizationRequirement(action, request.target, request.run, request.assignment)
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, token_digest, actor, requirement)
        return actor, capability_id

    def _authorize_recovery_request(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        request: GitEffectRequest,
        approval: RecoveryApproval,
        intent_kind: str,
    ) -> tuple[EntityRef, StableId]:
        if not _is_recovery_approval(approval):
            raise GitEffectDeniedError("Git recovery requires a freshly approved inspection intent")
        token_digest = _token_digest(bearer_token)
        actor, capability_id = self.auth._actor_for_token(authority, token_digest)
        operation_ref = EntityRef(
            authority.project.project_id, EntityKind.EXTERNAL_OPERATION, request.operation_id,
        )
        if (capability_id != approval.capability_id or actor != approval.actor
                or approval.intent_kind != intent_kind or approval.operation != operation_ref
                or approval.target != request.target or approval.attempt != request.attempt
                or approval.run != request.run or approval.assignment != request.assignment
                or approval.expected_source_digest != request.expected_source):
            raise GitEffectDeniedError("Git recovery approval does not match the current principal or effect")
        requirement = AuthorizationRequirement(
            RECOVERY_APPLY_ACTION, request.target, request.run, request.assignment, request.attempt,
        )
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, token_digest, actor, requirement)
        return actor, capability_id

    def recovery_replay(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        operation_ref: EntityRef,
        intent_kind: str,
        idempotency_key: StableId,
        intent_digest: Sha256Digest,
    ) -> GitEffectOperationView | None:
        """Return a prior exact recovery phase without re-reading the provider."""
        self._check_authority(authority)
        if (not isinstance(operation_ref, EntityRef) or operation_ref.kind is not EntityKind.EXTERNAL_OPERATION
                or operation_ref.project_id != authority.project.project_id
                or intent_kind not in {"retry_original_operation", "reconcile_observed_effect"}
                or not isinstance(idempotency_key, StableId)
                or not isinstance(intent_digest, Sha256Digest)):
            raise TypeError("recovery replay requires an exact operation, recovery kind, and idempotency key")
        view = self._view(authority, operation_ref.entity_id)
        requirement = AuthorizationRequirement(
            RECOVERY_APPLY_ACTION, view.request.target, view.request.run,
            view.request.assignment, view.request.attempt,
        )
        phases = (
            (f"recovery-retry-start:{idempotency_key}", f"recovery-retry-result:{idempotency_key}")
            if intent_kind == "retry_original_operation" else
            (f"recovery-reconcile-result:{idempotency_key}",)
        )
        for phase in phases:
            key = _phase_key(view.operation_id, phase)

            def matches(_connection: sqlite3.Connection, row: sqlite3.Row) -> bool:
                if row["event_id"] is None or row["event_kind"] is None:
                    return False
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    return False
                return bool(
                    row["event_kind"].startswith("todo.git.effect.")
                    and isinstance(payload, dict)
                    and payload.get("operation_id") == str(view.operation_id)
                    and payload.get("recovery_intent_kind") == intent_kind
                    and payload.get("recovery_intent_digest") == intent_digest.hex
                    and isinstance(payload.get("recovery_approval_digest"), str)
                )

            replay = self.auth.replay_authorized(
                authority, bearer_token, key, requirement, _TRANSITION_KIND, matches,
            )
            if replay is not None:
                return self._view(authority, view.operation_id)
        return None

    def read_operation(self, authority: SQLiteAuthority, bearer_token: str,
                       operation_id: StableId) -> GitEffectOperationView:
        self._check_authority(authority)
        if not isinstance(operation_id, StableId):
            raise TypeError("operation_id must be a StableId")
        view = self._view(authority, operation_id)
        self._authorize_inspection(authority, bearer_token, view.request, READ_ACTION)
        return view

    def reconcile(self, authority: SQLiteAuthority, bearer_token: str, operation_id: StableId, *,
                  idempotency_key: StableId, expected_revision: int | None = None,
                  _internal_request: GitEffectRequest | None = None,
                  _internal_intent: str | None = None,
                  _recovery: bool = False,
                  _recovery_approval: RecoveryApproval | None = None) -> GitEffectOperationView:
        self._check_authority(authority)
        if type(_recovery) is not bool:
            raise TypeError("_recovery must be a bool")
        if _recovery != (_recovery_approval is not None):
            raise GitEffectDeniedError("recovery transitions require their sealed approval")
        view = self._view(authority, operation_id)
        request = _internal_request or view.request
        intent_json = _internal_intent
        if intent_json is None:
            row = self._intent_row(authority, operation_id)
            intent_json = row["request_json"]
        if request.operation_id != operation_id:
            raise GitEffectDeniedError("reconcile request identifies another operation")
        if _recovery:
            actor, capability_id = self._authorize_recovery_request(
                authority, bearer_token, request, _recovery_approval, "reconcile_observed_effect",
            )
            replayed = self.recovery_replay(
                authority, bearer_token,
                EntityRef(authority.project.project_id, EntityKind.EXTERNAL_OPERATION, operation_id),
                "reconcile_observed_effect", idempotency_key,
            )
            if replayed is not None:
                return replayed
            if expected_revision != _recovery_approval.authority_revision:
                raise GitEffectStateError("recovery reconcile revision differs from its approved inspection")
            recovery_requirement = AuthorizationRequirement(
                RECOVERY_APPLY_ACTION, request.target, request.run, request.assignment, request.attempt,
            )
        else:
            actor, capability_id = self._authorize_inspection(authority, bearer_token, request, RECONCILE_ACTION)
            recovery_requirement = AuthorizationRequirement(
                RECONCILE_ACTION, request.target, request.run, request.assignment,
            )
        recovery_phase = f"recovery-reconcile-result:{idempotency_key}" if _recovery else None
        phase = recovery_phase or ("inspect:" + str(idempotency_key))
        replay = self._phase_replay(
            authority, bearer_token, request, phase,
            requirement=recovery_requirement,
            recovery_approval=_recovery_approval,
        )
        if replay is not None:
            return self._view(authority, operation_id)
        self.auth._revision(authority, expected_revision)
        if view.state in {GitEffectState.FINALIZED, GitEffectState.APPLIED, GitEffectState.CONFLICT,
                          GitEffectState.DIRTY, GitEffectState.REJECTED}:
            return view
        correlation = _id("gquery", f"{operation_id}:{idempotency_key}")
        context = ProviderCallContext(
            authority.project.project_id, actor,
            EntityRef(authority.project.project_id, EntityKind.CAPABILITY, capability_id),
            _id("gctx", f"{operation_id}:{correlation}"), _id("gscope", json.dumps(_ref_value(request.target), sort_keys=True)),
        )
        query = EffectInspectionRequest(context, operation_id, request.idempotency_key,
                                        provider_request_digest(request), correlation, request)
        result = self.provider.inspect(query)
        return self._store_provider_result(
            authority, bearer_token, request, intent_json, result,
            expected_revision=self.auth._revision(authority, expected_revision), phase=phase,
            inspection_correlation=correlation, inspection_request=query,
            recovery_approval=_recovery_approval,
        )

    def retry_not_applied(self, authority: SQLiteAuthority, bearer_token: str, operation_id: StableId, *,
                          idempotency_key: StableId, expected_revision: int | None = None,
                          _recovery: bool = False,
                          _recovery_approval: RecoveryApproval | None = None) -> GitEffectOperationView:
        self._check_authority(authority)
        if type(_recovery) is not bool:
            raise TypeError("_recovery must be a bool")
        if _recovery != (_recovery_approval is not None):
            raise GitEffectDeniedError("recovery transitions require their sealed approval")
        view = self._view(authority, operation_id)
        request = view.request
        if _recovery:
            self._authorize_recovery_request(
                authority, bearer_token, request, _recovery_approval, "retry_original_operation",
            )
            replayed = self.recovery_replay(
                authority, bearer_token,
                EntityRef(authority.project.project_id, EntityKind.EXTERNAL_OPERATION, operation_id),
                "retry_original_operation", idempotency_key,
            )
            if replayed is not None:
                return replayed
            if expected_revision != _recovery_approval.authority_revision:
                raise GitEffectStateError("recovery retry revision differs from its approved inspection")
        else:
            self._authorize_request(authority, bearer_token, request)
        recovery_phase_start = f"recovery-retry-start:{idempotency_key}"
        recovery_phase_result = f"recovery-retry-result:{idempotency_key}"
        result_replay = self._phase_replay(authority, bearer_token, request,
                                           recovery_phase_result if _recovery else
                                           "retry-result:" + str(idempotency_key),
                                           requirement=(AuthorizationRequirement(
                                               RECOVERY_APPLY_ACTION, request.target, request.run,
                                               request.assignment, request.attempt,
                                           ) if _recovery else None),
                                           recovery_approval=_recovery_approval)
        if result_replay is not None:
            return self._view(authority, operation_id)
        start_replay = self._phase_replay(
            authority, bearer_token, request,
            recovery_phase_start if _recovery else "retry:" + str(idempotency_key),
            requirement=(AuthorizationRequirement(
                RECOVERY_APPLY_ACTION, request.target, request.run, request.assignment, request.attempt,
            ) if _recovery else None),
            recovery_approval=_recovery_approval,
        )
        if start_replay is not None:
            if _recovery:
                return self._view(authority, operation_id)
            return self.reconcile(
                authority, bearer_token, operation_id,
                idempotency_key=_id("grecovery", f"{operation_id}:{idempotency_key}:{self.auth._revision(authority, None)}"),
                expected_revision=self.auth._revision(authority, None),
            )
        self.auth._revision(authority, expected_revision)
        if view.state is not GitEffectState.NOT_APPLIED:
            raise GitEffectStateError("explicit Git retry requires a durable NOT_APPLIED observation")
        intent_json = self._intent_row(authority, operation_id)["request_json"]
        started = self._transition(authority, bearer_token, request, intent_json, GitEffectState.NOT_APPLIED,
                                   GitEffectState.EXECUTING,
                                   phase=recovery_phase_start if _recovery else "retry:" + str(idempotency_key),
                                   expected_revision=self.auth._revision(authority, expected_revision),
                                   recovery_approval=_recovery_approval)
        if started.replayed:
            if _recovery:
                return self._view(authority, operation_id)
            return self.reconcile(authority, bearer_token, operation_id,
                                  idempotency_key=_phase_key(operation_id, "retry-recovery"),
                                  expected_revision=started.receipt.semantic_revision)
        result = self.provider.retry_not_applied(request)
        return self._store_provider_result(authority, bearer_token, request, intent_json, result,
                                           expected_revision=started.receipt.semantic_revision,
                                           phase=recovery_phase_result if _recovery else
                                           "retry-result:" + str(idempotency_key),
                                           recovery_approval=_recovery_approval)


def _prepare_context(command: _Prepare) -> tuple[GitEffectRequest, dict[str, object]]:
    return _intent_from(command.intent_json)


_PREPARE_HANDLER_IMPL = _PrepareHandler


__all__ = [
    "CREATE_WORKSPACE_ACTION", "INTEGRATE_ACTION", "READ_ACTION", "RECONCILE_ACTION",
    "GitEffectDeniedError", "GitEffectError", "GitEffectNotFoundError",
    "GitEffectObservationMismatchError", "GitEffectOperationView", "GitEffectProviderUnavailableError",
    "GitEffectService", "GitEffectState", "GitEffectStateError",
]
