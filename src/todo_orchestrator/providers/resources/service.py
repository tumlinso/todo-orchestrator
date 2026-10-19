"""Authenticated durable integration for externally owned resource permits.

Todo records the exact intent and provider provenance. It does not model
physical capacity or treat expiry, an unavailable provider, or an unknown
inspection as proof that a permit has been released.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import sqlite3
from typing import Callable

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    RESOURCE_READ_ACTION,
    RESOURCE_RECONCILE_ACTION,
    RESOURCE_RELEASE_ACTION,
    RESOURCE_RESERVE_ACTION,
    _token_digest,
)
from todo_orchestrator.authority.attempts import _stored_attempt
from todo_orchestrator.authority.commands import (
    DuplicateCommandHandlerError,
    IdempotencyConflictError,
    MutationContext,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.authority.sqlite import AuthorityError, InvalidAuthorityError, SQLiteAuthority
from todo_orchestrator.contracts import (
    AttemptState,
    EntityKind,
    EntityRef,
    ProviderCallContext,
    ProviderIdentity,
    StableId,
)
from todo_orchestrator.contracts.providers import (
    EffectInspectionRequest,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    ResourcePermitInspection,
    ResourcePermitInspectionState,
    ResourcePermitRef,
    ResourcePermitRelease,
    ResourcePermitReleaseRequest,
    ResourcePermitRequest,
    provider_request_digest,
)
from todo_orchestrator.model import CommandEffect, CommandResult


_PREPARE_KIND = "todo.resource.permit.prepare"
_TRANSITION_KIND = "todo.resource.permit.transition"
_FORMAT = "todo-orchestrator.resource-permit-intent"
_VERSION = 1


class ResourcePermitError(AuthorityError):
    """Base class for resource permit service failures."""


class ResourcePermitDeniedError(ResourcePermitError):
    """The current capability or attempt state does not authorize the request."""


class ResourcePermitNotFoundError(ResourcePermitError):
    """The referenced durable permit operation does not exist."""


class ResourcePermitStateError(ResourcePermitError):
    """The durable permit operation is not in a state that permits this step."""


class ResourcePermitObservationMismatchError(ResourcePermitError):
    """A provider result or receipt does not bind the exact permit request."""


class ResourcePermitProviderUnavailableError(ResourcePermitError):
    """The trusted provider could not be used for the requested operation."""


class ResourcePermitState(str, Enum):
    PREPARED = "prepared"
    EXECUTING = "executing"
    HELD = "held"
    RELEASED = "released"
    UNKNOWN = "unknown"
    NOT_APPLIED = "not_applied"
    FAILED = "failed"


@dataclass(frozen=True)
class ResourcePermitOperationView:
    operation_id: StableId
    operation_kind: str
    state: ResourcePermitState
    attempt: EntityRef
    target: EntityRef
    run: EntityRef | None
    assignment: EntityRef | None
    resource_class: StableId
    units: int
    scope_id: StableId
    permit_ref_digest: str | None
    permit_expires_at: datetime | None
    provider_identity: ProviderIdentity
    provider_receipt: ProviderReceipt | None
    reason_code: StableId | None = None
    inspection_state: ResourcePermitInspectionState | None = None
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
    external_state: str
    action: StableId
    permit_json: str | None
    provider_receipt_json: str | None
    inspection_json: str | None
    receipt_digest: str | None
    reason_code: str | None
    updated_at: str


def _utc(value: datetime, name: str = "timestamp") -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds")


def _now(clock: Callable[[], datetime]) -> datetime:
    return _utc(clock(), "resource permit clock")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _derived_id(prefix: str, material: str) -> StableId:
    return StableId(prefix + "-" + hashlib.sha256(material.encode("utf-8")).hexdigest())


def _ref_value(ref: EntityRef | None) -> object:
    if ref is None:
        return None
    return {
        "project_id": str(ref.project_id), "kind": ref.kind.value, "entity_id": str(ref.entity_id),
        "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _ref_from(value: object) -> EntityRef | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "project_id", "kind", "entity_id", "definition_revision_id", "incarnation_id",
    }:
        raise ValueError("stored resource reference has an invalid shape")
    return EntityRef(
        StableId(value["project_id"]), EntityKind(value["kind"]), StableId(value["entity_id"]),
        None if value["definition_revision_id"] is None else StableId(value["definition_revision_id"]),
        None if value["incarnation_id"] is None else StableId(value["incarnation_id"]),
    )


def _context_value(context: ProviderCallContext) -> dict[str, object]:
    return {
        "project_id": str(context.project_id), "actor": _ref_value(context.actor),
        "capability": _ref_value(context.capability), "trusted_context_id": str(context.trusted_context_id),
        "scope_id": str(context.scope_id),
    }


def _context_from(value: object) -> ProviderCallContext:
    if not isinstance(value, dict) or set(value) != {
        "project_id", "actor", "capability", "trusted_context_id", "scope_id",
    }:
        raise ValueError("stored resource provider context has an invalid shape")
    actor, capability = _ref_from(value["actor"]), _ref_from(value["capability"])
    if actor is None or capability is None:
        raise ValueError("stored resource provider context lacks identity")
    return ProviderCallContext(
        StableId(value["project_id"]), actor, capability,
        StableId(value["trusted_context_id"]), StableId(value["scope_id"]),
    )


def _identity_value(identity: ProviderIdentity) -> dict[str, object]:
    return {"provider_id": str(identity.provider_id), "version": identity.version,
            "contract_version": identity.contract_version}


def _identity_from(value: object) -> ProviderIdentity:
    if not isinstance(value, dict) or set(value) != {"provider_id", "version", "contract_version"}:
        raise ValueError("stored resource provider identity has an invalid shape")
    return ProviderIdentity(StableId(value["provider_id"]), value["version"], value["contract_version"])


def _receipt_value(receipt: ProviderReceipt) -> dict[str, object]:
    return {
        "receipt_id": str(receipt.receipt_id), "provider": _identity_value(receipt.provider),
        "correlation_id": str(receipt.correlation_id), "request_digest": receipt.request_digest.hex,
        "provenance_ref": str(receipt.provenance_ref), "observed_at": _iso(receipt.observed_at),
    }


def _receipt_from(value: object) -> ProviderReceipt:
    if not isinstance(value, dict) or set(value) != {
        "receipt_id", "provider", "correlation_id", "request_digest", "provenance_ref", "observed_at",
    }:
        raise ValueError("stored resource provider receipt has an invalid shape")
    from todo_orchestrator.contracts import Sha256Digest
    return ProviderReceipt(
        StableId(value["receipt_id"]), _identity_from(value["provider"]), StableId(value["correlation_id"]),
        Sha256Digest(value["request_digest"]), StableId(value["provenance_ref"]),
        datetime.fromisoformat(value["observed_at"]),
    )


def _permit_value(permit: ResourcePermitRef) -> dict[str, object]:
    return {
        "permit_id": str(permit.permit_id), "resource_class": str(permit.resource_class),
        "scope_id": str(permit.scope_id), "units": permit.units,
        "expires_at": _iso(permit.expires_at), "issuer": _identity_value(permit.issuer),
        "receipt_id": str(permit.receipt_id),
    }


def _permit_from(value: object) -> ResourcePermitRef:
    if not isinstance(value, dict) or set(value) != {
        "permit_id", "resource_class", "scope_id", "units", "expires_at", "issuer", "receipt_id",
    }:
        raise ValueError("stored resource permit reference has an invalid shape")
    return ResourcePermitRef(
        StableId(value["permit_id"]), StableId(value["resource_class"]), StableId(value["scope_id"]),
        value["units"], datetime.fromisoformat(value["expires_at"]), _identity_from(value["issuer"]),
        StableId(value["receipt_id"]),
    )


def _request_value(request: ResourcePermitRequest | ResourcePermitReleaseRequest) -> dict[str, object]:
    common = {
        "kind": "reserve" if isinstance(request, ResourcePermitRequest) else "release",
        "context": _context_value(request.context), "attempt": _ref_value(request.attempt),
        "operation_id": str(request.operation_id), "idempotency_key": str(request.idempotency_key),
        "expected_authority_revision": request.expected_authority_revision,
    }
    if isinstance(request, ResourcePermitRequest):
        return {
            **common, "resource_class": str(request.resource_class), "units": request.units,
            "scope_id": None if request.scope_id is None else str(request.scope_id),
            "lease_id": None if request.lease_id is None else str(request.lease_id),
            "lease_expires_at": None if request.lease_expires_at is None else _iso(request.lease_expires_at),
        }
    return {**common, "permit": _permit_value(request.permit)}


def _request_from(value: object) -> ResourcePermitRequest | ResourcePermitReleaseRequest:
    if not isinstance(value, dict):
        raise ValueError("stored resource permit request is not an object")
    kind = value.get("kind")
    common = {key: value[key] for key in (
        "context", "attempt", "operation_id", "idempotency_key", "expected_authority_revision",
    )}
    attempt = _ref_from(common["attempt"])
    context = _context_from(common["context"])
    if attempt is None:
        raise ValueError("stored resource permit request lacks attempt")
    if kind == "reserve" and set(value) == {
        "kind", "context", "attempt", "operation_id", "idempotency_key", "expected_authority_revision",
        "resource_class", "units", "scope_id", "lease_id", "lease_expires_at",
    }:
        return ResourcePermitRequest(
            context, attempt, StableId(common["operation_id"]), StableId(common["idempotency_key"]),
            StableId(value["resource_class"]), value["units"],
            None if value["scope_id"] is None else StableId(value["scope_id"]),
            common["expected_authority_revision"],
            None if value["lease_id"] is None else StableId(value["lease_id"]),
            None if value["lease_expires_at"] is None else datetime.fromisoformat(value["lease_expires_at"]),
        )
    if kind == "release" and set(value) == {
        "kind", "context", "attempt", "operation_id", "idempotency_key", "expected_authority_revision", "permit",
    }:
        return ResourcePermitReleaseRequest(
            context, attempt, StableId(common["operation_id"]), StableId(common["idempotency_key"]),
            _permit_from(value["permit"]), common["expected_authority_revision"],
        )
    raise ValueError("stored resource permit request has an invalid shape")


def _intent(request: ResourcePermitRequest | ResourcePermitReleaseRequest, *, target: EntityRef,
            run: EntityRef | None, assignment: EntityRef | None, actor: EntityRef,
            lease_id: StableId, lease_expires_at: datetime, original_operation_id: StableId | None) -> dict[str, object]:
    return {
        "format": _FORMAT, "version": _VERSION, "request": _request_value(request),
        "target": _ref_value(target), "run": _ref_value(run), "assignment": _ref_value(assignment),
        "actor": _ref_value(actor), "lease_id": str(lease_id), "lease_expires_at": _iso(lease_expires_at),
        "original_operation_id": None if original_operation_id is None else str(original_operation_id),
    }


def _intent_from(encoded: str) -> tuple[ResourcePermitRequest | ResourcePermitReleaseRequest, dict[str, object]]:
    try:
        value = json.loads(encoded)
        if not isinstance(value, dict) or set(value) != {
            "format", "version", "request", "target", "run", "assignment", "actor", "lease_id",
            "lease_expires_at", "original_operation_id",
        } or value["format"] != _FORMAT or value["version"] != _VERSION:
            raise ValueError("resource intent envelope has an invalid shape")
        if _json(value) != encoded:
            raise ValueError("resource intent envelope is not canonical")
        return _request_from(value["request"]), value
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidAuthorityError(f"stored resource permit intent is invalid: {exc}") from exc


def _scope_id(attempt: EntityRef, target: EntityRef, run: EntityRef | None,
              assignment: EntityRef | None, resource_class: StableId) -> StableId:
    material = _json({
        "attempt": _ref_value(attempt), "target": _ref_value(target), "run": _ref_value(run),
        "assignment": _ref_value(assignment), "resource_class": str(resource_class),
    })
    return _derived_id("resource-scope", material)


def _operation_id(project: StableId, actor: EntityRef, kind: str, key: StableId) -> StableId:
    return _derived_id("resource-op", f"{project}:{actor.entity_id}:{actor.incarnation_id}:{kind}:{key}")


def _phase_key(operation_id: StableId, phase: str) -> StableId:
    return _derived_id("resource-cmd", f"{operation_id}:{phase}")


def _row_view(row: sqlite3.Row, project_id: StableId) -> ResourcePermitOperationView:
    request, intent = _intent_from(row["request_json"])
    digest = provider_request_digest(request)
    if digest.hex != row["request_digest"]:
        raise InvalidAuthorityError("stored resource permit request digest does not match")
    permit = None if row["permit_json"] is None else _permit_from(json.loads(row["permit_json"]))
    if permit is None and isinstance(request, ResourcePermitReleaseRequest):
        # The release intent itself already carries the opaque permit ref. This
        # keeps a crash-after-prepare inspectable before any result is stored.
        permit = request.permit
    receipt_value = None
    inspection_receipt = None
    if row["provider_receipt_json"] is not None:
        envelope = json.loads(row["provider_receipt_json"])
        if not isinstance(envelope, dict) or set(envelope) != {"effect_receipt", "inspection_receipt"}:
            raise InvalidAuthorityError("stored resource provider receipt envelope is invalid")
        receipt_value = None if envelope["effect_receipt"] is None else _receipt_from(envelope["effect_receipt"])
        inspection_receipt = None if envelope["inspection_receipt"] is None else _receipt_from(envelope["inspection_receipt"])
    inspection_state = None
    if row["inspection_json"] is not None:
        observation = json.loads(row["inspection_json"])
        inspection_state = ResourcePermitInspectionState(observation["state"])
    target, run, assignment = (_ref_from(intent[name]) for name in ("target", "run", "assignment"))
    if target is None or not isinstance(request.attempt, EntityRef):
        raise InvalidAuthorityError("resource permit intent lacks exact target or attempt")
    if (target.project_id != project_id or request.attempt.project_id != project_id
            or run is not None and run.kind is not EntityKind.RUN
            or assignment is not None and assignment.kind is not EntityKind.ASSIGNMENT):
        raise InvalidAuthorityError("resource permit intent is outside its project or context")
    return ResourcePermitOperationView(
        StableId(row["operation_id"]), row["operation_kind"], ResourcePermitState(row["state"]),
        request.attempt, target, run, assignment,
        request.resource_class if isinstance(request, ResourcePermitRequest) else permit.resource_class,
        request.units if isinstance(request, ResourcePermitRequest) else permit.units,
        request.scope_id if isinstance(request, ResourcePermitRequest) else permit.scope_id,
        None if permit is None else hashlib.sha256(str(permit.permit_id).encode("ascii")).hexdigest(),
        None if permit is None else permit.expires_at,
        permit.issuer if permit is not None else _identity_from(json.loads(row["provider_identity_json"])),
        receipt_value, None if row["reason_code"] is None else StableId(row["reason_code"]),
        inspection_state, inspection_receipt,
    )


def _provider_request_from_intent(request: ResourcePermitRequest | ResourcePermitReleaseRequest):
    return request


def _exact_requirement(action: StableId, intent: dict[str, object]) -> AuthorizationRequirement:
    target, run, assignment, attempt = (
        _ref_from(intent["target"]), _ref_from(intent["run"]), _ref_from(intent["assignment"]),
        _ref_from(intent["request"]["attempt"]),
    )
    if target is None or attempt is None:
        raise ResourcePermitStateError("resource permit intent lacks exact authorization context")
    return AuthorizationRequirement(action, target, run, assignment, attempt)


class _PrepareHandler:
    kind = _PREPARE_KIND
    command_type = _Prepare

    def __init__(self, service: "ResourcePermitService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Prepare) -> AuthorizationRequirement:
        _, intent = _intent_from(command.intent_json)
        request, _ = _intent_from(command.intent_json)
        action = RESOURCE_RESERVE_ACTION if isinstance(request, ResourcePermitRequest) else RESOURCE_RELEASE_ACTION
        return _exact_requirement(action, intent)

    def canonical_payload(self, command: _Prepare) -> dict[str, object]:
        return {"intent_json": command.intent_json, "request_digest": command.request_digest,
                "created_at": command.created_at}

    def apply(self, context: MutationContext, command: _Prepare) -> CommandEffect:
        request, intent = _intent_from(command.intent_json)
        if (context.actor != _ref_from(intent["actor"])
                or provider_request_digest(request).hex != command.request_digest
                or request.context.actor != context.actor
                or request.expected_authority_revision != context.starting_revision):
            raise ResourcePermitDeniedError("resource permit intent differs from the authenticated command")
        attempt, row = _stored_attempt(context._connection, context.project, request.attempt)
        self.service._validate_attempt(
            intent, attempt, row, require_live=isinstance(request, ResourcePermitRequest),
        )
        existing = context._connection.execute(
            "SELECT request_digest, request_json FROM resource_permit_operations WHERE operation_id = ?",
            (str(request.operation_id),),
        ).fetchone()
        if existing is not None:
            if (existing["request_digest"] != command.request_digest
                    or existing["request_json"] != command.intent_json):
                raise ResourcePermitDeniedError("resource permit operation ID is already bound to another intent")
            return CommandEffect(False, {"operation_id": str(request.operation_id), "state": "prepared"})
        if context._connection.execute(
            "SELECT 1 FROM external_operations WHERE idempotency_key = ?", (str(request.idempotency_key),),
        ).fetchone() is not None:
            raise ResourcePermitDeniedError("resource permit idempotency key is already in use")
        context.execute(
            "INSERT INTO external_operations(operation_id, kind, idempotency_key, request_digest, state, "
            "created_at, updated_at, attempt_id, external_ref, receipt_digest) "
            "VALUES (?, 'todo.resource.permit', ?, ?, 'prepared', ?, ?, ?, NULL, NULL)",
            (str(request.operation_id), str(request.idempotency_key), command.request_digest,
             command.created_at, command.created_at, str(request.attempt.entity_id)),
        )
        target = _ref_from(intent["target"])
        context.execute(
            "INSERT INTO resource_permit_operations(operation_id, operation_kind, attempt_id, work_item_id, "
            "definition_revision_id, run_id, assignment_id, actor_id, actor_incarnation_id, resource_class_id, "
            "units, scope_id, idempotency_key, request_json, request_digest, expected_authority_revision, "
            "original_operation_id, state, permit_json, provider_receipt_json, inspection_json, reason_code, "
            "provider_identity_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "'prepared', NULL, NULL, NULL, NULL, ?, ?, ?)",
            (str(request.operation_id), "reserve" if isinstance(request, ResourcePermitRequest) else "release",
             str(request.attempt.entity_id), str(target.entity_id), str(target.definition_revision_id),
             None if intent["run"] is None else str(_ref_from(intent["run"]).entity_id),
             None if intent["assignment"] is None else str(_ref_from(intent["assignment"]).entity_id),
             str(context.actor.entity_id), str(context.actor.incarnation_id),
             str(request.resource_class if isinstance(request, ResourcePermitRequest) else request.permit.resource_class),
             request.units if isinstance(request, ResourcePermitRequest) else request.permit.units,
             str(request.scope_id if isinstance(request, ResourcePermitRequest) else request.permit.scope_id),
             str(request.idempotency_key), command.intent_json, command.request_digest,
             request.expected_authority_revision,
             None if intent["original_operation_id"] is None else intent["original_operation_id"],
             _json(_identity_value(self.service.provider_identity)), command.created_at, command.created_at),
        )
        return CommandEffect(True, {"operation_id": str(request.operation_id), "state": "prepared"},
                             "todo.resource.permit.prepared", {
                                 "operation_id": str(request.operation_id), "operation_kind":
                                 "reserve" if isinstance(request, ResourcePermitRequest) else "release",
                                 "request_digest": command.request_digest,
                                 "attempt_id": str(request.attempt.entity_id),
                                 "target": _ref_value(target),
                             })


class _TransitionHandler:
    kind = _TRANSITION_KIND
    command_type = _Transition

    def __init__(self, service: "ResourcePermitService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Transition) -> AuthorizationRequirement:
        _, intent = _intent_from(command.intent_json)
        return _exact_requirement(command.action, intent)

    def canonical_payload(self, command: _Transition) -> dict[str, object]:
        return {
            "operation_id": str(command.operation_id), "intent_json": command.intent_json,
            "expected_state": command.expected_state, "next_state": command.next_state,
            "external_state": command.external_state, "action": str(command.action),
            "permit_json": command.permit_json, "provider_receipt_json": command.provider_receipt_json,
            "inspection_json": command.inspection_json, "receipt_digest": command.receipt_digest,
            "reason_code": command.reason_code, "updated_at": command.updated_at,
        }

    def apply(self, context: MutationContext, command: _Transition) -> CommandEffect:
        request, intent = _intent_from(command.intent_json)
        if request.operation_id != command.operation_id or request.context.project_id != context.project.project_id:
            raise ResourcePermitDeniedError("resource permit transition targets another operation")
        row = context._connection.execute(
            "SELECT r.state, r.request_json, r.request_digest, e.state AS external_state, e.created_at "
            "FROM resource_permit_operations AS r JOIN external_operations AS e USING(operation_id) "
            "WHERE r.operation_id = ?", (str(command.operation_id),),
        ).fetchone()
        if (row is None or row["request_json"] != command.intent_json
                or row["request_digest"] != provider_request_digest(request).hex):
            raise ResourcePermitStateError("durable permit request differs from its immutable intent")
        if row["state"] != command.expected_state:
            raise ResourcePermitStateError(f"resource permit is {row['state']}, expected {command.expected_state}")
        self.service._validate_transition_receipt_times(command, row["created_at"])
        if (command.expected_state == ResourcePermitState.NOT_APPLIED.value
                and command.next_state == ResourcePermitState.EXECUTING.value):
            expected_action = (RESOURCE_RESERVE_ACTION if isinstance(request, ResourcePermitRequest)
                               else RESOURCE_RELEASE_ACTION)
            if command.action != expected_action or row["external_state"] != "not_applied":
                raise ResourcePermitStateError("retry no-effect state or action no longer matches the durable operation")
            self.service._validate_retry_inspection(context, request, command)
        attempt, attempt_row = _stored_attempt(context._connection, context.project, request.attempt)
        self.service._validate_attempt(
            intent, attempt, attempt_row,
            require_live=(command.action == RESOURCE_RESERVE_ACTION and command.next_state == "executing"),
        )
        if (command.next_state == ResourcePermitState.RELEASED.value
                and isinstance(request, ResourcePermitReleaseRequest)):
            original_id = intent["original_operation_id"]
            if original_id is None:
                raise ResourcePermitStateError("only a release operation can resolve a held permit")
            original = context._connection.execute(
                "SELECT r.state, r.permit_json, r.request_json, r.actor_id, r.actor_incarnation_id, "
                "e.state AS external_state "
                "FROM resource_permit_operations AS r JOIN external_operations AS e USING(operation_id) "
                "WHERE r.operation_id = ?", (original_id,),
            ).fetchone()
            if original is not None:
                original_request, original_intent = _intent_from(original["request_json"])
            else:
                original_request, original_intent = None, None
            if (original is None or original["state"] != ResourcePermitState.HELD.value
                    or original["external_state"] != "observed" or original["permit_json"] is None
                    or not isinstance(original_request, ResourcePermitRequest)
                    or original_request.attempt != request.attempt
                    or _ref_from(original_intent["actor"]) != context.actor
                    or original["actor_id"] != str(context.actor.entity_id)
                    or original["actor_incarnation_id"] != str(context.actor.incarnation_id)
                    or _permit_from(json.loads(original["permit_json"])) != request.permit):
                raise ResourcePermitStateError("release no longer matches the exact unresolved held permit")
        elif (command.next_state == ResourcePermitState.RELEASED.value
              and isinstance(request, ResourcePermitRequest)):
            if command.inspection_json is None or command.permit_json is None:
                raise ResourcePermitStateError("a reserved permit can be released only by exact inspection")
            inspection = json.loads(command.inspection_json)
            if inspection.get("state") != ResourcePermitInspectionState.RELEASED.value:
                raise ResourcePermitStateError("provider inspection does not prove this permit was released")
            permit = _permit_from(json.loads(command.permit_json))
            self.service._validate_permit(request, intent, permit, None, now=_now(self.service.clock),
                                          allow_expired=True)
        elif command.next_state == ResourcePermitState.RELEASED.value:
            raise ResourcePermitStateError("released state has no supported resource request")
        context.execute(
            "UPDATE resource_permit_operations SET state = ?, permit_json = COALESCE(?, permit_json), "
            "provider_receipt_json = COALESCE(?, provider_receipt_json), inspection_json = COALESCE(?, inspection_json), "
            "reason_code = ?, updated_at = ? WHERE operation_id = ? AND state = ?",
            (command.next_state, command.permit_json, command.provider_receipt_json, command.inspection_json,
             command.reason_code, command.updated_at, str(command.operation_id), command.expected_state),
        )
        external = context._connection.execute(
            "SELECT state FROM external_operations WHERE operation_id = ?", (str(command.operation_id),),
        ).fetchone()
        if external is None:
            raise ResourcePermitStateError("resource external-operation ledger row is missing")
        if external["state"] != command.external_state:
            receipt_digest = command.receipt_digest
            if command.external_state in {"observed", "finalized"}:
                if receipt_digest is None:
                    raise ResourcePermitObservationMismatchError("definitive permit result lacks a receipt digest")
                if external["state"] in {"executing", "unknown", "not_applied"}:
                    context.execute(
                        "UPDATE external_operations SET state = 'observed', receipt_digest = ?, updated_at = ? "
                        "WHERE operation_id = ? AND state = ?",
                        (receipt_digest, command.updated_at, str(command.operation_id), external["state"]),
                    )
                if command.external_state == "finalized":
                    context.execute(
                        "UPDATE external_operations SET state = 'finalized', updated_at = ? "
                        "WHERE operation_id = ? AND state = 'observed'",
                        (command.updated_at, str(command.operation_id)),
                    )
            else:
                context.execute(
                    "UPDATE external_operations SET state = ?, receipt_digest = ?, updated_at = ? "
                    "WHERE operation_id = ? AND state = ?",
                    (command.external_state, receipt_digest, command.updated_at,
                     str(command.operation_id), external["state"]),
                )
        if (command.next_state == ResourcePermitState.RELEASED.value
                and isinstance(request, ResourcePermitReleaseRequest)):
            original_id = intent["original_operation_id"]
            context.execute(
                "UPDATE resource_permit_operations SET state = 'released', updated_at = ? "
                "WHERE operation_id = ? AND state = 'held'",
                (command.updated_at, original_id),
            )
            context.execute(
                "UPDATE external_operations SET state = 'finalized', updated_at = ? "
                "WHERE operation_id = ? AND state = 'observed'",
                (command.updated_at, original_id),
            )
        return CommandEffect(True, {"operation_id": str(command.operation_id), "state": command.next_state},
                             "todo.resource.permit." + command.next_state, {
                                 "operation_id": str(command.operation_id), "state": command.next_state,
                                 "request_digest": row["request_digest"],
                                 "inspection": command.inspection_json is not None,
                                 "reason_code": command.reason_code,
                             })


class ResourcePermitService:
    def __init__(self, auth: AuthorityAuthService, provider, *, provider_identity: ProviderIdentity,
                 clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not isinstance(provider_identity, ProviderIdentity):
            raise TypeError("provider_identity must be a ProviderIdentity")
        if not all(callable(getattr(provider, method, None)) for method in ("reserve", "release", "inspect")):
            raise TypeError("resource permit provider must implement reserve, release, and inspect")
        self.auth = auth
        self.provider = provider
        self.provider_identity = provider_identity
        self.clock = clock or auth.clock
        for handler in (_PrepareHandler(self), _TransitionHandler(self)):
            try:
                self.auth.dispatcher.register(handler)
            except DuplicateCommandHandlerError:
                binding = self.auth.dispatcher._by_type.get(handler.command_type)
                if binding is None or type(binding.handler) is not type(handler):
                    raise
                if binding.handler.service.provider_identity != provider_identity:
                    raise ValueError("resource permit handlers are bound to another provider identity")

    def _check_authority(self, authority: SQLiteAuthority, *, writable: bool = True) -> None:
        if not isinstance(authority, SQLiteAuthority) or (writable and authority.readonly):
            raise TypeError("resource permit authority has the wrong access mode")

    def _read_attempt(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef,
                      action: StableId) -> tuple[EntityRef, StableId, object, object]:
        actor, capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        with authority.read_transaction() as connection:
            attempt, row = _stored_attempt(connection, authority.project, attempt_ref)
            requirement = AuthorizationRequirement(action, attempt.work_item, attempt.run,
                                                     attempt.assignment, attempt.ref)
            self.auth._authorize_capability(connection, authority.project, _token_digest(bearer_token), actor,
                                             requirement)
        if attempt.actor != actor:
            raise ResourcePermitDeniedError("resource permit action requires the live attempt owner")
        return actor, capability_id, attempt, row

    def _validate_attempt(self, intent: dict[str, object], attempt, row: sqlite3.Row,
                          *, require_live: bool) -> None:
        attempt_ref = _ref_from(intent["request"]["attempt"])
        target, run, assignment = (_ref_from(intent[name]) for name in ("target", "run", "assignment"))
        if (attempt_ref != attempt.ref or target != attempt.work_item or run != attempt.run
                or assignment != attempt.assignment or _ref_from(intent["actor"]) != attempt.actor
                or row["lease_id"] != intent["lease_id"]):
            raise ResourcePermitDeniedError("resource permit no longer matches the exact attempt lease and target")
        if attempt.lease is None or attempt.lease.lease_id != StableId(intent["lease_id"]):
            raise ResourcePermitDeniedError("resource permit attempt lease is no longer current")
        expires = datetime.fromisoformat(intent["lease_expires_at"])
        if require_live and (attempt.lease.expires_at != expires or row["lease_expires_at"] != _iso(expires)):
            raise ResourcePermitDeniedError("resource permit lease expiry changed")
        if not require_live and (attempt.lease.expires_at < expires
                                 or datetime.fromisoformat(row["lease_expires_at"]) < expires):
            raise ResourcePermitDeniedError("resource permit lease was shortened or replaced")
        if require_live and (attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE}
                             or attempt.lease.expires_at <= _now(self.clock)):
            raise ResourcePermitDeniedError("resource permit effect requires a live unexpired attempt")

    @staticmethod
    def _intent_row(authority: SQLiteAuthority, operation_id: StableId) -> sqlite3.Row:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT r.*, e.state AS external_state FROM resource_permit_operations AS r "
                "JOIN external_operations AS e USING(operation_id) WHERE r.operation_id = ?",
                (str(operation_id),),
            ).fetchone()
        if row is None:
            raise ResourcePermitNotFoundError("resource permit operation was not found")
        return row

    def _view(self, authority: SQLiteAuthority, operation_id: StableId) -> ResourcePermitOperationView:
        return _row_view(self._intent_row(authority, operation_id), authority.project.project_id)

    def _scope(self, attempt, resource_class: StableId) -> StableId:
        return _scope_id(attempt.ref, attempt.work_item, attempt.run, attempt.assignment, resource_class)

    def _context(self, actor: EntityRef, capability_id: StableId, operation_id: StableId,
                 scope_id: StableId) -> ProviderCallContext:
        project_id = actor.project_id
        return ProviderCallContext(
            project_id, actor, EntityRef(project_id, EntityKind.CAPABILITY, capability_id),
            _derived_id("resource-context", str(operation_id)), scope_id,
        )

    def _prepare(self, authority: SQLiteAuthority, bearer_token: str,
                 request: ResourcePermitRequest | ResourcePermitReleaseRequest, *,
                 intent_json: str, expected_revision: int) -> CommandResult:
        return self.auth.execute(
            authority, bearer_token,
            _Prepare(intent_json, provider_request_digest(request).hex, _iso(_now(self.clock))),
            idempotency_key=_phase_key(request.operation_id, "prepare"),
            expected_revision=expected_revision,
        )

    def _transition(self, authority: SQLiteAuthority, bearer_token: str, request,
                    intent_json: str, expected_state: ResourcePermitState,
                    next_state: ResourcePermitState, external_state: str, action: StableId, *,
                    phase: str, expected_revision: int | None, permit: ResourcePermitRef | None = None,
                    effect_receipt: ProviderReceipt | None = None,
                    inspection: dict[str, object] | None = None,
                    inspection_receipt: ProviderReceipt | None = None,
                    reason: StableId | None = None) -> CommandResult:
        receipt_json = None
        receipt_digest = None
        if effect_receipt is not None or inspection_receipt is not None:
            receipt_json = _json({
                "effect_receipt": None if effect_receipt is None else _receipt_value(effect_receipt),
                "inspection_receipt": None if inspection_receipt is None else _receipt_value(inspection_receipt),
            })
            # The ledger digest binds both receipts without relabeling a query receipt as an effect receipt.
            receipt_digest = hashlib.sha256(receipt_json.encode("ascii")).hexdigest()
        command = _Transition(
            request.operation_id, intent_json, expected_state.value, next_state.value, external_state,
            action, None if permit is None else _json(_permit_value(permit)), receipt_json,
            None if inspection is None else _json(inspection), receipt_digest,
            None if reason is None else str(reason), _iso(_now(self.clock)),
        )
        return self.auth.execute(
            authority, bearer_token, command,
            idempotency_key=_phase_key(request.operation_id, phase), expected_revision=expected_revision,
        )

    def _validate_receipt(
        self, result: ProviderResult, request, *, now: datetime, earliest: datetime,
    ) -> ProviderReceipt:
        receipt = result.receipt
        request_digest = provider_request_digest(request)
        if (result.provider != self.provider_identity or result.correlation_id != request.operation_id
                or not isinstance(receipt, ProviderReceipt) or receipt.provider != self.provider_identity
                or receipt.correlation_id != request.operation_id or receipt.request_digest != request_digest
                or receipt.provenance_ref != request.operation_id):
            raise ResourcePermitObservationMismatchError("provider receipt does not bind the exact permit intent")
        observed = _utc(receipt.observed_at)
        if observed > now:
            raise ResourcePermitObservationMismatchError("provider receipt is from the future")
        if observed < _utc(earliest, "operation creation timestamp"):
            raise ResourcePermitObservationMismatchError("provider receipt predates the permit operation")
        return receipt

    def _validate_transition_receipt_times(self, command: _Transition, created_at: str) -> None:
        """Recheck receipt time bounds in the authority writer transaction."""
        if command.provider_receipt_json is None:
            return
        try:
            envelope = json.loads(command.provider_receipt_json)
            if (not isinstance(envelope, dict)
                    or set(envelope) != {"effect_receipt", "inspection_receipt"}):
                raise ValueError("provider receipt envelope has an invalid shape")
            earliest = datetime.fromisoformat(created_at)
            now = _now(self.clock)
            for key in ("effect_receipt", "inspection_receipt"):
                raw = envelope[key]
                if raw is None:
                    continue
                receipt = _receipt_from(raw)
                if receipt.observed_at > now or receipt.observed_at < earliest:
                    raise ValueError("provider receipt timestamp is outside the operation interval")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ResourcePermitObservationMismatchError(
                "provider receipt time does not bind the permit operation"
            ) from exc

    def _inspection_request(self, actor: EntityRef, capability_id: StableId,
                            request: ResourcePermitRequest | ResourcePermitReleaseRequest,
                            authority_revision: int) -> EffectInspectionRequest:
        query_id = _derived_id("resource-inspect", f"{request.operation_id}:{authority_revision}")
        context = self._context(actor, capability_id, query_id, request.context.scope_id)
        return EffectInspectionRequest(
            context, request.operation_id, request.idempotency_key,
            provider_request_digest(request), query_id,
            resource_permit_request=request if isinstance(request, ResourcePermitRequest) else None,
            resource_permit_release_request=request if isinstance(request, ResourcePermitReleaseRequest) else None,
        )

    def _validate_retry_inspection(self, context: MutationContext,
                                   request: ResourcePermitRequest | ResourcePermitReleaseRequest,
                                   command: _Transition) -> None:
        """Recheck the definitive no-effect proof in the writer transaction."""
        try:
            value = json.loads(command.inspection_json) if command.inspection_json is not None else None
            receipt_envelope = (json.loads(command.provider_receipt_json)
                                if command.provider_receipt_json is not None else None)
            if (not isinstance(value, dict) or set(value) != {
                    "state", "permit", "query_correlation_id", "query_request_digest", "inspection_receipt"
            } or not isinstance(receipt_envelope, dict)
                    or set(receipt_envelope) != {"effect_receipt", "inspection_receipt"}
                    or receipt_envelope["effect_receipt"] is not None):
                raise ValueError("retry proof envelope is incomplete")
            expected_state = (ResourcePermitInspectionState.ABSENT
                              if isinstance(request, ResourcePermitRequest)
                              else ResourcePermitInspectionState.HELD)
            if value["state"] != expected_state.value:
                raise ValueError("retry proof does not establish that the original effect is absent")
            if isinstance(request, ResourcePermitRequest):
                if value["permit"] is not None:
                    raise ValueError("absent reservation inspection contains a permit")
            elif _permit_from(value["permit"]) != request.permit:
                raise ValueError("held permit inspection differs from the original release request")

            capability_id = context.authorized_capability_id
            if not isinstance(capability_id, StableId):
                raise ValueError("retry proof lacks the current authenticated capability")
            query = self._inspection_request(
                context.actor, capability_id, request, context.starting_revision,
            )
            if (value["query_correlation_id"] != str(query.correlation_id)
                    or value["query_request_digest"] != provider_request_digest(query).hex):
                raise ValueError("retry proof is not bound to this authority snapshot")
            receipt = _receipt_from(value["inspection_receipt"])
            envelope_receipt = (_receipt_from(receipt_envelope["inspection_receipt"])
                                if receipt_envelope["inspection_receipt"] is not None else None)
            if (receipt != envelope_receipt or receipt.provider != self.provider_identity
                    or receipt.correlation_id != query.correlation_id
                    or receipt.request_digest != provider_request_digest(query)
                    or receipt.provenance_ref != request.operation_id
                    or receipt.observed_at > _now(self.clock)):
                raise ValueError("retry inspection receipt does not bind the exact query")
            created_at = context._connection.execute(
                "SELECT created_at FROM external_operations WHERE operation_id = ?",
                (str(request.operation_id),),
            ).fetchone()
            if created_at is None or receipt.observed_at < datetime.fromisoformat(created_at[0]):
                raise ValueError("retry inspection predates its original operation")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ResourcePermitObservationMismatchError(
                "fresh provider inspection does not prove a safe same-request retry"
            ) from exc

    def _reserve_effect_result(self, request: ResourcePermitRequest, *, earliest: datetime):
        try:
            result = self.provider.reserve(request)
        except Exception:
            result = None
        now = _now(self.clock)
        if not isinstance(result, ProviderResult):
            next_state, ext_state, reason, permit, receipt = (
                ResourcePermitState.UNKNOWN, "unknown", StableId("provider_result_unavailable"), None, None,
            )
        elif result.status is ProviderStatus.UNAVAILABLE:
            next_state, ext_state, reason, permit, receipt = (
                ResourcePermitState.UNKNOWN, "unknown", result.reason_code, None, None,
            )
        elif result.status is ProviderStatus.UNKNOWN:
            next_state, ext_state, reason, permit, receipt = (
                ResourcePermitState.UNKNOWN, "unknown", result.reason_code, None, None,
            )
        elif result.status is ProviderStatus.OBSERVED_FAILURE:
            try:
                receipt = self._validate_receipt(result, request, now=now, earliest=earliest)
                permit = None
                next_state, ext_state, reason = ResourcePermitState.FAILED, "failed", result.reason_code
            except ResourcePermitObservationMismatchError:
                next_state, ext_state, reason, permit, receipt = (
                    ResourcePermitState.UNKNOWN, "unknown", StableId("provider_receipt_mismatch"), None, None,
                )
        else:
            try:
                receipt = self._validate_receipt(result, request, now=now, earliest=earliest)
                permit = result.value
                if not isinstance(permit, ResourcePermitRef):
                    raise ValueError("provider omitted typed permit reference")
                if (request.scope_id is None or request.lease_expires_at is None
                        or permit.resource_class != request.resource_class or permit.scope_id != request.scope_id
                        or permit.units != request.units or permit.issuer != self.provider_identity
                        or permit.receipt_id != receipt.receipt_id
                        or permit.expires_at <= now or permit.expires_at > request.lease_expires_at):
                    raise ValueError("permit identity, expiry, or receipt differs from the exact lease-bound request")
                next_state, ext_state, reason = ResourcePermitState.HELD, "observed", None
            except (ResourcePermitObservationMismatchError, TypeError, ValueError):
                next_state, ext_state, reason, permit, receipt = (
                    ResourcePermitState.UNKNOWN, "unknown", StableId("provider_result_mismatch"), None, None,
                )
        return next_state, ext_state, reason, permit, receipt

    def _perform_reserve(self, authority: SQLiteAuthority, bearer_token: str, request: ResourcePermitRequest,
                         intent_json: str, *, revision: int) -> ResourcePermitOperationView:
        started = self._transition(
            authority, bearer_token, request, intent_json, ResourcePermitState.PREPARED,
            ResourcePermitState.EXECUTING, "executing", RESOURCE_RESERVE_ACTION,
            phase="start", expected_revision=revision,
        )
        if started.replayed:
            return self._view(authority, request.operation_id)
        next_state, ext_state, reason, permit, receipt = self._reserve_effect_result(
            request, earliest=self._operation_created_at(authority, request.operation_id),
        )
        return self._finalize_external_call(
            authority, bearer_token, request, intent_json, next_state, ext_state,
            RESOURCE_RESERVE_ACTION, revision=self.auth._revision(authority, None),
            permit=permit, receipt=receipt, reason=reason, phase="reserve-result",
        )

    def _finalize_external_call(self, authority: SQLiteAuthority, bearer_token: str, request,
                                intent_json: str, state: ResourcePermitState, external_state: str,
                                action: StableId, *, revision: int, permit: ResourcePermitRef | None,
                                receipt: ProviderReceipt | None, reason: StableId | None,
                                phase: str, inspection: dict[str, object] | None = None,
                                inspection_receipt: ProviderReceipt | None = None) -> ResourcePermitOperationView:
        self._transition(
            authority, bearer_token, request, intent_json, ResourcePermitState.EXECUTING,
            state, external_state, action, phase=phase, expected_revision=revision,
            permit=permit, effect_receipt=receipt, inspection=inspection,
            inspection_receipt=inspection_receipt, reason=reason,
        )
        if state is ResourcePermitState.HELD:
            # Keep the operation in the shared ledger as observed: a held permit
            # blocks attempt finish until an independently authorized release.
            pass
        return self._view(authority, request.operation_id)

    def reserve(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef,
                resource_class: StableId, units: int, *, idempotency_key: StableId,
                expected_revision: int | None = None) -> ResourcePermitOperationView:
        self._check_authority(authority)
        if not isinstance(attempt_ref, EntityRef) or attempt_ref.kind is not EntityKind.ATTEMPT:
            raise TypeError("attempt_ref must identify an attempt")
        if not isinstance(resource_class, StableId) or not isinstance(idempotency_key, StableId):
            raise TypeError("resource_class and idempotency_key must be StableIds")
        if type(units) is not int or units < 1:
            raise ValueError("units must be positive")
        actor, capability_id, attempt, attempt_row = self._read_attempt(
            authority, bearer_token, attempt_ref, RESOURCE_RESERVE_ACTION,
        )
        operation_id = _operation_id(authority.project.project_id, actor, "reserve", idempotency_key)
        existing = self._maybe_row(authority, operation_id)
        if existing is not None:
            request, intent = _intent_from(existing["request_json"])
            if (not isinstance(request, ResourcePermitRequest) or request.attempt != attempt_ref
                    or request.resource_class != resource_class or request.units != units):
                raise ResourcePermitDeniedError("resource permit idempotency key is bound to another intent")
            self._authorize_current(authority, bearer_token, actor, _exact_requirement(RESOURCE_RESERVE_ACTION, intent))
            return _row_view(existing, authority.project.project_id)
        current_revision = self.auth._revision(authority, expected_revision)
        if (attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE} or attempt.lease is None
                or attempt.lease.expires_at <= _now(self.clock)):
            raise ResourcePermitDeniedError("resource permit reservation requires a live unexpired attempt")
        scope_id = self._scope(attempt, resource_class)
        context = self._context(actor, capability_id, operation_id, scope_id)
        request = ResourcePermitRequest(
            context, attempt.ref, operation_id, idempotency_key, resource_class, units, scope_id,
            current_revision, attempt.lease.lease_id, attempt.lease.expires_at,
        )
        intent = _intent(request, target=attempt.work_item, run=attempt.run,
                         assignment=attempt.assignment, actor=actor, lease_id=attempt.lease.lease_id,
                         lease_expires_at=attempt.lease.expires_at, original_operation_id=None)
        encoded = _json(intent)
        result = self._prepare(authority, bearer_token, request, intent_json=encoded,
                               expected_revision=current_revision)
        if result.replayed:
            return self._view(authority, operation_id)
        return self._perform_reserve(authority, bearer_token, request, encoded,
                                     revision=result.receipt.semantic_revision)

    def release(self, authority: SQLiteAuthority, bearer_token: str, operation_ref: EntityRef | StableId, *,
                idempotency_key: StableId, expected_revision: int | None = None) -> ResourcePermitOperationView:
        self._check_authority(authority)
        operation_id = self._operation_selector(authority, operation_ref)
        reserve_row = self._intent_row(authority, operation_id)
        reserve_request, reserve_intent = _intent_from(reserve_row["request_json"])
        if not isinstance(reserve_request, ResourcePermitRequest):
            raise ResourcePermitStateError("resource release must reference a reservation operation")
        actor, capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        requirement = _exact_requirement(RESOURCE_RELEASE_ACTION, reserve_intent)
        self._authorize_current(authority, bearer_token, actor, requirement)
        if actor != _ref_from(reserve_intent["actor"]):
            raise ResourcePermitDeniedError("resource release must be authorized by the original permit owner")
        release_operation_id = _operation_id(authority.project.project_id, actor, "release", idempotency_key)
        existing = self._maybe_row(authority, release_operation_id)
        if existing is not None:
            request, intent = _intent_from(existing["request_json"])
            original_request, _original_intent = _intent_from(reserve_row["request_json"])
            if (not isinstance(request, ResourcePermitReleaseRequest)
                    or intent["original_operation_id"] != str(operation_id)
                    or not isinstance(original_request, ResourcePermitRequest)
                    or request.attempt != original_request.attempt):
                raise ResourcePermitDeniedError("resource release idempotency key is bound to another permit")
            self._authorize_current(authority, bearer_token, actor,
                                    _exact_requirement(RESOURCE_RELEASE_ACTION, intent))
            return _row_view(existing, authority.project.project_id)
        if reserve_row["state"] != ResourcePermitState.HELD.value or reserve_row["permit_json"] is None:
            raise ResourcePermitStateError("only a durably held permit can be released")
        permit = _permit_from(json.loads(reserve_row["permit_json"]))
        revision = self.auth._revision(authority, expected_revision)
        current_attempt, current_row = self._load_attempt(authority, reserve_request.attempt)
        self._validate_attempt(reserve_intent, current_attempt, current_row, require_live=False)
        context = self._context(actor, capability_id, release_operation_id, permit.scope_id)
        request = ResourcePermitReleaseRequest(
            context, reserve_request.attempt, release_operation_id, idempotency_key, permit, revision,
        )
        intent = _intent(request, target=_ref_from(reserve_intent["target"]),
                         run=_ref_from(reserve_intent["run"]), assignment=_ref_from(reserve_intent["assignment"]),
                         actor=actor, lease_id=current_attempt.lease.lease_id,
                         lease_expires_at=current_attempt.lease.expires_at,
                         original_operation_id=operation_id)
        encoded = _json(intent)
        result = self._prepare(authority, bearer_token, request, intent_json=encoded, expected_revision=revision)
        if result.replayed:
            return self._view(authority, release_operation_id)
        started = self._transition(
            authority, bearer_token, request, encoded, ResourcePermitState.PREPARED,
            ResourcePermitState.EXECUTING, "executing", RESOURCE_RELEASE_ACTION,
            phase="start", expected_revision=result.receipt.semantic_revision,
        )
        if started.replayed:
            return self._view(authority, release_operation_id)
        try:
            provider_result = self.provider.release(request)
        except Exception:
            provider_result = None
        now = _now(self.clock)
        state, external_state, reason, receipt = self._effect_release_result(
            provider_result, request, now,
            earliest=self._operation_created_at(authority, release_operation_id),
        )
        result_view = self._finalize_external_call(
            authority, bearer_token, request, encoded, state, external_state,
            RESOURCE_RELEASE_ACTION, revision=self.auth._revision(authority, None),
            permit=permit, receipt=receipt, reason=reason, phase="release-result",
        )
        if state is ResourcePermitState.RELEASED:
            return self._view(authority, release_operation_id)
        return result_view

    def _effect_release_result(self, result, request, now, *, earliest: datetime):
        if not isinstance(result, ProviderResult):
            return ResourcePermitState.UNKNOWN, "unknown", StableId("provider_result_unavailable"), None
        if result.status is ProviderStatus.UNAVAILABLE:
            return ResourcePermitState.UNKNOWN, "unknown", result.reason_code, None
        if result.status is ProviderStatus.UNKNOWN:
            return ResourcePermitState.UNKNOWN, "unknown", result.reason_code, None
        try:
            receipt = self._validate_receipt(result, request, now=now, earliest=earliest)
        except ResourcePermitObservationMismatchError:
            return ResourcePermitState.UNKNOWN, "unknown", StableId("provider_receipt_mismatch"), None
        value = result.value
        if (result.status is ProviderStatus.OBSERVED_SUCCESS and isinstance(value, ResourcePermitRelease)
                and value.operation_id == request.operation_id and value.permit_id == request.permit.permit_id
                and value.released is True):
            return ResourcePermitState.RELEASED, "finalized", None, receipt
        if result.status is ProviderStatus.OBSERVED_FAILURE:
            return ResourcePermitState.FAILED, "failed", result.reason_code, receipt
        if isinstance(value, ResourcePermitRelease) and value.released is False:
            return ResourcePermitState.FAILED, "failed", StableId("permit_release_not_confirmed"), receipt
        return ResourcePermitState.UNKNOWN, "unknown", StableId("provider_result_mismatch"), None

    def _maybe_row(self, authority: SQLiteAuthority, operation_id: StableId) -> sqlite3.Row | None:
        with authority.read_transaction() as connection:
            return connection.execute(
                "SELECT r.*, e.state AS external_state FROM resource_permit_operations AS r "
                "JOIN external_operations AS e USING(operation_id) WHERE r.operation_id = ?",
                (str(operation_id),),
            ).fetchone()

    def _operation_created_at(self, authority: SQLiteAuthority, operation_id: StableId) -> datetime:
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT created_at FROM external_operations WHERE operation_id = ?",
                (str(operation_id),),
            ).fetchone()
        if row is None:
            raise ResourcePermitNotFoundError("resource permit operation does not exist")
        try:
            return _utc(datetime.fromisoformat(row["created_at"]))
        except (TypeError, ValueError) as exc:
            raise ResourcePermitStateError("resource permit operation timestamp is malformed") from exc

    def _load_attempt(self, authority: SQLiteAuthority, attempt_ref: EntityRef):
        with authority.read_transaction() as connection:
            return _stored_attempt(connection, authority.project, attempt_ref)

    def _authorize_current(self, authority: SQLiteAuthority, bearer_token: str, actor: EntityRef,
                           requirement: AuthorizationRequirement) -> None:
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, _token_digest(bearer_token), actor,
                                            requirement)

    def _operation_selector(self, authority: SQLiteAuthority, value: EntityRef | StableId) -> StableId:
        if isinstance(value, EntityRef):
            if value.kind is not EntityKind.EXTERNAL_OPERATION or value.project_id != authority.project.project_id:
                raise TypeError("operation_ref must be a project-local external-operation reference")
            return value.entity_id
        if not isinstance(value, StableId):
            raise TypeError("operation selector must be an external operation EntityRef or StableId")
        return value

    def _inspect_result(self, authority: SQLiteAuthority, bearer_token: str, operation_id: StableId,
                        action: StableId, *, expected_revision: int | None = None) -> tuple[
                            ResourcePermitOperationView, ResourcePermitInspection | None,
                            ProviderReceipt | None, EffectInspectionRequest,
                        ]:
        row = self._intent_row(authority, operation_id)
        request, intent = _intent_from(row["request_json"])
        actor, capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        requirement = _exact_requirement(action, intent)
        self._authorize_current(authority, bearer_token, actor, requirement)
        revision = self.auth._revision(authority, expected_revision)
        inspection_request = self._inspection_request(actor, capability_id, request, revision)
        try:
            result = self.provider.inspect(inspection_request)
        except Exception:
            result = None
        view = _row_view(row, authority.project.project_id)
        if not isinstance(result, ProviderResult) or result.status is not ProviderStatus.OBSERVED_SUCCESS:
            return view, None, None, inspection_request
        receipt = result.receipt
        if (result.provider != self.provider_identity or result.correlation_id != inspection_request.correlation_id
                or receipt is None or receipt.provider != self.provider_identity
                or receipt.correlation_id != inspection_request.correlation_id
                or receipt.request_digest != provider_request_digest(inspection_request)
                or receipt.provenance_ref != request.operation_id or receipt.observed_at > _now(self.clock)
                or receipt.observed_at < datetime.fromisoformat(row["created_at"])):
            raise ResourcePermitObservationMismatchError("resource inspection receipt does not bind the exact query")
        observed = result.value
        if not isinstance(observed, ResourcePermitInspection) or observed.operation_id != request.operation_id:
            raise ResourcePermitObservationMismatchError("resource inspection returned another operation")
        if observed.state is ResourcePermitInspectionState.ABSENT and observed.permit is not None:
            raise ResourcePermitObservationMismatchError("absent permit inspection included a permit")
        if isinstance(request, ResourcePermitRequest):
            if observed.state in {ResourcePermitInspectionState.HELD, ResourcePermitInspectionState.RELEASED}:
                self._validate_permit(request, intent, observed.permit, None, now=_now(self.clock),
                                      allow_expired=True)
            stored_permit = None if row["permit_json"] is None else _permit_from(json.loads(row["permit_json"]))
            if stored_permit is not None and observed.permit is not None and stored_permit != observed.permit:
                raise ResourcePermitObservationMismatchError("resource inspection permit differs from stored permit")
        else:
            if observed.permit != request.permit:
                raise ResourcePermitObservationMismatchError("resource inspection permit differs from release intent")
        return (ResourcePermitOperationView(
            **{**view.__dict__, "inspection_state": observed.state, "inspection_receipt": receipt}
        ), observed, receipt, inspection_request)

    def inspect(self, authority: SQLiteAuthority, bearer_token: str,
                operation_ref: EntityRef | StableId) -> ResourcePermitOperationView:
        self._check_authority(authority, writable=False)
        operation_id = self._operation_selector(authority, operation_ref)
        return self._inspect_result(authority, bearer_token, operation_id, RESOURCE_READ_ACTION)[0]

    def _validate_permit(self, request: ResourcePermitRequest, intent: dict[str, object], permit,
                         receipt: ProviderReceipt | None, *, now: datetime,
                         allow_expired: bool = False) -> None:
        if not isinstance(permit, ResourcePermitRef):
            raise ResourcePermitObservationMismatchError("provider did not return a typed permit reference")
        expiry = datetime.fromisoformat(intent["lease_expires_at"])
        if (permit.resource_class != request.resource_class or permit.scope_id != request.scope_id
                or permit.units != request.units or permit.issuer != self.provider_identity
                or (not allow_expired and permit.expires_at <= now) or permit.expires_at > expiry
                or receipt is not None and permit.receipt_id != receipt.receipt_id):
            raise ResourcePermitObservationMismatchError("permit does not match exact class, scope, units, issuer, or lease")

    def reconcile(self, authority: SQLiteAuthority, bearer_token: str, operation_ref: EntityRef | StableId, *,
                  idempotency_key: StableId, expected_revision: int | None = None) -> ResourcePermitOperationView:
        """Persist a fresh provider inspection; this method never executes reserve/release."""
        self._check_authority(authority)
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        operation_id = self._operation_selector(authority, operation_ref)
        row = self._intent_row(authority, operation_id)
        current = _row_view(row, authority.project.project_id)
        actor, _capability = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        request, intent = _intent_from(row["request_json"])
        requirement = _exact_requirement(RESOURCE_RECONCILE_ACTION, intent)
        self._authorize_current(authority, bearer_token, actor, requirement)
        # Same-key retries return the durable observation without another provider query.
        key = _phase_key(operation_id, "inspect:" + str(idempotency_key))
        replay = self.auth.replay_authorized(
            authority, bearer_token, key, requirement, _TRANSITION_KIND,
            lambda _connection, receipt: receipt["event_kind"].startswith("todo.resource.permit.")
            and json.loads(receipt["payload_json"]).get("operation_id") == str(operation_id)
            and json.loads(receipt["payload_json"]).get("inspection") is True,
        )
        if replay is not None:
            return self._view(authority, operation_id)
        if current.state in {ResourcePermitState.RELEASED, ResourcePermitState.FAILED,
                             ResourcePermitState.NOT_APPLIED}:
            return current
        revision = self.auth._revision(authority, expected_revision)
        inspected, observation, inspection_receipt, query = self._inspect_result(
            authority, bearer_token, operation_id, RESOURCE_RECONCILE_ACTION,
            expected_revision=revision,
        )
        if observation is None or inspection_receipt is None:
            raise ResourcePermitProviderUnavailableError("trusted resource inspection did not produce a definitive result")
        permit = observation.permit
        if isinstance(request, ResourcePermitRequest):
            if observation.state is ResourcePermitInspectionState.ABSENT:
                if current.state is ResourcePermitState.HELD:
                    # A previously observed hold disappearing is not proof of
                    # release. Preserve occupancy until provider confirms release.
                    next_state, ext, reason = ResourcePermitState.UNKNOWN, "unknown", StableId("held_permit_missing")
                else:
                    next_state, ext, reason = ResourcePermitState.NOT_APPLIED, "not_applied", None
            elif observation.state is ResourcePermitInspectionState.RELEASED:
                next_state, ext, reason = ResourcePermitState.RELEASED, "finalized", None
            else:
                next_state, ext, reason = ResourcePermitState.HELD, "observed", None
        else:
            if observation.state is ResourcePermitInspectionState.RELEASED:
                next_state, ext, reason = ResourcePermitState.RELEASED, "finalized", None
            elif observation.state is ResourcePermitInspectionState.HELD:
                next_state, ext, reason = ResourcePermitState.NOT_APPLIED, "not_applied", None
            else:
                # ABSENT cannot prove a release; retain unknown occupancy.
                next_state, ext, reason = ResourcePermitState.UNKNOWN, "unknown", StableId("permit_absence_unproven")
        inspection_json = _json({
            "state": observation.state.value,
            "permit": None if permit is None else _permit_value(permit),
            "query_correlation_id": str(query.correlation_id),
            "query_request_digest": provider_request_digest(query).hex,
            "inspection_receipt": _receipt_value(inspection_receipt),
        })
        self._transition(
            authority, bearer_token, request, row["request_json"], current.state, next_state, ext,
            RESOURCE_RECONCILE_ACTION, phase="inspect:" + str(idempotency_key), expected_revision=revision,
            permit=permit, inspection=json.loads(inspection_json),
            inspection_receipt=inspection_receipt,
        )
        return self._view(authority, operation_id)

    def retry(self, authority: SQLiteAuthority, bearer_token: str, operation_ref: EntityRef | StableId, *,
              idempotency_key: StableId, expected_revision: int | None = None) -> ResourcePermitOperationView:
        """Explicitly retry one definitively absent reserve or unreleased permit.

        The original operation ID and request are reused. A fresh provider
        inspection must prove ABSENT for reserve or HELD for release; the
        writer rechecks that exact query receipt, original owner, attempt, and
        lease before this method can cross the external effect boundary.
        """
        self._check_authority(authority)
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        operation_id = self._operation_selector(authority, operation_ref)
        row = self._intent_row(authority, operation_id)
        request, intent = _intent_from(row["request_json"])
        is_reserve = isinstance(request, ResourcePermitRequest)
        action = RESOURCE_RESERVE_ACTION if is_reserve else RESOURCE_RELEASE_ACTION
        requirement = _exact_requirement(action, intent)
        actor, _capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))
        self._authorize_current(authority, bearer_token, actor, requirement)
        if actor != _ref_from(intent["actor"]):
            raise ResourcePermitDeniedError("resource retry requires the original permit owner")
        self._authorize_current(authority, bearer_token, actor,
                                _exact_requirement(RESOURCE_RECONCILE_ACTION, intent))

        start_phase = "retry-start:" + str(idempotency_key)
        start_key = _phase_key(operation_id, start_phase)
        replay = self.auth.replay_authorized(
            authority, bearer_token, start_key, requirement, _TRANSITION_KIND,
            lambda _connection, receipt: receipt["event_kind"] == "todo.resource.permit.executing"
            and json.loads(receipt["payload_json"]).get("operation_id") == str(operation_id)
            and json.loads(receipt["payload_json"]).get("inspection") is True,
        )
        if replay is not None:
            return self._view(authority, operation_id)
        if row["state"] != ResourcePermitState.NOT_APPLIED.value:
            raise ResourcePermitStateError("only a definitively not-applied permit operation can be retried")

        revision = self.auth._revision(authority, expected_revision)
        current_attempt, current_attempt_row = self._load_attempt(authority, request.attempt)
        self._validate_attempt(intent, current_attempt, current_attempt_row, require_live=is_reserve)
        _view, observation, inspection_receipt, query = self._inspect_result(
            authority, bearer_token, operation_id, RESOURCE_RECONCILE_ACTION,
            expected_revision=revision,
        )
        expected_inspection = (ResourcePermitInspectionState.ABSENT if is_reserve
                               else ResourcePermitInspectionState.HELD)
        if observation is None or inspection_receipt is None:
            raise ResourcePermitProviderUnavailableError(
                "fresh trusted inspection did not prove the original effect absent"
            )
        if observation.state is not expected_inspection:
            raise ResourcePermitStateError(
                "fresh provider inspection no longer proves this original operation safe to retry"
            )
        if is_reserve and observation.permit is not None:
            raise ResourcePermitObservationMismatchError("absent reservation inspection included a permit")
        if not is_reserve and observation.permit != request.permit:
            raise ResourcePermitObservationMismatchError("held permit differs from the exact original request")
        proof = {
            "state": observation.state.value,
            "permit": None if observation.permit is None else _permit_value(observation.permit),
            "query_correlation_id": str(query.correlation_id),
            "query_request_digest": provider_request_digest(query).hex,
            "inspection_receipt": _receipt_value(inspection_receipt),
        }
        started = self._transition(
            authority, bearer_token, request, row["request_json"], ResourcePermitState.NOT_APPLIED,
            ResourcePermitState.EXECUTING, "executing", action, phase=start_phase,
            expected_revision=revision,
            permit=None if is_reserve else request.permit,
            inspection=proof, inspection_receipt=inspection_receipt,
        )
        if started.replayed:
            return self._view(authority, operation_id)
        if is_reserve:
            state, external, reason, permit, effect_receipt = self._reserve_effect_result(
                request, earliest=self._operation_created_at(authority, operation_id),
            )
        else:
            try:
                provider_result = self.provider.release(request)
            except Exception:
                provider_result = None
            state, external, reason, effect_receipt = self._effect_release_result(
                provider_result, request, _now(self.clock),
                earliest=self._operation_created_at(authority, operation_id),
            )
            permit = request.permit
        return self._finalize_external_call(
            authority, bearer_token, request, row["request_json"], state, external, action,
            revision=self.auth._revision(authority, None), permit=permit,
            receipt=effect_receipt, reason=reason,
            phase="retry-result:" + str(idempotency_key),
        )

__all__ = [
    "RESOURCE_RESERVE_ACTION", "RESOURCE_RELEASE_ACTION", "RESOURCE_READ_ACTION", "RESOURCE_RECONCILE_ACTION",
    "ResourcePermitDeniedError", "ResourcePermitError", "ResourcePermitNotFoundError",
    "ResourcePermitObservationMismatchError", "ResourcePermitOperationView",
    "ResourcePermitProviderUnavailableError", "ResourcePermitService", "ResourcePermitState",
    "ResourcePermitStateError",
]
