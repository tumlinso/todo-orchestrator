"""Authenticated native facts for accepted-plan declarations.

Messages are intentionally not consulted here. A decision, interface, checkpoint,
barrier, or rendezvous changes workflow state only through one of these typed,
authorized mutations tied to the exact accepted declaration payload.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from todo_orchestrator.contracts import (
    AttemptState,
    EntityKind,
    EntityRef,
    Project,
    RequirementMode,
    StableId,
)
from todo_orchestrator.contracts.providers import (
    DeclarationKind,
    DeclarationObservation,
    DeclarationObservationRequest,
    DeclarationObserver,
    DeclarationStatus,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    provider_request_digest,
)
from todo_orchestrator.model import CommandEffect, CommandResult
from todo_orchestrator.planning import (
    ConditionCause,
    ConditionResult,
    ConditionStatus,
    DecisionObservation,
    evaluate_results,
)
from todo_orchestrator.planning.package import CompiledPlan, _compatible_interface_version
from todo_orchestrator.planning.snapshot import decode_accepted_plan

from .auth import AuthorizationRequirement, AuthorityAuthService
from .commands import MutationContext
from .sqlite import (
    AuthorityError,
    InvalidAuthorityError,
    SQLiteAuthority,
    load_plan_revision_snapshot,
)


DECISION_RESOLVE_ACTION = StableId("todo.decision.resolve")
INTERFACE_PUBLISH_ACTION = StableId("todo.interface.publish")
CHECKPOINT_ACCEPT_ACTION = StableId("todo.checkpoint.accept")
BARRIER_RELEASE_ACTION = StableId("todo.barrier.release")
RENDEZVOUS_ARRIVE_ACTION = StableId("todo.rendezvous.arrive")
BLOCKER_OPEN_ACTION = StableId("todo.blocker.open")
BLOCKER_CLEAR_ACTION = StableId("todo.blocker.clear")
NATIVE_DECLARATION_PROVIDER_IDENTITY = ProviderIdentity(StableId("todo.sqlite.declarations"), "1")

_DECLARATION_KIND_TO_SECTION = {
    "decision": "decisions",
    "interface": "interfaces",
    "checkpoint": "checkpoints",
    "barrier": "barriers",
    "rendezvous": "rendezvous",
}
_SECTION_TO_ENTITY = {
    "decision": EntityKind.DECISION,
    "interface": EntityKind.INTERFACE,
    "checkpoint": EntityKind.CHECKPOINT,
    "barrier": EntityKind.BARRIER,
    "rendezvous": EntityKind.BARRIER,
}
_OPERATION_ACTIONS = {
    "decision_resolved": DECISION_RESOLVE_ACTION,
    "interface_published": INTERFACE_PUBLISH_ACTION,
    "checkpoint_accepted": CHECKPOINT_ACCEPT_ACTION,
    "barrier_released": BARRIER_RELEASE_ACTION,
    "rendezvous_arrived": RENDEZVOUS_ARRIVE_ACTION,
    "blocker_opened": BLOCKER_OPEN_ACTION,
    "blocker_cleared": BLOCKER_CLEAR_ACTION,
}
_FACTS_FOR_OPERATION = {
    "decision.resolve": ("decision", "decision_resolved"),
    "interface.publish": ("interface", "interface_published"),
    "checkpoint.accept": ("checkpoint", "checkpoint_accepted"),
    "barrier.release": ("barrier", "barrier_released"),
    "rendezvous.arrive": ("rendezvous", "rendezvous_arrived"),
    "blocker.open": (None, "blocker_opened"),
    "blocker.clear": (None, "blocker_cleared"),
}
_MAX_NOTE_CHARS = 1000


class DeclarationError(AuthorityError):
    """Base error for exact-plan declaration operations."""


class DeclarationNotFoundError(DeclarationError):
    """The requested declaration is not in the current accepted plan."""


class DeclarationMutationDeniedError(DeclarationError):
    """The current authenticated actor cannot make the requested declaration fact."""


class DeclarationObservationError(DeclarationError):
    """A stored declaration fact or observation context is inconsistent."""


@dataclass(frozen=True)
class DeclarationRecord:
    """One immutable declaration decoded from an authority-validated snapshot."""

    plan_revision_id: StableId
    target: EntityRef
    kind: str
    payload: Mapping[str, Any]
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.plan_revision_id, StableId):
            raise TypeError("plan_revision_id must be a StableId")
        if not isinstance(self.target, EntityRef):
            raise TypeError("target must be an EntityRef")
        if self.kind not in _DECLARATION_KIND_TO_SECTION:
            raise ValueError("kind is not a supported declaration kind")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload must be a mapping")
        if not isinstance(self.digest, str) or len(self.digest) != 64:
            raise ValueError("digest must be a lowercase SHA-256 hex string")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(child) for child in value]
    return value


def _canonical(value: object) -> str:
    return json.dumps(_plain(value), ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def _now(clock: Callable[[], datetime]) -> datetime:
    result = clock()
    if not isinstance(result, datetime) or result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("declaration clock must return an aware datetime")
    return result.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _target(project: Project, kind: str, identifier: StableId) -> EntityRef:
    return EntityRef(project.project_id, _SECTION_TO_ENTITY[kind], identifier)


def _decode_current_plan(
    connection: sqlite3.Connection,
    project: Project,
    plan_revision_id: StableId,
) -> CompiledPlan:
    row = connection.execute(
        "SELECT sequence, state FROM plan_revisions WHERE plan_revision_id = ?",
        (str(plan_revision_id),),
    ).fetchone()
    latest = connection.execute(
        "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    if row is None or row["state"] != "accepted" or latest is None or latest[0] != str(plan_revision_id):
        raise DeclarationNotFoundError("declaration mutations require the exact current accepted plan revision")
    snapshot = load_plan_revision_snapshot(connection, project, plan_revision_id)
    if snapshot.sequence is None:
        raise InvalidAuthorityError("accepted plan snapshot has no sequence")
    return decode_accepted_plan(snapshot.canonical_json, project, sequence=snapshot.sequence)


def load_plan_declaration(
    connection: sqlite3.Connection,
    project: Project,
    plan_revision_id: StableId,
    declaration_kind: str | DeclarationKind,
    declaration_id: StableId,
) -> DeclarationRecord | None:
    """Load an exact declaration from a validated accepted-plan snapshot.

    The payload digest is computed from the immutable typed snapshot, never
    accepted from a caller. This function performs no writes.
    """

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a SQLite connection")
    if not isinstance(project, Project):
        raise TypeError("project must be a Project")
    if not isinstance(plan_revision_id, StableId) or not isinstance(declaration_id, StableId):
        raise TypeError("plan revision and declaration IDs must be StableId values")
    kind = declaration_kind.value if isinstance(declaration_kind, DeclarationKind) else declaration_kind
    if not isinstance(kind, str) or kind not in _DECLARATION_KIND_TO_SECTION:
        raise ValueError("declaration_kind is unsupported")
    row = connection.execute(
        "SELECT sequence, state FROM plan_revisions WHERE plan_revision_id = ?",
        (str(plan_revision_id),),
    ).fetchone()
    if row is None or row["state"] != "accepted":
        raise DeclarationNotFoundError("declaration loader requires an accepted plan revision")
    snapshot = load_plan_revision_snapshot(connection, project, plan_revision_id)
    if snapshot.sequence is None:
        raise InvalidAuthorityError("accepted plan snapshot has no sequence")
    plan = decode_accepted_plan(snapshot.canonical_json, project, sequence=snapshot.sequence)
    item = next(
        (declaration for declaration in plan.declarations
         if declaration.kind == _DECLARATION_KIND_TO_SECTION[kind]
         and declaration.declaration_id == declaration_id),
        None,
    )
    if item is None:
        return None
    payload = _plain(item.payload)
    encoded = _canonical(payload)
    if payload.get("id") != str(declaration_id):
        raise InvalidAuthorityError("stored declaration identity differs from its typed record")
    return DeclarationRecord(
        plan_revision_id,
        _target(project, kind, declaration_id),
        kind,
        _freeze(payload),
        hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    )


def _latest_fact(
    connection: sqlite3.Connection,
    declaration: DeclarationRecord,
    kinds: tuple[str, ...] | None = None,
) -> sqlite3.Row | None:
    params: list[object] = [
        str(declaration.plan_revision_id), declaration.kind, str(declaration.target.entity_id), declaration.digest,
    ]
    sql = (
        "SELECT fact_sequence, fact_kind, payload_json, participant_project_id, participant_kind, "
        "participant_entity_id, participant_definition_revision_id, participant_incarnation_id "
        "FROM declaration_facts WHERE plan_revision_id = ? AND declaration_kind = ? "
        "AND declaration_id = ? AND declaration_digest = ?"
    )
    if kinds:
        sql += " AND fact_kind IN (" + ",".join("?" for _ in kinds) + ")"
        params.extend(kinds)
    sql += " ORDER BY fact_sequence DESC LIMIT 1"
    return connection.execute(sql, params).fetchone()


def _blocker_row(connection: sqlite3.Connection, declaration: DeclarationRecord) -> sqlite3.Row | None:
    return _latest_fact(connection, declaration, ("blocker_opened", "blocker_cleared"))


def declaration_condition(
    connection: sqlite3.Connection,
    declaration: DeclarationRecord,
    *,
    expected_version: str | None = None,
) -> tuple[ConditionResult, str | None, str | None]:
    """Return canonical condition status, current interface version, and decision option."""

    blocker = _blocker_row(connection, declaration)
    if blocker is not None and blocker["fact_kind"] == "blocker_opened":
        return (
            ConditionResult(ConditionStatus.UNSATISFIED, (ConditionCause(
                "declaration_blocked", str(declaration.target.entity_id), "an explicit blocker is open",
            ),)),
            None,
            None,
        )

    fact_kind = {
        "decision": "decision_resolved",
        "interface": "interface_published",
        "checkpoint": "checkpoint_accepted",
        "barrier": "barrier_released",
    }.get(declaration.kind)
    fact = _latest_fact(connection, declaration, None if fact_kind is None else (fact_kind,))
    if declaration.kind == "decision":
        option_id = None
        if fact is not None:
            try:
                option_id = json.loads(fact["payload_json"]).get("option_id")
            except (TypeError, ValueError) as exc:
                raise InvalidAuthorityError("stored decision fact payload is invalid") from exc
        else:
            option_id = declaration.payload.get("selected_option_id")
        if option_id is None:
            return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause(
                "decision_unresolved", str(declaration.target.entity_id), "no authoritative option has been selected",
            ),)), None, None
        options = {str(item["id"]) for item in declaration.payload.get("options", ())}
        if option_id not in options:
            raise InvalidAuthorityError("stored decision selection is absent from the declaration")
        return ConditionResult(ConditionStatus.SATISFIED), None, option_id

    if declaration.kind == "interface":
        if fact is None:
            return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause(
                "interface_unpublished", str(declaration.target.entity_id), "no interface version has been published",
            ),)), None, None
        try:
            payload = json.loads(fact["payload_json"])
            version = payload["version"]
            contract_digest = payload["contract_digest"]
            expected_contract_digest = _digest(declaration.payload["contract"])
            if contract_digest != expected_contract_digest:
                raise ValueError("contract digest differs")
            declared_version = str(declaration.payload["version"])
            compatible_with_declaration = _compatible_interface_version(
                version, declared_version, str(declaration.payload["compatibility"]), "$/interfaces",
            )
            compatible_with_request = (
                expected_version is None
                or _compatible_interface_version(
                    version, expected_version, str(declaration.payload["compatibility"]), "$/interfaces",
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidAuthorityError(f"stored interface fact is inconsistent: {exc}") from exc
        status = ConditionStatus.SATISFIED if compatible_with_declaration and compatible_with_request else ConditionStatus.UNSATISFIED
        return ConditionResult(status), version, None

    if declaration.kind == "checkpoint":
        status = ConditionStatus.SATISFIED if fact is not None else ConditionStatus.UNRESOLVED
        return ConditionResult(status), None, None

    if declaration.kind == "barrier":
        status = ConditionStatus.SATISFIED if fact is not None else ConditionStatus.UNRESOLVED
        return ConditionResult(status), None, None

    if declaration.kind == "rendezvous":
        participants = declaration.payload.get("participants", ())
        if not participants:
            raise InvalidAuthorityError("stored rendezvous has no participants")
        rows = connection.execute(
            "SELECT participant_project_id, participant_kind, participant_entity_id, "
            "participant_definition_revision_id, participant_incarnation_id FROM declaration_facts "
            "WHERE plan_revision_id = ? AND declaration_kind = 'rendezvous' AND declaration_id = ? "
            "AND declaration_digest = ? AND fact_kind = 'rendezvous_arrived'",
            (str(declaration.plan_revision_id), str(declaration.target.entity_id), declaration.digest),
        ).fetchall()
        arrived = {
            (row["participant_project_id"], row["participant_kind"], row["participant_entity_id"],
             row["participant_definition_revision_id"], row["participant_incarnation_id"])
            for row in rows
        }
        def participant_key(value: Mapping[str, object]) -> tuple[str, str, str, str | None, str | None]:
            kind = str(value["kind"])
            return (
                str(value["project_id"]),
                EntityKind.BARRIER.value if kind == "rendezvous" else kind,
                str(value["entity_id"]),
                None if value.get("revision_id") is None else str(value["revision_id"]),
                None if value.get("incarnation_id") is None else str(value["incarnation_id"]),
            )
        results = tuple(
            ConditionResult(ConditionStatus.SATISFIED if participant_key(value) in arrived else ConditionStatus.UNRESOLVED,
                            (ConditionCause("rendezvous_arrival", str(value["entity_id"]),
                                            "participant arrived" if participant_key(value) in arrived else "participant arrival is unobserved"),))
            for value in participants
        )
        mode = RequirementMode(str(declaration.payload["mode"]))
        combined = evaluate_results(mode, declaration.payload.get("quorum"), results)
        return combined, None, None

    return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause(
        "declaration_kind_unsupported", declaration.kind, "no native condition evaluator exists for this declaration",
    ),)), None, None


def native_declaration_facts(
    connection: sqlite3.Connection,
    plan: CompiledPlan,
) -> tuple[Mapping[EntityRef, ConditionResult], Mapping[str, DecisionObservation]]:
    """Load current-plan declarations from authority facts, not caller observations."""

    blockers: dict[EntityRef, ConditionResult] = {}
    decisions: dict[str, DecisionObservation] = {}
    for item in plan.declarations:
        kind = {
            "decisions": "decision", "interfaces": "interface", "checkpoints": "checkpoint",
            "barriers": "barrier", "rendezvous": "rendezvous",
        }.get(item.kind)
        if kind is None:
            continue
        declaration = load_plan_declaration(
            connection, plan.project, plan.revision.plan_revision_id, kind, item.declaration_id,
        )
        if declaration is None:
            continue
        result, _version, option_id = declaration_condition(connection, declaration)
        blockers[declaration.target] = result
        if kind == "decision":
            decision_status = (
                ConditionStatus.UNRESOLVED
                if result.status is ConditionStatus.UNSATISFIED
                else result.status
            )
            decisions[str(declaration.target.entity_id)] = DecisionObservation(decision_status, option_id)
    return MappingProxyType(blockers), MappingProxyType(decisions)


@dataclass(frozen=True)
class _DeclarationMutation:
    operation: str
    plan_revision_id: StableId
    target: EntityRef
    payload_json: str
    run: EntityRef | None = None
    assignment: EntityRef | None = None
    attempt: EntityRef | None = None

    def __post_init__(self) -> None:
        if self.operation not in _FACTS_FOR_OPERATION:
            raise ValueError("unsupported declaration operation")
        if not isinstance(self.plan_revision_id, StableId):
            raise TypeError("plan_revision_id must be a StableId")
        if not isinstance(self.target, EntityRef):
            raise TypeError("target must be an EntityRef")
        if not isinstance(self.payload_json, str):
            raise TypeError("payload_json must be text")


class _DeclarationHandler:
    kind = "todo.declaration.mutate"
    command_type = _DeclarationMutation

    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock

    def authorization_requirement(self, command: _DeclarationMutation) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            _OPERATION_ACTIONS[_FACTS_FOR_OPERATION[command.operation][1]], command.target,
            command.run, command.assignment, command.attempt,
            plan_revision=EntityRef(command.target.project_id, EntityKind.PLAN_REVISION, command.plan_revision_id),
        )

    def canonical_payload(self, command: _DeclarationMutation) -> Mapping[str, object]:
        return {
            "operation": command.operation,
            "plan_revision_id": str(command.plan_revision_id),
            "target": _ref_value(command.target),
            "payload": json.loads(command.payload_json),
            "run": None if command.run is None else _ref_value(command.run),
            "assignment": None if command.assignment is None else _ref_value(command.assignment),
            "attempt": None if command.attempt is None else _ref_value(command.attempt),
        }

    def apply(self, context: MutationContext, command: _DeclarationMutation) -> CommandEffect:
        connection = context._connection
        plan = _decode_current_plan(connection, context.project, command.plan_revision_id)
        kind, fact_kind = _FACTS_FOR_OPERATION[command.operation]
        allowed_kinds = {kind} if kind is not None else set(_DECLARATION_KIND_TO_SECTION)
        record = None
        for candidate_kind in sorted(allowed_kinds):
            record = load_plan_declaration(
                connection, context.project, command.plan_revision_id, candidate_kind,
                command.target.entity_id,
            )
            if record is not None and record.target == command.target:
                break
            record = None
        if record is None:
            raise DeclarationNotFoundError("exact declaration is absent from the current accepted plan")
        _validate_operation_context(connection, context.project, command, context.actor, plan, self._clock)
        try:
            payload = json.loads(command.payload_json)
        except (TypeError, ValueError) as exc:
            raise DeclarationMutationDeniedError("declaration mutation payload is invalid") from exc
        if not isinstance(payload, dict):
            raise DeclarationMutationDeniedError("declaration mutation payload must be an object")

        participant = None
        if fact_kind == "decision_resolved":
            option_id = payload.get("option_id")
            options = {item["id"] for item in record.payload.get("options", ())}
            if option_id not in options:
                raise DeclarationMutationDeniedError("decision option is not declared by this accepted plan")
            _validate_reason(payload.get("rationale"), "decision rationale", connection)
            resolvers = record.payload.get("resolvers", ())
            if resolvers and not _actor_resolves_work(context, command, resolvers):
                raise DeclarationMutationDeniedError("decision resolver requires an active attempt on a declared resolver work item")
            previous = _latest_fact(connection, record, ("decision_resolved",))
            if previous is not None and json.loads(previous["payload_json"]) == payload:
                return _noop(record, fact_kind, payload)
        elif fact_kind == "interface_published":
            version = payload.get("version")
            if not isinstance(version, str) or not version.strip() or version != version.strip():
                raise DeclarationMutationDeniedError("published interface version must be non-empty trimmed text")
            _validate_reason(payload.get("rationale"), "interface publication rationale", connection)
            try:
                compatible = _compatible_interface_version(
                    version, str(record.payload["version"]), str(record.payload["compatibility"]), "$/interfaces",
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise DeclarationMutationDeniedError("published interface version is incompatible with the accepted declaration") from exc
            if not compatible:
                raise DeclarationMutationDeniedError("published interface version is incompatible with the accepted declaration")
            contract_digest = _digest(record.payload["contract"])
            payload = {"version": version, "contract_digest": contract_digest,
                       "rationale": payload["rationale"]}
            previous = _latest_fact(connection, record, ("interface_published",))
            if previous is not None and json.loads(previous["payload_json"]) == payload:
                return _noop(record, fact_kind, payload)
        elif fact_kind == "checkpoint_accepted":
            _validate_reason(payload.get("rationale"), "checkpoint acceptance rationale", connection)
            evidence_ids = payload.get("evidence_ids")
            if not isinstance(evidence_ids, list) or any(not isinstance(item, str) for item in evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
                raise DeclarationMutationDeniedError("checkpoint evidence_ids must be a unique list of evidence IDs")
            _validate_checkpoint_evidence(connection, record, tuple(evidence_ids))
            previous = _latest_fact(connection, record, ("checkpoint_accepted",))
            if previous is not None and json.loads(previous["payload_json"]) == payload:
                return _noop(record, fact_kind, payload)
        elif fact_kind == "barrier_released":
            _validate_reason(payload.get("rationale"), "barrier release rationale", connection)
            previous = _latest_fact(connection, record, ("barrier_released",))
            if previous is not None:
                return _noop(record, fact_kind, payload)
        elif fact_kind == "rendezvous_arrived":
            participant_json = payload.get("participant")
            participant = _parse_ref_value(participant_json, context.project.project_id)
            declared = {
                _reference_key(value) for value in record.payload.get("participants", ())
            }
            if _reference_key(_ref_value(participant)) not in declared:
                raise DeclarationMutationDeniedError("participant is not declared by this rendezvous")
            _validate_arrival_participant(connection, command, context.actor, participant)
            if _latest_participant_arrival(connection, record, participant) is not None:
                return _noop(record, fact_kind, payload)
        else:
            _validate_reason(payload.get("reason"), "blocker reason", connection)
            previous = _blocker_row(connection, record)
            if fact_kind == "blocker_opened" and previous is not None and previous["fact_kind"] == "blocker_opened":
                if json.loads(previous["payload_json"]) == payload:
                    return _noop(record, fact_kind, payload)
            if fact_kind == "blocker_cleared" and (previous is None or previous["fact_kind"] == "blocker_cleared"):
                return _noop(record, fact_kind, payload)

        encoded_payload = _canonical(payload)
        participant_values = (None, None, None, None, None)
        if participant is not None:
            participant_values = (
                str(participant.project_id), participant.kind.value, str(participant.entity_id),
                None if participant.definition_revision_id is None else str(participant.definition_revision_id),
                None if participant.incarnation_id is None else str(participant.incarnation_id),
            )
        fact_id = "declfact-" + uuid4().hex
        occurred_at = _iso(_now(self._clock))
        connection.execute(
            "INSERT INTO declaration_facts(fact_id, plan_revision_id, declaration_kind, declaration_id, "
            "declaration_digest, fact_kind, participant_project_id, participant_kind, participant_entity_id, "
            "participant_definition_revision_id, participant_incarnation_id, payload_json, semantic_revision, "
            "actor_id, actor_incarnation_id, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (fact_id, str(record.plan_revision_id), record.kind, str(record.target.entity_id), record.digest,
             fact_kind, *participant_values, encoded_payload, context.starting_revision + 1,
             str(context.actor.entity_id), str(context.actor.incarnation_id), occurred_at),
        )
        return CommandEffect(True, {"fact_id": fact_id, "declaration_digest": record.digest,
                                    "fact_kind": fact_kind}, "declaration.fact.appended", {
            "fact_id": fact_id, "plan_revision_id": str(record.plan_revision_id),
            "declaration_kind": record.kind, "declaration_id": str(record.target.entity_id),
            "declaration_digest": record.digest, "fact_kind": fact_kind,
        })


def _ref_value(reference: EntityRef) -> dict[str, str | None]:
    return {
        "project_id": str(reference.project_id), "kind": reference.kind.value,
        "entity_id": str(reference.entity_id),
        "definition_revision_id": None if reference.definition_revision_id is None else str(reference.definition_revision_id),
        "incarnation_id": None if reference.incarnation_id is None else str(reference.incarnation_id),
    }


def _parse_ref_value(value: object, project_id: StableId) -> EntityRef:
    if not isinstance(value, dict):
        raise DeclarationMutationDeniedError("participant must be a typed qualified reference")
    try:
        ref_project = StableId(value["project_id"])
        kind = EntityKind(value["kind"])
        entity_id = StableId(value["entity_id"])
        revision = value.get("definition_revision_id")
        incarnation = value.get("incarnation_id")
        if ref_project != project_id:
            raise ValueError("participant belongs to a foreign project")
        return EntityRef(ref_project, kind, entity_id,
                         None if revision is None else StableId(revision),
                         None if incarnation is None else StableId(incarnation))
    except (KeyError, TypeError, ValueError) as exc:
        raise DeclarationMutationDeniedError("participant reference is invalid") from exc


def _reference_key(value: Mapping[str, object]) -> tuple[object, ...]:
    return (value.get("project_id"), value.get("kind"), value.get("entity_id"),
            value.get("revision_id", value.get("definition_revision_id")), value.get("incarnation_id"))


def _validate_reason(value: object, name: str, connection: sqlite3.Connection) -> str:
    from todo_orchestrator.coordination.payloads import validate_bounded_text
    if not isinstance(value, str) or len(value) > _MAX_NOTE_CHARS:
        raise DeclarationMutationDeniedError(f"{name} must be non-empty text up to {_MAX_NOTE_CHARS} characters")
    try:
        return validate_bounded_text(value, field=name, max_bytes=3000, connection=connection)
    except ValueError as exc:
        raise DeclarationMutationDeniedError(str(exc)) from exc


def _validate_operation_context(
    connection: sqlite3.Connection,
    project: Project,
    command: _DeclarationMutation,
    actor: EntityRef,
    plan: CompiledPlan,
    clock: Callable[[], datetime],
) -> None:
    now = _now(clock)
    run = command.run
    assignment = command.assignment
    attempt = command.attempt
    if assignment is not None and run is None:
        raise DeclarationMutationDeniedError("assignment context requires its exact run")
    if run is not None:
        row = connection.execute(
            "SELECT plan_revision_id, state FROM runs WHERE run_id = ?", (str(run.entity_id),)
        ).fetchone()
        if row is None or row["state"] != "open" or row["plan_revision_id"] != str(plan.revision.plan_revision_id):
            raise DeclarationMutationDeniedError("run context is absent, closed, or bound to another plan")
    assignment_row = None
    if assignment is not None:
        assignment_row = connection.execute(
            "SELECT run_id, assignee_actor_id, assignee_incarnation_id FROM assignments WHERE assignment_id = ?",
            (str(assignment.entity_id),),
        ).fetchone()
        if assignment_row is None or assignment_row["run_id"] != str(run.entity_id):
            raise DeclarationMutationDeniedError("assignment context does not belong to the exact run")
        if assignment_row["assignee_actor_id"] is not None and (
            assignment_row["assignee_actor_id"] != str(actor.entity_id)
            or assignment_row["assignee_incarnation_id"] != str(actor.incarnation_id)
        ):
            raise DeclarationMutationDeniedError("assignment is assigned to another actor incarnation")
    if attempt is not None:
        row = connection.execute(
            "SELECT actor_id, actor_incarnation_id, state, lease_expires_at, run_id, assignment_id "
            "FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),),
        ).fetchone()
        if row is None or row["actor_id"] != str(actor.entity_id) or row["actor_incarnation_id"] != str(actor.incarnation_id):
            raise DeclarationMutationDeniedError("attempt does not belong to the authenticated actor incarnation")
        if row["state"] not in {AttemptState.ADMITTED.value, AttemptState.ACTIVE.value, AttemptState.REPORTED.value}:
            raise DeclarationMutationDeniedError("attempt is not active for declaration work")
        if row["lease_expires_at"] is None or datetime.fromisoformat(row["lease_expires_at"]) <= now:
            raise DeclarationMutationDeniedError("attempt lease is missing or expired")
        if row["run_id"] != (None if run is None else str(run.entity_id)):
            raise DeclarationMutationDeniedError("attempt does not match the exact run context")
        if row["assignment_id"] != (None if assignment is None else str(assignment.entity_id)):
            raise DeclarationMutationDeniedError("attempt does not match the exact assignment context")


def _actor_resolves_work(
    context: MutationContext,
    command: _DeclarationMutation,
    resolvers: tuple[object, ...],
) -> bool:
    if command.attempt is None:
        return False
    row = context._connection.execute(
        "SELECT work_item_id, definition_revision_id, actor_id, actor_incarnation_id, state "
        "FROM attempts WHERE attempt_id = ?", (str(command.attempt.entity_id),),
    ).fetchone()
    if row is None or row["state"] not in {AttemptState.ADMITTED.value, AttemptState.ACTIVE.value, AttemptState.REPORTED.value}:
        return False
    if row["actor_id"] != str(context.actor.entity_id) or row["actor_incarnation_id"] != str(context.actor.incarnation_id):
        return False
    return any(
        item.get("project_id") == str(context.project.project_id)
        and item.get("kind") == EntityKind.WORK_ITEM.value
        and item.get("entity_id") == row["work_item_id"]
        and item.get("revision_id") == row["definition_revision_id"]
        for item in resolvers if isinstance(item, Mapping)
    )


def _validate_checkpoint_evidence(
    connection: sqlite3.Connection,
    declaration: DeclarationRecord,
    evidence_ids: tuple[str, ...],
) -> None:
    required = set(declaration.payload["acceptance"].get("required_evidence", ()))
    found_names: set[str] = set()
    producers = {
        (value["entity_id"], value.get("revision_id"))
        for value in declaration.payload.get("producers", ())
        if value.get("project_id") == str(declaration.target.project_id)
        and value.get("kind") == EntityKind.WORK_ITEM.value
    }
    for evidence_id in evidence_ids:
        StableId(evidence_id)
        rows = connection.execute(
            "SELECT e.result, a.work_item_id, a.definition_revision_id, v.state, f.fact_name "
            "FROM evidence AS e JOIN attempts AS a USING(attempt_id) "
            "JOIN verification_attempts AS v ON v.operation_id = e.operation_id "
            "JOIN evidence_facts AS f USING(evidence_id) WHERE e.evidence_id = ? "
            "ORDER BY f.fact_name", (evidence_id,),
        ).fetchall()
        if not rows or any(row["result"] != "pass" or row["state"] != "finalized" for row in rows):
            raise DeclarationMutationDeniedError("checkpoint evidence must be finalized, passing verification evidence")
        if producers and any((row["work_item_id"], row["definition_revision_id"]) not in producers for row in rows):
            raise DeclarationMutationDeniedError("checkpoint evidence must come from a declared producer work definition")
        found_names.update(row["fact_name"] for row in rows)
    missing = required - found_names
    if missing:
        raise DeclarationMutationDeniedError("checkpoint is missing required evidence: " + ", ".join(sorted(missing)))


def _participant_tuple(ref: EntityRef) -> tuple[str, str, str, str | None, str | None]:
    return (str(ref.project_id), ref.kind.value, str(ref.entity_id),
            None if ref.definition_revision_id is None else str(ref.definition_revision_id),
            None if ref.incarnation_id is None else str(ref.incarnation_id))


def _latest_participant_arrival(
    connection: sqlite3.Connection,
    declaration: DeclarationRecord,
    participant: EntityRef,
) -> sqlite3.Row | None:
    key = _participant_tuple(participant)
    return connection.execute(
        "SELECT fact_sequence FROM declaration_facts WHERE plan_revision_id = ? AND declaration_kind = 'rendezvous' "
        "AND declaration_id = ? AND declaration_digest = ? AND fact_kind = 'rendezvous_arrived' "
        "AND participant_project_id = ? AND participant_kind = ? AND participant_entity_id = ? "
        "AND participant_definition_revision_id IS ? AND participant_incarnation_id IS ? LIMIT 1",
        (str(declaration.plan_revision_id), str(declaration.target.entity_id), declaration.digest, *key),
    ).fetchone()


def _validate_arrival_participant(
    connection: sqlite3.Connection,
    command: _DeclarationMutation,
    actor: EntityRef,
    participant: EntityRef,
) -> None:
    if participant.kind is EntityKind.ACTOR:
        if participant != actor:
            raise DeclarationMutationDeniedError("only the matching actor incarnation may record its rendezvous arrival")
        return
    if participant.kind in {EntityKind.WORK_ITEM, EntityKind.ASSIGNMENT, EntityKind.ATTEMPT, EntityKind.RUN}:
        if command.attempt is None:
            raise DeclarationMutationDeniedError("work or run rendezvous participants require an active attempt context")
        row = connection.execute(
            "SELECT work_item_id, definition_revision_id, actor_id, actor_incarnation_id, assignment_id, run_id "
            "FROM attempts WHERE attempt_id = ?", (str(command.attempt.entity_id),),
        ).fetchone()
        if row is None or row["actor_id"] != str(actor.entity_id) or row["actor_incarnation_id"] != str(actor.incarnation_id):
            raise DeclarationMutationDeniedError("arrival attempt does not belong to the authenticated actor")
        matches = {
            EntityKind.WORK_ITEM: (row["work_item_id"], row["definition_revision_id"]),
            EntityKind.ASSIGNMENT: (row["assignment_id"], None),
            EntityKind.ATTEMPT: (command.attempt.entity_id and str(command.attempt.entity_id), None),
            EntityKind.RUN: (row["run_id"], None),
        }
        expected_id, expected_revision = matches[participant.kind]
        if expected_id != str(participant.entity_id) or expected_revision != (
            None if participant.definition_revision_id is None else str(participant.definition_revision_id)
        ):
            raise DeclarationMutationDeniedError("active attempt does not satisfy the declared rendezvous participant")
        return
    raise DeclarationMutationDeniedError("rendezvous arrivals support actor, work-item, assignment, attempt, or run participants")


def _noop(record: DeclarationRecord, fact_kind: str, payload: Mapping[str, object]) -> CommandEffect:
    return CommandEffect(False, {"declaration_id": str(record.target.entity_id),
                                 "declaration_digest": record.digest, "fact_kind": fact_kind,
                                 "no_op": True})


class DeclarationService:
    """Authenticated append-only declaration and blocker mutations."""

    def __init__(
        self,
        auth: AuthorityAuthService,
        *,
        clock: Callable[[], datetime] | None = None,
        observer_identity: ProviderIdentity | None = None,
    ) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        self.auth = auth
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.observer_identity = observer_identity or NATIVE_DECLARATION_PROVIDER_IDENTITY
        self.auth.dispatcher.register(_DeclarationHandler(self.clock))

    def _mutate(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        operation: str,
        plan_revision: EntityRef,
        target: EntityRef,
        payload: Mapping[str, object],
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
        attempt: EntityRef | None = None,
    ) -> CommandResult:
        if not isinstance(plan_revision, EntityRef) or plan_revision.kind is not EntityKind.PLAN_REVISION:
            raise TypeError("plan_revision must be an exact plan-revision reference")
        if plan_revision.project_id != authority.project.project_id or target.project_id != authority.project.project_id:
            raise ValueError("plan and declaration must belong to the target authority")
        command = _DeclarationMutation(
            operation, plan_revision.entity_id, target, _canonical(dict(payload)), run, assignment, attempt,
        )
        return self.auth.execute(authority, bearer_token, command,
                                 idempotency_key=idempotency_key, expected_revision=expected_revision)

    def resolve_decision(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                         target: EntityRef, option_id: StableId, rationale: str, *,
                         idempotency_key: StableId, expected_revision: int | None = None,
                         run: EntityRef | None = None, assignment: EntityRef | None = None,
                         attempt: EntityRef | None = None) -> CommandResult:
        return self._mutate(authority, bearer_token, "decision.resolve", plan_revision, target,
                            {"option_id": str(option_id), "rationale": rationale},
                            idempotency_key=idempotency_key, expected_revision=expected_revision,
                            run=run, assignment=assignment, attempt=attempt)

    def publish_interface(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                          target: EntityRef, version: str, rationale: str, *,
                          idempotency_key: StableId, expected_revision: int | None = None,
                          run: EntityRef | None = None, assignment: EntityRef | None = None,
                          attempt: EntityRef | None = None) -> CommandResult:
        return self._mutate(authority, bearer_token, "interface.publish", plan_revision, target,
                            {"version": version, "rationale": rationale},
                            idempotency_key=idempotency_key, expected_revision=expected_revision,
                            run=run, assignment=assignment, attempt=attempt)

    def accept_checkpoint(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                          target: EntityRef, evidence_ids: tuple[StableId, ...], rationale: str, *,
                          idempotency_key: StableId, expected_revision: int | None = None,
                          run: EntityRef | None = None, assignment: EntityRef | None = None,
                          attempt: EntityRef | None = None) -> CommandResult:
        if not isinstance(evidence_ids, tuple) or any(not isinstance(item, StableId) for item in evidence_ids):
            raise TypeError("evidence_ids must be a tuple of StableId values")
        return self._mutate(authority, bearer_token, "checkpoint.accept", plan_revision, target,
                            {"evidence_ids": [str(item) for item in evidence_ids], "rationale": rationale},
                            idempotency_key=idempotency_key, expected_revision=expected_revision,
                            run=run, assignment=assignment, attempt=attempt)

    def release_barrier(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                        target: EntityRef, rationale: str, *, idempotency_key: StableId,
                        expected_revision: int | None = None, run: EntityRef | None = None,
                        assignment: EntityRef | None = None, attempt: EntityRef | None = None) -> CommandResult:
        return self._mutate(authority, bearer_token, "barrier.release", plan_revision, target,
                            {"rationale": rationale}, idempotency_key=idempotency_key,
                            expected_revision=expected_revision, run=run,
                            assignment=assignment, attempt=attempt)

    def arrive_rendezvous(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                          target: EntityRef, participant: EntityRef, *, idempotency_key: StableId,
                          expected_revision: int | None = None, run: EntityRef | None = None,
                          assignment: EntityRef | None = None, attempt: EntityRef | None = None) -> CommandResult:
        return self._mutate(authority, bearer_token, "rendezvous.arrive", plan_revision, target,
                            {"participant": _ref_value(participant)}, idempotency_key=idempotency_key,
                            expected_revision=expected_revision, run=run,
                            assignment=assignment, attempt=attempt)

    def open_blocker(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                     target: EntityRef, reason: str, *, idempotency_key: StableId,
                     expected_revision: int | None = None, run: EntityRef | None = None,
                     assignment: EntityRef | None = None, attempt: EntityRef | None = None) -> CommandResult:
        return self._mutate(authority, bearer_token, "blocker.open", plan_revision, target,
                            {"reason": reason}, idempotency_key=idempotency_key,
                            expected_revision=expected_revision, run=run,
                            assignment=assignment, attempt=attempt)

    def clear_blocker(self, authority: SQLiteAuthority, bearer_token: str, plan_revision: EntityRef,
                      target: EntityRef, reason: str, *, idempotency_key: StableId,
                      expected_revision: int | None = None, run: EntityRef | None = None,
                      assignment: EntityRef | None = None, attempt: EntityRef | None = None) -> CommandResult:
        return self._mutate(authority, bearer_token, "blocker.clear", plan_revision, target,
                            {"reason": reason}, idempotency_key=idempotency_key,
                            expected_revision=expected_revision, run=run,
                            assignment=assignment, attempt=attempt)

    def observer(self, authority: SQLiteAuthority) -> "SQLiteDeclarationObserver":
        return SQLiteDeclarationObserver(authority, identity=self.observer_identity, clock=self.clock)


class SQLiteDeclarationObserver(DeclarationObserver):
    """Read-only DeclarationObserver backed by accepted plans and native fact rows."""

    def __init__(self, authority: SQLiteAuthority, *, identity: ProviderIdentity,
                 clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if not isinstance(identity, ProviderIdentity):
            raise TypeError("identity must be a ProviderIdentity")
        self.authority = authority
        self.identity = identity
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @contextmanager
    def _read_connection(self):
        if self.authority.write_transaction_active:
            yield self.authority.connection
        else:
            with self.authority.read_transaction() as connection:
                yield connection

    def observe_declaration(self, request: DeclarationObservationRequest) -> ProviderResult[DeclarationObservation]:
        if not isinstance(request, DeclarationObservationRequest):
            raise TypeError("request must be a DeclarationObservationRequest")
        unknown = lambda reason: ProviderResult(
            ProviderStatus.UNKNOWN, request.correlation_id, provider=self.identity,
            reason_code=StableId(reason),
        )
        if request.context.project_id != self.authority.project.project_id:
            return unknown("declaration_project_unknown")
        kind = request.declaration_kind.value
        expected_entity = _SECTION_TO_ENTITY.get(kind)
        if expected_entity is not request.target.kind:
            return unknown("declaration_kind_mismatch")
        try:
            with self._read_connection() as connection:
                current = connection.execute(
                    "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                if current is None or current[0] != str(request.plan_revision_id):
                    return unknown("declaration_plan_stale")
                declaration = load_plan_declaration(
                    connection, self.authority.project, request.plan_revision_id, kind, request.target.entity_id,
                )
                if declaration is None or declaration.target != request.target or declaration.digest != request.declaration_digest.hex:
                    return unknown("declaration_payload_mismatch")
                attempt = connection.execute(
                    "SELECT a.actor_id, a.actor_incarnation_id, a.work_item_id, a.definition_revision_id, "
                    "a.state, a.lease_expires_at, a.run_id, a.assignment_id, w.workspace_id "
                    "FROM attempts AS a LEFT JOIN attempt_workspace_qualifications AS w USING(attempt_id) "
                    "WHERE a.attempt_id = ?", (str(request.attempt.entity_id),),
                ).fetchone()
                if attempt is None or attempt["workspace_id"] != str(request.workspace_id):
                    return unknown("declaration_attempt_workspace_unknown")
                if (attempt["actor_id"] != str(request.context.actor.entity_id)
                        or attempt["actor_incarnation_id"] != str(request.context.actor.incarnation_id)
                        or attempt["state"] not in {AttemptState.ADMITTED.value, AttemptState.ACTIVE.value, AttemptState.REPORTED.value}
                        or attempt["lease_expires_at"] is None
                        or datetime.fromisoformat(attempt["lease_expires_at"]) <= _now(self.clock)):
                    return unknown("declaration_attempt_not_live")
                if (attempt["run_id"] is not None):
                    run = connection.execute("SELECT plan_revision_id, state FROM runs WHERE run_id = ?", (attempt["run_id"],)).fetchone()
                    if run is None or run["state"] != "open" or run["plan_revision_id"] != str(request.plan_revision_id):
                        return unknown("declaration_attempt_run_mismatch")
                membership = connection.execute(
                    "SELECT 1 FROM plan_revision_work_items WHERE plan_revision_id = ? AND work_item_id = ? "
                    "AND definition_revision_id = ?", (str(request.plan_revision_id), attempt["work_item_id"], attempt["definition_revision_id"]),
                ).fetchone()
                if membership is None:
                    return unknown("declaration_attempt_definition_mismatch")
                capability = connection.execute(
                    "SELECT c.actor_id, c.actor_incarnation_id, c.scope_kind, c.scope_entity_id, "
                    "c.scope_definition_revision_id, c.attempt_id, c.run_id, c.assignment_id, c.expires_at, c.revoked "
                    "FROM capabilities AS c JOIN attempt_capabilities AS ac USING(capability_id) "
                    "WHERE c.capability_id = ? AND ac.attempt_id = ?",
                    (str(request.context.capability.entity_id), str(request.attempt.entity_id)),
                ).fetchone()
                if capability is None or bool(capability["revoked"]):
                    return unknown("declaration_capability_unknown")
                if (capability["actor_id"] != attempt["actor_id"]
                        or capability["actor_incarnation_id"] != attempt["actor_incarnation_id"]
                        or capability["scope_kind"] != EntityKind.WORK_ITEM.value
                        or capability["scope_entity_id"] != attempt["work_item_id"]
                        or capability["scope_definition_revision_id"] != attempt["definition_revision_id"]
                        or capability["attempt_id"] != str(request.attempt.entity_id)
                        or (capability["run_id"] is not None and capability["run_id"] != attempt["run_id"])
                        or (capability["assignment_id"] is not None and capability["assignment_id"] != attempt["assignment_id"])
                        or (capability["expires_at"] is not None and datetime.fromisoformat(capability["expires_at"]) <= _now(self.clock))):
                    return unknown("declaration_capability_mismatch")
                result, version, _option = declaration_condition(
                    connection, declaration, expected_version=request.expected_version,
                )
        except (AuthorityError, InvalidAuthorityError, TypeError, ValueError, KeyError, sqlite3.Error):
            return unknown("declaration_observation_unavailable")

        if result.status is ConditionStatus.UNRESOLVED and not result.causes:
            return unknown("declaration_fact_missing")
        # A missing native fact is UNKNOWN; a partial rendezvous has a cause and
        # is a real observation of an unresolved condition.
        if result.status is ConditionStatus.UNRESOLVED and result.causes and all(
            cause.code in {"decision_unresolved", "interface_unpublished", "rendezvous_arrival"}
            for cause in result.causes
        ):
            if kind != DeclarationKind.RENDEZVOUS.value or not any(
                cause.message == "participant arrived" for cause in result.causes
            ):
                return unknown("declaration_fact_missing")
        status = {
            ConditionStatus.SATISFIED: DeclarationStatus.SATISFIED,
            ConditionStatus.UNSATISFIED: DeclarationStatus.UNSATISFIED,
            ConditionStatus.UNRESOLVED: DeclarationStatus.UNRESOLVED,
            ConditionStatus.UNAVAILABLE: DeclarationStatus.UNRESOLVED,
        }[result.status]
        observation = DeclarationObservation(
            request.target, request.declaration_kind, request.declaration_digest, status, version,
        )
        observed_at = _now(self.clock)
        receipt = ProviderReceipt(
            StableId("declaration-receipt-" + uuid4().hex), self.identity, request.correlation_id,
            provider_request_digest(request), request.correlation_id, observed_at,
        )
        return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.correlation_id,
                              provider=self.identity, value=observation, receipt=receipt)


__all__ = [
    "BARRIER_RELEASE_ACTION", "BLOCKER_CLEAR_ACTION", "BLOCKER_OPEN_ACTION", "CHECKPOINT_ACCEPT_ACTION",
    "DECISION_RESOLVE_ACTION", "DeclarationError", "DeclarationMutationDeniedError",
    "DeclarationNotFoundError", "DeclarationObservationError", "DeclarationRecord", "DeclarationService",
    "INTERFACE_PUBLISH_ACTION", "RENDEZVOUS_ARRIVE_ACTION", "SQLiteDeclarationObserver",
    "NATIVE_DECLARATION_PROVIDER_IDENTITY", "declaration_condition", "load_plan_declaration",
    "native_declaration_facts",
]
