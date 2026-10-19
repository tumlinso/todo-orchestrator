"""Authenticated plan-preserving run close, retirement, and handoff operations.

Run schedules and assignments are immutable. Lifecycle commands change only
the run state and append an auditable disposition event; they never delete or
rewrite accepted plan, attempt, outcome, or workspace history.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
from typing import Any

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeniedError,
    _token_digest,
)
from todo_orchestrator.authority.commands import (
    CommandEnvelope,
    DuplicateCommandHandlerError,
    MutationContext,
)
from todo_orchestrator.authority.sqlite import AuthorityError, InvalidAuthorityError, SQLiteAuthority
from todo_orchestrator.contracts import (
    AttemptState,
    EntityKind,
    EntityRef,
    RunState,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.coordination.store import (
    canonical_schedule_json,
    load_run_schedule,
    schedule_digest,
)
from todo_orchestrator.coordination.service import RunScheduleNotFoundError
from todo_orchestrator.coordination.payloads import PayloadRejectedError, validate_bounded_text
from todo_orchestrator.model import CommandEffect, CommandResult, RunScheduleView


RUN_CLOSE_ACTION = StableId("todo.run.close")
RUN_RETIRE_ACTION = StableId("todo.run.retire")
RUN_HANDOFF_ACTION = StableId("todo.run.handoff")


class RunLifecycleError(AuthorityError):
    """Base refusal for an invalid or unsafe run lifecycle transition."""


class RunLifecycleStaleError(RunLifecycleError):
    """The caller's exact run schedule or authority revision is stale."""


class RunNotQuiescentError(RunLifecycleError):
    """The run still has live work or unresolved external authority."""


class RunDispositionError(RunLifecycleError):
    """A pending assignment lacks an explicit and valid disposition."""


@dataclass(frozen=True)
class RunAssignmentHandoff:
    """Explicitly carry one unfinished assignment to a successor run."""

    source_assignment: EntityRef
    successor_assignment: EntityRef

    def __post_init__(self) -> None:
        for name, value in (("source_assignment", self.source_assignment),
                            ("successor_assignment", self.successor_assignment)):
            if not isinstance(value, EntityRef) or value.kind is not EntityKind.ASSIGNMENT:
                raise ValueError(f"{name} must be an assignment reference")
            if value.definition_revision_id is not None or value.incarnation_id is not None:
                raise ValueError(f"{name} must identify the assignment without extra qualifiers")
        if self.source_assignment.project_id != self.successor_assignment.project_id:
            raise ValueError("handoff assignments must belong to one project")
        if self.source_assignment == self.successor_assignment:
            raise ValueError("a handoff must name a distinct successor assignment")


@dataclass(frozen=True)
class UnresolvedRunAssignment:
    """Preserve an unfinished assignment with an explicit unresolved reason."""

    assignment: EntityRef
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.assignment, EntityRef) or self.assignment.kind is not EntityKind.ASSIGNMENT:
            raise ValueError("assignment must reference an assignment")
        if self.assignment.definition_revision_id is not None or self.assignment.incarnation_id is not None:
            raise ValueError("assignment must identify the assignment without extra qualifiers")
        if not isinstance(self.reason, str):
            raise TypeError("reason must be text")
        validate_bounded_text(self.reason, field="unresolved assignment reason", max_bytes=512,
                              allow_multiline=False)


@dataclass(frozen=True)
class RunLifecycleRecord:
    """Exact persisted schedule and latest lifecycle disposition for a run."""

    schedule: RunScheduleView
    schedule_digest: Sha256Digest
    successor_run: EntityRef | None = None
    handoffs: tuple[RunAssignmentHandoff, ...] = ()
    unresolved: tuple[UnresolvedRunAssignment, ...] = ()
    event_kind: str | None = None
    semantic_revision: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.schedule, RunScheduleView):
            raise TypeError("schedule must be a RunScheduleView")
        if not isinstance(self.schedule_digest, Sha256Digest):
            raise TypeError("schedule_digest must be a Sha256Digest")
        if self.successor_run is not None and (
            self.successor_run.kind is not EntityKind.RUN
            or self.successor_run.project_id != self.schedule.run.project_id
        ):
            raise ValueError("successor_run must be a same-project RUN reference")
        if not isinstance(self.handoffs, tuple) or any(not isinstance(item, RunAssignmentHandoff) for item in self.handoffs):
            raise TypeError("handoffs must be a tuple of RunAssignmentHandoff values")
        if not isinstance(self.unresolved, tuple) or any(not isinstance(item, UnresolvedRunAssignment) for item in self.unresolved):
            raise TypeError("unresolved must be a tuple of UnresolvedRunAssignment values")
        if self.event_kind is not None and self.event_kind not in {"todo.run.closed", "todo.run.retired"}:
            raise ValueError("event_kind is not a run lifecycle event")
        if self.semantic_revision is not None and (type(self.semantic_revision) is not int or self.semantic_revision < 1):
            raise ValueError("semantic_revision must be positive when present")


def _ref_json(ref: EntityRef | None) -> dict[str, str | None] | None:
    if ref is None:
        return None
    return {
        "project_id": str(ref.project_id), "kind": ref.kind.value,
        "entity_id": str(ref.entity_id),
        "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
    }


def _assignment_ref(project_id: StableId, assignment_id: str) -> EntityRef:
    return EntityRef(project_id, EntityKind.ASSIGNMENT, StableId(assignment_id))


def _parse_ref(value: Any, project_id: StableId, kind: EntityKind) -> EntityRef:
    if not isinstance(value, dict) or set(value) != {
        "project_id", "kind", "entity_id", "definition_revision_id", "incarnation_id",
    }:
        raise ValueError("lifecycle event reference has an invalid shape")
    ref = EntityRef(
        StableId(value["project_id"]), EntityKind(value["kind"]), StableId(value["entity_id"]),
        None if value["definition_revision_id"] is None else StableId(value["definition_revision_id"]),
        None if value["incarnation_id"] is None else StableId(value["incarnation_id"]),
    )
    if ref.project_id != project_id or ref.kind is not kind:
        raise ValueError("lifecycle event reference has an invalid project or kind")
    return ref


def _schedule(connection: sqlite3.Connection, authority: SQLiteAuthority, run_ref: EntityRef) -> RunScheduleView:
    if run_ref.project_id != authority.project.project_id or run_ref.kind is not EntityKind.RUN:
        raise RunLifecycleError("run reference must belong to this authority")
    try:
        view = load_run_schedule(connection, authority.project, run_ref.entity_id)
    except InvalidAuthorityError as exc:
        raise RunLifecycleError("stored run schedule is invalid") from exc
    if view is None:
        raise RunScheduleNotFoundError("run schedule does not exist")
    if view.run.ref != run_ref:
        raise RunLifecycleStaleError("run identity differs from its stored schedule")
    return view


def _digest(view: RunScheduleView) -> Sha256Digest:
    return Sha256Digest(schedule_digest(canonical_schedule_json(view)))


_BLOCKING_ATTEMPT_STATES = frozenset({
    AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED,
    AttemptState.EXPIRED, AttemptState.UNCERTAIN, AttemptState.QUARANTINED,
})


def _assignment_status(connection: sqlite3.Connection, assignment: EntityRef) -> tuple[bool, str | None]:
    """Return accepted-result presence and a stable blocker if work is unresolved."""
    completed = connection.execute(
        "SELECT 1 FROM outcomes WHERE work_item_id = ? AND definition_revision_id = ? LIMIT 1",
        (str(assignment.entity_id), str(assignment.definition_revision_id)),
    ).fetchone() is not None
    return completed, None


def _quiescence_blockers(connection: sqlite3.Connection, run_id: StableId) -> tuple[str, ...]:
    """Check all durable execution surfaces before a run can change lifecycle."""
    from todo_orchestrator.authority.child_store import require_parent_children_resolved

    blockers: set[str] = set()
    rows = connection.execute(
        "SELECT attempt_id, state FROM attempts WHERE run_id = ? ORDER BY attempt_id",
        (str(run_id),),
    ).fetchall()
    for row in rows:
        attempt_id = StableId(row["attempt_id"])
        if AttemptState(row["state"]) in _BLOCKING_ATTEMPT_STATES:
            blockers.add(f"attempt:{attempt_id}:{row['state']}")
        candidate = connection.execute(
            "SELECT 1 FROM outcome_candidates WHERE attempt_id = ? AND state = 'pending' LIMIT 1",
            (str(attempt_id),),
        ).fetchone()
        if candidate is not None:
            blockers.add(f"pending_candidate:{attempt_id}")
        try:
            require_parent_children_resolved(connection, attempt_id)
        except ValueError:
            blockers.add(f"unresolved_child:{attempt_id}")
        for table, settled in (
            ("external_operations", {"finalized", "failed", "not_applied"}),
            ("git_effect_operations", {"finalized", "failed", "not_applied"}),
            ("verification_attempts", {"finalized", "failed", "rejected", "stale", "not_started"}),
        ):
            # The table schemas are fixed by the authority version. Each lookup
            # is bounded to the exact attempt and never rewrites provider state.
            if table == "external_operations":
                pending = connection.execute(
                    "SELECT operation_id, state FROM external_operations WHERE attempt_id = ? ORDER BY operation_id",
                    (str(attempt_id),),
                ).fetchall()
            elif table == "git_effect_operations":
                pending = connection.execute(
                    "SELECT g.operation_id, g.state FROM git_effect_operations AS g "
                    "JOIN external_operations AS e USING(operation_id) WHERE e.attempt_id = ? ORDER BY g.operation_id",
                    (str(attempt_id),),
                ).fetchall()
            else:
                pending = connection.execute(
                    "SELECT operation_id, state FROM verification_attempts WHERE attempt_id = ? ORDER BY operation_id",
                    (str(attempt_id),),
                ).fetchall()
            blockers.update(
                f"{table}:{item['operation_id']}:{item['state']}"
                for item in pending if item["state"] not in settled
            )

    # Workspace creation can be durably prepared for an exact run assignment
    # before AttemptService creates an attempt. Those operations have no
    # external_operations.attempt_id, so the attempt loop above cannot see
    # them. Bind their safety status through the immutable typed request rather
    # than allowing run retirement to erase an in-flight workspace reservation.
    from todo_orchestrator.providers.git.service import _intent_from

    pre_attempt = connection.execute(
        "SELECT e.operation_id, e.state AS external_state, g.state AS effect_state, g.request_json "
        "FROM external_operations AS e JOIN git_effect_operations AS g USING (operation_id) "
        "WHERE e.attempt_id IS NULL ORDER BY e.operation_id"
    ).fetchall()
    settled_external = {"finalized", "failed", "not_applied"}
    settled_git = {"finalized", "not_applied"}
    for operation in pre_attempt:
        try:
            request, _ = _intent_from(operation["request_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            # An unparseable immutable request cannot be safely attributed to a
            # different run. Conservatively keep all run lifecycle changes
            # blocked until its identity can be inspected.
            blockers.add(f"unclassified_pre_attempt_git_effect:{operation['operation_id']}")
            continue
        if request.run is None or request.run.entity_id != run_id:
            continue
        if (operation["external_state"] not in settled_external
                or operation["effect_state"] not in settled_git):
            blockers.add(
                f"pre_attempt_git_effect:{operation['operation_id']}:{operation['effect_state']}"
            )
    return tuple(sorted(blockers))


def _exact_successor_plan(connection: sqlite3.Connection, authority: SQLiteAuthority, view: RunScheduleView):
    from todo_orchestrator.planning.service import _load_plan

    return _load_plan(connection, authority.project, view.run.plan_revision.entity_id)


def _validate_handoff(
    connection: sqlite3.Connection,
    authority: SQLiteAuthority,
    source: RunScheduleView,
    successor: RunScheduleView,
    handoff: RunAssignmentHandoff,
) -> None:
    source_entry = next((item for item in source.entries if item.assignment.ref == handoff.source_assignment), None)
    successor_entry = next((item for item in successor.entries if item.assignment.ref == handoff.successor_assignment), None)
    if source_entry is None:
        raise RunDispositionError("handoff source assignment is not in the retiring run")
    if successor_entry is None:
        raise RunDispositionError("handoff destination assignment is not in the successor run")
    if _assignment_status(connection, source_entry.assignment.work_item)[0]:
        raise RunDispositionError("completed assignments cannot be handed off as unfinished work")
    old_work = source_entry.assignment.work_item
    new_work = successor_entry.assignment.work_item
    if old_work == new_work:
        return
    plan = _exact_successor_plan(connection, authority, successor)
    if plan is None:
        raise RunDispositionError("successor run has no accepted plan snapshot")
    new_item = next((item for item in plan.work_items if item.definition.ref == new_work), None)
    if new_item is None or old_work not in new_item.definition.supersedes:
        raise RunDispositionError("successor work must explicitly supersede the exact source definition")


def _validate_retirement(
    connection: sqlite3.Connection,
    authority: SQLiteAuthority,
    source: RunScheduleView,
    successor: RunScheduleView | None,
    handoffs: tuple[RunAssignmentHandoff, ...],
    unresolved: tuple[UnresolvedRunAssignment, ...],
) -> tuple[dict[str, object], ...]:
    source_ids = {entry.assignment.ref for entry in source.entries}
    handoff_sources = [item.source_assignment for item in handoffs]
    unresolved_refs = [item.assignment for item in unresolved]
    if len(set(handoff_sources)) != len(handoff_sources) or len(set(unresolved_refs)) != len(unresolved_refs):
        raise RunDispositionError("retirement dispositions must identify each assignment at most once")
    if set(handoff_sources) & set(unresolved_refs):
        raise RunDispositionError("an assignment cannot be both handed off and left unresolved")
    if any(item not in source_ids for item in (*handoff_sources, *unresolved_refs)):
        raise RunDispositionError("retirement disposition names an assignment outside the source run")
    if handoffs and successor is None:
        raise RunDispositionError("handoffs require an exact successor run")
    if successor is not None:
        if successor.run.ref == source.run.ref:
            raise RunDispositionError("a run cannot succeed itself")
        if successor.run.state is not RunState.OPEN:
            raise RunDispositionError("successor run must remain open")
        latest = connection.execute(
            "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest is None or latest[0] != str(successor.run.plan_revision.entity_id):
            raise RunDispositionError("successor run must use the current accepted plan revision")

    result = []
    dispositions = {item.source_assignment: item for item in handoffs}
    unresolved_by_ref = {item.assignment: item for item in unresolved}
    for entry in source.entries:
        assignment_ref = entry.assignment.ref
        completed, _ = _assignment_status(connection, entry.assignment.work_item)
        handoff = dispositions.get(assignment_ref)
        unresolved_item = unresolved_by_ref.get(assignment_ref)
        if completed:
            if handoff is not None or unresolved_item is not None:
                raise RunDispositionError("completed assignments cannot be reclassified during retirement")
            result.append({"assignment": _ref_json(assignment_ref), "disposition": "completed"})
            continue
        if (handoff is None) == (unresolved_item is None):
            raise RunDispositionError("each incomplete assignment needs exactly one handoff or unresolved reason")
        if handoff is not None:
            assert successor is not None
            _validate_handoff(connection, authority, source, successor, handoff)
            result.append({
                "assignment": _ref_json(assignment_ref), "disposition": "handed_off",
                "successor_assignment": _ref_json(handoff.successor_assignment),
            })
        else:
            assert unresolved_item is not None
            try:
                validate_bounded_text(unresolved_item.reason, field="unresolved assignment reason", max_bytes=512,
                                      connection=connection, allow_multiline=False)
            except (PayloadRejectedError, ValueError) as exc:
                raise RunDispositionError("unresolved reason contains unsafe text") from exc
            result.append({
                "assignment": _ref_json(assignment_ref), "disposition": "unresolved",
                "reason": unresolved_item.reason,
            })
    return tuple(result)


@dataclass(frozen=True)
class _CloseRun:
    run_ref: EntityRef
    schedule_digest: Sha256Digest
    expected_revision: int

    def __deepcopy__(self, memo):
        return self


@dataclass(frozen=True)
class _RetireRun:
    run_ref: EntityRef
    schedule_digest: Sha256Digest
    expected_revision: int
    successor_run: EntityRef | None
    successor_schedule_digest: Sha256Digest | None
    handoffs: tuple[RunAssignmentHandoff, ...]
    unresolved: tuple[UnresolvedRunAssignment, ...]

    def __deepcopy__(self, memo):
        return self


class _LifecycleHandler:
    def __init__(self, service: RunLifecycleService, *, retire: bool) -> None:
        self.service = service
        self.retire = retire
        self.command_type = _RetireRun if retire else _CloseRun
        self.kind = "todo.run.retire" if retire else "todo.run.close"

    def authorization_requirement(self, command):
        action = RUN_RETIRE_ACTION if self.retire else RUN_CLOSE_ACTION
        return AuthorizationRequirement(action, command.run_ref, run=command.run_ref)

    def canonical_payload(self, command):
        payload: dict[str, object] = {
            "run": _ref_json(command.run_ref),
            "schedule_digest": command.schedule_digest.hex,
            "expected_revision": command.expected_revision,
        }
        if self.retire:
            payload.update({
                "successor_run": _ref_json(command.successor_run),
                "successor_schedule_digest": None if command.successor_schedule_digest is None
                    else command.successor_schedule_digest.hex,
                "handoffs": [
                    {"source_assignment": _ref_json(item.source_assignment),
                     "successor_assignment": _ref_json(item.successor_assignment)}
                    for item in command.handoffs
                ],
                "unresolved": [
                    {"assignment": _ref_json(item.assignment), "reason": item.reason}
                    for item in command.unresolved
                ],
            })
        return payload

    def apply(self, context: MutationContext, command) -> CommandEffect:
        if command.expected_revision != context.starting_revision:
            raise RunLifecycleStaleError("expected authority revision differs from the locked writer snapshot")
        source = _schedule(context._connection, context.authority, command.run_ref)
        actual_digest = _digest(source)
        if actual_digest != command.schedule_digest:
            raise RunLifecycleStaleError("run schedule digest changed since lifecycle review")
        row = context._connection.execute("SELECT state FROM runs WHERE run_id = ?", (str(command.run_ref.entity_id),)).fetchone()
        if row is None:
            raise RunScheduleNotFoundError("run schedule does not exist")
        state = RunState(row["state"])

        if self.retire and state is RunState.RETIRED:
            existing = self.service._latest_event(context._connection, context.project.project_id, command.run_ref.entity_id)
            proposed = self.canonical_payload(command)
            if existing is not None and existing["event_kind"] == "todo.run.retired":
                stored = json.loads(existing["payload_json"])
                keys = ("successor_run", "successor_schedule_digest", "handoffs", "unresolved")
                if all(stored.get(key) == proposed.get(key) for key in keys):
                    return CommandEffect(False, {"run_id": str(command.run_ref.entity_id), "state": "retired"})
            raise RunDispositionError("retired run has a different durable disposition")
        if not self.retire and state is RunState.CLOSED:
            return CommandEffect(False, {"run_id": str(command.run_ref.entity_id), "state": "closed"})
        if not self.retire and state is RunState.RETIRED:
            raise RunLifecycleError("retired runs cannot be closed")
        if state not in ({RunState.OPEN, RunState.CLOSED} if self.retire else {RunState.OPEN}):
            raise RunLifecycleError("run is not in a state that permits this transition")

        blockers = _quiescence_blockers(context._connection, command.run_ref.entity_id)
        if blockers:
            raise RunNotQuiescentError("run has unresolved execution authority: " + ", ".join(blockers))
        if self.retire:
            successor = None
            successor_digest = None
            if command.successor_run is not None:
                successor = _schedule(context._connection, context.authority, command.successor_run)
                successor_digest = _digest(successor)
                if successor_digest != command.successor_schedule_digest:
                    raise RunLifecycleStaleError("successor schedule digest changed since lifecycle review")
            dispositions = _validate_retirement(
                context._connection, context.authority, source, successor,
                command.handoffs, command.unresolved,
            )
            payload = self.canonical_payload(command)
            payload.update({
                "from_state": state.value,
                "dispositions": list(dispositions),
            })
            next_state = RunState.RETIRED
            event_kind = "todo.run.retired"
            result = {"run_id": str(command.run_ref.entity_id), "state": next_state.value,
                      "successor_run_id": None if command.successor_run is None else str(command.successor_run.entity_id),
                      "handoff_count": len(command.handoffs), "unresolved_count": len(command.unresolved)}
        else:
            missing = [entry.assignment.ref for entry in source.entries
                       if not _assignment_status(context._connection, entry.assignment.work_item)[0]]
            if missing:
                raise RunDispositionError("run cannot close with incomplete assignments: " +
                                          ", ".join(str(item.entity_id) for item in missing))
            next_state = RunState.CLOSED
            event_kind = "todo.run.closed"
            payload = self.canonical_payload(command)
            payload["from_state"] = state.value
            result = {"run_id": str(command.run_ref.entity_id), "state": next_state.value}

        cursor = context.execute(
            "UPDATE runs SET state = ? WHERE run_id = ? AND state = ?",
            (next_state.value, str(command.run_ref.entity_id), state.value),
        )
        if cursor.rowcount != 1:
            raise RunLifecycleStaleError("run state changed while applying lifecycle transition")
        return CommandEffect(True, result, event_kind, payload)


class RunLifecycleService:
    """Read and apply quiescent run closure or explicit retirement/handoff."""

    def __init__(self, auth: AuthorityAuthService) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        self.auth = auth
        for retire, command_type in ((False, _CloseRun), (True, _RetireRun)):
            handler = _LifecycleHandler(self, retire=retire)
            try:
                auth.dispatcher.register(handler)
            except DuplicateCommandHandlerError:
                binding = auth.dispatcher._by_type.get(command_type)
                if binding is None or type(binding.handler) is not _LifecycleHandler:
                    raise

    @staticmethod
    def _validate_call(authority: SQLiteAuthority, bearer_token: str, run_ref: EntityRef,
                       schedule_digest_value: Sha256Digest, idempotency_key: StableId,
                       expected_revision: int) -> None:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if not isinstance(bearer_token, str) or not bearer_token:
            raise TypeError("bearer_token must be non-empty text")
        if not isinstance(run_ref, EntityRef) or run_ref.kind is not EntityKind.RUN:
            raise TypeError("run_ref must reference a run")
        if run_ref.project_id != authority.project.project_id:
            raise ValueError("run_ref must belong to this authority")
        if not isinstance(schedule_digest_value, Sha256Digest):
            raise TypeError("schedule_digest must be a Sha256Digest")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")

    def _latest_event(self, connection: sqlite3.Connection, project_id: StableId, run_id: StableId):
        rows = connection.execute(
            "SELECT event_id, semantic_revision, event_kind, payload_json FROM authority_events "
            "WHERE event_kind IN ('todo.run.closed', 'todo.run.retired') ORDER BY semantic_revision DESC, event_ordinal DESC"
        ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError) as exc:
                raise RunLifecycleError("stored run lifecycle event is invalid") from exc
            if payload.get("run", {}).get("project_id") == str(project_id) and payload.get("run", {}).get("entity_id") == str(run_id):
                return row
        return None

    def read_lifecycle(self, authority: SQLiteAuthority, run_ref: EntityRef) -> RunLifecycleRecord:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if not isinstance(run_ref, EntityRef) or run_ref.kind is not EntityKind.RUN:
            raise TypeError("run_ref must reference a run")
        with authority.read_transaction() as connection:
            schedule = _schedule(connection, authority, run_ref)
            event = self._latest_event(connection, authority.project.project_id, run_ref.entity_id)
            if event is None:
                return RunLifecycleRecord(schedule, _digest(schedule))
            try:
                payload = json.loads(event["payload_json"])
                successor_raw = payload.get("successor_run")
                successor = None if successor_raw is None else _parse_ref(successor_raw, authority.project.project_id, EntityKind.RUN)
                handoffs = tuple(RunAssignmentHandoff(
                    _parse_ref(item["source_assignment"], authority.project.project_id, EntityKind.ASSIGNMENT),
                    _parse_ref(item["successor_assignment"], authority.project.project_id, EntityKind.ASSIGNMENT),
                ) for item in payload.get("handoffs", ()))
                unresolved = tuple(UnresolvedRunAssignment(
                    _parse_ref(item["assignment"], authority.project.project_id, EntityKind.ASSIGNMENT),
                    item["reason"],
                ) for item in payload.get("unresolved", ()))
                return RunLifecycleRecord(
                    schedule, _digest(schedule), successor, handoffs, unresolved,
                    event["event_kind"], event["semantic_revision"],
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RunLifecycleError("stored run lifecycle lineage is invalid") from exc

    def close_run(self, authority: SQLiteAuthority, bearer_token: str, run_ref: EntityRef, *,
                  schedule_digest: Sha256Digest, idempotency_key: StableId,
                  expected_revision: int) -> CommandResult:
        self._validate_call(authority, bearer_token, run_ref, schedule_digest, idempotency_key, expected_revision)
        return self._execute(
            authority, bearer_token, _CloseRun(run_ref, schedule_digest, expected_revision),
            idempotency_key=idempotency_key, expected_revision=expected_revision,
        )

    def retire_run(self, authority: SQLiteAuthority, bearer_token: str, run_ref: EntityRef, *,
                   schedule_digest: Sha256Digest, idempotency_key: StableId,
                   expected_revision: int, successor_run: EntityRef | None = None,
                   handoffs: tuple[RunAssignmentHandoff, ...] = (),
                   unresolved: tuple[UnresolvedRunAssignment, ...] = ()) -> CommandResult:
        self._validate_call(authority, bearer_token, run_ref, schedule_digest, idempotency_key, expected_revision)
        if not isinstance(handoffs, tuple) or any(not isinstance(item, RunAssignmentHandoff) for item in handoffs):
            raise TypeError("handoffs must be a tuple of RunAssignmentHandoff values")
        if not isinstance(unresolved, tuple) or any(not isinstance(item, UnresolvedRunAssignment) for item in unresolved):
            raise TypeError("unresolved must be a tuple of UnresolvedRunAssignment values")
        if successor_run is not None and (
            not isinstance(successor_run, EntityRef) or successor_run.kind is not EntityKind.RUN
            or successor_run.project_id != run_ref.project_id
        ):
            raise ValueError("successor_run must reference a run in this project")
        if any(item.source_assignment.project_id != run_ref.project_id
               or item.successor_assignment.project_id != run_ref.project_id for item in handoffs):
            raise ValueError("handoff assignments must belong to this project")
        if any(item.assignment.project_id != run_ref.project_id for item in unresolved):
            raise ValueError("unresolved assignments must belong to this project")
        successor_digest = None
        if successor_run is not None:
            with authority.read_transaction() as connection:
                successor_view = _schedule(connection, authority, successor_run)
                successor_digest = _digest(successor_view)
        command = _RetireRun(
            run_ref, schedule_digest, expected_revision, successor_run, successor_digest,
            handoffs, unresolved,
        )
        return self._execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                             expected_revision=expected_revision)

    def _execute(self, authority: SQLiteAuthority, bearer_token: str, command: _CloseRun | _RetireRun,
                 *, idempotency_key: StableId, expected_revision: int) -> CommandResult:
        """Reauthorize the source action and each exact handoff on every replay."""
        digest = _token_digest(bearer_token)
        actor, _capability_id = self.auth._actor_for_token(authority, digest)
        envelope = CommandEnvelope(
            command, idempotency_key,
            self.auth._revision(authority, expected_revision), actor,
        )

        def check(connection, snapshot, handler, current_actor):
            requirement = handler.authorization_requirement(snapshot)
            authorized = self.auth._authorize_capability(
                connection, authority.project, digest, current_actor, requirement,
            )
            if isinstance(snapshot, _RetireRun) and snapshot.handoffs:
                if snapshot.successor_run is None:
                    raise CapabilityDeniedError("run handoff has no successor context")
                for item in snapshot.handoffs:
                    self.auth._authorize_capability(
                        connection, authority.project, digest, current_actor,
                        AuthorizationRequirement(
                            RUN_HANDOFF_ACTION, snapshot.successor_run,
                            run=snapshot.successor_run,
                            assignment=item.successor_assignment,
                        ),
                    )
            return authorized

        return self.auth.dispatcher._execute_authorized(authority, envelope, check)


__all__ = [
    "RUN_CLOSE_ACTION", "RUN_HANDOFF_ACTION", "RUN_RETIRE_ACTION",
    "RunAssignmentHandoff", "RunDispositionError", "RunLifecycleError",
    "RunLifecycleRecord", "RunLifecycleStaleError", "RunLifecycleService",
    "RunNotQuiescentError", "UnresolvedRunAssignment",
]
