"""Authenticated durable scheduling for accepted plan work."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
from datetime import datetime

from todo_orchestrator.authority.attempts import (
    AttemptAdmissionDeniedError,
    AttemptHostUnavailableError,
    AttemptObservationMismatchError,
    AttemptOwnershipError,
    AttemptService,
    AttemptTransitionError,
    AttemptLeaseMismatchError,
    ATTEMPT_SESSION_ACTIONS,
    CLAIM_ACTION,
    FINISH_ACTION,
    RELEASE_ACTION,
    _Claim,
    _ClaimHandler,
    _Release,
    _ReleaseHandler,
    _attempt_from_row,
    _stable_id,
    _stored_attempt,
    _workspace_map,
)
from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    CapabilityDeniedError,
    CapabilityDeliveryUncertainError,
    AuthorityAuthService,
    _bearer,
    _capability_from_values,
    _context_from_row,
    _scope_from_row,
    _stored_actions,
    _stored_capability,
    _token_digest,
)
from todo_orchestrator.authority.commands import (
    DuplicateCommandHandlerError,
    MutationContext,
)
from todo_orchestrator.authority.sqlite import (
    AuthorityError,
    InvalidAuthorityError,
    ReadOnlyAuthorityError,
    SQLiteAuthority,
    load_plan_revision_snapshot,
)
from todo_orchestrator.contracts import (
    Assignment,
    Attempt,
    AttemptState,
    Capability,
    EntityKind,
    EntityRef,
    PlanRevisionState,
    Run,
    RunState,
    StableId,
)
from todo_orchestrator.model import (
    CommandEffect,
    CommandResult,
    EligibilityRequest,
    EligibilityStatus,
    IsolationPolicy,
    LaneSpec,
    QueueEntry,
    QueuePolicy,
    RunSchedule,
    RunScheduleView,
    ScheduledWork,
    DispatchResult,
)
from todo_orchestrator.planning import CompiledPlan, accepted_plan_payload, decode_accepted_plan

from .store import canonical_schedule_json, load_run_schedule, schedule_digest


RUN_SCHEDULE_ACTION = StableId("todo.run.schedule")
RUN_DISPATCH_ACTION = StableId("todo.run.dispatch")
ATTEMPT_FINISH_ACTION = FINISH_ACTION
_DEFAULT_LANE_ID = StableId("default")


class CoordinationError(AuthorityError):
    """Base class for persisted run scheduling errors."""


class RunScheduleConflictError(CoordinationError):
    """A run identifier already names a different immutable schedule."""


class RunScheduleNotFoundError(CoordinationError):
    """The requested run has no persisted schedule in this authority."""


class DispatchSelectionError(CoordinationError):
    """A selector does not resolve to current eligible scheduled work."""


class AmbiguousDispatchError(DispatchSelectionError):
    """A selector matches more than one open assignment."""


@dataclass(frozen=True)
class _Dispatch:
    plan_revision_id: StableId
    plan_payload_json: str
    workspace_id: StableId
    target: EntityRef | None
    requested_run: EntityRef | None
    assignment: EntityRef | None
    authorization_run: EntityRef | None
    attempt_id: StableId
    lease_id: StableId
    capability_id: StableId
    parent_bearer_digest: str
    child_token_digest: str
    idempotency_key: StableId

    def __deepcopy__(self, memo):
        # The trusted accepted-plan snapshot is reloaded from canonical JSON
        # inside apply; a mutable CompiledPlan never crosses the command seam.
        return self


class _DispatchHandler:
    kind = "todo.coordination.dispatch"
    command_type = _Dispatch

    def __init__(self, service: CoordinationService) -> None:
        self.service = service
        self.claim_handler = _ClaimHandler(service.attempts)

    def authorization_requirement(self, command: _Dispatch) -> AuthorizationRequirement:
        scope = command.target or command.assignment or command.requested_run
        if scope is None:
            raise DispatchSelectionError("dispatch requires a run, assignment, or exact work-item selector")
        return AuthorizationRequirement(
            RUN_DISPATCH_ACTION, scope, command.authorization_run or command.requested_run,
            command.assignment,
        )

    def canonical_payload(self, command: _Dispatch) -> dict[str, object]:
        return {
            "plan_revision_id": str(command.plan_revision_id),
            "plan_digest": hashlib.sha256(command.plan_payload_json.encode("utf-8")).hexdigest(),
            "workspace_id": str(command.workspace_id),
            "target": None if command.target is None else _ref_sort_key(command.target),
            "run": None if command.requested_run is None else str(command.requested_run.entity_id),
            "assignment": None if command.assignment is None else str(command.assignment.entity_id),
        }

    @staticmethod
    def _open_views(context: MutationContext) -> list[RunScheduleView]:
        rows = context._connection.execute(
            "SELECT run_id FROM runs WHERE state = 'open' ORDER BY run_id"
        ).fetchall()
        views = []
        for row in rows:
            try:
                view = load_run_schedule(context._connection, context.project, StableId(row[0]))
            except InvalidAuthorityError as exc:
                raise CoordinationError(f"stored run schedule is invalid: {exc}") from exc
            if view is None:
                raise InvalidAuthorityError("open run has no stored scheduling view")
            views.append(view)
        return views

    def _resolve_candidates(
        self, context: MutationContext, plan: CompiledPlan, command: _Dispatch
    ) -> tuple[tuple[EntityRef, EntityRef | None, EntityRef | None, QueueEntry | None], ...]:
        """Resolve exact targets and assignment context from the current writer snapshot."""
        if command.requested_run is not None:
            run_id = command.requested_run.entity_id
            try:
                view = load_run_schedule(context._connection, context.project, run_id)
            except InvalidAuthorityError as exc:
                raise CoordinationError(f"stored run schedule is invalid: {exc}") from exc
            if view is None:
                raise RunScheduleNotFoundError(f"run schedule does not exist: {run_id}")
            if view.run.state is not RunState.OPEN:
                raise DispatchSelectionError("dispatch requires an open run")
            if view.run.plan_revision != plan.revision.ref:
                raise DispatchSelectionError("run schedule is bound to a different accepted plan revision")
            entries = list(view.entries)
            if command.assignment is not None:
                entries = [entry for entry in entries if entry.assignment.ref == command.assignment]
            if command.target is not None:
                entries = [entry for entry in entries if entry.assignment.work_item == command.target]
            if command.assignment is not None or command.target is not None:
                if len(entries) != 1:
                    raise DispatchSelectionError("run, assignment, and target selectors do not identify one queue entry")
            elif not entries:
                raise DispatchSelectionError("run has no queue entries")
            return tuple((entry.assignment.work_item, view.run.ref, entry.assignment.ref, entry) for entry in entries)

        if command.assignment is not None:
            rows = context._connection.execute(
                "SELECT run_id FROM assignments WHERE assignment_id = ?",
                (str(command.assignment.entity_id),),
            ).fetchall()
            if len(rows) != 1:
                raise DispatchSelectionError("assignment is foreign or does not exist")
            view = load_run_schedule(context._connection, context.project, StableId(rows[0][0]))
            if view is None or view.run.state is not RunState.OPEN:
                raise DispatchSelectionError("assignment does not belong to an open run")
            if view.run.plan_revision != plan.revision.ref:
                raise DispatchSelectionError("assignment is bound to a different accepted plan revision")
            entries = [entry for entry in view.entries if entry.assignment.ref == command.assignment]
            if command.target is not None:
                entries = [entry for entry in entries if entry.assignment.work_item == command.target]
            if len(entries) != 1:
                raise DispatchSelectionError("assignment and target selectors do not identify one queue entry")
            entry = entries[0]
            return ((entry.assignment.work_item, view.run.ref, entry.assignment.ref, entry),)

        if command.target is None:
            raise DispatchSelectionError("dispatch requires a work-item, assignment, or run selector")
        if command.target.project_id != context.project.project_id:
            raise DispatchSelectionError("work-item selector belongs to another project")
        matches = []
        for view in self._open_views(context):
            if view.run.plan_revision != plan.revision.ref:
                continue
            for entry in view.entries:
                if entry.assignment.work_item == command.target:
                    matches.append((command.target, view.run.ref, entry.assignment.ref, entry))
        if len(matches) > 1:
            raise AmbiguousDispatchError("work item has multiple open assignments; specify a run or assignment")
        if matches:
            return (matches[0],)
        return ((command.target, None, None, None),)

    def apply(self, context: MutationContext, command: _Dispatch) -> CommandEffect:
        plan = _load_accepted_plan(
            context._connection, context, command.plan_revision_id, command.plan_payload_json
        )
        candidates = self._resolve_candidates(context, plan, command)
        automatic = command.requested_run is not None and command.assignment is None and command.target is None
        last_denial: AttemptAdmissionDeniedError | None = None
        last_unknown: AttemptAdmissionDeniedError | None = None
        for target, run, assignment, entry in candidates:
            if not any(item.definition.ref == target for item in plan.work_items):
                raise DispatchSelectionError("selected queue definition is absent from the accepted plan")
            exact_requirement = AuthorizationRequirement(CLAIM_ACTION, target, run, assignment)
            try:
                self.service.auth._authorize_capability(
                    context._connection, context.project, command.parent_bearer_digest,
                    context.actor, exact_requirement,
                )
                self.service.auth._authorize_capability(
                    context._connection, context.project, command.parent_bearer_digest,
                    context.actor,
                    AuthorizationRequirement(RUN_DISPATCH_ACTION, target, run, assignment),
                )
                if entry is not None and entry.required_role is not None:
                    self.service.auth._authorize_capability(
                        context._connection, context.project, command.parent_bearer_digest,
                        context.actor, AuthorizationRequirement(entry.required_role, target, run, assignment),
                    )
            except CapabilityDeniedError:
                if automatic:
                    continue
                raise

            correlation_seed = "\0".join((
                str(command.idempotency_key), str(target.project_id), str(target.entity_id),
                str(target.definition_revision_id),
            ))
            qualification_correlation = StableId(
                "workspace-proof-" + hashlib.sha256(correlation_seed.encode("utf-8")).hexdigest()
            )
            try:
                qualification = self.service.attempts.host.qualify_workspace(
                    command.workspace_id, target, qualification_correlation
                )
            except Exception as exc:
                raise AttemptHostUnavailableError(f"workspace qualification failed: {exc}") from exc
            now = self.service.attempts._now()
            self.service.attempts._validate_qualification(
                qualification, command.workspace_id, target, qualification_correlation,
                now, require_fresh=True,
            )
            qualifications = _workspace_map(context._connection, context.project)
            qualifications[target] = qualification
            request = EligibilityRequest(
                target, context.actor, CLAIM_ACTION, context.starting_revision, run, assignment,
            )
            decision = self.claim_handler._decision(
                context, request, plan, workspace_qualifications=qualifications,
            )
            if decision.status is not EligibilityStatus.ALLOWED:
                denial = AttemptAdmissionDeniedError(decision)
                if automatic and decision.status is EligibilityStatus.BLOCKED:
                    last_denial = denial
                    continue
                if automatic and decision.status is EligibilityStatus.UNKNOWN:
                    last_unknown = denial
                    continue
                raise denial

            claimed = self.claim_handler.apply(context, _Claim(
                target, plan, command.workspace_id, qualification, qualification_correlation,
                command.attempt_id, command.lease_id, run, assignment,
            ))
            expires_at = datetime.fromisoformat(str(claimed.result["lease_expires_at"]))
            attempt_ref = EntityRef(context.project.project_id, EntityKind.ATTEMPT, command.attempt_id)
            derived = self.service.auth._derive_scoped_capability_in_transaction(
                context,
                bearer_digest=command.parent_bearer_digest,
                requirement=exact_requirement,
                capability_id=command.capability_id,
                token_digest=command.child_token_digest,
                scope=target,
                actions=ATTEMPT_SESSION_ACTIONS,
                run=run,
                assignment=assignment,
                attempt=attempt_ref,
                expires_at=expires_at,
            )
            context.execute(
                "INSERT INTO attempt_capabilities(attempt_id, capability_id) VALUES (?, ?)",
                (str(command.attempt_id), str(command.capability_id)),
            )
            event = {
                "attempt_id": str(command.attempt_id),
                "work_item_id": str(target.entity_id),
                "definition_revision_id": str(target.definition_revision_id),
                "run_id": None if run is None else str(run.entity_id),
                "assignment_id": None if assignment is None else str(assignment.entity_id),
                "lease_id": str(command.lease_id),
                "lease_expires_at": expires_at.isoformat(timespec="microseconds"),
                "capability_id": str(derived.capability_id),
                "workspace_id": str(command.workspace_id),
            }
            return CommandEffect(
                True,
                {"attempt_id": str(command.attempt_id), "lease_id": str(command.lease_id),
                 "capability_id": str(command.capability_id),
                 "lease_expires_at": expires_at.isoformat(timespec="microseconds")},
                "todo.coordination.dispatched", event,
            )
        if last_unknown is not None:
            raise last_unknown
        if last_denial is not None:
            raise last_denial
        raise DispatchSelectionError("no queue entry is authorized and eligible for dispatch")


@dataclass(frozen=True)
class _Finish:
    attempt_ref: EntityRef
    target: EntityRef
    expected_lease_id: StableId
    run: EntityRef | None
    assignment: EntityRef | None
    observation: object | None
    bearer_digest: str

    def __deepcopy__(self, memo):
        return self


class _FinishHandler:
    kind = "todo.attempt.finish"
    command_type = _Finish

    def __init__(self, service: CoordinationService) -> None:
        self.service = service
        self.release_handler = _ReleaseHandler(service.attempts)

    def authorization_requirement(self, command: _Finish) -> AuthorizationRequirement:
        return AuthorizationRequirement(
            ATTEMPT_FINISH_ACTION, command.target, command.run,
            command.assignment, command.attempt_ref,
        )

    def canonical_payload(self, command: _Finish) -> dict[str, object]:
        return {
            "attempt_id": str(command.attempt_ref.entity_id),
            "target": _ref_sort_key(command.target),
            "expected_lease_id": str(command.expected_lease_id),
            "run": None if command.run is None else str(command.run.entity_id),
            "assignment": None if command.assignment is None else str(command.assignment.entity_id),
        }

    def apply(self, context: MutationContext, command: _Finish) -> CommandEffect:
        self.service.auth._authorize_capability(
            context._connection, context.project, command.bearer_digest,
            context.actor,
            AuthorizationRequirement(
                RELEASE_ACTION, command.target, command.run,
                command.assignment, command.attempt_ref,
            ),
        )
        released = self.release_handler.apply(context, _Release(
            command.target, command.attempt_ref, command.expected_lease_id,
            command.run, command.assignment, command.observation,
        ))
        result = dict(released.result)
        result["outcome_accepted"] = False
        return CommandEffect(released.changed, result, released.event_kind, released.event_payload)


@dataclass(frozen=True)
class _OpenRun:
    plan_revision_id: StableId
    plan_payload_json: str
    schedule: RunSchedule

    def __deepcopy__(self, memo):
        # Only immutable refs and a private canonical string cross the command
        # snapshot boundary; MappingProxyType plan fields stay out of dispatch.
        return self


def _ref_sort_key(ref: EntityRef) -> tuple[str, str, str, str, str]:
    return (
        str(ref.project_id), ref.kind.value, str(ref.entity_id),
        "" if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "" if ref.incarnation_id is None else str(ref.incarnation_id),
    )


def _assignment_id(run_id: StableId, work_item: EntityRef) -> StableId:
    value = "\0".join((str(run_id), *_ref_sort_key(work_item)))
    return StableId("assignment-" + hashlib.sha256(value.encode("utf-8")).hexdigest())


def _normalized_view(
    project_id: StableId,
    actor: EntityRef,
    plan: CompiledPlan,
    schedule: RunSchedule,
) -> RunScheduleView:
    if schedule.plan_revision != plan.revision.ref:
        raise CoordinationError("schedule plan revision does not match the supplied accepted plan")
    lanes = schedule.lanes or (
        LaneSpec(_DEFAULT_LANE_ID, QueuePolicy.SERIAL, None, IsolationPolicy.SHARED_SCOPES),
    )
    lanes = tuple(sorted(lanes, key=lambda lane: str(lane.lane_id)))
    lane_by_id = {lane.lane_id: lane for lane in lanes}

    plan_work = {item.definition.ref for item in plan.work_items}
    requested = schedule.work
    if not requested:
        if len(lanes) != 1:
            raise CoordinationError("an empty work list can use only a single lane")
        requested = tuple(ScheduledWork(ref, lanes[0].lane_id) for ref in sorted(plan_work, key=_ref_sort_key))
    if not requested:
        raise CoordinationError("a run schedule must contain at least one work item")

    placements: list[tuple[ScheduledWork, StableId]] = []
    for item in requested:
        if item.work_item.project_id != project_id or item.work_item not in plan_work:
            raise CoordinationError("scheduled work must match an exact definition in the supplied accepted plan")
        lane_id = item.lane_id
        if lane_id is None:
            if len(lanes) != 1:
                raise CoordinationError("work assigned to multiple lanes must specify its lane_id")
            lane_id = lanes[0].lane_id
        if lane_id not in lane_by_id:
            raise CoordinationError(f"scheduled work names an unknown lane: {lane_id}")
        placements.append((item, lane_id))
    used_lanes = {lane_id for _, lane_id in placements}
    if used_lanes != set(lane_by_id):
        raise CoordinationError("every declared lane must contain at least one scheduled work item")

    run_ref = EntityRef(project_id, EntityKind.RUN, schedule.run_id)
    run = Run(schedule.run_id, project_id, plan.revision.ref, RunState.OPEN, actor)
    entries: list[QueueEntry] = []
    for lane in lanes:
        members = sorted(
            ((item, lane_id) for item, lane_id in placements if lane_id == lane.lane_id),
            key=lambda pair: _ref_sort_key(pair[0].work_item),
        )
        for position, (item, _) in enumerate(members):
            assignment = Assignment(
                _assignment_id(schedule.run_id, item.work_item), project_id,
                item.work_item, item.assignee, run_ref,
            )
            entries.append(QueueEntry(
                assignment, lane.lane_id, position, lane.queue_policy,
                lane.required_role, lane.isolation_policy,
            ))
    distinct_assignees = {item.assignee for item, _ in placements if item.assignee is not None}
    has_parallel_work = any(lane.queue_policy is QueuePolicy.PARALLEL for lane in lanes) and len(entries) > 1
    if (len(distinct_assignees) > 1 or has_parallel_work) and schedule.charter is None:
        raise CoordinationError("multi-worker or parallel schedules require a typed run charter")
    return RunScheduleView(run, lanes, tuple(entries), schedule.charter)


def _load_accepted_plan(
    connection, context: MutationContext, plan_revision_id: StableId, plan_payload_json: str
) -> CompiledPlan:
    row = connection.execute(
        "SELECT state FROM plan_revisions WHERE plan_revision_id = ?",
        (str(plan_revision_id),),
    ).fetchone()
    if row is None or row["state"] != PlanRevisionState.ACCEPTED.value:
        raise CoordinationError("schedule requires an accepted plan revision")
    try:
        record = load_plan_revision_snapshot(connection, context.project, plan_revision_id)
        if record.sequence is None:
            raise InvalidAuthorityError("accepted plan sequence is missing")
        stored = decode_accepted_plan(record.canonical_json, context.project, sequence=record.sequence)
    except (InvalidAuthorityError, TypeError, ValueError) as exc:
        raise CoordinationError(f"accepted plan snapshot cannot be loaded: {exc}") from exc
    try:
        supplied_payload = json.loads(plan_payload_json)
    except (TypeError, ValueError) as exc:
        raise CoordinationError("private plan snapshot is not valid JSON") from exc
    if supplied_payload != accepted_plan_payload(stored):
        raise CoordinationError("typed plan fields do not match the stored accepted snapshot")
    return stored


class _OpenRunHandler:
    kind = "todo.run.schedule"
    command_type = _OpenRun

    def authorization_requirement(self, command: _OpenRun) -> AuthorizationRequirement:
        run_ref = EntityRef(command.schedule.plan_revision.project_id, EntityKind.RUN, command.schedule.run_id)
        return AuthorizationRequirement(RUN_SCHEDULE_ACTION, command.schedule.plan_revision, run=run_ref)

    def canonical_payload(self, command: _OpenRun) -> dict[str, object]:
        lanes = sorted(command.schedule.lanes, key=lambda lane: str(lane.lane_id))
        work = sorted(command.schedule.work, key=lambda item: _ref_sort_key(item.work_item))
        return {
            "run_id": str(command.schedule.run_id),
            "plan_revision_id": str(command.schedule.plan_revision.entity_id),
            "plan": json.loads(command.plan_payload_json),
            "lanes": [
                {
                    "lane_id": str(lane.lane_id),
                    "queue_policy": lane.queue_policy.value,
                    "required_role": None if lane.required_role is None else str(lane.required_role),
                    "isolation_policy": lane.isolation_policy.value,
                }
                for lane in lanes
            ],
            "work": [
                {
                    "work_item": _ref_sort_key(item.work_item),
                    "lane_id": None if item.lane_id is None else str(item.lane_id),
                    "assignee": None if item.assignee is None else _ref_sort_key(item.assignee),
                }
                for item in work
            ],
            "charter": None if command.schedule.charter is None else {
                "objective": command.schedule.charter.objective,
                "boundaries": list(command.schedule.charter.boundaries),
                "acceptance_conditions": list(command.schedule.charter.acceptance_conditions),
            },
        }

    def apply(self, context: MutationContext, command: _OpenRun) -> CommandEffect:
        accepted_plan = _load_accepted_plan(
            context._connection, context, command.plan_revision_id, command.plan_payload_json
        )
        candidate = _normalized_view(context.project.project_id, context.actor, accepted_plan, command.schedule)
        existing_run = context._connection.execute(
            "SELECT 1 FROM runs WHERE run_id = ?", (str(command.schedule.run_id),)
        ).fetchone()
        if existing_run is not None:
            existing = load_run_schedule(context._connection, context.project, command.schedule.run_id)
            if existing is not None and canonical_schedule_json(existing) == canonical_schedule_json(candidate):
                result = {
                    "run_id": str(existing.run.run_id),
                    "assignment_ids": [str(entry.assignment.assignment_id) for entry in existing.entries],
                }
                return CommandEffect(False, result)
            raise RunScheduleConflictError(
                f"run ID already names different or incomplete scheduling state: {command.schedule.run_id}"
            )

        encoded = canonical_schedule_json(candidate)
        digest = schedule_digest(encoded)
        context.execute(
            "INSERT INTO runs(run_id, plan_revision_id, state, created_by_actor_id, created_by_incarnation_id) "
            "VALUES (?, ?, 'open', ?, ?)",
            (str(candidate.run.run_id), str(candidate.run.plan_revision.entity_id),
             str(context.actor.entity_id), str(context.actor.incarnation_id)),
        )
        context.execute(
            "INSERT INTO run_schedules(run_id, schedule_json, schedule_digest) VALUES (?, ?, ?)",
            (str(candidate.run.run_id), encoded, digest),
        )
        for lane_ordinal, lane in enumerate(candidate.lanes):
            context.execute(
                "INSERT INTO run_lanes(run_id, lane_id, lane_ordinal, queue_policy, required_role, isolation_policy) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(candidate.run.run_id), str(lane.lane_id), lane_ordinal, lane.queue_policy.value,
                 None if lane.required_role is None else str(lane.required_role), lane.isolation_policy.value),
            )
        for entry in candidate.entries:
            assignment = entry.assignment
            context.execute(
                "INSERT INTO assignments(assignment_id, work_item_id, definition_revision_id, "
                "assignee_actor_id, assignee_incarnation_id, run_id) VALUES (?, ?, ?, ?, ?, ?)",
                (str(assignment.assignment_id), str(assignment.work_item.entity_id),
                 str(assignment.work_item.definition_revision_id),
                 None if assignment.assignee is None else str(assignment.assignee.entity_id),
                 None if assignment.assignee is None else str(assignment.assignee.incarnation_id),
                 str(candidate.run.run_id)),
            )
            context.execute(
                "INSERT INTO run_queue(assignment_id, run_id, lane_id, queue_position) VALUES (?, ?, ?, ?)",
                (str(assignment.assignment_id), str(candidate.run.run_id), str(entry.lane_id), entry.queue_position),
            )
        result = {
            "run_id": str(candidate.run.run_id),
            "assignment_ids": [str(entry.assignment.assignment_id) for entry in candidate.entries],
        }
        return CommandEffect(True, result, "todo.run.scheduled", {
            "run_id": str(candidate.run.run_id),
            "plan_revision_id": str(candidate.run.plan_revision.entity_id),
            "lane_count": len(candidate.lanes),
            "assignment_ids": [str(entry.assignment.assignment_id) for entry in candidate.entries],
        })


class CoordinationService:
    """Authenticated run scheduling with deterministic durable queue policy."""

    def __init__(self, auth: AuthorityAuthService, *, attempts: AttemptService | None = None) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if attempts is not None and (not isinstance(attempts, AttemptService) or attempts.auth is not auth):
            raise TypeError("attempts must be an AttemptService using the same auth service")
        self.auth = auth
        self.attempts = attempts
        try:
            auth.dispatcher.register(_OpenRunHandler())
        except DuplicateCommandHandlerError:
            binding = auth.dispatcher._by_type.get(_OpenRun)
            if binding is None or type(binding.handler) is not _OpenRunHandler:
                raise
        if attempts is not None:
            for handler in (_DispatchHandler(self), _FinishHandler(self)):
                try:
                    auth.dispatcher.register(handler)
                except DuplicateCommandHandlerError:
                    binding = auth.dispatcher._by_type.get(handler.command_type)
                    if binding is None or type(binding.handler) is not type(handler):
                        raise

    def open_run(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        plan: CompiledPlan,
        schedule: RunSchedule,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if not isinstance(plan, CompiledPlan) or plan.project != authority.project:
            raise ValueError("plan must be compiled for this authority project")
        if not isinstance(schedule, RunSchedule):
            raise TypeError("schedule must be a RunSchedule")
        if schedule.plan_revision.project_id != authority.project.project_id:
            raise ValueError("schedule plan revision belongs to another authority project")
        if schedule.plan_revision != plan.revision.ref:
            raise ValueError("schedule plan revision must match the supplied compiled plan")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        plan_payload_json = json.dumps(
            accepted_plan_payload(plan), ensure_ascii=True, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        )
        return self.auth.execute(
            authority, bearer_token,
            _OpenRun(plan.revision.plan_revision_id, plan_payload_json, schedule),
            idempotency_key=idempotency_key, expected_revision=expected_revision,
        )

    def read_run(self, authority: SQLiteAuthority, run_id: StableId) -> RunScheduleView:
        if not isinstance(authority, SQLiteAuthority):
            raise TypeError("authority must be a SQLiteAuthority")
        if not isinstance(run_id, StableId):
            raise TypeError("run_id must be a StableId")
        with authority.read_transaction() as connection:
            try:
                view = load_run_schedule(connection, authority.project, run_id)
            except InvalidAuthorityError as exc:
                raise CoordinationError(str(exc)) from exc
        if view is None:
            raise RunScheduleNotFoundError(f"run schedule does not exist: {run_id}")
        return view

    def dispatch(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        plan: CompiledPlan,
        *,
        workspace_id: StableId,
        idempotency_key: StableId,
        expected_revision: int | None = None,
        work_item: EntityRef | None = None,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
    ) -> DispatchResult:
        """Atomically select, claim, and issue one attempt-scoped bearer grant.

        A run-only selector picks the first currently eligible queue entry in
        the persisted lane/position order. Exact target and assignment selectors
        must be mutually consistent; target-only selection refuses multiple
        open assignments. Provider qualification is requested for the exact
        target selected under the writer transaction.
        """
        if self.attempts is None:
            raise CoordinationError("dispatch requires an injected AttemptService")
        if not isinstance(authority, SQLiteAuthority) or authority.readonly:
            raise ReadOnlyAuthorityError("dispatch requires a writable SQLite authority")
        if not isinstance(plan, CompiledPlan) or plan.project != authority.project:
            raise ValueError("plan must be compiled for this authority project")
        if not isinstance(workspace_id, StableId) or not isinstance(idempotency_key, StableId):
            raise TypeError("workspace_id and idempotency_key must be StableId values")
        for value, kind, name in (
            (work_item, EntityKind.WORK_ITEM, "work_item"),
            (run, EntityKind.RUN, "run"),
            (assignment, EntityKind.ASSIGNMENT, "assignment"),
        ):
            if value is not None and (not isinstance(value, EntityRef) or value.kind is not kind
                                      or value.project_id != authority.project.project_id):
                raise ValueError(f"{name} must be a project-local {kind.value} reference")
        if work_item is None and run is None and assignment is None:
            raise ValueError("dispatch requires a work_item, run, or assignment selector")
        if assignment is not None and run is None:
            with authority.read_transaction() as connection:
                row = connection.execute(
                    "SELECT run_id FROM assignments WHERE assignment_id = ?",
                    (str(assignment.entity_id),),
                ).fetchone()
            authorization_run = (
                EntityRef(authority.project.project_id, EntityKind.RUN, StableId(row[0]))
                if row is not None else None
            )
        else:
            authorization_run = run

        plan_payload_json = json.dumps(
            accepted_plan_payload(plan), ensure_ascii=True, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        )
        token = _bearer()
        command = _Dispatch(
            plan.revision.plan_revision_id, plan_payload_json, workspace_id,
            work_item, run, assignment, authorization_run,
            _stable_id("attempt", idempotency_key),
            _stable_id("lease", idempotency_key),
            _stable_id("dispatch-capability", idempotency_key),
            _token_digest(bearer_token), _token_digest(token), idempotency_key,
        )
        result = self.auth.execute(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision,
        )
        if result.replayed:
            raise CapabilityDeliveryUncertainError(result.receipt)
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(
                connection, authority.project,
                EntityRef(authority.project.project_id, EntityKind.ATTEMPT, command.attempt_id),
            )
            row = _stored_capability(connection, command.capability_id)
            if row is None or row["revoked"]:
                raise CoordinationError("dispatched attempt capability was not durably stored")
            capability_actor = attempt.actor
            scope = _scope_from_row(authority.project, row)
            cap_run, cap_assignment, cap_attempt = _context_from_row(authority.project, row)
            expires = None if row["expires_at"] is None else datetime.fromisoformat(row["expires_at"])
            capability = _capability_from_values(
                authority.project, command.capability_id, capability_actor, scope,
                _stored_actions(connection, command.capability_id), cap_run,
                cap_assignment, cap_attempt, expires,
                StableId(row["parent_capability_id"]) if row["parent_capability_id"] else None,
            )
        return DispatchResult(attempt, capability, token, result.receipt)

    def resume(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        plan: CompiledPlan,
        attempt_ref: EntityRef,
        expected_lease_id: StableId,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
        work_item: EntityRef | None = None,
        run: EntityRef | None = None,
        assignment: EntityRef | None = None,
    ) -> CommandResult:
        """Renew the exact persisted attempt after checking any supplied selectors."""
        if self.attempts is None:
            raise CoordinationError("resume requires an injected AttemptService")
        attempt = self.attempts._attempt_for_service(authority, attempt_ref)
        if attempt is not None:
            if work_item is not None and work_item != attempt.work_item:
                raise DispatchSelectionError("resume target conflicts with the persisted attempt")
            if run is not None and run != attempt.run:
                raise DispatchSelectionError("resume run conflicts with the persisted attempt")
            if assignment is not None and assignment != attempt.assignment:
                raise DispatchSelectionError("resume assignment conflicts with the persisted attempt")
        return self.attempts.heartbeat(
            authority, bearer_token, attempt_ref, expected_lease_id, plan,
            idempotency_key=idempotency_key, expected_revision=expected_revision,
        )

    def finish(
        self,
        authority: SQLiteAuthority,
        bearer_token: str,
        attempt_ref: EntityRef,
        expected_lease_id: StableId,
        *,
        idempotency_key: StableId,
        expected_revision: int | None = None,
    ) -> CommandResult:
        """Safely release an attempt, revoke its derived grant family, and accept no result."""
        if self.attempts is None:
            raise CoordinationError("finish requires an injected AttemptService")
        if not isinstance(idempotency_key, StableId):
            raise TypeError("idempotency_key must be a StableId")
        attempt = self.attempts._attempt_for_service(authority, attempt_ref)
        if attempt is None:
            target = attempt_ref
            run = assignment = None
        else:
            target, run, assignment = attempt.work_item, attempt.run, attempt.assignment
        observation = self.attempts._prepare_observation(authority, attempt_ref, idempotency_key)
        command = _Finish(
            attempt_ref, target, expected_lease_id, run, assignment,
            observation, _token_digest(bearer_token),
        )
        return self.auth.execute(
            authority, bearer_token, command, idempotency_key=idempotency_key,
            expected_revision=expected_revision,
        )


__all__ = [
    "CoordinationError", "CoordinationService", "RUN_SCHEDULE_ACTION",
    "RUN_DISPATCH_ACTION", "ATTEMPT_FINISH_ACTION", "DispatchSelectionError",
    "AmbiguousDispatchError", "RunScheduleConflictError", "RunScheduleNotFoundError",
]
