"""Deterministic read and transactional admission eligibility policy.

The pure evaluator consumes immutable authority facts. ``EligibilityAdapter``
obtains local facts from one validated SQLite authority and uses an injected
clock; host/provider observations and compiled authored context are inputs to
that trusted adapter, not authentication. A later trust boundary must bind
those inputs to the actual caller and source operation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from types import MappingProxyType
from typing import Any

from todo_orchestrator.contracts import (
    Assignment,
    Attempt,
    AttemptState,
    Capability,
    EntityKind,
    EntityRef,
    Lease,
    Outcome,
    OutcomeDisposition,
    PlanRevisionState,
    Project,
    RequirementKind,
    Run,
    RunState,
    StableId,
)
from todo_orchestrator.model.eligibility import (
    AttemptScopeSnapshot,
    EligibilityCause,
    EligibilityDecision,
    EligibilityRequest,
    EligibilityStatus,
    WorkspaceQualification,
)
from todo_orchestrator.model.children import ChildScopeOccupancy
from todo_orchestrator.model.coordination import IsolationPolicy, QueueEntry, QueuePolicy
from todo_orchestrator.planning import (
    BlockingEdge,
    BlockingGroup,
    ConditionCause,
    ConditionResult,
    ConditionStatus,
    CompiledPlan,
    DecisionObservation,
    evaluate_blocking_group,
    evaluate_results,
)
from todo_orchestrator.planning.package import WorkItemContext
from todo_orchestrator.planning.snapshot import accepted_plan_payload, decode_accepted_plan

from .sqlite import AuthorityError, InvalidAuthorityError, ReadOnlyAuthorityError, SQLiteAuthority, load_plan_revision_snapshot
from .scopes import plan_scope_membership, scope_covers
from .declarations import native_declaration_facts
from todo_orchestrator.coordination.store import load_all_queue_entries


class EligibilityAdapterError(AuthorityError):
    """Eligibility facts could not be safely observed from this authority."""


@dataclass(frozen=True)
class EligibilityFacts:
    """One immutable, revision-consistent eligibility snapshot.

    External blocker, decision, workspace, and extra scope facts are trusted
    adapter inputs. Provider receipts are observations, not attestations.
    """

    project: Project
    authority_revision: int
    evaluated_at: datetime
    plan: CompiledPlan
    plan_matches_authority: bool
    accepted_plan_revision: bool
    registered_actors: frozenset[EntityRef]
    capabilities: tuple[Capability, ...]
    revoked_capability_ids: frozenset[StableId]
    runs: Mapping[EntityRef, Run]
    assignments: Mapping[EntityRef, Assignment]
    attempts: tuple[Attempt, ...]
    outcomes: Mapping[EntityRef, Outcome]
    legacy_completion_assertions: Mapping[EntityRef, str] = field(default_factory=dict)
    queue_entries: Mapping[EntityRef, QueueEntry] = field(default_factory=dict)
    blocker_observations: Mapping[EntityRef, ConditionResult] = field(default_factory=dict)
    check_observations: Mapping[StableId, ConditionResult] = field(default_factory=dict)
    decision_observations: Mapping[str, DecisionObservation] = field(default_factory=dict)
    scope_contexts: Mapping[EntityRef, WorkItemContext] = field(default_factory=dict)
    plan_memberships: Mapping[EntityRef, frozenset[EntityRef]] = field(default_factory=dict)
    workspace_qualifications: Mapping[EntityRef, WorkspaceQualification] = field(default_factory=dict)
    approved_participants: Mapping[EntityRef, frozenset[EntityRef]] = field(default_factory=dict)
    attempt_scope_snapshots: Mapping[EntityRef, AttemptScopeSnapshot] = field(default_factory=dict)
    child_scope_occupancies: tuple[ChildScopeOccupancy, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.project, Project):
            raise TypeError("project must be a Project")
        if type(self.authority_revision) is not int or self.authority_revision < 0:
            raise ValueError("authority_revision must be a non-negative integer")
        _require_aware(self.evaluated_at, "evaluated_at")
        if not isinstance(self.plan, CompiledPlan):
            raise TypeError("plan must be a CompiledPlan")
        if self.plan.project != self.project:
            raise ValueError("plan and eligibility facts must have the same project identity")
        if type(self.plan_matches_authority) is not bool or type(self.accepted_plan_revision) is not bool:
            raise TypeError("plan authority flags must be bool values")
        if not isinstance(self.registered_actors, frozenset) or any(
            not isinstance(ref, EntityRef) or ref.kind is not EntityKind.ACTOR
            or ref.project_id != self.project.project_id
            for ref in self.registered_actors
        ):
            raise TypeError("registered_actors must be same-project actor incarnation references")
        if not isinstance(self.capabilities, tuple) or any(not isinstance(value, Capability) for value in self.capabilities):
            raise TypeError("capabilities must be a tuple of Capability values")
        if not isinstance(self.revoked_capability_ids, frozenset) or any(
            not isinstance(value, StableId) for value in self.revoked_capability_ids
        ):
            raise TypeError("revoked_capability_ids must be a frozenset of StableId values")
        if not isinstance(self.attempts, tuple) or any(not isinstance(value, Attempt) for value in self.attempts):
            raise TypeError("attempts must be a tuple of Attempt values")
        if any(value.project_id != self.project.project_id for value in self.capabilities + self.attempts):
            raise ValueError("capabilities and attempts must belong to the project")
        for mapping_name, mapping, key_type, value_type in (
            ("runs", self.runs, EntityRef, Run),
            ("assignments", self.assignments, EntityRef, Assignment),
            ("queue_entries", self.queue_entries, EntityRef, QueueEntry),
            ("outcomes", self.outcomes, EntityRef, Outcome),
            ("legacy_completion_assertions", self.legacy_completion_assertions, EntityRef, str),
            ("blocker_observations", self.blocker_observations, EntityRef, ConditionResult),
            ("check_observations", self.check_observations, StableId, ConditionResult),
            ("decision_observations", self.decision_observations, str, DecisionObservation),
            ("scope_contexts", self.scope_contexts, EntityRef, WorkItemContext),
            ("plan_memberships", self.plan_memberships, EntityRef, frozenset),
            ("workspace_qualifications", self.workspace_qualifications, EntityRef, WorkspaceQualification),
            ("approved_participants", self.approved_participants, EntityRef, frozenset),
            ("attempt_scope_snapshots", self.attempt_scope_snapshots, EntityRef, AttemptScopeSnapshot),
        ):
            if not isinstance(mapping, Mapping):
                raise TypeError(f"{mapping_name} must be a mapping")
            if any(not isinstance(key, key_type) or not isinstance(value, value_type) for key, value in mapping.items()):
                raise TypeError(f"{mapping_name} contains an invalid key or value")
            object.__setattr__(self, mapping_name, MappingProxyType(dict(mapping)))
        if any(
            key != value.work_item or value.project_id != self.project.project_id
            for key, value in self.outcomes.items()
        ):
            raise ValueError("outcomes must be keyed by their same-project work-item reference")
        if any(
            key.kind is not EntityKind.WORK_ITEM or key.project_id != self.project.project_id
            or key.definition_revision_id is None
            for key in self.legacy_completion_assertions
        ):
            raise ValueError("legacy completion assertions must be keyed by exact same-project work definitions")
        if any(key.project_id != self.project.project_id for key in self.runs):
            raise ValueError("run references must belong to the project")
        if any(key.project_id != self.project.project_id for key in self.assignments):
            raise ValueError("assignment references must belong to the project")
        if any(
            key.kind is not EntityKind.ASSIGNMENT or key.project_id != self.project.project_id
            or value.assignment.ref != key or self.assignments.get(key) != value.assignment
            for key, value in self.queue_entries.items()
        ):
            raise ValueError("queue entries must match persisted project-local assignments")
        if any(key.project_id != self.project.project_id for key in self.workspace_qualifications):
            raise ValueError("workspace qualification keys must belong to the project")
        if any(
            key.kind is not EntityKind.PLAN_REVISION or key.project_id != self.project.project_id
            or any(
                not isinstance(ref, EntityRef) or ref.project_id != self.project.project_id
                or ref.kind not in {
                    EntityKind.WORK_ITEM, EntityKind.REQUIREMENT, EntityKind.CHECKPOINT,
                    EntityKind.INTERFACE, EntityKind.DECISION, EntityKind.BARRIER,
                    EntityKind.INVARIANT,
                }
                for ref in members
            )
            for key, members in self.plan_memberships.items()
        ):
            raise ValueError("plan memberships must map project-local plan revisions to exact accepted-plan refs")
        if any(
            key.kind is not EntityKind.WORK_ITEM or key.project_id != self.project.project_id
            or any(
                not isinstance(ref, EntityRef) or ref.kind is not EntityKind.ACTOR
                or ref.project_id != self.project.project_id
                for ref in participants
            )
            for key, participants in self.approved_participants.items()
        ):
            raise ValueError("approved participants must be project-local actor incarnations keyed by work item")
        if any(
            key.kind is not EntityKind.ATTEMPT or key.project_id != self.project.project_id
            for key in self.attempt_scope_snapshots
        ):
            raise ValueError("attempt scope snapshots must be keyed by same-project attempt references")
        if not isinstance(self.child_scope_occupancies, tuple) or any(
            not isinstance(value, ChildScopeOccupancy) for value in self.child_scope_occupancies
        ):
            raise TypeError("child_scope_occupancies must be a tuple of ChildScopeOccupancy values")
        if any(
            value.parent_attempt.project_id != self.project.project_id
            or value.target.project_id != self.project.project_id
            for value in self.child_scope_occupancies
        ):
            raise ValueError("child scope occupancy references must belong to the project")


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")


def _ref_key(ref: EntityRef | None) -> tuple[str, ...]:
    if ref is None:
        return ()
    return (
        str(ref.project_id), ref.kind.value, str(ref.entity_id),
        "" if ref.definition_revision_id is None else str(ref.definition_revision_id),
        "" if ref.incarnation_id is None else str(ref.incarnation_id),
    )


def _cause_key(cause: EligibilityCause) -> tuple[object, ...]:
    return (cause.code, cause.message, _ref_key(cause.subject), tuple(_ref_key(ref) for ref in cause.related))


def _condition_result_cause(
    result: ConditionResult,
    *,
    subject: EntityRef,
    code_prefix: str,
    related: tuple[EntityRef, ...] = (),
) -> EligibilityCause:
    detail = "; ".join(cause.message for cause in result.causes) or result.status.value
    return EligibilityCause(
        f"{code_prefix}_{result.status.value}",
        detail,
        subject,
        related,
    )


def _result_status(
    result: ConditionResult,
    *,
    subject: EntityRef,
    code_prefix: str,
    related: tuple[EntityRef, ...] = (),
) -> tuple[EligibilityStatus | None, EligibilityCause | None]:
    if result.status is ConditionStatus.SATISFIED:
        return None, None
    if result.status is ConditionStatus.UNSATISFIED:
        return EligibilityStatus.BLOCKED, _condition_result_cause(
            result, subject=subject, code_prefix=code_prefix, related=related
        )
    return EligibilityStatus.UNKNOWN, _condition_result_cause(
        result, subject=subject, code_prefix=code_prefix, related=related
    )


def _aggregate(revision: int, blocked: list[EligibilityCause], unknown: list[EligibilityCause]) -> EligibilityDecision:
    if blocked:
        causes = tuple(sorted(set(blocked), key=_cause_key))
        return EligibilityDecision(EligibilityStatus.BLOCKED, revision, causes)
    if unknown:
        causes = tuple(sorted(set(unknown), key=_cause_key))
        return EligibilityDecision(EligibilityStatus.UNKNOWN, revision, causes)
    return EligibilityDecision(EligibilityStatus.ALLOWED, revision)


def _work_item(plan: CompiledPlan, ref: EntityRef) -> PlannedWorkItem | None:
    for item in plan.work_items:
        if item.definition.ref == ref:
            return item
    return None


def _completion_result(ref: EntityRef, facts: EligibilityFacts) -> ConditionResult:
    item = _work_item(facts.plan, ref)
    outcome = facts.outcomes.get(ref)
    if outcome is None and ref in facts.legacy_completion_assertions:
        legacy_source = facts.legacy_completion_assertions[ref]
        return ConditionResult(
            ConditionStatus.SATISFIED,
            (ConditionCause(
                "legacy_completion_assertion", str(ref.entity_id),
                "legacy source state asserts completion; no native outcome or verification was created; " + legacy_source,
            ),),
        )
    if item is None:
        if outcome is not None:
            if outcome.disposition in {
                OutcomeDisposition.COMPLETED,
                OutcomeDisposition.ACCEPTED_NEGATIVE,
                OutcomeDisposition.NO_CHANGE,
            }:
                return ConditionResult(
                    ConditionStatus.SATISFIED,
                    (ConditionCause("work_item_outcome", str(ref.entity_id), f"accepted outcome is {outcome.disposition.value}"),),
                )
            return ConditionResult(
                ConditionStatus.UNSATISFIED,
                (ConditionCause("work_item_outcome_not_complete", str(ref.entity_id), f"accepted outcome is {outcome.disposition.value}"),),
            )
        return ConditionResult(
            ConditionStatus.UNRESOLVED,
            (ConditionCause(
                "work_item_definition_unavailable",
                str(ref.entity_id),
                "completion cannot be checked without the qualified local definition and its accepted outcome",
            ),),
        )
    if outcome is None:
        return ConditionResult(
            ConditionStatus.UNSATISFIED,
            (ConditionCause("work_item_incomplete", str(ref.entity_id), "no accepted outcome exists for this work-item definition"),),
        )
    allowed = item.context.acceptance.get("allowed_dispositions", ())
    if outcome.disposition.value in allowed:
        return ConditionResult(
            ConditionStatus.SATISFIED,
            (ConditionCause("work_item_outcome", str(ref.entity_id), f"accepted outcome is {outcome.disposition.value}"),),
        )
    return ConditionResult(
        ConditionStatus.UNSATISFIED,
        (ConditionCause(
            "work_item_outcome_not_accepted",
            str(ref.entity_id),
            f"accepted outcome {outcome.disposition.value!r} is not allowed by this definition",
        ),),
    )


def _graph_blocker_result(edge: BlockingEdge, facts: EligibilityFacts) -> ConditionResult:
    ref = edge.target.reference
    if edge.relation.value == "completion" and ref.project_id == facts.project.project_id:
        return _completion_result(ref, facts)
    supplied = facts.blocker_observations.get(ref)
    if supplied is not None:
        return supplied
    if edge.relation.value == "completion" and ref.kind is EntityKind.WORK_ITEM:
        return _completion_result(ref, facts)
    if edge.relation.value == "decision_resolved" and ref.kind is EntityKind.DECISION:
        decision = facts.decision_observations.get(str(ref.entity_id))
        if decision is not None:
            return ConditionResult(decision.status)
    return ConditionResult(
        ConditionStatus.UNRESOLVED,
        (ConditionCause("blocker_missing", str(ref.entity_id), "no typed observation was supplied for this blocker"),),
    )


def _requirement_result(requirement, facts: EligibilityFacts) -> ConditionResult:
    definition = requirement.definition
    if definition.kind is RequirementKind.CHECK:
        if definition.check_key is None:
            return ConditionResult(
                ConditionStatus.UNAVAILABLE,
                (ConditionCause("invalid_check", str(definition.requirement_id), "check has no key"),),
            )
        return facts.check_observations.get(
            definition.check_key,
            ConditionResult(
                ConditionStatus.UNRESOLVED,
                (ConditionCause("check_unobserved", str(definition.check_key), "no check result was supplied"),),
            ),
        )
    target = definition.target
    if target is None:
        return ConditionResult(
            ConditionStatus.UNAVAILABLE,
            (ConditionCause("invalid_prerequisite", str(definition.requirement_id), "prerequisite has no target"),),
        )
    if target.kind is EntityKind.WORK_ITEM and target.project_id == facts.project.project_id:
        return _completion_result(target, facts)
    supplied = facts.blocker_observations.get(target)
    if supplied is not None:
        return supplied
    return ConditionResult(
        ConditionStatus.UNRESOLVED,
        (ConditionCause("prerequisite_unobserved", str(target.entity_id), "no adopted observation was supplied for this typed prerequisite"),),
    )


def _scope_contains(grant: EntityRef, requested: EntityRef, target: EntityRef, facts: EligibilityFacts) -> bool:
    membership = facts.plan_memberships.get(grant)
    return (
        scope_covers(grant, target, plan_membership=membership)
        and scope_covers(grant, requested, plan_membership=membership)
    )


def _capability_matches(capability: Capability, request: EligibilityRequest, facts: EligibilityFacts) -> tuple[bool, str | None]:
    if capability.capability_id in facts.revoked_capability_ids:
        return False, "capability_revoked"
    if capability.actor != request.actor:
        return False, "capability_actor_mismatch"
    if request.action not in capability.actions:
        return False, "capability_action_missing"
    queue_entry = None if request.assignment is None else facts.queue_entries.get(request.assignment)
    if queue_entry is not None and queue_entry.required_role is not None:
        if queue_entry.required_role not in capability.actions:
            return False, "lane_role_action_missing"
    if capability.expires_at is not None and capability.expires_at <= facts.evaluated_at:
        return False, "capability_expired"
    if not _scope_contains(capability.scope, request.target, request.target, facts):
        return False, "capability_scope_exceeded"
    if request.scope is not None and not _scope_contains(capability.scope, request.scope, request.target, facts):
        return False, "capability_scope_exceeded"
    for name in ("run", "assignment", "attempt"):
        bound = getattr(capability, name)
        requested = getattr(request, name)
        if bound is not None and bound != requested:
            return False, "capability_context_mismatch"
    return True, None


def _path_overlaps(first: str, second: str) -> bool:
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _scope_parts(context: WorkItemContext) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]] | None:
    try:
        scope = context.scope
        raw_paths = scope["paths"]
        raw_locks = scope.get("locks", ())
        paths = tuple((item["path"], item["access"]) for item in raw_paths)
        locks = tuple((item["name"], item["mode"]) for item in raw_locks)
    except (AttributeError, KeyError, TypeError):
        return None
    if any(
        not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
        or any(part in {"", ".", ".."} or ":" in part for part in path.split("/"))
        or any(char in path for char in "*?[]")
        or not isinstance(access, str) or access not in {"read", "write", "forbidden"}
        for path, access in paths
    ):
        return None
    if any(not isinstance(name, str) or not isinstance(mode, str) or mode not in {"shared", "exclusive"} for name, mode in locks):
        return None
    return paths, locks


def _scope_snapshot_payload(scope: AttemptScopeSnapshot) -> str:
    value = {
        "locks": [list(item) for item in sorted(scope.locks)],
        "paths": [list(item) for item in sorted(scope.paths)],
    }
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _load_attempt_scope_snapshots(connection, project_id: StableId) -> Mapping[EntityRef, AttemptScopeSnapshot]:
    snapshots: dict[EntityRef, AttemptScopeSnapshot] = {}
    for row in connection.execute(
        "SELECT attempt_id, scope_json, scope_digest FROM attempt_scope_snapshots ORDER BY attempt_id"
    ).fetchall():
        encoded = row["scope_json"]
        digest = row["scope_digest"]
        if not isinstance(encoded, str) or not isinstance(digest, str):
            raise EligibilityAdapterError("stored attempt scope snapshot is not text")
        if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != digest:
            raise EligibilityAdapterError("stored attempt scope snapshot digest does not match")
        try:
            value = json.loads(encoded)
            if not isinstance(value, dict) or set(value) != {"locks", "paths"}:
                raise ValueError("unexpected snapshot fields")
            paths = tuple(tuple(item) for item in value["paths"])
            locks = tuple(tuple(item) for item in value["locks"])
            snapshot = AttemptScopeSnapshot(paths, locks)
            if _scope_snapshot_payload(snapshot) != encoded:
                raise ValueError("snapshot encoding is not canonical")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EligibilityAdapterError(f"stored attempt scope snapshot is invalid: {exc}") from exc
        ref = _entity_ref(project_id, "attempt", row["attempt_id"])
        snapshots[ref] = snapshot
    return MappingProxyType(snapshots)


def _load_child_scope_occupancies(
    connection,
    project_id: StableId,
    workspace_qualifications: Mapping[EntityRef, WorkspaceQualification],
) -> tuple[ChildScopeOccupancy, ...]:
    from .child_store import decode_child_scope

    rows = connection.execute(
        "SELECT execution.execution_id, execution.parent_attempt_id, execution.work_item_id, "
        "execution.definition_revision_id, execution.scope_json, execution.scope_digest "
        "FROM child_executions AS execution "
        "LEFT JOIN child_candidates AS candidate USING(execution_id) "
        "LEFT JOIN child_candidate_reviews AS review USING(candidate_id) "
        "WHERE execution.state <> 'stopped' "
        "OR (candidate.candidate_id IS NOT NULL AND review.review_id IS NULL) "
        "ORDER BY execution.parent_attempt_id, execution.logical_id, execution.ordinal"
    ).fetchall()
    result = []
    for row in rows:
        try:
            scope = decode_child_scope(row["scope_json"], row["scope_digest"])
            parent = _entity_ref(project_id, "attempt", row["parent_attempt_id"])
            target = _entity_ref(
                project_id, "work_item", row["work_item_id"], row["definition_revision_id"]
            )
            result.append(ChildScopeOccupancy(
                StableId(row["execution_id"]), parent, target, scope,
                workspace_qualifications.get(parent),
            ))
        except (TypeError, ValueError) as exc:
            raise EligibilityAdapterError(f"stored child execution scope is invalid: {exc}") from exc
    return tuple(result)


def _independent_workspaces(
    first: WorkspaceQualification | None,
    second: WorkspaceQualification | None,
    project_id: StableId,
) -> bool:
    return bool(
        first is not None and second is not None
        and first.workspace_id != second.workspace_id
        and first.repository_id == second.repository_id
        and first.common_base == second.common_base
        and first.common_base.project_id == project_id
        and first.destination == second.destination
        and first.receipt.provider == second.receipt.provider
        and first.isolation is not None and second.isolation is not None
        and first.isolation.repository_storage == second.isolation.repository_storage
        and first.isolation.workspace_root != second.isolation.workspace_root
        and first.isolation.index_file != second.isolation.index_file
        and first.isolation.head_ref != second.isolation.head_ref
    )


def _evaluate_conflicts(request: EligibilityRequest, facts: EligibilityFacts) -> tuple[list[EligibilityCause], list[EligibilityCause]]:
    blocked: list[EligibilityCause] = []
    unknown: list[EligibilityCause] = []
    target_item = _work_item(facts.plan, request.target)
    assert target_item is not None  # checked before this helper
    target_scope = _scope_parts(target_item.context)
    if target_scope is None:
        unknown.append(EligibilityCause("target_scope_unavailable", "the compiled work-item source scope is not usable", request.target))
        return blocked, unknown
    candidate_paths, candidate_locks = target_scope

    terminal = {AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED}
    active = {AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED}
    unresolved = {AttemptState.EXPIRED, AttemptState.UNCERTAIN, AttemptState.QUARANTINED}
    for attempt in facts.attempts:
        if attempt.ref == request.attempt or attempt.state in terminal:
            continue
        known_state = attempt.state in active or attempt.state in unresolved
        live = (
            attempt.state in active
            and attempt.lease is not None
            and attempt.lease.expires_at > facts.evaluated_at
        )
        if not known_state:
            unknown.append(EligibilityCause(
                "attempt_state_unrecognized", f"attempt {attempt.attempt_id} has an unrecognized state",
                attempt.work_item, (attempt.ref,),
            ))
            continue
        if attempt.work_item == request.target:
            cause = EligibilityCause(
                "work_item_already_active" if live else "work_item_attempt_unresolved",
                "this work-item definition already has a live nonterminal attempt"
                if live else "this work-item definition has an unreconciled attempt",
                request.target, (attempt.ref,),
            )
            (blocked if live else unknown).append(cause)
            continue

        other_scope = facts.attempt_scope_snapshots.get(attempt.ref)
        if other_scope is None:
            unknown.append(EligibilityCause(
                "active_scope_unavailable", "the active attempt's source scope is unavailable",
                attempt.work_item, (attempt.ref,),
            ))
            continue
        other_paths, other_locks = other_scope.paths, other_scope.locks

        lock_conflicts = tuple(sorted(
            name for name, mode in candidate_locks for other_name, other_mode in other_locks
            if name == other_name and (mode == "exclusive" or other_mode == "exclusive")
        ))
        if lock_conflicts:
            cause = EligibilityCause(
                "named_lock_conflict" if live else "unresolved_named_lock_conflict",
                ("active" if live else "unreconciled") + " attempt may hold an incompatible named lock: " + ", ".join(lock_conflicts),
                request.target, (attempt.ref,),
            )
            (blocked if live else unknown).append(cause)
            continue

        path_conflicts = tuple(sorted({
            first_path for first_path, first_access in candidate_paths
            for second_path, second_access in other_paths
            if first_access != "forbidden" and second_access != "forbidden"
            and _path_overlaps(first_path, second_path)
            and (first_access == "write" or second_access == "write")
        }))
        if not path_conflicts:
            continue
        requested_workspace_ref = request.attempt or request.target
        candidate_workspace = facts.workspace_qualifications.get(requested_workspace_ref)
        active_workspace = facts.workspace_qualifications.get(attempt.ref)
        if _independent_workspaces(candidate_workspace, active_workspace, facts.project.project_id):
            continue
        cause = EligibilityCause(
            "unsafe_source_overlap" if live else "unresolved_source_overlap",
            ("active attempts" if live else "an unreconciled attempt")
            + " have overlapping read/write source scopes without matching qualified workspaces: "
            + ", ".join(path_conflicts),
            request.target,
            (attempt.ref,),
        )
        (blocked if live else unknown).append(cause)

    # Child scopes are independent durable occupancy records. Their parent's
    # full source scope may not mention the narrower path, so inspect them
    # separately. The parent owner may renew its own attempt while children
    # are running; other requests must respect the child scope itself.
    from todo_orchestrator.coordination.child_scope import child_scopes_conflict
    candidate_snapshot = AttemptScopeSnapshot(
        tuple((path, access) for path, access in candidate_paths if access != "forbidden"),
        candidate_locks,
    )
    for child in facts.child_scope_occupancies:
        if request.attempt == child.parent_attempt:
            continue
        if not child_scopes_conflict(candidate_snapshot, child.scope):
            continue
        candidate_workspace = facts.workspace_qualifications.get(request.attempt or request.target)
        if _independent_workspaces(candidate_workspace, child.parent_workspace, facts.project.project_id):
            continue
        related = (child.parent_attempt,)
        if child.parent_workspace is None:
            unknown.append(EligibilityCause(
                "child_scope_workspace_unavailable",
                "an unresolved child scope has no trusted parent workspace qualification",
                request.target,
                related,
            ))
        else:
            blocked.append(EligibilityCause(
                "child_scope_occupied",
                "an unresolved subordinate execution owns an overlapping read/write scope",
                request.target,
                related,
            ))
    return blocked, unknown


def _evaluate_queue_policy(
    request: EligibilityRequest, facts: EligibilityFacts, entry: QueueEntry
) -> tuple[list[EligibilityCause], list[EligibilityCause]]:
    """Apply durable queue and isolation constraints to shared admission facts."""
    blocked: list[EligibilityCause] = []
    unknown: list[EligibilityCause] = []
    siblings = tuple(
        candidate for candidate in facts.queue_entries.values()
        if candidate.assignment.run == entry.assignment.run
        and candidate.lane_id == entry.lane_id
        and candidate.assignment.ref != entry.assignment.ref
    )

    if entry.queue_policy is QueuePolicy.SERIAL:
        for sibling in siblings:
            for attempt in facts.attempts:
                if attempt.assignment != sibling.assignment.ref and attempt.work_item != sibling.assignment.work_item:
                    continue
                if attempt.state in {AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED}:
                    continue
                live = (
                    attempt.state in {AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED}
                    and attempt.lease is not None
                    and attempt.lease.expires_at > facts.evaluated_at
                )
                cause = EligibilityCause(
                    "serial_lane_occupied" if live else "serial_lane_reconciliation_required",
                    "another lane assignment still has a live attempt" if live else
                    "another lane assignment has unresolved attempt ownership",
                    sibling.assignment.work_item,
                    (attempt.ref,),
                )
                (blocked if live else unknown).append(cause)

        for sibling in siblings:
            if sibling.queue_position >= entry.queue_position:
                continue
            outcome = facts.outcomes.get(sibling.assignment.work_item)
            prior_work = _work_item(facts.plan, sibling.assignment.work_item)
            allowed = () if prior_work is None else prior_work.context.acceptance.get("allowed_dispositions", ())
            if outcome is None or outcome.disposition.value not in allowed:
                blocked.append(EligibilityCause(
                    "serial_queue_predecessor_incomplete",
                    "a prior serial queue item has no accepted outcome allowed by its authored acceptance policy",
                    sibling.assignment.work_item,
                    (entry.assignment.ref,),
                ))

    if entry.isolation_policy is IsolationPolicy.QUALIFIED_WORKSPACES:
        requested_workspace_ref = request.attempt or request.target
        candidate_workspace = facts.workspace_qualifications.get(requested_workspace_ref)
        if (
            candidate_workspace is None
            or candidate_workspace.common_base.project_id != facts.project.project_id
            or candidate_workspace.destination.project_id != facts.project.project_id
        ):
            unknown.append(EligibilityCause(
                "lane_candidate_workspace_unqualified",
                "this lane requires a provider-qualified candidate workspace with a project-local common base and destination",
                request.target,
                (entry.assignment.ref,),
            ))
        for sibling in siblings:
            for attempt in facts.attempts:
                if attempt.assignment != sibling.assignment.ref and attempt.work_item != sibling.assignment.work_item:
                    continue
                if attempt.state in {AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED}:
                    continue
                active_workspace = facts.workspace_qualifications.get(attempt.ref)
                if _independent_workspaces(candidate_workspace, active_workspace, facts.project.project_id):
                    continue
                live = (
                    attempt.state in {AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED}
                    and attempt.lease is not None
                    and attempt.lease.expires_at > facts.evaluated_at
                )
                cause = EligibilityCause(
                    "lane_workspace_isolation_conflict" if live else "lane_workspace_isolation_unknown",
                    "lane sibling lacks a distinct qualified workspace with matching common base and destination",
                    sibling.assignment.work_item,
                    (attempt.ref,),
                )
                (blocked if live else unknown).append(cause)
    return blocked, unknown


def evaluate_eligibility(request: EligibilityRequest, facts: EligibilityFacts) -> EligibilityDecision:
    """Evaluate eligibility from exactly the supplied immutable facts."""
    if not isinstance(request, EligibilityRequest) or not isinstance(facts, EligibilityFacts):
        raise TypeError("evaluate_eligibility requires an EligibilityRequest and EligibilityFacts")
    blocked: list[EligibilityCause] = []
    unknown: list[EligibilityCause] = []
    revision = facts.authority_revision

    if request.target.project_id != facts.project.project_id:
        return EligibilityDecision(EligibilityStatus.BLOCKED, revision, (
            EligibilityCause("project_mismatch", "request target does not belong to this authority", request.target),
        ))
    if request.expected_revision != revision:
        blocked.append(EligibilityCause(
            "stale_authority_revision",
            f"request expects semantic revision {request.expected_revision}, current revision is {revision}",
            request.target,
        ))
    if not facts.plan_matches_authority:
        blocked.append(EligibilityCause(
            "plan_not_authoritative", "compiled plan identity or contents do not match the stored accepted proposal",
            request.target,
        ))
    if not facts.accepted_plan_revision:
        blocked.append(EligibilityCause(
            "plan_revision_not_accepted", "the compiled plan revision is not accepted",
            request.target,
        ))
    if request.target not in facts.plan.revision.work_items:
        blocked.append(EligibilityCause(
            "target_revision_mismatch", "target work item is not from the supplied compiled plan revision",
            request.target,
        ))
    item = _work_item(facts.plan, request.target)
    if item is None:
        blocked.append(EligibilityCause("work_item_not_in_plan", "target is not a work item in this plan", request.target))
    if request.actor not in facts.registered_actors:
        blocked.append(EligibilityCause("actor_incarnation_not_registered", "requesting actor incarnation is not registered", request.actor))
    participants = request.participants or (request.actor,)
    for participant in participants:
        if participant not in facts.registered_actors:
            blocked.append(EligibilityCause("participant_incarnation_not_registered", "participant actor incarnation is not registered", participant))

    if item is not None:
        ownership = item.context.ownership
        required_owners = tuple(member.reference for member in ownership.actors)
        if required_owners:
            if ownership.mode == "any" and request.actor not in required_owners:
                blocked.append(EligibilityCause("owner_acl_denied", "requesting actor incarnation is not an authored owner", request.target, required_owners))
            elif ownership.mode == "all":
                approved = facts.approved_participants.get(request.target)
                if approved is None:
                    if set(required_owners) == {request.actor}:
                        pass
                    else:
                        unknown.append(EligibilityCause(
                            "owner_participants_unverified",
                            "all-owner participation requires a trusted participant approval fact",
                            request.target,
                            required_owners,
                        ))
                elif (
                    request.actor not in approved
                    or not set(required_owners).issubset(approved)
                    or not set(required_owners).issubset(participants)
                    or not set(participants).issubset(approved)
                ):
                    blocked.append(EligibilityCause(
                        "owner_acl_denied",
                        "trusted participant facts do not include every authored owner and the requesting actor",
                        request.target,
                        required_owners,
                    ))
            elif ownership.mode not in {"any", "all"}:
                unknown.append(EligibilityCause("owner_acl_unavailable", "authored ownership mode is not recognized", request.target))

        accepted_outcome = facts.outcomes.get(request.target)
        if (
            accepted_outcome is not None
            and accepted_outcome.disposition.value in item.context.acceptance.get("allowed_dispositions", ())
        ):
            blocked.append(EligibilityCause(
                "work_item_already_completed",
                "an accepted outcome already completes this exact work-item definition",
                request.target,
                (accepted_outcome.ref,),
            ))
        elif accepted_outcome is None and request.target in facts.legacy_completion_assertions:
            blocked.append(EligibilityCause(
                "legacy_completion_requires_revalidation",
                "legacy state asserts that this exact work definition is complete; create a fresh native result before dispatch",
                request.target,
            ))

    actor_capabilities = [cap for cap in facts.capabilities if cap.actor == request.actor]
    matching = False
    cap_failures: list[str] = []
    for capability in actor_capabilities:
        accepted, reason = _capability_matches(capability, request, facts)
        if accepted:
            matching = True
            break
        if reason is not None:
            cap_failures.append(reason)
    if not matching:
        failures = sorted(set(cap_failures))
        code = failures[0] if len(failures) == 1 else "capability_denied"
        message = "no unrevoked, unexpired capability grants this action and scope"
        if failures:
            message += " (" + ", ".join(failures) + ")"
        blocked.append(EligibilityCause(code, message, request.target))

    assignment: Assignment | None = None
    if request.assignment is not None:
        assignment = facts.assignments.get(request.assignment)
        if assignment is None:
            blocked.append(EligibilityCause("assignment_not_found", "requested assignment is absent from the authority", request.assignment))
        else:
            if assignment.work_item != request.target:
                blocked.append(EligibilityCause("assignment_target_mismatch", "assignment belongs to another work item", request.assignment, (request.target,)))
            if assignment.assignee is not None and assignment.assignee != request.actor:
                blocked.append(EligibilityCause("assignment_actor_mismatch", "assignment is bound to another actor incarnation", request.assignment, (assignment.assignee,)))
            if request.run is not None and assignment.run != request.run:
                blocked.append(EligibilityCause("assignment_run_mismatch", "assignment is not bound to the requested run", request.assignment, (request.run,)))

    effective_run = request.run or (None if assignment is None else assignment.run)
    if effective_run is not None:
        run = facts.runs.get(effective_run)
        if run is None:
            blocked.append(EligibilityCause("run_not_found", "requested or assigned run is absent from the authority", effective_run))
        elif run.state is not RunState.OPEN:
            blocked.append(EligibilityCause("run_not_open", f"run state is {run.state.value}", effective_run))
        elif run.plan_revision != facts.plan.revision.ref:
            blocked.append(EligibilityCause("run_plan_mismatch", "run belongs to another plan revision", effective_run, (facts.plan.revision.ref,)))

    scheduled_for_target = tuple(
        value for value in facts.queue_entries.values()
        if value.assignment.work_item == request.target
        and (scheduled_run := facts.runs.get(value.assignment.run)) is not None
        and scheduled_run.state is RunState.OPEN
    )
    queue_entry = None if request.assignment is None else facts.queue_entries.get(request.assignment)
    if scheduled_for_target and queue_entry is None:
        blocked.append(EligibilityCause(
            "scheduled_assignment_required",
            "this work item belongs to a persisted run queue and must be claimed through its exact assignment",
            request.target,
            tuple(sorted((value.assignment.ref for value in scheduled_for_target), key=_ref_key)),
        ))
    if queue_entry is not None:
        queue_blocked, queue_unknown = _evaluate_queue_policy(request, facts, queue_entry)
        blocked.extend(queue_blocked)
        unknown.extend(queue_unknown)

    if request.attempt is not None:
        current_attempt = next((attempt for attempt in facts.attempts if attempt.ref == request.attempt), None)
        if current_attempt is None:
            blocked.append(EligibilityCause("attempt_not_found", "requested attempt is absent from the authority", request.attempt))
        else:
            if current_attempt.work_item != request.target:
                blocked.append(EligibilityCause("attempt_target_mismatch", "attempt belongs to another work item", request.attempt, (request.target,)))
            if current_attempt.actor != request.actor:
                blocked.append(EligibilityCause("attempt_actor_mismatch", "attempt belongs to another actor incarnation", request.attempt, (current_attempt.actor,)))
            if request.assignment is not None and current_attempt.assignment != request.assignment:
                blocked.append(EligibilityCause("attempt_assignment_mismatch", "attempt belongs to another assignment", request.attempt, (request.assignment,)))
            if effective_run is not None and current_attempt.run != effective_run:
                blocked.append(EligibilityCause("attempt_run_mismatch", "attempt belongs to another run", request.attempt, (effective_run,)))
            if current_attempt.state in {AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED}:
                blocked.append(EligibilityCause("attempt_terminal", f"attempt is already {current_attempt.state.value}", request.attempt))
            elif current_attempt.state in {AttemptState.EXPIRED, AttemptState.UNCERTAIN, AttemptState.QUARANTINED}:
                unknown.append(EligibilityCause("attempt_reconciliation_required", f"attempt is {current_attempt.state.value}", request.attempt))
            elif current_attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED}:
                unknown.append(EligibilityCause("attempt_state_unrecognized", "attempt state cannot be safely evaluated", request.attempt))
            if current_attempt.lease is None:
                unknown.append(EligibilityCause("attempt_lease_missing", "requested active attempt has no lease", request.attempt))
            elif current_attempt.lease.expires_at <= facts.evaluated_at:
                unknown.append(EligibilityCause("attempt_lease_expired", "requested attempt lease is expired and requires reconciliation", request.attempt))

    if item is not None:
        requirement_by_id = {
            value.definition.requirement_id: value
            for value in facts.plan.requirements
            if value.definition.owner == request.target
        }
        for group in item.definition.requirement_groups:
            # CHECKs describe evidence needed to evaluate/promote a result.
            # They are performed by the verification lifecycle and must not
            # make the work they verify impossible to claim. Prerequisites
            # remain admission gates; typed graph blockers are evaluated below.
            if group.kind is RequirementKind.CHECK:
                continue
            results = tuple(
                _requirement_result(requirement_by_id[requirement_id], facts)
                for requirement_id in group.requirement_ids
                if requirement_id in requirement_by_id
            )
            if len(results) != len(group.requirement_ids):
                result = ConditionResult(
                    ConditionStatus.UNAVAILABLE,
                    (ConditionCause("requirement_missing", str(request.target.entity_id), "compiled plan omits a grouped requirement"),),
                )
            else:
                result = evaluate_results(group.mode, group.quorum, results)
            status, cause = _result_status(result, subject=request.target, code_prefix="requirement_group")
            if status is EligibilityStatus.BLOCKED and cause is not None:
                blocked.append(cause)
            elif status is EligibilityStatus.UNKNOWN and cause is not None:
                unknown.append(cause)

    for group in facts.plan.blocking_groups:
        if group.source.reference != request.target:
            continue
        blocker_results = tuple(_graph_blocker_result(edge, facts) for edge in group.members)
        result = evaluate_blocking_group(group, blocker_results, facts.decision_observations)
        status, cause = _result_status(
            result,
            subject=request.target,
            code_prefix="blocking_group",
            related=tuple(edge.target.reference for edge in group.members),
        )
        if status is EligibilityStatus.BLOCKED and cause is not None:
            blocked.append(cause)
        elif status is EligibilityStatus.UNKNOWN and cause is not None:
            unknown.append(cause)

    if item is not None:
        conflict_blocked, conflict_unknown = _evaluate_conflicts(request, facts)
        blocked.extend(conflict_blocked)
        unknown.extend(conflict_unknown)
    return _aggregate(revision, blocked, unknown)


def _entity_ref(project_id: StableId, kind: str, entity_id: str, revision_id: str | None = None, incarnation_id: str | None = None) -> EntityRef:
    return EntityRef(
        project_id,
        EntityKind(kind),
        StableId(entity_id),
        None if revision_id is None else StableId(revision_id),
        None if incarnation_id is None else StableId(incarnation_id),
    )


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    result = datetime.fromisoformat(value)
    _require_aware(result, "stored timestamp")
    return result


def _load_facts(
    connection,
    authority: SQLiteAuthority,
    request: EligibilityRequest,
    plan: CompiledPlan,
    evaluated_at: datetime,
    *,
    blocker_observations: Mapping[EntityRef, ConditionResult],
    check_observations: Mapping[StableId, ConditionResult],
    decision_observations: Mapping[str, DecisionObservation],
    scope_contexts: Mapping[EntityRef, WorkItemContext],
    workspace_qualifications: Mapping[EntityRef, WorkspaceQualification],
    approved_participants: Mapping[EntityRef, frozenset[EntityRef]],
) -> EligibilityFacts:
    project_id = authority.project.project_id
    meta = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
    if meta is None:
        raise EligibilityAdapterError("authority metadata is missing")
    revision = int(meta["semantic_revision"])

    plan_row = connection.execute(
        "SELECT state, content_digest FROM plan_revisions WHERE plan_revision_id = ?",
        (str(plan.revision.plan_revision_id),),
    ).fetchone()
    stored_plan = None
    stored_members: frozenset[EntityRef] = frozenset()
    if plan_row is not None:
        try:
            snapshot = load_plan_revision_snapshot(connection, authority.project, plan.revision.plan_revision_id)
            if snapshot.sequence is None:
                raise InvalidAuthorityError("stored plan sequence is missing")
            body = json.loads(snapshot.canonical_json)
            stored_plan = decode_accepted_plan(snapshot.canonical_json, authority.project, sequence=snapshot.sequence)
            stored_members = frozenset(
                EntityRef(project_id, EntityKind.WORK_ITEM, item.work_item_id, item.definition_revision_id)
                for item in snapshot.work_items
            )
            # Re-serialize actual typed fields. This catches a caller that
            # replaced a scope, gate, or ownership field but retained the
            # original canonical_json and digest attributes.
            plan_matches = bool(
                body["effective_plan"] == accepted_plan_payload(plan)
                and plan.revision.plan_revision_id == stored_plan.revision.plan_revision_id
                and plan.revision.sequence == stored_plan.revision.sequence
                and plan.revision.based_on_revision_id == stored_plan.revision.based_on_revision_id
                and set(plan.revision.work_items) == set(stored_plan.revision.work_items)
                and request.target in stored_members
            )
        except (InvalidAuthorityError, TypeError, ValueError, KeyError):
            plan_matches = False
    else:
        plan_matches = False
    accepted = plan_row is not None and plan_row["state"] == PlanRevisionState.ACCEPTED.value

    registered = frozenset(
        _entity_ref(project_id, "actor", row["actor_id"], incarnation_id=row["incarnation_id"])
        for row in connection.execute("SELECT actor_id, incarnation_id FROM actors").fetchall()
    )

    action_rows: dict[str, list[StableId]] = {}
    for row in connection.execute(
        "SELECT capability_id, action FROM capability_actions ORDER BY capability_id, action_ordinal"
    ).fetchall():
        action_rows.setdefault(row["capability_id"], []).append(StableId(row["action"]))
    capabilities: list[Capability] = []
    revoked: set[StableId] = set()
    for row in connection.execute("SELECT * FROM capabilities ORDER BY capability_id").fetchall():
        cap_id = StableId(row["capability_id"])
        capabilities.append(Capability(
            capability_id=cap_id,
            project_id=project_id,
            actor=_entity_ref(project_id, "actor", row["actor_id"], incarnation_id=row["actor_incarnation_id"]),
            scope=_entity_ref(
                project_id,
                row["scope_kind"],
                row["scope_entity_id"],
                row["scope_definition_revision_id"],
                row["scope_incarnation_id"],
            ),
            actions=tuple(action_rows.get(str(cap_id), ())),
            run=None if row["run_id"] is None else _entity_ref(project_id, "run", row["run_id"]),
            assignment=None if row["assignment_id"] is None else _entity_ref(project_id, "assignment", row["assignment_id"]),
            attempt=None if row["attempt_id"] is None else _entity_ref(project_id, "attempt", row["attempt_id"]),
            expires_at=_parse_time(row["expires_at"]),
            parent_capability=(None if row["parent_capability_id"] is None else
                               _entity_ref(project_id, "capability", row["parent_capability_id"])),
        ))
        if bool(row["revoked"]):
            revoked.add(cap_id)

    plan_memberships: dict[EntityRef, frozenset[EntityRef]] = {}
    plan_scope_refs = {item.scope for item in capabilities if item.scope.kind is EntityKind.PLAN_REVISION}
    if stored_plan is not None:
        plan_scope_refs.add(stored_plan.revision.ref)
    for plan_scope in plan_scope_refs:
        try:
            plan_memberships[plan_scope] = plan_scope_membership(connection, authority.project, plan_scope)
        except InvalidAuthorityError:
            # A corrupt historical plan grant cannot cover any target; it does
            # not make unrelated project-scoped authority facts unreadable.
            continue

    runs = {}
    for row in connection.execute("SELECT * FROM runs").fetchall():
        run = Run(
            StableId(row["run_id"]), project_id,
            _entity_ref(project_id, "plan_revision", row["plan_revision_id"]),
            RunState(row["state"]),
            None if row["created_by_actor_id"] is None else _entity_ref(
                project_id, "actor", row["created_by_actor_id"], incarnation_id=row["created_by_incarnation_id"]
            ),
        )
        runs[run.ref] = run

    assignments = {}
    for row in connection.execute("SELECT * FROM assignments").fetchall():
        assignment = Assignment(
            StableId(row["assignment_id"]), project_id,
            _entity_ref(project_id, "work_item", row["work_item_id"], row["definition_revision_id"]),
            None if row["assignee_actor_id"] is None else _entity_ref(
                project_id, "actor", row["assignee_actor_id"], incarnation_id=row["assignee_incarnation_id"]
            ),
            None if row["run_id"] is None else _entity_ref(project_id, "run", row["run_id"]),
        )
        assignments[assignment.ref] = assignment

    queue_entries = load_all_queue_entries(connection, authority.project)

    attempt_caps: dict[str, list[StableId]] = {}
    for row in connection.execute("SELECT attempt_id, capability_id FROM attempt_capabilities").fetchall():
        attempt_caps.setdefault(row["attempt_id"], []).append(StableId(row["capability_id"]))
    attempts: list[Attempt] = []
    for row in connection.execute("SELECT * FROM attempts ORDER BY attempt_id").fetchall():
        actor = _entity_ref(project_id, "actor", row["actor_id"], incarnation_id=row["actor_incarnation_id"])
        lease = None
        if row["lease_id"] is not None and row["lease_expires_at"] is not None:
            lease = Lease(StableId(row["lease_id"]), actor, _parse_time(row["lease_expires_at"]))
        attempts.append(Attempt(
            StableId(row["attempt_id"]), project_id,
            _entity_ref(project_id, "work_item", row["work_item_id"], row["definition_revision_id"]),
            actor,
            AttemptState(row["state"]),
            tuple(attempt_caps.get(row["attempt_id"], ())),
            None if row["assignment_id"] is None else _entity_ref(project_id, "assignment", row["assignment_id"]),
            None if row["run_id"] is None else _entity_ref(project_id, "run", row["run_id"]),
            lease,
        ))

    outcomes = {}
    for row in connection.execute(
        "SELECT * FROM outcomes ORDER BY work_item_id, definition_revision_id, version"
    ).fetchall():
        outcome = Outcome(
            StableId(row["outcome_id"]), project_id,
            _entity_ref(project_id, "work_item", row["work_item_id"], row["definition_revision_id"]),
            row["version"], OutcomeDisposition(row["disposition"]),
            _entity_ref(project_id, "actor", row["accepted_by_actor_id"], incarnation_id=row["accepted_by_incarnation_id"]),
            _parse_time(row["accepted_at"]),
            (),
            None if row["attempt_id"] is None else _entity_ref(project_id, "attempt", row["attempt_id"]),
        )
        outcomes[outcome.work_item] = outcome

    legacy_completion_assertions = {}
    for row in connection.execute(
        "SELECT a.work_item_id, a.definition_revision_id, a.source_task_id, i.import_id, i.source_project_id "
        "FROM legacy_completion_assertions AS a JOIN legacy_imports AS i USING(import_id) "
        "ORDER BY a.work_item_id, a.definition_revision_id"
    ).fetchall():
        ref = _entity_ref(project_id, "work_item", row["work_item_id"], row["definition_revision_id"])
        legacy_completion_assertions[ref] = (
            f"source Project Control task {row['source_task_id']} from source project "
            f"{row['source_project_id']} is searchable in immutable legacy import {row['import_id']}"
        )

    attempt_scope_snapshots = _load_attempt_scope_snapshots(connection, project_id)
    child_scope_occupancies = _load_child_scope_occupancies(
        connection, project_id, workspace_qualifications,
    )

    authoritative_blockers = dict(blocker_observations)
    authoritative_decisions = dict(decision_observations)
    if stored_plan is not None and accepted:
        native_blockers, native_decisions = native_declaration_facts(connection, stored_plan)
        # Local declaration rows are canonical workflow state. Caller-supplied
        # observations remain available only for refs not owned by this plan.
        authoritative_blockers.update(native_blockers)
        authoritative_decisions.update(native_decisions)

    return EligibilityFacts(
        project=authority.project,
        authority_revision=revision,
        evaluated_at=evaluated_at,
        plan=plan,
        plan_matches_authority=plan_matches,
        accepted_plan_revision=accepted,
        registered_actors=registered,
        capabilities=tuple(capabilities),
        revoked_capability_ids=frozenset(revoked),
        runs=runs,
        assignments=assignments,
        attempts=tuple(attempts),
        outcomes=outcomes,
        legacy_completion_assertions=legacy_completion_assertions,
        queue_entries=queue_entries,
        blocker_observations=authoritative_blockers,
        check_observations=check_observations,
        decision_observations=authoritative_decisions,
        scope_contexts=scope_contexts,
        plan_memberships=plan_memberships,
        workspace_qualifications=workspace_qualifications,
        approved_participants=approved_participants,
        attempt_scope_snapshots=attempt_scope_snapshots,
        child_scope_occupancies=child_scope_occupancies,
    )


def _validated_observation_mapping(name: str, value: Mapping[Any, Any]) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return MappingProxyType(dict(value))


class EligibilityAdapter:
    """Read a consistent advisory snapshot or re-evaluate under a writer lock.

    Callers must provide the already compiled plan and any provider-owned
    observations. The adapter binds the plan's revision/digest to authority
    rows, obtains the current time itself, and reads current facts in the same
    SQLite snapshot/transaction as the decision.
    """

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _evaluate(
        self,
        authority: SQLiteAuthority,
        connection,
        request: EligibilityRequest,
        plan: CompiledPlan,
        *,
        blocker_observations: Mapping[EntityRef, ConditionResult],
        check_observations: Mapping[StableId, ConditionResult],
        decision_observations: Mapping[str, DecisionObservation],
        scope_contexts: Mapping[EntityRef, WorkItemContext],
        workspace_qualifications: Mapping[EntityRef, WorkspaceQualification],
        approved_participants: Mapping[EntityRef, frozenset[EntityRef]],
    ) -> EligibilityDecision:
        now = self._clock()
        _require_aware(now, "eligibility clock result")
        facts = _load_facts(
            connection,
            authority,
            request,
            plan,
            now,
            blocker_observations=_validated_observation_mapping("blocker_observations", blocker_observations),
            check_observations=_validated_observation_mapping("check_observations", check_observations),
            decision_observations=_validated_observation_mapping("decision_observations", decision_observations),
            scope_contexts=_validated_observation_mapping("scope_contexts", scope_contexts),
            workspace_qualifications=_validated_observation_mapping("workspace_qualifications", workspace_qualifications),
            approved_participants=_validated_observation_mapping("approved_participants", approved_participants),
        )
        return evaluate_eligibility(request, facts)

    def evaluate_read(
        self,
        authority: SQLiteAuthority,
        request: EligibilityRequest,
        plan: CompiledPlan,
        *,
        blocker_observations: Mapping[EntityRef, ConditionResult] = MappingProxyType({}),
        check_observations: Mapping[StableId, ConditionResult] = MappingProxyType({}),
        decision_observations: Mapping[str, DecisionObservation] = MappingProxyType({}),
        scope_contexts: Mapping[EntityRef, WorkItemContext] = MappingProxyType({}),
        workspace_qualifications: Mapping[EntityRef, WorkspaceQualification] = MappingProxyType({}),
        approved_participants: Mapping[EntityRef, frozenset[EntityRef]] = MappingProxyType({}),
    ) -> EligibilityDecision:
        """Assess advisory eligibility against one read-only authority snapshot."""
        if not authority.readonly:
            raise ReadOnlyAuthorityError("advisory eligibility requires an explicitly read-only authority")
        with authority.read_transaction() as connection:
            return self._evaluate(
                authority, connection, request, plan,
                blocker_observations=blocker_observations,
                check_observations=check_observations,
                decision_observations=decision_observations,
                scope_contexts=scope_contexts,
                workspace_qualifications=workspace_qualifications,
                approved_participants=approved_participants,
            )

    def evaluate_in_transaction(
        self,
        authority: SQLiteAuthority,
        connection,
        request: EligibilityRequest,
        plan: CompiledPlan,
        *,
        blocker_observations: Mapping[EntityRef, ConditionResult] = MappingProxyType({}),
        check_observations: Mapping[StableId, ConditionResult] = MappingProxyType({}),
        decision_observations: Mapping[str, DecisionObservation] = MappingProxyType({}),
        scope_contexts: Mapping[EntityRef, WorkItemContext] = MappingProxyType({}),
        workspace_qualifications: Mapping[EntityRef, WorkspaceQualification] = MappingProxyType({}),
        approved_participants: Mapping[EntityRef, frozenset[EntityRef]] = MappingProxyType({}),
    ) -> EligibilityDecision:
        """Re-evaluate from fresh facts inside ``authority.write_transaction``.

        The previously observed revision is compared by the same pure policy
        after acquiring SQLite's writer reservation. Callers must check the
        returned decision before mutating; this method does not reserve work.
        """
        if authority.readonly:
            raise ReadOnlyAuthorityError("transactional eligibility requires a writer authority")
        if connection is not authority.connection:
            raise EligibilityAdapterError("transactional eligibility must use this authority's connection")
        if not authority.write_transaction_active:
            raise EligibilityAdapterError("transactional eligibility requires the authority's active write transaction")
        return self._evaluate(
            authority, connection, request, plan,
            blocker_observations=blocker_observations,
            check_observations=check_observations,
            decision_observations=decision_observations,
            scope_contexts=scope_contexts,
            workspace_qualifications=workspace_qualifications,
            approved_participants=approved_participants,
        )


__all__ = [
    "EligibilityAdapter",
    "EligibilityAdapterError",
    "EligibilityFacts",
    "evaluate_eligibility",
]
