"""Candidate reporting and separately authorized, source-bound outcomes.

External source and host observations are collected before the authority writer
transaction. Their exact receipts are then checked in the guarded command; the
service does not claim that SQLite and a repository are one atomic resource.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from typing import Protocol

from todo_orchestrator.authority.auth import (
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeniedError,
    _token_digest,
)
from todo_orchestrator.authority.attempts import (
    AttemptHost,
    AttemptNotFoundError,
    AttemptObservationMismatchError,
    _attempt_from_row,
    _check_observation,
    _observation_audit,
    _stored_attempt,
    _stored_workspace,
)
from todo_orchestrator.authority.commands import MutationContext
from todo_orchestrator.authority.sqlite import AuthorityError, InvalidAuthorityError, SQLiteAuthority, load_plan_revision_snapshot
from todo_orchestrator.contracts import (
    AttemptState,
    ArtifactExpectation,
    DeclarationKind,
    DeclarationObservation,
    DeclarationObservationRequest,
    DeclarationObserver,
    DeclarationStatus,
    EntityKind,
    EntityRef,
    EvidenceKind,
    EvidenceResult,
    OutcomeDisposition,
    ProviderCallContext,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Project,
    RequirementKind,
    Sha256Digest,
    SourceObservation,
    SourceObservationRequest,
    StableId,
    VerificationKind,
    WorkingTreeState,
    provider_request_digest,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    CommandEffect,
    CommandResult,
    ProcessLiveness,
    SourceSafety,
)
from todo_orchestrator.planning import (
    BlockerRelation,
    CompiledPlan,
    ConditionCause,
    ConditionResult,
    ConditionStatus,
    DecisionObservation,
    decode_accepted_plan,
    evaluate_blocking_group,
    evaluate_condition,
    evaluate_results,
)
from todo_orchestrator.contracts import RequirementMode
from todo_orchestrator.planning.package import _compatible_interface_version

from .service import (
    SourceObserver,
    VerificationDeniedError,
    VerificationError,
    _digest,
    _id,
    _json,
    _load_plan,
    _ref_value,
    _source_value,
)


REPORT_CANDIDATE_ACTION = StableId("todo.outcome.report")
ACCEPT_OUTCOME_ACTION = StableId("todo.outcome.accept")
REJECT_CANDIDATE_ACTION = StableId("todo.outcome.reject")
READ_OUTCOME_ACTION = StableId("todo.outcome.read")
MANUAL_OWNER_ACTIONS = {
    "owner": StableId("todo.outcome.manual.owner"),
    "maintainer": StableId("todo.outcome.manual.maintainer"),
    "reviewer": StableId("todo.outcome.manual.reviewer"),
    "project_admin": StableId("todo.outcome.manual.project_admin"),
}


class CandidateError(AuthorityError):
    """Base class for outcome candidate and acceptance failures."""


class CandidateNotFoundError(CandidateError):
    """The report is absent, belongs to another attempt, or is not pending."""


class CandidateDeniedError(CandidateError):
    """The current attempt, evidence, policy, or capability refuses the transition."""


class CandidateObservationMismatchError(CandidateError):
    """A source or host observation does not bind the finalization request."""


class CandidateStateError(CandidateError):
    """The candidate or attempt is not in a finalizable state."""


@dataclass(frozen=True)
class CandidateReportView:
    candidate: EntityRef
    attempt: EntityRef
    target: EntityRef
    disposition: OutcomeDisposition
    note: str | None
    state: str
    reported_by: EntityRef
    source_digest: Sha256Digest
    reported_at: datetime


@dataclass(frozen=True)
class OutcomeApplicabilityView:
    """Fresh, read-only assessment separate from immutable accepted history."""

    outcome: EntityRef
    status: str
    reasons: tuple[str, ...]
    evaluated_at: datetime
    current_plan_revision_id: StableId | None
    current_source_digest: Sha256Digest | None

    @property
    def applicable(self) -> bool:
        return self.status == "applicable"


class _Report:
    def __init__(self, attempt, target, candidate_id, disposition, note, source_json, receipt_json, request_digest,
                 source_identity, run, assignment, at):
        self.attempt = attempt
        self.target = target
        self.candidate_id = candidate_id
        self.disposition = disposition
        self.note = note
        self.source_json = source_json
        self.receipt_json = receipt_json
        self.request_digest = request_digest
        self.source_identity = source_identity
        self.run = run
        self.assignment = assignment
        self.at = at

    def __deepcopy__(self, memo):
        return self


class _Finalize:
    def __init__(self, action, attempt, target, candidate_id, source_json, source_receipt_json,
                 source_request_digest, safety_json, applicability_json, declaration_json, plan_revision_id,
                 required_manual_actions, run, assignment, provider_capability_id, at):
        self.action = action
        self.attempt = attempt
        self.target = target
        self.candidate_id = candidate_id
        self.source_json = source_json
        self.source_receipt_json = source_receipt_json
        self.source_request_digest = source_request_digest
        self.safety_json = safety_json
        self.applicability_json = applicability_json
        self.declaration_json = declaration_json
        self.plan_revision_id = plan_revision_id
        self.required_manual_actions = required_manual_actions
        self.provider_capability_id = provider_capability_id
        self.run = run
        self.assignment = assignment
        self.at = at

    def __deepcopy__(self, memo):
        return self


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _source_request(context, attempt, target, workspace, correlation, artifacts=()):
    attempt_ref = attempt if isinstance(attempt, EntityRef) else attempt.ref
    return SourceObservationRequest(context, correlation, None, attempt_ref, workspace.workspace_id, target, None,
                                    tuple(artifacts))


def _artifact_expectations(connection: sqlite3.Connection, attempt_id: StableId) -> tuple[ArtifactExpectation, ...]:
    rows = connection.execute(
        "SELECT DISTINCT a.artifact_id, a.content_digest FROM evidence AS e "
        "JOIN evidence_artifacts AS ea USING(evidence_id) JOIN artifacts AS a USING(artifact_id) "
        "WHERE e.attempt_id = ? ORDER BY a.artifact_id", (str(attempt_id),),
    ).fetchall()
    expectations = []
    for row in rows:
        if row["content_digest"] is None:
            raise CandidateObservationMismatchError("artifact evidence has no trusted content digest")
        expectations.append(ArtifactExpectation(StableId(row["artifact_id"]), Sha256Digest(row["content_digest"])))
    return tuple(expectations)


def _expected_artifact_value(expectations: tuple[ArtifactExpectation, ...]) -> list[dict[str, str]]:
    return [{"artifact_id": str(item.artifact_id), "available": True,
             "content_digest": item.expected_digest.hex} for item in expectations]


def _source_receipt_value(receipt: ProviderReceipt) -> dict[str, object]:
    return {
        "receipt_id": str(receipt.receipt_id),
        "provider": {"provider_id": str(receipt.provider.provider_id), "version": receipt.provider.version,
                     "contract_version": receipt.provider.contract_version},
        "correlation_id": str(receipt.correlation_id), "request_digest": receipt.request_digest.hex,
        "provenance_ref": str(receipt.provenance_ref), "observed_at": _iso(receipt.observed_at),
    }


def _decode_source(encoded: str) -> dict[str, object]:
    value = json.loads(encoded)
    if not isinstance(value, dict) or set(value) != {"repository_id", "source_digest", "base_digest", "working_tree", "inputs", "artifacts"}:
        raise CandidateObservationMismatchError("stored source observation has an invalid shape")
    return value


def _provider_source(
    result: ProviderResult[SourceObservation], request: SourceObservationRequest,
    identity: ProviderIdentity, workspace, now: datetime, max_age: timedelta,
) -> tuple[SourceObservation, ProviderReceipt]:
    if not isinstance(result, ProviderResult) or result.status is not ProviderStatus.OBSERVED_SUCCESS:
        raise CandidateObservationMismatchError("source observer did not return a successful typed observation")
    receipt = result.receipt
    if (result.provider != identity or result.correlation_id != request.correlation_id
            or receipt is None or receipt.provider != identity
            or receipt.correlation_id != request.correlation_id
            or receipt.request_digest != provider_request_digest(request)
            or request.workspace_id is None or receipt.provenance_ref != request.workspace_id):
        raise CandidateObservationMismatchError("source receipt does not bind the exact attempt workspace request")
    if not isinstance(result.value, SourceObservation):
        raise CandidateObservationMismatchError("source observer returned no typed observation")
    if (result.value.repository_id != workspace.repository_id
            or result.value.base_digest is None
            or result.value.base_digest.hex != workspace.common_base.digest):
        raise CandidateObservationMismatchError("source observation names a different repository or qualified base")
    if request.expected_source is not None and result.value.source_digest != request.expected_source:
        raise CandidateObservationMismatchError("source observation differs from the exact expected source digest")
    expected_artifacts = {item.artifact_id: item.expected_digest for item in request.artifacts}
    observed_artifacts = {item.artifact_id: item for item in result.value.artifacts}
    if set(observed_artifacts) != set(expected_artifacts):
        raise CandidateObservationMismatchError("source observation omitted or added artifact availability facts")
    if any(not observed_artifacts[identifier].available
           or observed_artifacts[identifier].content_digest != digest
           for identifier, digest in expected_artifacts.items()):
        raise CandidateObservationMismatchError("an expected artifact is unavailable or has changed content")
    observed = receipt.observed_at.astimezone(timezone.utc)
    if observed > now or now - observed > max_age:
        raise CandidateObservationMismatchError("source observation is stale or from the future")
    return result.value, receipt


def _fresh_plan(connection: sqlite3.Connection, project: Project, target: EntityRef) -> tuple[StableId, CompiledPlan]:
    row = connection.execute(
        "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    if row is None:
        raise CandidateDeniedError("authority has no accepted plan")
    revision = StableId(row[0])
    plan = _load_plan(connection, project, revision)
    if not any(item.definition.ref == target for item in plan.work_items):
        raise CandidateDeniedError("the exact work definition is no longer in the current accepted plan")
    return revision, plan


def _safe_json_map(value: Mapping[str, object]) -> dict[str, object]:
    # Dispatcher canonicalization applies a second JSON-type check to every
    # command payload. Here we snapshot the provider response before dispatch.
    return json.loads(_json(dict(value)))


def _plain_json_value(value):
    if isinstance(value, Mapping):
        return {str(key): _plain_json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json_value(item) for item in value]
    return value


def _declarations(plan: CompiledPlan, kind: str) -> dict[str, Mapping[str, object]]:
    return {str(item.payload["id"]): item.payload for item in plan.declarations if item.kind == kind}


def _declaration_specs(plan: CompiledPlan, target: EntityRef):
    kind_by_entity = {
        EntityKind.CHECKPOINT: DeclarationKind.CHECKPOINT,
        EntityKind.INTERFACE: DeclarationKind.INTERFACE,
        EntityKind.BARRIER: DeclarationKind.BARRIER,
    }
    specs = {}
    for requirement in plan.requirements:
        definition = requirement.definition
        if definition.owner != target or definition.kind is not RequirementKind.PREREQUISITE or definition.target is None:
            continue
        reference = requirement.target.reference
        declaration_kind = kind_by_entity.get(reference.kind)
        if reference.kind is EntityKind.BARRIER:
            declaration_kind = (DeclarationKind.RENDEZVOUS
                                if str(reference.entity_id) in _declarations(plan, "rendezvous")
                                else DeclarationKind.BARRIER)
        if declaration_kind is not None:
            specs[(declaration_kind.value, str(reference.entity_id), str(reference.definition_revision_id or ""))] = (
                reference, declaration_kind, None,
            )
    for group in plan.blocking_groups:
        if group.source.reference != target:
            continue
        for edge in group.members:
            reference = edge.target.reference
            if edge.relation is BlockerRelation.CHECKPOINT_ACCEPTED:
                declaration_kind = DeclarationKind.CHECKPOINT
            elif edge.relation is BlockerRelation.INTERFACE_VERSION:
                declaration_kind = DeclarationKind.INTERFACE
            elif edge.relation is BlockerRelation.BARRIER_RELEASED:
                declaration_kind = DeclarationKind.BARRIER
            elif edge.relation is BlockerRelation.RENDEZVOUS_MET:
                declaration_kind = DeclarationKind.RENDEZVOUS
            else:
                continue
            specs[(declaration_kind.value, str(reference.entity_id), str(reference.definition_revision_id or ""))] = (
                reference, declaration_kind,
                edge.expected_version if edge.relation is BlockerRelation.INTERFACE_VERSION else None,
            )
    return tuple(specs[key] for key in sorted(specs))


def _declaration_payload(plan: CompiledPlan, reference: EntityRef, kind: DeclarationKind):
    plural = {
        DeclarationKind.CHECKPOINT: "checkpoints", DeclarationKind.INTERFACE: "interfaces",
        DeclarationKind.BARRIER: "barriers", DeclarationKind.RENDEZVOUS: "rendezvous",
    }[kind]
    return _declarations(plan, plural).get(str(reference.entity_id))


def _declaration_key(reference: EntityRef, kind: DeclarationKind) -> str:
    return f"{kind.value}:{reference.entity_id}:{reference.definition_revision_id or ''}"


def _accepted_work_outcome(connection, plan: CompiledPlan, reference: EntityRef) -> tuple[ConditionResult, str | None]:
    if reference.project_id != plan.project.project_id or reference.kind is not EntityKind.WORK_ITEM:
        return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause(
            "foreign_work_outcome_unavailable", str(reference.entity_id),
            "cross-authority outcome status requires a trusted adopted observation",
        ),)), None
    planned = next((item for item in plan.work_items if item.definition.ref == reference), None)
    if planned is None:
        return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause(
            "work_definition_unavailable", str(reference.entity_id),
            "the exact work definition is absent from the current accepted plan",
        ),)), None
    row = connection.execute(
        "SELECT outcome_id, disposition FROM outcomes WHERE work_item_id = ? AND definition_revision_id = ? "
        "ORDER BY version DESC LIMIT 1", (str(reference.entity_id), str(reference.definition_revision_id)),
    ).fetchone()
    if row is None:
        return ConditionResult(ConditionStatus.UNSATISFIED, (ConditionCause(
            "work_item_incomplete", str(reference.entity_id), "no accepted outcome exists for this exact definition",
        ),)), None
    satisfied = row["disposition"] in planned.context.acceptance.get("allowed_dispositions", ())
    return ConditionResult(
        ConditionStatus.SATISFIED if satisfied else ConditionStatus.UNSATISFIED,
        (ConditionCause("work_item_outcome", str(reference.entity_id),
                        f"accepted outcome is {row['disposition']}"),),
    ), row["outcome_id"]


def _declaration_result(connection, plan: CompiledPlan, target: EntityRef, kind: str,
                        *, expected_version: str | None = None,
                        trusted_statuses: Mapping[str, DeclarationObservation] | None = None) -> ConditionResult:
    if target.project_id != plan.project.project_id:
        return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause(
            "foreign_declaration_unavailable", str(target.entity_id),
            "cross-authority declaration status requires a trusted adopted observation",
        ),))
    declarations = _declarations(plan, kind)
    declaration = declarations.get(str(target.entity_id))
    if declaration is None:
        return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause(
            "declaration_unavailable", str(target.entity_id), f"current accepted plan has no {kind} declaration",
        ),))
    if kind == "decisions":
        selected = declaration.get("selected_option_id")
        return ConditionResult(
            ConditionStatus.SATISFIED if selected is not None else ConditionStatus.UNRESOLVED,
            (ConditionCause("decision_resolution", str(target.entity_id),
                            "decision has an accepted selected option" if selected is not None
                            else "decision is unresolved in the accepted plan"),),
        )
    declaration_kind = {
        "checkpoints": DeclarationKind.CHECKPOINT,
        "interfaces": DeclarationKind.INTERFACE,
        "barriers": DeclarationKind.BARRIER,
        "rendezvous": DeclarationKind.RENDEZVOUS,
    }.get(kind)
    if declaration_kind is None:
        return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause(
            "unsupported_declaration_kind", str(target.entity_id), "declaration kind has no trusted status contract",
        ),))
    observation = (trusted_statuses or {}).get(_declaration_key(target, declaration_kind))
    if observation is None:
        return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause(
            "declaration_status_unobserved", str(target.entity_id),
            f"no fresh trusted status receipt is available for {kind}",
        ),))
    if observation.status is DeclarationStatus.UNRESOLVED:
        return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause(
            "declaration_status_unresolved", str(target.entity_id), f"trusted provider reports {kind} unresolved",
        ),))
    if observation.status is DeclarationStatus.UNSATISFIED:
        return ConditionResult(ConditionStatus.UNSATISFIED, (ConditionCause(
            "declaration_status_unsatisfied", str(target.entity_id), f"trusted provider reports {kind} unsatisfied",
        ),))
    if kind == "interfaces" and expected_version is not None:
        try:
            compatible = _compatible_interface_version(
                str(observation.observed_version), expected_version, str(declaration["compatibility"]),
                "$/interfaces/" + str(target.entity_id),
            )
        except (KeyError, TypeError, ValueError):
            compatible = False
        if not compatible:
            return ConditionResult(ConditionStatus.UNSATISFIED, (ConditionCause(
                "interface_version_mismatch", str(target.entity_id),
                f"current interface version {declaration.get('version')!r} is incompatible with {expected_version!r}",
            ),))
    return ConditionResult(ConditionStatus.SATISFIED, (ConditionCause(
        "declaration_status_observed", str(target.entity_id),
        f"fresh trusted provider receipt confirms {kind} status",
    ),))


def _has_current_check_evidence(connection, attempt_id: StableId, source: Mapping[str, object], requirement,
                                *, allow_benchmark_negative: bool = False) -> bool:
    contract = requirement.verification
    if contract is None:
        return False
    rows = connection.execute(
        "SELECT e.*, v.state FROM evidence AS e JOIN verification_attempts AS v USING(operation_id) "
        "WHERE e.attempt_id = ? AND e.requirement_id = ? AND e.requirement_definition_revision_id = ? "
        "AND ((e.result = 'pass' AND v.state = 'finalized') OR (e.result = 'fail' AND v.state = 'rejected')) "
        "ORDER BY e.observed_at DESC",
        (str(attempt_id), str(requirement.requirement_id), str(requirement.definition_revision_id)),
    ).fetchall()
    expected_contract = _digest(_json(contract.to_mapping())).hex
    current_inputs = {entry["name"]: entry["digest"] for entry in source.get("inputs", ())}
    for row in rows:
        if row["source_digest"] != source.get("source_digest") or row["contract_digest"] != expected_contract:
            continue
        facts = connection.execute(
            "SELECT fact_name, fact_kind, fact_version, fact_digest, artifact_id, value_json FROM evidence_facts WHERE evidence_id = ?",
            (row["evidence_id"],),
        ).fetchall()
        actual = {(item["fact_name"], item["fact_kind"], item["fact_version"]) for item in facts}
        wanted = {(str(item.name), item.kind.value, item.version) for item in requirement.required_evidence}
        if not wanted.issubset(actual):
            continue
        passing = row["result"] == EvidenceResult.PASS.value and row["state"] == "finalized"
        negative = (allow_benchmark_negative and row["result"] == EvidenceResult.FAIL.value
                    and row["state"] == "rejected" and _benchmark_definitively_missed(requirement, facts))
        if not (passing or negative):
            continue
        inputs = connection.execute(
            "SELECT input_name, input_digest FROM evidence_inputs WHERE evidence_id = ?",
            (row["evidence_id"],),
        ).fetchall()
        if any(current_inputs.get(item["input_name"]) != item["input_digest"] for item in inputs):
            continue
        artifacts = connection.execute(
            "SELECT a.artifact_id, a.content_digest FROM evidence_artifacts AS ea "
            "JOIN artifacts AS a USING(artifact_id) WHERE ea.evidence_id = ?",
            (row["evidence_id"],),
        ).fetchall()
        bound = {item["artifact_id"]: item["fact_digest"] for item in facts if item["artifact_id"] is not None}
        if any(item["content_digest"] is None or bound.get(item["artifact_id"]) != item["content_digest"]
               for item in artifacts):
            continue
        return True
    return False


def _benchmark_definitively_missed(requirement, facts) -> bool:
    contract = requirement.verification
    if contract is None or contract.kind is not VerificationKind.BENCHMARK:
        return False
    config = contract.config
    samples = []
    for fact in facts:
        if fact["fact_kind"] != EvidenceKind.BENCHMARK_SAMPLE.value:
            continue
        if fact["value_json"] is None:
            return False
        try:
            value = json.loads(fact["value_json"])
            if set(value) != {"value", "unit", "sample_count"}:
                return False
            if value["unit"] != config["unit"] or type(value["sample_count"]) is not int:
                return False
            numeric = value["value"]
            if type(numeric) not in {int, float}:
                return False
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        samples.append((float(numeric), value["sample_count"]))
    if not samples or sum(count for _, count in samples) < config.get("minimum_samples", 1):
        return False
    threshold = float(config["threshold"])
    operator = config["operator"]
    def passes(value: float) -> bool:
        return {
            "lt": value < threshold, "lte": value <= threshold, "eq": value == threshold,
            "gte": value >= threshold, "gt": value > threshold,
        }[operator]
    return all(not passes(value) for value, _ in samples)


def _manual_requirements_for_acceptance(connection, plan: CompiledPlan, target: EntityRef,
                                        attempt_id: StableId, source: Mapping[str, object],
                                        *, allow_benchmark_negative: bool = False) -> tuple[object, ...]:
    requirements = {req.definition.requirement_id: req.definition for req in plan.requirements
                    if req.definition.owner == target and req.definition.kind is RequirementKind.CHECK}
    manual_ids = {identifier for identifier, req in requirements.items() if req.verification is not None
                  and req.verification.kind is VerificationKind.MANUAL_OWNER}
    selected: set[StableId] = set()
    item = next((value for value in plan.work_items if value.definition.ref == target), None)
    if item is None:
        return ()
    grouped: set[StableId] = set()
    for group in item.definition.requirement_groups:
        if group.kind is not RequirementKind.CHECK:
            continue
        grouped.update(group.requirement_ids)
        manual = sorted((identifier for identifier in group.requirement_ids if identifier in manual_ids), key=str)
        ready_nonmanual = sum(
            1 for identifier in group.requirement_ids
            if identifier in requirements and identifier not in manual_ids
            and _has_current_check_evidence(connection, attempt_id, source, requirements[identifier],
                                            allow_benchmark_negative=allow_benchmark_negative)
        )
        if group.mode is RequirementMode.ALL:
            selected.update(manual)
        elif group.mode is RequirementMode.ANY and ready_nonmanual == 0 and manual:
            selected.add(manual[0])
        elif group.mode is RequirementMode.QUORUM:
            needed = max(0, int(group.quorum or 0) - ready_nonmanual)
            selected.update(manual[:needed])
    selected.update(identifier for identifier in manual_ids if identifier not in grouped)
    return tuple(requirements[identifier] for identifier in sorted(selected, key=str))


def _current_dependency_failures(connection, plan: CompiledPlan, target: EntityRef,
                                 source: Mapping[str, object],
                                 declaration_statuses: Mapping[str, DeclarationObservation] | None = None) -> tuple[str, ...]:
    item = next((value for value in plan.work_items if value.definition.ref == target), None)
    if item is None:
        return ("exact work definition is no longer current",)
    requirements = {req.definition.requirement_id: req.definition for req in plan.requirements
                    if req.definition.owner == target}
    decisions = {
        identifier: DecisionObservation(
            ConditionStatus.SATISFIED if payload.get("selected_option_id") is not None else ConditionStatus.UNRESOLVED,
            None if payload.get("selected_option_id") is None else str(payload["selected_option_id"]),
        ) for identifier, payload in _declarations(plan, "decisions").items()
    }
    failures = []
    for group in item.definition.requirement_groups:
        if group.kind is not RequirementKind.PREREQUISITE:
            continue
        results = []
        for identifier in group.requirement_ids:
            requirement = requirements.get(identifier)
            if requirement is None or requirement.target is None:
                results.append(ConditionResult(ConditionStatus.UNAVAILABLE))
                continue
            target_ref = requirement.target.reference
            if target_ref.kind is EntityKind.WORK_ITEM:
                result = _accepted_work_outcome(connection, plan, target_ref)[0]
            else:
                declaration_kind = {
                    EntityKind.CHECKPOINT: "checkpoints", EntityKind.INTERFACE: "interfaces",
                    EntityKind.DECISION: "decisions", EntityKind.BARRIER: "barriers",
                }.get(target_ref.kind)
                result = ConditionResult(ConditionStatus.UNAVAILABLE) if declaration_kind is None else _declaration_result(
                    connection, plan, target_ref, declaration_kind, trusted_statuses=declaration_statuses)
            results.append(result)
        combined = evaluate_results(group.mode, group.quorum, results)
        if combined.status is not ConditionStatus.SATISFIED:
            failures.append("a current typed prerequisite group is " + combined.status.value)
    for group in plan.blocking_groups:
        if group.source.reference != target:
            continue
        blockers = []
        for edge in group.members:
            ref = edge.target.reference
            if edge.relation is BlockerRelation.COMPLETION:
                blocker = _accepted_work_outcome(connection, plan, ref)[0]
            elif edge.relation is BlockerRelation.CHECKPOINT_ACCEPTED:
                blocker = _declaration_result(connection, plan, ref, "checkpoints", trusted_statuses=declaration_statuses)
            elif edge.relation is BlockerRelation.INTERFACE_VERSION:
                blocker = _declaration_result(connection, plan, ref, "interfaces", expected_version=edge.expected_version,
                                              trusted_statuses=declaration_statuses)
            elif edge.relation is BlockerRelation.DECISION_RESOLVED:
                blocker = _declaration_result(connection, plan, ref, "decisions")
            elif edge.relation is BlockerRelation.BARRIER_RELEASED:
                blocker = _declaration_result(connection, plan, ref, "barriers", trusted_statuses=declaration_statuses)
            elif edge.relation is BlockerRelation.RENDEZVOUS_MET:
                blocker = _declaration_result(connection, plan, ref, "rendezvous", trusted_statuses=declaration_statuses)
            elif edge.relation is BlockerRelation.EVIDENCE_VERIFIED:
                row = connection.execute(
                    "SELECT e.result, e.source_digest, v.state FROM evidence AS e "
                    "JOIN verification_attempts AS v USING(operation_id) WHERE e.evidence_id = ?",
                    (str(ref.entity_id),),
                ).fetchone()
                passed = row is not None and row["result"] == EvidenceResult.PASS.value \
                    and row["state"] == "finalized" and row["source_digest"] == source.get("source_digest")
                blocker = ConditionResult(ConditionStatus.SATISFIED if passed else ConditionStatus.UNSATISFIED)
            else:
                blocker = ConditionResult(ConditionStatus.UNAVAILABLE)
            blockers.append(blocker)
        result = evaluate_blocking_group(group, tuple(blockers), decisions)
        if result.status is not ConditionStatus.SATISFIED:
            failures.append("a current dependency group is " + result.status.value)
    return tuple(failures)


class _ReportHandler:
    kind = "todo.outcome.report_candidate"
    command_type = _Report

    def __init__(self, service: "OutcomeAcceptanceService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Report) -> AuthorizationRequirement:
        return AuthorizationRequirement(REPORT_CANDIDATE_ACTION, command.target, command.run,
                                         command.assignment, command.attempt)

    def canonical_payload(self, command: _Report) -> dict[str, object]:
        return {
            "attempt": _ref_value(command.attempt), "target": _ref_value(command.target),
            "candidate_id": str(command.candidate_id), "disposition": command.disposition.value,
            "note": command.note, "source_json": command.source_json,
            "source_receipt_json": command.receipt_json, "source_request_digest": command.request_digest.hex,
            "source_identity": {"provider_id": str(command.source_identity.provider_id),
                                "version": command.source_identity.version,
                                "contract_version": command.source_identity.contract_version},
            "run": None if command.run is None else _ref_value(command.run),
            "assignment": None if command.assignment is None else _ref_value(command.assignment),
            "reported_at": command.at,
        }

    def apply(self, context: MutationContext, command: _Report) -> CommandEffect:
        attempt, row = _stored_attempt(context._connection, context.project, command.attempt)
        # Provider calls happen before dispatch. Recheck freshness and lease
        # validity only after the writer reservation has been acquired.
        now = self.service._now()
        if (attempt.work_item != command.target or attempt.actor != context.actor
                or attempt.run != command.run or attempt.assignment != command.assignment
                or attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE}
                or attempt.lease is None):
            raise CandidateDeniedError("only the live attempt owner can report its current candidate")
        if attempt.lease.expires_at <= now:
            raise CandidateDeniedError("attempt lease expired before candidate report")
        _, plan = _fresh_plan(context._connection, context.project, command.target)
        item = next(item for item in plan.work_items if item.definition.ref == command.target)
        allowed = item.context.acceptance.get("allowed_dispositions", ())
        if command.disposition is not OutcomeDisposition.FAILED and command.disposition.value not in allowed:
            raise CandidateDeniedError("candidate disposition is not allowed by the authored acceptance policy")
        request_body = json.loads(command.source_json)
        receipt_body = json.loads(command.receipt_json)
        if (request_body.get("repository_id") is None or len(request_body.get("source_digest", "")) != 64
                or receipt_body.get("request_digest") != command.request_digest.hex
                or receipt_body.get("provider") != {
                    "provider_id": str(command.source_identity.provider_id),
                    "version": command.source_identity.version,
                    "contract_version": command.source_identity.contract_version,
                }):
            raise CandidateObservationMismatchError("candidate source evidence is malformed or unbound")
        self.service._require_fresh_receipt(receipt_body, now, "candidate source")
        expected_artifacts = _artifact_expectations(context._connection, attempt.attempt_id)
        if request_body.get("artifacts") != _expected_artifact_value(expected_artifacts):
            raise CandidateObservationMismatchError("candidate artifact availability no longer matches authority records")
        updated = context.execute(
            "UPDATE attempts SET state = 'reported' WHERE attempt_id = ? AND state = ? AND lease_id = ?",
            (str(attempt.attempt_id), attempt.state.value, row["lease_id"]),
        ).rowcount
        if updated != 1:
            raise CandidateStateError("attempt state changed while reporting candidate")
        context.execute(
            "INSERT INTO outcome_candidates(candidate_id, attempt_id, work_item_id, definition_revision_id, "
            "disposition, note, report_source_json, report_receipt_json, reported_by_actor_id, "
            "reported_by_incarnation_id, reported_at, state, outcome_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL)",
            (str(command.candidate_id), str(attempt.attempt_id), str(command.target.entity_id),
             str(command.target.definition_revision_id), command.disposition.value, command.note,
             command.source_json, command.receipt_json, str(context.actor.entity_id),
             str(context.actor.incarnation_id), command.at),
        )
        payload = {"candidate_id": str(command.candidate_id), "attempt_id": str(attempt.attempt_id),
                   "target": _ref_value(command.target), "disposition": command.disposition.value,
                   "source_digest": request_body["source_digest"]}
        return CommandEffect(True, {"candidate_id": str(command.candidate_id), "state": "pending"},
                             "todo.outcome.candidate_reported", payload)


class _FinalizeHandler:
    kind = "todo.outcome.finalize_candidate"
    command_type = _Finalize

    def __init__(self, service: "OutcomeAcceptanceService") -> None:
        self.service = service

    def authorization_requirement(self, command: _Finalize) -> AuthorizationRequirement:
        return AuthorizationRequirement(command.action, command.target, command.run,
                                         command.assignment, command.attempt,
                                         command.required_manual_actions)

    def canonical_payload(self, command: _Finalize) -> dict[str, object]:
        return {
            "action": str(command.action), "attempt": _ref_value(command.attempt),
            "target": _ref_value(command.target), "candidate_id": str(command.candidate_id),
            "source_json": command.source_json, "source_receipt_json": command.source_receipt_json,
            "source_request_digest": command.source_request_digest.hex,
            "safety_json": command.safety_json, "applicability_json": command.applicability_json,
            "declaration_json": command.declaration_json,
            "plan_revision_id": str(command.plan_revision_id),
            "required_manual_actions": [str(value) for value in command.required_manual_actions],
            "provider_capability_id": str(command.provider_capability_id),
            "run": None if command.run is None else _ref_value(command.run),
            "assignment": None if command.assignment is None else _ref_value(command.assignment),
            "occurred_at": command.at,
        }

    def apply(self, context: MutationContext, command: _Finalize) -> CommandEffect:
        row = context._connection.execute(
            "SELECT c.*, a.state AS attempt_state, a.lease_id, a.lease_expires_at, a.actor_id, "
            "a.actor_incarnation_id, a.run_id, a.assignment_id FROM outcome_candidates AS c "
            "JOIN attempts AS a USING(attempt_id) WHERE c.candidate_id = ? AND c.attempt_id = ?",
            (str(command.candidate_id), str(command.attempt.entity_id)),
        ).fetchone()
        if row is None:
            raise CandidateNotFoundError("candidate does not belong to the requested attempt")
        if row["state"] != "pending" or row["attempt_state"] != AttemptState.REPORTED.value:
            raise CandidateStateError("candidate is not pending on a reported attempt")
        attempt, attempt_row = _stored_attempt(context._connection, context.project, command.attempt)
        now = self.service._now()
        if (attempt.work_item != command.target or attempt.run != command.run or attempt.assignment != command.assignment
                or row["work_item_id"] != str(command.target.entity_id)
                or row["definition_revision_id"] != str(command.target.definition_revision_id)
                or attempt.lease is None or attempt.lease.expires_at <= now):
            raise CandidateDeniedError("attempt target, context, or lease changed before outcome finalization")
        workspace = _stored_workspace(context._connection, context.project, command.attempt)
        source = _decode_source(command.source_json)
        report_source = _decode_source(row["report_source_json"])
        report_receipt = json.loads(row["report_receipt_json"])
        final_receipt = json.loads(command.source_receipt_json)
        if source != report_source:
            raise CandidateObservationMismatchError("source identity or inputs changed since candidate report")
        expected_artifacts = _artifact_expectations(context._connection, attempt.attempt_id)
        if source.get("artifacts") != _expected_artifact_value(expected_artifacts):
            raise CandidateObservationMismatchError("current artifact set or digest differs from candidate report")
        if (report_receipt.get("provider") != final_receipt.get("provider")
                or final_receipt.get("provenance_ref") != str(workspace.workspace_id)
                or final_receipt.get("request_digest") != command.source_request_digest.hex
                or final_receipt.get("observed_at") > command.at):
            raise CandidateObservationMismatchError("final source receipt is not a fresh observation of the same workspace")
        self.service._require_fresh_receipt(final_receipt, now, "final source")
        safety = json.loads(command.safety_json)
        if (safety.get("source") != SourceSafety.CLEAN.value
                or safety.get("process") != ProcessLiveness.STOPPED.value
                or safety.get("children") != ChildActivity.NONE.value
                or safety.get("attempt_id") != str(attempt.attempt_id)
                or safety.get("lease_id") != str(attempt.lease.lease_id)
                or safety.get("workspace_id") != str(workspace.workspace_id)):
            raise CandidateDeniedError("attempt safety is dirty, unknown, live, or bound to another lease/workspace")
        safety_receipt = safety.get("receipt")
        if not isinstance(safety_receipt, dict):
            raise CandidateObservationMismatchError("host safety receipt is missing")
        if safety_receipt.get("provider") != {
            "provider_id": str(self.service.host_identity.provider_id),
            "version": self.service.host_identity.version,
            "contract_version": self.service.host_identity.contract_version,
        }:
            raise CandidateObservationMismatchError("host safety receipt has an unexpected provider identity")
        self.service._require_fresh_receipt(safety_receipt, now, "host safety")
        plan_revision, plan = _fresh_plan(context._connection, context.project, command.target)
        if plan_revision != command.plan_revision_id:
            raise CandidateDeniedError("accepted plan changed while final source and host observations were collected")
        guard_correlation = _id("outcome-source-guard", str(command.candidate_id))
        guard_context = self.service._provider_context(
            context.actor, "", command.action, command.target,
            command.provider_capability_id, guard_correlation,
        )
        guard_request = SourceObservationRequest(
            guard_context, guard_correlation, Sha256Digest(str(source["source_digest"])),
            command.attempt, workspace.workspace_id, command.target, None, expected_artifacts,
        )
        try:
            guard_result = self.service.source_observer.observe(guard_request)
            guard_now = self.service._now()
            guard_source, guard_receipt = _provider_source(
                guard_result, guard_request, self.service.source_identity, workspace, guard_now,
                self.service.max_observation_age,
            )
        except Exception as exc:
            raise CandidateObservationMismatchError(
                f"writer-bound source/artifact revalidation failed: {type(exc).__name__}"
            ) from exc
        if _source_value(guard_source) != source:
            raise CandidateObservationMismatchError("source or artifact state changed before the guarded outcome write")
        writer_source_receipt = _source_receipt_value(guard_receipt)
        writer_declaration_records = self.service._observe_declarations(
            plan, command.target, command.attempt, workspace, plan_revision, context.actor,
            command.provider_capability_id,
            "writer:" + str(command.candidate_id), self.service._now(),
        )
        commit_now = self.service._now()
        if attempt.lease is None or attempt.lease.expires_at <= commit_now:
            raise CandidateDeniedError("attempt lease expired before guarded outcome write")
        self.service._require_fresh_receipt(final_receipt, commit_now, "final source")
        self.service._require_fresh_receipt(report_receipt, commit_now, "candidate report source")
        self.service._require_fresh_receipt(safety_receipt, commit_now, "host safety")
        self.service._require_fresh_receipt(writer_source_receipt, commit_now, "writer source")
        declaration_statuses = self.service._validated_declaration_statuses(
            plan, command.target, writer_declaration_records, commit_now,
        )
        if command.action == ACCEPT_OUTCOME_ACTION:
            outcome, provenance = self.service._validate_and_build_outcome(
                context, command, row, attempt, plan, source, final_receipt, safety,
                declaration_statuses, writer_source_receipt, writer_declaration_records,
            )
            version_row = context._connection.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM outcomes WHERE work_item_id = ? AND definition_revision_id = ?",
                (str(command.target.entity_id), str(command.target.definition_revision_id)),
            ).fetchone()
            version = int(version_row[0])
            outcome_id = _id("outcome", str(command.candidate_id))
            evidence_ids = outcome["evidence_ids"]
            context.execute(
                "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, disposition, "
                "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at, attempt_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(outcome_id), str(command.target.entity_id), str(command.target.definition_revision_id),
                 version, row["disposition"], str(context.actor.entity_id), str(context.actor.incarnation_id),
                 command.at, str(attempt.attempt_id)),
            )
            for evidence_id in evidence_ids:
                context.execute("INSERT INTO outcome_evidence(outcome_id, evidence_id) VALUES (?, ?)",
                                (str(outcome_id), evidence_id))
            provenance["outcome"] = {"outcome_id": str(outcome_id), "version": version,
                                      "accepted_by": _ref_value(context.actor), "accepted_at": command.at}
            provenance_json = _json(provenance)
            context.execute(
                "INSERT INTO outcome_provenance(outcome_id, candidate_id, canonical_json, content_digest) "
                "VALUES (?, ?, ?, ?)",
                (str(outcome_id), str(command.candidate_id), provenance_json, _digest(provenance_json).hex),
            )
            state, event = AttemptState.ACCEPTED, "todo.outcome.accepted"
        else:
            outcome_id = None
            version = None
            evidence_ids = ()
            state, event = AttemptState.REJECTED, "todo.outcome.candidate_rejected"
        updated = context.execute(
            "UPDATE attempts SET state = ?, lease_id = NULL, lease_expires_at = NULL "
            "WHERE attempt_id = ? AND state = 'reported' AND lease_id = ?",
            (state.value, str(attempt.attempt_id), str(attempt.lease.lease_id)),
        ).rowcount
        if updated != 1:
            raise CandidateStateError("attempt state changed during finalization")
        context.execute(
            "UPDATE outcome_candidates SET state = ?, outcome_id = ? WHERE candidate_id = ? AND state = 'pending'",
            ("accepted" if outcome_id is not None else "rejected",
             None if outcome_id is None else str(outcome_id), str(command.candidate_id)),
        )
        revoked = self.service.auth._revoke_attempt_capability_families_in_transaction(context, attempt.attempt_id)
        payload = {"candidate_id": str(command.candidate_id), "attempt_id": str(attempt.attempt_id),
                   "target": _ref_value(command.target), "state": state.value,
                   "outcome_id": None if outcome_id is None else str(outcome_id),
                   "evidence_ids": list(evidence_ids), "revoked_attempt_capabilities": revoked}
        return CommandEffect(True, {"candidate_id": str(command.candidate_id), "state": state.value,
                                    "outcome_id": None if outcome_id is None else str(outcome_id),
                                    "version": version}, event, payload)


class OutcomeAcceptanceService:
    """Report candidates, then separately accept or reject under fresh authority guards."""

    def __init__(self, auth: AuthorityAuthService, *, source_observer: SourceObserver,
                 source_identity: ProviderIdentity, host: AttemptHost, host_identity: ProviderIdentity,
                 declaration_observer: DeclarationObserver | None = None,
                 declaration_identity: ProviderIdentity | None = None,
                 clock: Callable[[], datetime] | None = None,
                 max_observation_age: timedelta = timedelta(seconds=30)) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not callable(getattr(source_observer, "observe", None)):
            raise TypeError("source_observer must implement observe")
        if not callable(getattr(host, "inspect_attempt", None)):
            raise TypeError("host must implement inspect_attempt")
        if not isinstance(source_identity, ProviderIdentity) or not isinstance(host_identity, ProviderIdentity):
            raise TypeError("source_identity and host_identity must be ProviderIdentity values")
        if declaration_observer is None:
            if declaration_identity is not None:
                raise ValueError("declaration_identity requires a declaration_observer")
        elif (not callable(getattr(declaration_observer, "observe_declaration", None))
              or not isinstance(declaration_identity, ProviderIdentity)):
            raise TypeError("declaration_observer requires observe_declaration and a ProviderIdentity")
        if not isinstance(max_observation_age, timedelta) or max_observation_age <= timedelta(0):
            raise ValueError("max_observation_age must be positive")
        self.auth = auth
        self.source_observer = source_observer
        self.source_identity = source_identity
        self.host = host
        self.host_identity = host_identity
        self.declaration_observer = declaration_observer
        self.declaration_identity = declaration_identity
        self.clock = clock or auth.clock
        self.max_observation_age = max_observation_age
        auth.dispatcher.register(_ReportHandler(self))
        auth.dispatcher.register(_FinalizeHandler(self))

    def _now(self) -> datetime:
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("acceptance clock must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)

    def _require_fresh_receipt(self, receipt: Mapping[str, object], now: datetime, label: str) -> None:
        try:
            observed_at = datetime.fromisoformat(str(receipt["observed_at"])).astimezone(timezone.utc)
        except (KeyError, TypeError, ValueError) as exc:
            raise CandidateObservationMismatchError(f"{label} receipt has no valid observation time") from exc
        if observed_at > now or now - observed_at > self.max_observation_age:
            raise CandidateObservationMismatchError(f"{label} receipt is stale or from the future")

    def _preauthorize(self, authority, bearer_token, action, target, attempt):
        digest = _token_digest(bearer_token)
        actor, _ = self.auth._actor_for_token(authority, digest)
        run = assignment = None
        with authority.read_transaction() as connection:
            stored, _ = _stored_attempt(connection, authority.project, attempt)
            if stored.work_item != target:
                raise CandidateDeniedError("attempt does not match target")
            run, assignment = stored.run, stored.assignment
            requirement = AuthorizationRequirement(action, target, run, assignment, attempt)
            self.auth._authorize_capability(connection, authority.project, digest, actor, requirement)
            revision_row = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
            if revision_row is None:
                raise CandidateDeniedError("authority revision is unavailable")
            workspace = _stored_workspace(connection, authority.project, attempt)
            attempt_value, row = _stored_attempt(connection, authority.project, attempt)
        return actor, run, assignment, int(revision_row[0]), workspace, attempt_value, row

    def _provider_context(self, actor, token, action, target, capability_id, correlation):
        del token, action
        scope = json.dumps(_ref_value(target), sort_keys=True, separators=(",", ":"))
        return ProviderCallContext(
            actor.project_id, actor, EntityRef(actor.project_id, EntityKind.CAPABILITY, capability_id),
            _id("outcome-context", str(correlation)),
            _id("outcome-scope", scope),
        )

    def _observe_declarations(self, plan, target, attempt_ref, workspace, plan_revision_id,
                              actor, capability_id, correlation_prefix, now):
        if self.declaration_observer is None:
            return []
        records = []
        for reference, kind, expected_version in _declaration_specs(plan, target):
            if reference.project_id != plan.project.project_id:
                continue
            declaration = _declaration_payload(plan, reference, kind)
            if declaration is None:
                continue
            declaration_digest = _digest(_json(_plain_json_value(declaration)))
            correlation = _id("declaration-status", correlation_prefix + ":" + _declaration_key(reference, kind))
            context = self._provider_context(actor, "", ACCEPT_OUTCOME_ACTION, target, capability_id, correlation)
            request = DeclarationObservationRequest(
                context, correlation, attempt_ref, workspace.workspace_id, plan_revision_id,
                reference, kind, declaration_digest, expected_version,
            )
            try:
                result = self.declaration_observer.observe_declaration(request)
            except Exception:
                continue
            observed_now = self._now()
            receipt = result.receipt
            observation = result.value
            if (result.status is not ProviderStatus.OBSERVED_SUCCESS or result.provider != self.declaration_identity
                    or not isinstance(receipt, ProviderReceipt) or not isinstance(observation, DeclarationObservation)):
                continue
            request_digest = provider_request_digest(request)
            if (result.correlation_id != correlation or receipt.provider != self.declaration_identity
                    or receipt.correlation_id != correlation or receipt.request_digest != request_digest
                    or receipt.provenance_ref != correlation or observation.target != reference
                    or observation.declaration_kind is not kind
                    or observation.declaration_digest != declaration_digest):
                continue
            receipt_value = _source_receipt_value(receipt)
            try:
                self._require_fresh_receipt(receipt_value, observed_now, "declaration status")
            except CandidateObservationMismatchError:
                continue
            records.append({
                "kind": kind.value, "target": _ref_value(reference),
                "declaration_digest": declaration_digest.hex, "expected_version": expected_version,
                "status": observation.status.value, "observed_version": observation.observed_version,
                "correlation_id": str(correlation), "request_digest": request_digest.hex,
                "receipt": receipt_value,
            })
        return records

    def _validated_declaration_statuses(self, plan, target, records, now):
        if not isinstance(records, list):
            raise CandidateObservationMismatchError("declaration status evidence is malformed")
        specs = _declaration_specs(plan, target)
        expected = {_declaration_key(reference, kind): (reference, kind, version)
                    for reference, kind, version in specs}
        observed = {}
        for record in records:
            if not isinstance(record, dict):
                raise CandidateObservationMismatchError("declaration status record is malformed")
            try:
                kind = DeclarationKind(record["kind"])
                key = _declaration_key(EntityRef(
                    plan.project.project_id, EntityKind(
                        {DeclarationKind.CHECKPOINT: "checkpoint", DeclarationKind.INTERFACE: "interface",
                         DeclarationKind.BARRIER: "barrier", DeclarationKind.RENDEZVOUS: "barrier"}[kind]),
                    StableId(record["target"]["entity_id"]),
                    None if record["target"].get("definition_revision_id") is None
                    else StableId(record["target"]["definition_revision_id"])), kind)
            except (AttributeError, KeyError, TypeError, ValueError):
                raise CandidateObservationMismatchError("declaration status reference is malformed") from None
            spec = expected.get(key)
            if spec is None or key in observed:
                raise CandidateObservationMismatchError("declaration status is unexpected or duplicated")
            reference, expected_kind, expected_version = spec
            declaration = _declaration_payload(plan, reference, expected_kind)
            digest = _digest(_json(_plain_json_value(declaration))).hex if declaration is not None else None
            receipt = record.get("receipt")
            identity = None if self.declaration_identity is None else {
                "provider_id": str(self.declaration_identity.provider_id),
                "version": self.declaration_identity.version,
                "contract_version": self.declaration_identity.contract_version,
            }
            if (self.declaration_identity is None or record.get("target") != _ref_value(reference)
                    or record.get("kind") != expected_kind.value or record.get("declaration_digest") != digest
                    or record.get("expected_version") != expected_version or not isinstance(receipt, dict)
                    or receipt.get("provider") != identity or receipt.get("correlation_id") != record.get("correlation_id")
                    or receipt.get("request_digest") != record.get("request_digest")
                    or receipt.get("provenance_ref") != record.get("correlation_id")):
                raise CandidateObservationMismatchError("declaration status receipt does not bind the current exact declaration")
            try:
                Sha256Digest(record["declaration_digest"])
                Sha256Digest(record["request_digest"])
                StableId(record["correlation_id"])
            except (KeyError, TypeError, ValueError):
                raise CandidateObservationMismatchError("declaration receipt digests or correlation are invalid") from None
            self._require_fresh_receipt(receipt, now, "declaration status")
            try:
                status = DeclarationStatus(record["status"])
                observed_version = record.get("observed_version")
                if observed_version is not None and (not isinstance(observed_version, str) or not observed_version.strip()):
                    raise ValueError("invalid observed version")
                observation = DeclarationObservation(reference, expected_kind, Sha256Digest(digest), status,
                                                    observed_version)
            except (KeyError, TypeError, ValueError):
                raise CandidateObservationMismatchError("declaration observation fields are invalid") from None
            if expected_kind is DeclarationKind.INTERFACE and status is DeclarationStatus.SATISFIED:
                declaration_version = str(declaration.get("version", ""))
                compatibility = str(declaration.get("compatibility", ""))
                try:
                    actual_version = observed_version
                    expected_interface_version = expected_version or declaration_version
                    if actual_version is None or not _compatible_interface_version(
                        actual_version, expected_interface_version, compatibility,
                        "$/interfaces/" + str(reference.entity_id),
                    ):
                        raise ValueError("incompatible published interface version")
                except (TypeError, ValueError):
                    observation = DeclarationObservation(reference, expected_kind, Sha256Digest(digest),
                                                         DeclarationStatus.UNSATISFIED, observed_version)
            observed[key] = observation
        return observed

    def report_candidate(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef,
                         disposition: OutcomeDisposition, *, idempotency_key: StableId,
                         expected_revision: int | None = None, note: str | None = None) -> tuple[CommandResult, EntityRef]:
        if not isinstance(disposition, OutcomeDisposition) or disposition is OutcomeDisposition.SUPERSEDED:
            raise TypeError("disposition must be a reportable OutcomeDisposition")
        if note is not None and (not isinstance(note, str) or len(note) > 4096 or note != note.strip()):
            raise ValueError("note must be trimmed text of at most 4096 characters")
        if not isinstance(attempt_ref, EntityRef) or attempt_ref.kind is not EntityKind.ATTEMPT:
            raise TypeError("attempt_ref must reference an attempt")
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, attempt_ref)
        target = attempt.work_item
        candidate_id = _id("candidate", f"{attempt_ref.entity_id}:{idempotency_key}")
        actor, run, assignment, revision, workspace, attempt, row = self._preauthorize(
            authority, bearer_token, REPORT_CANDIDATE_ACTION, target, attempt_ref,
        )
        if actor != attempt.actor:
            raise CandidateDeniedError("candidate reports must be submitted by the attempt actor incarnation")
        requirement = AuthorizationRequirement(REPORT_CANDIDATE_ACTION, target, run, assignment, attempt_ref)

        def report_intent(connection, receipt_row):
            candidate = connection.execute(
                "SELECT * FROM outcome_candidates WHERE candidate_id = ?",
                (str(candidate_id),),
            ).fetchone()
            if candidate is None:
                return False
            event = json.loads(receipt_row["payload_json"]) if receipt_row["payload_json"] else {}
            return (
                receipt_row["event_kind"] == "todo.outcome.candidate_reported"
                and event.get("candidate_id") == str(candidate_id)
                and event.get("attempt_id") == str(attempt_ref.entity_id)
                and event.get("target") == _ref_value(target)
                and event.get("disposition") == disposition.value
                and candidate["attempt_id"] == str(attempt_ref.entity_id)
                and candidate["work_item_id"] == str(target.entity_id)
                and candidate["definition_revision_id"] == str(target.definition_revision_id)
                and candidate["disposition"] == disposition.value
                and candidate["note"] == note
                and candidate["reported_by_actor_id"] == str(actor.entity_id)
                and candidate["reported_by_incarnation_id"] == str(actor.incarnation_id)
            )

        replay = self.auth.replay_authorized(
            authority, bearer_token, idempotency_key, requirement,
            "todo.outcome.report_candidate", report_intent,
        )
        if replay is not None:
            return replay, EntityRef(authority.project.project_id, EntityKind.OUTCOME, candidate_id)
        now = self._now()
        if attempt.state not in {AttemptState.ADMITTED, AttemptState.ACTIVE} or attempt.lease is None or attempt.lease.expires_at <= now:
            raise CandidateStateError("candidate report requires a live admitted or active attempt")
        context = self._provider_context(actor, bearer_token, REPORT_CANDIDATE_ACTION, target,
                                         self.auth._actor_for_token(authority, _token_digest(bearer_token))[1], candidate_id)
        with authority.read_transaction() as connection:
            artifacts = _artifact_expectations(connection, attempt.attempt_id)
        request = _source_request(context, attempt_ref, target, workspace, candidate_id, artifacts)
        result = self.source_observer.observe(request)
        observed_now = self._now()
        source, receipt = _provider_source(result, request, self.source_identity, workspace, observed_now, self.max_observation_age)
        source_json = _json(_source_value(source))
        receipt_json = _json(_source_receipt_value(receipt))
        command = _Report(
            attempt_ref, target, candidate_id, disposition, note, source_json, receipt_json,
            provider_request_digest(request), self.source_identity, run, assignment, _iso(observed_now),
        )
        result = self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                   expected_revision=revision if expected_revision is None else expected_revision)
        return result, EntityRef(authority.project.project_id, EntityKind.OUTCOME, candidate_id)

    def read_candidate(self, authority: SQLiteAuthority, candidate_ref: EntityRef) -> CandidateReportView:
        if not isinstance(candidate_ref, EntityRef) or candidate_ref.kind is not EntityKind.OUTCOME:
            raise TypeError("candidate_ref must reference an outcome candidate")
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM outcome_candidates WHERE candidate_id = ?",
                (str(candidate_ref.entity_id),),
            ).fetchone()
        if row is None:
            raise CandidateNotFoundError("candidate was not found")
        source = _decode_source(row["report_source_json"])
        return CandidateReportView(
            candidate_ref,
            EntityRef(authority.project.project_id, EntityKind.ATTEMPT, StableId(row["attempt_id"])),
            EntityRef(authority.project.project_id, EntityKind.WORK_ITEM,
                      StableId(row["work_item_id"]), StableId(row["definition_revision_id"])),
            OutcomeDisposition(row["disposition"]), row["note"], row["state"],
            EntityRef(authority.project.project_id, EntityKind.ACTOR, StableId(row["reported_by_actor_id"]),
                      incarnation_id=StableId(row["reported_by_incarnation_id"])),
            Sha256Digest(str(source["source_digest"])), datetime.fromisoformat(row["reported_at"]).astimezone(timezone.utc),
        )

    def _safety(self, attempt_ref, attempt, row, workspace, now):
        observation = self.host.inspect_attempt(attempt, workspace)
        observed_now = self._now()
        try:
            checked = _check_observation(
                observation, target=attempt.work_item, attempt_ref=attempt_ref, row=row,
                workspace=workspace, now=observed_now, max_age=self.max_observation_age,
            )
        except (TypeError, ValueError, AttemptObservationMismatchError) as exc:
            raise CandidateObservationMismatchError(str(exc)) from exc
        if (checked.receipt.provider != self.host_identity or not checked.safe_to_release):
            raise CandidateDeniedError("host did not prove a fresh clean, stopped, child-free attempt")
        return checked

    def accept_candidate(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef,
                         candidate_ref: EntityRef, *, idempotency_key: StableId,
                         expected_revision: int | None = None) -> CommandResult:
        return self._finalize(authority, bearer_token, attempt_ref, candidate_ref,
                              ACCEPT_OUTCOME_ACTION, idempotency_key, expected_revision)

    def reject_candidate(self, authority: SQLiteAuthority, bearer_token: str, attempt_ref: EntityRef,
                         candidate_ref: EntityRef, *, idempotency_key: StableId,
                         expected_revision: int | None = None) -> CommandResult:
        return self._finalize(authority, bearer_token, attempt_ref, candidate_ref,
                              REJECT_CANDIDATE_ACTION, idempotency_key, expected_revision)

    def read_outcome_applicability(self, authority: SQLiteAuthority, outcome_ref: EntityRef,
                                   *, bearer_token: str | None = None) -> OutcomeApplicabilityView:
        """Re-evaluate an immutable outcome against the latest accepted facts.

        This read does not change historical acceptance. A source/provider
        failure is reported as unavailable rather than treating the old pass
        as current.
        """
        if not isinstance(outcome_ref, EntityRef) or outcome_ref.kind is not EntityKind.OUTCOME:
            raise TypeError("outcome_ref must reference an outcome")
        now = self._now()
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT o.*, p.canonical_json AS provenance_json, p.content_digest AS provenance_digest "
                "FROM outcomes AS o JOIN outcome_provenance AS p USING(outcome_id) WHERE o.outcome_id = ?",
                (str(outcome_ref.entity_id),),
            ).fetchone()
            if row is None:
                raise CandidateNotFoundError("accepted outcome was not found")
            if _digest(row["provenance_json"]).hex != row["provenance_digest"]:
                return OutcomeApplicabilityView(outcome_ref, "unavailable", ("outcome provenance digest is invalid",), now, None, None)
            provenance = json.loads(row["provenance_json"])
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM,
                               StableId(row["work_item_id"]), StableId(row["definition_revision_id"]))
            attempt_ref = EntityRef(authority.project.project_id, EntityKind.ATTEMPT, StableId(row["attempt_id"]))
            attempt, _ = _stored_attempt(connection, authority.project, attempt_ref)
            workspace = _stored_workspace(connection, authority.project, attempt_ref)
            try:
                current_revision, plan = _fresh_plan(connection, authority.project, target)
            except CandidateDeniedError:
                return OutcomeApplicabilityView(outcome_ref, "stale", ("exact work definition is no longer in the accepted plan",), now, None, None)
            artifacts = _artifact_expectations(connection, attempt.attempt_id)
            evidence_rows = connection.execute(
                "SELECT e.evidence_id FROM outcome_evidence AS oe JOIN evidence AS e USING(evidence_id) "
                "WHERE oe.outcome_id = ? ORDER BY e.evidence_id", (str(outcome_ref.entity_id),),
            ).fetchall()
        if bearer_token is None:
            return OutcomeApplicabilityView(
                outcome_ref, "unavailable", ("a current todo.outcome.read capability is required for fresh provider observations",),
                now, current_revision, None,
            )
        actor, _run, _assignment, _semantic_revision, workspace, attempt, attempt_row = self._preauthorize(
            authority, bearer_token, READ_OUTCOME_ACTION, target, attempt_ref,
        )
        capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))[1]
        correlation = _id("outcome-applicability", str(outcome_ref.entity_id) + ":" + _iso(now))
        context = self._provider_context(actor, bearer_token, READ_OUTCOME_ACTION, target,
                                         capability_id, correlation)
        request = _source_request(context, attempt_ref, target, workspace, correlation, artifacts)
        try:
            result = self.source_observer.observe(request)
            observed_now = self._now()
            source, receipt = _provider_source(result, request, self.source_identity, workspace, observed_now,
                                               self.max_observation_age)
        except Exception as exc:
            return OutcomeApplicabilityView(outcome_ref, "unavailable", (f"fresh source observation unavailable: {type(exc).__name__}",), now, current_revision, None)
        source_value = _source_value(source)
        reasons: list[str] = []
        if source_value != provenance.get("source"):
            reasons.append("source identity, digest, working-tree state, or input contents changed")
        declaration_records = self._observe_declarations(
            plan, target, attempt_ref, workspace, current_revision, actor,
            capability_id, str(outcome_ref.entity_id), self._now(),
        )
        with authority.read_transaction() as connection:
            # Re-read plan and all evidence after the external observation so
            # a concurrent authority change cannot be hidden by the first read.
            try:
                current_revision, plan = _fresh_plan(connection, authority.project, target)
            except CandidateDeniedError:
                return OutcomeApplicabilityView(outcome_ref, "stale", ("exact work definition is no longer in the accepted plan",), now, None, source.source_digest)
            try:
                declaration_statuses = self._validated_declaration_statuses(
                    plan, target, declaration_records, self._now(),
                )
            except CandidateObservationMismatchError as exc:
                declaration_statuses = {}
                reasons.append(str(exc))
            requirement_by_ref = {req.definition.ref: req.definition for req in plan.requirements
                                  if req.definition.owner == target}
            evidence_rows = connection.execute(
                "SELECT e.*, v.state FROM outcome_evidence AS oe JOIN evidence AS e USING(evidence_id) "
                "JOIN verification_attempts AS v USING(operation_id) WHERE oe.outcome_id = ? ORDER BY e.evidence_id",
                (str(outcome_ref.entity_id),),
            ).fetchall()
            evidence_facts = {evidence["evidence_id"]: connection.execute(
                "SELECT fact_name, fact_kind, fact_version, fact_digest, artifact_id, value_json FROM evidence_facts WHERE evidence_id = ?",
                (evidence["evidence_id"],),
            ).fetchall() for evidence in evidence_rows}
            evidence_artifacts = {evidence["evidence_id"]: connection.execute(
                "SELECT a.artifact_id, a.content_digest FROM evidence_artifacts AS ea "
                "JOIN artifacts AS a USING(artifact_id) WHERE ea.evidence_id = ?",
                (evidence["evidence_id"],),
            ).fetchall() for evidence in evidence_rows}
            dependency_failures = _current_dependency_failures(
                connection, plan, target, source_value, declaration_statuses,
            )
        reasons.extend(dependency_failures)
        disposition = OutcomeDisposition(row["disposition"])
        for evidence in evidence_rows:
            if evidence["source_digest"] != source.source_digest.hex:
                reasons.append("an accepted check result is bound to a different source digest")
            requirement_ref = EntityRef(authority.project.project_id, EntityKind.REQUIREMENT,
                                        StableId(evidence["requirement_id"]),
                                        StableId(evidence["requirement_definition_revision_id"]))
            requirement = requirement_by_ref.get(requirement_ref)
            if requirement is None or requirement.verification is None:
                reasons.append("an accepted check requirement is absent from the current exact work definition")
                continue
            if evidence["contract_digest"] != _digest(_json(requirement.verification.to_mapping())).hex:
                reasons.append("an authored verification contract changed")
            expected_evidence = {(str(fact.name), fact.kind.value, fact.version) for fact in requirement.required_evidence}
            actual_rows = evidence_facts[evidence["evidence_id"]]
            actual_evidence = {(fact["fact_name"], fact["fact_kind"], fact["fact_version"]) for fact in actual_rows}
            if not expected_evidence.issubset(actual_evidence):
                reasons.append("required typed evidence facts are missing")
            passing = evidence["result"] == EvidenceResult.PASS.value and evidence["state"] == "finalized"
            valid_negative = (
                evidence["result"] == EvidenceResult.FAIL.value
                and evidence["state"] == "rejected"
                and disposition in {OutcomeDisposition.ACCEPTED_NEGATIVE, OutcomeDisposition.EVALUATED_NOT_PROMOTED}
                and _benchmark_definitively_missed(requirement, actual_rows)
            )
            if not (passing or valid_negative):
                reasons.append("an accepted check result is neither finalized passing evidence nor an authored definitive benchmark negative")
            if any(artifact["content_digest"] is None
                   or not any(fact["artifact_id"] == artifact["artifact_id"]
                              and fact["fact_digest"] == artifact["content_digest"] for fact in actual_rows)
                   for artifact in evidence_artifacts[evidence["evidence_id"]]):
                reasons.append("an accepted artifact lacks an exact digest-bound availability record")
        status = "applicable" if not reasons else "stale"
        return OutcomeApplicabilityView(outcome_ref, status, tuple(sorted(set(reasons))), now,
                                        current_revision, source.source_digest)

    def _finalize(self, authority, bearer_token, attempt_ref, candidate_ref, action, idempotency_key, expected_revision):
        if not isinstance(candidate_ref, EntityRef) or candidate_ref.kind is not EntityKind.OUTCOME:
            raise TypeError("candidate_ref must reference an outcome candidate")
        with authority.read_transaction() as connection:
            row = connection.execute(
                "SELECT c.*, a.run_id, a.assignment_id, a.actor_id, a.actor_incarnation_id "
                "FROM outcome_candidates AS c JOIN attempts AS a USING(attempt_id) WHERE c.candidate_id = ? AND c.attempt_id = ?",
                (str(candidate_ref.entity_id), str(attempt_ref.entity_id)),
            ).fetchone()
            if row is None:
                raise CandidateNotFoundError("candidate does not belong to attempt")
            target = EntityRef(authority.project.project_id, EntityKind.WORK_ITEM,
                               StableId(row["work_item_id"]), StableId(row["definition_revision_id"]))
            attempt, attempt_row = _stored_attempt(connection, authority.project, attempt_ref)
            workspace = _stored_workspace(connection, authority.project, attempt_ref)
            artifacts = _artifact_expectations(connection, attempt.attempt_id)
            plan_revision, plan = _fresh_plan(connection, authority.project, target)
            manual_requirements = _manual_requirements_for_acceptance(
                connection, plan, target, attempt.attempt_id, _decode_source(row["report_source_json"]),
            ) if action == ACCEPT_OUTCOME_ACTION else ()
        actor, run, assignment, revision, workspace, attempt, attempt_row = self._preauthorize(
            authority, bearer_token, action, target, attempt_ref,
        )
        capability_id = self.auth._actor_for_token(authority, _token_digest(bearer_token))[1]

        def finalization_intent(connection, receipt_row):
            candidate = connection.execute(
                "SELECT * FROM outcome_candidates WHERE candidate_id = ? AND attempt_id = ?",
                (str(candidate_ref.entity_id), str(attempt_ref.entity_id)),
            ).fetchone()
            if candidate is None:
                return False
            event = json.loads(receipt_row["payload_json"]) if receipt_row["payload_json"] else {}
            expected_state = "accepted" if action == ACCEPT_OUTCOME_ACTION else "rejected"
            return (
                receipt_row["event_kind"] == ("todo.outcome.accepted" if action == ACCEPT_OUTCOME_ACTION
                                              else "todo.outcome.candidate_rejected")
                and event.get("candidate_id") == str(candidate_ref.entity_id)
                and event.get("attempt_id") == str(attempt_ref.entity_id)
                and event.get("target") == _ref_value(target)
                and event.get("state") == (AttemptState.ACCEPTED.value if action == ACCEPT_OUTCOME_ACTION
                                            else AttemptState.REJECTED.value)
                and candidate["work_item_id"] == str(target.entity_id)
                and candidate["definition_revision_id"] == str(target.definition_revision_id)
                and candidate["state"] == expected_state
                and ((action == ACCEPT_OUTCOME_ACTION and candidate["outcome_id"] == event.get("outcome_id"))
                     or (action != ACCEPT_OUTCOME_ACTION and candidate["outcome_id"] is None))
            )

        replay = self.auth.replay_authorized(
            authority, bearer_token, idempotency_key,
            AuthorizationRequirement(action, target, run, assignment, attempt_ref,
                                     tuple(sorted({MANUAL_OWNER_ACTIONS[req.verification.config["approver_role"]]
                                                   for req in manual_requirements}, key=str))),
            "todo.outcome.finalize_candidate", finalization_intent,
        )
        if replay is not None:
            return replay
        now = self._now()
        if attempt.state is not AttemptState.REPORTED or attempt.lease is None:
            raise CandidateStateError("candidate finalization requires a reported live attempt")
        safety_observation = self._safety(attempt_ref, attempt, attempt_row, workspace, now)
        context = self._provider_context(actor, bearer_token, action, target,
                                         self.auth._actor_for_token(authority, _token_digest(bearer_token))[1],
                                         _id("candidate-final", str(candidate_ref.entity_id)))
        correlation = _id("candidate-final-source", str(candidate_ref.entity_id))
        request = _source_request(context, attempt_ref, target, workspace, correlation, artifacts)
        source_result = self.source_observer.observe(request)
        observed_now = self._now()
        if attempt.lease.expires_at <= observed_now:
            raise CandidateDeniedError("attempt lease expired while collecting source observation")
        source, receipt = _provider_source(source_result, request, self.source_identity, workspace, observed_now, self.max_observation_age)
        source_json = _json(_source_value(source))
        receipt_json = _json(_source_receipt_value(receipt))
        safety_json = _json({
            "attempt_id": str(safety_observation.attempt.entity_id), "state": safety_observation.observed_state.value,
            "lease_id": str(safety_observation.lease_id), "source": safety_observation.source.value,
            "process": safety_observation.process.value, "children": safety_observation.children.value,
            "workspace_id": str(safety_observation.workspace.workspace_id),
            "receipt": _source_receipt_value(safety_observation.receipt),
        })
        required_manual_actions = tuple(sorted({
            MANUAL_OWNER_ACTIONS[req.verification.config["approver_role"]]
            for req in manual_requirements
        }, key=str))
        declaration_records = self._observe_declarations(
            plan, target, attempt_ref, workspace, plan_revision, actor, capability_id,
            str(candidate_ref.entity_id), self._now(),
        ) if action == ACCEPT_OUTCOME_ACTION else []
        command = _Finalize(action, attempt_ref, target, candidate_ref.entity_id, source_json, receipt_json,
                            provider_request_digest(request), safety_json, "{}", _json(declaration_records), plan_revision,
                            required_manual_actions, run, assignment, capability_id, _iso(self._now()))
        return self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                 expected_revision=revision if expected_revision is None else expected_revision)

    def _validate_and_build_outcome(self, context, command, candidate_row, attempt, plan, source, receipt, safety,
                                    declaration_statuses, writer_source_receipt, writer_declaration_records):
        disposition = OutcomeDisposition(candidate_row["disposition"])
        if disposition in {OutcomeDisposition.FAILED, OutcomeDisposition.SUPERSEDED}:
            raise CandidateDeniedError("failed or superseded candidates cannot become accepted outcomes")
        item = next((value for value in plan.work_items if value.definition.ref == command.target), None)
        if item is None:
            raise CandidateDeniedError("work definition is absent from the accepted plan")
        allowed = item.context.acceptance.get("allowed_dispositions", ())
        if disposition.value not in allowed:
            raise CandidateDeniedError("candidate disposition is not allowed by the authored acceptance policy")
        if disposition is OutcomeDisposition.NO_CHANGE:
            workspace = _stored_workspace(context._connection, context.project, command.attempt)
            if source["source_digest"] != workspace.common_base.digest:
                raise CandidateDeniedError("no_change requires the trusted source digest to equal the qualified base")
        if disposition in {OutcomeDisposition.ACCEPTED_NEGATIVE, OutcomeDisposition.EVALUATED_NOT_PROMOTED} and not any(
            req.definition.verification is not None and req.definition.verification.kind is VerificationKind.BENCHMARK
            for req in plan.requirements if req.definition.owner == command.target
        ):
            raise CandidateDeniedError(f"{disposition.value} requires an authored benchmark requirement")
        requirement_values = [req.definition for req in plan.requirements if req.definition.owner == command.target]
        selected_manual = _manual_requirements_for_acceptance(
            context._connection, plan, command.target, attempt.attempt_id,
            _decode_source(candidate_row["report_source_json"]),
            allow_benchmark_negative=disposition in {OutcomeDisposition.ACCEPTED_NEGATIVE,
                                                       OutcomeDisposition.EVALUATED_NOT_PROMOTED},
        )
        manual_actions = tuple(sorted({
            MANUAL_OWNER_ACTIONS[req.verification.config["approver_role"]]
            for req in selected_manual
        }, key=str))
        if manual_actions != command.required_manual_actions:
            raise CandidateDeniedError("manual approver roles changed while finalization was prepared")
        manual_attestations = []
        if manual_actions:
            actor_row = context._connection.execute(
                "SELECT kind FROM actors WHERE actor_id = ? AND incarnation_id = ?",
                (str(context.actor.entity_id), str(context.actor.incarnation_id)),
            ).fetchone()
            if actor_row is None or actor_row["kind"] != "human":
                raise CandidateDeniedError("manual-owner acceptance requires a registered human approver")
            for requirement in selected_manual:
                contract = requirement.verification
                if (str(contract.config["actor_id"]) != str(context.actor.entity_id)
                        or str(contract.config["incarnation_id"]) != str(context.actor.incarnation_id)):
                    raise CandidateDeniedError("manual-owner contract requires its exact authored actor incarnation")
                manual_attestations.append({
                    "requirement": _ref_value(requirement.ref),
                    "evidence": [{"name": str(fact.name), "kind": fact.kind.value, "version": fact.version}
                                 for fact in requirement.required_evidence],
                    "role": contract.config["approver_role"],
                    "authorized_action": str(MANUAL_OWNER_ACTIONS[contract.config["approver_role"]]),
                    "actor": _ref_value(context.actor),
                    "attested_at": command.at,
                })
        requirements = {req.requirement_id: req for req in requirement_values}
        check_requirements = {identifier: req for identifier, req in requirements.items()
                              if req.kind is RequirementKind.CHECK}
        groups = [group for group in item.definition.requirement_groups if group.kind is RequirementKind.CHECK]
        grouped: set[StableId] = set()
        evidence_by_requirement = {}
        all_evidence: dict[str, dict[str, object]] = {}
        for req_id, requirement in check_requirements.items():
            if any(req.requirement_id == req_id for req in selected_manual):
                evidence_by_requirement[req_id] = [None]
                continue
            rows = context._connection.execute(
                "SELECT e.*, v.state AS verification_state FROM evidence AS e "
                "JOIN verification_attempts AS v USING(operation_id) "
                "WHERE e.attempt_id = ? AND e.requirement_id = ? AND e.requirement_definition_revision_id = ? "
                "AND ((e.result = 'pass' AND v.state = 'finalized') OR (e.result = 'fail' AND v.state = 'rejected')) "
                "ORDER BY e.observed_at DESC",
                (str(attempt.attempt_id), str(req_id), str(requirement.definition_revision_id)),
            ).fetchall()
            valid = []
            for evidence in rows:
                if evidence["source_digest"] != source["source_digest"]:
                    continue
                if requirement.verification is None:
                    continue
                expected_contract = _digest(_json(requirement.verification.to_mapping())).hex
                if evidence["contract_digest"] != expected_contract:
                    continue
                facts = context._connection.execute(
                    "SELECT fact_name, fact_kind, fact_version, fact_digest, artifact_id, value_json FROM evidence_facts WHERE evidence_id = ? ORDER BY fact_name",
                    (evidence["evidence_id"],),
                ).fetchall()
                actual_facts = {(fact["fact_name"], fact["fact_kind"], fact["fact_version"]): fact["fact_digest"] for fact in facts}
                expected_facts = {(str(fact.name), fact.kind.value, fact.version) for fact in requirement.required_evidence}
                if not expected_facts.issubset(actual_facts):
                    continue
                passing = evidence["result"] == EvidenceResult.PASS.value and evidence["verification_state"] == "finalized"
                valid_negative = (
                    evidence["result"] == EvidenceResult.FAIL.value
                    and evidence["verification_state"] == "rejected"
                    and disposition in {OutcomeDisposition.ACCEPTED_NEGATIVE, OutcomeDisposition.EVALUATED_NOT_PROMOTED}
                    and _benchmark_definitively_missed(requirement, facts)
                )
                if not (passing or valid_negative):
                    continue
                input_rows = context._connection.execute(
                    "SELECT input_name, input_digest FROM evidence_inputs WHERE evidence_id = ? ORDER BY input_name",
                    (evidence["evidence_id"],),
                ).fetchall()
                current_inputs = {entry["name"]: entry["digest"] for entry in source["inputs"]}
                if any(current_inputs.get(entry["input_name"]) != entry["input_digest"] for entry in input_rows):
                    continue
                artifacts = context._connection.execute(
                    "SELECT a.artifact_id, a.provider_id, a.external_ref, a.content_digest FROM evidence_artifacts AS ea "
                    "JOIN artifacts AS a USING(artifact_id) WHERE ea.evidence_id = ? ORDER BY a.artifact_id",
                    (evidence["evidence_id"],),
                ).fetchall()
                if any(artifact["content_digest"] is None for artifact in artifacts):
                    continue
                bound_artifacts = {fact["artifact_id"]: fact["fact_digest"] for fact in facts
                                   if fact["artifact_id"] is not None}
                if any(bound_artifacts.get(artifact["artifact_id"]) != artifact["content_digest"]
                       for artifact in artifacts):
                    continue
                valid.append(evidence)
                all_evidence[evidence["evidence_id"]] = {
                    "evidence_id": evidence["evidence_id"], "requirement": _ref_value(requirement.ref),
                    "result": evidence["result"], "verification_state": evidence["verification_state"],
                    "source_digest": evidence["source_digest"], "contract_digest": evidence["contract_digest"],
                    "verifier_id": evidence["verifier_id"], "verifier_version": evidence["verifier_version"],
                    "inputs": [{"name": entry["input_name"], "digest": entry["input_digest"]} for entry in input_rows],
            "facts": [{"name": fact["fact_name"], "kind": fact["fact_kind"],
                               "version": fact["fact_version"], "digest": fact["fact_digest"],
                               "artifact_id": fact["artifact_id"],
                               "value": None if fact["value_json"] is None else json.loads(fact["value_json"])} for fact in facts],
                    "artifacts": [{"artifact_id": artifact["artifact_id"], "provider_id": artifact["provider_id"],
                                   "external_ref": artifact["external_ref"], "content_digest": artifact["content_digest"]}
                                  for artifact in artifacts],
                }
            evidence_by_requirement[req_id] = valid
        if disposition in {OutcomeDisposition.ACCEPTED_NEGATIVE, OutcomeDisposition.EVALUATED_NOT_PROMOTED} and not any(
            evidence.get("result") == EvidenceResult.FAIL.value for evidence in all_evidence.values()
        ):
            raise CandidateDeniedError(f"{disposition.value} requires definitive below-threshold benchmark evidence")
        groups_results = []
        for group in groups:
            grouped.update(group.requirement_ids)
            values = [ConditionResult(ConditionStatus.SATISFIED if evidence_by_requirement.get(ref) else ConditionStatus.UNSATISFIED,
                                     () if evidence_by_requirement.get(ref) else (ConditionCause("check_evidence_missing", str(ref), "no current passing evidence satisfies the exact authored contract"),))
                      for ref in group.requirement_ids]
            result = evaluate_results(group.mode, group.quorum, tuple(values))
            if result.status is not ConditionStatus.SATISFIED:
                raise CandidateDeniedError("authored check group is not satisfied: " + result.status.value)
            groups_results.append({"mode": group.mode.value, "requirement_ids": [str(ref) for ref in group.requirement_ids],
                                   "result": result.status.value})
        for req_id in check_requirements.keys() - grouped:
            if not evidence_by_requirement.get(req_id):
                raise CandidateDeniedError(f"ungrouped required check has no current passing evidence: {req_id}")
        required_names = set(item.context.acceptance.get("required_evidence", ()))
        fact_names = {fact["name"] for evidence in all_evidence.values() for fact in evidence["facts"]}
        fact_names.update(str(fact.name) for req in selected_manual for fact in req.required_evidence)
        if not required_names.issubset(fact_names):
            raise CandidateDeniedError("authored acceptance evidence names are not all present in passing evidence")
        # Recheck every typed prerequisite against the current accepted plan
        # and durable outcome/evidence facts under this writer transaction.
        dependencies = []
        decision_observations = {
            identifier: DecisionObservation(
                ConditionStatus.SATISFIED if payload.get("selected_option_id") is not None else ConditionStatus.UNRESOLVED,
                None if payload.get("selected_option_id") is None else str(payload["selected_option_id"]),
            )
            for identifier, payload in _declarations(plan, "decisions").items()
        }
        for group in item.definition.requirement_groups:
            if group.kind is not RequirementKind.PREREQUISITE:
                continue
            values = []
            for req_id in group.requirement_ids:
                requirement = requirements.get(req_id)
                if requirement is None or requirement.target is None:
                    raise CandidateDeniedError("prerequisite definition is unavailable")
                target = requirement.target
                ref = target.reference
                outcome_id = None
                if ref.kind is EntityKind.WORK_ITEM:
                    result, outcome_id = _accepted_work_outcome(context._connection, plan, ref)
                elif ref.kind is EntityKind.CHECKPOINT:
                    result = _declaration_result(context._connection, plan, ref, "checkpoints",
                                                 trusted_statuses=declaration_statuses)
                elif ref.kind is EntityKind.INTERFACE:
                    result = _declaration_result(context._connection, plan, ref, "interfaces",
                                                 trusted_statuses=declaration_statuses)
                elif ref.kind is EntityKind.DECISION:
                    result = _declaration_result(context._connection, plan, ref, "decisions")
                elif ref.kind is EntityKind.BARRIER:
                    result = _declaration_result(context._connection, plan, ref, "barriers",
                                                 trusted_statuses=declaration_statuses)
                else:
                    result = ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause(
                        "typed_prerequisite_unsupported", str(ref.entity_id),
                        f"current applicability does not support prerequisite kind {ref.kind.value}",
                    ),))
                values.append(result)
                dependencies.append({"requirement": _ref_value(requirement.ref), "target": _ref_value(ref),
                                     "outcome_id": outcome_id, "result": result.status.value,
                                     "causes": [{"code": cause.code, "subject": cause.subject, "message": cause.message}
                                                for cause in result.causes]})
            result = evaluate_results(group.mode, group.quorum, tuple(values))
            if result.status is not ConditionStatus.SATISFIED:
                raise CandidateDeniedError("authored prerequisite group is not satisfied")
        blocker_results = []
        for group in plan.blocking_groups:
            if group.source.reference != command.target:
                continue
            for edge in group.members:
                target = edge.target.reference
                if edge.relation is BlockerRelation.COMPLETION:
                    blocker = _accepted_work_outcome(context._connection, plan, target)[0]
                elif edge.relation is BlockerRelation.CHECKPOINT_ACCEPTED:
                    blocker = _declaration_result(context._connection, plan, target, "checkpoints",
                                                  trusted_statuses=declaration_statuses)
                elif edge.relation is BlockerRelation.INTERFACE_VERSION:
                    blocker = _declaration_result(context._connection, plan, target, "interfaces",
                                                  expected_version=edge.expected_version,
                                                  trusted_statuses=declaration_statuses)
                elif edge.relation is BlockerRelation.DECISION_RESOLVED:
                    blocker = _declaration_result(context._connection, plan, target, "decisions")
                elif edge.relation is BlockerRelation.BARRIER_RELEASED:
                    blocker = _declaration_result(context._connection, plan, target, "barriers",
                                                  trusted_statuses=declaration_statuses)
                elif edge.relation is BlockerRelation.RENDEZVOUS_MET:
                    blocker = _declaration_result(context._connection, plan, target, "rendezvous",
                                                  trusted_statuses=declaration_statuses)
                elif edge.relation is BlockerRelation.EVIDENCE_VERIFIED:
                    evidence_row = context._connection.execute(
                        "SELECT e.result, e.source_digest, v.state FROM evidence AS e "
                        "JOIN verification_attempts AS v USING(operation_id) WHERE e.evidence_id = ?",
                        (str(target.entity_id),),
                    ).fetchone()
                    passed = (evidence_row is not None and evidence_row["result"] == EvidenceResult.PASS.value
                              and evidence_row["state"] == "finalized"
                              and evidence_row["source_digest"] == source["source_digest"])
                    blocker = ConditionResult(ConditionStatus.SATISFIED if passed else ConditionStatus.UNSATISFIED,
                        () if passed else (ConditionCause("evidence_not_current", str(target.entity_id),
                            "exact evidence is absent, nonpassing, nonfinal, or bound to a different source"),))
                else:
                    blocker = ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause(
                        "unsupported_blocker_relation", str(target.entity_id), "blocker relation is unsupported",
                    ),))
                blocker_results.append(blocker)
            evaluated = evaluate_blocking_group(group, tuple(blocker_results[-len(group.members):]), decision_observations)
            if evaluated.status is not ConditionStatus.SATISFIED:
                raise CandidateDeniedError("authored dependency group is not satisfied: " + evaluated.status.value)
        evidence_ids = tuple(sorted(all_evidence))
        artifact_union = sorted({artifact["artifact_id"]: artifact for evidence in all_evidence.values()
                                 for artifact in evidence["artifacts"]}.values(), key=lambda value: value["artifact_id"])
        return ({"evidence_ids": evidence_ids}, {
            "format": "todo-orchestrator.outcome-provenance", "schema_version": 1,
            "project_id": str(context.project.project_id), "candidate_id": str(command.candidate_id),
            "attempt": _ref_value(command.attempt), "work_item": _ref_value(command.target),
            "plan_revision_id": str(command.plan_revision_id), "disposition": disposition.value,
            "source": source, "source_receipt": receipt, "host_safety": safety,
            "writer_source_receipt": writer_source_receipt,
            "requirements": [all_evidence[eid]["requirement"] for eid in evidence_ids],
            "evidence": [all_evidence[eid] for eid in evidence_ids], "artifacts": artifact_union,
            "check_groups": groups_results, "dependencies": dependencies,
            "declaration_observations": writer_declaration_records,
            "manual_attestations": manual_attestations,
        })


def _fresh_plan_from_authority(authority, target):
    with authority.read_transaction() as connection:
        return _fresh_plan(connection, authority.project, target)


__all__ = [
    "ACCEPT_OUTCOME_ACTION", "CandidateDeniedError", "CandidateError", "CandidateNotFoundError",
    "CandidateObservationMismatchError", "CandidateReportView", "CandidateStateError", "OutcomeApplicabilityView",
    "MANUAL_OWNER_ACTIONS", "OutcomeAcceptanceService", "READ_OUTCOME_ACTION", "REJECT_CANDIDATE_ACTION",
    "REPORT_CANDIDATE_ACTION",
]
