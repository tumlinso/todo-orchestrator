"""Read-only, authenticated diagnosis of interrupted Todo operations.

Inspection never calls a provider's execution or reconciliation method. It
reads a stable SQLite snapshot, obtains typed host/provider observations, then
checks that the authority snapshot and presented capability are still current
before returning a recovery view.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from typing import Any

from todo_orchestrator.authority.attempts import (
    AttemptHost,
    AttemptObservationMismatchError,
    AttemptNotFoundError,
    _attempt_from_row,
    _check_observation,
    _stored_attempt,
    _stored_workspace,
)
from todo_orchestrator.authority.auth import (
    AuthenticationFailedError,
    AuthorizationRequirement,
    AuthorityAuthService,
    CapabilityDeniedError,
    RECOVERY_INSPECT_ACTION,
    _token_digest,
)
from todo_orchestrator.authority.sqlite import (
    AuthorityError,
    InvalidAuthorityError,
    SQLiteAuthority,
)
from todo_orchestrator.contracts import (
    AttemptState,
    EffectInspectionRequest,
    EntityKind,
    EntityRef,
    GitEffectDisposition,
    GitEffectObservation,
    GitEffectRequest,
    GitOperationKind,
    ProviderCallContext,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Sha256Digest,
    SourceObservation,
    SourceObservationRequest,
    StableId,
    VerificationInspection,
    VerificationInspectionState,
    WorkingTreeState,
    provider_request_digest,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation, ChildActivity, ProcessLiveness, SourceSafety, WorkspaceQualification,
)
from todo_orchestrator.providers.git.service import _intent_from as _git_intent_from
from todo_orchestrator.verification.service import _request_context as _verification_context
from todo_orchestrator.verification.service import _request_from_json as _verification_request_from_json

from todo_orchestrator.views.recovery import (
    RecoveryBlocker,
    RecoveryChild,
    RecoveryEvidence,
    RecoveryInspection,
    RecoveryIntent,
    RecoveryIntentKind,
    RecoveryOperation,
    RecoveryOperationStatus,
    RecoveryOutcomeCandidate,
    RecoveryPrecondition,
    RecoveryStatus,
)


class RecoveryInspectionError(AuthorityError):
    """Base error for the read-only recovery inspection API."""


class RecoveryNotFoundError(RecoveryInspectionError):
    """The requested attempt or external operation is not in this authority."""


class RecoveryObservationError(RecoveryInspectionError):
    """A trusted provider returned a malformed or incorrectly bound observation."""


@dataclass(frozen=True)
class _OperationRecord:
    external: dict[str, Any]
    git: dict[str, Any] | None
    verification: dict[str, Any] | None

    @property
    def operation_ref(self) -> EntityRef:
        return EntityRef(
            StableId(self.external["project_id"]), EntityKind.EXTERNAL_OPERATION,
            StableId(self.external["operation_id"]),
        )


@dataclass(frozen=True)
class _AttemptSnapshot:
    attempt: Any
    attempt_row: dict[str, Any]
    workspace: Any | None
    revision: int
    operations: tuple[_OperationRecord, ...]
    children: tuple[RecoveryChild, ...]
    evidence: tuple[RecoveryEvidence, ...]
    outcome_candidates: tuple[RecoveryOutcomeCandidate, ...]
    signature: str


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _now(clock) -> datetime:
    result = clock()
    if not isinstance(result, datetime) or result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("recovery clock must return a timezone-aware datetime")
    return result.astimezone(timezone.utc)


def _stable_id(prefix: str, *parts: object) -> StableId:
    material = json.dumps([str(part) for part in parts], ensure_ascii=True, separators=(",", ":"))
    return StableId(prefix + "-" + hashlib.sha256(material.encode("ascii")).hexdigest())


def _snapshot_signature(parts: object) -> str:
    encoded = json.dumps(parts, ensure_ascii=True, allow_nan=False, sort_keys=True,
                         separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _is_git_oid(value: str) -> bool:
    return len(value) in {40, 64} and all(char in "0123456789abcdef" for char in value)


def _dict_rows(connection: sqlite3.Connection, sql: str, args: tuple[object, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(sql, args).fetchall()]


def _operation_rows(connection: sqlite3.Connection, project_id: StableId,
                    *, attempt_id: StableId | None = None,
                    operation_id: StableId | None = None) -> tuple[_OperationRecord, ...]:
    if (attempt_id is None) == (operation_id is None):
        raise ValueError("select operations by exactly one attempt or operation ID")
    if operation_id is not None:
        external = connection.execute(
            "SELECT * FROM external_operations WHERE operation_id = ?", (str(operation_id),)
        ).fetchall()
    else:
        external = connection.execute(
            "SELECT * FROM external_operations WHERE attempt_id = ? ORDER BY operation_id",
            (str(attempt_id),),
        ).fetchall()
    records: list[_OperationRecord] = []
    for row in external:
        external_value = dict(row)
        external_value["project_id"] = str(project_id)
        op_id = row["operation_id"]
        git_row = connection.execute(
            "SELECT * FROM git_effect_operations WHERE operation_id = ?", (op_id,)
        ).fetchone()
        verification_row = connection.execute(
            "SELECT * FROM verification_attempts WHERE operation_id = ?", (op_id,)
        ).fetchone()
        records.append(_OperationRecord(
            external_value,
            None if git_row is None else dict(git_row),
            None if verification_row is None else dict(verification_row),
        ))
    return tuple(records)


def _children(connection: sqlite3.Connection, attempt_id: StableId, project_id: StableId) -> tuple[RecoveryChild, ...]:
    rows = connection.execute(
        "SELECT e.execution_id, e.state, c.candidate_id, r.review_id "
        "FROM child_executions AS e LEFT JOIN child_candidates AS c USING(execution_id) "
        "LEFT JOIN child_candidate_reviews AS r USING(candidate_id) "
        "WHERE e.parent_attempt_id = ? ORDER BY e.logical_id, e.ordinal",
        (str(attempt_id),),
    ).fetchall()
    return tuple(RecoveryChild(
        StableId(row["execution_id"]),
        row["state"], row["candidate_id"] is not None and row["review_id"] is None,
    ) for row in rows)


def _native_children_safe(children: tuple[RecoveryChild, ...]) -> bool:
    """Keep Todo's durable child occupancy authoritative over host summaries."""
    return all(child.state == "stopped" and not child.candidate_pending_review for child in children)


def _pending_candidates(snapshot: _AttemptSnapshot | None) -> tuple[RecoveryOutcomeCandidate, ...]:
    if snapshot is None:
        return ()
    return tuple(candidate for candidate in snapshot.outcome_candidates if candidate.state == "pending")


def _block_pending_candidate_recovery(snapshot: _AttemptSnapshot,
                                      operation: RecoveryOperation) -> RecoveryOperation:
    unresolved_report = (snapshot.attempt.state is AttemptState.REPORTED
                         or bool(_pending_candidates(snapshot)))
    if unresolved_report and operation.status in {
        RecoveryOperationStatus.SAFELY_RETRYABLE, RecoveryOperationStatus.EFFECT_OBSERVED,
    }:
        return RecoveryInspectionService._uncertain_operation(
            operation, "outcome_candidate_pending_review" if _pending_candidates(snapshot)
            else "reported_attempt_unresolved",
        )
    return operation


def _evidence(connection: sqlite3.Connection, attempt_id: StableId, project_id: StableId) -> tuple[RecoveryEvidence, ...]:
    rows = connection.execute(
        "SELECT evidence_id, requirement_id, requirement_definition_revision_id, operation_id, result, "
        "verifier_id, verifier_version, contract_digest, source_digest, observed_at "
        "FROM evidence WHERE attempt_id = ? ORDER BY observed_at, evidence_id",
        (str(attempt_id),),
    ).fetchall()
    return tuple(RecoveryEvidence(
        EntityRef(project_id, EntityKind.EVIDENCE, StableId(row["evidence_id"])),
        row["result"], StableId(row["verifier_id"]), row["verifier_version"],
        Sha256Digest(row["contract_digest"]),
        None if row["source_digest"] is None else Sha256Digest(row["source_digest"]),
        None if row["operation_id"] is None else EntityRef(
            project_id, EntityKind.EXTERNAL_OPERATION, StableId(row["operation_id"])
        ),
        None if row["requirement_id"] is None else EntityRef(
            project_id, EntityKind.REQUIREMENT, StableId(row["requirement_id"]),
            definition_revision_id=StableId(row["requirement_definition_revision_id"]),
        ),
        datetime.fromisoformat(row["observed_at"]).astimezone(timezone.utc),
    ) for row in rows)


def _outcome_candidates(connection: sqlite3.Connection, attempt_id: StableId,
                        project_id: StableId) -> tuple[RecoveryOutcomeCandidate, ...]:
    rows = connection.execute(
        "SELECT candidate_id, work_item_id, definition_revision_id, disposition, state, reported_at, outcome_id "
        "FROM outcome_candidates WHERE attempt_id = ? ORDER BY reported_at, candidate_id",
        (str(attempt_id),),
    ).fetchall()
    return tuple(RecoveryOutcomeCandidate(
        StableId(row["candidate_id"]),
        EntityRef(project_id, EntityKind.WORK_ITEM, StableId(row["work_item_id"]),
                  definition_revision_id=StableId(row["definition_revision_id"])),
        row["disposition"], row["state"],
        datetime.fromisoformat(row["reported_at"]).astimezone(timezone.utc),
        None if row["outcome_id"] is None else EntityRef(
            project_id, EntityKind.OUTCOME, StableId(row["outcome_id"]),
        ),
    ) for row in rows)


def _load_attempt(authority: SQLiteAuthority, attempt_ref: EntityRef) -> _AttemptSnapshot:
    with authority.read_transaction() as connection:
        attempt, attempt_row = _stored_attempt(connection, authority.project, attempt_ref)
        workspace_row = connection.execute(
            "SELECT * FROM attempt_workspace_qualifications WHERE attempt_id = ?",
            (str(attempt_ref.entity_id),),
        ).fetchone()
        try:
            workspace = None if workspace_row is None else _stored_workspace(connection, authority.project, attempt_ref)
        except AttemptObservationMismatchError:
            # A damaged qualification must be reported as unavailable recovery
            # evidence, not turn an otherwise inspectable attempt into an error.
            workspace = None
        meta = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
        if meta is None:
            raise InvalidAuthorityError("authority semantic revision is missing")
        operations = _operation_rows(connection, authority.project.project_id, attempt_id=attempt_ref.entity_id)
        children = _children(connection, attempt_ref.entity_id, authority.project.project_id)
        evidence = _evidence(connection, attempt_ref.entity_id, authority.project.project_id)
        candidates = _outcome_candidates(connection, attempt_ref.entity_id, authority.project.project_id)
        row_dict = dict(attempt_row)
        linked = {
            "workspace": None if workspace_row is None else dict(workspace_row),
            "operations": [
                {"external": item.external, "git": item.git, "verification": item.verification}
                for item in operations
            ],
            "children": _dict_rows(connection,
                "SELECT e.*, c.candidate_id, c.summary, c.artifacts_json, c.artifacts_digest, "
                "c.submitted_by_actor_id, c.submitted_by_incarnation_id, c.submitted_at, "
                "r.review_id, r.decision, r.reviewer_actor_id, r.reviewer_incarnation_id, r.reviewed_at "
                "FROM child_executions e LEFT JOIN child_candidates c USING(execution_id) "
                "LEFT JOIN child_candidate_reviews r USING(candidate_id) "
                "WHERE e.parent_attempt_id = ? ORDER BY e.execution_id", (str(attempt_ref.entity_id),)),
            "evidence": _dict_rows(connection, "SELECT * FROM evidence WHERE attempt_id = ? ORDER BY evidence_id",
                                   (str(attempt_ref.entity_id),)),
            "outcomes": _dict_rows(connection, "SELECT * FROM outcomes WHERE attempt_id = ? ORDER BY outcome_id",
                                    (str(attempt_ref.entity_id),)),
            "outcome_candidates": _dict_rows(connection,
                "SELECT * FROM outcome_candidates WHERE attempt_id = ? ORDER BY candidate_id",
                (str(attempt_ref.entity_id),)),
        }
        signature = _snapshot_signature({"revision": meta[0], "attempt": row_dict, **linked})
    return _AttemptSnapshot(attempt, row_dict, workspace, int(meta[0]), operations, children, evidence,
                            candidates, signature)


def _load_operation(authority: SQLiteAuthority, operation_ref: EntityRef) -> tuple[_OperationRecord, int, str]:
    with authority.read_transaction() as connection:
        records = _operation_rows(connection, authority.project.project_id, operation_id=operation_ref.entity_id)
        meta = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
    if not records:
        raise RecoveryNotFoundError("external operation is unavailable in this authority")
    record = records[0]
    return record, int(meta[0]), _snapshot_signature({
        "revision": meta[0], "external": record.external, "git": record.git, "verification": record.verification,
    })


class RecoveryInspectionService:
    """Read-only inspection using the authority reader and injected observers.

    ``operation_inspectors`` maps ``"git"`` and ``"verification"`` to trusted
    providers that implement only their read-only ``inspect`` port. No provider
    is asked to reconcile or execute an operation.
    """

    def __init__(self, auth: AuthorityAuthService, *, host: AttemptHost,
                 operation_inspectors: Mapping[str, object] | None = None,
                 source_observer: object | None = None, clock=None,
                 max_observation_age: timedelta = timedelta(seconds=30)) -> None:
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be an AuthorityAuthService")
        if not callable(getattr(host, "inspect_attempt", None)):
            raise TypeError("host must implement inspect_attempt")
        if not isinstance(max_observation_age, timedelta) or max_observation_age <= timedelta(0):
            raise ValueError("max_observation_age must be positive")
        inspectors = dict(operation_inspectors or {})
        if any(key not in {"git", "verification"} or not callable(getattr(value, "inspect", None))
               for key, value in inspectors.items()):
            raise TypeError("operation_inspectors must map git/verification to read-only inspect providers")
        if source_observer is not None and not callable(getattr(source_observer, "observe", None)):
            raise TypeError("source_observer must implement observe")
        self.auth = auth
        self.host = host
        self.operation_inspectors = inspectors
        self.source_observer = source_observer
        self.clock = clock or auth.clock
        self.max_observation_age = max_observation_age

    @staticmethod
    def _check_authority(authority: SQLiteAuthority) -> None:
        if not isinstance(authority, SQLiteAuthority) or not authority.readonly:
            raise TypeError("recovery inspection requires an existing read-only SQLiteAuthority")

    def _authorize(self, authority: SQLiteAuthority, bearer_token: str, target: EntityRef,
                   run: EntityRef | None, assignment: EntityRef | None,
                   attempt: EntityRef | None) -> tuple[EntityRef, StableId]:
        digest = _token_digest(bearer_token)
        actor, capability_id = self.auth._actor_for_token(authority, digest)
        requirement = AuthorizationRequirement(RECOVERY_INSPECT_ACTION, target, run, assignment, attempt)
        with authority.read_transaction() as connection:
            self.auth._authorize_capability(connection, authority.project, digest, actor, requirement)
        return actor, capability_id

    @staticmethod
    def _context(actor: EntityRef, capability_id: StableId, query_id: StableId,
                 target: EntityRef) -> ProviderCallContext:
        ref = json.dumps({
            "project": str(target.project_id), "kind": target.kind.value,
            "id": str(target.entity_id), "definition": None if target.definition_revision_id is None
                else str(target.definition_revision_id),
        }, sort_keys=True, separators=(",", ":"))
        return ProviderCallContext(
            actor.project_id, actor, EntityRef(actor.project_id, EntityKind.CAPABILITY, capability_id),
            _stable_id("rctx", actor.entity_id, actor.incarnation_id, query_id),
            _stable_id("rscope", ref),
        )

    def inspect_attempt(self, authority: SQLiteAuthority, bearer_token: str,
                        attempt_ref: EntityRef) -> RecoveryInspection:
        self._check_authority(authority)
        if (not isinstance(attempt_ref, EntityRef) or attempt_ref.kind is not EntityKind.ATTEMPT
                or attempt_ref.project_id != authority.project.project_id):
            raise TypeError("attempt_ref must be a project-local attempt reference")
        snapshot = _load_attempt(authority, attempt_ref)
        actor, capability_id = self._authorize(
            authority, bearer_token, snapshot.attempt.work_item, snapshot.attempt.run,
            snapshot.attempt.assignment, attempt_ref,
        )
        now = _now(self.clock)
        host_observation, host_blockers = self._host_observation(snapshot, now)
        operation_views: list[RecoveryOperation] = []
        for record in snapshot.operations:
            operation = self._inspect_operation(
                authority, record, actor, capability_id, now,
                attempt_ref=attempt_ref, workspace=snapshot.workspace,
                host_observation=host_observation, children=snapshot.children,
            )
            operation_views.append(_block_pending_candidate_recovery(snapshot, operation))
        now = _now(self.clock)
        host_observation, host_blockers = self._refresh_host(snapshot, host_observation, host_blockers, now)
        operation_views = [self._refresh_operation(item, now) for item in operation_views]
        current_source = next((item.source_observation for item in operation_views
                               if item.source_observation is not None), None)
        current_source_receipt = next((item.source_receipt for item in operation_views
                                       if item.source_receipt is not None), None)
        same = self._still_same_attempt(authority, bearer_token, snapshot)
        return self._attempt_view(
            authority, snapshot, now, host_observation, host_blockers,
            tuple(operation_views), current_source, current_source_receipt,
            consistent=same,
        )

    def inspect_effect(self, authority: SQLiteAuthority, bearer_token: str,
                       operation_ref: EntityRef) -> RecoveryInspection:
        """Inspect one exact durable effect, including pre-attempt workspace creation."""
        self._check_authority(authority)
        if (not isinstance(operation_ref, EntityRef) or operation_ref.kind is not EntityKind.EXTERNAL_OPERATION
                or operation_ref.project_id != authority.project.project_id):
            raise TypeError("operation_ref must be a project-local external-operation reference")
        record, revision, signature = _load_operation(authority, operation_ref)
        target, run, assignment, attempt_ref, workspace_id = self._operation_context(record, authority)
        actor, capability_id = self._authorize(authority, bearer_token, target, run, assignment, attempt_ref)
        now = _now(self.clock)
        workspace = None
        host_observation = None
        attempt_snapshot = None
        attempt_load_failed = False
        blockers: list[RecoveryBlocker] = []
        if attempt_ref is not None:
            try:
                attempt_snapshot = _load_attempt(authority, attempt_ref)
                workspace = attempt_snapshot.workspace
                host_observation, host_blockers = self._host_observation(attempt_snapshot, now)
                blockers.extend(host_blockers)
            except Exception:
                attempt_load_failed = True
                blockers.append(RecoveryBlocker("attempt_state_unavailable", attempt_ref))
        operation = self._inspect_operation(
            authority, record, actor, capability_id, now,
            attempt_ref=attempt_ref, workspace=workspace, host_observation=host_observation,
            children=() if attempt_snapshot is None else attempt_snapshot.children,
        )
        stable = self._still_same_operation(authority, bearer_token, operation_ref, signature,
                                            target, run, assignment, attempt_ref)
        if attempt_snapshot is not None:
            stable = stable and self._still_same_attempt(authority, bearer_token, attempt_snapshot)
        elif attempt_ref is not None:
            stable = False
        now = _now(self.clock)
        host_observation, host_blockers = self._refresh_host(
            attempt_snapshot, host_observation, tuple(blockers), now,
        ) if attempt_snapshot is not None else (host_observation, tuple(blockers))
        blockers = list(host_blockers)
        pending_candidates = _pending_candidates(attempt_snapshot)
        if pending_candidates:
            blockers.append(RecoveryBlocker("outcome_candidate_pending_review", attempt_ref))
        elif attempt_snapshot is not None and attempt_snapshot.attempt.state is AttemptState.REPORTED:
            blockers.append(RecoveryBlocker("reported_attempt_unresolved", attempt_ref))
        operation = self._refresh_operation(operation, now)
        if attempt_snapshot is not None:
            operation = _block_pending_candidate_recovery(attempt_snapshot, operation)
        if not stable:
            blockers.append(RecoveryBlocker("authority_changed_during_inspection", operation_ref))
            operation = self._uncertain_operation(operation, "authority_changed_during_inspection")
        blockers.extend(operation.blockers)
        status = self._status_for_effect(operation, host_observation)
        if pending_candidates or (attempt_snapshot is not None
                                  and attempt_snapshot.attempt.state is AttemptState.REPORTED):
            status = RecoveryStatus.UNCERTAIN
        preconditions = (
            RecoveryPrecondition("authority_revision_unchanged", stable, operation_ref),
            RecoveryPrecondition("exact_effect_identity_valid", operation.status is not RecoveryOperationStatus.IRRECOVERABLE,
                                 operation_ref),
        )
        intents: tuple[RecoveryIntent, ...] = ()
        reported_unresolved = (attempt_snapshot is not None
                               and attempt_snapshot.attempt.state is AttemptState.REPORTED)
        if (operation.status is RecoveryOperationStatus.SAFELY_RETRYABLE and stable
                and not pending_candidates and not reported_unresolved):
            retry_preconditions = preconditions + (
                RecoveryPrecondition("effect_proven_not_applied", True, operation_ref),
                RecoveryPrecondition("source_matches_original_request",
                                     operation.source_observation is not None, operation_ref),
            )
            intents = (RecoveryIntent(
                RecoveryIntentKind.RETRY_ORIGINAL_OPERATION, attempt_ref, target, (operation_ref,), revision,
                None if host_observation is None else host_observation.lease_id,
                None if operation.source_observation is None else operation.source_observation.source_digest,
                workspace_id, retry_preconditions,
            ),)
        elif (operation.status is RecoveryOperationStatus.EFFECT_OBSERVED and not pending_candidates
              and not reported_unresolved):
            reconcile_source = (
                operation.source_observation.source_digest
                if operation.source_observation is not None else
                host_observation.source_digest if host_observation is not None else None
            )
            if reconcile_source is not None:
                intents = (RecoveryIntent(
                RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT, attempt_ref, target, (operation_ref,), revision,
                None if host_observation is None else host_observation.lease_id,
                reconcile_source,
                workspace_id, preconditions,
                ),)
        state = "unattached"
        lease_id = lease_expires_at = lease_expired = None
        children: tuple[RecoveryChild, ...] = ()
        evidence: tuple[RecoveryEvidence, ...] = ()
        outcome_candidates: tuple[RecoveryOutcomeCandidate, ...] = ()
        if attempt_ref is not None:
            if attempt_snapshot is None and not attempt_load_failed:
                attempt_snapshot = _load_attempt(authority, attempt_ref)
            if attempt_snapshot is not None:
                state = attempt_snapshot.attempt.state.value
                children = attempt_snapshot.children
                evidence = attempt_snapshot.evidence
                outcome_candidates = attempt_snapshot.outcome_candidates
                if attempt_snapshot.attempt.lease is not None:
                    lease_id = attempt_snapshot.attempt.lease.lease_id
                    lease_expires_at = attempt_snapshot.attempt.lease.expires_at
                    lease_expired = lease_expires_at <= now
            else:
                state = "unavailable"
        return RecoveryInspection(
            attempt=attempt_ref, target=target, workspace_id=workspace_id, state=state,
            lease_id=lease_id, lease_expires_at=lease_expires_at, lease_expired=lease_expired,
            status=status, authority_revision=revision, observed_at=now,
            host_observation=host_observation, source_observation=operation.source_observation,
            source_receipt=operation.source_receipt, children=children, operations=(operation,),
            preconditions=preconditions, blockers=tuple(blockers), intents=intents, evidence=evidence,
            outcome_candidates=outcome_candidates,
        )

    def _operation_context(self, record: _OperationRecord, authority: SQLiteAuthority):
        if record.git is not None:
            try:
                request, intent = _git_intent_from(record.git["request_json"])
                if (provider_request_digest(request).hex != record.external["request_digest"]
                        or record.git["request_digest"] != record.external["request_digest"]):
                    raise ValueError("operation request digests disagree")
                if request.target is None:
                    raise ValueError("Git operation has no exact target")
                return request.target, request.run, request.assignment, request.attempt, request.workspace_id
            except Exception as exc:
                raise RecoveryObservationError("stored Git operation identity is invalid") from exc
        if record.verification is not None:
            try:
                request = _verification_request_from_json(record.verification["request_json"])
                if (provider_request_digest(request).hex != record.external["request_digest"]
                        or record.verification["request_digest"] != record.external["request_digest"]):
                    raise ValueError("verification request digests disagree")
                with authority.read_transaction() as connection:
                    attempt, _row = _stored_attempt(connection, authority.project, request.attempt)
                return (attempt.work_item, attempt.run, attempt.assignment, request.attempt, request.workspace_id)
            except Exception as exc:
                raise RecoveryObservationError("stored verification operation identity is invalid") from exc
        raise RecoveryObservationError("external operation has no supported typed inspection record")

    def _host_observation(self, snapshot: _AttemptSnapshot, now: datetime):
        attempt = snapshot.attempt
        if (attempt.lease is None and attempt.state in {
            AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED,
        }):
            return None, ()
        if attempt.lease is None or snapshot.workspace is None:
            return None, (RecoveryBlocker("host_state_not_bound_to_live_lease", attempt.ref),)
        try:
            observation = self.host.inspect_attempt(attempt, snapshot.workspace)
            observed_now = _now(self.clock)
            observation = _check_observation(
                observation, target=attempt.work_item, attempt_ref=attempt.ref,
                row=_mapping_row(snapshot.attempt_row), workspace=snapshot.workspace,
                now=observed_now, max_age=self.max_observation_age,
            )
            return observation, ()
        except Exception:
            return None, (RecoveryBlocker("host_observation_unavailable_or_mismatched", attempt.ref),)

    def _inspect_operation(self, authority: SQLiteAuthority, record: _OperationRecord,
                           actor: EntityRef, capability_id: StableId, now: datetime, *,
                           attempt_ref: EntityRef | None, workspace: Any | None,
                           host_observation: AttemptSafetyObservation | None,
                           children: tuple[RecoveryChild, ...]) -> RecoveryOperation:
        ext = record.external
        op_ref = record.operation_ref
        blockers: list[RecoveryBlocker] = []
        request = None
        original_digest = Sha256Digest(ext["request_digest"])
        target: EntityRef
        run = assignment = None
        workspace_id = None
        if record.git is not None:
            kind = "git"
            try:
                request, _intent = _git_intent_from(record.git["request_json"])
                target, run, assignment, attempt_ref = request.target, request.run, request.assignment, request.attempt
                workspace_id = request.workspace_id
                if (target is None or provider_request_digest(request) != original_digest
                        or record.git["request_digest"] != original_digest.hex
                        or request.operation_id != StableId(ext["operation_id"])
                        or request.idempotency_key != StableId(ext["idempotency_key"])
                        or (ext["attempt_id"] is not None and ext["attempt_id"] != str(attempt_ref.entity_id))):
                    raise ValueError("typed Git operation differs from its immutable authority row")
            except Exception:
                target = authority.project.ref
                blockers.append(RecoveryBlocker("git_intent_invalid", op_ref))
                return RecoveryOperation(op_ref, attempt_ref, target, workspace_id, kind,
                    ext["state"], RecoveryOperationStatus.IRRECOVERABLE, original_digest,
                    None if ext["receipt_digest"] is None else Sha256Digest(ext["receipt_digest"]), blockers=tuple(blockers))
        elif record.verification is not None:
            kind = "verification"
            try:
                request = _verification_request_from_json(record.verification["request_json"])
                with authority.read_transaction() as connection:
                    attempt, attempt_row = _stored_attempt(connection, authority.project, request.attempt)
                target = attempt.work_item
                attempt_ref = request.attempt
                workspace_id = request.workspace_id
                if (provider_request_digest(request) != original_digest
                        or record.verification["request_digest"] != original_digest.hex
                        or request.operation_id != StableId(ext["operation_id"])
                        or request.idempotency_key != StableId(ext["idempotency_key"])
                        or ext["attempt_id"] != str(attempt_ref.entity_id)
                        or record.verification["attempt_id"] != str(attempt_ref.entity_id)
                        or record.verification["work_item_id"] != str(target.entity_id)
                        or record.verification["definition_revision_id"] != str(target.definition_revision_id)
                        or record.verification["requirement_id"] != str(request.requirement.entity_id)
                        or record.verification["requirement_definition_revision_id"] != str(
                            request.requirement.definition_revision_id)):
                    raise ValueError("typed verification operation differs from its immutable authority row")
                run, assignment = attempt.run, attempt.assignment
            except Exception:
                target = authority.project.ref
                blockers.append(RecoveryBlocker("verification_intent_invalid", op_ref))
                return RecoveryOperation(op_ref, attempt_ref, target, workspace_id, kind,
                    ext["state"], RecoveryOperationStatus.IRRECOVERABLE, original_digest,
                    None if ext["receipt_digest"] is None else Sha256Digest(ext["receipt_digest"]), blockers=tuple(blockers))
        else:
            target = authority.project.ref
            blockers.append(RecoveryBlocker("unsupported_external_operation_kind", op_ref))
            return RecoveryOperation(op_ref, attempt_ref, target, workspace_id, str(ext["kind"]),
                ext["state"], RecoveryOperationStatus.UNCERTAIN, original_digest,
                None if ext["receipt_digest"] is None else Sha256Digest(ext["receipt_digest"]), blockers=tuple(blockers))

        inner_state = record.git["state"] if record.git is not None else record.verification["state"]
        if ext["state"] == "finalized" or inner_state in {"finalized", "stale", "rejected", "failed"}:
            consistent_terminal = (
                (inner_state in {"finalized", "stale"} and ext["state"] == "finalized")
                or (inner_state in {"rejected", "failed"} and ext["state"] == "failed")
            )
            status = (RecoveryOperationStatus.COMPLETE if consistent_terminal
                      and inner_state in {"finalized", "stale"}
                      else RecoveryOperationStatus.IRRECOVERABLE)
            if status is RecoveryOperationStatus.IRRECOVERABLE:
                blockers.append(RecoveryBlocker("operation_failed_or_rejected", op_ref))
            return self._operation_view(record, attempt_ref, target, workspace_id, kind, status,
                                        original_digest, blockers=tuple(blockers))
        if ext["state"] == "prepared" or inner_state == "prepared":
            return self._operation_view(record, attempt_ref, target, workspace_id, kind,
                                        RecoveryOperationStatus.PREPARED, original_digest,
                                        blockers=(RecoveryBlocker("effect_has_not_started", op_ref),))

        provider = self.operation_inspectors.get(kind)
        if provider is None:
            blockers.append(RecoveryBlocker("provider_inspection_unavailable", op_ref))
            return self._operation_view(record, attempt_ref, target, workspace_id, kind,
                                        RecoveryOperationStatus.UNCERTAIN, original_digest,
                                        blockers=tuple(blockers))
        query_id = _stable_id("rquery", op_ref.entity_id, actor.entity_id, actor.incarnation_id, capability_id)
        context = self._context(actor, capability_id, query_id, target)
        query = EffectInspectionRequest(
            context, StableId(ext["operation_id"]), StableId(ext["idempotency_key"]),
            original_digest, query_id,
            request if kind == "git" else None,
            request if kind == "verification" else None,
        )
        try:
            result = provider.inspect(query)
        except Exception:
            result = None
        now = _now(self.clock)
        receipt = self._valid_provider_receipt(result, provider, query, now, kind, request)
        if (receipt is None or result.status not in {
                ProviderStatus.OBSERVED_SUCCESS, ProviderStatus.OBSERVED_FAILURE,
            } or result.value is None):
            blockers.append(RecoveryBlocker("provider_observation_unavailable_or_mismatched", op_ref))
            return self._operation_view(record, attempt_ref, target, workspace_id, kind,
                                        RecoveryOperationStatus.UNCERTAIN, original_digest,
                                        inspection_receipt=None if receipt is None else receipt,
                                        blockers=tuple(blockers))

        git_observation = None
        verification_inspection = None
        source_observation = source_receipt = None
        if kind == "git" and isinstance(result.value, GitEffectObservation):
            git_observation = result.value
            if git_observation.operation_id != StableId(ext["operation_id"]):
                blockers.append(RecoveryBlocker("provider_operation_identity_mismatch", op_ref))
                status = RecoveryOperationStatus.UNCERTAIN
            elif git_observation.disposition is GitEffectDisposition.APPLIED:
                binding_ok, effect_workspace = self._git_applied_binding(
                    provider, request, git_observation, now,
                )
                if not binding_ok:
                    status = RecoveryOperationStatus.UNCERTAIN
                    blockers.append(RecoveryBlocker("git_effect_result_binding_mismatch", op_ref))
                elif request.operation is GitOperationKind.CREATE_WORKSPACE:
                    source_observation, source_receipt = self._observe_git_source(
                        authority, actor, capability_id, request, effect_workspace, provider, now,
                    )
                    if source_observation is None:
                        status = RecoveryOperationStatus.UNCERTAIN
                        blockers.append(RecoveryBlocker("workspace_source_observation_unavailable", op_ref))
                    elif source_observation.working_tree is WorkingTreeState.DIRTY:
                        status = RecoveryOperationStatus.DIRTY
                        blockers.append(RecoveryBlocker("workspace_source_dirty", op_ref))
                    elif (source_observation.source_digest != request.expected_source
                          or (request.source_commit is not None
                              and source_observation.source_revision != request.source_commit)):
                        status = RecoveryOperationStatus.UNCERTAIN
                        blockers.append(RecoveryBlocker("workspace_source_identity_mismatch", op_ref))
                    else:
                        status = RecoveryOperationStatus.EFFECT_OBSERVED
                else:
                    status = RecoveryOperationStatus.EFFECT_OBSERVED
            elif git_observation.disposition is GitEffectDisposition.NOT_APPLIED:
                if attempt_ref is None:
                    source_observation, source_receipt = self._observe_git_base(
                        actor, capability_id, request, provider, now,
                    )
                    source_matches = bool(
                        source_observation is not None
                        and source_observation.working_tree is WorkingTreeState.CLEAN
                        and source_observation.source_digest == request.expected_source
                        and source_observation.base_digest == request.expected_source
                        and request.source_commit is not None
                        and source_observation.source_revision == request.source_commit
                    )
                    host_safe = True
                else:
                    source_observation, source_receipt = self._observe_git_source(
                        authority, actor, capability_id, request, workspace, provider, now,
                    )
                    source_matches = bool(
                        source_observation is not None
                        and source_observation.working_tree is WorkingTreeState.CLEAN
                        and source_observation.source_digest == request.expected_source
                        and (request.source_commit is None
                             or source_observation.source_revision == request.source_commit)
                    )
                    host_safe = (
                        self._host_safe_for_retry(host_observation, attempt_ref, request.attempt)
                        or self._accepted_integration_fenced_for_retry(authority, request, source_observation)
                    ) and _native_children_safe(children)
                if source_matches and host_safe:
                    status = RecoveryOperationStatus.SAFELY_RETRYABLE
                elif source_observation is not None and source_observation.working_tree is WorkingTreeState.DIRTY:
                    status = RecoveryOperationStatus.DIRTY
                    blockers.append(RecoveryBlocker("git_source_dirty", op_ref))
                elif attempt_ref is None:
                    status = RecoveryOperationStatus.UNCERTAIN
                    blockers.append(RecoveryBlocker(
                        "pre_attempt_source_identity_mismatch" if source_observation is not None
                        else "pre_attempt_source_not_revalidated", op_ref,
                    ))
                else:
                    status = RecoveryOperationStatus.UNCERTAIN
                    blockers.append(RecoveryBlocker(
                        "child_activity_unresolved" if not _native_children_safe(children)
                        else "not_applied_requires_source_and_host_revalidation", op_ref,
                    ))
            elif git_observation.disposition is GitEffectDisposition.DIRTY:
                status = RecoveryOperationStatus.DIRTY
            elif git_observation.disposition in {GitEffectDisposition.CONFLICT, GitEffectDisposition.REJECTED}:
                status = RecoveryOperationStatus.IRRECOVERABLE
            else:
                status = RecoveryOperationStatus.UNCERTAIN
            if git_observation.original_receipt is not None and not self._valid_original_receipt(
                    git_observation.original_receipt, provider, request, op_ref):
                status = RecoveryOperationStatus.UNCERTAIN
                blockers.append(RecoveryBlocker("original_effect_receipt_mismatch", op_ref))
        elif kind == "verification" and isinstance(result.value, VerificationInspection):
            verification_inspection = result.value
            if verification_inspection.operation_id != StableId(ext["operation_id"]):
                status = RecoveryOperationStatus.UNCERTAIN
                blockers.append(RecoveryBlocker("provider_operation_identity_mismatch", op_ref))
            elif verification_inspection.state is VerificationInspectionState.COMPLETED:
                observation = verification_inspection.observation
                original_receipt = verification_inspection.original_receipt
                valid = self._valid_verification_completion(record.verification, request, observation,
                                                             original_receipt, provider, op_ref)
                if not valid:
                    status = RecoveryOperationStatus.UNCERTAIN
                    blockers.append(RecoveryBlocker("verification_observation_binding_mismatch", op_ref))
                else:
                    status = RecoveryOperationStatus.EFFECT_OBSERVED
            elif verification_inspection.state is VerificationInspectionState.NOT_STARTED:
                source_observation, source_receipt = self._observe_verification_source(
                    authority, provider, actor, capability_id, request, record.verification, now,
                )
                host_safe = (self._host_safe_for_retry(host_observation, attempt_ref, request.attempt)
                             and _native_children_safe(children))
                source_matches = self._source_matches_request(source_observation, request)
                if source_matches and host_safe and ext["state"] in {"not_applied", "unknown", "executing"}:
                    status = RecoveryOperationStatus.SAFELY_RETRYABLE
                elif source_observation is not None and source_observation.working_tree is WorkingTreeState.DIRTY:
                    status = RecoveryOperationStatus.DIRTY
                    blockers.append(RecoveryBlocker("verification_source_dirty", op_ref))
                else:
                    status = RecoveryOperationStatus.UNCERTAIN
                    blockers.append(RecoveryBlocker(
                        "child_activity_unresolved" if not _native_children_safe(children)
                        else "retry_preconditions_not_proven", op_ref,
                    ))
            else:
                status = RecoveryOperationStatus.UNCERTAIN
                blockers.append(RecoveryBlocker("verification_still_running", op_ref))
        else:
            status = RecoveryOperationStatus.UNCERTAIN
            blockers.append(RecoveryBlocker("provider_returned_wrong_observation_type", op_ref))
        return self._operation_view(
            record, attempt_ref, target, workspace_id, kind, status, original_digest,
            inspection_receipt=receipt, source_observation=source_observation,
            source_receipt=source_receipt, git_observation=git_observation,
            verification_inspection=verification_inspection, blockers=tuple(blockers),
        )

    def _git_applied_binding(self, provider: object, request: GitEffectRequest,
                             observation: GitEffectObservation,
                             now: datetime) -> tuple[bool, WorkspaceQualification | None]:
        """Tie a reported APPLIED result back to the exact typed Git request."""
        if observation.resulting_source is None or observation.external_ref is None:
            return False, None
        if request.operation is GitOperationKind.CREATE_WORKSPACE:
            qualify = getattr(provider, "qualify_workspace", None)
            if (not callable(qualify) or request.workspace_id is None or request.target is None
                    or observation.resulting_source != request.expected_source):
                return False, None
            correlation_id = _stable_id("rqualify", request.operation_id, now.isoformat())
            try:
                qualification = qualify(request.workspace_id, request.target, correlation_id)
            except Exception:
                return False, None
            identity = getattr(provider, "identity", None)
            valid = isinstance(qualification, WorkspaceQualification) and bool(
                qualification.workspace_id == request.workspace_id
                and qualification.destination.project_id == request.target.project_id
                and qualification.common_base.digest == request.expected_source.hex
                and (request.source_commit is None or qualification.common_base.ref == request.source_commit)
                and qualification.isolation is not None
                and qualification.isolation.head_ref == observation.external_ref
                and (request.destination_ref is None
                     or qualification.destination.ref == request.destination_ref)
                and qualification.receipt.correlation_id == correlation_id
                and qualification.receipt.provenance_ref == qualification.common_base.ref
                and (identity is None or qualification.receipt.provider == identity)
            )
            return valid, qualification if valid else None
        if request.operation is GitOperationKind.INTEGRATE:
            commit = str(observation.external_ref)
            return bool(
                request.workspace_id is not None and request.source_commit is not None
                and request.destination_ref is not None and request.expected_destination is not None
                and _is_git_oid(commit)
                and _is_git_oid(str(request.source_commit))
                and _is_git_oid(str(request.expected_destination))
            ), None
        return False, None

    def _valid_provider_receipt(self, result: object, provider: object, query: EffectInspectionRequest,
                                now: datetime, kind: str, original_request: object) -> ProviderReceipt | None:
        if not isinstance(result, ProviderResult) or result.receipt is None:
            return None
        receipt = result.receipt
        identity = getattr(provider, "identity", None)
        expected_provenance = None
        if kind == "verification":
            expected_provenance = query.operation_id
            if (getattr(original_request, "verifier_id", None) is None
                    or result.provider is None
                    or result.provider.provider_id != original_request.verifier_id
                    or result.provider.version != original_request.verifier_version):
                return None
        elif isinstance(original_request, GitEffectRequest):
            expected_provenance = (original_request.source_commit or original_request.base_ref
                                   or original_request.workspace_id)
        if (result.correlation_id != query.correlation_id or receipt.correlation_id != query.correlation_id
                or receipt.request_digest != provider_request_digest(query)
                or (identity is not None and result.provider != identity)
                or result.provider != receipt.provider
                or (expected_provenance is not None and receipt.provenance_ref != expected_provenance)):
            return None
        observed = receipt.observed_at.astimezone(timezone.utc)
        if observed > now or now - observed > self.max_observation_age:
            return None
        return receipt

    @staticmethod
    def _valid_original_receipt(receipt: ProviderReceipt, provider: object,
                                request: GitEffectRequest, operation: EntityRef) -> bool:
        return (
            receipt.correlation_id == request.operation_id
            and receipt.request_digest == provider_request_digest(request)
            and receipt.provenance_ref == (request.source_commit or request.base_ref or request.workspace_id)
            and (getattr(provider, "identity", receipt.provider) == receipt.provider)
            and operation.entity_id == request.operation_id
        )

    @staticmethod
    def _valid_verification_completion(row: dict[str, Any], request: object, observation: object,
                                       receipt: ProviderReceipt | None, provider: object,
                                       operation: EntityRef) -> bool:
        if receipt is None or observation is None:
            return False
        return (
            observation.operation_id == operation.entity_id
            and str(observation.verifier_id) == row["verifier_id"]
            and observation.verifier_version == row["verifier_version"]
            and observation.contract_digest.hex == row["contract_digest"]
            and observation.source_digest.hex == row["source_digest"]
            and tuple(sorted((str(item.name), item.digest.hex) for item in observation.inputs))
                == tuple(sorted((str(item.name), item.digest.hex) for item in request.inputs))
            and receipt.correlation_id == request.operation_id
            and receipt.request_digest == provider_request_digest(request)
            and receipt.provider.provider_id == StableId(row["verifier_id"])
            and receipt.provider.version == row["verifier_version"]
            and receipt.provenance_ref == request.operation_id
            and (getattr(provider, "identity", receipt.provider) == receipt.provider)
        )

    def _observe_verification_source(self, authority: SQLiteAuthority, verifier: object,
                                     actor: EntityRef, capability_id: StableId, request: object,
                                     row: dict[str, Any], now: datetime):
        if self.source_observer is None:
            return None, None
        try:
            with authority.read_transaction() as connection:
                attempt, _attempt_row = _stored_attempt(connection, authority.project, request.attempt)
            context = _verification_context(actor, capability_id, request.operation_id, attempt.work_item)
            query_id = _stable_id("rsource", request.operation_id, actor.entity_id, actor.incarnation_id)
            source_request = SourceObservationRequest(
                context, query_id, request.expected_source, request.attempt, request.workspace_id,
                attempt.work_item, request.contract,
            )
            result = self.source_observer.observe(source_request)
            if (not isinstance(result, ProviderResult) or result.status is not ProviderStatus.OBSERVED_SUCCESS
                    or not isinstance(result.value, SourceObservation) or result.receipt is None):
                return None, None
            stored = json.loads(row["source_receipt_json"])
            provider_value = stored["receipt"]["provider"]
            expected_provider = ProviderIdentity(
                StableId(provider_value["provider_id"]), provider_value["version"], provider_value["contract_version"]
            )
            receipt = result.receipt
            observed_now = _now(self.clock)
            if (result.provider != expected_provider or receipt.provider != expected_provider
                    or result.correlation_id != query_id or receipt.correlation_id != query_id
                    or receipt.request_digest != provider_request_digest(source_request)
                    or receipt.provenance_ref != request.workspace_id):
                return None, None
            if (receipt.observed_at > observed_now or observed_now - receipt.observed_at > self.max_observation_age
                    or result.value.repository_id != StableId(stored["source"]["repository_id"])
                    or result.value.base_digest is None
                    or result.value.base_digest.hex != stored["source"]["base_digest"]):
                return None, None
            return result.value, receipt
        except Exception:
            return None, None

    def _observe_git_source(self, authority: SQLiteAuthority, actor: EntityRef,
                            capability_id: StableId, request: GitEffectRequest,
                            workspace: Any | None, provider: object, now: datetime):
        """Reobserve the exact attempt workspace before advertising a Git retry."""
        observer = self.source_observer
        if (observer is None or request.target is None
                or request.workspace_id is None or workspace is None
                or workspace.workspace_id != request.workspace_id):
            return None, None
        try:
            query_id = _stable_id("rsource", request.operation_id, actor.entity_id,
                                  actor.incarnation_id, capability_id)
            context = self._context(actor, capability_id, query_id, request.target)
            source_request = SourceObservationRequest(
                context, query_id, request.expected_source, request.attempt,
                request.workspace_id, request.target,
            )
            result = observer.observe(source_request)
            if (not isinstance(result, ProviderResult)
                    or result.status not in {ProviderStatus.OBSERVED_SUCCESS, ProviderStatus.OBSERVED_FAILURE}
                    or not isinstance(result.value, SourceObservation) or result.receipt is None):
                return None, None
            receipt = result.receipt
            observed_now = _now(self.clock)
            expected_provider = getattr(provider, "identity", None)
            if (result.provider is None or receipt.provider != result.provider
                    or (expected_provider is not None and result.provider != expected_provider)
                    or result.correlation_id != query_id or receipt.correlation_id != query_id
                    or receipt.request_digest != provider_request_digest(source_request)
                    or receipt.provenance_ref != request.workspace_id):
                return None, None
            observed_at = receipt.observed_at.astimezone(timezone.utc)
            if observed_at > observed_now or observed_now - observed_at > self.max_observation_age:
                return None, None
            source = result.value
            if (source.repository_id != workspace.repository_id
                    or source.base_digest is None
                    or source.base_digest.hex != workspace.common_base.digest):
                return None, None
            return source, receipt
        except Exception:
            return None, None

    def _observe_git_base(self, actor: EntityRef, capability_id: StableId,
                          request: GitEffectRequest, provider: object, now: datetime):
        """Revalidate an unattached workspace operation against its exact base ref."""
        observer = self.source_observer
        if observer is None or request.base_ref is None or request.source_commit is None:
            return None, None
        try:
            query_id = _stable_id("rbase", request.operation_id, actor.entity_id,
                                  actor.incarnation_id, capability_id)
            context = self._context(actor, capability_id, query_id, request.target)
            source_request = SourceObservationRequest(
                context, query_id, request.expected_source, base_ref=request.base_ref,
            )
            result = observer.observe(source_request)
            if (not isinstance(result, ProviderResult)
                    or result.status is not ProviderStatus.OBSERVED_SUCCESS
                    or not isinstance(result.value, SourceObservation) or result.receipt is None):
                return None, None
            receipt = result.receipt
            expected_provider = getattr(provider, "identity", None)
            config = getattr(provider, "config", None)
            expected_repository_id = getattr(config, "repository_id", None)
            observed_now = _now(self.clock)
            if (expected_provider is None or expected_repository_id is None
                    or result.provider != expected_provider or receipt.provider != expected_provider
                    or result.correlation_id != query_id or receipt.correlation_id != query_id
                    or receipt.request_digest != provider_request_digest(source_request)
                    or receipt.provenance_ref != request.base_ref
                    or receipt.observed_at > observed_now
                    or observed_now - receipt.observed_at > self.max_observation_age
                    or result.value.repository_id != expected_repository_id):
                return None, None
            return result.value, receipt
        except Exception:
            return None, None

    @staticmethod
    def _source_matches_request(source: SourceObservation | None, request: object) -> bool:
        return bool(
            source is not None and source.working_tree is WorkingTreeState.CLEAN
            and source.source_digest == request.expected_source
            and tuple(sorted((str(item.name), item.digest.hex) for item in source.inputs))
                == tuple(sorted((str(item.name), item.digest.hex) for item in request.inputs))
        )

    def _accepted_integration_fenced_for_retry(
        self, authority: SQLiteAuthority, request: GitEffectRequest,
        source: SourceObservation | None,
    ) -> bool:
        """Revalidate one accepted immutable integration, without a worker lease.

        All other operation recovery retains the stopped-process requirement.
        A host's durable source fence must exactly match accepted provenance,
        and the full current source must still equal that accepted observation.
        """
        if request.operation is not GitOperationKind.INTEGRATE or source is None:
            return False
        handoff_for = getattr(self.host, "authoring_handoff_for", None)
        if not callable(handoff_for):
            return False
        try:
            from todo_orchestrator.providers.git.service import _accepted_identity, _source_value
            from todo_orchestrator.verification.acceptance import _authoring_handoff_value
            from todo_orchestrator.model import AttemptAuthoringHandoff

            with authority.read_transaction() as connection:
                provenance, _receipt, _digest = _accepted_identity(
                    connection, authority.project, request, self.operation_inspectors["git"].identity,
                )
                attempt, _row = _stored_attempt(connection, authority.project, request.attempt)
            proof = handoff_for(attempt)
            return bool(
                isinstance(proof, AttemptAuthoringHandoff)
                and proof.attempt == request.attempt
                and proof.workspace_id == request.workspace_id
                and proof.source_commit == request.source_commit
                and proof.source_digest == request.expected_source
                and _source_value(source) == provenance["source"]
                and _authoring_handoff_value(proof)
                    == provenance["host_safety"]["authoring_handoff"]
            )
        except Exception:
            return False

    @staticmethod
    def _host_safe_for_retry(observation: AttemptSafetyObservation | None,
                             attempt_ref: EntityRef, expected_attempt: EntityRef) -> bool:
        return bool(
            observation is not None and observation.attempt == attempt_ref == expected_attempt
            and observation.source is SourceSafety.CLEAN
            and observation.process is ProcessLiveness.STOPPED
            and observation.children is ChildActivity.NONE
        )

    def _operation_view(self, record: _OperationRecord, attempt: EntityRef | None,
                        target: EntityRef, workspace_id: StableId | None, kind: str,
                        status: RecoveryOperationStatus, digest: Sha256Digest, *,
                        inspection_receipt: ProviderReceipt | None = None,
                        source_observation: SourceObservation | None = None,
                        source_receipt: ProviderReceipt | None = None,
                        git_observation: GitEffectObservation | None = None,
                        verification_inspection: VerificationInspection | None = None,
                        blockers: tuple[RecoveryBlocker, ...] = ()) -> RecoveryOperation:
        ext = record.external
        return RecoveryOperation(
            record.operation_ref, attempt, target, workspace_id, kind, ext["state"], status,
            digest, None if ext["receipt_digest"] is None else Sha256Digest(ext["receipt_digest"]),
            None if verification_inspection is None else verification_inspection.state.value,
            inspection_receipt, source_observation, source_receipt, git_observation,
            verification_inspection, blockers,
        )

    def _refresh_host(self, snapshot: _AttemptSnapshot, observation: AttemptSafetyObservation | None,
                      blockers: tuple[RecoveryBlocker, ...], now: datetime):
        if observation is None or snapshot.attempt.lease is None or snapshot.workspace is None:
            return observation, blockers
        try:
            observation = _check_observation(
                observation, target=snapshot.attempt.work_item, attempt_ref=snapshot.attempt.ref,
                row=_mapping_row(snapshot.attempt_row), workspace=snapshot.workspace,
                now=now, max_age=self.max_observation_age,
            )
            return observation, blockers
        except Exception:
            return None, (*blockers, RecoveryBlocker("host_observation_stale_at_report", snapshot.attempt.ref))

    def _refresh_operation(self, operation: RecoveryOperation, now: datetime) -> RecoveryOperation:
        receipts = tuple(item for item in (operation.inspection_receipt, operation.source_receipt)
                         if item is not None)
        if any(item.observed_at.astimezone(timezone.utc) > now
               or now - item.observed_at.astimezone(timezone.utc) > self.max_observation_age
               for item in receipts):
            return self._uncertain_operation(operation, "provider_observation_stale_at_report")
        return operation

    @staticmethod
    def _uncertain_operation(operation: RecoveryOperation, code: str) -> RecoveryOperation:
        return RecoveryOperation(
            operation.operation, operation.attempt, operation.target, operation.workspace_id,
            operation.kind, operation.state, RecoveryOperationStatus.UNCERTAIN,
            operation.request_digest, operation.receipt_digest, operation.inspection_state,
            operation.inspection_receipt, operation.source_observation, operation.source_receipt,
            operation.git_observation, operation.verification_inspection,
            (*operation.blockers, RecoveryBlocker(code, operation.operation)),
        )

    def _attempt_view(self, authority: SQLiteAuthority, snapshot: _AttemptSnapshot, now: datetime,
                      host: AttemptSafetyObservation | None, host_blockers: tuple[RecoveryBlocker, ...],
                      operations: tuple[RecoveryOperation, ...], source: SourceObservation | None,
                      source_receipt: ProviderReceipt | None, *, consistent: bool) -> RecoveryInspection:
        attempt = snapshot.attempt
        blockers = list(host_blockers)
        pending_candidates = _pending_candidates(snapshot)
        if pending_candidates:
            blockers.append(RecoveryBlocker("outcome_candidate_pending_review", attempt.ref))
        elif attempt.state is AttemptState.REPORTED:
            blockers.append(RecoveryBlocker("reported_attempt_unresolved", attempt.ref))
        for operation in operations:
            blockers.extend(operation.blockers)
        if not consistent:
            blockers.append(RecoveryBlocker("authority_changed_during_inspection", attempt.ref))
            operations = tuple(self._uncertain_operation(item, "authority_changed_during_inspection")
                               for item in operations)
        lease = attempt.lease
        expired = None if lease is None else lease.expires_at <= now
        preconditions: list[RecoveryPrecondition] = [
            RecoveryPrecondition("authority_revision_unchanged", consistent, attempt.ref),
            RecoveryPrecondition("stored_workspace_binding_valid", snapshot.workspace is not None, attempt.ref),
        ]
        if host is not None:
            if host.source is SourceSafety.UNKNOWN:
                blockers.append(RecoveryBlocker("source_safety_unproven", attempt.ref))
            preconditions.extend((
                RecoveryPrecondition("source_clean", host.source is SourceSafety.CLEAN, attempt.ref),
                RecoveryPrecondition("process_stopped", host.process is ProcessLiveness.STOPPED, attempt.ref),
                RecoveryPrecondition(
                    "external_producer_quiescent",
                    host.process is ProcessLiveness.EXTERNAL_PRODUCER_QUIESCENT, attempt.ref,
                ),
                RecoveryPrecondition("no_active_children", host.children is ChildActivity.NONE, attempt.ref),
                RecoveryPrecondition("host_state_matches_exact_lease", True, attempt.ref),
            ))
        intents: list[RecoveryIntent] = []
        op_refs = tuple(item.operation for item in operations)
        all_ops_resolved = all(item.status is RecoveryOperationStatus.COMPLETE for item in operations)
        handoff = None if host is None else host.authoring_handoff
        handoff_valid = bool(
            host is not None and handoff is not None
            and host.source is SourceSafety.CLEAN
            and host.source_digest is not None
            and host.children is ChildActivity.NONE
            and handoff.request.project_id == authority.project.project_id
            and handoff.request.authority_id == authority.project.authority_id
            and handoff.request.attempt == attempt.ref
            and lease is not None and handoff.request.lease_id == lease.lease_id
            and snapshot.workspace is not None
            and handoff.request.workspace_id == snapshot.workspace.workspace_id
            and handoff.receipt.provider == snapshot.workspace.receipt.provider
            and handoff.source_digest == host.source_digest
            and (source is None or source.source_digest == handoff.source_digest)
        )
        authoring_quiescent = bool(host is not None and (host.process.quiescent or handoff_valid))
        if (expired is True and attempt.state is not AttemptState.REPORTED and not pending_candidates
                and host is not None and host.source_digest is not None and host.safe_to_release
                and authoring_quiescent and all_ops_resolved
                and not any(item.state != "stopped" or item.candidate_pending_review for item in snapshot.children)
                and consistent):
            release_preconditions = tuple(
                item for item in preconditions
                if item.code not in {"process_stopped", "external_producer_quiescent"}
            ) + (
                RecoveryPrecondition(
                    "authoring_quiescent", authoring_quiescent, attempt.ref,
                    "writer quiescent or exact scoped authoring handoff is current",
                ),
            )
            intents.append(RecoveryIntent(
                RecoveryIntentKind.RELEASE_EXPIRED_ATTEMPT, attempt.ref, attempt.work_item,
                op_refs, snapshot.revision, lease.lease_id,
                (source.source_digest if source is not None else host.source_digest),
                None if snapshot.workspace is None else snapshot.workspace.workspace_id, release_preconditions,
            ))
        dirty_handoff_operations_resolved = all(
            item.status in {RecoveryOperationStatus.COMPLETE, RecoveryOperationStatus.IRRECOVERABLE}
            for item in operations
        )
        if (expired is True and attempt.state not in {AttemptState.REPORTED, AttemptState.ACCEPTED,
                                                       AttemptState.REJECTED, AttemptState.RELEASED}
                and not pending_candidates and host is not None
                and host.source is SourceSafety.DIRTY
                and host.source_digest is not None
                and host.process.quiescent
                and host.children is ChildActivity.NONE
                and dirty_handoff_operations_resolved
                and not any(item.state != "stopped" or item.candidate_pending_review for item in snapshot.children)
                and consistent and snapshot.workspace is not None):
            handoff_preconditions = tuple(preconditions) + (
                RecoveryPrecondition("lease_expired", True, attempt.ref),
                RecoveryPrecondition("writer_stopped", host.process is ProcessLiveness.STOPPED, attempt.ref),
                RecoveryPrecondition(
                    "external_producer_quiescent",
                    host.process is ProcessLiveness.EXTERNAL_PRODUCER_QUIESCENT, attempt.ref,
                ),
                RecoveryPrecondition("writer_quiescent", host.process.quiescent, attempt.ref),
                RecoveryPrecondition("no_active_children", True, attempt.ref),
                RecoveryPrecondition("uncommitted_source_preserved", True, attempt.ref),
                RecoveryPrecondition("no_ambiguous_external_effect", True, attempt.ref),
            )
            intents.append(RecoveryIntent(
                RecoveryIntentKind.HANDOFF_DIRTY_WORKSPACE, attempt.ref, attempt.work_item,
                op_refs, snapshot.revision, lease.lease_id,
                source.source_digest if source is not None else host.source_digest,
                snapshot.workspace.workspace_id, handoff_preconditions,
            ))
        for operation in operations:
            if (operation.status is RecoveryOperationStatus.SAFELY_RETRYABLE and consistent
                    and not pending_candidates and attempt.state is not AttemptState.REPORTED):
                intents.append(RecoveryIntent(
                    RecoveryIntentKind.RETRY_ORIGINAL_OPERATION, attempt.ref, attempt.work_item,
                    (operation.operation,), snapshot.revision,
                    None if lease is None else lease.lease_id,
                    None if operation.source_observation is None else operation.source_observation.source_digest,
                    None if snapshot.workspace is None else snapshot.workspace.workspace_id,
                    tuple(preconditions) + (
                        RecoveryPrecondition("operation_not_started", True, operation.operation),
                        RecoveryPrecondition("source_matches_original_request", True, operation.operation),
                    ),
                ))
            elif (operation.status is RecoveryOperationStatus.EFFECT_OBSERVED and consistent
                  and not pending_candidates and attempt.state is not AttemptState.REPORTED):
                reconcile_source = (
                    operation.source_observation.source_digest
                    if operation.source_observation is not None else
                    source.source_digest if source is not None else
                    host.source_digest if host is not None else None
                )
                if reconcile_source is not None:
                    intents.append(RecoveryIntent(
                    RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT, attempt.ref, attempt.work_item,
                    (operation.operation,), snapshot.revision,
                    None if lease is None else lease.lease_id,
                    reconcile_source,
                    None if snapshot.workspace is None else snapshot.workspace.workspace_id,
                    tuple(preconditions) + (
                        RecoveryPrecondition("effect_receipt_matches_intent",
                            operation.inspection_receipt is not None, operation.operation),
                    ),
                    ))
        status = self._classify_attempt(attempt, lease is not None and expired is True, host,
                                        host_blockers, operations, snapshot.children, consistent,
                                        pending_candidates)
        return RecoveryInspection(
            attempt.ref, attempt.work_item,
            None if snapshot.workspace is None else snapshot.workspace.workspace_id,
            attempt.state.value, None if lease is None else lease.lease_id,
            None if lease is None else lease.expires_at, expired, status, snapshot.revision,
            now, host, source, source_receipt, snapshot.children, operations,
            tuple(preconditions), tuple(blockers), tuple(intents), snapshot.evidence,
            snapshot.outcome_candidates,
        )

    @staticmethod
    def _classify_attempt(attempt, expired: bool, host: AttemptSafetyObservation | None,
                          host_blockers: tuple[RecoveryBlocker, ...], operations: tuple[RecoveryOperation, ...],
                          children: tuple[RecoveryChild, ...], consistent: bool,
                          pending_candidates: tuple[RecoveryOutcomeCandidate, ...] = ()) -> RecoveryStatus:
        if not consistent or (host is None and attempt.lease is not None) or host_blockers:
            return RecoveryStatus.UNCERTAIN
        if any(item.status is RecoveryOperationStatus.IRRECOVERABLE for item in operations):
            return RecoveryStatus.IRRECOVERABLE
        if host is not None:
            if host.source is SourceSafety.DIRTY:
                return RecoveryStatus.DIRTY
            if host.source is SourceSafety.UNKNOWN:
                return RecoveryStatus.UNCERTAIN
            if host.process in {ProcessLiveness.LIVE, ProcessLiveness.UNKNOWN} or host.children in {
                ChildActivity.ACTIVE, ChildActivity.UNKNOWN,
            } or any(item.state != "stopped" or item.candidate_pending_review for item in children):
                return RecoveryStatus.UNKNOWN_LIVE
        if any(item.status is RecoveryOperationStatus.DIRTY for item in operations):
            return RecoveryStatus.DIRTY
        if any(item.status is RecoveryOperationStatus.UNCERTAIN for item in operations):
            return RecoveryStatus.UNCERTAIN
        if pending_candidates or attempt.state is AttemptState.REPORTED:
            return RecoveryStatus.UNCERTAIN
        if any(item.status is RecoveryOperationStatus.EFFECT_OBSERVED for item in operations):
            return RecoveryStatus.UNCERTAIN
        if any(item.status is RecoveryOperationStatus.SAFELY_RETRYABLE for item in operations):
            return RecoveryStatus.SAFELY_RETRYABLE
        if attempt.state in {AttemptState.ACCEPTED, AttemptState.REJECTED, AttemptState.RELEASED}:
            return RecoveryStatus.COMPLETE if all(
                item.status is RecoveryOperationStatus.COMPLETE for item in operations
            ) else RecoveryStatus.UNCERTAIN
        if expired:
            return RecoveryStatus.EXPIRED
        return RecoveryStatus.ACTIVE

    @staticmethod
    def _status_for_effect(operation: RecoveryOperation, host: AttemptSafetyObservation | None) -> RecoveryStatus:
        if operation.status is RecoveryOperationStatus.COMPLETE:
            return RecoveryStatus.COMPLETE
        if operation.status is RecoveryOperationStatus.DIRTY:
            return RecoveryStatus.DIRTY
        if operation.status is RecoveryOperationStatus.IRRECOVERABLE:
            return RecoveryStatus.IRRECOVERABLE
        if operation.status is RecoveryOperationStatus.SAFELY_RETRYABLE:
            return RecoveryStatus.SAFELY_RETRYABLE
        if host is not None and (not host.process.quiescent or host.children is not ChildActivity.NONE):
            return RecoveryStatus.UNKNOWN_LIVE
        return RecoveryStatus.UNCERTAIN

    def _still_same_attempt(self, authority: SQLiteAuthority, bearer_token: str,
                            snapshot: _AttemptSnapshot) -> bool:
        try:
            fresh = _load_attempt(authority, snapshot.attempt.ref)
            self._authorize(authority, bearer_token, fresh.attempt.work_item, fresh.attempt.run,
                             fresh.attempt.assignment, fresh.attempt.ref)
            return fresh.signature == snapshot.signature
        except Exception:
            return False

    def _still_same_operation(self, authority: SQLiteAuthority, bearer_token: str,
                              operation_ref: EntityRef, signature: str, target: EntityRef,
                              run: EntityRef | None, assignment: EntityRef | None,
                              attempt: EntityRef | None) -> bool:
        try:
            fresh, _revision, fresh_signature = _load_operation(authority, operation_ref)
            self._authorize(authority, bearer_token, target, run, assignment, attempt)
            return fresh_signature == signature
        except Exception:
            return False

    @staticmethod
    def _attempt_context_refs(authority: SQLiteAuthority, attempt_ref: EntityRef):
        with authority.read_transaction() as connection:
            attempt, _row = _stored_attempt(connection, authority.project, attempt_ref)
        return attempt.run, attempt.assignment

    @staticmethod
    def _attempt_state(authority: SQLiteAuthority, attempt_ref: EntityRef) -> str:
        with authority.read_transaction() as connection:
            attempt, _ = _stored_attempt(connection, authority.project, attempt_ref)
        return attempt.state.value

    def _read_operation_for_inspect(self, authority: SQLiteAuthority, bearer_token: str,
                                    operation_ref: EntityRef) -> RecoveryInspection:
        return self.inspect_effect(authority, bearer_token, operation_ref)


def _mapping_row(value: Mapping[str, Any]):
    """Small sqlite.Row-compatible adapter for the established attempt validator."""
    class Row(dict):
        def __getitem__(self, key):
            return super().__getitem__(key)
    return Row(value)


__all__ = [
    "RECOVERY_INSPECT_ACTION", "RecoveryInspectionError", "RecoveryInspectionService",
    "RecoveryNotFoundError", "RecoveryObservationError",
]
