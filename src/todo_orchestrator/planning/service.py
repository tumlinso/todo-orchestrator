"""Authenticated, atomic application of reviewed planning intent."""

from dataclasses import dataclass
from datetime import datetime
import json

from todo_orchestrator.authority.auth import AuthorityAuthService, AuthorizationRequirement
from todo_orchestrator.authority.sqlite import (
    AuthorityError, load_plan_revision_snapshot, store_plan_revision_snapshot,
)
from todo_orchestrator.contracts import (
    Attempt, AttemptState, EntityKind, EntityRef, Lease, Outcome,
    OutcomeDisposition, Sha256Digest, StableId,
)
from todo_orchestrator.model import CommandEffect

from .changes import AcceptedSnapshot, ExplicitRetirement, preview_changes
from .package import compile_plan_json
from .snapshot import (
    _adoption_from_payload, _adoption_payload, decode_accepted_plan,
    encode_accepted_snapshot, materialize_accepted_plan,
)


class PlanCommitError(AuthorityError):
    """Reviewed intent cannot be applied to the current authority."""


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _load_plan(connection, project, revision_id=None):
    if revision_id is None:
        row = connection.execute(
            "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        revision_id = StableId(row[0])
    record = load_plan_revision_snapshot(connection, project, revision_id)
    return decode_accepted_plan(record.canonical_json, project, sequence=record.sequence)


def _snapshot(connection, project):
    plan = _load_plan(connection, project)
    revision = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()[0]

    def ref(kind, entity_id, definition=None, incarnation=None):
        return EntityRef(project.project_id, kind, StableId(entity_id),
                         None if definition is None else StableId(definition),
                         None if incarnation is None else StableId(incarnation))

    attempts = []
    for row in connection.execute("SELECT * FROM attempts ORDER BY attempt_id"):
        actor = ref(EntityKind.ACTOR, row["actor_id"], incarnation=row["actor_incarnation_id"])
        lease = None if row["lease_id"] is None else Lease(
            StableId(row["lease_id"]), actor, datetime.fromisoformat(row["lease_expires_at"]))
        caps = tuple(StableId(item[0]) for item in connection.execute(
            "SELECT capability_id FROM attempt_capabilities WHERE attempt_id = ? ORDER BY capability_id", (row["attempt_id"],)))
        attempts.append(Attempt(
            StableId(row["attempt_id"]), project.project_id,
            ref(EntityKind.WORK_ITEM, row["work_item_id"], row["definition_revision_id"]),
            actor, AttemptState(row["state"]), caps,
            None if row["assignment_id"] is None else ref(EntityKind.ASSIGNMENT, row["assignment_id"]),
            None if row["run_id"] is None else ref(EntityKind.RUN, row["run_id"]), lease,
        ))
    outcomes = []
    for row in connection.execute("SELECT * FROM outcomes ORDER BY outcome_id"):
        evidence_ids = tuple(StableId(item[0]) for item in connection.execute(
            "SELECT evidence_id FROM outcome_evidence WHERE outcome_id = ? ORDER BY evidence_id", (row["outcome_id"],)))
        outcomes.append(Outcome(
            StableId(row["outcome_id"]), project.project_id,
            ref(EntityKind.WORK_ITEM, row["work_item_id"], row["definition_revision_id"]),
            row["version"], OutcomeDisposition(row["disposition"]),
            ref(EntityKind.ACTOR, row["accepted_by_actor_id"], incarnation=row["accepted_by_incarnation_id"]),
            datetime.fromisoformat(row["accepted_at"]), evidence_ids,
            None if row["attempt_id"] is None else ref(EntityKind.ATTEMPT, row["attempt_id"]),
        ))
    return AcceptedSnapshot(project.authority_id, project.project_id, revision, plan,
                            tuple(attempts), tuple(outcomes))


@dataclass(frozen=True)
class _CommitPlan:
    project_id: StableId
    authority_id: StableId
    package_json: str
    adoption_json: str
    retirements: tuple[ExplicitRetirement, ...]
    reviewed_digest: Sha256Digest
    expected_authority_revision: int
    expected_plan_revision_id: StableId | None


def _compile(command, project):
    facts = tuple(_adoption_from_payload(item) for item in json.loads(command.adoption_json))
    result = compile_plan_json(command.package_json, project, adoption_facts=facts)
    if not result.ok or result.plan is None:
        raise PlanCommitError("plan compilation failed: " + "; ".join(item.code for item in result.diagnostics))
    return result.plan


class _CommitHandler:
    kind = "planning.plan.commit"
    command_type = _CommitPlan

    def authorization_requirement(self, command):
        return AuthorizationRequirement(StableId("todo.plan.commit"),
            EntityRef(command.project_id, EntityKind.PROJECT, command.project_id))

    def canonical_payload(self, command):
        from todo_orchestrator.contracts import Project
        plan = _compile(command, Project(command.project_id, command.authority_id))
        return {
            "project_id": str(command.project_id), "authority_id": str(command.authority_id),
            "proposal_digest": plan.content_digest.hex,
            "adoptions": json.loads(command.adoption_json),
            "retirements": sorted([
                {"kind": item.reference.kind.value, "entity_id": str(item.reference.entity_id),
                 "project_id": str(item.reference.project_id),
                 "revision_id": None if item.reference.definition_revision_id is None else str(item.reference.definition_revision_id)}
                for item in command.retirements
            ], key=_canonical),
            "reviewed_digest": command.reviewed_digest.hex,
            "expected_authority_revision": command.expected_authority_revision,
            "expected_plan_revision_id": None if command.expected_plan_revision_id is None else str(command.expected_plan_revision_id),
        }

    def apply(self, context, command):
        if command.project_id != context.project.project_id or command.authority_id != context.project.authority_id:
            raise PlanCommitError("commit authority/project identity mismatch")
        snapshot = _snapshot(context.authority.connection, context.project)
        if (snapshot.authority_revision != command.expected_authority_revision
                or snapshot.accepted_revision_id != command.expected_plan_revision_id):
            raise PlanCommitError("reviewed authority or accepted-plan precondition is stale")
        proposal = _compile(command, context.project)
        changes = preview_changes(proposal, snapshot, explicit_retirements=command.retirements)
        if changes.digest != command.reviewed_digest:
            raise PlanCommitError("reviewed change digest does not match current intent and facts")
        if changes.conflicts or any(item.severity.value == "error" for item in changes.diagnostics):
            raise PlanCommitError("plan change is blocked: " + "; ".join(
                [item.code for item in changes.conflicts] + [item.code for item in changes.diagnostics]))
        if changes.is_noop:
            return CommandEffect(False, {"plan_revision_id": None if snapshot.accepted_revision_id is None else str(snapshot.accepted_revision_id),
                                         "change_digest": changes.digest.hex})
        accepted = materialize_accepted_plan(proposal, snapshot, changes)
        record = encode_accepted_snapshot(accepted, authority_id=context.project.authority_id,
                                         semantic_revision=context.starting_revision + 1,
                                         based_on_revision_id=snapshot.accepted_revision_id)
        stored = store_plan_revision_snapshot(context, record, based_on_revision_id=snapshot.accepted_revision_id)
        result = {"plan_revision_id": str(stored.plan_revision_id), "sequence": stored.sequence,
                  "change_digest": changes.digest.hex, "snapshot_digest": stored.snapshot_digest}
        return CommandEffect(True, result, "planning.plan.accepted", result)


class PlanService:
    """Compose authenticated commits with explicit read-only planning snapshots."""

    def __init__(self, auth: AuthorityAuthService):
        if not isinstance(auth, AuthorityAuthService):
            raise TypeError("auth must be AuthorityAuthService")
        self.auth = auth
        # The handler has no service state and is safe to share on this dispatcher.
        from todo_orchestrator.authority.commands import DuplicateCommandHandlerError
        try:
            auth.dispatcher.register(_CommitHandler())
        except DuplicateCommandHandlerError:
            binding = auth.dispatcher._by_type.get(_CommitPlan)
            if binding is None or type(binding.handler) is not _CommitHandler:
                raise

    def load_accepted_plan(self, authority, plan_revision_id=None):
        with authority.read_transaction() as connection:
            return _load_plan(connection, authority.project, plan_revision_id)

    def read_snapshot(self, authority):
        with authority.read_transaction() as connection:
            return _snapshot(connection, authority.project)

    def preview(self, authority, package_json, *, adoption_facts=(), explicit_retirements=()):
        result = compile_plan_json(package_json, authority.project, adoption_facts=adoption_facts)
        if not result.ok or result.plan is None:
            raise PlanCommitError("plan compilation failed: " + "; ".join(item.code for item in result.diagnostics))
        return preview_changes(result.plan, self.read_snapshot(authority), explicit_retirements=explicit_retirements)

    def commit(self, authority, bearer_token, package_json, *, reviewed_digest,
               idempotency_key, expected_authority_revision, expected_plan_revision_id,
               adoption_facts=(), explicit_retirements=()):
        if not isinstance(reviewed_digest, Sha256Digest):
            raise TypeError("reviewed_digest must be Sha256Digest")
        if type(expected_authority_revision) is not int or expected_authority_revision < 0:
            raise ValueError("expected_authority_revision must be a non-negative integer")
        if expected_plan_revision_id is not None and not isinstance(expected_plan_revision_id, StableId):
            raise TypeError("expected_plan_revision_id must be StableId or None")
        if not isinstance(explicit_retirements, tuple) or any(not isinstance(item, ExplicitRetirement) for item in explicit_retirements):
            raise TypeError("explicit_retirements must be a tuple of ExplicitRetirement values")
        if not isinstance(package_json, str):
            raise TypeError("package_json must be UTF-8 JSON text")
        adoptions = sorted((_adoption_payload(item) for item in adoption_facts), key=_canonical)
        command = _CommitPlan(authority.project.project_id, authority.project.authority_id,
            package_json, _canonical(adoptions), explicit_retirements, reviewed_digest,
            expected_authority_revision, expected_plan_revision_id)
        return self.auth.execute(authority, bearer_token, command, idempotency_key=idempotency_key,
                                 expected_revision=expected_authority_revision)


__all__ = ["PlanCommitError", "PlanService"]
