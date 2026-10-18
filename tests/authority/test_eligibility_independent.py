"""Independent adversarial checks for eligibility policy boundaries."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest

from todo_orchestrator.authority import (
    CommandDispatcher,
    EligibilityAdapter,
    EligibilityFacts,
    SQLiteAuthority,
    evaluate_eligibility,
)
from todo_orchestrator.contracts import (
    ActorKind,
    Attempt,
    AttemptState,
    Capability,
    EntityKind,
    EntityRef,
    Lease,
    Outcome,
    OutcomeDisposition,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.contracts.providers import (
    ProviderIdentity,
    ProviderReceipt,
)
from todo_orchestrator.model import (
    AttemptScopeSnapshot,
    CommandEffect,
    CommandEnvelope,
    EligibilityRequest,
    EligibilityStatus,
    QualifiedDestination,
    QualifiedSourceRevision,
    WorkspaceQualification,
)
from todo_orchestrator.planning import compile_plan, parse_plan_json


NOW = datetime(2026, 10, 18, 17, 0, tzinfo=timezone.utc)
PROJECT = Project(StableId("project-eligibility"), StableId("authority-eligibility"))
ACTION = StableId("work.execute")


def actor(actor_id: str = "worker", incarnation: str = "incarnation-1") -> EntityRef:
    return EntityRef(
        PROJECT.project_id,
        EntityKind.ACTOR,
        StableId(actor_id),
        incarnation_id=StableId(incarnation),
    )


def scope(paths=(), locks=()):
    return {
        "paths": [{"path": path, "access": access} for path, access in paths],
        "concepts": [],
        "locks": [{"name": name, "mode": mode} for name, mode in locks],
    }


def make_plan(candidate_scope=None, other_scope=None, *, ownership=None):
    candidate = {
        "id": "candidate",
        "title": "Candidate work",
        "objective": "Exercise the eligibility boundary",
        "outcome": "The boundary is evaluated",
        "scope": candidate_scope or scope(),
        "acceptance": {
            "assertions": [],
            "required_evidence": [],
            "allowed_dispositions": ["completed"],
        },
    }
    if ownership is not None:
        candidate["ownership"] = ownership
    work_items = [candidate]
    if other_scope is not None:
        work_items.append({
            "id": "other",
            "title": "Concurrent work",
            "objective": "Exercise the competing scope",
            "outcome": "The competing scope is evaluated",
            "scope": other_scope,
            "acceptance": {
                "assertions": [],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
        })
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "eligibility-fixture",
        "project": {
            "project_id": str(PROJECT.project_id),
            "authority_id": str(PROJECT.authority_id),
        },
        "work_items": work_items,
    }
    parsed = parse_plan_json(json.dumps(document))
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    compiled = compile_plan(parsed.package, PROJECT)
    if not compiled.ok:
        raise AssertionError(compiled.diagnostics)
    return compiled.plan


def capability(
    actor_ref: EntityRef,
    scope_ref: EntityRef | None = None,
    *,
    expires_at: datetime | None = None,
    capability_id: str = "capability-1",
) -> Capability:
    return Capability(
        StableId(capability_id),
        PROJECT.project_id,
        actor_ref,
        scope_ref or PROJECT.ref,
        (ACTION,),
        expires_at=expires_at,
    )


def request_for(plan, actor_ref=None, *, expected_revision=0, participants=(), target=None, scope_ref=None):
    return EligibilityRequest(
        target or plan.work_items[0].definition.ref,
        actor_ref or actor(),
        ACTION,
        expected_revision,
        participants=participants,
        scope=scope_ref,
    )


def facts_for(
    plan,
    *,
    actor_ref=None,
    registered_actors=None,
    capabilities=None,
    attempts=(),
    outcomes=None,
    workspace_qualifications=None,
    approved_participants=None,
    attempt_scope_snapshots=None,
    authority_revision=0,
):
    requester = actor_ref or actor()
    contexts = {item.definition.ref: item.context for item in plan.work_items}
    durable_scopes = {
        attempt.ref: AttemptScopeSnapshot(
            tuple((entry["path"], entry["access"]) for entry in contexts[attempt.work_item].scope["paths"]),
            tuple((entry["name"], entry["mode"])
                  for entry in contexts[attempt.work_item].scope.get("locks", ())),
        )
        for attempt in attempts
        if attempt.work_item in contexts
    }
    if attempt_scope_snapshots is not None:
        durable_scopes.update(attempt_scope_snapshots)
    return EligibilityFacts(
        project=PROJECT,
        authority_revision=authority_revision,
        evaluated_at=NOW,
        plan=plan,
        plan_matches_authority=True,
        accepted_plan_revision=True,
        registered_actors=frozenset(registered_actors or (requester,)),
        capabilities=tuple(capabilities or (capability(requester),)),
        revoked_capability_ids=frozenset(),
        runs={},
        assignments={},
        attempts=tuple(attempts),
        outcomes=outcomes or {},
        workspace_qualifications=workspace_qualifications or {},
        approved_participants=approved_participants or {},
        attempt_scope_snapshots=durable_scopes,
    )


def concurrent_attempt(plan, *, attempt_id="active-1", item_index=1, state=AttemptState.ACTIVE, lease=True):
    target = plan.work_items[item_index].definition.ref
    owner = actor(f"owner-{attempt_id}", f"inc-{attempt_id}")
    return Attempt(
        StableId(attempt_id),
        PROJECT.project_id,
        target,
        owner,
        state,
        lease=Lease(StableId(f"lease-{attempt_id}"), owner, NOW + timedelta(hours=1)) if lease else None,
    )


def workspace_qualification(
    *,
    workspace_id="workspace-a",
    project_id=None,
    repository_id="repository-a",
    base_ref="base-a",
    base_digest="1" * 64,
    destination_ref="main",
    provider_id="git-provider",
):
    project_id = project_id or PROJECT.project_id
    repository = StableId(repository_id)
    provider = ProviderIdentity(StableId(provider_id), "1")
    receipt = ProviderReceipt(
        StableId(f"receipt-{workspace_id}"),
        provider,
        StableId(f"correlation-{workspace_id}"),
        Sha256Digest("2" * 64),
        StableId(f"provenance-{workspace_id}"),
        NOW,
    )
    return WorkspaceQualification(
        StableId(workspace_id),
        repository,
        QualifiedSourceRevision(project_id, repository, StableId(base_ref), base_digest),
        QualifiedDestination(project_id, repository, StableId(destination_ref)),
        receipt,
    )


@dataclass(frozen=True)
class ChangeActorLabel:
    label: str


class ChangeActorLabelHandler:
    kind = "test.change_actor_label"
    command_type = ChangeActorLabel

    def canonical_payload(self, command):
        return {"label": command.label}

    def apply(self, context, command):
        changed = context.execute(
            "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ? AND label IS NOT ?",
            (command.label, str(context.actor.entity_id), str(context.actor.incarnation_id), command.label),
        ).rowcount == 1
        if not changed:
            return CommandEffect(False, {"label": command.label})
        return CommandEffect(
            True,
            {"label": command.label},
            "test.actor_label_changed",
            {"actor_id": str(context.actor.entity_id), "label": command.label},
        )


class IndependentEligibilityTests(unittest.TestCase):
    def evaluate(self, plan, *, request=None, facts=None):
        request = request or request_for(plan)
        facts = facts or facts_for(plan, actor_ref=request.actor)
        return evaluate_eligibility(request, facts)

    def test_segment_overlap_read_sharing_and_named_lock_conflicts(self):
        cases = (
            (
                "prefix_is_not_a_segment_overlap",
                scope((("src/pkg", "write"),)),
                scope((("src/package", "write"),)),
                EligibilityStatus.ALLOWED,
                None,
            ),
            (
                "overlapping_shared_reads",
                scope((("src/pkg", "read"),)),
                scope((("src/pkg/sub", "read"),)),
                EligibilityStatus.ALLOWED,
                None,
            ),
            (
                "overlapping_read_and_write",
                scope((("src/pkg", "read"),)),
                scope((("src/pkg/sub", "write"),)),
                EligibilityStatus.BLOCKED,
                "unsafe_source_overlap",
            ),
            (
                "shared_lock_is_compatible",
                scope(locks=(("index", "shared"),)),
                scope(locks=(("index", "shared"),)),
                EligibilityStatus.ALLOWED,
                None,
            ),
            (
                "exclusive_lock_conflicts",
                scope(locks=(("index", "shared"),)),
                scope(locks=(("index", "exclusive"),)),
                EligibilityStatus.BLOCKED,
                "named_lock_conflict",
            ),
        )
        for name, requested_scope, active_scope, status, cause_code in cases:
            with self.subTest(name=name):
                plan = make_plan(requested_scope, active_scope)
                attempt = concurrent_attempt(plan)
                result = self.evaluate(plan, facts=facts_for(plan, attempts=(attempt,)))
                self.assertEqual(result.status, status)
                if cause_code:
                    self.assertIn(cause_code, {cause.code for cause in result.causes})

        plan = make_plan(scope((("src/pkg", "write"),)), scope((("src/pkg/sub", "read"),)))
        uncertain = concurrent_attempt(plan, state=AttemptState.UNCERTAIN, lease=False)
        decision = self.evaluate(plan, facts=facts_for(plan, attempts=(uncertain,)))
        self.assertEqual(decision.status, EligibilityStatus.UNKNOWN)
        self.assertTrue(any(uncertain.ref in cause.related for cause in decision.causes))

    def test_work_item_owner_and_completion_invariants_are_enforced(self):
        requester = actor("requester", "requester-inc")
        owner = actor("owner", "owner-inc")
        plan = make_plan(ownership={
            "mode": "any",
            "actors": [{
                "project_id": str(owner.project_id),
                "kind": "actor",
                "entity_id": str(owner.entity_id),
                "incarnation_id": str(owner.incarnation_id),
            }],
        })
        request = request_for(plan, requester, participants=(requester, owner))
        facts = facts_for(plan, actor_ref=requester, registered_actors=(requester, owner))
        decision = self.evaluate(plan, request=request, facts=facts)
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("owner_acl_denied", {cause.code for cause in decision.causes})

        completed_plan = make_plan()
        completed_target = completed_plan.work_items[0].definition.ref
        accepted = Outcome(
            StableId("outcome-accepted"),
            PROJECT.project_id,
            completed_target,
            1,
            OutcomeDisposition.COMPLETED,
            actor("reviewer", "reviewer-inc"),
            NOW,
        )
        decision = self.evaluate(completed_plan, facts=facts_for(completed_plan, outcomes={completed_target: accepted}))
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertTrue(decision.causes)

    def test_capability_incarnation_expiry_and_requested_scope_are_enforced(self):
        plan = make_plan()
        target = plan.work_items[0].definition.ref
        requester = actor("worker", "new-incarnation")
        unrelated = EntityRef(PROJECT.project_id, EntityKind.ARTIFACT, StableId("unrelated-artifact"))
        request = request_for(plan, requester, scope_ref=unrelated)
        scoped = capability(request.actor, target)
        decision = self.evaluate(plan, request=request, facts=facts_for(plan, capabilities=(scoped,)))
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("capability_scope_exceeded", {cause.code for cause in decision.causes})

        old_incarnation = actor("worker", "old-incarnation")
        wrong_actor_grant = capability(old_incarnation)
        decision = self.evaluate(
            plan,
            request=request,
            facts=facts_for(plan, actor_ref=requester, capabilities=(wrong_actor_grant,)),
        )
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)

        expired_grant = capability(requester, expires_at=NOW)
        decision = self.evaluate(
            plan,
            request=request,
            facts=facts_for(plan, actor_ref=requester, capabilities=(expired_grant,)),
        )
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("capability_expired", {cause.code for cause in decision.causes})

    def test_only_exactly_qualified_distinct_workspaces_isolate_overlap(self):
        plan = make_plan(scope((("src/pkg", "write"),)), scope((("src/pkg/sub", "write"),)))
        attempt = concurrent_attempt(plan)
        candidate_ref = plan.work_items[0].definition.ref
        active_ref = attempt.ref
        candidate = workspace_qualification(workspace_id="candidate-workspace")
        active = workspace_qualification(workspace_id="active-workspace")

        def check(candidate_workspace, active_workspace, expected):
            facts = facts_for(
                plan,
                attempts=(attempt,),
                workspace_qualifications={candidate_ref: candidate_workspace, active_ref: active_workspace},
            )
            result = self.evaluate(plan, facts=facts)
            self.assertEqual(result.status, expected)

        check(candidate, active, EligibilityStatus.ALLOWED)
        mismatches = (
            workspace_qualification(workspace_id="candidate-workspace"),
            workspace_qualification(workspace_id="active-workspace", destination_ref="release"),
            workspace_qualification(workspace_id="active-workspace", base_ref="other-base"),
            workspace_qualification(workspace_id="active-workspace", repository_id="repository-b"),
            workspace_qualification(
                workspace_id="active-workspace",
                project_id=StableId("another-project"),
            ),
            workspace_qualification(workspace_id="active-workspace", provider_id="other-provider"),
        )
        for active_workspace in mismatches:
            with self.subTest(active_workspace=active_workspace.workspace_id, provider=active_workspace.receipt.provider):
                check(candidate, active_workspace, EligibilityStatus.BLOCKED)

    def test_multiple_same_kind_conflict_causes_have_stable_order(self):
        plan = make_plan()
        target = plan.work_items[0].definition.ref
        first_actor = actor("a", "inc-a")
        second_actor = actor("b", "inc-b")
        first = Attempt(
            StableId("active-a"), PROJECT.project_id, target, first_actor, AttemptState.ACTIVE,
            lease=Lease(StableId("lease-a"), first_actor, NOW + timedelta(hours=1)),
        )
        second = Attempt(
            StableId("active-b"), PROJECT.project_id, target, second_actor, AttemptState.ACTIVE,
            lease=Lease(StableId("lease-b"), second_actor, NOW + timedelta(hours=1)),
        )
        request = request_for(plan)
        forward = evaluate_eligibility(request, facts_for(plan, attempts=(first, second)))
        reverse = evaluate_eligibility(request, facts_for(plan, attempts=(second, first)))
        self.assertEqual(forward.status, EligibilityStatus.BLOCKED)
        self.assertEqual(forward, reverse)
        self.assertEqual(len([cause for cause in forward.causes if cause.code == "work_item_already_active"]), 2)

    def test_transactional_recheck_rejects_a_stale_advisory_decision(self):
        plan = make_plan()
        target = plan.work_items[0].definition.ref
        requester = actor()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eligibility.sqlite3"
            SQLiteAuthority.initialize(path, PROJECT)
            with SQLiteAuthority.open_writer(path, PROJECT) as writer:
                with writer.write_transaction() as connection:
                    connection.execute(
                        "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                        (str(requester.entity_id), str(requester.incarnation_id), ActorKind.AUTOMATION.value, "before"),
                    )
                    connection.execute(
                        "INSERT INTO plan_revisions(plan_revision_id, sequence, state, content_digest) VALUES (?, ?, ?, ?)",
                        (str(plan.revision.plan_revision_id), 1, "accepted", plan.content_digest.hex),
                    )
                    for item in plan.work_items:
                        definition = item.definition
                        connection.execute(
                            "INSERT INTO work_items(work_item_id, definition_revision_id, title, outcome) VALUES (?, ?, ?, ?)",
                            (str(definition.work_item_id), str(definition.definition_revision_id), definition.title, definition.outcome),
                        )
                        connection.execute(
                            "INSERT INTO plan_revision_work_items(plan_revision_id, work_item_id) VALUES (?, ?)",
                            (str(plan.revision.plan_revision_id), str(definition.work_item_id)),
                        )
                    connection.execute(
                        "INSERT INTO capabilities(capability_id, actor_id, actor_incarnation_id, scope_kind, scope_entity_id) "
                        "VALUES (?, ?, ?, 'project', ?)",
                        ("capability-1", str(requester.entity_id), str(requester.incarnation_id), str(PROJECT.project_id)),
                    )
                    connection.execute(
                        "INSERT INTO capability_actions(capability_id, action_ordinal, action) VALUES (?, 0, ?)",
                        ("capability-1", str(ACTION)),
                    )

            request = request_for(plan, requester, expected_revision=0)
            adapter = EligibilityAdapter(clock=lambda: NOW)
            with SQLiteAuthority.open_reader(path, PROJECT) as reader:
                advisory = adapter.evaluate_read(reader, request, plan)
            self.assertEqual(advisory.status, EligibilityStatus.ALLOWED)
            self.assertEqual(advisory.authority_revision, 0)

            dispatcher = CommandDispatcher([ChangeActorLabelHandler()])
            with SQLiteAuthority.open_writer(path, PROJECT) as writer:
                dispatcher.execute(
                    writer,
                    CommandEnvelope(ChangeActorLabel("after"), StableId("bump-authority"), 0, requester),
                )
            with SQLiteAuthority.open_writer(path, PROJECT) as writer:
                with writer.write_transaction() as connection:
                    fresh = adapter.evaluate_in_transaction(writer, connection, request, plan)
            self.assertEqual(fresh.status, EligibilityStatus.BLOCKED)
            self.assertEqual(fresh.authority_revision, 1)
            self.assertIn("stale_authority_revision", {cause.code for cause in fresh.causes})


if __name__ == "__main__":
    unittest.main()
