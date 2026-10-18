from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from todo_orchestrator.authority import (
    AuthorityAuthService,
    CommandDispatcher,
    EligibilityAdapter,
    EligibilityAdapterError,
    EligibilityFacts,
    InvalidAuthorityError,
    SQLiteAuthority,
    evaluate_eligibility,
    load_plan_revision_snapshot,
)
from todo_orchestrator.contracts import (
    Attempt,
    AttemptState,
    Capability,
    EntityKind,
    EntityRef,
    Lease,
    OutcomeDisposition,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.contracts.providers import ProviderIdentity, ProviderReceipt
from todo_orchestrator.model import (
    AttemptScopeSnapshot,
    EligibilityRequest,
    EligibilityStatus,
    QualifiedDestination,
    QualifiedSourceRevision,
    WorkspaceIsolation,
    WorkspaceQualification,
)
from todo_orchestrator.planning import (
    ConditionResult,
    ConditionStatus,
    DecisionObservation,
    compile_plan,
    parse_plan_json,
)
from tests.authority.plan_fixtures import commit_plan


NOW = datetime(2031, 4, 5, 6, 7, 8, tzinfo=timezone.utc)


def sid(value: str) -> StableId:
    return StableId(value)


def ref(project: Project, kind: EntityKind, identifier: str, *, revision: StableId | None = None,
        incarnation: StableId | None = None) -> EntityRef:
    return EntityRef(project.project_id, kind, sid(identifier), revision, incarnation)


def plan_document(*, items=None, ownership=None, requirements=None, dependencies=None):
    items = items or [
        {"id": "work-a", "paths": [{"path": "src/package", "access": "write"}], "locks": []},
        {"id": "work-b", "paths": [{"path": "docs/guide.md", "access": "write"}], "locks": []},
    ]
    work_items = []
    for item in items:
        work_items.append({
            "id": item["id"],
            "title": item.get("title", item["id"]),
            "objective": "Complete the scoped outcome",
            "outcome": "The scoped outcome is present",
            "scope": {
                "paths": item.get("paths", []),
                "concepts": [],
                "locks": item.get("locks", []),
            },
            "acceptance": {
                "assertions": ["result is verified"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
            "ownership": ownership or {"mode": "any", "actors": []},
            **({"requirement_groups": item["requirement_groups"]} if "requirement_groups" in item else {}),
        })
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "eligibility-fixture",
        "project": {"project_id": "project-a", "authority_id": "authority-a"},
        "work_items": work_items,
    }
    if requirements is not None:
        document["requirements"] = requirements
    if dependencies is not None:
        document["dependencies"] = dependencies
    return document


def compiled_plan(project: Project, **kwargs):
    document = plan_document(**kwargs)
    document["project"] = {
        "project_id": str(project.project_id),
        "authority_id": str(project.authority_id),
    }
    parsed = parse_plan_json(json.dumps(document))
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    result = compile_plan(parsed.package, project)
    if not result.ok:
        raise AssertionError(result.diagnostics)
    return result.plan


def base_facts(project: Project, plan, *, revision=0, now=NOW, actor=None, caps=None,
               registered=None, attempts=(), outcomes=None, **overrides):
    actor = actor or ref(project, EntityKind.ACTOR, "operator", incarnation=sid("inc-1"))
    registered = frozenset(registered if registered is not None else (actor,))
    attempt_scope_snapshots = {}
    for attempt in attempts:
        item = next((item for item in plan.work_items if item.definition.ref == attempt.work_item), None)
        if item is not None:
            scope = item.context.scope
            attempt_scope_snapshots[attempt.ref] = AttemptScopeSnapshot(
                tuple((entry["path"], entry["access"]) for entry in scope["paths"]),
                tuple((entry["name"], entry["mode"]) for entry in scope.get("locks", ())),
            )
    defaults = dict(
        project=project,
        authority_revision=revision,
        evaluated_at=now,
        plan=plan,
        plan_matches_authority=True,
        accepted_plan_revision=True,
        registered_actors=registered,
        capabilities=tuple(caps if caps is not None else (
            Capability(
                sid("cap-1"), project.project_id, actor, project.ref, (sid("work:execute"),)
            ),
        )),
        revoked_capability_ids=frozenset(),
        runs={},
        assignments={},
        attempts=tuple(attempts),
        outcomes=outcomes or {},
        attempt_scope_snapshots=attempt_scope_snapshots,
    )
    defaults.update(overrides)
    return EligibilityFacts(**defaults)


def request_for(project: Project, plan, actor=None, target_id="work-a", **kwargs):
    actor = actor or ref(project, EntityKind.ACTOR, "operator", incarnation=sid("inc-1"))
    target = next(item.definition.ref for item in plan.work_items if str(item.definition.work_item_id) == target_id)
    return EligibilityRequest(target, actor, sid("work:execute"), 0, **kwargs)


class EligibilityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.project = Project(sid("project-a"), sid("authority-a"))
        self.actor = ref(self.project, EntityKind.ACTOR, "operator", incarnation=sid("inc-1"))
        self.plan = compiled_plan(self.project)
        self.request = request_for(self.project, self.plan, self.actor)

    def test_allowance_is_bound_to_revision_actor_and_plan_identity(self):
        decision = evaluate_eligibility(self.request, base_facts(self.project, self.plan))
        self.assertEqual(decision.status, EligibilityStatus.ALLOWED)
        self.assertEqual(decision.authority_revision, 0)

        old_definition = EntityRef(
            self.project.project_id, EntityKind.WORK_ITEM, self.request.target.entity_id,
            sid("work-a-old-definition"),
        )
        wrong_version = EligibilityRequest(old_definition, self.actor, sid("work:execute"), 0)
        decision = evaluate_eligibility(wrong_version, base_facts(self.project, self.plan))
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("target_revision_mismatch", {cause.code for cause in decision.causes})

        stale = EligibilityRequest(self.request.target, self.actor, sid("work:execute"), 1)
        decision = evaluate_eligibility(stale, base_facts(self.project, self.plan))
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("stale_authority_revision", {cause.code for cause in decision.causes})

        mismatched = base_facts(self.project, self.plan, plan_matches_authority=False)
        decision = evaluate_eligibility(self.request, mismatched)
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("plan_not_authoritative", {cause.code for cause in decision.causes})

    def test_capability_action_scope_expiry_revocation_and_incarnation_are_exact(self):
        target_grant = Capability(
            sid("cap-target"), self.project.project_id, self.actor, self.request.target,
            (sid("work:execute"),), expires_at=NOW + timedelta(seconds=1),
        )
        allowed = base_facts(self.project, self.plan, caps=(target_grant,))
        self.assertEqual(evaluate_eligibility(self.request, allowed).status, EligibilityStatus.ALLOWED)

        wrong_scope = EntityRef(self.project.project_id, EntityKind.WORK_ITEM, sid("work-b"), self.plan.revision.plan_revision_id)
        request = EligibilityRequest(self.request.target, self.actor, sid("work:execute"), 0, scope=wrong_scope)
        denied = evaluate_eligibility(request, allowed)
        self.assertEqual(denied.status, EligibilityStatus.BLOCKED)
        self.assertIn("capability_scope_exceeded", {cause.code for cause in denied.causes})

        expired = Capability(
            sid("cap-expired"), self.project.project_id, self.actor, self.project.ref,
            (sid("work:execute"),), expires_at=NOW,
        )
        denied = evaluate_eligibility(self.request, base_facts(self.project, self.plan, caps=(expired,)))
        self.assertIn("capability_expired", {cause.code for cause in denied.causes})

        denied = evaluate_eligibility(
            self.request,
            base_facts(self.project, self.plan, caps=(target_grant,), revoked_capability_ids=frozenset({target_grant.capability_id})),
        )
        self.assertIn("capability_revoked", {cause.code for cause in denied.causes})

        other_incarnation = ref(self.project, EntityKind.ACTOR, "operator", incarnation=sid("inc-2"))
        denied = evaluate_eligibility(
            EligibilityRequest(self.request.target, other_incarnation, sid("work:execute"), 0),
            base_facts(self.project, self.plan),
        )
        self.assertIn("actor_incarnation_not_registered", {cause.code for cause in denied.causes})

    def test_owner_participation_comes_from_authenticated_actor_and_trusted_facts(self):
        owner = ref(self.project, EntityKind.ACTOR, "owner", incarnation=sid("owner-inc"))
        any_plan = compiled_plan(
            self.project,
            ownership={"mode": "any", "actors": [{
                "project_id": str(owner.project_id), "kind": "actor", "entity_id": str(owner.entity_id),
                "incarnation_id": str(owner.incarnation_id),
            }]},
        )
        request = request_for(self.project, any_plan, self.actor, participants=(self.actor, owner))
        facts = base_facts(self.project, any_plan, registered=frozenset({self.actor, owner}))
        decision = evaluate_eligibility(request, facts)
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("owner_acl_denied", {cause.code for cause in decision.causes})

        all_plan = compiled_plan(
            self.project,
            ownership={"mode": "all", "actors": [
                {"project_id": str(ref.project_id), "kind": "actor", "entity_id": str(ref.entity_id),
                 "incarnation_id": str(ref.incarnation_id)}
                for ref in (self.actor, owner)
            ]},
        )
        request = request_for(self.project, all_plan, self.actor, participants=(self.actor, owner))
        facts = base_facts(self.project, all_plan, registered=frozenset({self.actor, owner}))
        self.assertEqual(evaluate_eligibility(request, facts).status, EligibilityStatus.UNKNOWN)
        facts = base_facts(
            self.project, all_plan, registered=frozenset({self.actor, owner}),
            approved_participants={request.target: frozenset({self.actor, owner})},
        )
        self.assertEqual(evaluate_eligibility(request, facts).status, EligibilityStatus.ALLOWED)

    def test_requirement_and_conditional_dependency_share_typed_condition_results(self):
        required_plan = compiled_plan(
            self.project,
            items=[{
                "id": "work-a", "paths": [],
                "requirement_groups": [{"kind": "check", "mode": "all", "members": ["review-check"]}],
            }],
            requirements=[{
                "id": "review-check", "work_item_id": "work-a", "kind": "check",
                "description": "Review is accepted", "check_key": "review",
            }],
        )
        request = request_for(self.project, required_plan)
        missing = evaluate_eligibility(request, base_facts(self.project, required_plan))
        self.assertEqual(missing.status, EligibilityStatus.ALLOWED)
        failed = base_facts(
            self.project, required_plan,
            check_observations={sid("review"): ConditionResult(ConditionStatus.UNSATISFIED)},
        )
        self.assertEqual(evaluate_eligibility(request, failed).status, EligibilityStatus.ALLOWED)

        # A decision declaration is required for a validated condition reference.
        document = plan_document(items=[{"id": "work-a", "paths": []}, {"id": "work-b", "paths": []}], dependencies=[{
            "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "work-a"},
            "mode": "all",
            "members": [{
                "relation": "completion",
                "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "work-b"},
                "condition": {"op": "decision_equals", "decision_id": "ship", "option_id": "yes"},
            }],
        }])
        document["decisions"] = [{
            "id": "ship", "title": "Ship?", "question": "Proceed?",
            "options": [{"id": "yes", "description": "yes"}, {"id": "no", "description": "no"}],
            "selected_option_id": None, "unknowns": [], "resolvers": [],
        }]
        parsed = parse_plan_json(json.dumps(document))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        conditional_plan = compile_plan(parsed.package, self.project).plan
        request = request_for(self.project, conditional_plan)
        inactive = base_facts(
            self.project, conditional_plan,
            decision_observations={"ship": DecisionObservation(ConditionStatus.SATISFIED, "no")},
        )
        self.assertEqual(evaluate_eligibility(request, inactive).status, EligibilityStatus.ALLOWED)
        active_unknown = base_facts(
            self.project, conditional_plan,
            decision_observations={"ship": DecisionObservation(ConditionStatus.SATISFIED, "yes")},
        )
        self.assertEqual(evaluate_eligibility(request, active_unknown).status, EligibilityStatus.BLOCKED)

    def test_caller_blocker_cannot_override_authoritative_local_completion(self):
        plan = compiled_plan(
            self.project,
            items=[
                {"id": "work-a", "paths": [], "requirement_groups": [{
                    "kind": "prerequisite", "mode": "all", "members": ["prior-work"],
                }]},
                {"id": "work-b", "paths": []},
            ],
            requirements=[{
                "id": "prior-work", "work_item_id": "work-a", "kind": "prerequisite",
                "description": "Prior work must be complete",
                "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "work-b"},
            }],
        )
        target = next(item.definition.ref for item in plan.work_items if item.definition.work_item_id == sid("work-a"))
        prior = next(item.definition.ref for item in plan.work_items if item.definition.work_item_id == sid("work-b"))
        request = EligibilityRequest(target, self.actor, sid("work:execute"), 0)
        facts = base_facts(
            self.project, plan,
            blocker_observations={prior: ConditionResult(ConditionStatus.SATISFIED)},
        )
        decision = evaluate_eligibility(request, facts)
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("requirement_group_unsatisfied", {cause.code for cause in decision.causes})

    def test_path_and_lock_conflicts_require_exact_qualified_workspace_evidence(self):
        lock_plan = compiled_plan(self.project, items=[
            {"id": "work-a", "paths": [{"path": "src/package", "access": "write"}], "locks": [{"name": "build", "mode": "exclusive"}]},
            {"id": "work-b", "paths": [{"path": "src/package/file.py", "access": "read"}], "locks": [{"name": "build", "mode": "shared"}]},
        ])
        request = request_for(self.project, lock_plan, target_id="work-a")
        other = next(item.definition.ref for item in lock_plan.work_items if item.definition.work_item_id == sid("work-b"))
        attempt = Attempt(
            sid("attempt-b"), self.project.project_id, other,
            ref(self.project, EntityKind.ACTOR, "worker", incarnation=sid("worker-inc")),
            AttemptState.ACTIVE,
            lease=Lease(sid("lease-b"), ref(self.project, EntityKind.ACTOR, "worker", incarnation=sid("worker-inc")), NOW + timedelta(hours=1)),
        )
        facts = base_facts(self.project, lock_plan, attempts=(attempt,))
        decision = evaluate_eligibility(request, facts)
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("named_lock_conflict", {cause.code for cause in decision.causes})

        # Workspace qualification cannot override a named lock.
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)

        path_plan = compiled_plan(self.project, items=[
            {"id": "work-a", "paths": [{"path": "src/package", "access": "write"}]},
            {"id": "work-b", "paths": [{"path": "src/package/file.py", "access": "read"}]},
        ])
        request = request_for(self.project, path_plan)
        other = next(item.definition.ref for item in path_plan.work_items if item.definition.work_item_id == sid("work-b"))
        attempt = Attempt(
            sid("attempt-b"), self.project.project_id, other,
            ref(self.project, EntityKind.ACTOR, "worker", incarnation=sid("worker-inc")),
            AttemptState.ACTIVE,
            lease=Lease(sid("lease-b"), ref(self.project, EntityKind.ACTOR, "worker", incarnation=sid("worker-inc")), NOW + timedelta(hours=1)),
        )
        denied = evaluate_eligibility(request, base_facts(self.project, path_plan, attempts=(attempt,)))
        self.assertIn("unsafe_source_overlap", {cause.code for cause in denied.causes})

        repository = sid("repository-1")
        source = QualifiedSourceRevision(self.project.project_id, repository, sid("main"), "a" * 64)
        destination = QualifiedDestination(self.project.project_id, repository, sid("integration"))
        provider = ProviderIdentity(sid("git-provider"), "1")

        def qualification(workspace_id):
            receipt = ProviderReceipt(
                sid("receipt-" + workspace_id), provider, sid("correlation-" + workspace_id),
                Sha256Digest("b" * 64), sid("provenance-" + workspace_id), NOW,
            )
            marker = "a" if workspace_id == "workspace-a" else "b"
            isolation = WorkspaceIsolation(
                Sha256Digest("d" * 64), Sha256Digest(marker * 64),
                Sha256Digest(("1" if marker == "a" else "2") * 64),
                sid("refs/heads/" + workspace_id),
                Sha256Digest(("3" if marker == "a" else "4") * 64),
            )
            return WorkspaceQualification(sid(workspace_id), repository, source, destination, receipt, isolation)

        isolated = base_facts(
            self.project, path_plan, attempts=(attempt,),
            workspace_qualifications={request.target: qualification("workspace-a"), attempt.ref: qualification("workspace-b")},
        )
        self.assertEqual(evaluate_eligibility(request, isolated).status, EligibilityStatus.ALLOWED)
        different_base = QualifiedSourceRevision(self.project.project_id, repository, sid("release"), "c" * 64)
        bad_workspace = WorkspaceQualification(
            sid("workspace-b"), repository, different_base, destination,
            qualification("workspace-b").receipt, qualification("workspace-b").isolation,
        )
        unsafe = base_facts(
            self.project, path_plan, attempts=(attempt,),
            workspace_qualifications={request.target: qualification("workspace-a"), attempt.ref: bad_workspace},
        )
        self.assertEqual(evaluate_eligibility(request, unsafe).status, EligibilityStatus.BLOCKED)

    def test_active_attempt_scope_uses_immutable_snapshot_not_current_context(self):
        plan = compiled_plan(self.project, items=[
            {"id": "work-a", "paths": [{"path": "src/package", "access": "write"}]},
            {"id": "work-b", "paths": [{"path": "src/package/subtree", "access": "write"}]},
        ])
        request = request_for(self.project, plan, target_id="work-a")
        other_item = next(item for item in plan.work_items if item.definition.work_item_id == sid("work-b"))
        worker = ref(self.project, EntityKind.ACTOR, "worker", incarnation=sid("worker-inc"))
        attempt = Attempt(
            sid("attempt-b"), self.project.project_id, other_item.definition.ref,
            worker, AttemptState.ACTIVE,
            lease=Lease(sid("lease-b"), worker, NOW + timedelta(hours=1)),
        )

        # The current plan and caller-provided context say this scope overlaps,
        # but the immutable claim snapshot says the active work owns docs only.
        disjoint = base_facts(
            self.project, plan, attempts=(attempt,),
            scope_contexts={attempt.work_item: other_item.context},
            attempt_scope_snapshots={attempt.ref: AttemptScopeSnapshot(
                (("docs/reference", "write"),), (),
            )},
        )
        self.assertEqual(evaluate_eligibility(request, disjoint).status, EligibilityStatus.ALLOWED)

        # Caller input cannot erase a conflict present in the stored snapshot.
        conflict = base_facts(
            self.project, plan, attempts=(attempt,),
            scope_contexts={attempt.work_item: other_item.context},
            attempt_scope_snapshots={attempt.ref: AttemptScopeSnapshot(
                (("src/package/subtree", "write"),), (),
            )},
        )
        blocked = evaluate_eligibility(request, conflict)
        self.assertEqual(blocked.status, EligibilityStatus.BLOCKED)
        self.assertIn("unsafe_source_overlap", {cause.code for cause in blocked.causes})

        missing = base_facts(
            self.project, plan, attempts=(attempt,), scope_contexts={attempt.work_item: other_item.context},
            attempt_scope_snapshots={},
        )
        unknown = evaluate_eligibility(request, missing)
        self.assertEqual(unknown.status, EligibilityStatus.UNKNOWN)
        self.assertIn("active_scope_unavailable", {cause.code for cause in unknown.causes})

    def test_expired_lease_is_unknown_only_when_scopes_may_conflict(self):
        disjoint_plan = compiled_plan(self.project)
        request = request_for(self.project, disjoint_plan)
        other = next(item.definition.ref for item in disjoint_plan.work_items if item.definition.work_item_id == sid("work-b"))
        worker = ref(self.project, EntityKind.ACTOR, "worker", incarnation=sid("worker-inc"))
        attempt = Attempt(
            sid("attempt-b"), self.project.project_id, other, worker, AttemptState.ACTIVE,
            lease=Lease(sid("lease-b"), worker, NOW - timedelta(seconds=1)),
        )
        self.assertEqual(evaluate_eligibility(request, base_facts(self.project, disjoint_plan, attempts=(attempt,))).status, EligibilityStatus.ALLOWED)

        conflict_plan = compiled_plan(self.project, items=[
            {"id": "work-a", "paths": [{"path": "src/package", "access": "write"}]},
            {"id": "work-b", "paths": [{"path": "src/package/subtree", "access": "read"}]},
        ])
        request = request_for(self.project, conflict_plan)
        other = next(item.definition.ref for item in conflict_plan.work_items if item.definition.work_item_id == sid("work-b"))
        attempt = Attempt(
            sid("attempt-b"), self.project.project_id, other, worker, AttemptState.EXPIRED,
        )
        unknown = evaluate_eligibility(request, base_facts(self.project, conflict_plan, attempts=(attempt,)))
        self.assertEqual(unknown.status, EligibilityStatus.UNKNOWN)


class EligibilityAdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.path = Path(self.root.name) / "authority.sqlite3"
        self.project = Project(sid("project-adapter"), sid("authority-adapter"))
        SQLiteAuthority.initialize(self.path, self.project)
        self.actor = ref(self.project, EntityKind.ACTOR, "operator", incarnation=sid("inc-1"))
        self.document = plan_document(items=[{"id": "work-a", "paths": []}])
        self.document["project"] = {
            "project_id": str(self.project.project_id),
            "authority_id": str(self.project.authority_id),
        }
        self.package_json = json.dumps(self.document)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            auth = AuthorityAuthService(CommandDispatcher(), clock=lambda: NOW)
            enrollment = auth.enroll_local_owner(
                authority, "eligibility fixture owner 732", label="owner",
                idempotency_key=sid("owner-enroll"), expected_revision=0,
            )
            owner = auth.login_local_owner(
                authority, "eligibility fixture owner 732",
                actions=(sid("todo.plan.commit"),), expires_at=NOW + timedelta(days=1),
                idempotency_key=sid("owner-login"), expected_revision=enrollment.receipt.semantic_revision,
            )
            _, _, self.plan = commit_plan(authority, auth, owner.bearer_token, self.package_json)
            self.target = self.plan.work_items[0].definition.ref
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                    (str(self.actor.entity_id), str(self.actor.incarnation_id), "service", "fixture"),
                )
                connection.execute(
                    "INSERT INTO capabilities(capability_id, actor_id, actor_incarnation_id, scope_kind, scope_entity_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    ("cap-1", str(self.actor.entity_id), str(self.actor.incarnation_id), "project", str(self.project.project_id)),
                )
                connection.execute(
                    "INSERT INTO capability_actions(capability_id, action_ordinal, action) VALUES (?, ?, ?)",
                    ("cap-1", 0, "work:execute"),
                )
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
        self.request = EligibilityRequest(self.target, self.actor, sid("work:execute"), revision)

    def tearDown(self):
        self.root.cleanup()

    def test_read_adapter_uses_trusted_clock_and_validated_plan_facts(self):
        adapter = EligibilityAdapter(clock=lambda: NOW)
        with SQLiteAuthority.open_reader(self.path, self.project) as reader:
            decision = adapter.evaluate_read(reader, self.request, self.plan)
        self.assertEqual(decision.status, EligibilityStatus.ALLOWED)

        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with writer.write_transaction() as connection:
                connection.execute("UPDATE capabilities SET expires_at = ? WHERE capability_id = ?", ((NOW - timedelta(seconds=1)).isoformat(), "cap-1"))
        with SQLiteAuthority.open_reader(self.path, self.project) as reader:
            decision = adapter.evaluate_read(reader, self.request, self.plan)
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("capability_expired", {cause.code for cause in decision.causes})

    def test_read_adapter_rejects_typed_scope_forgery_with_original_digest(self):
        item = self.plan.work_items[0]
        forged_scope = dict(item.context.scope)
        forged_scope["paths"] = ({"path": "private/other", "access": "write"},)
        forged_item = replace(item, context=replace(item.context, scope=forged_scope))
        forged_plan = replace(
            self.plan,
            work_items=(forged_item, *self.plan.work_items[1:]),
        )
        with SQLiteAuthority.open_reader(self.path, self.project) as reader:
            decision = EligibilityAdapter(clock=lambda: NOW).evaluate_read(
                reader, self.request, forged_plan,
            )
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("plan_not_authoritative", {cause.code for cause in decision.causes})

    def test_reopened_snapshot_loader_rejects_corrupted_canonical_content(self):
        import todo_orchestrator.authority.sqlite as authority_module

        revision_id = self.plan.revision.plan_revision_id
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with writer.write_transaction() as connection:
                connection.execute("DROP TRIGGER plan_revision_snapshots_no_update")
                connection.execute(
                    "UPDATE plan_revision_snapshots SET canonical_json = canonical_json || ' ' "
                    "WHERE plan_revision_id = ?",
                    (str(revision_id),),
                )
                connection.execute(next(
                    statement for statement in authority_module._SCHEMA_STATEMENTS
                    if statement.startswith("CREATE TRIGGER plan_revision_snapshots_no_update")
                ))
        with SQLiteAuthority.open_reader(self.path, self.project) as reader:
            with reader.read_transaction() as connection:
                with self.assertRaises(InvalidAuthorityError):
                    load_plan_revision_snapshot(connection, self.project, revision_id)

    def test_transactional_adapter_requires_writer_lock_and_rechecks_revision(self):
        adapter = EligibilityAdapter(clock=lambda: NOW)
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with self.assertRaises(EligibilityAdapterError):
                with writer.write_transaction() as connection:
                    connection.execute(
                        "UPDATE authority_meta SET semantic_revision = ? WHERE singleton = 1",
                        (self.request.expected_revision + 1,),
                    )
                    self.assertTrue(writer.write_transaction_active)
                    decision = adapter.evaluate_in_transaction(writer, connection, self.request, self.plan)
                    self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
                    self.assertIn("stale_authority_revision", {cause.code for cause in decision.causes})
                    raise EligibilityAdapterError("force fixture transaction rollback")
            self.assertFalse(writer.write_transaction_active)
            with self.assertRaises(EligibilityAdapterError):
                writer.connection.execute("BEGIN IMMEDIATE")
                try:
                    adapter.evaluate_in_transaction(writer, writer.connection, self.request, self.plan)
                finally:
                    writer.connection.execute("ROLLBACK")

    def test_latest_outcome_version_is_selected_deterministically(self):
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, disposition, "
                    "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("newer", str(self.target.entity_id), str(self.target.definition_revision_id), 2, "failed",
                     str(self.actor.entity_id), str(self.actor.incarnation_id), NOW.isoformat()),
                )
                connection.execute(
                    "INSERT INTO outcomes(outcome_id, work_item_id, definition_revision_id, version, disposition, "
                    "accepted_by_actor_id, accepted_by_incarnation_id, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("older", str(self.target.entity_id), str(self.target.definition_revision_id), 1, "completed",
                     str(self.actor.entity_id), str(self.actor.incarnation_id), NOW.isoformat()),
                )
        with SQLiteAuthority.open_reader(self.path, self.project) as reader:
            decision = EligibilityAdapter(clock=lambda: NOW).evaluate_read(reader, self.request, self.plan)
        self.assertNotIn("work_item_already_completed", {cause.code for cause in decision.causes})


if __name__ == "__main__":
    unittest.main()
