from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
import unittest

from todo_orchestrator.contracts import (
    ATTEMPT_TRANSITIONS,
    DOMAIN_CONTRACT_VERSION,
    EXTERNAL_OPERATION_TRANSITIONS,
    PLAN_REVISION_TRANSITIONS,
    RUN_TRANSITIONS,
    Actor,
    ActorKind,
    Assignment,
    Attempt,
    AttemptState,
    Capability,
    EntityKind,
    EntityRef,
    Evidence,
    EvidenceInput,
    EvidenceResult,
    ExternalOperation,
    ExternalOperationState,
    Lease,
    Outcome,
    OutcomeDisposition,
    PlanRevision,
    PlanRevisionState,
    Project,
    Requirement,
    RequirementGroup,
    RequirementKind,
    RequirementMode,
    Run,
    RunState,
    Sha256Digest,
    SourceProvenance,
    StableId,
    WorkItem,
)


def sid(value: str) -> StableId:
    return StableId(value)


def ref(kind: EntityKind, entity_id: str, *, project: str = "project", revision: str | None = None,
        incarnation: str | None = None) -> EntityRef:
    if kind in {EntityKind.WORK_ITEM, EntityKind.REQUIREMENT} and revision is None:
        revision = "revision"
    if kind is EntityKind.ACTOR and incarnation is None:
        incarnation = "incarnation"
    return EntityRef(
        sid(project),
        kind,
        sid(entity_id),
        None if revision is None else sid(revision),
        None if incarnation is None else sid(incarnation),
    )


def work_ref(entity_id: str = "work", *, revision: str = "revision", project: str = "project") -> EntityRef:
    return ref(EntityKind.WORK_ITEM, entity_id, revision=revision, project=project)


def actor_ref(entity_id: str = "actor", *, project: str = "project", incarnation: str = "incarnation") -> EntityRef:
    return ref(EntityKind.ACTOR, entity_id, project=project, incarnation=incarnation)


def digest(value: str = "a" * 64) -> Sha256Digest:
    return Sha256Digest(value)


class DomainValueTests(unittest.TestCase):
    def test_contract_version_and_identifiers_are_stable_values(self):
        self.assertEqual(DOMAIN_CONTRACT_VERSION, 1)
        self.assertEqual(str(sid("work-17")), "work-17")
        for invalid in ("", "  ", "has space", "a\nb", "\x7f", "\x80", "a\x9fb", "x" * 129):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                StableId(invalid)

    def test_digest_requires_lowercase_sha256_hex(self):
        for invalid in ("", "a" * 63, "A" * 64, "g" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                Sha256Digest(invalid)

    def test_entity_reference_requires_revision_for_work_definitions(self):
        with self.assertRaisesRegex(ValueError, "definition revision"):
            EntityRef(sid("project"), EntityKind.WORK_ITEM, sid("work"))
        self.assertEqual(work_ref().definition_revision_id, sid("revision"))

    def test_actor_reference_binds_an_incarnation(self):
        actor = Actor(sid("actor"), sid("project"), sid("incarnation-1"), ActorKind.AUTOMATION)
        other_incarnation = Actor(sid("actor"), sid("project"), sid("incarnation-2"), ActorKind.AUTOMATION)
        self.assertEqual(actor.ref.incarnation_id, sid("incarnation-1"))
        self.assertNotEqual(actor.ref, other_incarnation.ref)
        with self.assertRaisesRegex(ValueError, "incarnation_id"):
            EntityRef(sid("project"), EntityKind.ACTOR, sid("actor"))

    def test_project_reference_must_point_to_its_project_identity(self):
        with self.assertRaisesRegex(ValueError, "identify its project_id"):
            ref(EntityKind.PROJECT, "other")
        self.assertEqual(Project(sid("project"), sid("authority")).ref.entity_id, sid("project"))

    def test_requirement_groups_validate_all_any_and_quorum_shapes(self):
        ids = (sid("r1"), sid("r2"))
        self.assertEqual(RequirementGroup(RequirementKind.CHECK, RequirementMode.ALL, ids).quorum, None)
        self.assertEqual(RequirementGroup(RequirementKind.CHECK, RequirementMode.QUORUM, ids, 2).quorum, 2)
        for mode, quorum in (
            (RequirementMode.ALL, 1),
            (RequirementMode.ANY, 1),
            (RequirementMode.QUORUM, None),
            (RequirementMode.QUORUM, 0),
            (RequirementMode.QUORUM, 3),
            (RequirementMode.QUORUM, True),
        ):
            with self.subTest(mode=mode, quorum=quorum), self.assertRaises(ValueError):
                RequirementGroup(RequirementKind.CHECK, mode, ids, quorum)

    def test_requirement_groups_reject_duplicates_and_empty_groups(self):
        with self.assertRaisesRegex(ValueError, "not be empty"):
            RequirementGroup(RequirementKind.PREREQUISITE, RequirementMode.ALL, ())
        with self.assertRaisesRegex(ValueError, "duplicates"):
            RequirementGroup(
                RequirementKind.CHECK,
                RequirementMode.ANY,
                (sid("r1"), sid("r1")),
            )

    def test_work_item_has_no_mutable_lifecycle_and_rejects_self_lineage(self):
        item = WorkItem(
            sid("work"), sid("project"), sid("revision"), "Build API", "Expose the API."
        )
        self.assertEqual(item.requirement_groups, ())
        self.assertEqual(item.ref, work_ref())
        with self.assertRaises(FrozenInstanceError):
            item.title = "Changed"
        with self.assertRaisesRegex(ValueError, "own parent"):
            WorkItem(
                sid("work"), sid("project"), sid("revision"), "Build API", "Expose the API.",
                parent=work_ref(),
            )

    def test_plan_revision_selects_exact_definitions_across_versions(self):
        revision = PlanRevision(sid("revision"), sid("project"), 1, (work_ref(),))
        self.assertEqual(revision.ref.kind, EntityKind.PLAN_REVISION)
        retained = work_ref(revision="older")
        mixed = PlanRevision(sid("revision"), sid("project"), 1, (retained, work_ref("other")))
        self.assertEqual(mixed.work_items, (retained, work_ref("other")))
        with self.assertRaisesRegex(ValueError, "one definition per work item"):
            PlanRevision(sid("revision"), sid("project"), 1, (retained, work_ref()))
        with self.assertRaises(ValueError):
            PlanRevision(sid("revision"), sid("project"), 1, (work_ref(project="foreign"),))
        with self.assertRaisesRegex(ValueError, "positive integer"):
            PlanRevision(sid("revision"), sid("project"), True, ())

    def test_requirement_shape_distinguishes_prerequisite_and_check(self):
        prerequisite = Requirement(
            sid("r1"), sid("project"), sid("revision"), sid("work"),
            RequirementKind.PREREQUISITE, "Wait for prerequisite", target=work_ref("other"),
        )
        check = Requirement(
            sid("r2"), sid("project"), sid("revision"), sid("work"),
            RequirementKind.CHECK, "Run quality checks", check_key=sid("quality"),
        )
        self.assertEqual(prerequisite.owner, work_ref())
        self.assertEqual(check.ref.kind, EntityKind.REQUIREMENT)
        with self.assertRaisesRegex(ValueError, "prerequisite target"):
            Requirement(
                sid("r3"), sid("project"), sid("revision"), sid("work"),
                RequirementKind.PREREQUISITE, "Missing target",
            )
        with self.assertRaisesRegex(ValueError, "must have a StableId check_key"):
            Requirement(
                sid("r4"), sid("project"), sid("revision"), sid("work"),
                RequirementKind.CHECK, "Missing key",
            )

    def test_prerequisite_contract_covers_heterogeneous_blockers(self):
        for kind in (
            EntityKind.WORK_ITEM,
            EntityKind.CHECKPOINT,
            EntityKind.INTERFACE,
            EntityKind.BARRIER,
            EntityKind.DECISION,
        ):
            target = work_ref("target") if kind is EntityKind.WORK_ITEM else ref(kind, "target")
            with self.subTest(kind=kind):
                requirement = Requirement(
                    sid("r-" + kind.value), sid("project"), sid("revision"), sid("work"),
                    RequirementKind.PREREQUISITE, "Wait for prerequisite", target=target,
                )
                self.assertEqual(requirement.target.kind, kind)
        with self.assertRaisesRegex(ValueError, "prerequisite target"):
            Requirement(
                sid("bad"), sid("project"), sid("revision"), sid("work"),
                RequirementKind.PREREQUISITE, "Not a blocker",
                target=ref(EntityKind.ACTOR, "actor"),
            )

    def test_run_and_assignment_are_optional_for_a_simple_attempt(self):
        project = sid("project")
        actor = Actor(sid("actor"), project, sid("incarnation"), ActorKind.AUTOMATION)
        assignment = Assignment(sid("assignment"), project, work_ref(), assignee=actor.ref)
        attempt = Attempt(
            sid("attempt"), project, work_ref(), actor.ref, AttemptState.ADMITTED,
        )
        self.assertIsNone(assignment.run)
        self.assertIsNone(attempt.run)
        self.assertIsNone(attempt.assignment)

    def test_run_must_reference_a_plan_revision_in_its_project(self):
        run = Run(
            sid("run"), sid("project"), ref(EntityKind.PLAN_REVISION, "revision"),
        )
        self.assertEqual(run.state, RunState.OPEN)
        with self.assertRaisesRegex(ValueError, "belong to this project"):
            Run(
                sid("run"), sid("project"),
                ref(EntityKind.PLAN_REVISION, "revision", project="other"),
            )

    def test_capability_is_scoped_grant_data_without_role_authentication(self):
        actor = Actor(sid("actor"), sid("project"), sid("incarnation-1"), ActorKind.AUTOMATION)
        grant = Capability(
            sid("grant"), sid("project"), actor.ref, work_ref(), (sid("work.read"),),
            parent_capability=ref(EntityKind.CAPABILITY, "parent-grant"),
        )
        attempt = Attempt(
            sid("attempt"), sid("project"), work_ref(), actor.ref, AttemptState.ADMITTED,
        )
        self.assertEqual(grant.scope.kind, EntityKind.WORK_ITEM)
        self.assertEqual(grant.actor.incarnation_id, sid("incarnation-1"))
        self.assertEqual(grant.parent_capability.entity_id, sid("parent-grant"))
        self.assertEqual(attempt.actor, grant.actor)
        self.assertNotIn("role", {field.name for field in fields(Capability)})
        self.assertNotIn("authenticated", {field.name for field in fields(Actor)})
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            Capability(sid("grant"), sid("project"), actor_ref(), work_ref(), ())
        with self.assertRaisesRegex(ValueError, "parent_capability must belong to this project"):
            Capability(sid("grant"), sid("project"), actor.ref, work_ref(), (sid("work.read"),),
                       parent_capability=ref(EntityKind.CAPABILITY, "parent", project="other"))

    def test_attempt_lease_binds_to_the_same_actor_and_requires_aware_expiry(self):
        owner = actor_ref()
        lease = Lease(sid("lease"), owner, datetime(2026, 10, 18, tzinfo=timezone.utc))
        attempt = Attempt(
            sid("attempt"), sid("project"), work_ref(), owner,
            AttemptState.ACTIVE, lease=lease,
        )
        self.assertEqual(attempt.lease, lease)
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            Lease(sid("lease"), owner, datetime(2026, 10, 18))
        with self.assertRaisesRegex(ValueError, "must match"):
            Attempt(
                sid("attempt"), sid("project"), work_ref(), owner,
                AttemptState.ACTIVE,
                lease=Lease(sid("lease"), actor_ref("other"), datetime(2026, 10, 18, tzinfo=timezone.utc)),
            )

    def test_attempt_transition_contract_has_terminal_and_quarantine_paths(self):
        self.assertIn(AttemptState.ACTIVE, ATTEMPT_TRANSITIONS[AttemptState.ADMITTED])
        self.assertIn(AttemptState.QUARANTINED, ATTEMPT_TRANSITIONS[AttemptState.UNCERTAIN])
        self.assertEqual(ATTEMPT_TRANSITIONS[AttemptState.ACCEPTED], frozenset())
        self.assertNotIn(AttemptState.ACCEPTED, ATTEMPT_TRANSITIONS[AttemptState.ADMITTED])

    def test_live_attempts_can_be_quarantined_without_automatic_release(self):
        for state in (AttemptState.ADMITTED, AttemptState.ACTIVE, AttemptState.REPORTED):
            with self.subTest(state=state):
                self.assertIn(AttemptState.QUARANTINED, ATTEMPT_TRANSITIONS[state])

    def test_evidence_requires_input_contract_verifier_and_aware_observation(self):
        evidence = Evidence(
            sid("evidence"), sid("project"), ref(EntityKind.ATTEMPT, "attempt"),
            EvidenceResult.PASS, sid("verifier"), "1.2", digest(),
            (EvidenceInput(sid("source"), digest()),),
            datetime(2026, 10, 18, tzinfo=timezone.utc),
        )
        self.assertEqual(evidence.result, EvidenceResult.PASS)
        self.assertFalse(hasattr(evidence, "current"))
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            Evidence(
                sid("evidence"), sid("project"), ref(EntityKind.ATTEMPT, "attempt"),
                EvidenceResult.PASS, sid("verifier"), "1.2", digest(), (), datetime(2026, 10, 18),
            )

    def test_outcome_is_a_versioned_accepted_disposition(self):
        outcome = Outcome(
            sid("outcome"), sid("project"), work_ref(), 1, OutcomeDisposition.NO_CHANGE,
            actor_ref(), datetime(2026, 10, 18, tzinfo=timezone.utc),
        )
        self.assertEqual(outcome.disposition, OutcomeDisposition.NO_CHANGE)
        self.assertIsNone(outcome.attempt)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            Outcome(
                sid("outcome"), sid("project"), work_ref(), 0, OutcomeDisposition.NO_CHANGE,
                actor_ref(), datetime(2026, 10, 18, tzinfo=timezone.utc),
            )

    def test_external_operation_unknown_is_reconcilable_and_finalize_requires_receipt(self):
        now = datetime(2026, 10, 18, tzinfo=timezone.utc)
        operation = ExternalOperation(
            sid("operation"), sid("project"), sid("git.commit"), sid("request"), digest(),
            ExternalOperationState.UNKNOWN, now, now,
        )
        self.assertIn(ExternalOperationState.OBSERVED, EXTERNAL_OPERATION_TRANSITIONS[operation.state])
        self.assertNotIn(ExternalOperationState.EXECUTING, EXTERNAL_OPERATION_TRANSITIONS[operation.state])
        with self.assertRaisesRegex(ValueError, "receipt digest"):
            ExternalOperation(
                sid("operation"), sid("project"), sid("git.commit"), sid("request"), digest(),
                ExternalOperationState.FINALIZED, now, now,
            )

    def test_plan_and_run_state_contracts_are_terminal_at_expected_points(self):
        self.assertEqual(
            PLAN_REVISION_TRANSITIONS[PlanRevisionState.PROPOSED],
            frozenset({PlanRevisionState.VALIDATED}),
        )
        self.assertEqual(PLAN_REVISION_TRANSITIONS[PlanRevisionState.ACCEPTED], frozenset())
        self.assertIn(RunState.RETIRED, RUN_TRANSITIONS[RunState.CLOSED])
        self.assertEqual(RUN_TRANSITIONS[RunState.RETIRED], frozenset())

    def test_source_provenance_requires_digest_shape(self):
        provenance = SourceProvenance("plan.json", digest(), "compiler/1")
        self.assertEqual(provenance.source, "plan.json")


if __name__ == "__main__":
    unittest.main()
