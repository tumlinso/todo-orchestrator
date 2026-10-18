"""Native declaration facts use exact accepted-plan payloads and normal auth."""

import json
import unittest
from datetime import timedelta
from dataclasses import replace

from todo_orchestrator.authority import (
    CapabilityDeniedError,
    DeclarationMutationDeniedError,
    DeclarationService,
)
from todo_orchestrator.authority.declarations import (
    BARRIER_RELEASE_ACTION,
    BLOCKER_CLEAR_ACTION,
    BLOCKER_OPEN_ACTION,
    CHECKPOINT_ACCEPT_ACTION,
    DECISION_RESOLVE_ACTION,
    INTERFACE_PUBLISH_ACTION,
    RENDEZVOUS_ARRIVE_ACTION,
    declaration_condition,
    load_plan_declaration,
    native_declaration_facts,
)
from todo_orchestrator.contracts import (
    DeclarationKind,
    DeclarationObservationRequest,
    DeclarationStatus,
    EntityKind,
    EntityRef,
    ProviderCallContext,
    ProviderStatus,
    Sha256Digest,
    StableId,
)

from tests.verification.test_execution_independent import PROJECT


class DeclarationServiceTests(unittest.TestCase):
    def setUp(self):
        from tests.verification.test_execution_independent import (
            IndependentVerificationExecutionTests,
            OWNER_ACTIONS,
            OWNER_PASSWORD,
        )

        self.fixture = IndependentVerificationExecutionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        with self.fixture.open_writer() as authority:
            self.fixture.owner = self.fixture.auth.login_local_owner(
                authority, OWNER_PASSWORD,
                actions=(*OWNER_ACTIONS, DECISION_RESOLVE_ACTION, INTERFACE_PUBLISH_ACTION,
                         CHECKPOINT_ACCEPT_ACTION, BARRIER_RELEASE_ACTION, RENDEZVOUS_ARRIVE_ACTION,
                         BLOCKER_OPEN_ACTION, BLOCKER_CLEAR_ACTION),
                scope=PROJECT.ref, expires_at=self.fixture.clock() + timedelta(hours=1),
                idempotency_key=StableId("declaration-owner-token"),
                expected_revision=self.fixture.revision(),
            )
        self.service = DeclarationService(self.fixture.auth, clock=self.fixture.clock)

    def commit_package(self, source: str, key: str):
        f = self.fixture
        with f.open_writer() as authority:
            preview = f.plans.preview(authority, source)
            result = f.plans.commit(
                authority, f.owner.bearer_token, source,
                reviewed_digest=preview.digest,
                idempotency_key=StableId(key),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            plan = f.plans.load_accepted_plan(authority)
        return plan, result

    def package_with_decision(self, *, options=("one", "two")):
        from tests.verification.test_execution_independent import package_json

        document = json.loads(package_json())
        document["decisions"] = [{
            "id": "runtime-choice", "title": "Runtime choice",
            "question": "Which implementation should be used?",
            "options": [{"id": value, "description": value}
                        for value in options],
        }]
        document["interfaces"] = [{
            "id": "runtime-api", "title": "Runtime API", "version": "1.0.0",
            "contract": {"format": "json", "required": ["result"]},
            "producers": [], "consumers": [], "compatibility": "evolvable",
        }]
        return json.dumps(document, ensure_ascii=False, sort_keys=True)

    def delegate_decision(self, plan, key: str):
        f = self.fixture
        with f.open_writer() as authority:
            return f.auth.delegate(
                authority, f.owner.bearer_token, "worker-verify",
                actions=(DECISION_RESOLVE_ACTION,), scope=plan.revision.ref,
                expires_at=f.clock() + timedelta(minutes=20),
                idempotency_key=StableId(key), expected_revision=f.revision(),
            )

    def test_exact_plan_scoped_capability_resolves_once_then_becomes_noop(self):
        f = self.fixture
        plan, _ = self.commit_package(self.package_with_decision(), "declaration-plan-a")
        decision = EntityRef(PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        grant = self.delegate_decision(plan, "declaration-decision-grant")

        with f.open_writer() as authority:
            first = self.service.resolve_decision(
                authority, grant.bearer_token, plan.revision.ref, decision,
                StableId("one"), "Use the first declared option.",
                idempotency_key=StableId("declaration-resolve-first"),
                expected_revision=f.revision(),
            )
        self.assertTrue(first.receipt.changed)
        after_first = f.revision()

        with f.open_writer() as authority:
            replay_as_noop = self.service.resolve_decision(
                authority, grant.bearer_token, plan.revision.ref, decision,
                StableId("one"), "Use the first declared option.",
                idempotency_key=StableId("declaration-resolve-noop"),
                expected_revision=after_first,
            )
        self.assertFalse(replay_as_noop.receipt.changed)
        self.assertEqual(f.revision(), after_first)
        with f.open_reader() as authority:
            facts = authority.connection.execute(
                "SELECT count(*) FROM declaration_facts WHERE fact_kind = 'decision_resolved'"
            ).fetchone()[0]
        self.assertEqual(facts, 1)

        before = f.revision()
        interface = EntityRef(PROJECT.project_id, EntityKind.INTERFACE, StableId("runtime-api"))
        with f.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.service.publish_interface(
                    authority, grant.bearer_token, plan.revision.ref, interface,
                    "1.1.0", "This grant has no interface publication authority.",
                    idempotency_key=StableId("declaration-unauthorized-interface"),
                    expected_revision=before,
                )
        self.assertEqual(f.revision(), before)

    def test_interface_barrier_rendezvous_and_explicit_blocker_feed_native_facts(self):
        f = self.fixture
        source = json.loads(self.package_with_decision())
        source["barriers"] = [{
            "id": "release-point", "title": "Release point",
            "participants": [{
                "project_id": str(PROJECT.project_id), "kind": "work_item", "entity_id": "verify",
            }], "mode": "all",
        }]
        source["rendezvous"] = [{
            "id": "owner-sync", "title": "Owner synchronization",
            "participants": [{
                "project_id": str(PROJECT.project_id), "kind": "work_item", "entity_id": "verify",
            }], "mode": "all",
        }]
        plan, _ = self.commit_package(json.dumps(source, sort_keys=True), "declaration-all-plan")
        decision = EntityRef(PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        interface = EntityRef(PROJECT.project_id, EntityKind.INTERFACE, StableId("runtime-api"))
        barrier = EntityRef(PROJECT.project_id, EntityKind.BARRIER, StableId("release-point"))
        rendezvous = EntityRef(PROJECT.project_id, EntityKind.BARRIER, StableId("owner-sync"))

        with f.open_writer() as authority:
            self.service.resolve_decision(
                authority, f.owner.bearer_token, plan.revision.ref, decision,
                StableId("one"), "Select a declared implementation.",
                idempotency_key=StableId("declaration-all-decision"), expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            self.service.publish_interface(
                authority, f.owner.bearer_token, plan.revision.ref, interface,
                "1.1.0", "Publish the compatible interface revision.",
                idempotency_key=StableId("declaration-all-interface"), expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            self.service.release_barrier(
                authority, f.owner.bearer_token, plan.revision.ref, barrier,
                "Release after the coordinator reviewed the declared gate.",
                idempotency_key=StableId("declaration-all-barrier"), expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            dispatched = f.coordination.dispatch(
                authority, f.owner.bearer_token, plan,
                workspace_id=StableId("declaration-all-workspace"),
                idempotency_key=StableId("declaration-all-dispatch"),
                expected_revision=f.revision(), work_item=f.work_ref("verify"),
            )
        with f.open_writer() as authority:
            self.service.arrive_rendezvous(
                authority, f.owner.bearer_token, plan.revision.ref, rendezvous,
                dispatched.attempt.work_item,
                idempotency_key=StableId("declaration-all-rendezvous"), expected_revision=f.revision(),
                attempt=dispatched.attempt.ref,
            )

        with f.open_reader() as authority:
            conditions, decisions = native_declaration_facts(authority.connection, plan)
            self.assertEqual(decisions["runtime-choice"].status.value, "satisfied")
            for target in (interface, barrier, rendezvous):
                self.assertEqual(conditions[target].status.value, "satisfied")
            published, version, _ = declaration_condition(
                authority.connection,
                load_plan_declaration(authority.connection, PROJECT, plan.revision.plan_revision_id,
                                      "interface", StableId("runtime-api")),
                expected_version="1.1.0",
            )
            self.assertEqual(published.status.value, "satisfied")
            self.assertEqual(version, "1.1.0")

        with f.open_writer() as authority:
            self.service.open_blocker(
                authority, f.owner.bearer_token, plan.revision.ref, decision,
                "A new dependency needs review.",
                idempotency_key=StableId("declaration-all-blocker-open"), expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            conditions, decisions = native_declaration_facts(authority.connection, plan)
            self.assertEqual(conditions[decision].status.value, "unsatisfied")
            self.assertEqual(decisions["runtime-choice"].status.value, "unresolved")
        with f.open_writer() as authority:
            self.service.clear_blocker(
                authority, f.owner.bearer_token, plan.revision.ref, decision,
                "The dependency review is complete.",
                idempotency_key=StableId("declaration-all-blocker-clear"), expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            conditions, decisions = native_declaration_facts(authority.connection, plan)
            self.assertEqual(conditions[decision].status.value, "satisfied")
            self.assertEqual(decisions["runtime-choice"].status.value, "satisfied")

    def test_checkpoint_requires_finalized_named_evidence_and_observer_is_fail_closed(self):
        f = self.fixture
        document = json.loads(self.package_with_decision())
        document["checkpoints"] = [{
            "id": "tested", "title": "Tests accepted",
            "acceptance": {"assertions": ["verification passed"],
                           "required_evidence": ["verify-report"],
                           "allowed_dispositions": ["completed"]},
            "unknowns": [],
            "producers": [{"project_id": str(PROJECT.project_id),
                           "kind": "work_item", "entity_id": "verify"}],
        }]
        plan, _ = self.commit_package(json.dumps(document, sort_keys=True), "declaration-checkpoint-plan")
        checkpoint = EntityRef(PROJECT.project_id, EntityKind.CHECKPOINT, StableId("tested"))
        with f.open_writer() as authority:
            dispatched = f.coordination.dispatch(
                authority, f.owner.bearer_token, plan,
                workspace_id=StableId("declaration-checkpoint-workspace"),
                idempotency_key=StableId("declaration-checkpoint-dispatch"),
                expected_revision=f.revision(), work_item=f.work_ref("verify"),
            )
        with f.open_writer() as authority:
            with self.assertRaises(DeclarationMutationDeniedError):
                self.service.accept_checkpoint(
                    authority, f.owner.bearer_token, plan.revision.ref, checkpoint, (),
                    "No evidence has been produced.",
                    idempotency_key=StableId("declaration-checkpoint-empty"),
                    expected_revision=f.revision(),
                )
        requirement = f.requirement_ref("check-verify")
        with f.open_writer() as authority:
            operation = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref, requirement,
                idempotency_key=StableId("declaration-checkpoint-verify"), expected_revision=f.revision(),
            )
        self.assertEqual(operation.state, "finalized")

        with f.open_reader() as authority:
            declaration = load_plan_declaration(
                authority.connection, PROJECT, plan.revision.plan_revision_id,
                "checkpoint", StableId("tested"),
            )
        reader = f.open_reader()
        self.addCleanup(reader.close)
        observer = self.service.observer(reader)
        request = DeclarationObservationRequest(
            ProviderCallContext(PROJECT.project_id, dispatched.attempt.actor,
                                dispatched.capability.ref, StableId("native-declaration-context"),
                                StableId("native-declaration-scope")),
            StableId("native-declaration-before"), dispatched.attempt.ref,
            StableId("declaration-checkpoint-workspace"), plan.revision.plan_revision_id,
            checkpoint, DeclarationKind.CHECKPOINT, Sha256Digest(declaration.digest),
        )
        missing = observer.observe_declaration(request)
        self.assertEqual(missing.status, ProviderStatus.UNKNOWN)

        with f.open_writer() as authority:
            self.service.accept_checkpoint(
                authority, f.owner.bearer_token, plan.revision.ref, checkpoint,
                (operation.evidence_id,), "The exact required evidence passed.",
                idempotency_key=StableId("declaration-checkpoint-accept"),
                expected_revision=f.revision(),
            )
        observed = observer.observe_declaration(replace(request, correlation_id=StableId("native-declaration-after")))
        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS)
        self.assertEqual(observed.value.status, DeclarationStatus.SATISFIED)
        wrong = observer.observe_declaration(replace(
            request, correlation_id=StableId("native-declaration-wrong-digest"),
            declaration_digest=Sha256Digest("f" * 64),
        ))
        self.assertEqual(wrong.status, ProviderStatus.UNKNOWN)

    def test_old_plan_grant_cannot_resolve_same_id_revised_declaration(self):
        f = self.fixture
        old_plan, _ = self.commit_package(
            self.package_with_decision(options=("one", "two")), "declaration-plan-old",
        )
        old_grant = self.delegate_decision(old_plan, "declaration-old-grant")
        new_plan, _ = self.commit_package(
            self.package_with_decision(options=("one", "three")), "declaration-plan-new",
        )
        decision = EntityRef(PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        before = f.revision()

        with f.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.service.resolve_decision(
                    authority, old_grant.bearer_token, new_plan.revision.ref, decision,
                    StableId("one"), "A stale plan capability cannot mutate a revised declaration.",
                    idempotency_key=StableId("declaration-stale-plan-attempt"),
                    expected_revision=before,
                )
        self.assertEqual(f.revision(), before)
        with f.open_reader() as authority:
            facts = authority.connection.execute("SELECT count(*) FROM declaration_facts").fetchone()[0]
        self.assertEqual(facts, 0)


if __name__ == "__main__":
    unittest.main()
