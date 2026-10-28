"""Native declaration facts use exact accepted-plan payloads and normal auth."""

import json
import unittest
from datetime import timedelta
from dataclasses import replace
from unittest.mock import patch

from todo_orchestrator.authority import (
    CapabilityDeniedError,
    DeclarationMutationDeniedError,
    DeclarationService,
)
from todo_orchestrator.authority.attempts import AttemptAdmissionDeniedError, CLAIM_ACTION
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
    OutcomeDisposition,
    ProviderCallContext,
    ProviderIdentity,
    ProviderStatus,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.model import EligibilityRequest, EligibilityStatus
from todo_orchestrator.planning import ConditionResult, ConditionStatus
from todo_orchestrator.verification.acceptance import (
    ACCEPT_OUTCOME_ACTION,
    REPORT_CANDIDATE_ACTION,
    READ_OUTCOME_ACTION,
    CandidateDeniedError,
    OutcomeAcceptanceService,
)

from tests.verification.test_execution_independent import PROJECT, SOURCE_IDENTITY


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
                         BLOCKER_OPEN_ACTION, BLOCKER_CLEAR_ACTION, REPORT_CANDIDATE_ACTION,
                         ACCEPT_OUTCOME_ACTION, READ_OUTCOME_ACTION),
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

    def test_native_facts_load_verified_plan_once_and_ignore_caller_payload(self):
        f = self.fixture
        source = json.loads(self.package_with_decision())
        source["checkpoints"] = [{
            "id": f"runtime-checkpoint-{index:02d}",
            "title": f"Runtime checkpoint {index}",
            "acceptance": {
                "assertions": ["complete"], "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
            "unknowns": [], "producers": [],
        } for index in range(20)]
        plan, _ = self.commit_package(json.dumps(source, sort_keys=True), "declaration-batch-plan")

        module = __import__("todo_orchestrator.authority.declarations", fromlist=["unused"])
        original_loader = module.load_plan_revision_snapshot
        with f.open_reader() as authority:
            with patch.object(module, "load_plan_revision_snapshot", wraps=original_loader) as loader:
                observed, decisions = native_declaration_facts(authority.connection, plan)
            self.assertEqual(loader.call_count, 1)

            # The batch path returns the same current fact values as the exact
            # single-declaration API, which continues to validate each read.
            expected_conditions = {}
            expected_decisions = {}
            kind_by_section = {
                "decisions": "decision", "interfaces": "interface",
                "checkpoints": "checkpoint", "barriers": "barrier",
                "rendezvous": "rendezvous",
            }
            target_kind = {
                "decision": EntityKind.DECISION,
                "interface": EntityKind.INTERFACE,
                "checkpoint": EntityKind.CHECKPOINT,
                "barrier": EntityKind.BARRIER,
                "rendezvous": EntityKind.BARRIER,
            }
            for item in plan.declarations:
                kind = kind_by_section[item.kind]
                record = load_plan_declaration(
                    authority.connection, PROJECT, plan.revision.plan_revision_id,
                    kind, item.declaration_id,
                )
                condition, _version, option_id = declaration_condition(authority.connection, record)
                target = EntityRef(PROJECT.project_id, target_kind[kind], item.declaration_id)
                expected_conditions[target] = condition
                if kind == "decision":
                    status = (ConditionStatus.UNRESOLVED
                              if condition.status is ConditionStatus.UNSATISFIED
                              else condition.status)
                    from todo_orchestrator.authority.declarations import DecisionObservation
                    expected_decisions[str(item.declaration_id)] = DecisionObservation(status, option_id)
            self.assertEqual(dict(observed), expected_conditions)
            self.assertEqual(dict(decisions), expected_decisions)

            # A caller may retain a stale CompiledPlan. Its declaration payload
            # cannot invent a selected option or replace accepted contracts.
            forged = []
            for item in plan.declarations:
                payload = dict(item.payload)
                if item.kind == "decisions":
                    payload["selected_option_id"] = "one"
                if item.kind == "interfaces":
                    payload["contract"] = {"forged": True}
                forged.append(replace(item, payload=payload))
            untrusted_plan = replace(plan, declarations=tuple(forged))
            untrusted_facts, untrusted_decisions = native_declaration_facts(authority.connection, untrusted_plan)
            self.assertEqual(dict(untrusted_facts), expected_conditions)
            self.assertEqual(dict(untrusted_decisions), expected_decisions)
            self.assertEqual(untrusted_decisions["runtime-choice"].status, ConditionStatus.UNRESOLVED)

        # A real authority fact written after the first read is visible to the
        # next call, which still uses one verified accepted-plan load.
        decision = EntityRef(PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        with f.open_writer() as authority:
            self.service.resolve_decision(
                authority, f.owner.bearer_token, plan.revision.ref, decision,
                StableId("one"), "Resolve the current accepted declaration.",
                idempotency_key=StableId("declaration-batch-resolve"),
                expected_revision=f.revision(),
            )
        with f.open_reader() as authority:
            with patch.object(module, "load_plan_revision_snapshot", wraps=original_loader) as loader:
                current, current_decisions = native_declaration_facts(authority.connection, plan)
            self.assertEqual(loader.call_count, 1)
            self.assertEqual(current_decisions["runtime-choice"].status, ConditionStatus.SATISFIED)
            self.assertEqual(current[decision].status, ConditionStatus.SATISFIED)

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

    def test_interface_rendezvous_and_explicit_blocker_feed_native_facts(self):
        f = self.fixture
        source = json.loads(self.package_with_decision())
        source["rendezvous"] = [{
            "id": "owner-sync", "title": "Owner synchronization",
            "participants": [{
                "project_id": str(PROJECT.project_id), "kind": "work_item", "entity_id": "verify",
            }], "mode": "all",
        }]
        plan, _ = self.commit_package(json.dumps(source, sort_keys=True), "declaration-all-plan")
        decision = EntityRef(PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        interface = EntityRef(PROJECT.project_id, EntityKind.INTERFACE, StableId("runtime-api"))
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
            for target in (interface, rendezvous):
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

    def test_barrier_release_requires_exact_accepted_participant_outcomes_and_quorum(self):
        from tests.verification.test_acceptance_independent import BenchmarkVerifier, HOST_IDENTITY

        f = self.fixture
        document = json.loads(self.package_with_decision())
        participant_ids = ("barrier-a", "barrier-b", "barrier-c")
        for identifier in participant_ids:
            work = {
                "id": identifier,
                "title": identifier,
                "objective": "Satisfy an authored barrier participant.",
                "outcome": "The participant has an accepted outcome.",
                "scope": {"paths": [{"path": f"barriers/{identifier}", "access": "write"}],
                          "concepts": [], "locks": []},
                "ownership": {"mode": "any", "actors": []},
                "acceptance": {"assertions": ["outcome accepted"], "required_evidence": [],
                               "allowed_dispositions": ["completed"]},
            }
            if identifier == "barrier-c":
                work["requirement_groups"] = [{"kind": "check", "mode": "all",
                                                "members": ["barrier-benchmark"]}]
                work["acceptance"]["allowed_dispositions"] = ["evaluated_not_promoted"]
            document["work_items"].append(work)
        document["work_items"].append({
            "id": "barrier-dependent", "title": "Barrier dependent",
            "objective": "Wait for the authored all-participant barrier.",
            "outcome": "The barrier has been released after all participant outcomes.",
            "scope": {"paths": [{"path": "barriers/dependent", "access": "write"}],
                      "concepts": [], "locks": []},
            "ownership": {"mode": "any", "actors": []},
            "acceptance": {"assertions": ["barrier released"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
            "requirement_groups": [{"kind": "prerequisite", "mode": "all",
                                    "members": ["needs-barrier"]}],
        })
        document["requirements"].append({
            "id": "barrier-benchmark", "work_item_id": "barrier-c", "kind": "check",
            "description": "A definitive benchmark result is accepted by this participant's policy.",
            "check_key": "barrier-benchmark",
            "verification": {"kind": "benchmark", "version": 1, "config": {
                "metric": "latency", "operator": "lte", "threshold": 10.0,
                "unit": "ms", "minimum_samples": 2,
            }},
            "required_evidence": [{"name": "barrier-benchmark-report",
                                    "kind": "benchmark_sample", "version": 1}],
        })
        document["requirements"].append({
            "id": "needs-barrier", "work_item_id": "barrier-dependent", "kind": "prerequisite",
            "description": "All barrier participants must have an accepted outcome.",
            "target": {"project_id": str(PROJECT.project_id), "kind": "barrier", "entity_id": "all-three"},
        })
        def participant(identifier):
            return {"project_id": str(PROJECT.project_id), "kind": "work_item", "entity_id": identifier}

        document["barriers"] = [
            {"id": "all-three", "title": "All participants", "participants": [
                participant(identifier) for identifier in participant_ids
            ], "mode": "all"},
            {"id": "quorum-two", "title": "Two participants", "participants": [
                participant(identifier) for identifier in participant_ids
            ], "mode": "quorum", "quorum": 2},
        ]
        plan, _ = self.commit_package(json.dumps(document, sort_keys=True), "declaration-barrier-outcome-plan")
        f.plan = plan
        all_barrier = EntityRef(PROJECT.project_id, EntityKind.BARRIER, StableId("all-three"))
        quorum_barrier = EntityRef(PROJECT.project_id, EntityKind.BARRIER, StableId("quorum-two"))
        acceptance = OutcomeAcceptanceService(
            f.auth, source_observer=f.source, source_identity=SOURCE_IDENTITY,
            host=f.host, host_identity=HOST_IDENTITY, clock=f.clock,
        )

        def release(target, key):
            with f.open_writer() as authority:
                return self.service.release_barrier(
                    authority, f.owner.bearer_token, plan.revision.ref, target,
                    "The participant outcome condition has been met.",
                    idempotency_key=StableId(key), expected_revision=f.revision(),
                )

        before = f.revision()
        for target, key in ((all_barrier, "declaration-barrier-all-premature"),
                            (quorum_barrier, "declaration-barrier-quorum-premature")):
            with self.subTest(barrier=str(target.entity_id)):
                with self.assertRaises(DeclarationMutationDeniedError):
                    release(target, key)
                self.assertEqual(f.revision(), before)

        def accept_participant(identifier):
            ref = next(item.definition.ref for item in plan.work_items
                       if str(item.definition.work_item_id) == identifier)
            with f.open_writer() as authority:
                dispatched = f.coordination.dispatch(
                    authority, f.owner.bearer_token, plan,
                    workspace_id=StableId("barrier-workspace-" + identifier),
                    idempotency_key=StableId("barrier-dispatch-" + identifier),
                    expected_revision=f.revision(), work_item=ref,
                )
            disposition = OutcomeDisposition.COMPLETED
            if identifier == "barrier-c":
                requirement = next(item.definition.ref for item in plan.requirements
                                   if str(item.definition.requirement_id) == "barrier-benchmark")
                f.verification.provider = BenchmarkVerifier(f.ledger_path, f.clock)
                with f.open_writer() as authority:
                    checked = f.verification.execute(
                        authority, dispatched.bearer_token, dispatched.attempt.ref, requirement,
                        idempotency_key=StableId("barrier-verify-" + identifier),
                        expected_revision=f.revision(),
                    )
                self.assertEqual(checked.state, "rejected")
                disposition = OutcomeDisposition.EVALUATED_NOT_PROMOTED
            with f.open_writer() as authority:
                _reported, candidate = acceptance.report_candidate(
                    authority, dispatched.bearer_token, dispatched.attempt.ref,
                    disposition,
                    idempotency_key=StableId("barrier-report-" + identifier),
                    expected_revision=f.revision(),
                )
            with f.open_writer() as authority:
                acceptance.accept_candidate(
                    authority, f.owner.bearer_token, dispatched.attempt.ref, candidate,
                    idempotency_key=StableId("barrier-accept-" + identifier),
                    expected_revision=f.revision(),
                )

        accept_participant("barrier-a")
        accept_participant("barrier-b")
        release(quorum_barrier, "declaration-barrier-quorum-success")
        with f.open_reader() as authority:
            conditions, _ = native_declaration_facts(authority.connection, plan)
            self.assertIs(conditions[quorum_barrier].status, ConditionStatus.SATISFIED)
            self.assertIs(conditions[all_barrier].status, ConditionStatus.UNRESOLVED)
        dependent = next(item.definition.ref for item in plan.work_items
                         if str(item.definition.work_item_id) == "barrier-dependent")
        before_blocked_admission = f.revision()
        with f.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError):
                f.attempts.claim(
                    authority, f.owner.bearer_token, dependent, plan,
                    idempotency_key=StableId("declaration-barrier-dependent-before-all"),
                    expected_revision=before_blocked_admission,
                    workspace_id=StableId("declaration-barrier-dependent-workspace"),
                )
        self.assertEqual(f.revision(), before_blocked_admission)
        with self.assertRaises(DeclarationMutationDeniedError):
            release(all_barrier, "declaration-barrier-all-short")
        accept_participant("barrier-c")
        release(all_barrier, "declaration-barrier-all-success")

        with f.open_writer() as authority:
            admitted = f.attempts.claim(
                authority, f.owner.bearer_token, dependent, plan,
                idempotency_key=StableId("declaration-barrier-dependent-after-all"),
                expected_revision=f.revision(),
                workspace_id=StableId("declaration-barrier-dependent-workspace"),
            )
        self.assertEqual(admitted.receipt.result["state"], "admitted")

        with f.open_reader() as authority:
            all_record = load_plan_declaration(
                authority.connection, PROJECT, plan.revision.plan_revision_id, "barrier", StableId("all-three"),
            )
            quorum_record = load_plan_declaration(
                authority.connection, PROJECT, plan.revision.plan_revision_id, "barrier", StableId("quorum-two"),
            )
            self.assertEqual(declaration_condition(authority.connection, all_record)[0].status,
                             ConditionStatus.SATISFIED)
            self.assertEqual(declaration_condition(authority.connection, quorum_record)[0].status,
                             ConditionStatus.SATISFIED)
            observed_conditions, _ = native_declaration_facts(authority.connection, plan)
            self.assertIs(observed_conditions[all_barrier].status, ConditionStatus.SATISFIED)
            self.assertIs(observed_conditions[quorum_barrier].status, ConditionStatus.SATISFIED)

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
        worker_request = DeclarationObservationRequest(
            ProviderCallContext(PROJECT.project_id, dispatched.attempt.actor,
                                dispatched.capability.ref, StableId("native-declaration-context"),
                                StableId("native-declaration-scope")),
            StableId("native-declaration-before"), dispatched.attempt.ref,
            StableId("declaration-checkpoint-workspace"), plan.revision.plan_revision_id,
            checkpoint, DeclarationKind.CHECKPOINT, Sha256Digest(declaration.digest),
        )
        # Native observation never treats a capability reference as authority
        # by itself. The worker grant cannot impersonate the approver.
        self.assertEqual(observer.observe_declaration(worker_request).status, ProviderStatus.UNKNOWN)
        missing = observer.observe_declaration(replace(
            worker_request, authorization_action=ACCEPT_OUTCOME_ACTION,
        ))
        self.assertEqual(missing.status, ProviderStatus.UNKNOWN)

        owner_capability = f.owner.capability
        request = DeclarationObservationRequest(
            ProviderCallContext(
                PROJECT.project_id, owner_capability.actor,
                EntityRef(PROJECT.project_id, EntityKind.CAPABILITY, owner_capability.capability_id),
                StableId("native-declaration-owner-context"), StableId("native-declaration-owner-scope"),
            ),
            StableId("native-declaration-owner-before"), dispatched.attempt.ref,
            StableId("declaration-checkpoint-workspace"), plan.revision.plan_revision_id,
            checkpoint, DeclarationKind.CHECKPOINT, Sha256Digest(declaration.digest),
            authorization_action=ACCEPT_OUTCOME_ACTION,
        )
        self.assertEqual(observer.observe_declaration(request).status, ProviderStatus.UNKNOWN)

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

    def test_canonical_decision_fact_controls_advisory_and_attempt_admission(self):
        f = self.fixture
        document = json.loads(self.package_with_decision())
        verify = next(item for item in document["work_items"] if item["id"] == "verify")
        verify["requirement_groups"].append({
            "kind": "prerequisite", "mode": "all", "members": ["needs-decision"],
        })
        document["requirements"].append({
            "id": "needs-decision", "work_item_id": "verify", "kind": "prerequisite",
            "description": "The decision must be authoritatively resolved",
            "target": {"project_id": str(PROJECT.project_id), "kind": "decision", "entity_id": "runtime-choice"},
        })
        plan, _ = self.commit_package(json.dumps(document, sort_keys=True), "declaration-admission-plan")
        target = next(item.definition.ref for item in plan.work_items
                      if str(item.definition.work_item_id) == "verify")
        decision = EntityRef(PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        request = EligibilityRequest(target, f.owner.capability.actor, CLAIM_ACTION, f.revision())

        # A caller-provided SATISFIED observation cannot replace unresolved
        # canonical state from the accepted declaration snapshot.
        with f.open_reader() as authority:
            advisory = f.attempts.eligibility.evaluate_read(
                authority, request, plan,
                blocker_observations={decision: ConditionResult(ConditionStatus.SATISFIED)},
            )
        self.assertIs(advisory.status, EligibilityStatus.UNKNOWN)
        before_denied = f.revision()
        with f.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError):
                f.attempts.claim(
                    authority, f.owner.bearer_token, target, plan,
                    idempotency_key=StableId("declaration-admission-before-resolution"),
                    expected_revision=before_denied, workspace_id=StableId("declaration-admission-workspace"),
                )
        self.assertEqual(f.revision(), before_denied)

        with f.open_writer() as authority:
            self.service.resolve_decision(
                authority, f.owner.bearer_token, plan.revision.ref, decision,
                StableId("one"), "Select the declared option before admission.",
                idempotency_key=StableId("declaration-admission-resolution"),
                expected_revision=f.revision(),
            )
        request = replace(request, expected_revision=f.revision())
        with f.open_reader() as authority:
            advisory = f.attempts.eligibility.evaluate_read(
                authority, request, plan,
                blocker_observations={decision: ConditionResult(ConditionStatus.UNRESOLVED)},
            )
        self.assertIs(advisory.status, EligibilityStatus.ALLOWED)
        with f.open_writer() as authority:
            admitted = f.attempts.claim(
                authority, f.owner.bearer_token, target, plan,
                idempotency_key=StableId("declaration-admission-after-resolution"),
                expected_revision=f.revision(), workspace_id=StableId("declaration-admission-workspace"),
            )
        self.assertEqual(admitted.receipt.result["state"], "admitted")

    def test_v03_acceptance_rechecks_native_checkpoint_facts_in_writer(self):
        f = self.fixture
        document = json.loads(self.package_with_decision())
        document["checkpoints"] = [{
            "id": "release-check", "title": "Release check",
            "acceptance": {"assertions": ["the gate is accepted"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
            "unknowns": [], "producers": [],
        }]
        verify = next(item for item in document["work_items"] if item["id"] == "verify")
        verify["requirement_groups"].append({
            "kind": "prerequisite", "mode": "all", "members": ["needs-checkpoint"],
        })
        document["requirements"].append({
            "id": "needs-checkpoint", "work_item_id": "verify", "kind": "prerequisite",
            "description": "The checkpoint must be accepted",
            "target": {"project_id": str(PROJECT.project_id), "kind": "checkpoint", "entity_id": "release-check"},
        })
        plan, _ = self.commit_package(json.dumps(document, sort_keys=True), "declaration-v03-plan")
        f.plan = plan
        target = next(item.definition.ref for item in plan.work_items
                      if str(item.definition.work_item_id) == "verify")
        checkpoint = EntityRef(PROJECT.project_id, EntityKind.CHECKPOINT, StableId("release-check"))

        before_denied = f.revision()
        with f.open_writer() as authority:
            with self.assertRaises(AttemptAdmissionDeniedError):
                f.attempts.claim(
                    authority, f.owner.bearer_token, target, plan,
                    idempotency_key=StableId("declaration-v03-claim-before-gate"),
                    expected_revision=before_denied, workspace_id=StableId("declaration-v03-workspace"),
                )
        self.assertEqual(f.revision(), before_denied)

        with f.open_writer() as authority:
            self.service.accept_checkpoint(
                authority, f.owner.bearer_token, plan.revision.ref, checkpoint, (),
                "The empty-evidence checkpoint is explicitly accepted.",
                idempotency_key=StableId("declaration-v03-gate-accept"), expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            dispatched = f.coordination.dispatch(
                authority, f.owner.bearer_token, plan,
                workspace_id=StableId("declaration-v03-workspace"), work_item=target,
                idempotency_key=StableId("declaration-v03-dispatch"), expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            verified = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"), idempotency_key=StableId("declaration-v03-verify"),
                expected_revision=f.revision(),
            )
        self.assertEqual(verified.state, "finalized")

        from tests.verification.test_execution_independent import SOURCE_IDENTITY
        acceptance = OutcomeAcceptanceService(
            f.auth, source_observer=f.source, source_identity=SOURCE_IDENTITY,
            host=f.host, host_identity=ProviderIdentity(StableId("v02-attempt-host"), "1"),
            clock=f.clock, max_observation_age=timedelta(minutes=5),
        )
        with f.open_writer() as authority:
            _reported, candidate = acceptance.report_candidate(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                OutcomeDisposition.COMPLETED, idempotency_key=StableId("declaration-v03-report"),
                expected_revision=f.revision(),
            )

        with f.open_writer() as authority:
            self.service.open_blocker(
                authority, f.owner.bearer_token, plan.revision.ref, checkpoint,
                "The checkpoint is under renewed review.",
                idempotency_key=StableId("declaration-v03-gate-block"), expected_revision=f.revision(),
            )
        before_refusal = f.revision()
        with f.open_writer() as authority:
            with self.assertRaises(CandidateDeniedError):
                acceptance.accept_candidate(
                    authority, f.owner.bearer_token, dispatched.attempt.ref, candidate,
                    idempotency_key=StableId("declaration-v03-refuse-open-gate"),
                    expected_revision=before_refusal,
                )
        self.assertEqual(f.revision(), before_refusal)
        with f.open_reader() as authority:
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 0)
            self.assertEqual(authority.connection.execute(
                "SELECT state FROM outcome_candidates WHERE candidate_id = ?", (str(candidate.entity_id),)
            ).fetchone()[0], "pending")

        with f.open_writer() as authority:
            self.service.clear_blocker(
                authority, f.owner.bearer_token, plan.revision.ref, checkpoint,
                "Review completed; the accepted checkpoint remains current.",
                idempotency_key=StableId("declaration-v03-gate-clear"), expected_revision=f.revision(),
            )
        with f.open_writer() as authority:
            accepted = acceptance.accept_candidate(
                authority, f.owner.bearer_token, dispatched.attempt.ref, candidate,
                idempotency_key=StableId("declaration-v03-accept-after-clear"), expected_revision=f.revision(),
            )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        with f.open_reader() as authority:
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 1)
            outcome_id = authority.connection.execute("SELECT outcome_id FROM outcomes").fetchone()[0]
            applicability = acceptance.read_outcome_applicability(
                authority,
                EntityRef(PROJECT.project_id, EntityKind.OUTCOME, StableId(outcome_id)),
                bearer_token=f.owner.bearer_token,
            )
        self.assertEqual(applicability.status, "applicable")


if __name__ == "__main__":
    unittest.main()
