"""Focused outcome history/applicability regressions."""

from dataclasses import replace
import json
from types import SimpleNamespace
import unittest

from todo_orchestrator.contracts import (
    DeclarationObservation, DeclarationStatus, EntityKind, EntityRef, ProviderIdentity,
    OutcomeDisposition, ProviderReceipt, ProviderResult, ProviderStatus, Sha256Digest, StableId,
    provider_request_digest,
)
from todo_orchestrator.coordination.payloads import PayloadRejectedError
from todo_orchestrator.planning import compile_plan_json
from todo_orchestrator.verification.acceptance import (
    ACCEPT_OUTCOME_ACTION, CandidateObservationMismatchError, _declaration_result,
)

from tests.verification import test_acceptance_independent as acceptance_fixtures
from tests.verification.test_execution_independent import FixtureSourceObserver, PROJECT, package_json


class OutcomeApplicabilityTests(unittest.TestCase):
    def test_candidate_note_rejects_issued_bearer_without_authority_churn(self):
        fixture_case = acceptance_fixtures.IndependentOutcomeAcceptanceTests()
        fixture_case.setUp()
        self.addCleanup(fixture_case.doCleanups)
        f = fixture_case.fixture
        dispatched = fixture_case.dispatch("verify", "payload-note-dispatch")
        before = fixture_case.snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(PayloadRejectedError):
                fixture_case.acceptance.report_candidate(
                    authority,
                    dispatched.bearer_token,
                    dispatched.attempt.ref,
                    OutcomeDisposition.COMPLETED,
                    idempotency_key=StableId("payload-note-report"),
                    expected_revision=f.revision(),
                    note=f"Do not share this credential: {dispatched.bearer_token}",
                )
        self.assertEqual(fixture_case.snapshot(), before)

    def test_declaration_receipts_bind_exact_payload_and_report_typed_status(self):
        fixture_case = acceptance_fixtures.IndependentOutcomeAcceptanceTests()
        fixture_case.setUp()
        self.addCleanup(fixture_case.doCleanups)
        f = fixture_case.fixture
        document = json.loads(package_json())
        document["checkpoints"] = [{
            "id": "tested", "title": "Tests accepted",
            "acceptance": {"assertions": ["all tests pass"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
            "unknowns": [], "producers": [],
        }]
        requirement = next(item for item in document["requirements"] if item["id"] == "needs-base")
        requirement["target"] = {
            "project_id": str(PROJECT.project_id), "kind": "checkpoint", "entity_id": "tested",
        }
        compiled = compile_plan_json(json.dumps(document), PROJECT)
        self.assertTrue(compiled.ok, compiled.diagnostics)
        plan = compiled.plan
        work = next(item.definition for item in plan.work_items if item.definition.ref.entity_id == StableId("blocked"))
        reference = next(item.target.reference for item in plan.requirements
                         if item.definition.requirement_id == StableId("needs-base"))
        identity = ProviderIdentity(StableId("test-declaration-status"), "1")

        class Observer:
            status = DeclarationStatus.SATISFIED
            request = None

            def observe_declaration(self, request):
                self.request = request
                observation = DeclarationObservation(
                    request.target, request.declaration_kind, request.declaration_digest, self.status,
                )
                receipt = ProviderReceipt(
                    StableId("declaration-receipt"), identity, request.correlation_id,
                    provider_request_digest(request), request.correlation_id, f.clock(),
                )
                return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.correlation_id,
                                      identity, observation, receipt)

        observer = Observer()
        fixture_case.acceptance.declaration_observer = observer
        fixture_case.acceptance.declaration_identity = identity
        attempt = EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, StableId("declaration-attempt"))
        actor = EntityRef(PROJECT.project_id, EntityKind.ACTOR, StableId("worker"), incarnation_id=StableId("worker-inc"))
        workspace = SimpleNamespace(workspace_id=StableId("declaration-workspace"))
        records = fixture_case.acceptance._observe_declarations(
            plan, work.ref, attempt, workspace, plan.revision.plan_revision_id, actor,
            StableId("declaration-capability"), "test-positive", f.clock(),
        )
        statuses = fixture_case.acceptance._validated_declaration_statuses(plan, work.ref, records, f.clock())
        decision = _declaration_result(None, plan, reference, "checkpoints", trusted_statuses=statuses)
        self.assertEqual(decision.status.value, "satisfied")
        self.assertEqual(observer.request.plan_revision_id, plan.revision.plan_revision_id)

        observer.status = DeclarationStatus.UNSATISFIED
        negative_records = fixture_case.acceptance._observe_declarations(
            plan, work.ref, attempt, workspace, plan.revision.plan_revision_id, actor,
            StableId("declaration-capability"), "test-negative", f.clock(),
        )
        negative = _declaration_result(None, plan, reference, "checkpoints",
            trusted_statuses=fixture_case.acceptance._validated_declaration_statuses(
                plan, work.ref, negative_records, f.clock(),
            ))
        self.assertEqual(negative.status.value, "unsatisfied")

        tampered = [dict(records[0], declaration_digest="f" * 64)]
        with self.assertRaises(CandidateObservationMismatchError):
            fixture_case.acceptance._validated_declaration_statuses(plan, work.ref, tampered, f.clock())

    def test_later_source_change_stales_applicability_without_rewriting_accepted_history(self):
        fixture_case = acceptance_fixtures.IndependentOutcomeAcceptanceTests()
        fixture_case.setUp()
        self.addCleanup(fixture_case.doCleanups)
        f = fixture_case.fixture
        dispatched = fixture_case.dispatch("verify", "applicability-dispatch")
        with f.open_writer() as authority:
            checked = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"), idempotency_key=StableId("applicability-check"),
                expected_revision=f.revision(),
            )
        self.assertEqual(checked.state, "finalized")
        from todo_orchestrator.contracts import OutcomeDisposition
        _, candidate = fixture_case.report(dispatched.bearer_token, dispatched.attempt.ref,
                                           OutcomeDisposition.COMPLETED, "applicability-report")
        approver = fixture_case.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"), "applicability-approver",
        )
        fixture_case.accept(approver.bearer_token, dispatched.attempt.ref, candidate, "applicability-accept")
        with f.open_reader() as authority:
            outcome_id = authority.connection.execute("SELECT outcome_id FROM outcomes").fetchone()[0]
        outcome_ref = EntityRef(PROJECT.project_id, EntityKind.OUTCOME, StableId(outcome_id))
        with f.open_reader() as authority:
            current = fixture_case.acceptance.read_outcome_applicability(
                authority, outcome_ref, bearer_token=f.owner.bearer_token,
            )
        self.assertTrue(current.applicable, current.reasons)

        class ChangedSource(FixtureSourceObserver):
            def observe(self, request):
                result = super().observe(request)
                changed = replace(
                    result.value,
                    source_digest=Sha256Digest("5" * 64),
                    inputs=(replace(result.value.inputs[0], digest=Sha256Digest("c" * 64)),),
                )
                return replace(result, value=changed)

        fixture_case.acceptance.source_observer = ChangedSource(f.clock)
        with f.open_reader() as authority:
            stale = fixture_case.acceptance.read_outcome_applicability(
                authority, outcome_ref, bearer_token=f.owner.bearer_token,
            )
        self.assertFalse(stale.applicable)
        self.assertIn("source identity", " ".join(stale.reasons))
        with f.open_reader() as authority:
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 1)
            self.assertEqual(authority.connection.execute("SELECT state FROM outcome_candidates").fetchone()[0], "accepted")


if __name__ == "__main__":
    unittest.main()
