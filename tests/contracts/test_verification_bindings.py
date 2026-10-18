"""Independent checks for source and verification provider request bindings."""

from dataclasses import replace
import unittest

from todo_orchestrator.contracts import (
    EntityKind, EntityRef, EvidenceInput, EvidenceKind, EvidenceResult,
    EvidenceRequirement, DeclarationKind, DeclarationObservation, DeclarationObservationRequest,
    DeclarationStatus, ProviderCallContext, Sha256Digest, StableId,
    SourceObservationRequest, VerificationContract, VerificationEvidenceFact,
    VerificationKind, VerificationObservation, VerificationRequest,
    provider_request_digest,
)


def sid(value: str) -> StableId:
    return StableId(value)


def contract(kind: str = "file", *, path: str = "src/package.py") -> VerificationContract:
    if kind == "file":
        config = {"path": path, "predicate": "exists"}
    else:
        config = {"argv": ["python", "-m", "unittest"]}
    return VerificationContract.from_mapping({"kind": kind, "version": 1, "config": config})


def digest(char: str = "a") -> Sha256Digest:
    return Sha256Digest(char * 64)


class VerificationBindingContractTests(unittest.TestCase):
    def setUp(self):
        self.project = sid("binding-project")
        self.actor = EntityRef(self.project, EntityKind.ACTOR, sid("worker"), incarnation_id=sid("worker-inc"))
        self.capability = EntityRef(self.project, EntityKind.CAPABILITY, sid("worker-cap"))
        self.context = ProviderCallContext(self.project, self.actor, self.capability, sid("trusted-context"), sid("work-scope"))
        self.attempt = EntityRef(self.project, EntityKind.ATTEMPT, sid("attempt"))
        self.workspace = sid("workspace")
        self.target = EntityRef(self.project, EntityKind.WORK_ITEM, sid("work"), sid("work-definition"))
        self.requirement = EntityRef(self.project, EntityKind.REQUIREMENT, sid("check"), sid("work-definition"))
        self.contract = contract()
        self.evidence = (EvidenceRequirement(sid("result"), EvidenceKind.FILE_OBSERVATION),)

    def source_request(self, **changes):
        values = {
            "context": self.context,
            "correlation_id": sid("source-observation"),
            "expected_source": digest("a"),
            "attempt": self.attempt,
            "workspace_id": self.workspace,
            "target": self.target,
            "contract": self.contract,
        }
        values.update(changes)
        return SourceObservationRequest(**values)

    def verification_request(self, **changes):
        values = {
            "context": self.context,
            "attempt": self.attempt,
            "requirement": self.requirement,
            "operation_id": sid("verify-operation"),
            "idempotency_key": sid("verify-retry"),
            "verifier_id": sid("file-verifier"),
            "expected_source": digest("a"),
            "contract_digest": provider_request_digest(self.contract),
            "inputs": (EvidenceInput(sid("source"), digest("b")),),
            "contract": self.contract,
            "workspace_id": self.workspace,
            "verifier_version": "2.1",
            "required_evidence": self.evidence,
        }
        values.update(changes)
        return VerificationRequest(**values)

    def test_source_observation_requires_complete_project_local_attempt_binding(self):
        request = self.source_request()
        self.assertEqual(request.attempt, self.attempt)
        self.assertEqual(request.target, self.target)
        with self.assertRaisesRegex(ValueError, "supplied together"):
            self.source_request(attempt=None)
        with self.assertRaisesRegex(ValueError, "project-local attempt"):
            self.source_request(attempt=EntityRef(sid("other"), EntityKind.ATTEMPT, sid("attempt")))
        with self.assertRaisesRegex(ValueError, "project-local qualified work-item"):
            self.source_request(target=EntityRef(sid("other"), EntityKind.WORK_ITEM, sid("work"), sid("definition")))
        with self.assertRaisesRegex(ValueError, "project-local qualified work-item"):
            self.source_request(target=EntityRef(self.project, EntityKind.INTERFACE, sid("api")))
        with self.assertRaisesRegex(TypeError, "workspace_id"):
            self.source_request(workspace_id="workspace")
        with self.assertRaisesRegex(TypeError, "expected_source"):
            self.source_request(expected_source="a" * 64)

    def test_source_only_observation_binds_attempt_workspace_and_target_without_fake_contract(self):
        request = SourceObservationRequest(
            self.context, sid("source-only"), digest("a"), self.attempt,
            self.workspace, self.target, None,
        )
        self.assertIsNone(request.contract)
        self.assertNotEqual(
            provider_request_digest(request),
            provider_request_digest(replace(request, expected_source=digest("b"))),
        )
        with self.assertRaisesRegex(ValueError, "attempt, workspace_id, and target"):
            replace(request, target=None)

    def test_source_observation_request_digest_covers_all_source_binding_fields(self):
        original = self.source_request()
        original_digest = provider_request_digest(original)
        variants = (
            self.source_request(expected_source=digest("c")),
            self.source_request(correlation_id=sid("different-correlation")),
            self.source_request(attempt=EntityRef(self.project, EntityKind.ATTEMPT, sid("other-attempt"))),
            self.source_request(workspace_id=sid("other-workspace")),
            self.source_request(target=EntityRef(self.project, EntityKind.WORK_ITEM, sid("other-work"), sid("work-definition"))),
            self.source_request(contract=contract(path="src/other.py")),
        )
        for changed in variants:
            with self.subTest(changed=changed):
                self.assertNotEqual(provider_request_digest(changed), original_digest)
        self.assertEqual(provider_request_digest(self.source_request()), original_digest)

    def test_verification_request_binds_typed_contract_digest_and_exact_requirement(self):
        request = self.verification_request()
        self.assertEqual(request.requirement, self.requirement)
        with self.assertRaisesRegex(ValueError, "contract_digest does not match"):
            self.verification_request(contract_digest=digest("c"))
        with self.assertRaisesRegex(ValueError, "contract and workspace_id"):
            self.verification_request(workspace_id=None)
        with self.assertRaisesRegex(TypeError, "contract must be a VerificationContract"):
            self.verification_request(contract={"kind": "file"})
        with self.assertRaisesRegex(ValueError, "project"):
            self.verification_request(requirement=EntityRef(sid("other"), EntityKind.REQUIREMENT, sid("check"), sid("work-definition")))
        with self.assertRaisesRegex(ValueError, "requirement"):
            self.verification_request(requirement=EntityRef(self.project, EntityKind.WORK_ITEM, sid("work"), sid("work-definition")))
        duplicate_names = (self.evidence[0], EvidenceRequirement(sid("result"), EvidenceKind.ARTIFACT_REFERENCE))
        with self.assertRaisesRegex(ValueError, "must not repeat names"):
            self.verification_request(required_evidence=duplicate_names)

    def test_verification_provider_request_digest_changes_with_each_gate_binding(self):
        original = self.verification_request()
        original_digest = provider_request_digest(original)
        changed_contract = contract(path="src/changed.py")
        changed_contract_digest = provider_request_digest(changed_contract)
        changed_evidence = (EvidenceRequirement(sid("different-result"), EvidenceKind.FILE_OBSERVATION),)
        variants = (
            self.verification_request(operation_id=sid("other-operation")),
            self.verification_request(idempotency_key=sid("other-retry")),
            self.verification_request(verifier_id=sid("other-verifier")),
            self.verification_request(expected_source=digest("c")),
            self.verification_request(contract=changed_contract, contract_digest=changed_contract_digest),
            self.verification_request(workspace_id=sid("other-workspace")),
            self.verification_request(verifier_version="2.2"),
            self.verification_request(required_evidence=changed_evidence),
            self.verification_request(inputs=(EvidenceInput(sid("source"), digest("c")),)),
        )
        for changed in variants:
            with self.subTest(changed=changed):
                self.assertNotEqual(provider_request_digest(changed), original_digest)

    def test_named_evidence_facts_are_typed_versioned_and_unique_by_name(self):
        fact = VerificationEvidenceFact(sid("result"), EvidenceKind.FILE_OBSERVATION, 1, digest("c"))
        self.assertEqual(fact.version, 1)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            VerificationEvidenceFact(sid("bad-version"), EvidenceKind.FILE_OBSERVATION, 0, digest())
        with self.assertRaisesRegex(TypeError, "EvidenceKind"):
            VerificationEvidenceFact(sid("bad-kind"), "file_observation", 1, digest())
        duplicate = VerificationEvidenceFact(sid("result"), EvidenceKind.ARTIFACT_REFERENCE, 1, digest("d"))
        with self.assertRaisesRegex(ValueError, "must not repeat names"):
            VerificationObservation(
                sid("verify-operation"), EvidenceResult.PASS, sid("file-verifier"), "2.1",
                digest(), provider_request_digest(self.contract), (), (), (fact, duplicate),
            )

    def test_declaration_observation_binds_exact_accepted_plan_target_and_version(self):
        target = EntityRef(self.project, EntityKind.INTERFACE, sid("api-v1"))
        request = DeclarationObservationRequest(
            self.context, sid("declaration-query"), self.attempt, self.workspace,
            sid("plan-revision-7"), target, DeclarationKind.INTERFACE, digest("d"), "2.1",
        )
        observation = DeclarationObservation(
            target, DeclarationKind.INTERFACE, digest("d"), DeclarationStatus.SATISFIED, "2.2",
        )
        self.assertEqual(observation.target, request.target)
        original = provider_request_digest(request)
        for changed in (
            replace(request, correlation_id=sid("other-query")),
            replace(request, workspace_id=sid("other-workspace")),
            replace(request, plan_revision_id=sid("other-plan")),
            replace(request, target=EntityRef(self.project, EntityKind.INTERFACE, sid("other-api"))),
            replace(request, declaration_digest=digest("e")),
            replace(request, expected_version="3.0"),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(provider_request_digest(changed), original)
        with self.assertRaisesRegex(ValueError, "project"):
            replace(request, attempt=EntityRef(sid("other-project"), EntityKind.ATTEMPT, sid("attempt")))
        with self.assertRaisesRegex(ValueError, "project-local"):
            replace(request, target=EntityRef(sid("other-project"), EntityKind.INTERFACE, sid("api-v1")))


if __name__ == "__main__":
    unittest.main()
