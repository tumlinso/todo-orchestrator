"""Typed verification contract authoring and durable plan round trips."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, SQLiteAuthority
from todo_orchestrator.contracts import (
    EntityKind, EntityRef, EvidenceKind, Outcome, OutcomeDisposition, Project,
    StableId, VerificationContract, VerificationKind,
)
from todo_orchestrator.planning import PlanService, compile_plan_json


CONTRACTS = [
    {"kind": "command", "version": 1, "config": {"argv": ["python", "-m", "unittest"], "cwd": "."}},
    {"kind": "file", "version": 1, "config": {"path": "src/pkg.py", "predicate": "exists"}},
    {"kind": "artifact", "version": 1, "config": {"artifact_kind": "report", "predicate": "sha256", "sha256": "a" * 64}},
    {"kind": "benchmark", "version": 1, "config": {"metric": "latency", "operator": "lte", "threshold": 3.5, "unit": "ms", "minimum_samples": 4}},
    {"kind": "predicate", "version": 1, "config": {"name": "manifest-valid", "semantics_version": 1, "operator": "equals", "expected": True}},
    {"kind": "interface", "version": 1, "config": {"interface_id": "api-v1", "version": "1.2", "compatibility": "evolvable"}},
    {"kind": "checkpoint", "version": 1, "config": {"checkpoint_id": "qualified", "required_state": "accepted"}},
    {"kind": "manual_owner", "version": 1, "config": {"approver_role": "owner", "actor_id": "owner", "incarnation_id": "owner-inc"}},
    {"kind": "domain_provider", "version": 1, "config": {"provider_id": "git", "provider_version": "1.4.2", "contract_id": "clean-tree", "contract_version": 2, "parameters": {"branch": "main", "allow_untracked": False}}},
]


def package_document():
    return {
        "format": "todo-orchestrator.plan", "schema_version": 1, "package_id": "verification-contracts",
        "project": {"project_id": "verification-project", "authority_id": "verification-authority"},
        "work_items": [{
            "id": "work", "title": "Qualify work", "objective": "exercise typed criteria",
            "outcome": "all authored criteria survive commit and reopen",
            "scope": {"paths": [], "concepts": ["verification"]},
            "acceptance": {"assertions": ["contracts are immutable"], "required_evidence": [], "allowed_dispositions": ["completed", "no_change", "evaluated_not_promoted"]},
            "requirement_groups": [{"kind": "check", "mode": "all", "members": [f"check-{i}" for i in range(len(CONTRACTS))]}],
        }],
        "requirements": [{
            "id": f"check-{i}", "work_item_id": "work", "kind": "check", "description": f"check {i}",
            "check_key": f"check-{i}", "verification": contract,
            "required_evidence": [{"name": f"evidence-{i}", "kind": evidence_kind, "version": 1}],
        } for i, (contract, evidence_kind) in enumerate(zip(CONTRACTS, [kind.value for kind in EvidenceKind]))],
    }


class VerificationContractTests(unittest.TestCase):
    def test_all_nine_versioned_contracts_normalize_and_roundtrip(self):
        for raw in CONTRACTS:
            contract = VerificationContract.from_mapping(raw)
            self.assertEqual(VerificationContract.from_mapping(contract.to_mapping()), contract)
            self.assertEqual(contract.version, 1)
        self.assertEqual(len(VerificationKind), 9)

    def test_unsupported_versions_unknown_fields_and_unsafe_paths_fail_closed(self):
        cases = [
            {**CONTRACTS[0], "version": 2},
            {**CONTRACTS[1], "config": {"path": "../secret", "predicate": "exists"}},
            {**CONTRACTS[3], "config": {**CONTRACTS[3]["config"], "operator": "approximately"}},
            {**CONTRACTS[4], "config": {**CONTRACTS[4]["config"], "expression": "__import__('os')"}},
            {**CONTRACTS[5], "config": {**CONTRACTS[5]["config"], "version": "latest"}},
        ]
        for item in cases:
            with self.subTest(item=item), self.assertRaises(ValueError):
                VerificationContract.from_mapping(item)

    def test_plan_compilation_binds_contract_and_required_evidence(self):
        result = compile_plan_json(json.dumps(package_document()), target=Project(StableId("verification-project"), StableId("verification-authority")))
        self.assertTrue(result.ok, result.diagnostics)
        self.assertEqual(len(result.plan.requirements), len(CONTRACTS))
        normalized = [VerificationContract.from_mapping(value).to_mapping() for value in CONTRACTS]
        for index, requirement in enumerate(result.plan.requirements):
            self.assertEqual(requirement.definition.verification.to_mapping(), normalized[index])
            self.assertEqual(requirement.definition.required_evidence[0].name, StableId(f"evidence-{index}"))

    def test_authenticated_commit_reopens_exact_contracts_and_outcome_semantics(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "authority.sqlite3"
        project = Project(StableId("verification-project"), StableId("verification-authority"))
        SQLiteAuthority.initialize(path, project)
        authority = SQLiteAuthority.open_writer(path, project)
        self.addCleanup(authority.close)
        dispatcher = CommandDispatcher()
        now = datetime(2026, 10, 18, tzinfo=timezone.utc)
        auth = AuthorityAuthService(dispatcher, clock=lambda: now)
        enrollment = auth.enroll_local_owner(authority, "verification owner fixture phrase", label="owner", idempotency_key=StableId("enroll"), expected_revision=0)
        owner = auth.login_local_owner(authority, "verification owner fixture phrase", actions=(StableId("todo.plan.commit"),), expires_at=now + timedelta(days=1), idempotency_key=StableId("login"), expected_revision=enrollment.receipt.semantic_revision)
        service = PlanService(auth)
        text = json.dumps(package_document())
        preview = service.preview(authority, text)
        service.commit(authority, owner.bearer_token, text, reviewed_digest=preview.digest, idempotency_key=StableId("commit"), expected_authority_revision=preview.expected_authority_revision, expected_plan_revision_id=preview.expected_revision_id)
        authority.close()
        reopened = SQLiteAuthority.open_writer(path, project)
        self.addCleanup(reopened.close)
        accepted = service.load_accepted_plan(reopened)
        normalized = [VerificationContract.from_mapping(value).to_mapping() for value in CONTRACTS]
        self.assertEqual([item.definition.verification.to_mapping() for item in accepted.requirements], normalized)
        rows = reopened.connection.execute("SELECT verification_json, required_evidence_json FROM requirements ORDER BY requirement_id").fetchall()
        self.assertEqual(len(rows), len(CONTRACTS))
        self.assertTrue(all(json.loads(row[0]) is not None and len(json.loads(row[1])) == 1 for row in rows))

    def test_no_change_and_evaluated_not_promoted_are_not_failures(self):
        project_id = StableId("project")
        actor = EntityRef(project_id, EntityKind.ACTOR, StableId("owner"), incarnation_id=StableId("owner-inc"))
        work = EntityRef(project_id, EntityKind.WORK_ITEM, StableId("work"), StableId("definition"))
        common = dict(outcome_id=StableId("outcome"), project_id=project_id, work_item=work, version=1,
                      accepted_by=actor, accepted_at=datetime(2026, 10, 18, tzinfo=timezone.utc))
        no_change = Outcome(disposition=OutcomeDisposition.NO_CHANGE, **common)
        evaluated = Outcome(disposition=OutcomeDisposition.EVALUATED_NOT_PROMOTED, **common)
        failed = Outcome(disposition=OutcomeDisposition.FAILED, **common)
        self.assertNotEqual(no_change.disposition, failed.disposition)
        self.assertNotEqual(evaluated.disposition, failed.disposition)
        self.assertEqual(no_change.disposition.value, "no_change")
        self.assertEqual(evaluated.disposition.value, "evaluated_not_promoted")


if __name__ == "__main__":
    unittest.main()
