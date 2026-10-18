"""Independent V01 checks across typed criteria, plan snapshots, and authority."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AuthenticatedPrincipal,
    AuthorityAuthService,
    CapabilityDeniedError,
    CommandDispatcher,
    SQLiteAuthority,
)
from todo_orchestrator.authority.sqlite import load_plan_revision_snapshot
from todo_orchestrator.contracts import (
    ActorKind,
    EvidenceKind,
    Outcome,
    OutcomeDisposition,
    Project,
    StableId,
    VerificationContract,
    VerificationKind,
)
from todo_orchestrator.planning import (
    PlanCommitError,
    PlanService,
    accepted_plan_payload,
    compile_plan_json,
    decode_accepted_plan,
    parse_plan_json,
)


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("verification-independent-project"),
                  StableId("verification-independent-authority"))
OWNER_PASSWORD = "verification fixture owner credential 927"
PLAN_COMMIT = StableId("todo.plan.commit")
CAPABILITY_DELEGATE = StableId("todo.capability.delegate")
CAPABILITY_REVOKE = StableId("todo.capability.revoke")


class FixedClock:
    def __call__(self):
        return NOW


class FixtureAuthenticator:
    provider_id = "verification-independent-provider"

    def authenticate(self, credential):
        if credential == "verification-worker":
            return AuthenticatedPrincipal("verification-worker-subject", ActorKind.AUTOMATION,
                                          "verification worker")
        return None


def verification_contracts():
    """Nine deliberately minimal v1 configurations, omitting optional defaults."""
    return (
        ("command-check", "command", {
            "argv": ["python", "-m", "unittest"],
        }, "command_result"),
        ("file-check", "file", {
            "path": "reports/summary.txt", "predicate": "exists",
        }, "file_observation"),
        ("artifact-check", "artifact", {
            "artifact_kind": "verification-report", "predicate": "exists",
        }, "artifact_reference"),
        ("benchmark-check", "benchmark", {
            "metric": "throughput", "operator": "gte", "threshold": 1.0, "unit": "items/s",
        }, "benchmark_sample"),
        ("predicate-check", "predicate", {
            "name": "result-present", "semantics_version": 1,
            "operator": "nonempty", "expected": None,
        }, "predicate_result"),
        ("interface-check", "interface", {
            "interface_id": "public-api", "version": "1.2.0", "compatibility": "frozen",
        }, "interface_observation"),
        ("checkpoint-check", "checkpoint", {
            "checkpoint_id": "release-ready", "required_state": "accepted",
        }, "checkpoint_receipt"),
        ("manual-owner-check", "manual_owner", {
            "approver_role": "owner", "actor_id": "owner-actor", "incarnation_id": "owner-incarnation",
        }, "manual_attestation"),
        ("provider-check", "domain_provider", {
            "provider_id": "domain-checker", "provider_version": "2.1",
            "contract_id": "science-result", "contract_version": 1, "parameters": {"mode": "strict"},
        }, "provider_receipt"),
    )


def package_document():
    contracts = verification_contracts()
    requirement_ids = [item[0] for item in contracts]
    return {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "verification-independent-plan",
        "project": {"project_id": str(PROJECT.project_id), "authority_id": str(PROJECT.authority_id)},
        "work_items": [{
            "id": "verification-work",
            "title": "Verify an independently authored result",
            "objective": "Keep verification criteria explicit and versioned",
            "outcome": "The accepted result records current typed evidence",
            "scope": {"paths": [], "concepts": ["verification"]},
            "acceptance": {
                "assertions": ["required criteria are satisfied"],
                "required_evidence": [],
                "allowed_dispositions": [
                    "completed", "accepted_negative", "no_change", "evaluated_not_promoted",
                ],
            },
            "requirement_groups": [{"kind": "check", "mode": "all", "members": requirement_ids}],
        }],
        "requirements": [{
            "id": requirement_id,
            "work_item_id": "verification-work",
            "kind": "check",
            "description": f"Check {kind} result",
            "check_key": f"check-{requirement_id}",
            "verification": {"kind": kind, "version": 1, "config": deepcopy(config)},
            "required_evidence": [{"name": f"evidence-{requirement_id}", "kind": evidence_kind,
                                   "version": 1}],
        } for requirement_id, kind, config, evidence_kind in contracts],
    }


class VerificationRequirementsIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(
            self.dispatcher, clock=FixedClock(), authenticator=FixtureAuthenticator(),
        )
        self.plans = PlanService(self.auth)
        with self.open_writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="verification fixture owner",
                idempotency_key=StableId("verification-owner-enrollment"), expected_revision=0,
            )
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD,
                actions=(PLAN_COMMIT, CAPABILITY_DELEGATE, CAPABILITY_REVOKE,
                         StableId("todo.attempt.claim")), scope=PROJECT.ref,
                expires_at=NOW + timedelta(days=1),
                idempotency_key=StableId("verification-owner-token"),
                expected_revision=enrollment.receipt.semantic_revision,
            )

    def open_writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def open_reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    def state_snapshot(self):
        with self.open_reader() as authority:
            fingerprint = self.dispatcher.logical_fingerprint(authority)
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            counts = tuple(
                (table, authority.connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
                for table in (
                    "plan_revisions", "plan_revision_snapshots", "requirements",
                    "command_receipts", "command_idempotency", "authority_events",
                )
            )
        return fingerprint, revision, counts

    def commit_plan(self, document, key):
        package_json = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with self.open_writer() as authority:
            preview = self.plans.preview(authority, package_json)
            result = self.plans.commit(
                authority, self.owner.bearer_token, package_json,
                reviewed_digest=preview.digest,
                idempotency_key=StableId(key),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
        return package_json, preview, result

    def test_all_nine_versioned_contracts_and_default_configs_roundtrip(self):
        self.assertEqual({kind.value for kind in VerificationKind}, {
            "command", "file", "artifact", "benchmark", "predicate", "interface",
            "checkpoint", "manual_owner", "domain_provider",
        })
        for requirement_id, kind_name, config, _ in verification_contracts():
            with self.subTest(kind=kind_name):
                contract = VerificationContract.from_mapping({
                    "kind": kind_name, "version": 1, "config": deepcopy(config),
                })
                restored = VerificationContract.from_mapping(contract.to_mapping())
                direct_restored = VerificationContract(
                    contract.kind, contract.version, contract.config,
                )
                self.assertEqual(restored, contract)
                self.assertEqual(direct_restored, contract)
                self.assertEqual(contract.kind.value, kind_name)
                self.assertEqual(contract.version, 1)
                self.assertTrue(contract.config)

        # Repository root is a valid command working directory and normalizes
        # through the same typed public mapping as every other config.
        root_command = VerificationContract.from_mapping({
            "kind": "command", "version": 1,
            "config": {"argv": ["python", "-m", "unittest"], "cwd": "."},
        })
        self.assertEqual(VerificationContract.from_mapping(root_command.to_mapping()), root_command)
        self.assertEqual(root_command.config["cwd"], ".")

    def test_typed_requirement_evidence_roundtrips_through_accepted_sqlite_snapshot(self):
        document = package_document()
        package_json, preview, committed = self.commit_plan(document, "verification-initial-plan")
        self.assertTrue(committed.receipt.changed)
        self.assertNotEqual(preview.digest.hex, "")

        with self.open_reader() as authority:
            accepted = self.plans.load_accepted_plan(authority)
            self.assertIsNotNone(accepted)
            record = load_plan_revision_snapshot(
                authority.connection, PROJECT, accepted.revision.plan_revision_id,
            )
            decoded = decode_accepted_plan(record.canonical_json, PROJECT, sequence=accepted.revision.sequence)
            self.assertEqual(accepted_plan_payload(decoded), accepted_plan_payload(accepted))
            self.assertEqual(len(accepted.requirements), 9)
            expected = {
                requirement_id: (kind, VerificationContract.from_mapping({
                    "kind": kind, "version": 1, "config": config,
                }).to_mapping(), evidence_kind)
                for requirement_id, kind, config, evidence_kind in verification_contracts()
            }
            actual = {str(item.definition.requirement_id): item for item in accepted.requirements}
            self.assertEqual(set(actual), set(expected))
            for requirement_id, (kind, config, evidence_kind) in expected.items():
                with self.subTest(requirement=requirement_id):
                    requirement = actual[requirement_id].definition
                    self.assertEqual(requirement.verification.kind.value, kind)
                    self.assertEqual(requirement.verification.to_mapping()["config"], config["config"])
                    self.assertEqual(len(requirement.required_evidence), 1)
                    self.assertEqual(requirement.required_evidence[0].kind.value, evidence_kind)
                    self.assertEqual(requirement.required_evidence[0].version, 1)
                    row = authority.connection.execute(
                        "SELECT verification_json, required_evidence_json FROM requirements "
                        "WHERE requirement_id = ? AND definition_revision_id = ?",
                        (requirement_id, str(requirement.definition_revision_id)),
                    ).fetchone()
                    self.assertEqual(json.loads(row[0]), requirement.verification.to_mapping())
                    self.assertEqual(json.loads(row[1]), [item.to_mapping() for item in requirement.required_evidence])

    def test_unsupported_versions_and_untyped_runner_fields_are_rejected(self):
        cases = (
            ("command-check", "contract version", lambda item: item["verification"].update(version=2)),
            ("predicate-check", "predicate semantics", lambda item: item["verification"]["config"].update(semantics_version=2)),
            ("command-check", "unknown command field", lambda item: item["verification"]["config"].update(shell=True)),
            ("command-check", "unknown evidence field", lambda item: item["required_evidence"][0].update(path="secret.txt")),
            ("interface-check", "interface version leading zero", lambda item: item["verification"]["config"].update(version="01.2")),
            ("interface-check", "interface version too many components", lambda item: item["verification"]["config"].update(version="1.2.3.4")),
        )
        base = package_document()
        for requirement_id, label, mutate in cases:
            with self.subTest(case=label):
                document = deepcopy(base)
                requirement = next(item for item in document["requirements"]
                                   if item["id"] == requirement_id)
                mutate(requirement)
                result = parse_plan_json(json.dumps(document, sort_keys=True))
                self.assertFalse(result.ok)
                self.assertTrue(any(item.severity.value == "error" for item in result.diagnostics))

    def test_contract_tampering_changes_review_digest_and_worker_cannot_weaken_it(self):
        baseline = package_document()
        self.commit_plan(baseline, "verification-protected-plan")
        worker_actions = (StableId("todo.attempt.claim"),)
        with self.open_writer() as authority:
            self.worker = self.auth.delegate(
                authority, self.owner.bearer_token, "verification-worker",
                actions=worker_actions, scope=PROJECT.ref,
                expires_at=NOW + timedelta(hours=1),
                idempotency_key=StableId("verification-worker-token"),
            )

        weakened = deepcopy(baseline)
        target = next(item for item in weakened["requirements"] if item["id"] == "benchmark-check")
        target["verification"]["config"]["threshold"] = 0.0
        target["required_evidence"] = []
        package_json = json.dumps(weakened, ensure_ascii=False, sort_keys=True)
        with self.open_writer() as authority:
            current = self.plans.preview(authority, json.dumps(baseline, sort_keys=True))
            altered = self.plans.preview(authority, package_json)
        self.assertNotEqual(altered.digest, current.digest)

        before = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(PlanCommitError):
                self.plans.commit(
                    authority, self.owner.bearer_token, package_json,
                    reviewed_digest=current.digest,
                    idempotency_key=StableId("verification-tampered-owner-review"),
                    expected_authority_revision=current.expected_authority_revision,
                    expected_plan_revision_id=current.expected_revision_id,
                )
        self.assertEqual(self.state_snapshot(), before)

        with self.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.plans.commit(
                    authority, self.worker.bearer_token, package_json,
                    reviewed_digest=altered.digest,
                    idempotency_key=StableId("verification-untrusted-worker-weaken"),
                    expected_authority_revision=altered.expected_authority_revision,
                    expected_plan_revision_id=altered.expected_revision_id,
                )
        self.assertEqual(self.state_snapshot(), before)
        with self.open_reader() as authority:
            accepted = self.plans.load_accepted_plan(authority)
            accepted_benchmark = next(item for item in accepted.requirements
                                      if item.definition.requirement_id == StableId("benchmark-check"))
            self.assertEqual(accepted_benchmark.definition.verification.config["threshold"], 1.0)
            self.assertEqual(len(accepted_benchmark.definition.required_evidence), 1)

    def test_no_change_and_evaluated_not_promoted_are_not_failure_dispositions(self):
        compiled = compile_plan_json(json.dumps(package_document(), sort_keys=True), PROJECT)
        self.assertTrue(compiled.ok, compiled.diagnostics)
        acceptance = compiled.plan.work_items[0].context.acceptance
        allowed = set(acceptance["allowed_dispositions"])
        self.assertTrue({"no_change", "evaluated_not_promoted", "accepted_negative"} <= allowed)
        self.assertIs(OutcomeDisposition.NO_CHANGE, OutcomeDisposition("no_change"))
        self.assertIs(OutcomeDisposition.EVALUATED_NOT_PROMOTED,
                      OutcomeDisposition("evaluated_not_promoted"))
        self.assertIs(OutcomeDisposition.ACCEPTED_NEGATIVE, OutcomeDisposition("accepted_negative"))
        self.assertNotEqual(OutcomeDisposition.NO_CHANGE, OutcomeDisposition.FAILED)
        self.assertNotEqual(OutcomeDisposition.EVALUATED_NOT_PROMOTED, OutcomeDisposition.FAILED)
        work_ref = compiled.plan.work_items[0].definition.ref
        for version, disposition in enumerate((OutcomeDisposition.NO_CHANGE,
                                                OutcomeDisposition.EVALUATED_NOT_PROMOTED), start=1):
            outcome = Outcome(
                StableId(f"verification-outcome-{version}"), PROJECT.project_id, work_ref, version,
                disposition, self.owner.capability.actor, NOW,
            )
            self.assertIs(outcome.disposition, disposition)


if __name__ == "__main__":
    unittest.main()
