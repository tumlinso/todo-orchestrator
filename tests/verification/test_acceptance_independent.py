"""Independent public-path checks for candidate reporting and acceptance."""

from datetime import timedelta
import hashlib
import json
import unittest
from dataclasses import replace

from todo_orchestrator.authority import CapabilityDeniedError, IdempotencyConflictError, SQLiteAuthority
from todo_orchestrator.coordination import RUN_DISPATCH_ACTION
from todo_orchestrator.authority.attempts import (
    AttemptLeaseMismatchError,
    AttemptTransitionError,
    RECONCILE_ACTION,
    _stored_workspace,
)
from todo_orchestrator.contracts import (
    ArtifactAvailability, EntityKind, EntityRef, EvidenceInput, EvidenceKind, EvidenceResult, OutcomeDisposition,
    ProviderIdentity, ProviderReceipt, Sha256Digest, StableId, VerificationEvidenceFact,
    VerificationObservation, WorkingTreeState, provider_request_digest,
)
from todo_orchestrator.verification.acceptance import (
    ACCEPT_OUTCOME_ACTION,
    MANUAL_OWNER_ACTIONS,
    REJECT_CANDIDATE_ACTION,
    REPORT_CANDIDATE_ACTION,
    READ_OUTCOME_ACTION,
    CandidateDeniedError,
    CandidateObservationMismatchError,
    CandidateStateError,
    OutcomeAcceptanceService,
)
from todo_orchestrator.model import (
    AttemptAuthoringHandoff,
    AttemptAuthoringHandoffRequest,
    ProcessLiveness,
    authoring_handoff_request_digest,
)

from tests.verification.test_execution_independent import (
    CLAIM_ACTION,
    FINISH_ACTION,
    HEARTBEAT_ACTION,
    OWNER_ACTIONS,
    OWNER_PASSWORD,
    RELEASE_ACTION,
    VERIFICATION_ACTION,
    VERIFICATION_RECONCILE_ACTION,
    PROJECT,
    SOURCE_IDENTITY,
    FixtureSourceObserver,
    LedgerVerifier,
    VERIFIER_IDENTITY,
    _receipt_id,
    package_json,
)


HOST_IDENTITY = ProviderIdentity(StableId("v02-attempt-host"), "1")
REPORT_ACTIONS = OWNER_ACTIONS + (
    REPORT_CANDIDATE_ACTION,
    ACCEPT_OUTCOME_ACTION,
    REJECT_CANDIDATE_ACTION,
    MANUAL_OWNER_ACTIONS["owner"],
    READ_OUTCOME_ACTION,
    RECONCILE_ACTION,
)


class HandoffFixtureAttemptHost:
    """Attempt host fixture with a persistent source pin and live producer."""

    def __init__(self, wrapped, clock):
        self.wrapped = wrapped
        self.clock = clock
        self.proofs = {}
        self.handoff_calls = 0
        self.inspect_calls = 0
        self.last_process = None

    def qualify_workspace(self, workspace_id, target, correlation_id):
        return self.wrapped.qualify_workspace(workspace_id, target, correlation_id)

    def handoff_authoring(self, request: AttemptAuthoringHandoffRequest):
        self.handoff_calls += 1
        suffix = hashlib.sha256(str(request.attempt.entity_id).encode("utf-8")).hexdigest()[:16]
        source_commit = StableId("commit-" + suffix)
        source_tree = StableId("tree-" + suffix)
        source_digest = Sha256Digest("4" * 64)
        receipt = ProviderReceipt(
            _receipt_id("v03-authoring-handoff", request.attempt.entity_id), HOST_IDENTITY,
            request.attempt.entity_id,
            authoring_handoff_request_digest(request, source_commit, source_tree, source_digest),
            source_commit, self.clock(),
        )
        proof = AttemptAuthoringHandoff(
            request, source_commit, source_tree, source_digest, receipt,
        )
        self.proofs[str(request.attempt.entity_id)] = proof
        return proof

    def inspect_attempt(self, attempt, workspace):
        self.inspect_calls += 1
        observation = self.wrapped.inspect_attempt(attempt, workspace)
        proof = self.proofs.get(str(attempt.attempt_id))
        if proof is not None:
            observation = replace(
                observation,
                process=ProcessLiveness.LIVE,
                source_digest=proof.source_digest,
                authoring_handoff=proof,
            )
        self.last_process = observation.process
        return observation


class StaleSafetyHandoffHost:
    """Replays an exact handoff under an expired host-safety observation."""

    def __init__(self, wrapped, clock):
        self.wrapped = wrapped
        self.clock = clock

    def handoff_authoring(self, request):
        return self.wrapped.handoff_authoring(request)

    def inspect_attempt(self, attempt, workspace):
        observation = self.wrapped.inspect_attempt(attempt, workspace)
        stale_receipt = replace(
            observation.receipt,
            observed_at=self.clock() - timedelta(minutes=10),
        )
        return replace(observation, receipt=stale_receipt)


class ArtifactVerifier(LedgerVerifier):
    """Verifier fixture that binds one exact artifact digest to a named fact."""

    @staticmethod
    def _request_value(request):
        value = LedgerVerifier._request_value(request)
        facts = []
        artifacts = []
        for required in request.required_evidence:
            artifact_id = None
            if required.kind is EvidenceKind.ARTIFACT_REFERENCE:
                artifact_id = "v03-artifact-" + hashlib.sha256(
                    (str(request.operation_id) + str(required.name)).encode("utf-8")
                ).hexdigest()[:20]
                artifacts.append(artifact_id)
            facts.append({
                "name": str(required.name),
                "kind": required.kind.value,
                "version": required.version,
                "digest": hashlib.sha256(
                    (str(request.operation_id) + str(required.name) + ":artifact").encode("utf-8")
                ).hexdigest(),
                "artifact_id": artifact_id,
            })
        value["evidence_facts"] = facts
        value["artifact_ids"] = artifacts
        return value

    @staticmethod
    def _observation(value):
        return VerificationObservation(
            StableId(value["operation_id"]), EvidenceResult.PASS,
            StableId(value["verifier_id"]), VERIFIER_IDENTITY.version,
            Sha256Digest(value["source_digest"]), Sha256Digest(value["contract_digest"]),
            tuple(EvidenceInput(StableId(item["name"]), Sha256Digest(item["digest"]))
                  for item in value["inputs"]),
            tuple(StableId(item) for item in value["artifact_ids"]),
            tuple(VerificationEvidenceFact(
                StableId(item["name"]), EvidenceKind(item["kind"]), item["version"],
                Sha256Digest(item["digest"]),
                None if item["artifact_id"] is None else StableId(item["artifact_id"]),
            ) for item in value["evidence_facts"]),
        )


class BenchmarkVerifier(LedgerVerifier):
    """Verifier fixture that emits the exact authored benchmark evidence kind."""

    @staticmethod
    def _request_value(request):
        value = LedgerVerifier._request_value(request)
        for fact in value["evidence_facts"]:
            fact["kind"] = EvidenceKind.BENCHMARK_SAMPLE.value
            fact["benchmark_value"] = 12.0
            fact["unit"] = "ms"
            fact["sample_count"] = 4
        return value

    @staticmethod
    def _observation(value):
        return VerificationObservation(
            StableId(value["operation_id"]), EvidenceResult.FAIL,
            StableId(value["verifier_id"]), VERIFIER_IDENTITY.version,
            Sha256Digest(value["source_digest"]), Sha256Digest(value["contract_digest"]),
            tuple(EvidenceInput(StableId(item["name"]), Sha256Digest(item["digest"]))
                  for item in value["inputs"]), (),
            tuple(VerificationEvidenceFact(
                StableId(item["name"]), EvidenceKind(item["kind"]), item["version"],
                Sha256Digest(item["digest"]), benchmark_value=item["benchmark_value"],
                unit=item["unit"], sample_count=item["sample_count"],
            ) for item in value["evidence_facts"]),
        )

    def verify(self, request):
        request_value = self._request_value(request)
        receipt = ProviderReceipt(
            _receipt_id("v03-benchmark-receipt", request.operation_id), VERIFIER_IDENTITY,
            request.operation_id, provider_request_digest(request), request.operation_id, self.clock(),
        )
        request_value["original_receipt"] = self._receipt_mapping(receipt)
        with self._lock:
            ledger = self._read()
            ledger["verify_calls"] += 1
            ledger["requests"][str(request.operation_id)] = request_value
            self._write(ledger)
        if self.raise_after_effect:
            raise RuntimeError("fixture interruption after benchmark effect")
        return self._result(
            request.operation_id, self._observation(request_value),
            provider_request_digest(request), request.operation_id,
        )


class ArtifactAwareSourceObserver(FixtureSourceObserver):
    """Trusted source fixture that reports exactly the requested artifact digests."""

    def observe(self, request):
        result = super().observe(request)
        availability = tuple(
            ArtifactAvailability(item.artifact_id, True, item.expected_digest)
            for item in request.artifacts
        )
        return replace(result, value=replace(result.value, artifacts=availability))


class PinnedSourceObserver(ArtifactAwareSourceObserver):
    def __init__(self, clock, source_commit):
        super().__init__(clock)
        self.source_commit = source_commit

    def observe(self, request):
        result = super().observe(request)
        return replace(result, value=replace(result.value, source_revision=self.source_commit))


class ChangedPinnedSourceObserver(PinnedSourceObserver):
    """Report a clean source revision that changed after the durable handoff."""

    def observe(self, request):
        result = super().observe(request)
        return replace(result, value=replace(
            result.value,
            source_digest=Sha256Digest("5" * 64),
            source_revision=StableId("commit-after-handoff"),
        ))


class MissingArtifactSourceObserver(ArtifactAwareSourceObserver):
    """Trusted observer fixture reporting that requested artifact bytes disappeared."""

    def observe(self, request):
        result = super().observe(request)
        unavailable = tuple(
            ArtifactAvailability(item.artifact_id, False, None)
            for item in request.artifacts
        )
        self.last_artifacts = unavailable
        return replace(result, value=replace(result.value, artifacts=unavailable))


class SourceChangesAfterFinalObservation(ArtifactAwareSourceObserver):
    """Simulate source and artifact drift between preflight and writer commit."""

    def __init__(self, clock):
        super().__init__(clock)
        self.changed_after_preflight = False
        self.final_preflight_count = 0
        self.observed_values = []

    def observe(self, request):
        result = super().observe(request)
        if self.changed_after_preflight:
            unavailable = tuple(
                ArtifactAvailability(item.artifact_id, False, None)
                for item in request.artifacts
            )
            changed = replace(
                result.value,
                source_digest=Sha256Digest("5" * 64),
                inputs=tuple(replace(item, digest=Sha256Digest("c" * 64))
                             for item in result.value.inputs),
                working_tree=WorkingTreeState.DIRTY,
                artifacts=unavailable,
            )
            result = replace(result, value=changed)
            self.observed_values.append(result.value)
            return result

        if str(request.correlation_id).startswith("candidate-final-source-"):
            self.final_preflight_count += 1
            self.changed_after_preflight = True
        self.observed_values.append(result.value)
        return result


class GuardClockAdvancingSourceObserver(ArtifactAwareSourceObserver):
    """Advance the trusted clock after the writer-guard observation is made."""

    def __init__(self, clock):
        super().__init__(clock)
        self.guard_observations = 0

    def observe(self, request):
        result = super().observe(request)
        if str(request.correlation_id).startswith("outcome-source-guard-"):
            self.guard_observations += 1
            self.clock.value += timedelta(seconds=2)
        return result


class OneTickFutureSourceObserver(ArtifactAwareSourceObserver):
    """Make each provider receipt one clock tick newer than its caller snapshot."""

    def observe(self, request):
        self.clock.value += timedelta(microseconds=1)
        return super().observe(request)


class IndependentOutcomeAcceptanceTests(unittest.TestCase):
    """Exercise acceptance through real disposable authority services."""

    def setUp(self):
        from tests.verification.test_execution_independent import IndependentVerificationExecutionTests

        self.fixture = IndependentVerificationExecutionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.source = ArtifactAwareSourceObserver(f.clock)
        f.verification.source_observer = f.source
        with f.open_writer() as authority:
            f.owner = f.auth.login_local_owner(
                authority,
                OWNER_PASSWORD,
                actions=REPORT_ACTIONS,
                scope=PROJECT.ref,
                expires_at=f.clock() + timedelta(hours=1),
                idempotency_key=StableId("v03-owner-token"),
                expected_revision=f.revision(),
            )
        self.acceptance = OutcomeAcceptanceService(
            f.auth, source_observer=f.source,
            source_identity=SOURCE_IDENTITY,
            host=f.host,
            host_identity=HOST_IDENTITY,
            clock=f.clock,
            max_observation_age=timedelta(minutes=5),
        )

    def delegate(self, credential, actions, scope, key):
        f = self.fixture
        with f.open_writer() as authority:
            return f.auth.delegate(
                authority,
                f.owner.bearer_token,
                credential,
                actions=tuple(actions),
                scope=scope,
                expires_at=f.clock() + timedelta(minutes=30),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def dispatch(self, work_id, key):
        f = self.fixture
        with f.open_writer() as authority:
            return f.coordination.dispatch(
                authority,
                f.owner.bearer_token,
                f.plan,
                workspace_id=StableId("v03-workspace-" + work_id),
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
                work_item=f.work_ref(work_id),
            )

    def report(self, token, attempt, disposition, key):
        f = self.fixture
        with f.open_writer() as authority:
            return self.acceptance.report_candidate(
                authority,
                token,
                attempt,
                disposition,
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def accept(self, token, attempt, candidate, key):
        f = self.fixture
        with f.open_writer() as authority:
            return self.acceptance.accept_candidate(
                authority,
                token,
                attempt,
                candidate,
                idempotency_key=StableId(key),
                expected_revision=f.revision(),
            )

    def snapshot(self):
        f = self.fixture
        with f.open_reader() as authority:
            tables = (
                "attempts", "verification_attempts", "evidence", "outcomes",
                "outcome_candidates", "outcome_evidence", "outcome_provenance",
                "command_receipts", "command_idempotency", "authority_events",
            )
            return (
                f.dispatcher.logical_fingerprint(authority),
                f.revision(),
                tuple((table, authority.connection.execute(
                    f'SELECT count(*) FROM "{table}"'
                ).fetchone()[0]) for table in tables),
            )

    def require_artifact_fact(self):
        f = self.fixture
        document = json.loads(package_json())
        requirement = next(item for item in document["requirements"] if item["id"] == "check-verify")
        requirement["required_evidence"] = [{
            "name": "verify-artifact", "kind": "artifact_reference", "version": 1,
        }]
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with f.open_writer() as authority:
            preview = f.plans.preview(authority, encoded)
            f.plans.commit(
                authority, f.owner.bearer_token, encoded,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("v03-artifact-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            f.plan = f.plans.load_accepted_plan(authority)

    def require_exact_manual_owner(self):
        f = self.fixture
        owner = f.owner.capability.actor
        document = json.loads(package_json())
        work = next(item for item in document["work_items"] if item["id"] == "verify")
        work["requirement_groups"] = [{
            "kind": "check", "mode": "any", "members": ["check-verify", "manual-check"],
        }]
        document["requirements"].append({
            "id": "manual-check", "work_item_id": "verify", "kind": "check",
            "description": "Manual attestation alternative", "check_key": "manual-check",
            "verification": {"kind": "manual_owner", "version": 1, "config": {
                "approver_role": "owner", "actor_id": str(owner.entity_id),
                "incarnation_id": str(owner.incarnation_id),
            }},
            "required_evidence": [{"name": "manual-report", "kind": "manual_attestation", "version": 1}],
        })
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with f.open_writer() as authority:
            preview = f.plans.preview(authority, encoded)
            f.plans.commit(
                authority, f.owner.bearer_token, encoded,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("v03-manual-owner-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            f.plan = f.plans.load_accepted_plan(authority)

    def require_mixed_check_groups(self):
        """Add ANY, QUORUM and ungrouped checks to verify work."""
        f = self.fixture
        owner = f.owner.capability.actor
        document = json.loads(package_json())
        work = next(item for item in document["work_items"] if item["id"] == "verify")
        work["requirement_groups"] = [
            {"kind": "check", "mode": "any", "members": ["check-verify", "manual-alternative"]},
            {"kind": "check", "mode": "quorum", "quorum": 2,
             "members": ["quorum-a", "quorum-b", "quorum-c"]},
        ]

        manual = {
            "id": "manual-alternative", "work_item_id": "verify", "kind": "check",
            "description": "Optional human attestation alternative", "check_key": "manual-alternative",
            "verification": {"kind": "manual_owner", "version": 1, "config": {
                "approver_role": "owner", "actor_id": str(owner.entity_id),
                "incarnation_id": str(owner.incarnation_id),
            }},
            "required_evidence": [{"name": "manual-report", "kind": "manual_attestation", "version": 1}],
        }
        document["requirements"].append(manual)
        for identifier in ("quorum-a", "quorum-b", "quorum-c", "ungrouped-check"):
            document["requirements"].append({
                "id": identifier, "work_item_id": "verify", "kind": "check",
                "description": "Independent check " + identifier, "check_key": identifier,
                "verification": {"kind": "domain_provider", "version": 1, "config": {
                    "provider_id": str(VERIFIER_IDENTITY.provider_id), "provider_version": VERIFIER_IDENTITY.version,
                    "contract_id": "v02-test-verification", "contract_version": 1,
                    "parameters": {"scenario": identifier},
                }},
                "required_evidence": [{"name": identifier + "-report", "kind": "provider_receipt", "version": 1}],
            })

        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with f.open_writer() as authority:
            preview = f.plans.preview(authority, encoded)
            f.plans.commit(
                authority, f.owner.bearer_token, encoded,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("v03-mixed-check-groups-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            f.plan = f.plans.load_accepted_plan(authority)

    def test_scoped_handoff_preserves_review_after_expiry_without_claiming_stop(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-handoff-review-claim")
        suffix = hashlib.sha256(str(attempt.entity_id).encode("utf-8")).hexdigest()[:16]
        source_commit = StableId("commit-" + suffix)
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        f.source = PinnedSourceObserver(f.clock, source_commit)
        self.acceptance.source_observer = f.source
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),)
            ).fetchone()
        lease_id = StableId(row["lease_id"])
        handback_revision = f.revision()

        with f.open_writer() as authority:
            handback = f.attempts.handback_authoring(
                authority, f.owner.bearer_token, attempt, lease_id,
                idempotency_key=StableId("v03-handoff-review-key"),
                expected_revision=handback_revision,
            )
        self.assertFalse(handback.receipt.changed)
        self.assertEqual(handback.receipt.result["source_commit"], str(source_commit))
        self.assertEqual(handback.receipt.result["source_digest"], "4" * 64)
        self.assertEqual(host.last_process, ProcessLiveness.LIVE)
        self.assertEqual(host.handoff_calls, 1)

        _, candidate = self.report(
            f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED, "v03-handoff-review-report",
        )
        # Simulate a response loss after the handback commit followed by other
        # authority work. The exact retry must reuse its original receipt and
        # must not call or regenerate a time-varying host observation.
        with f.open_writer() as authority:
            handback_replay = f.attempts.handback_authoring(
                authority, f.owner.bearer_token, attempt, lease_id,
                idempotency_key=StableId("v03-handoff-review-key"),
                expected_revision=handback_revision,
            )
        self.assertTrue(handback_replay.replayed)
        self.assertEqual(handback_replay.receipt, handback.receipt)
        self.assertEqual(host.handoff_calls, 1)

        f.clock.value += timedelta(minutes=6)
        revision_before_reconcile = f.revision()
        with f.open_writer() as authority:
            reconciled = f.attempts.reconcile_expired(
                authority, f.owner.bearer_token, attempt,
                idempotency_key=StableId("v03-handoff-review-reconcile"),
                expected_revision=revision_before_reconcile,
            )
        self.assertFalse(reconciled.receipt.changed)
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT state, lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),)
            ).fetchone()
        self.assertEqual(row["state"], "reported")
        self.assertEqual(row["lease_id"], str(lease_id))

        accepted = self.accept(
            f.owner.bearer_token, attempt, candidate, "v03-handoff-review-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        self.assertEqual(host.last_process, ProcessLiveness.LIVE)

        # A stopped-process observation by itself does not let a stale report
        # bypass its expired lease; only the exact scoped pin does.
        other_attempt = f.claim("verify", f.owner.bearer_token, key="v03-no-handoff-claim")
        _, other_candidate = self.report(
            f.owner.bearer_token, other_attempt, OutcomeDisposition.COMPLETED, "v03-no-handoff-report",
        )
        f.clock.value += timedelta(minutes=6)
        with self.assertRaises(CandidateDeniedError):
            self.accept(
                f.owner.bearer_token, other_attempt, other_candidate, "v03-no-handoff-accept",
            )

    def test_handoff_report_rejects_a_source_edit_after_the_pin(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-handoff-source-drift-claim")
        suffix = hashlib.sha256(str(attempt.entity_id).encode("utf-8")).hexdigest()[:16]
        source_commit = StableId("commit-" + suffix)
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        f.source = PinnedSourceObserver(f.clock, source_commit)
        self.acceptance.source_observer = f.source
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),)
            ).fetchone()
        with f.open_writer() as authority:
            f.attempts.handback_authoring(
                authority, f.owner.bearer_token, attempt, StableId(row["lease_id"]),
                idempotency_key=StableId("v03-handoff-source-drift-key"),
                expected_revision=f.revision(),
            )

        # Model an edit after the host's fence. Reporting must not attach a new
        # source observation to the earlier handoff receipt, even after the
        # execution lease expires.
        f.clock.value += timedelta(minutes=6)
        self.acceptance.source_observer = ChangedPinnedSourceObserver(f.clock, source_commit)
        before = f.state_snapshot()
        with self.assertRaises(CandidateObservationMismatchError):
            self.report(
                f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                "v03-handoff-source-drift-report",
            )
        self.assertEqual(f.state_snapshot(), before)

    def test_expired_nonterminal_attempt_can_handback_and_report_exact_snapshot(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-expired-handoff-claim")
        suffix = hashlib.sha256(str(attempt.entity_id).encode("utf-8")).hexdigest()[:16]
        source_commit = StableId("commit-" + suffix)
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        f.source = PinnedSourceObserver(f.clock, source_commit)
        self.acceptance.source_observer = f.source
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id, lease_expires_at, state FROM attempts WHERE attempt_id = ?",
                (str(attempt.entity_id),),
            ).fetchone()
        lease_id = StableId(row["lease_id"])
        original_expiry = row["lease_expires_at"]
        self.assertIn(row["state"], {"admitted", "active"})
        f.clock.value += timedelta(minutes=6)
        self.assertGreater(f.clock.value.isoformat(), original_expiry)

        with f.open_writer() as authority:
            handback = f.attempts.handback_authoring(
                authority, f.owner.bearer_token, attempt, lease_id,
                idempotency_key=StableId("v03-expired-handoff-key"),
                expected_revision=f.revision(),
            )
        self.assertFalse(handback.receipt.changed)
        self.assertEqual(host.handoff_calls, 1)
        with f.open_reader() as authority:
            after_handoff = authority.connection.execute(
                "SELECT lease_id, lease_expires_at, state FROM attempts WHERE attempt_id = ?",
                (str(attempt.entity_id),),
            ).fetchone()
        self.assertEqual(after_handoff["state"], row["state"])
        self.assertEqual(after_handoff["lease_id"], str(lease_id))
        self.assertEqual(after_handoff["lease_expires_at"], original_expiry)

        _, candidate = self.report(
            f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED, "v03-expired-handoff-report",
        )
        with f.open_reader() as authority:
            after_report = authority.connection.execute(
                "SELECT lease_id, lease_expires_at, state FROM attempts WHERE attempt_id = ?",
                (str(attempt.entity_id),),
            ).fetchone()
        self.assertEqual(after_report["state"], "reported")
        self.assertEqual(after_report["lease_id"], str(lease_id))
        self.assertEqual(after_report["lease_expires_at"], original_expiry)
        self.assertEqual(host.last_process, ProcessLiveness.LIVE)

        accepted = self.accept(
            f.owner.bearer_token, attempt, candidate, "v03-expired-handoff-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        self.assertEqual(host.last_process, ProcessLiveness.LIVE)

    def test_expired_report_without_handoff_is_denied_without_authority_change(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-expired-no-handoff-claim")
        f.clock.value += timedelta(minutes=6)
        before = f.state_snapshot()
        request_count = len(f.source.requests)
        with self.assertRaises(CandidateStateError):
            self.report(
                f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                "v03-expired-no-handoff-report",
            )
        self.assertEqual(f.state_snapshot(), before)
        self.assertEqual(len(f.source.requests), request_count)

    def test_expired_report_rejects_host_pin_without_committed_todo_handoff(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-expired-uncommitted-pin-claim")
        suffix = hashlib.sha256(str(attempt.entity_id).encode("utf-8")).hexdigest()[:16]
        source_commit = StableId("commit-" + suffix)
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        f.source = PinnedSourceObserver(f.clock, source_commit)
        self.acceptance.source_observer = f.source
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),),
            ).fetchone()
            workspace = _stored_workspace(authority.connection, authority.project, attempt)
        request = AttemptAuthoringHandoffRequest(
            PROJECT.project_id, PROJECT.authority_id, attempt, StableId(row["lease_id"]),
            workspace.workspace_id, StableId("v03-expired-uncommitted-pin-key"),
        )
        # Model the host side effect succeeding before the Todo handback command
        # can durably record its matching idempotency receipt.
        host.handoff_authoring(request)
        f.clock.value += timedelta(minutes=6)
        before = f.state_snapshot()
        with self.assertRaises(CandidateDeniedError):
            self.report(
                f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                "v03-expired-uncommitted-pin-report",
            )
        self.assertEqual(f.state_snapshot(), before)

    def test_expired_handback_rejects_a_noncurrent_lease_before_host_effect(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-expired-wrong-lease-claim")
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),),
            ).fetchone()
        f.clock.value += timedelta(minutes=6)
        before = f.state_snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(AttemptLeaseMismatchError):
                f.attempts.handback_authoring(
                    authority, f.owner.bearer_token, attempt, StableId("wrong-expired-lease"),
                    idempotency_key=StableId("v03-expired-wrong-lease-key"),
                    expected_revision=f.revision(),
                )
        self.assertEqual(host.handoff_calls, 0)
        self.assertEqual(f.state_snapshot(), before)

    def test_expired_report_rejects_stale_host_safety_after_exact_handoff(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-expired-stale-safety-claim")
        suffix = hashlib.sha256(str(attempt.entity_id).encode("utf-8")).hexdigest()[:16]
        source_commit = StableId("commit-" + suffix)
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        f.source = PinnedSourceObserver(f.clock, source_commit)
        self.acceptance.source_observer = f.source
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(attempt.entity_id),),
            ).fetchone()
        f.clock.value += timedelta(minutes=6)
        with f.open_writer() as authority:
            f.attempts.handback_authoring(
                authority, f.owner.bearer_token, attempt, StableId(row["lease_id"]),
                idempotency_key=StableId("v03-expired-stale-safety-handoff"),
                expected_revision=f.revision(),
            )
        self.acceptance.host = StaleSafetyHandoffHost(host, f.clock)
        before = f.state_snapshot()
        with self.assertRaises(CandidateObservationMismatchError):
            self.report(
                f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                "v03-expired-stale-safety-report",
            )
        self.assertEqual(f.state_snapshot(), before)

    def test_released_or_reconciled_attempt_cannot_be_handed_back_or_reported(self):
        f = self.fixture
        released_attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-released-handoff-claim")
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(released_attempt.entity_id),),
            ).fetchone()
        released_lease = StableId(row["lease_id"])
        with f.open_writer() as authority:
            f.attempts.release(
                authority, f.owner.bearer_token, released_attempt, released_lease,
                idempotency_key=StableId("v03-release-before-handoff"), expected_revision=f.revision(),
            )
        host = HandoffFixtureAttemptHost(f.host, f.clock)
        f.host = host
        f.attempts.host = host
        self.acceptance.host = host
        before_release_retry = f.state_snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(AttemptLeaseMismatchError):
                f.attempts.handback_authoring(
                    authority, f.owner.bearer_token, released_attempt, released_lease,
                    idempotency_key=StableId("v03-handoff-released-attempt"),
                    expected_revision=f.revision(),
                )
        with self.assertRaises(CandidateStateError):
            self.report(
                f.owner.bearer_token, released_attempt, OutcomeDisposition.COMPLETED,
                "v03-report-released-attempt",
            )
        self.assertEqual(f.state_snapshot(), before_release_retry)
        self.assertEqual(host.handoff_calls, 0)

        reconciled_attempt = f.claim("verify", f.owner.bearer_token, key="v03-reconciled-handoff-claim")
        with f.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?", (str(reconciled_attempt.entity_id),),
            ).fetchone()
        reconciled_lease = StableId(row["lease_id"])
        f.clock.value += timedelta(minutes=6)
        with f.open_writer() as authority:
            f.attempts.reconcile_expired(
                authority, f.owner.bearer_token, reconciled_attempt,
                idempotency_key=StableId("v03-reconcile-before-handoff"), expected_revision=f.revision(),
            )
        before_reconciled_retry = f.state_snapshot()
        with f.open_writer() as authority:
            with self.assertRaises(AttemptLeaseMismatchError):
                f.attempts.handback_authoring(
                    authority, f.owner.bearer_token, reconciled_attempt, reconciled_lease,
                    idempotency_key=StableId("v03-handoff-reconciled-attempt"),
                    expected_revision=f.revision(),
                )
        with self.assertRaises(CandidateStateError):
            self.report(
                f.owner.bearer_token, reconciled_attempt, OutcomeDisposition.COMPLETED,
                "v03-report-reconciled-attempt",
            )
        self.assertEqual(f.state_snapshot(), before_reconciled_retry)
        self.assertEqual(host.handoff_calls, 0)

    def test_dispatched_check_is_accepted_by_a_distinct_scoped_actor_and_history_is_immutable(self):
        f = self.fixture
        self.require_artifact_fact()
        f.verification.provider = ArtifactVerifier(f.ledger_path, f.clock)
        dispatched = self.dispatch("verify", "v03-dispatch-verified-work")
        self.assertIn(REPORT_CANDIDATE_ACTION, dispatched.capability.actions)
        self.assertIn(VERIFICATION_ACTION, dispatched.capability.actions)

        with f.open_writer() as authority:
            verified = f.verification.execute(
                authority,
                dispatched.bearer_token,
                dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-check-evidence"),
                expected_revision=f.revision(),
            )
        self.assertEqual(verified.state, "finalized")

        _, candidate_ref = self.report(
            dispatched.bearer_token,
            dispatched.attempt.ref,
            OutcomeDisposition.COMPLETED,
            "v03-report-completion",
        )
        approver = self.delegate(
            "worker-other",
            (ACCEPT_OUTCOME_ACTION,),
            f.work_ref("verify"),
            "v03-scoped-approver",
        )
        reporter_only = self.delegate(
            "worker-missing",
            (REPORT_CANDIDATE_ACTION,),
            f.work_ref("verify"),
            "v03-report-only",
        )
        before_denied_accept = self.snapshot()
        with self.assertRaises(CapabilityDeniedError):
            self.accept(reporter_only.bearer_token, dispatched.attempt.ref, candidate_ref,
                        "v03-unauthorized-accept")
        self.assertEqual(self.snapshot(), before_denied_accept)

        accepted = self.accept(
            approver.bearer_token,
            dispatched.attempt.ref,
            candidate_ref,
            "v03-authorized-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        self.assertEqual(self.snapshot()[2][3][1], 1)

        with f.open_reader() as authority:
            outcome = authority.connection.execute(
                "SELECT outcome_id, disposition, accepted_by_actor_id, attempt_id "
                "FROM outcomes"
            ).fetchone()
            provenance_row = authority.connection.execute(
                "SELECT canonical_json, content_digest FROM outcome_provenance WHERE outcome_id = ?",
                (outcome["outcome_id"],),
            ).fetchone()
            child = authority.connection.execute(
                "SELECT revoked FROM capabilities WHERE capability_id = ?",
                (str(dispatched.capability.capability_id),),
            ).fetchone()
            parent = authority.connection.execute(
                "SELECT revoked FROM capabilities WHERE capability_id = ?",
                (str(f.owner.capability.capability_id),),
            ).fetchone()
        provenance = json.loads(provenance_row["canonical_json"])
        self.assertEqual(outcome["disposition"], "completed")
        self.assertEqual(outcome["accepted_by_actor_id"], str(approver.capability.actor.entity_id))
        self.assertEqual(outcome["attempt_id"], str(dispatched.attempt.attempt_id))
        self.assertEqual(provenance["candidate_id"], str(candidate_ref.entity_id))
        self.assertEqual(provenance["work_item"]["definition_revision_id"],
                         str(f.work_ref("verify").definition_revision_id))
        self.assertEqual(provenance["source"]["source_digest"], "4" * 64)
        self.assertEqual([item["evidence_id"] for item in provenance["evidence"]],
                         [str(verified.evidence_id)])
        self.assertEqual(len(provenance["artifacts"]), 1)
        self.assertEqual(provenance["artifacts"][0]["artifact_id"],
                         provenance["evidence"][0]["artifacts"][0]["artifact_id"])
        self.assertTrue(provenance["artifacts"][0]["content_digest"])
        self.assertEqual(child["revoked"], 1)
        self.assertEqual(parent["revoked"], 0)
        self.assertTrue(provenance_row["content_digest"])

        immutable = (provenance_row["canonical_json"], provenance_row["content_digest"])
        later_source = ArtifactAwareSourceObserver(f.clock, change_after_first=True)
        request = f.source.requests[-1]
        first_observation = later_source.observe(request).value
        changed_observation = later_source.observe(request).value
        self.assertEqual(first_observation.source_digest.hex, provenance["source"]["source_digest"])
        self.assertNotEqual(changed_observation.source_digest.hex, provenance["source"]["source_digest"])
        self.acceptance.source_observer = later_source
        with f.open_reader() as authority:
            applicability = self.acceptance.read_outcome_applicability(
                authority,
                EntityRef(PROJECT.project_id, EntityKind.OUTCOME, StableId(outcome["outcome_id"])),
                bearer_token=f.owner.bearer_token,
            )
        self.assertEqual(applicability.status, "stale")
        self.assertIn("source identity, digest, working-tree state, or input contents changed",
                      applicability.reasons)
        with f.open_reader() as authority:
            persisted = authority.connection.execute(
                "SELECT canonical_json, content_digest FROM outcome_provenance WHERE outcome_id = ?",
                (outcome["outcome_id"],),
            ).fetchone()
            self.assertEqual((persisted["canonical_json"], persisted["content_digest"]), immutable)

    def test_artifact_reference_without_identifier_stays_unresolved_and_cannot_be_reported(self):
        f = self.fixture
        self.require_artifact_fact()
        dispatched = self.dispatch("verify", "v03-dispatch-missing-artifact")
        with f.open_writer() as authority:
            missing_artifact = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-missing-artifact-evidence"),
                expected_revision=f.revision(),
            )
        self.assertEqual(missing_artifact.state, "unknown")
        before = self.snapshot()
        with self.assertRaises(CandidateDeniedError):
            self.report(
                dispatched.bearer_token, dispatched.attempt.ref, OutcomeDisposition.COMPLETED,
                "v03-report-missing-artifact",
            )
        self.assertEqual(self.snapshot(), before)

    def test_artifact_disappearance_blocks_acceptance_and_stales_only_current_applicability(self):
        f = self.fixture
        self.require_artifact_fact()
        f.verification.provider = ArtifactVerifier(f.ledger_path, f.clock)
        dispatched = self.dispatch("verify", "v03-dispatch-artifact-drift")
        with f.open_writer() as authority:
            checked = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-artifact-drift-check"), expected_revision=f.revision(),
            )
        self.assertEqual(checked.state, "finalized")
        _, candidate = self.report(
            dispatched.bearer_token, dispatched.attempt.ref, OutcomeDisposition.COMPLETED,
            "v03-artifact-drift-report",
        )
        acceptor = self.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"),
            "v03-artifact-drift-acceptor",
        )
        missing = MissingArtifactSourceObserver(f.clock)
        self.acceptance.source_observer = missing
        before_denied = self.snapshot()
        with self.assertRaises(CandidateObservationMismatchError):
            self.accept(acceptor.bearer_token, dispatched.attempt.ref, candidate,
                        "v03-artifact-drift-refuse")
        self.assertEqual(self.snapshot(), before_denied)
        self.assertTrue(missing.requests[-1].artifacts)

        self.assertTrue(all(not fact.available for fact in missing.last_artifacts))

        self.acceptance.source_observer = f.source
        accepted = self.accept(
            acceptor.bearer_token, dispatched.attempt.ref, candidate, "v03-artifact-drift-accept-valid",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        with f.open_reader() as authority:
            outcome_row = authority.connection.execute(
                "SELECT outcome_id FROM outcomes"
            ).fetchone()
            provenance_before = authority.connection.execute(
                "SELECT canonical_json, content_digest FROM outcome_provenance WHERE outcome_id = ?",
                (outcome_row["outcome_id"],),
            ).fetchone()
        fingerprint_before = self.snapshot()[0]
        self.acceptance.source_observer = missing
        outcome_ref = EntityRef(PROJECT.project_id, EntityKind.OUTCOME, StableId(outcome_row["outcome_id"]))
        with f.open_reader() as authority:
            applicability = self.acceptance.read_outcome_applicability(
                authority, outcome_ref, bearer_token=f.owner.bearer_token,
            )
        self.assertFalse(applicability.applicable)
        self.assertTrue(missing.requests[-1].artifacts)
        self.assertEqual(self.snapshot()[0], fingerprint_before)
        with f.open_reader() as authority:
            provenance_after = authority.connection.execute(
                "SELECT canonical_json, content_digest FROM outcome_provenance WHERE outcome_id = ?",
                (outcome_row["outcome_id"],),
            ).fetchone()
        self.assertEqual(tuple(provenance_after), tuple(provenance_before))

    def test_source_and_artifact_change_after_final_preflight_is_rechecked_before_commit(self):
        f = self.fixture
        self.require_artifact_fact()
        f.verification.provider = ArtifactVerifier(f.ledger_path, f.clock)
        dispatched = self.dispatch("verify", "v03-dispatch-final-observation-race")
        with f.open_writer() as authority:
            checked = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-final-race-check"), expected_revision=f.revision(),
            )
        self.assertEqual(checked.state, "finalized")
        _, candidate = self.report(
            dispatched.bearer_token, dispatched.attempt.ref, OutcomeDisposition.COMPLETED,
            "v03-final-race-report",
        )
        acceptor = self.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"),
            "v03-final-race-acceptor",
        )
        racing_source = SourceChangesAfterFinalObservation(f.clock)
        self.acceptance.source_observer = racing_source
        before = self.snapshot()

        with self.assertRaises(CandidateObservationMismatchError):
            self.accept(acceptor.bearer_token, dispatched.attempt.ref, candidate,
                        "v03-final-race-refuse")

        self.assertEqual(racing_source.final_preflight_count, 1)
        self.assertTrue(racing_source.changed_after_preflight)
        self.assertGreaterEqual(len(racing_source.requests), 2)
        self.assertEqual(racing_source.observed_values[0].source_digest.hex, "4" * 64)
        self.assertEqual(racing_source.observed_values[1].source_digest.hex, "5" * 64)
        self.assertTrue(racing_source.observed_values[1].artifacts)
        self.assertTrue(all(not item.available for item in racing_source.observed_values[1].artifacts))
        self.assertEqual(self.snapshot(), before)
        with f.open_reader() as authority:
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM outcomes"
            ).fetchone()[0], 0)

    def test_writer_guard_receipt_age_is_checked_against_clock_after_provider_returns(self):
        f = self.fixture
        dispatched = self.dispatch("verify", "v03-dispatch-guard-clock")
        with f.open_writer() as authority:
            checked = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-guard-clock-check"), expected_revision=f.revision(),
            )
        self.assertEqual(checked.state, "finalized")
        _, candidate = self.report(
            dispatched.bearer_token, dispatched.attempt.ref, OutcomeDisposition.COMPLETED,
            "v03-guard-clock-report",
        )
        acceptor = self.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"),
            "v03-guard-clock-acceptor",
        )
        advancing_source = GuardClockAdvancingSourceObserver(f.clock)
        self.acceptance.source_observer = advancing_source
        self.acceptance.max_observation_age = timedelta(seconds=1)
        before = self.snapshot()
        prior_clock = f.clock()

        with self.assertRaises(CandidateObservationMismatchError):
            self.accept(acceptor.bearer_token, dispatched.attempt.ref, candidate,
                        "v03-guard-clock-refuse")

        self.assertEqual(advancing_source.guard_observations, 1)
        self.assertEqual(f.clock() - prior_clock, timedelta(seconds=2))
        self.assertEqual(self.snapshot(), before)

    def test_slightly_future_provider_receipts_succeed_after_clock_resampling(self):
        f = self.fixture
        dispatched = self.dispatch("verify", "v03-dispatch-future-receipts")
        with f.open_writer() as authority:
            checked = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-future-receipts-check"), expected_revision=f.revision(),
            )
        self.assertEqual(checked.state, "finalized")
        advancing_source = OneTickFutureSourceObserver(f.clock)
        self.acceptance.source_observer = advancing_source
        _, candidate = self.report(
            dispatched.bearer_token, dispatched.attempt.ref, OutcomeDisposition.COMPLETED,
            "v03-future-receipts-report",
        )
        accepted = self.accept(
            f.owner.bearer_token, dispatched.attempt.ref, candidate,
            "v03-future-receipts-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")
        self.assertGreaterEqual(len(advancing_source.requests), 3)

    def test_accepted_outcome_retries_replay_report_and_final_receipts_before_providers(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-replay-accepted-claim")
        report_revision = f.revision()
        with f.open_writer() as authority:
            original_report, candidate = self.acceptance.report_candidate(
                authority, f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                idempotency_key=StableId("v03-replay-accepted-report"),
                expected_revision=report_revision,
            )
        accept_revision = f.revision()
        with f.open_writer() as authority:
            original_accept = self.acceptance.accept_candidate(
                authority, f.owner.bearer_token, attempt, candidate,
                idempotency_key=StableId("v03-replay-accepted-finalize"),
                expected_revision=accept_revision,
            )
        self.assertEqual(original_accept.receipt.result["state"], "accepted")
        report_only = self.delegate(
            "worker-missing", (REPORT_CANDIDATE_ACTION,), f.work_ref("prerequisite"),
            "v03-replay-report-only-token",
        )

        with self.assertRaises(CapabilityDeniedError):
            with f.open_writer() as authority:
                self.acceptance.accept_candidate(
                    authority, report_only.bearer_token, attempt, candidate,
                    idempotency_key=StableId("v03-replay-accepted-finalize"),
                    expected_revision=accept_revision,
                )
        with self.assertRaises(IdempotencyConflictError):
            with f.open_writer() as authority:
                self.acceptance.reject_candidate(
                    authority, f.owner.bearer_token, attempt, candidate,
                    idempotency_key=StableId("v03-replay-accepted-finalize"),
                    expected_revision=accept_revision,
                )

        class UnavailableSource:
            calls = 0

            def observe(self, request):
                self.calls += 1
                raise RuntimeError("source provider is unavailable")

        unavailable = UnavailableSource()
        self.acceptance.source_observer = unavailable
        before = self.snapshot()
        with f.open_writer() as authority:
            replayed_report, replayed_candidate = self.acceptance.report_candidate(
                authority, f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                idempotency_key=StableId("v03-replay-accepted-report"),
                expected_revision=report_revision,
            )
        with f.open_writer() as authority:
            replayed_accept = self.acceptance.accept_candidate(
                authority, f.owner.bearer_token, attempt, candidate,
                idempotency_key=StableId("v03-replay-accepted-finalize"),
                expected_revision=accept_revision,
            )
        self.assertEqual(replayed_candidate, candidate)
        self.assertTrue(replayed_report.replayed)
        self.assertTrue(replayed_accept.replayed)
        self.assertEqual(replayed_report.receipt, original_report.receipt)
        self.assertEqual(replayed_accept.receipt, original_accept.receipt)
        self.assertLess(report_revision, self.snapshot()[1])
        self.assertLess(accept_revision, self.snapshot()[1])
        self.assertEqual(unavailable.calls, 0)
        self.assertEqual(self.snapshot(), before)

    def test_rejected_candidate_retry_replays_receipt_with_original_stale_revision(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-replay-rejected-claim")
        report_revision = f.revision()
        with f.open_writer() as authority:
            original_report, candidate = self.acceptance.report_candidate(
                authority, f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                idempotency_key=StableId("v03-replay-rejected-report"),
                expected_revision=report_revision,
            )
        reject_revision = f.revision()
        with f.open_writer() as authority:
            original_rejection = self.acceptance.reject_candidate(
                authority, f.owner.bearer_token, attempt, candidate,
                idempotency_key=StableId("v03-replay-rejected-finalize"),
                expected_revision=reject_revision,
            )
        self.assertEqual(original_rejection.receipt.result["state"], "rejected")

        class UnavailableSource:
            calls = 0

            def observe(self, request):
                self.calls += 1
                raise RuntimeError("source provider is unavailable")

        unavailable = UnavailableSource()
        self.acceptance.source_observer = unavailable
        before = self.snapshot()
        with f.open_writer() as authority:
            replayed_report, replayed_candidate = self.acceptance.report_candidate(
                authority, f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                idempotency_key=StableId("v03-replay-rejected-report"),
                expected_revision=report_revision,
            )
        with f.open_writer() as authority:
            replayed_rejection = self.acceptance.reject_candidate(
                authority, f.owner.bearer_token, attempt, candidate,
                idempotency_key=StableId("v03-replay-rejected-finalize"),
                expected_revision=reject_revision,
            )
        self.assertEqual(replayed_candidate, candidate)
        self.assertTrue(replayed_report.replayed)
        self.assertTrue(replayed_rejection.replayed)
        self.assertEqual(replayed_report.receipt, original_report.receipt)
        self.assertEqual(replayed_rejection.receipt, original_rejection.receipt)
        self.assertLess(reject_revision, self.snapshot()[1])
        self.assertEqual(unavailable.calls, 0)
        self.assertEqual(self.snapshot(), before)

    def test_manual_owner_requires_exact_human_incarnation_and_role_action(self):
        f = self.fixture
        self.require_exact_manual_owner()
        attempt = f.claim("verify", f.owner.bearer_token, key="v03-manual-owner-claim")
        _, candidate = self.report(
            f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
            "v03-manual-owner-report",
        )
        unauthorized = self.delegate(
            "worker-other",
            (ACCEPT_OUTCOME_ACTION,),
            f.work_ref("verify"),
            "v03-manual-owner-missing-role",
        )
        before = self.snapshot()
        with self.assertRaises(CapabilityDeniedError):
            self.accept(unauthorized.bearer_token, attempt, candidate, "v03-manual-owner-no-role")
        self.assertEqual(self.snapshot(), before)

        wrong_incarnation = self.delegate(
            "worker-missing",
            (ACCEPT_OUTCOME_ACTION, MANUAL_OWNER_ACTIONS["owner"]),
            f.work_ref("verify"),
            "v03-manual-owner-wrong-actor",
        )
        before = self.snapshot()
        with self.assertRaises(CandidateDeniedError):
            self.accept(wrong_incarnation.bearer_token, attempt, candidate,
                        "v03-manual-owner-wrong-actor-accept")
        self.assertEqual(self.snapshot(), before)

        accepted = self.accept(
            f.owner.bearer_token, attempt, candidate, "v03-manual-owner-valid-accept",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")

    def test_requirement_groups_and_ungrouped_checks_preserve_their_acceptance_semantics(self):
        f = self.fixture
        self.require_mixed_check_groups()
        attempt = f.claim("verify", f.owner.bearer_token, key="v03-grouped-check-claim-missing-ungrouped")
        for requirement in ("check-verify", "quorum-a", "quorum-b"):
            with f.open_writer() as authority:
                result = f.verification.execute(
                    authority, f.owner.bearer_token, attempt, f.requirement_ref(requirement),
                    idempotency_key=StableId("v03-grouped-evidence-" + requirement),
                    expected_revision=f.revision(),
                )
            self.assertEqual(result.state, "finalized")
        _, missing_ungrouped = self.report(
            f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
            "v03-report-missing-ungrouped-check",
        )
        before = self.snapshot()
        with self.assertRaises(CandidateDeniedError):
            self.accept(f.owner.bearer_token, attempt, missing_ungrouped,
                        "v03-accept-missing-ungrouped-check")
        self.assertEqual(self.snapshot(), before)
        with f.open_writer() as authority:
            rejected = self.acceptance.reject_candidate(
                authority, f.owner.bearer_token, attempt, missing_ungrouped,
                idempotency_key=StableId("v03-reject-missing-ungrouped-check"),
                expected_revision=f.revision(),
            )
        self.assertEqual(rejected.receipt.result["state"], "rejected")

        retry = f.claim("verify", f.owner.bearer_token, key="v03-grouped-check-claim-complete")
        for requirement in ("check-verify", "quorum-a", "quorum-b", "ungrouped-check"):
            with f.open_writer() as authority:
                result = f.verification.execute(
                    authority, f.owner.bearer_token, retry, f.requirement_ref(requirement),
                    idempotency_key=StableId("v03-complete-grouped-evidence-" + requirement),
                    expected_revision=f.revision(),
                )
            self.assertEqual(result.state, "finalized")
        _, complete = self.report(
            f.owner.bearer_token, retry, OutcomeDisposition.COMPLETED,
            "v03-report-grouped-checks-complete",
        )
        accept_only = self.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"),
            "v03-grouped-check-accept-only",
        )
        accepted = self.accept(
            accept_only.bearer_token, retry, complete, "v03-accept-grouped-checks-complete",
        )
        self.assertEqual(accepted.receipt.result["state"], "accepted")

    def test_no_change_and_evaluated_not_promoted_are_distinct_acceptable_outcomes(self):
        f = self.fixture
        document = json.loads(package_json())
        prerequisite = next(item for item in document["work_items"] if item["id"] == "prerequisite")
        prerequisite["acceptance"]["allowed_dispositions"].append("no_change")
        verify = next(item for item in document["work_items"] if item["id"] == "verify")
        verify["acceptance"]["allowed_dispositions"].append("evaluated_not_promoted")
        benchmark = next(item for item in document["requirements"] if item["id"] == "check-verify")
        benchmark["verification"] = {
            "kind": "benchmark", "version": 1,
            "config": {"metric": "latency", "operator": "lte", "threshold": 10.0,
                       "unit": "ms", "minimum_samples": 2},
        }
        benchmark["required_evidence"] = [{
            "name": "verify-report", "kind": "benchmark_sample", "version": 1,
        }]
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with f.open_writer() as authority:
            preview = f.plans.preview(authority, encoded)
            f.plans.commit(
                authority, f.owner.bearer_token, encoded,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("v03-noncompletion-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            f.plan = f.plans.load_accepted_plan(authority)

        class SourceAtQualifiedBase(FixtureSourceObserver):
            def observe(self, request):
                from dataclasses import replace
                result = super().observe(request)
                value = replace(result.value, source_digest=Sha256Digest("1" * 64))
                return replace(result, value=value)

        original_observer = self.acceptance.source_observer
        self.acceptance.source_observer = SourceAtQualifiedBase(f.clock)
        unchanged_attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-no-change-attempt")
        _, unchanged_candidate = self.report(
            f.owner.bearer_token, unchanged_attempt, OutcomeDisposition.NO_CHANGE,
            "v03-no-change-candidate",
        )
        approver = self.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("prerequisite"),
            "v03-no-change-approver",
        )
        unchanged = self.accept(
            approver.bearer_token, unchanged_attempt, unchanged_candidate,
            "v03-no-change-accept",
        )
        self.assertEqual(unchanged.receipt.result["state"], "accepted")
        self.acceptance.source_observer = original_observer

        f.verification.provider = BenchmarkVerifier(f.ledger_path, f.clock)
        benchmark_attempt = self.dispatch("verify", "v03-benchmark-dispatch")
        with f.open_writer() as authority:
            result = f.verification.execute(
                authority, benchmark_attempt.bearer_token, benchmark_attempt.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-benchmark-evidence"), expected_revision=f.revision(),
            )
        self.assertEqual(result.state, "rejected", result.inspection)
        _, benchmark_candidate = self.report(
            benchmark_attempt.bearer_token, benchmark_attempt.attempt.ref,
            OutcomeDisposition.EVALUATED_NOT_PROMOTED, "v03-benchmark-candidate",
        )
        benchmark_approver = self.delegate(
            "worker-missing", (ACCEPT_OUTCOME_ACTION,), f.work_ref("verify"),
            "v03-benchmark-approver",
        )
        evaluated = self.accept(
            benchmark_approver.bearer_token, benchmark_attempt.attempt.ref,
            benchmark_candidate, "v03-benchmark-accept",
        )
        self.assertEqual(evaluated.receipt.result["state"], "accepted")
        with f.open_reader() as authority:
            outcomes = authority.connection.execute(
                "SELECT disposition FROM outcomes ORDER BY version"
            ).fetchall()
            negative = authority.connection.execute(
                "SELECT o.outcome_id, e.result, v.state, fact.value_json FROM outcomes AS o "
                "JOIN outcome_evidence AS oe USING(outcome_id) JOIN evidence AS e USING(evidence_id) "
                "JOIN verification_attempts AS v USING(operation_id) "
                "JOIN evidence_facts AS fact USING(evidence_id) WHERE o.disposition = 'evaluated_not_promoted'"
            ).fetchone()
        self.assertEqual([row["disposition"] for row in outcomes], ["no_change", "evaluated_not_promoted"])
        self.assertEqual(negative["result"], "fail")
        self.assertEqual(negative["state"], "rejected")
        self.assertEqual(json.loads(negative["value_json"]), {"sample_count": 4, "unit": "ms", "value": 12.0})
        with f.open_reader() as authority:
            current = self.acceptance.read_outcome_applicability(
                authority,
                EntityRef(PROJECT.project_id, EntityKind.OUTCOME, StableId(negative["outcome_id"])),
                bearer_token=f.owner.bearer_token,
            )
        self.assertTrue(current.applicable, current.reasons)

    def test_missing_check_blocks_acceptance_and_rejection_leaves_work_retryable(self):
        f = self.fixture
        attempt = f.claim("verify", f.owner.bearer_token, key="v03-claim-without-check")
        _, candidate = self.report(f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                                   "v03-report-without-check")
        before = self.snapshot()
        with self.assertRaises(CandidateDeniedError):
            self.accept(f.owner.bearer_token, attempt, candidate, "v03-accept-without-check")
        self.assertEqual(self.snapshot(), before)

        with f.open_writer() as authority:
            rejected = self.acceptance.reject_candidate(
                authority, f.owner.bearer_token, attempt, candidate,
                idempotency_key=StableId("v03-reject-no-check"), expected_revision=f.revision(),
            )
        self.assertEqual(rejected.receipt.result["state"], "rejected")
        with f.open_reader() as authority:
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 0)
        retry = f.claim("verify", f.owner.bearer_token, key="v03-retry-after-rejected-candidate")
        self.assertNotEqual(retry, attempt)

    def test_failed_candidate_is_not_an_outcome_and_simple_no_gate_retry_can_complete(self):
        f = self.fixture
        first_attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-claim-failed-candidate")
        _, failed_candidate = self.report(
            f.owner.bearer_token, first_attempt, OutcomeDisposition.FAILED,
            "v03-report-process-failure",
        )
        before = self.snapshot()
        with self.assertRaises(CandidateDeniedError):
            self.accept(f.owner.bearer_token, first_attempt, failed_candidate,
                        "v03-accept-process-failure")
        self.assertEqual(self.snapshot(), before)

        with f.open_writer() as authority:
            self.acceptance.reject_candidate(
                authority, f.owner.bearer_token, first_attempt, failed_candidate,
                idempotency_key=StableId("v03-reject-process-failure"),
                expected_revision=f.revision(),
            )
        retry_attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-claim-simple-retry")
        _, completed_candidate = self.report(
            f.owner.bearer_token, retry_attempt, OutcomeDisposition.COMPLETED,
            "v03-report-simple-completion",
        )
        approver = self.delegate(
            "worker-other", (ACCEPT_OUTCOME_ACTION,), f.work_ref("prerequisite"),
            "v03-simple-approver",
        )
        self.accept(approver.bearer_token, retry_attempt, completed_candidate,
                    "v03-accept-simple-completion")
        with f.open_reader() as authority:
            outcome = authority.connection.execute(
                "SELECT disposition, attempt_id FROM outcomes"
            ).fetchone()
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM outcome_evidence"
            ).fetchone()[0], 0)
        self.assertEqual(tuple(outcome), ("completed", str(retry_attempt.entity_id)))

    def test_fresh_source_change_after_candidate_report_refuses_acceptance(self):
        f = self.fixture
        dispatched = self.dispatch("verify", "v03-dispatch-source-race")
        with f.open_writer() as authority:
            verified = f.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                f.requirement_ref("check-verify"),
                idempotency_key=StableId("v03-source-race-check"), expected_revision=f.revision(),
            )
        self.assertEqual(verified.state, "finalized")
        changing_source = FixtureSourceObserver(f.clock, change_after_first=True)
        self.acceptance.source_observer = changing_source
        _, candidate = self.report(
            dispatched.bearer_token, dispatched.attempt.ref, OutcomeDisposition.COMPLETED,
            "v03-source-race-report",
        )
        before = self.snapshot()
        with self.assertRaises(CandidateObservationMismatchError):
            self.accept(f.owner.bearer_token, dispatched.attempt.ref, candidate, "v03-source-race-accept")
        self.assertEqual(self.snapshot(), before)
        with f.open_reader() as authority:
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 0)

    def test_source_observation_must_match_qualified_workspace_before_candidate_report(self):
        f = self.fixture
        attempt = f.claim("prerequisite", f.owner.bearer_token, key="v03-claim-wrong-source")

        class WrongRepository(FixtureSourceObserver):
            def observe(self, request):
                result = super().observe(request)
                value = result.value
                from dataclasses import replace
                return replace(result, value=replace(value, repository_id=StableId("foreign-repository")))

        observer = WrongRepository(f.clock)
        self.acceptance.source_observer = observer
        before = self.snapshot()
        with self.assertRaises(CandidateObservationMismatchError):
            self.report(f.owner.bearer_token, attempt, OutcomeDisposition.COMPLETED,
                        "v03-wrong-source-report")
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
