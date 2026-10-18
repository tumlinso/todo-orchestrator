"""Independent end-to-end checks for durable verification attempts."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AttemptService,
    AuthorityAuthService,
    CapabilityDeniedError,
    CommandDispatcher,
    EligibilityAdapter,
    SQLiteAuthority,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.authority.auth import (
    AuthenticatedPrincipal,
    AuthenticationFailedError,
)
from todo_orchestrator.authority.attempts import (
    CLAIM_ACTION,
    FINISH_ACTION,
    HEARTBEAT_ACTION,
    RELEASE_ACTION,
    VERIFICATION_ACTION,
    VERIFICATION_RECONCILE_ACTION,
)
from todo_orchestrator.contracts import (
    ActorKind,
    EntityKind,
    EntityRef,
    EvidenceInput,
    EvidenceKind,
    EvidenceResult,
    Project,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Sha256Digest,
    SourceObservation,
    StableId,
    VerificationContract,
    VerificationEvidenceFact,
    VerificationInspection,
    VerificationInspectionState,
    VerificationObservation,
    VerificationRequest,
    WorkingTreeState,
    SourceObservationRequest,
    EffectInspectionRequest,
    provider_request_digest,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceQualification,
)
from todo_orchestrator.planning import PlanService, compile_plan_json
from todo_orchestrator.coordination import CoordinationService, RUN_DISPATCH_ACTION
from todo_orchestrator.verification.service import (
    VERIFY_ACTION,
    VERIFY_RECONCILE_ACTION,
    VerificationService,
    VerificationDeniedError,
    VerificationState,
    VerificationStateError,
)


PROJECT = Project(StableId("v02-independent-project"), StableId("v02-independent-authority"))
REPOSITORY = StableId("v02-independent-repository")
OWNER_PASSWORD = "independent V02 verification fixture owner 927"
OWNER_ACTIONS = (
    StableId("todo.plan.commit"),
    StableId("todo.capability.delegate"),
    StableId("todo.capability.revoke"),
    CLAIM_ACTION,
    HEARTBEAT_ACTION,
    RELEASE_ACTION,
    FINISH_ACTION,
    RUN_DISPATCH_ACTION,
    VERIFICATION_ACTION,
    VERIFICATION_RECONCILE_ACTION,
)
SOURCE_IDENTITY = ProviderIdentity(StableId("v02-source-observer"), "1")
VERIFIER_IDENTITY = ProviderIdentity(StableId("v02-verifier"), "1")


class FixedClock:
    def __init__(self, value: datetime | None = None):
        self.value = value or datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class SteppingClock:
    """Distinct monotonic phase timestamps for concurrent idempotency probes."""

    def __init__(self, value: datetime):
        self.value = value
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            self.value += timedelta(microseconds=1)
            return self.value


class FixtureAuthenticator:
    provider_id = "v02-independent-authenticator"

    def authenticate(self, credential):
        if credential not in {"worker-verify", "worker-missing", "worker-other"}:
            return None
        return AuthenticatedPrincipal(
            "subject-" + credential, ActorKind.AUTOMATION, credential,
        )


def _receipt_id(prefix: str, correlation: StableId) -> StableId:
    suffix = hashlib.sha256(str(correlation).encode("utf-8")).hexdigest()[:20]
    return StableId(prefix + "-" + suffix)


class FixtureAttemptHost:
    """Trusted temporary-workspace fixture for isolated SQLite authorities."""

    def __init__(self, clock):
        self.clock = clock

    def qualify_workspace(self, workspace_id, target, correlation_id):
        base = QualifiedSourceRevision(PROJECT.project_id, REPOSITORY, StableId("base-main"), "1" * 64)
        destination = QualifiedDestination(PROJECT.project_id, REPOSITORY, StableId("main"))
        receipt = ProviderReceipt(
            _receipt_id("v02-qualification", correlation_id),
            ProviderIdentity(StableId("v02-attempt-host"), "1"), correlation_id,
            Sha256Digest("2" * 64), base.ref, self.clock(),
        )
        return WorkspaceQualification(workspace_id, REPOSITORY, base, destination, receipt)

    def inspect_attempt(self, attempt, workspace):
        receipt = ProviderReceipt(
            _receipt_id("v02-attempt-inspection", attempt.attempt_id),
            ProviderIdentity(StableId("v02-attempt-host"), "1"), attempt.attempt_id,
            Sha256Digest("3" * 64), workspace.common_base.ref, self.clock(),
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


class FixtureSourceObserver:
    def __init__(self, clock, *, change_after_first: bool = False):
        self.clock = clock
        self.change_after_first = change_after_first
        self.requests: list[SourceObservationRequest] = []

    def observe(self, request: SourceObservationRequest):
        self.requests.append(request)
        changed = self.change_after_first and len(self.requests) > 1
        source_digest = Sha256Digest("5" * 64 if changed else "4" * 64)
        input_digest = Sha256Digest("b" * 64 if changed else "a" * 64)
        value = SourceObservation(
            REPOSITORY, source_digest, Sha256Digest("1" * 64),
            WorkingTreeState.DIRTY if changed else WorkingTreeState.CLEAN,
            (EvidenceInput(StableId("source-manifest"), input_digest),),
        )
        receipt = ProviderReceipt(
            _receipt_id("v02-source", request.correlation_id),
            SOURCE_IDENTITY, request.correlation_id, provider_request_digest(request),
            request.workspace_id, self.clock(),
        )
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.correlation_id, SOURCE_IDENTITY, value, receipt,
        )


class LedgerVerifier:
    """A restartable provider fake whose ledger represents an external effect."""

    def __init__(self, path: Path, clock, *, raise_after_effect: bool = False):
        self.path = path
        self.clock = clock
        self.raise_after_effect = raise_after_effect
        self._lock = threading.Lock()
        self.unavailable_commands: set[str] = set()

    def _read(self):
        if not self.path.exists():
            return {"verify_calls": 0, "inspect_calls": 0, "requests": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, value):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)

    @staticmethod
    def _request_value(request: VerificationRequest):
        fact_name = StableId(str(request.requirement.entity_id).removeprefix("check-") + "-report")
        fact_digest = Sha256Digest(hashlib.sha256(
            (str(request.operation_id) + ":report").encode("utf-8")
        ).hexdigest())
        return {
            "operation_id": str(request.operation_id),
            "verifier_id": str(request.verifier_id),
            "source_digest": request.expected_source.hex,
            "contract_digest": request.contract_digest.hex,
            "inputs": [{"name": str(item.name), "digest": item.digest.hex} for item in request.inputs],
            "evidence_facts": [{
                "name": str(fact_name), "kind": EvidenceKind.COMMAND_RESULT.value,
                "version": 1, "digest": fact_digest.hex,
            }],
        }

    @staticmethod
    def _observation(request_value):
        return VerificationObservation(
            StableId(request_value["operation_id"]), EvidenceResult.PASS,
            StableId(request_value["verifier_id"]), VERIFIER_IDENTITY.version,
            Sha256Digest(request_value["source_digest"]),
            Sha256Digest(request_value["contract_digest"]),
            tuple(EvidenceInput(StableId(item["name"]), Sha256Digest(item["digest"]))
                  for item in request_value["inputs"]),
            (),
            tuple(VerificationEvidenceFact(
                StableId(item["name"]), EvidenceKind(item["kind"]), item["version"],
                Sha256Digest(item["digest"]),
            ) for item in request_value["evidence_facts"]),
        )

    def _result(self, correlation_id, value, request_digest, provenance_ref):
        receipt = ProviderReceipt(
            _receipt_id("v02-verifier-receipt", correlation_id), VERIFIER_IDENTITY,
            correlation_id, request_digest, provenance_ref, self.clock(),
        )
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, correlation_id, VERIFIER_IDENTITY, value, receipt,
        )

    @staticmethod
    def _receipt_mapping(receipt: ProviderReceipt) -> dict[str, str]:
        return {
            "receipt_id": str(receipt.receipt_id),
            "correlation_id": str(receipt.correlation_id),
            "request_digest": receipt.request_digest.hex,
            "provenance_ref": str(receipt.provenance_ref),
        }

    def _original_receipt(self, stored: dict[str, str]) -> ProviderReceipt:
        return ProviderReceipt(
            StableId(stored["receipt_id"]), VERIFIER_IDENTITY,
            StableId(stored["correlation_id"]), Sha256Digest(stored["request_digest"]),
            StableId(stored["provenance_ref"]), self.clock(),
        )

    def verify(self, request: VerificationRequest):
        command = request.contract.config["argv"][0]
        if command in self.unavailable_commands:
            return ProviderResult(
                ProviderStatus.UNAVAILABLE, request.operation_id,
                reason_code=StableId("configured-verifier-unavailable"),
            )
        request_value = self._request_value(request)
        receipt = ProviderReceipt(
            _receipt_id("v02-verifier-receipt", request.operation_id), VERIFIER_IDENTITY,
            request.operation_id, provider_request_digest(request), request.operation_id, self.clock(),
        )
        request_value["original_receipt"] = self._receipt_mapping(receipt)
        with self._lock:
            ledger = self._read()
            ledger["verify_calls"] += 1
            ledger["requests"][str(request.operation_id)] = request_value
            self._write(ledger)
        if self.raise_after_effect:
            raise RuntimeError("fixture interruption after external effect")
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.operation_id, VERIFIER_IDENTITY,
            self._observation(request_value), receipt,
        )

    def inspect(self, request: EffectInspectionRequest):
        with self._lock:
            ledger = self._read()
            ledger["inspect_calls"] += 1
            self._write(ledger)
        request_value = ledger["requests"].get(str(request.operation_id))
        if request_value is None:
            inspection = VerificationInspection(
                request.operation_id, VerificationInspectionState.NOT_STARTED,
            )
        else:
            inspection = VerificationInspection(
                request.operation_id, VerificationInspectionState.COMPLETED,
                self._observation(request_value),
                self._original_receipt(request_value["original_receipt"]),
            )
        return self._result(
            request.correlation_id, inspection, provider_request_digest(request),
            request.operation_id,
        )

    def counts(self):
        ledger = self._read()
        return ledger["verify_calls"], ledger["inspect_calls"]


def package_json():
    def work(identifier, path, *, groups=()):
        return {
            "id": identifier,
            "title": identifier,
            "objective": "Exercise durable verification for " + identifier,
            "outcome": "Its exact authored contract receives an observation",
            "scope": {"paths": [{"path": path, "access": "write"}], "concepts": [], "locks": []},
            "ownership": {"mode": "any", "actors": []},
            "acceptance": {
                "assertions": ["the stored verification binds current inputs"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
            **({"requirement_groups": list(groups)} if groups else {}),
        }

    check_group = lambda identifier: {"kind": "check", "mode": "all", "members": [identifier]}
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "v02-independent-verification",
        "project": {
            "project_id": str(PROJECT.project_id),
            "authority_id": str(PROJECT.authority_id),
        },
        "work_items": [
            work("verify", "src/verify", groups=(check_group("check-verify"),)),
            work("missing", "docs/missing", groups=(check_group("check-missing"),)),
            work("other", "reports/other", groups=(check_group("check-other"),)),
            work("blocked", "src/blocked", groups=({
                "kind": "prerequisite", "mode": "all", "members": ["needs-base"],
            },)),
            work("prerequisite", "src/prerequisite"),
        ],
        "requirements": [
            {
                "id": "check-verify", "work_item_id": "verify", "kind": "check",
                "description": "Run the authored verification command", "check_key": "check-verify",
                "verification": {"kind": "command", "version": 1,
                                 "config": {"argv": ["verify-result"], "timeout_seconds": 30}},
                "required_evidence": [{"name": "verify-report", "kind": "command_result", "version": 1}],
            },
            {
                "id": "check-missing", "work_item_id": "missing", "kind": "check",
                "description": "Run a check with an unavailable verifier", "check_key": "check-missing",
                "verification": {"kind": "command", "version": 1,
                                 "config": {"argv": ["missing-verifier"], "timeout_seconds": 30}},
                "required_evidence": [{"name": "missing-report", "kind": "command_result", "version": 1}],
            },
            {
                "id": "check-other", "work_item_id": "other", "kind": "check",
                "description": "Run an unrelated check", "check_key": "check-other",
                "verification": {"kind": "command", "version": 1,
                                 "config": {"argv": ["other-result"], "timeout_seconds": 30}},
                "required_evidence": [{"name": "other-report", "kind": "command_result", "version": 1}],
            },
            {
                "id": "needs-base", "work_item_id": "blocked", "kind": "prerequisite",
                "description": "An earlier work item must be accepted",
                "target": {
                    "project_id": str(PROJECT.project_id),
                    "kind": "work_item",
                    "entity_id": "prerequisite",
                },
            },
        ],
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True)


class IndependentVerificationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "authority.sqlite3"
        self.ledger_path = self.root / "provider-effects.json"
        self.clock = FixedClock()
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(
            self.dispatcher, clock=self.clock, authenticator=FixtureAuthenticator(),
        )
        with self.open_writer() as authority:
            enrolled = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="verification fixture owner",
                idempotency_key=StableId("v02-owner-enrollment"), expected_revision=0,
            )
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=OWNER_ACTIONS, scope=PROJECT.ref,
                expires_at=self.clock() + timedelta(hours=1),
                idempotency_key=StableId("v02-owner-token"),
                expected_revision=enrolled.receipt.semantic_revision,
            )
            self.plans = PlanService(self.auth)
            source = package_json()
            preview = self.plans.preview(authority, source)
            self.plans.commit(
                authority, self.owner.bearer_token, source,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("v02-accepted-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            self.plan = self.plans.load_accepted_plan(authority)

        self.host = FixtureAttemptHost(self.clock)
        self.attempts = AttemptService(
            self.auth, eligibility=EligibilityAdapter(clock=self.clock),
            host=self.host, clock=self.clock, lease_duration=timedelta(minutes=5),
        )
        self.coordination = CoordinationService(self.auth, attempts=self.attempts)
        self.source = FixtureSourceObserver(self.clock)
        self.verifier = LedgerVerifier(self.ledger_path, self.clock)
        self.verification = VerificationService(
            self.auth, source_observer=self.source, source_identity=SOURCE_IDENTITY,
            provider=self.verifier, provider_identity=VERIFIER_IDENTITY, clock=self.clock,
            max_source_age=timedelta(minutes=5),
        )

    def open_writer(self, path: Path | None = None):
        return SQLiteAuthority.open_writer(path or self.path, PROJECT)

    def open_reader(self, path: Path | None = None):
        return SQLiteAuthority.open_reader(path or self.path, PROJECT)

    def work_ref(self, work_id: str) -> EntityRef:
        return next(
            item.definition.ref for item in self.plan.work_items
            if str(item.definition.work_item_id) == work_id
        )

    def requirement_ref(self, requirement_id: str) -> EntityRef:
        return next(
            item.definition.ref for item in self.plan.requirements
            if str(item.definition.requirement_id) == requirement_id
        )

    def revision(self) -> int:
        with self.open_reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def delegate_worker(self, work_id: str, credential: str, *, key: str, can_release: bool = False):
        actions = [CLAIM_ACTION, VERIFY_ACTION, VERIFY_RECONCILE_ACTION]
        if can_release:
            actions.append(RELEASE_ACTION)
        with self.open_writer() as authority:
            return self.auth.delegate(
                authority, self.owner.bearer_token, credential,
                actions=tuple(actions),
                scope=self.work_ref(work_id),
                expires_at=self.clock() + timedelta(minutes=30),
                idempotency_key=StableId(key), expected_revision=self.revision(),
            )

    def claim(self, work_id: str, token: str, *, key: str):
        with self.open_writer() as authority:
            result = self.attempts.claim(
                authority, token, self.work_ref(work_id), self.plan,
                idempotency_key=StableId(key), expected_revision=self.revision(),
                workspace_id=StableId("workspace-" + work_id),
            )
        return EntityRef(PROJECT.project_id, EntityKind.ATTEMPT, StableId(result.receipt.result["attempt_id"]))

    def state_snapshot(self):
        with self.open_reader() as authority:
            fingerprint = self.dispatcher.logical_fingerprint(authority)
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            counts = tuple(
                (table, authority.connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
                for table in ("verification_attempts", "evidence", "external_operations",
                              "command_receipts", "command_idempotency", "authority_events")
            )
        return fingerprint, revision, counts

    def test_pending_check_can_be_claimed_and_executed_but_real_prerequisites_still_block(self):
        worker = self.delegate_worker("verify", "worker-verify", key="v02-worker-verify")
        self.assertEqual(set(worker.capability.actions), {CLAIM_ACTION, VERIFY_ACTION, VERIFY_RECONCILE_ACTION})
        self.assertNotIn(StableId("todo.outcome.accept"), worker.capability.actions)

        blocked_before = self.state_snapshot()
        with self.assertRaises(AttemptAdmissionDeniedError):
            self.claim("blocked", self.owner.bearer_token, key="v02-blocked-prerequisite")
        self.assertEqual(self.state_snapshot(), blocked_before)

        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-pending-check")
        self.assertIsNotNone(attempt_ref)
        requirement = next(
            item.definition for item in self.plan.requirements
            if item.definition.ref == self.requirement_ref("check-verify")
        )
        self.assertIsNotNone(requirement.verification)
        with self.open_writer() as authority:
            operation = self.verification.execute(
                authority, worker.bearer_token, attempt_ref, requirement.ref,
                idempotency_key=StableId("v02-execute-verification"),
                expected_revision=self.revision(),
            )
        self.assertEqual(operation.state, VerificationState.FINALIZED)
        self.assertEqual(operation.attempt, attempt_ref)
        self.assertEqual(operation.requirement, requirement.ref)
        self.assertEqual(operation.source_digest, Sha256Digest("4" * 64))
        self.assertEqual(operation.contract_digest,
                         Sha256Digest(hashlib.sha256(json.dumps(
                             requirement.verification.to_mapping(), ensure_ascii=False,
                             allow_nan=False, sort_keys=True, separators=(",", ":"),
                         ).encode("utf-8")).hexdigest()))
        self.assertEqual(self.verifier.counts()[0], 1)
        self.assertEqual(self.source.requests[0].contract, requirement.verification)
        self.assertEqual(self.source.requests[0].attempt, attempt_ref)
        self.assertEqual(self.source.requests[0].workspace_id, StableId("workspace-verify"))
        with self.open_reader() as authority:
            evidence = authority.connection.execute(
                "SELECT attempt_id, requirement_id, operation_id, result, source_digest "
                "FROM evidence WHERE evidence_id = ?", (str(operation.evidence_id),),
            ).fetchone()
            facts = tuple(authority.connection.execute(
                "SELECT fact_name, fact_kind, fact_version FROM evidence_facts WHERE evidence_id = ?",
                (str(operation.evidence_id),),
            ))
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 0)
        self.assertEqual(tuple(evidence), (
            str(attempt_ref.entity_id), "check-verify", str(operation.operation.entity_id),
            "pass", "4" * 64,
        ))
        self.assertEqual(tuple(tuple(row) for row in facts),
                         (("verify-report", "command_result", 1),))

    def test_dispatch_derives_verification_rights_and_heartbeat_renews_exact_child_grant(self):
        with self.open_writer() as authority:
            dispatched = self.coordination.dispatch(
                authority, self.owner.bearer_token, self.plan,
                workspace_id=StableId("workspace-dispatched-verify"),
                idempotency_key=StableId("v02-dispatch-verify"),
                expected_revision=self.revision(), work_item=self.work_ref("verify"),
            )
        child = dispatched.capability
        expected_actions = {
            HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION,
            VERIFICATION_ACTION, VERIFICATION_RECONCILE_ACTION,
        }
        self.assertEqual(set(child.actions), expected_actions)
        self.assertEqual(child.attempt, dispatched.attempt.ref)
        self.assertEqual(child.scope, dispatched.attempt.work_item)
        initial_expiry = child.expires_at
        self.assertEqual(initial_expiry, dispatched.attempt.lease.expires_at)
        self.assertLess(initial_expiry, self.owner.capability.expires_at)

        with self.open_writer() as authority:
            operation = self.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                self.requirement_ref("check-verify"),
                idempotency_key=StableId("v02-dispatched-verification"),
                expected_revision=self.revision(),
            )
        self.assertEqual(operation.state, VerificationState.FINALIZED)

        self.clock.value += timedelta(minutes=1)
        with self.open_writer() as authority:
            heartbeat = self.attempts.heartbeat(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                dispatched.attempt.lease.lease_id, self.plan,
                idempotency_key=StableId("v02-dispatched-heartbeat"),
                expected_revision=self.revision(),
            )
        renewed_lease_expiry = datetime.fromisoformat(heartbeat.receipt.result["lease_expires_at"])
        self.assertGreater(renewed_lease_expiry, initial_expiry)
        self.assertLessEqual(renewed_lease_expiry, self.owner.capability.expires_at)

        with self.open_reader() as authority:
            cap_expiry = datetime.fromisoformat(authority.connection.execute(
                "SELECT expires_at FROM capabilities WHERE capability_id = ?",
                (str(child.capability_id),),
            ).fetchone()[0])
            stored_actions = {
                StableId(row[0]) for row in authority.connection.execute(
                    "SELECT action FROM capability_actions WHERE capability_id = ?",
                    (str(child.capability_id),),
                )
            }
        self.assertEqual(stored_actions, expected_actions)
        self.assertEqual(cap_expiry, renewed_lease_expiry)

        # The renewed derived bearer remains usable after its original lease
        # bound, but before the renewed lease and parent capability expire.
        self.clock.value = initial_expiry + timedelta(seconds=1)
        with self.open_writer() as authority:
            after_renewal = self.verification.execute(
                authority, dispatched.bearer_token, dispatched.attempt.ref,
                self.requirement_ref("check-verify"),
                idempotency_key=StableId("v02-dispatched-verification-after-renewal"),
                expected_revision=self.revision(),
            )
        self.assertEqual(after_renewal.state, VerificationState.FINALIZED)

    def test_effect_is_inspected_after_real_process_restart_without_blind_reexecution(self):
        worker = self.delegate_worker("verify", "worker-verify", key="v02-worker-restart")
        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-restart")
        self.verifier.raise_after_effect = True
        with self.open_writer() as authority:
            interrupted = self.verification.execute(
                authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                idempotency_key=StableId("v02-interrupted-verification"),
            )
        self.assertEqual(interrupted.state, VerificationState.UNKNOWN)
        self.assertEqual(self.verifier.counts(), (1, 0))
        self.assertIsNotNone(interrupted.request_digest)

        repository_root = Path(__file__).resolve().parents[2]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join((
            str(repository_root / "src"), str(repository_root),
        ))
        payload = {
            "path": str(self.path),
            "project_id": str(PROJECT.project_id),
            "authority_id": str(PROJECT.authority_id),
            "attempt_id": str(attempt_ref.entity_id),
            "operation_id": str(interrupted.operation.entity_id),
            "token": worker.bearer_token,
            "ledger_path": str(self.ledger_path),
            "now": self.clock().isoformat(),
        }
        script = r'''
import json, sys
from datetime import datetime, timezone
from pathlib import Path
from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, SQLiteAuthority
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, StableId
from todo_orchestrator.verification.service import VerificationService
from tests.verification.test_execution_independent import (
    FixedClock, FixtureSourceObserver, LedgerVerifier, SOURCE_IDENTITY, VERIFIER_IDENTITY,
)
request = json.load(sys.stdin)
project = Project(StableId(request["project_id"]), StableId(request["authority_id"]))
clock = FixedClock(datetime.fromisoformat(request["now"]).astimezone(timezone.utc))
auth = AuthorityAuthService(CommandDispatcher(), clock=clock)
source = FixtureSourceObserver(clock)
provider = LedgerVerifier(Path(request["ledger_path"]), clock)
service = VerificationService(
    auth, source_observer=source, source_identity=SOURCE_IDENTITY,
    provider=provider, provider_identity=VERIFIER_IDENTITY, clock=clock,
)
operation_ref = EntityRef(project.project_id, EntityKind.EXTERNAL_OPERATION, StableId(request["operation_id"]))
with SQLiteAuthority.open_writer(Path(request["path"]), project) as authority:
    view = service.reconcile(
        authority, request["token"], operation_ref,
        idempotency_key=StableId("v02-reconcile-after-restart"),
    )
print(json.dumps({"state": view.state, "evidence_id": None if view.evidence_id is None else str(view.evidence_id)}))
'''
        process = subprocess.run(
            [sys.executable, "-S", "-c", script], input=json.dumps(payload), text=True,
            capture_output=True, env=environment, cwd=repository_root, timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        recovered = json.loads(process.stdout.strip())
        self.assertEqual(recovered["state"], VerificationState.FINALIZED)
        self.assertIsNotNone(recovered["evidence_id"])
        self.assertEqual(self.verifier.counts(), (1, 1))
        with self.open_reader() as authority:
            stored = authority.connection.execute(
                "SELECT state, evidence_id, source_digest FROM verification_attempts WHERE operation_id = ?",
                (str(interrupted.operation.entity_id),),
            ).fetchone()
            self.assertEqual(tuple(stored), ("finalized", recovered["evidence_id"], "4" * 64))
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM evidence WHERE operation_id = ?",
                (str(interrupted.operation.entity_id),),
            ).fetchone()[0], 1)

    def test_proven_not_started_requires_explicit_retry_of_same_operation(self):
        worker = self.delegate_worker("verify", "worker-verify", key="v02-worker-not-started")
        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-not-started")
        key = StableId("v02-provider-not-started")
        with self.open_writer() as authority:
            with patch.object(self.verifier, "verify", side_effect=KeyboardInterrupt("interrupt before effect")):
                with self.assertRaisesRegex(KeyboardInterrupt, "interrupt before effect"):
                    self.verification.execute(
                        authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                        idempotency_key=key,
                    )
        with self.open_writer() as authority:
            prepared = self.verification._view_for_idempotency(authority, key)
            self.assertEqual(prepared.state, VerificationState.EXECUTING)
            with self.assertRaises(VerificationStateError):
                self.verification.retry_not_started(
                    authority, worker.bearer_token, prepared.operation,
                    idempotency_key=StableId("v02-illegal-preinspect-retry"),
                )
        self.assertEqual(self.verifier.counts(), (0, 0))

        with self.open_writer() as authority:
            not_started = self.verification.reconcile(
                authority, worker.bearer_token, prepared.operation,
                idempotency_key=StableId("v02-inspect-not-started"),
            )
        self.assertEqual(not_started.state, VerificationState.NOT_STARTED)
        self.assertEqual(self.verifier.counts(), (0, 1))
        with self.open_writer() as authority:
            retried = self.verification.retry_not_started(
                authority, worker.bearer_token, prepared.operation,
                idempotency_key=StableId("v02-authorized-explicit-retry"),
            )
        self.assertEqual(retried.operation, prepared.operation)
        self.assertEqual(retried.request_digest, prepared.request_digest)
        self.assertEqual(retried.state, VerificationState.FINALIZED)
        self.assertEqual(self.verifier.counts(), (1, 1))
        ledger = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        self.assertEqual(tuple(ledger["requests"]), (str(prepared.operation.entity_id),))
        self.assertEqual(ledger["requests"][str(prepared.operation.entity_id)]["source_digest"], "4" * 64)

    def test_proven_not_started_cannot_retry_after_safe_attempt_release(self):
        worker = self.delegate_worker(
            "verify", "worker-verify", key="v02-worker-release-not-started", can_release=True,
        )
        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-release-not-started")
        key = StableId("v02-release-not-started")
        with self.open_writer() as authority:
            with patch.object(self.verifier, "verify", side_effect=KeyboardInterrupt("interrupt before effect")):
                with self.assertRaisesRegex(KeyboardInterrupt, "interrupt before effect"):
                    self.verification.execute(
                        authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                        idempotency_key=key,
                    )
        with self.open_writer() as authority:
            prepared = self.verification._view_for_idempotency(authority, key)
            self.assertEqual(prepared.state, VerificationState.EXECUTING)
            not_started = self.verification.reconcile(
                authority, worker.bearer_token, prepared.operation,
                idempotency_key=StableId("v02-release-inspect-not-started"),
            )
        self.assertEqual(not_started.state, VerificationState.NOT_STARTED)
        with self.open_reader() as authority:
            attempt = self.attempts._attempt_for_service(authority, attempt_ref)
        self.assertIsNotNone(attempt)
        self.assertIsNotNone(attempt.lease)
        with self.open_writer() as authority:
            released = self.attempts.release(
                authority, worker.bearer_token, attempt_ref, attempt.lease.lease_id,
                idempotency_key=StableId("v02-release-attempt-before-retry"),
                expected_revision=self.revision(),
            )
        self.assertEqual(released.receipt.result["state"], "released")
        self.assertEqual(self.verifier.counts(), (0, 1))
        before_retry = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(VerificationDeniedError):
                self.verification.retry_not_started(
                    authority, worker.bearer_token, prepared.operation,
                    idempotency_key=StableId("v02-forbidden-retry-after-release"),
                )
        self.assertEqual(self.verifier.counts(), (0, 1))
        self.assertEqual(self.state_snapshot(), before_retry)

    def test_concurrent_exact_retries_of_prepared_operation_create_one_external_effect(self):
        worker = self.delegate_worker("verify", "worker-verify", key="v02-worker-concurrent")
        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-concurrent")
        key = StableId("v02-concurrent-prepared")
        with self.open_writer() as authority:
            with patch.object(self.verification, "_start_and_call", side_effect=RuntimeError("simulated crash")):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.verification.execute(
                        authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                        idempotency_key=key,
                    )
        with self.open_writer() as authority:
            prepared = self.verification._view_for_idempotency(authority, key)
        self.assertIsNotNone(prepared)
        self.assertEqual(prepared.state, VerificationState.PREPARED)

        stepping_clock = SteppingClock(self.clock.value)
        self.clock = stepping_clock
        self.auth.clock = stepping_clock
        self.attempts.clock = stepping_clock
        self.host.clock = stepping_clock
        self.source.clock = stepping_clock
        self.verifier.clock = stepping_clock
        self.verification.clock = stepping_clock

        rendezvous = threading.Barrier(2)
        start_and_call = self.verification._start_and_call

        def retry_together(*args, **kwargs):
            rendezvous.wait(timeout=10)
            return start_and_call(*args, **kwargs)

        def retry(_index):
            with self.open_writer() as authority:
                return self.verification.execute(
                    authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                    idempotency_key=key,
                )

        with patch.object(self.verification, "_start_and_call", side_effect=retry_together):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(pool.map(retry, range(2)))
        self.assertEqual(self.verifier.counts()[0], 1)
        self.assertTrue(all(result.operation == prepared.operation for result in results))
        with self.open_reader() as authority:
            state = authority.connection.execute(
                "SELECT state FROM verification_attempts WHERE operation_id = ?",
                (str(prepared.operation.entity_id),),
            ).fetchone()[0]
            evidence_count = authority.connection.execute(
                "SELECT count(*) FROM evidence WHERE operation_id = ?",
                (str(prepared.operation.entity_id),),
            ).fetchone()[0]
        self.assertEqual(state, VerificationState.FINALIZED)
        self.assertEqual(evidence_count, 1)

    def test_trusted_source_observer_change_marks_historical_evidence_stale(self):
        worker = self.delegate_worker("verify", "worker-verify", key="v02-worker-stale")
        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-stale")
        self.source.change_after_first = True
        with self.open_writer() as authority:
            operation = self.verification.execute(
                authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                idempotency_key=StableId("v02-source-drift"),
            )
        self.assertEqual(operation.state, VerificationState.STALE)
        self.assertEqual(operation.source_digest, Sha256Digest("4" * 64))
        self.assertIsNotNone(operation.evidence_id)
        with self.open_reader() as authority:
            evidence = authority.connection.execute(
                "SELECT result, source_digest FROM evidence WHERE evidence_id = ?",
                (str(operation.evidence_id),),
            ).fetchone()
            final_receipt = json.loads(authority.connection.execute(
                "SELECT final_source_receipt_json FROM verification_attempts WHERE operation_id = ?",
                (str(operation.operation.entity_id),),
            ).fetchone()[0])
        self.assertEqual(tuple(evidence), ("pass", "4" * 64))
        self.assertEqual(final_receipt["source"]["source_digest"], "5" * 64)
        self.assertEqual(final_receipt["source"]["working_tree"], "dirty")
        self.assertEqual(final_receipt["source"]["inputs"][0]["digest"], "b" * 64)

    def test_unavailable_verifier_is_local_and_unrelated_check_can_still_run(self):
        worker_missing = self.delegate_worker("missing", "worker-missing", key="v02-worker-missing")
        worker_other = self.delegate_worker("other", "worker-other", key="v02-worker-other")
        missing_attempt = self.claim("missing", worker_missing.bearer_token, key="v02-claim-missing")
        other_attempt = self.claim("other", worker_other.bearer_token, key="v02-claim-other")
        self.verifier.unavailable_commands.add("missing-verifier")

        with self.open_writer() as authority:
            unavailable = self.verification.execute(
                authority, worker_missing.bearer_token, missing_attempt,
                self.requirement_ref("check-missing"),
                idempotency_key=StableId("v02-missing-verifier"),
            )
        self.assertEqual(unavailable.state, VerificationState.UNKNOWN)
        self.assertIsNone(unavailable.evidence_id)

        with self.open_writer() as authority:
            independent = self.verification.execute(
                authority, worker_other.bearer_token, other_attempt,
                self.requirement_ref("check-other"),
                idempotency_key=StableId("v02-independent-verifier"),
            )
        self.assertEqual(independent.state, VerificationState.FINALIZED)
        self.assertEqual(self.verifier.counts()[0], 1)
        with self.open_reader() as authority:
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM evidence WHERE operation_id = ?",
                (str(unavailable.operation.entity_id),),
            ).fetchone()[0], 0)
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM evidence WHERE operation_id = ?",
                (str(independent.operation.entity_id),),
            ).fetchone()[0], 1)

    def test_stale_reconcile_and_revoked_exact_retry_refuse_before_provider_or_state_change(self):
        worker = self.delegate_worker("verify", "worker-verify", key="v02-worker-refusal")
        attempt_ref = self.claim("verify", worker.bearer_token, key="v02-claim-refusal")
        self.verifier.unavailable_commands.add("verify-result")
        with self.open_writer() as authority:
            operation = self.verification.execute(
                authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                idempotency_key=StableId("v02-refused-retry"),
            )
        self.assertEqual(operation.state, VerificationState.UNKNOWN)
        current_revision = self.revision()
        provider_counts = self.verifier.counts()
        before = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(StaleAuthorityRevisionError):
                self.verification.reconcile(
                    authority, worker.bearer_token, operation.operation,
                    idempotency_key=StableId("v02-stale-reconcile"),
                    expected_revision=current_revision - 1,
                )
        self.assertEqual(self.verifier.counts(), provider_counts)
        self.assertEqual(self.state_snapshot(), before)

        with self.open_writer() as authority:
            self.auth.revoke_family(
                authority, self.owner.bearer_token, worker.capability.capability_id,
                idempotency_key=StableId("v02-revoke-worker"), expected_revision=self.revision(),
            )
        after_revoke = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises((AuthenticationFailedError, CapabilityDeniedError)):
                self.verification.execute(
                    authority, worker.bearer_token, attempt_ref, self.requirement_ref("check-verify"),
                    idempotency_key=StableId("v02-refused-retry"),
                )
        self.assertEqual(self.verifier.counts(), provider_counts)
        self.assertEqual(self.state_snapshot(), after_revoke)


if __name__ == "__main__":
    unittest.main()
