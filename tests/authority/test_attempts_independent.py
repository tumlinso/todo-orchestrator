"""Independent adversarial integration tests for attempt claims and leases."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AuthenticationFailedError,
    AuthorityAuthService,
    CommandDispatcher,
    EligibilityAdapter,
    SQLiteAuthority,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.authority.attempts import (
    AttemptAdmissionDeniedError,
    AttemptLeaseMismatchError,
    AttemptOwnershipError,
    AttemptObservationMismatchError,
    AttemptService,
    CLAIM_ACTION,
    HEARTBEAT_ACTION,
    RECONCILE_ACTION,
    RELEASE_ACTION,
)
from todo_orchestrator.contracts import (
    ActorKind,
    AttemptState,
    EntityKind,
    EntityRef,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.contracts.providers import ProviderIdentity, ProviderReceipt
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    EligibilityRequest,
    EligibilityStatus,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceQualification,
)
from todo_orchestrator.planning import compile_plan, parse_plan_json
from tests.authority.plan_fixtures import commit_plan


NOW = datetime(2026, 10, 18, 17, 0, tzinfo=timezone.utc)
PROJECT = Project(StableId("project-attempts-independent"), StableId("authority-attempts-independent"))
OWNER_PASSWORD = "fixture independent attempt owner 927"
OWNER_REVOKE_ACTION = StableId("todo.capability.revoke")
WORK_ACTION = StableId("work:execute")
REPOSITORY_ID = StableId("attempts-fixture-repository")
PROVIDER = ProviderIdentity(StableId("attempts-fixture-host"), "1")
ATTEMPT_ACTIONS = (
    WORK_ACTION,
    StableId("todo.plan.commit"),
    CLAIM_ACTION,
    HEARTBEAT_ACTION,
    RELEASE_ACTION,
    RECONCILE_ACTION,
    OWNER_REVOKE_ACTION,
)


def make_plan(project: Project, *, work_item_ids: tuple[str, ...] | None = None):
    scopes = {
        "work-a": [("src/pkg", "write")],
        "work-b": [("src/pkg/sub", "write")],
        "work-c": [("docs/guide.md", "write")],
        "work-d": [("assets/model.bin", "write")],
    }
    locks = {
        "work-a": [("model-cache", "exclusive")],
        "work-d": [("model-cache", "exclusive")],
    }
    selected_work_items = work_item_ids or tuple(scopes)
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "attempts-independent-fixture",
        "project": {"project_id": str(project.project_id), "authority_id": str(project.authority_id)},
        "work_items": [
            {
                "id": work_id,
                "title": work_id,
                "objective": "Exercise an attempt authority boundary",
                "outcome": "The attempt behavior is checked",
                "scope": {
                    "paths": [{"path": path, "access": access} for path, access in paths],
                    "concepts": [],
                    "locks": [
                        {"name": name, "mode": mode}
                        for name, mode in locks.get(work_id, ())
                    ],
                },
                "ownership": {"mode": "any", "actors": []},
                "acceptance": {"assertions": [], "required_evidence": [],
                               "allowed_dispositions": ["completed"]},
            }
            for work_id, paths in scopes.items()
            if work_id in selected_work_items
        ],
    }
    parsed = parse_plan_json(json.dumps(document))
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    compiled = compile_plan(parsed.package, project)
    if not compiled.ok:
        raise AssertionError(compiled.diagnostics)
    return compiled.plan


def _qualification(project: Project, workspace_id: StableId, correlation_id: StableId,
                   *, base_ref: str = "base-main", base_digest: str = "1" * 64,
                   base_project: StableId | None = None,
                   destination_project: StableId | None = None,
                   receipt_correlation: StableId | None = None,
                   observed_at: datetime = NOW) -> WorkspaceQualification:
    common_base = QualifiedSourceRevision(
        base_project or project.project_id, REPOSITORY_ID, StableId(base_ref), base_digest
    )
    destination = QualifiedDestination(
        destination_project or project.project_id, REPOSITORY_ID, StableId("main")
    )
    receipt = ProviderReceipt(
        StableId("qualification-" + hashlib.sha256(
            f"{workspace_id}:{correlation_id}".encode("utf-8")
        ).hexdigest()[:20]),
        PROVIDER,
        receipt_correlation or correlation_id,
        Sha256Digest("2" * 64),
        common_base.ref,
        observed_at,
    )
    return WorkspaceQualification(workspace_id, REPOSITORY_ID, common_base, destination, receipt)


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class FakeAttemptHost:
    """Deterministic trusted host fixture with explicit wrong/stale responses."""

    def __init__(self, project: Project, *, clock: MutableClock,
                 base_by_workspace: dict[str, tuple[str, str]] | None = None,
                 qualification_mode: str | None = None,
                 safety_by_work_item: dict[str, tuple[SourceSafety, ProcessLiveness, ChildActivity]] | None = None,
                 observation_mode: str | None = None) -> None:
        self.project = project
        self.clock = clock
        self.base_by_workspace = base_by_workspace or {}
        self.qualification_mode = qualification_mode
        self.safety_by_work_item = safety_by_work_item or {}
        self.observation_mode = observation_mode

    def qualify_workspace(self, workspace_id: StableId, target: EntityRef,
                          correlation_id: StableId) -> WorkspaceQualification:
        base_ref, base_digest = self.base_by_workspace.get(
            str(workspace_id), ("base-main", "1" * 64)
        )
        qualification = _qualification(
            self.project, workspace_id, correlation_id, base_ref=base_ref,
            base_digest=base_digest, observed_at=self.clock(),
        )
        if self.qualification_mode == "wrong_workspace":
            return WorkspaceQualification(
                StableId("wrong-workspace"), qualification.repository_id,
                qualification.common_base, qualification.destination, qualification.receipt,
            )
        if self.qualification_mode == "wrong_correlation":
            return _qualification(
                self.project, workspace_id, correlation_id, base_ref=base_ref,
                base_digest=base_digest, receipt_correlation=StableId("wrong-correlation"),
                observed_at=self.clock(),
            )
        if self.qualification_mode == "wrong_project":
            foreign_project = StableId("foreign-project")
            return _qualification(
                self.project, workspace_id, correlation_id, base_ref=base_ref,
                base_digest=base_digest, base_project=foreign_project,
                destination_project=foreign_project,
                observed_at=self.clock(),
            )
        return qualification

    def inspect_attempt(self, attempt, workspace: WorkspaceQualification) -> AttemptSafetyObservation:
        source, process, children = self.safety_by_work_item.get(
            str(attempt.work_item.entity_id),
            (SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE),
        )
        observed_at = self.clock()
        lease_id = attempt.lease.lease_id
        observed_expiry = attempt.lease.expires_at
        observed_state = attempt.state
        observed_workspace = workspace
        if self.observation_mode == "stale_receipt":
            observed_at -= timedelta(minutes=5)
        elif self.observation_mode == "wrong_lease":
            lease_id = StableId("stale-observed-lease")
        elif self.observation_mode == "wrong_expiry":
            observed_expiry += timedelta(seconds=1)
        receipt = ProviderReceipt(
            StableId("inspection-" + hashlib.sha256(
                str(attempt.attempt_id).encode("utf-8")
            ).hexdigest()[:20]),
            PROVIDER,
            attempt.attempt_id,
            Sha256Digest("3" * 64),
            workspace.common_base.ref,
            observed_at,
        )
        return AttemptSafetyObservation(
            attempt.ref, observed_state, lease_id, observed_expiry, observed_workspace,
            source, process, children, receipt,
        )


def _claim_in_process(path: str, project: Project, plan, token: str, revision: int,
                      worker_id: int, gate, results) -> None:
    """Run one independent process against the shared authority file."""
    try:
        clock = MutableClock()
        dispatcher = CommandDispatcher([])
        auth = AuthorityAuthService(dispatcher, clock=clock)
        host = FakeAttemptHost(project, clock=clock)
        service = AttemptService(
            auth, eligibility=EligibilityAdapter(clock=clock), host=host,
            clock=clock, lease_duration=timedelta(minutes=2),
        )
        gate.wait(timeout=20)
        target = next(item.definition.ref for item in plan.work_items
                      if str(item.definition.work_item_id) == "work-a")
        with SQLiteAuthority.open_writer(path, project) as authority:
            result = service.claim(
                authority, token, target, plan,
                idempotency_key=StableId(f"process-race-{worker_id}"),
                expected_revision=revision,
                workspace_id=StableId("workspace-process-race"),
            )
        results.put(("ok", str(result.receipt.receipt_id)))
    except Exception as exc:  # The parent asserts exactly one typed policy refusal.
        results.put(("error", type(exc).__name__, str(exc)))


class IndependentAttemptAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        self.project = PROJECT
        self.plan = make_plan(self.project)
        SQLiteAuthority.initialize(self.path, self.project)
        self.clock = MutableClock()
        self.dispatcher = CommandDispatcher([])
        self.auth = AuthorityAuthService(self.dispatcher, clock=self.clock)
        self._seed_count = 0
        with self.open_writer() as authority:
            self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="fixture owner",
                idempotency_key=StableId("attempt-fixture-owner"), expected_revision=0,
            )
        self._seed_plan()

    def open_reader(self, path: Path | None = None, project: Project | None = None):
        return SQLiteAuthority.open_reader(path or self.path, project or self.project)

    def open_writer(self, path: Path | None = None, project: Project | None = None):
        return SQLiteAuthority.open_writer(path or self.path, project or self.project)

    def _seed_plan(self, plan=None, *, sequence: int = 1) -> None:
        proposal = self.plan if plan is None else plan
        with self.open_writer() as authority:
            self._seed_count += 1
            if not hasattr(self, "_fixture_owner"):
                self._fixture_owner = self.auth.login_local_owner(
                    authority, OWNER_PASSWORD,
                    actions=ATTEMPT_ACTIONS,
                    scope=self.project.ref,
                    expires_at=NOW + timedelta(days=1),
                    idempotency_key=StableId("attempt-plan-owner"),
                    expected_revision=self.revision(),
                )
            _, _, accepted = commit_plan(
                authority, self.auth, self._fixture_owner.bearer_token,
                proposal.canonical_json, key=f"attempt-plan-{self._seed_count}",
            )
            self.plan = accepted

    def revision(self) -> int:
        with self.open_reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def logical_dump(self) -> str:
        with self.open_reader() as authority:
            return "\n".join(authority.connection.iterdump())

    def issue_owner(self, *, expires_at: datetime | None = None, key: str = "attempt-owner"):
        with self.open_writer() as authority:
            return self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=ATTEMPT_ACTIONS,
                scope=self.project.ref, expires_at=expires_at or NOW + timedelta(hours=2),
                idempotency_key=StableId(key), expected_revision=self.revision(),
            )

    def service(self, host: FakeAttemptHost, *, lease_duration: timedelta = timedelta(minutes=2),
                max_observation_age: timedelta = timedelta(seconds=30)) -> AttemptService:
        return AttemptService(
            self.auth, eligibility=EligibilityAdapter(clock=self.clock), host=host,
            clock=self.clock, lease_duration=lease_duration,
            max_observation_age=max_observation_age,
        )

    def target(self, work_item_id: str, plan=None) -> EntityRef:
        plan = self.plan if plan is None else plan
        return next(item.definition.ref for item in plan.work_items
                    if str(item.definition.work_item_id) == work_item_id)

    def claim(self, service: AttemptService, token: str, work_item_id: str, workspace_id: str,
              key: str, *, run: EntityRef | None = None,
              assignment: EntityRef | None = None, plan=None):
        plan = self.plan if plan is None else plan
        with self.open_writer() as authority:
            return service.claim(
                authority, token, self.target(work_item_id, plan), plan,
                idempotency_key=StableId(key), expected_revision=self.revision(),
                workspace_id=StableId(workspace_id), run=run, assignment=assignment,
            )

    def stored_attempt(self, work_item_id: str):
        with self.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT attempt_id, lease_id, lease_expires_at, state FROM attempts "
                "WHERE work_item_id = ? AND definition_revision_id = ?",
                (work_item_id, str(self.target(work_item_id).definition_revision_id)),
            ).fetchone()
        if row is None:
            raise AssertionError(f"no stored attempt for {work_item_id}")
        return (EntityRef(self.project.project_id, EntityKind.ATTEMPT, StableId(row[0])),
                StableId(row[1]) if row[1] is not None else None,
                datetime.fromisoformat(row[2]) if row[2] is not None else None,
                AttemptState(row[3]))

    def test_two_process_claim_race_has_one_commit_and_no_loser_event_churn(self):
        first = self.issue_owner(key="process-claimant-one")
        second = self.issue_owner(key="process-claimant-two")
        baseline_revision = self.revision()
        with self.open_reader() as authority:
            baseline = tuple(authority.connection.execute(
                "SELECT (SELECT count(*) FROM attempts), (SELECT count(*) FROM authority_events), "
                "(SELECT count(*) FROM command_receipts), (SELECT count(*) FROM command_idempotency)"
            ).fetchone())

        context = multiprocessing.get_context("fork")
        gate = context.Barrier(2)
        results = context.Queue()
        processes = [
            context.Process(target=_claim_in_process,
                            args=(str(self.path), self.project, self.plan, token, baseline_revision,
                                  worker_id, gate, results))
            for worker_id, token in enumerate((first.bearer_token, second.bearer_token), start=1)
        ]
        try:
            for process in processes:
                process.start()
            outcomes = [results.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=30)
                self.assertFalse(process.is_alive(), "claim process did not terminate")
                self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            results.close()

        successes = [outcome for outcome in outcomes if outcome[0] == "ok"]
        refusals = [outcome for outcome in outcomes if outcome[0] == "error"]
        self.assertEqual(len(successes), 1, outcomes)
        self.assertEqual(len(refusals), 1, outcomes)
        self.assertIn(refusals[0][1], {
            AttemptAdmissionDeniedError.__name__, StaleAuthorityRevisionError.__name__,
        }, outcomes)
        with self.open_reader() as authority:
            after = tuple(authority.connection.execute(
                "SELECT (SELECT count(*) FROM attempts), (SELECT count(*) FROM authority_events), "
                "(SELECT count(*) FROM command_receipts), (SELECT count(*) FROM command_idempotency)"
            ).fetchone())
        self.assertEqual(after, tuple(value + 1 for value in baseline))
        self.assertEqual(self.revision(), baseline_revision + 1)
        committed_dump = self.logical_dump()
        with self.assertRaises(AttemptAdmissionDeniedError):
            self.claim(self.service(FakeAttemptHost(self.project, clock=self.clock)),
                       first.bearer_token, "work-a", "workspace-after-race", "race-policy-check")
        self.assertEqual(self.logical_dump(), committed_dump)

    def test_overlap_without_exact_workspace_isolation_is_denied_but_disjoint_work_claims(self):
        token = self.issue_owner(key="scope-claimant")
        host = FakeAttemptHost(
            self.project,
            clock=self.clock,
            base_by_workspace={
                "workspace-a": ("base-common", "1" * 64),
                "workspace-b": ("base-diverged", "4" * 64),
                "workspace-c": ("base-other", "5" * 64),
            },
        )
        service = self.service(host)
        self.claim(service, token.bearer_token, "work-a", "workspace-a", "attempt-scope-a")
        before = self.logical_dump()
        with self.assertRaises(AttemptAdmissionDeniedError) as caught:
            self.claim(service, token.bearer_token, "work-b", "workspace-b", "attempt-scope-overlap")
        self.assertIn("unsafe_source_overlap", {cause.code for cause in caught.exception.decision.causes})
        self.assertEqual(self.logical_dump(), before)

        result = self.claim(service, token.bearer_token, "work-c", "workspace-c", "attempt-scope-disjoint")
        self.assertTrue(result.receipt.changed)
        with self.open_reader() as authority:
            rows = tuple(authority.connection.execute(
                "SELECT work_item_id FROM attempts ORDER BY work_item_id"
            ).fetchall())
        self.assertEqual(tuple(row[0] for row in rows), ("work-a", "work-c"))

    def test_reopened_cross_plan_admission_uses_immutable_claimed_paths_and_locks(self):
        token = self.issue_owner(key="persisted-scope-owner")
        host = FakeAttemptHost(
            self.project,
            clock=self.clock,
            base_by_workspace={
                "workspace-original": ("base-original", "1" * 64),
                "workspace-overlap": ("base-candidate", "4" * 64),
                "workspace-lock": ("base-lock-candidate", "5" * 64),
                "workspace-disjoint": ("base-disjoint", "6" * 64),
            },
        )
        service = self.service(host)
        self.claim(service, token.bearer_token, "work-a", "workspace-original", "persisted-scope-original")
        original_work_ref = self.target("work-a")

        # Commit a partial plan that omits the active work item from its input.
        # The accepted snapshot retains that exact omitted definition, while
        # admission must still use the attempt's persisted scope snapshot.
        revised_proposal = make_plan(self.project, work_item_ids=("work-b", "work-c", "work-d"))
        self._seed_plan(revised_proposal, sequence=2)
        revised_plan = self.plan
        overlap_target = self.target("work-b", revised_plan)
        disjoint_context = next(
            item.context for item in revised_plan.work_items
            if item.definition.work_item_id == StableId("work-c")
        )
        candidate_workspace = _qualification(
            self.project, StableId("workspace-advisory-overlap"), StableId("advisory-overlap-correlation"),
            base_ref="base-candidate", base_digest="4" * 64, observed_at=self.clock(),
        )
        request = EligibilityRequest(
            overlap_target, token.capability.actor, CLAIM_ACTION, self.revision(),
        )
        with self.open_reader() as authority:
            decision = service.eligibility.evaluate_read(
                authority, request, revised_plan,
                scope_contexts={original_work_ref: disjoint_context},
                workspace_qualifications={overlap_target: candidate_workspace},
            )
        self.assertEqual(decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("unsafe_source_overlap", {cause.code for cause in decision.causes})
        self.assertNotIn("active_scope_unavailable", {cause.code for cause in decision.causes})

        before_overlap = self.logical_dump()
        with self.assertRaises(AttemptAdmissionDeniedError) as overlap:
            self.claim(
                service, token.bearer_token, "work-b", "workspace-overlap",
                "persisted-scope-overlap", plan=revised_plan,
            )
        self.assertIn("unsafe_source_overlap", {cause.code for cause in overlap.exception.decision.causes})
        self.assertEqual(self.logical_dump(), before_overlap)

        before_lock = self.logical_dump()
        with self.assertRaises(AttemptAdmissionDeniedError) as lock:
            self.claim(
                service, token.bearer_token, "work-d", "workspace-lock",
                "persisted-scope-lock", plan=revised_plan,
            )
        self.assertIn("named_lock_conflict", {cause.code for cause in lock.exception.decision.causes})
        self.assertEqual(self.logical_dump(), before_lock)

        disjoint = self.claim(
            service, token.bearer_token, "work-c", "workspace-disjoint",
            "persisted-scope-disjoint", plan=revised_plan,
        )
        self.assertTrue(disjoint.receipt.changed)
        with self.open_reader() as authority:
            rows = tuple(authority.connection.execute(
                "SELECT work_item_id FROM attempts ORDER BY work_item_id"
            ).fetchall())
        self.assertEqual(tuple(row[0] for row in rows), ("work-a", "work-c"))

    def test_expired_dirty_or_unknown_live_attempt_retains_lease_and_quarantines_conservatively(self):
        token = self.issue_owner(key="expiry-reconciler")
        host = FakeAttemptHost(self.project, clock=self.clock)
        service = self.service(host, lease_duration=timedelta(seconds=5))
        self.claim(service, token.bearer_token, "work-a", "workspace-dirty", "attempt-dirty")
        self.claim(service, token.bearer_token, "work-c", "workspace-unknown", "attempt-unknown")
        dirty_ref, dirty_lease, dirty_expiry, _ = self.stored_attempt("work-a")
        unknown_ref, unknown_lease, unknown_expiry, _ = self.stored_attempt("work-c")
        self.assertIsNotNone(dirty_lease)
        self.assertIsNotNone(unknown_lease)

        host.safety_by_work_item = {
            "work-a": (SourceSafety.DIRTY, ProcessLiveness.STOPPED, ChildActivity.NONE),
            "work-c": (SourceSafety.CLEAN, ProcessLiveness.UNKNOWN, ChildActivity.NONE),
        }
        self.clock.value = NOW + timedelta(seconds=6)
        with self.open_writer() as authority:
            dirty_result = service.reconcile_expired(
                authority, token.bearer_token, dirty_ref,
                idempotency_key=StableId("reconcile-dirty"), expected_revision=self.revision(),
            )
            unknown_result = service.reconcile_expired(
                authority, token.bearer_token, unknown_ref,
                idempotency_key=StableId("reconcile-unknown-live"), expected_revision=self.revision(),
            )
        self.assertEqual(dirty_result.receipt.result["state"], AttemptState.QUARANTINED.value)
        self.assertEqual(unknown_result.receipt.result["state"], AttemptState.UNCERTAIN.value)
        for work_item_id, lease_id, expiry in (
            ("work-a", dirty_lease, dirty_expiry), ("work-c", unknown_lease, unknown_expiry),
        ):
            _, current_lease, current_expiry, state = self.stored_attempt(work_item_id)
            self.assertEqual(current_lease, lease_id)
            self.assertEqual(current_expiry, expiry)
            self.assertIn(state, {AttemptState.QUARANTINED, AttemptState.UNCERTAIN})

    def test_wrong_lease_and_stale_observation_refuse_release_without_state_change(self):
        token = self.issue_owner(key="lease-checker")
        host = FakeAttemptHost(self.project, clock=self.clock)
        service = self.service(host, max_observation_age=timedelta(seconds=20))
        self.claim(service, token.bearer_token, "work-a", "workspace-lease", "attempt-lease")
        attempt_ref, lease_id, _, _ = self.stored_attempt("work-a")
        before_wrong_lease = self.logical_dump()
        with self.assertRaises(AttemptLeaseMismatchError):
            with self.open_writer() as authority:
                service.release(
                    authority, token.bearer_token, attempt_ref, StableId("not-current-lease"),
                    idempotency_key=StableId("release-wrong-lease"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.logical_dump(), before_wrong_lease)

        host.observation_mode = "stale_receipt"
        before_stale_observation = self.logical_dump()
        with self.assertRaises(AttemptObservationMismatchError):
            with self.open_writer() as authority:
                service.release(
                    authority, token.bearer_token, attempt_ref, lease_id,
                    idempotency_key=StableId("release-stale-observation"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.logical_dump(), before_stale_observation)

    def test_expired_or_revoked_attempt_capability_cannot_change_live_attempt(self):
        expires_soon = NOW + timedelta(seconds=5)
        expired_token = self.issue_owner(expires_at=expires_soon, key="expired-attempt-capability")
        revoked_token = self.issue_owner(key="revoked-attempt-capability")
        host = FakeAttemptHost(self.project, clock=self.clock)
        service = self.service(host)
        self.claim(service, expired_token.bearer_token, "work-a", "workspace-expired", "claim-expiring")
        self.claim(service, revoked_token.bearer_token, "work-c", "workspace-revoked", "claim-revoking")
        revoked_ref, _, _, _ = self.stored_attempt("work-c")
        with self.open_writer() as authority:
            self.auth.revoke_family(
                authority, revoked_token.bearer_token, revoked_token.capability.capability_id,
                idempotency_key=StableId("revoke-attempt-capability"), expected_revision=self.revision(),
            )

        for work_item_id, issued, key in (
            ("work-a", expired_token, "heartbeat-expired-capability"),
            ("work-c", revoked_token, "heartbeat-revoked-capability"),
        ):
            attempt_ref, lease_id, _, _ = self.stored_attempt(work_item_id)
            before = self.logical_dump()
            self.clock.value = expires_soon + timedelta(seconds=1)
            with self.assertRaises(AuthenticationFailedError):
                with self.open_writer() as authority:
                    service.heartbeat(
                        authority, issued.bearer_token, attempt_ref, lease_id, self.plan,
                        idempotency_key=StableId(key), expected_revision=self.revision(),
                    )
            self.assertEqual(self.logical_dump(), before)

        self.assertEqual(self.stored_attempt("work-c")[0], revoked_ref)

    def test_claim_rejects_workspace_qualification_with_wrong_identity_or_receipt_correlation(self):
        token = self.issue_owner(key="qualification-checker")
        host = FakeAttemptHost(self.project, clock=self.clock)
        service = self.service(host)
        for mode in ("wrong_workspace", "wrong_correlation", "wrong_project"):
            with self.subTest(mode=mode):
                host.qualification_mode = mode
                before = self.logical_dump()
                with self.assertRaises(AttemptObservationMismatchError):
                    self.claim(service, token.bearer_token, "work-a", "workspace-qualified",
                               f"bad-qualification-{mode}")
                self.assertEqual(self.logical_dump(), before)

    def test_run_bound_claim_heartbeat_and_release_keep_attempt_incarnation_ownership(self):
        run_ref = EntityRef(self.project.project_id, EntityKind.RUN, StableId("run-bound-attempt"))
        with self.open_writer() as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO runs(run_id, plan_revision_id, state) VALUES (?, ?, 'open')",
                    (str(run_ref.entity_id), str(self.plan.revision.plan_revision_id)),
                )
            owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=ATTEMPT_ACTIONS, scope=self.project.ref,
                run=run_ref, expires_at=NOW + timedelta(hours=2),
                idempotency_key=StableId("run-bound-owner"), expected_revision=self.revision(),
            )
            other_incarnation = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=ATTEMPT_ACTIONS, scope=self.project.ref,
                run=run_ref, expires_at=NOW + timedelta(hours=2),
                idempotency_key=StableId("run-bound-other-incarnation"),
                expected_revision=self.revision(),
            )

        host = FakeAttemptHost(self.project, clock=self.clock)
        service = self.service(host)
        self.claim(service, owner.bearer_token, "work-a", "workspace-run-bound",
                   "run-bound-claim", run=run_ref)
        attempt_ref, lease_id, _, _ = self.stored_attempt("work-a")
        with self.open_writer() as authority:
            heartbeat = service.heartbeat(
                authority, owner.bearer_token, attempt_ref, lease_id, self.plan,
                idempotency_key=StableId("run-bound-heartbeat"), expected_revision=self.revision(),
            )
        self.assertTrue(heartbeat.receipt.changed)
        current_lease = StableId(heartbeat.receipt.result["lease_id"])

        before_wrong_owner = self.logical_dump()
        with self.assertRaises(AttemptOwnershipError):
            with self.open_writer() as authority:
                service.release(
                    authority, other_incarnation.bearer_token, attempt_ref, current_lease,
                    idempotency_key=StableId("run-bound-wrong-owner-release"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.logical_dump(), before_wrong_owner)

        with self.open_writer() as authority:
            released = service.release(
                authority, owner.bearer_token, attempt_ref, current_lease,
                idempotency_key=StableId("run-bound-owner-release"),
                expected_revision=self.revision(),
            )
        self.assertEqual(released.receipt.result["state"], AttemptState.RELEASED.value)
        self.assertIsNone(self.stored_attempt("work-a")[1])


if __name__ == "__main__":
    unittest.main()
