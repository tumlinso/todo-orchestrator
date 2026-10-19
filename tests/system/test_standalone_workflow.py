"""Practical standalone workflow journey over temporary SQLite and real Git."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api import (
    DEFAULT_OWNER_ACTIONS,
    IsolationPolicy,
    LaneSpec,
    PlanPreviewMismatchError,
    ProviderComposition,
    QueuePolicy,
    RunCharter,
    RunSchedule,
    ScheduledWork,
    TodoApplication,
    authority_path,
)
from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AuthorityAuthService,
    CommandDispatcher,
    SQLiteAuthority,
)
from todo_orchestrator.authority.attempts import (
    ATTEMPT_SESSION_ACTIONS,
    CLAIM_ACTION,
    OUTCOME_REPORT_ACTION,
    VERIFICATION_ACTION,
)
from todo_orchestrator.authority.auth import AuthenticatedPrincipal
from todo_orchestrator.contracts import (
    ActorKind,
    EffectInspectionRequest,
    EntityRef,
    EntityKind,
    EvidenceResult,
    OutcomeDisposition,
    Project,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Sha256Digest,
    StableId,
    VerificationInspection,
    VerificationInspectionState,
    VerificationObservation,
    VerificationRequest,
    provider_request_digest,
)
from todo_orchestrator.coordination import RUN_DISPATCH_ACTION
from todo_orchestrator.providers.git import CREATE_WORKSPACE_ACTION, GitRepositoryConfig
from todo_orchestrator.verification.service import VERIFY_ACTION

from tests.verification.test_git_independent import TemporaryGitRepository


NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
OWNER_CREDENTIAL = "Q02 disposable workflow owner credential 784"
VERIFIER_IDENTITY = ProviderIdentity(StableId("q02-source-aware-verifier"), "1")
WORKER_ACTIONS = (
    *ATTEMPT_SESSION_ACTIONS,
    CLAIM_ACTION,
    RUN_DISPATCH_ACTION,
    CREATE_WORKSPACE_ACTION,
    VERIFY_ACTION,
    OUTCOME_REPORT_ACTION,
)


class FixedClock:
    def __call__(self) -> datetime:
        return NOW


class WorkerAuthenticator:
    """Test-only trusted identity source for two distinct temporary workers."""

    provider_id = "q02-temporary-worker-authenticator"

    def authenticate(self, credential: object) -> AuthenticatedPrincipal | None:
        if credential == "worker-alpha-credential":
            return AuthenticatedPrincipal("q02-worker-alpha", ActorKind.AUTOMATION, "worker alpha")
        if credential == "worker-beta-credential":
            return AuthenticatedPrincipal("q02-worker-beta", ActorKind.AUTOMATION, "worker beta")
        return None


class StoppedProcessObserver:
    """Explicit disposable host fixture; Git itself supplies workspace facts."""

    def inspect(self, attempt):
        from todo_orchestrator.model import ProcessLiveness

        return ProcessLiveness.STOPPED


class EmptyChildObserver:
    def inspect(self, attempt):
        from todo_orchestrator.model import ChildActivity

        return ChildActivity.NONE


class ContentVerifier:
    """Injected domain verifier that inspects bytes in actual Git worktrees."""

    def __init__(self, identity: ProviderIdentity, clock: FixedClock):
        self.identity = identity
        self.clock = clock
        self.workspaces: dict[StableId, tuple[Path, str]] = {}
        self.calls: list[tuple[StableId, Sha256Digest, str, EvidenceResult]] = []

    def register_workspace(self, workspace_id: StableId, root: Path, relative_path: str) -> None:
        self.workspaces[workspace_id] = (root, relative_path)

    def verify(self, request: VerificationRequest):
        if request.verifier_id != self.identity.provider_id or request.workspace_id is None:
            raise AssertionError("verification request lost its authored provider/workspace binding")
        root, relative_path = self.workspaces[request.workspace_id]
        content = (root / relative_path).read_text(encoding="utf-8")
        verdict = EvidenceResult.FAIL if content.startswith("fail:") else EvidenceResult.PASS
        self.calls.append((request.attempt.entity_id, request.expected_source, content, verdict))
        observation = VerificationObservation(
            request.operation_id,
            verdict,
            self.identity.provider_id,
            self.identity.version,
            request.expected_source,
            request.contract_digest,
            request.inputs,
            (),
        )
        receipt = ProviderReceipt(
            StableId("q02-verifier-receipt-" + hashlib.sha256(
                str(request.operation_id).encode("utf-8")
            ).hexdigest()[:20]),
            self.identity,
            request.operation_id,
            provider_request_digest(request),
            request.operation_id,
            self.clock(),
        )
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS,
            request.operation_id,
            self.identity,
            observation,
            receipt,
        )

    def inspect(self, request: EffectInspectionRequest):
        inspection = VerificationInspection(
            request.operation_id,
            VerificationInspectionState.NOT_STARTED,
        )
        receipt = ProviderReceipt(
            StableId("q02-verifier-inspection-" + hashlib.sha256(
                str(request.correlation_id).encode("utf-8")
            ).hexdigest()[:20]),
            self.identity,
            request.correlation_id,
            provider_request_digest(request),
            request.operation_id,
            self.clock(),
        )
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS,
            request.correlation_id,
            self.identity,
            inspection,
            receipt,
        )


def _plan(project: Project) -> str:
    def work_item(item_id: str, path: str, *, dispositions: tuple[str, ...] = ("completed",)):
        return {
            "id": item_id,
            "title": f"Q02 {item_id}",
            "objective": f"Exercise integrated workflow for {item_id}",
            "outcome": "A source-bound verified result is accepted",
            "scope": {"paths": [{"path": path, "access": "write"}], "concepts": [], "locks": []},
            "ownership": {"mode": "any", "actors": []},
            "acceptance": {
                "assertions": ["verification binds the current source"],
                "required_evidence": [],
                "allowed_dispositions": list(dispositions),
            },
            "requirement_groups": [{"kind": "check", "mode": "all", "members": [f"check-{item_id}"]}],
        }

    def check(item_id: str):
        return {
            "id": f"check-{item_id}",
            "work_item_id": item_id,
            "kind": "check",
            "description": f"Verify current source for {item_id}",
            "check_key": f"q02-{item_id}",
            "verification": {
                "kind": "domain_provider",
                "version": 1,
                "config": {
                    "provider_id": str(VERIFIER_IDENTITY.provider_id),
                    "provider_version": VERIFIER_IDENTITY.version,
                    "contract_id": "q02-content-check",
                    "contract_version": 1,
                    "parameters": {"work_item": item_id},
                },
            },
            "required_evidence": [],
        }

    return json.dumps({
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "q02-integrated-workflow",
        "project": {"project_id": str(project.project_id), "authority_id": str(project.authority_id)},
        "work_items": [
            work_item("alpha", "module.txt", dispositions=("completed", "failed")),
            work_item("beta", "README.md"),
            work_item("conflict", "module.txt"),
        ],
        "requirements": [check("alpha"), check("beta"), check("conflict")],
    }, sort_keys=True, separators=(",", ":"))


class StandaloneWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-q02-workflow-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git_fixture = TemporaryGitRepository(self.root)
        self.project = Project(StableId("q02-workflow-project"), StableId("q02-workflow-authority"))
        self.repository_id = StableId("q02-workflow-repository")
        self.clock = FixedClock()
        self.verifier = ContentVerifier(VERIFIER_IDENTITY, self.clock)
        config = GitRepositoryConfig(
            self.project.project_id,
            self.repository_id,
            self.git_fixture.repository,
            self.root / "managed-workspaces",
            self.root / "provider-journal",
            StableId("refs/heads/main"),
            StableId("refs/heads/todo-integration"),
        )
        self.providers = ProviderComposition.local_git(
            config,
            process_observer=StoppedProcessObserver(),
            child_observer=EmptyChildObserver(),
            verification_provider=self.verifier,
            verification_identity=VERIFIER_IDENTITY,
            clock=self.clock,
        )
        self.project_root = self.root / "standalone-project"

    def _delegate_workers(self, owner):
        auth = AuthorityAuthService(
            CommandDispatcher(), clock=self.clock, authenticator=WorkerAuthenticator(),
        )
        path = authority_path(owner.root, owner.metadata)
        results = {}
        for suffix, credential in (
            ("alpha", "worker-alpha-credential"),
            ("beta", "worker-beta-credential"),
        ):
            with SQLiteAuthority.open_writer(path, self.project) as authority:
                results[suffix] = auth.delegate(
                    authority,
                    owner.bearer_token,
                    credential,
                    actions=WORKER_ACTIONS,
                    scope=self.project.ref,
                    expires_at=NOW + timedelta(hours=2),
                    idempotency_key=StableId(f"q02-delegate-{suffix}"),
                    expected_revision=owner.read_model().semantic_revision,
                )
        return results

    def _workspace(self, owner, verifier, *, target: StableId | EntityRef, workspace_id: str,
                   assignment=None, run_id=None, path: str):
        created = owner.create_workspace(
            target,
            idempotency_key=StableId(f"q02-create-{workspace_id}"),
            workspace_id=StableId(workspace_id),
            run_id=run_id,
            assignment=assignment,
        )
        root = self.providers.git_provider.workspace_path_for(StableId(workspace_id))
        verifier.register_workspace(StableId(workspace_id), root, path)
        self.assertTrue(root.is_dir())
        self.assertTrue(created.operation_id.value)
        return root

    def _write_and_commit(self, root: Path, path: str, content: str, label: str) -> None:
        (root / path).write_text(content, encoding="utf-8")
        self.git_fixture.git(root, "add", path)
        self.git_fixture.git(root, "commit", "--quiet", "-m", f"fixture {label}")

    def test_two_workers_conflicts_rejection_retry_current_verification_close_and_export(self):
        owner_actions = tuple(sorted({*DEFAULT_OWNER_ACTIONS, StableId("todo.capability.delegate")}))
        with TodoApplication.initialize(
            self.project_root,
            project_id=self.project.project_id,
            repository_id=self.repository_id,
            authority_id=self.project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            owner_actions=owner_actions,
            providers=self.providers,
        ) as owner:
            package = _plan(self.project)
            stale_preview = owner.preview_plan(package)
            workers = self._delegate_workers(owner)
            self.assertNotEqual(workers["alpha"].capability.actor, workers["beta"].capability.actor)
            before_stale_commit = owner.read_model().semantic_revision
            with self.assertRaises(PlanPreviewMismatchError):
                owner.commit_plan(package, stale_preview, idempotency_key=StableId("q02-stale-plan"))
            self.assertEqual(owner.read_model().semantic_revision, before_stale_commit)

            fresh_preview = owner.preview_plan(package)
            committed = owner.commit_plan(
                package, fresh_preview, idempotency_key=StableId("q02-commit-plan"),
            )
            revision = StableId(str(committed.result["plan_revision_id"]))
            # Reopening and replaying a schedule command with the original key
            # proves an exact idempotent retry without semantic churn.
            alpha = owner.work_item_ref("alpha", revision)
            beta = owner.work_item_ref("beta", revision)
            conflict = owner.work_item_ref("conflict", revision)
            run_id = StableId("q02-parallel-run")
            lane = StableId("parallel-shared-scopes")
            schedule = RunSchedule(
                run_id,
                owner.ref(EntityKind.PLAN_REVISION, revision),
                (LaneSpec(lane, QueuePolicy.PARALLEL, isolation_policy=IsolationPolicy.SHARED_SCOPES),),
                (
                    ScheduledWork(alpha, lane, workers["alpha"].capability.actor),
                    ScheduledWork(beta, lane, workers["beta"].capability.actor),
                ),
                RunCharter(
                    "Complete independent work without overlapping claims",
                    ("Respect exact accepted task scopes", "Keep verification bound to current source"),
                    ("Accept verified work and close the run after all attempts settle",),
                ),
            )
            before_open = owner.read_model().semantic_revision
            opened = owner.open_run(
                revision, schedule,
                idempotency_key=StableId("q02-open-run"),
                expected_revision=before_open,
            )
            after_open = owner.read_model().semantic_revision
            replayed_open = owner.open_run(
                revision, schedule,
                idempotency_key=StableId("q02-open-run"),
                expected_revision=before_open,
            )
            self.assertEqual(replayed_open.receipt_id, opened.receipt_id)
            self.assertEqual(owner.read_model().semantic_revision, after_open)

            run_view = owner.read_run(run_id)
            entries = {entry.assignment.work_item.entity_id: entry for entry in run_view.entries}
            alpha_assignment = entries[alpha.entity_id].assignment.ref
            beta_assignment = entries[beta.entity_id].assignment.ref
            self.assertEqual(entries[alpha.entity_id].assignment.assignee, workers["alpha"].capability.actor)
            self.assertEqual(entries[beta.entity_id].assignment.assignee, workers["beta"].capability.actor)
            self.assertNotEqual(alpha_assignment, beta_assignment)

            alpha_root = self._workspace(
                owner, self.verifier, target=alpha, workspace_id="q02-alpha-first",
                assignment=alpha_assignment, run_id=run_id, path="module.txt",
            )
            beta_root = self._workspace(
                owner, self.verifier, target=beta, workspace_id="q02-beta",
                assignment=beta_assignment, run_id=run_id, path="README.md",
            )
            alpha_worktree = self.git_fixture.identities(alpha_root)
            beta_worktree = self.git_fixture.identities(beta_root)
            self.assertNotEqual(alpha_worktree["root"], beta_worktree["root"])
            self.assertNotEqual(alpha_worktree["git_dir"], beta_worktree["git_dir"])
            self.assertNotEqual(alpha_worktree["index"], beta_worktree["index"])
            self.assertEqual(alpha_worktree["common_dir"], beta_worktree["common_dir"])

            worker_alpha = TodoApplication.open(
                self.project_root, bearer_token=workers["alpha"].bearer_token, providers=self.providers,
            )
            worker_beta = TodoApplication.open(
                self.project_root, bearer_token=workers["beta"].bearer_token, providers=self.providers,
            )
            with worker_alpha, worker_beta:
                alpha_first = worker_alpha.dispatch(
                    "q02-alpha-first",
                    idempotency_key=StableId("q02-dispatch-alpha-first"),
                    work_item=alpha,
                    run_id=run_id,
                    assignment=alpha_assignment,
                    plan_revision_id=revision,
                )
                beta_attempt = worker_beta.dispatch(
                    "q02-beta",
                    idempotency_key=StableId("q02-dispatch-beta"),
                    work_item=beta,
                    run_id=run_id,
                    assignment=beta_assignment,
                    plan_revision_id=revision,
                )
                self.assertNotEqual(alpha_first.attempt_ref, beta_attempt.attempt_ref)
                live_claims = [row for row in owner.read_model().sections["attempts"]
                               if row["state"] in {"admitted", "active"}]
                self.assertEqual(len(live_claims), 2)

                # The conflict target gets its own real worktree, created by
                # a separately identified Git provider over the same repo.
                # Its target binding is valid, but the provider identity does
                # not match alpha's qualification, so overlapping source scope
                # remains unsafe to admit.
                conflict_config = replace(
                    self.providers.git_provider.config,
                    provider_id=StableId("q02-conflict-git-provider"),
                    workspace_root=self.root / "conflict-workspaces",
                    journal_root=self.root / "conflict-provider-journal",
                )
                conflict_providers = ProviderComposition.local_git(
                    conflict_config,
                    process_observer=StoppedProcessObserver(),
                    child_observer=EmptyChildObserver(),
                    verification_provider=self.verifier,
                    verification_identity=VERIFIER_IDENTITY,
                    clock=self.clock,
                )
                conflict_owner = TodoApplication.open(
                    self.project_root,
                    bearer_token=owner.bearer_token,
                    providers=conflict_providers,
                )
                with conflict_owner:
                    conflict_owner.create_workspace(
                        conflict,
                        idempotency_key=StableId("q02-create-conflict-workspace"),
                        workspace_id=StableId("q02-conflict-workspace"),
                    )
                conflict_root = conflict_providers.git_provider.workspace_path_for(
                    StableId("q02-conflict-workspace"),
                )
                conflict_worktree = self.git_fixture.identities(conflict_root)
                self.assertNotEqual(conflict_worktree["root"], alpha_worktree["root"])
                self.assertNotEqual(conflict_worktree["git_dir"], alpha_worktree["git_dir"])
                self.assertNotEqual(conflict_worktree["index"], alpha_worktree["index"])
                self.assertEqual(conflict_worktree["common_dir"], alpha_worktree["common_dir"])

                conflict_worker = TodoApplication.open(
                    self.project_root,
                    bearer_token=workers["beta"].bearer_token,
                    providers=conflict_providers,
                )
                before_denial = owner.read_model().semantic_revision
                with conflict_worker:
                    with self.assertRaises(AttemptAdmissionDeniedError) as denied:
                        conflict_worker.dispatch(
                            "q02-conflict-workspace",
                            idempotency_key=StableId("q02-dispatch-conflict"),
                            work_item=conflict,
                            plan_revision_id=revision,
                            expected_revision=before_denial,
                        )
                self.assertIn(
                    "unsafe_source_overlap",
                    {cause.code for cause in denied.exception.decision.causes},
                )
                self.assertEqual(owner.read_model().semantic_revision, before_denial)

                self._write_and_commit(
                    alpha_root, "module.txt", "fail: first source must be rejected\n", "alpha-failed",
                )
                self._write_and_commit(beta_root, "README.md", "pass: independent source\n", "beta-passed")

                alpha_first_attempt = TodoApplication.open(
                    self.project_root, bearer_token=alpha_first.bearer_token, providers=self.providers,
                )
                beta_attempt_session = TodoApplication.open(
                    self.project_root, bearer_token=beta_attempt.bearer_token, providers=self.providers,
                )
                with alpha_first_attempt, beta_attempt_session:
                    failed_verification = alpha_first_attempt.verify(
                        alpha_first.attempt_ref, "check-alpha",
                        idempotency_key=StableId("q02-verify-alpha-failed"),
                    )
                    self.assertEqual(failed_verification.state, "rejected")
                    self.assertEqual(failed_verification.observation["verdict"], "fail")
                    beta_verification = beta_attempt_session.verify(
                        beta_attempt.attempt_ref, "check-beta",
                        idempotency_key=StableId("q02-verify-beta"),
                    )
                    self.assertEqual(beta_verification.state, "finalized")
                    self.assertEqual(beta_verification.observation["verdict"], "pass")
                    concurrent_attempts = {
                        row["attempt_id"]: row
                        for row in owner.read_model().sections["attempts"]
                    }
                    for attempt in (alpha_first.attempt_ref, beta_attempt.attempt_ref):
                        row = concurrent_attempts[str(attempt.entity_id)]
                        self.assertEqual(row["state"], "admitted")
                        self.assertIsNotNone(row["lease_id"])
                        self.assertGreater(
                            datetime.fromisoformat(row["lease_expires_at"]), NOW,
                        )

                    failed_candidate = alpha_first_attempt.report(
                        alpha_first.attempt_ref,
                        OutcomeDisposition.FAILED,
                        idempotency_key=StableId("q02-report-alpha-failed"),
                        note="Initial verification failed; reject and retry.",
                    )
                    failed_report = owner.read_candidate(failed_candidate.candidate_ref)
                    self.assertEqual(failed_verification.source_digest, failed_report.source_digest)
                    rejected = owner.reject(
                        alpha_first.attempt_ref,
                        failed_candidate.candidate_ref,
                        idempotency_key=StableId("q02-reject-alpha-failed"),
                    )
                    self.assertEqual(rejected.result["state"], "rejected")

                    beta_candidate = beta_attempt_session.report(
                        beta_attempt.attempt_ref,
                        OutcomeDisposition.COMPLETED,
                        idempotency_key=StableId("q02-report-beta"),
                    )
                    beta_accepted = owner.accept(
                        beta_attempt.attempt_ref,
                        beta_candidate.candidate_ref,
                        idempotency_key=StableId("q02-accept-beta"),
                    )
                    self.assertEqual(beta_accepted.result["state"], "accepted")

                # A rejected candidate closes its attempt but leaves the same
                # scheduled assignment available for a fresh attempt.
                alpha_retry_root = self._workspace(
                    owner, self.verifier, target=alpha, workspace_id="q02-alpha-retry",
                    assignment=alpha_assignment, run_id=run_id, path="module.txt",
                )
                self.assertNotEqual(
                    self.git_fixture.identities(alpha_retry_root)["index"], alpha_worktree["index"],
                )
                alpha_retry = worker_alpha.dispatch(
                    "q02-alpha-retry",
                    idempotency_key=StableId("q02-dispatch-alpha-retry"),
                    work_item=alpha,
                    run_id=run_id,
                    assignment=alpha_assignment,
                    plan_revision_id=revision,
                )
                self.assertNotEqual(alpha_first.attempt_ref, alpha_retry.attempt_ref)
                self._write_and_commit(
                    alpha_retry_root, "module.txt", "pass: corrected source after rejection\n",
                    "alpha-retried",
                )
                alpha_retry_session = TodoApplication.open(
                    self.project_root, bearer_token=alpha_retry.bearer_token, providers=self.providers,
                )
                with alpha_retry_session:
                    passed_verification = alpha_retry_session.verify(
                        alpha_retry.attempt_ref, "check-alpha",
                        idempotency_key=StableId("q02-verify-alpha-retry"),
                    )
                    self.assertEqual(passed_verification.state, "finalized")
                    self.assertEqual(passed_verification.observation["verdict"], "pass")
                    retry_candidate = alpha_retry_session.report(
                        alpha_retry.attempt_ref,
                        OutcomeDisposition.COMPLETED,
                        idempotency_key=StableId("q02-report-alpha-retry"),
                    )
                    retry_report = owner.read_candidate(retry_candidate.candidate_ref)
                    self.assertEqual(passed_verification.source_digest, retry_report.source_digest)
                    self.assertNotEqual(failed_verification.source_digest, passed_verification.source_digest)
                    alpha_accepted = owner.accept(
                        alpha_retry.attempt_ref,
                        retry_candidate.candidate_ref,
                        idempotency_key=StableId("q02-accept-alpha-retry"),
                    )
                    self.assertEqual(alpha_accepted.result["state"], "accepted")

            self.assertEqual(len(self.verifier.calls), 3)
            self.assertEqual(
                [call[3] for call in self.verifier.calls],
                [EvidenceResult.FAIL, EvidenceResult.PASS, EvidenceResult.PASS],
            )
            self.assertEqual(
                [call[2] for call in self.verifier.calls],
                [
                    "fail: first source must be rejected\n",
                    "pass: independent source\n",
                    "pass: corrected source after rejection\n",
                ],
            )
            self.assertEqual(self.verifier.calls[0][1], failed_verification.source_digest)
            self.assertEqual(self.verifier.calls[1][1], beta_verification.source_digest)
            self.assertEqual(self.verifier.calls[2][1], passed_verification.source_digest)
            self.assertNotEqual(self.verifier.calls[0][1], self.verifier.calls[2][1])

            schedule_digest = owner.run_schedule_digest(run_id)
            closed = owner.close_run(
                run_id,
                schedule_digest,
                idempotency_key=StableId("q02-close-run"),
                expected_revision=owner.read_model().semantic_revision,
            )
            self.assertEqual(closed.result["state"], "closed")
            self.assertEqual(owner.read_model().sections["runs"][0]["state"], "closed")

            read_model = owner.read_model()
            outcomes = read_model.sections["outcomes"]
            self.assertEqual(len(outcomes), 2)
            self.assertEqual(
                {row["work_item_id"] for row in outcomes},
                {str(alpha.entity_id), str(beta.entity_id)},
            )
            self.assertEqual({row["disposition"] for row in outcomes}, {"completed"})
            serialized = read_model.to_json()
            sensitive_values = (
                OWNER_CREDENTIAL,
                owner.bearer_token,
                workers["alpha"].bearer_token,
                workers["beta"].bearer_token,
                alpha_first.bearer_token,
                beta_attempt.bearer_token,
                alpha_retry.bearer_token,
                "fail: first source must be rejected",
                "pass: independent source",
                "pass: corrected source after rejection",
            )
            for value in sensitive_values:
                self.assertNotIn(value, serialized)


if __name__ == "__main__":
    unittest.main()
