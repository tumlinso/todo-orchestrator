"""Independent V04 tests using only disposable, real Git repositories."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from todo_orchestrator.contracts import (
    EffectInspectionRequest,
    EntityKind,
    EntityRef,
    GitEffectDisposition,
    GitEffectRequest,
    GitOperationKind,
    Project,
    ProviderCallContext,
    ProviderStatus,
    Sha256Digest,
    SourceObservationRequest,
    StableId,
    WorkingTreeState,
)
from todo_orchestrator.contracts.providers import provider_request_digest
from todo_orchestrator.authority import (
    AttemptAdmissionDeniedError,
    AttemptHostUnavailableError,
    AttemptService,
    AuthorityAuthService,
    CLAIM_ACTION,
    CommandDispatcher,
    SQLiteAuthority,
)
from todo_orchestrator.planning import PlanService
from todo_orchestrator.providers.git import (
    GitProviderError,
    GitRepositoryConfig,
    GitRepositoryProvider,
)


class TemporaryGitRepository:
    """Small real-Git fixture with linked worktrees and byte-level snapshots."""

    def __init__(self, root: Path):
        self.root = root
        self.executable = shutil.which("git")
        if self.executable is None:
            raise unittest.SkipTest("Git is required for V04 provider qualification")
        self.repository = root / "repository"
        self.repository.mkdir()
        self.worktree_root = root / "worktrees"
        self.worktree_root.mkdir()
        self.git(self.repository, "init", "--quiet", "--initial-branch=main")
        self.git(self.repository, "config", "user.name", "Todo Orchestrator Fixture")
        self.git(self.repository, "config", "user.email", "todo-fixture@example.invalid")
        (self.repository / "README.md").write_bytes(b"fixture repository\n")
        (self.repository / "module.txt").write_bytes(b"base value\nsecond line\n")
        self.git(self.repository, "add", "README.md", "module.txt")
        self.git(self.repository, "commit", "--quiet", "-m", "disposable base")
        self.base = self.git(self.repository, "rev-parse", "HEAD").stdout.strip()
        self.git(self.repository, "branch", "todo-integration", self.base)

    def git(self, cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["GIT_OPTIONAL_LOCKS"] = "0"
        result = subprocess.run(
            [self.executable, *args],
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if check and result.returncode:
            raise AssertionError(
                f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
            )
        return result

    def add_worktree(
        self,
        name: str,
        *,
        branch: str | None = None,
        start: str | None = None,
    ) -> Path:
        path = self.worktree_root / name
        args = ["worktree", "add", "--quiet"]
        if branch is None:
            args.extend(["--detach", str(path), start or self.base])
        else:
            args.extend(["-b", branch, str(path), start or self.base])
        self.git(self.repository, *args)
        self.git(path, "config", "user.name", "Todo Orchestrator Fixture")
        self.git(path, "config", "user.email", "todo-fixture@example.invalid")
        return path

    def identities(self, worktree: Path) -> dict[str, str]:
        top = self.git(worktree, "rev-parse", "--show-toplevel").stdout.strip()
        git_dir = self.git(worktree, "rev-parse", "--absolute-git-dir").stdout.strip()
        common_dir = self.git(worktree, "rev-parse", "--git-common-dir").stdout.strip()
        index = self.git(worktree, "rev-parse", "--git-path", "index").stdout.strip()
        if not os.path.isabs(common_dir):
            common_dir = str((worktree / common_dir).resolve())
        if not os.path.isabs(index):
            index = str((worktree / index).resolve())
        return {
            "root": str(Path(top).resolve()),
            "git_dir": str(Path(git_dir).resolve()),
            "common_dir": str(Path(common_dir).resolve()),
            "index": str(Path(index).resolve()),
            "head": self.git(worktree, "rev-parse", "HEAD").stdout.strip(),
        }

    def snapshot(self, worktree: Path) -> tuple[str, bytes, str, tuple[tuple[str, bytes | str], ...]]:
        identities = self.identities(worktree)
        index = Path(identities["index"])
        status = self.git(
            worktree, "status", "--porcelain=v2", "--untracked-files=all"
        ).stdout
        contents: list[tuple[str, bytes | str]] = []
        for path in sorted(worktree.rglob("*")):
            relative = path.relative_to(worktree)
            if relative.parts[0] == ".git" or path.is_dir():
                continue
            value: bytes | str = os.readlink(path) if path.is_symlink() else path.read_bytes()
            contents.append((relative.as_posix(), value))
        return identities["head"], index.read_bytes(), status, tuple(contents)


class RecordingGitProvider(GitRepositoryProvider):
    """Record the actual host qualifications made during admission."""

    def __init__(self, *args, **kwargs):
        self.qualified_workspaces: list[StableId] = []
        self.after_qualification = None
        super().__init__(*args, **kwargs)

    def qualify_workspace(self, workspace_id, target, correlation_id):
        self.qualified_workspaces.append(workspace_id)
        result = super().qualify_workspace(workspace_id, target, correlation_id)
        callback = self.after_qualification
        if callback is not None and callback(workspace_id):
            self.after_qualification = None
        return result

class GitProviderIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-v04-git-")
        self.addCleanup(self.temporary.cleanup)
        self.git = TemporaryGitRepository(Path(self.temporary.name))
        self.project_id = StableId("v04-independent-project")
        self.repository_id = StableId("v04-independent-repository")
        self.base_ref = StableId("refs/heads/main")
        self.integration_ref = StableId("refs/heads/todo-integration")
        self.config = GitRepositoryConfig(
            self.project_id,
            self.repository_id,
            self.git.repository,
            Path(self.temporary.name) / "managed-workspaces",
            Path(self.temporary.name) / "provider-journal",
            self.base_ref,
            self.integration_ref,
        )
        self.provider = GitRepositoryProvider(self.config)
        self.context = ProviderCallContext(
            self.project_id,
            EntityRef(self.project_id, EntityKind.ACTOR, StableId("fixture-owner"),
                     incarnation_id=StableId("fixture-owner-incarnation")),
            EntityRef(self.project_id, EntityKind.CAPABILITY, StableId("fixture-capability")),
            StableId("fixture-trusted-context"), StableId("fixture-scope"),
        )
        self.target = EntityRef(
            self.project_id, EntityKind.WORK_ITEM, StableId("git-work-item"),
            definition_revision_id=StableId("git-work-item-v1"),
        )

    def create_request(self, workspace: str, operation: str | None = None) -> GitEffectRequest:
        revision = self.provider.qualified_revision()
        return GitEffectRequest(
            self.context,
            StableId(operation or f"create-{workspace}"),
            StableId(f"idem-create-{workspace}"),
            GitOperationKind.CREATE_WORKSPACE,
            Sha256Digest(revision.digest),
            1,
            StableId(workspace),
            self.base_ref,
        )

    def create_workspace(self, workspace: str) -> Path:
        request = self.create_request(workspace)
        result = self.provider.perform(request)
        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.APPLIED)
        path = self.provider.workspace_path_for(StableId(workspace))
        self.assertTrue(path.is_dir())
        return path

    def source_request(self, workspace: str, suffix: str = "source") -> SourceObservationRequest:
        return SourceObservationRequest(
            self.context,
            StableId(f"observe-{workspace}-{suffix}"),
            attempt=EntityRef(self.project_id, EntityKind.ATTEMPT, StableId(f"attempt-{workspace}")),
            workspace_id=StableId(workspace),
            target=self.target,
        )

    def integrate_request(
        self,
        workspace: str,
        source_commit: str,
        *,
        expected_destination: str | None = None,
        operation: str = "integrate-independent",
    ) -> GitEffectRequest:
        source = self.provider.qualified_revision(StableId(source_commit))
        expected = expected_destination or str(self.provider.integration_head())
        return GitEffectRequest(
            self.context,
            StableId(operation),
            StableId(f"idem-{operation}"),
            GitOperationKind.INTEGRATE,
            Sha256Digest(source.digest),
            1,
            StableId(workspace),
            source_commit=StableId(source_commit),
            destination_ref=self.config.integration_ref,
            expected_destination=StableId(expected),
        )

    def _admission_fixture(self, count: int = 3):
        project = Project(self.project_id, StableId("v04-independent-authority"))
        authority_path = Path(self.temporary.name) / "admission-authority.sqlite3"
        SQLiteAuthority.initialize(authority_path, project)
        now = datetime(2034, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
        clock = lambda: now
        dispatcher = CommandDispatcher()
        auth = AuthorityAuthService(dispatcher, clock=clock)
        actions = (StableId("todo.plan.commit"), CLAIM_ACTION)
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            enrollment = auth.enroll_local_owner(
                authority, "temporary fixture owner credential 937", label="fixture owner",
                idempotency_key=StableId("admission-owner-enrollment"), expected_revision=0,
            )
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            issued = auth.login_local_owner(
                authority, "temporary fixture owner credential 937", actions=actions,
                scope=project.ref, expires_at=now + timedelta(days=1),
                idempotency_key=StableId("admission-owner-capability"),
                expected_revision=enrollment.receipt.semantic_revision,
            )

        document = {
            "format": "todo-orchestrator.plan",
            "schema_version": 1,
            "package_id": "v04-real-git-admission",
            "project": {
                "project_id": str(project.project_id),
                "authority_id": str(project.authority_id),
            },
            "work_items": [
                {
                    "id": f"overlap-{index}",
                    "title": f"Overlapping work {index}",
                    "objective": "Make a scoped change",
                    "outcome": "The scoped change is present",
                    "scope": {
                        "paths": [{"path": "shared/target.txt", "access": "write"}],
                        "concepts": [],
                        "locks": [],
                    },
                    "acceptance": {
                        "assertions": ["target exists"],
                        "required_evidence": [],
                        "allowed_dispositions": ["completed"],
                    },
                    "ownership": {"mode": "any", "actors": []},
                }
                for index in range(count)
            ],
        }
        package_json = json.dumps(document, sort_keys=True, separators=(",", ":"))
        plan_service = PlanService(auth)
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            preview = plan_service.preview(authority, package_json)
            plan_service.commit(
                authority, issued.bearer_token, package_json,
                reviewed_digest=preview.digest,
                idempotency_key=StableId("admission-plan-commit"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            plan = plan_service.load_accepted_plan(authority)

        integration_ref = StableId("refs/heads/todo-admission-integration")
        self.git.git(self.git.repository, "branch", "todo-admission-integration", self.git.base)
        config = GitRepositoryConfig(
            self.project_id, self.repository_id, self.git.repository,
            Path(self.temporary.name) / "admission-workspaces",
            Path(self.temporary.name) / "admission-provider-journal",
            self.base_ref, integration_ref,
        )
        provider = RecordingGitProvider(config, clock=clock)
        attempts = AttemptService(auth, host=provider, clock=clock)
        return authority_path, project, auth, issued, plan, provider, attempts

    def _create_workspace_with(self, provider: GitRepositoryProvider, workspace_id: StableId) -> Path:
        revision = provider.qualified_revision()
        request = GitEffectRequest(
            self.context,
            StableId(f"independent-create-{workspace_id}"),
            StableId(f"independent-create-key-{workspace_id}"),
            GitOperationKind.CREATE_WORKSPACE,
            Sha256Digest(revision.digest),
            1,
            workspace_id,
            provider.config.base_ref,
        )
        created = provider.perform(request)
        self.assertEqual(created.status, ProviderStatus.OBSERVED_SUCCESS, created)
        self.assertEqual(created.value.disposition, GitEffectDisposition.APPLIED)
        path = provider.workspace_path_for(workspace_id)
        self.assertTrue(path.is_dir())
        return path

    @staticmethod
    def _authority_counts(authority: SQLiteAuthority) -> tuple[int, ...]:
        connection = authority.connection
        return (
            connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton=1").fetchone()[0],
            connection.execute("SELECT count(*) FROM attempts").fetchone()[0],
            connection.execute("SELECT count(*) FROM attempt_workspace_qualifications").fetchone()[0],
            connection.execute("SELECT count(*) FROM attempt_scope_snapshots").fetchone()[0],
            connection.execute("SELECT count(*) FROM authority_events").fetchone()[0],
            connection.execute("SELECT count(*) FROM command_receipts").fetchone()[0],
            connection.execute("SELECT count(*) FROM command_idempotency").fetchone()[0],
        )

    def test_authenticated_overlapping_claims_require_live_distinct_git_workspaces(self):
        authority_path, project, _auth, issued, plan, provider, attempts = self._admission_fixture()
        workspace_ids = tuple(StableId(f"physical-overlap-{index}") for index in range(3))
        paths = {workspace_id: self._create_workspace_with(provider, workspace_id)
                 for workspace_id in workspace_ids}
        qualifications = tuple(
            provider.qualify_workspace(workspace_ids[index], plan.work_items[index].definition.ref,
                                       StableId(f"physical-proof-{index}"))
            for index in (0, 1)
        )
        first_iso, second_iso = (item.isolation for item in qualifications)
        self.assertIsNotNone(first_iso)
        self.assertIsNotNone(second_iso)
        self.assertNotEqual(first_iso.workspace_root, second_iso.workspace_root)
        self.assertNotEqual(first_iso.index_file, second_iso.index_file)
        self.assertNotEqual(first_iso.head_ref, second_iso.head_ref)
        self.assertEqual(qualifications[0].common_base, qualifications[1].common_base)
        self.assertEqual(qualifications[0].destination, qualifications[1].destination)

        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0]
            first = attempts.claim(
                authority, issued.bearer_token, plan.work_items[0].definition.ref, plan,
                idempotency_key=StableId("physical-overlap-claim-0"), expected_revision=revision,
                workspace_id=workspace_ids[0],
            )
            second = attempts.claim(
                authority, issued.bearer_token, plan.work_items[1].definition.ref, plan,
                idempotency_key=StableId("physical-overlap-claim-1"),
                expected_revision=first.receipt.semantic_revision, workspace_id=workspace_ids[1],
            )
            self.assertNotEqual(first.receipt.result["attempt_id"], second.receipt.result["attempt_id"])
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM attempts").fetchone()[0], 2)

        # Preserve the admitted owner's workspace path, but replace its registered
        # branch checkout with a detached worktree at the same base. Cached proof of
        # distinct paths/refs must no longer justify a third overlapping claim.
        old = provider.qualify_workspace(
            workspace_ids[0], plan.work_items[0].definition.ref, StableId("before-rebind-proof"),
        )
        self.assertEqual(
            self.git.git(paths[workspace_ids[0]], "symbolic-ref", "--quiet", "HEAD").stdout.strip(),
            str(old.isolation.head_ref),
        )
        self.git.git(self.git.repository, "worktree", "remove", "--force", str(paths[workspace_ids[0]]))
        self.git.git(
            self.git.repository, "worktree", "add", "--quiet", "--detach",
            str(paths[workspace_ids[0]]), self.git.base,
        )
        with self.assertRaises(GitProviderError):
            provider.qualify_workspace(
                workspace_ids[0], plan.work_items[0].definition.ref, StableId("after-rebind-proof"),
            )
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            before = self._authority_counts(authority)
            provider.qualified_workspaces.clear()
            with self.assertRaises((AttemptAdmissionDeniedError, AttemptHostUnavailableError)):
                attempts.claim(
                    authority, issued.bearer_token, plan.work_items[2].definition.ref, plan,
                    idempotency_key=StableId("physical-overlap-claim-after-rebind"),
                    expected_revision=before[0], workspace_id=workspace_ids[2],
                )
            self.assertIn(workspace_ids[0], provider.qualified_workspaces)
            self.assertEqual(self._authority_counts(authority), before)

    def test_missing_integration_destination_ref_refuses_claim_without_authority_churn(self):
        authority_path, project, _auth, issued, plan, provider, attempts = self._admission_fixture(count=1)
        workspace_id = StableId("missing-destination-workspace")
        self._create_workspace_with(provider, workspace_id)
        self.git.git(self.git.repository, "update-ref", "-d", str(provider.config.integration_ref))

        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            before = self._authority_counts(authority)
            with self.assertRaises(AttemptHostUnavailableError):
                attempts.claim(
                    authority, issued.bearer_token, plan.work_items[0].definition.ref, plan,
                    idempotency_key=StableId("missing-destination-claim"),
                    expected_revision=before[0], workspace_id=workspace_id,
                )
            self.assertEqual(self._authority_counts(authority), before)

    def test_peer_rebound_after_preflight_is_rejected_before_claim_commit(self):
        authority_path, project, _auth, issued, plan, provider, attempts = self._admission_fixture()
        workspace_ids = tuple(StableId(f"preflight-race-{index}") for index in range(3))
        paths = {workspace_id: self._create_workspace_with(provider, workspace_id)
                 for workspace_id in workspace_ids}
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0]
            first = attempts.claim(
                authority, issued.bearer_token, plan.work_items[0].definition.ref, plan,
                idempotency_key=StableId("preflight-race-first-claim"), expected_revision=revision,
                workspace_id=workspace_ids[0],
            )
            second = attempts.claim(
                authority, issued.bearer_token, plan.work_items[1].definition.ref, plan,
                idempotency_key=StableId("preflight-race-second-claim"),
                expected_revision=first.receipt.semantic_revision, workspace_id=workspace_ids[1],
            )

        old = provider.qualify_workspace(
            workspace_ids[0], plan.work_items[0].definition.ref, StableId("preflight-race-original-proof"),
        )
        mutated: list[StableId] = []
        peer_seen_before_candidate: list[bool] = []

        def rebind_peer_after_candidate_is_qualified(workspace_id: StableId) -> bool:
            if workspace_id != workspace_ids[2]:
                return False
            peer_seen_before_candidate.append(workspace_ids[0] in provider.qualified_workspaces[:-1])
            self.git.git(self.git.repository, "worktree", "remove", "--force", str(paths[workspace_ids[0]]))
            self.git.git(
                self.git.repository, "worktree", "add", "--quiet", str(paths[workspace_ids[0]]),
                str(old.isolation.head_ref).removeprefix("refs/heads/"),
            )
            mutated.append(workspace_id)
            return True

        provider.after_qualification = rebind_peer_after_candidate_is_qualified
        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            before = self._authority_counts(authority)
            with self.assertRaises(AttemptAdmissionDeniedError):
                attempts.claim(
                    authority, issued.bearer_token, plan.work_items[2].definition.ref, plan,
                    idempotency_key=StableId("preflight-race-third-claim"),
                    expected_revision=before[0], workspace_id=workspace_ids[2],
                )
            self.assertEqual(mutated, [workspace_ids[2]])
            self.assertEqual(peer_seen_before_candidate, [True])
            self.assertEqual(self._authority_counts(authority), before)
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM attempts").fetchone()[0], 2)
            self.assertEqual(second.receipt.result["state"], "admitted")

    def test_source_observation_detects_index_only_staged_content(self):
        workspace = self.create_workspace("staged-only")
        request = self.source_request("staged-only")
        clean = self.provider.observe(request)
        self.assertEqual(clean.status, ProviderStatus.OBSERVED_SUCCESS, clean)
        self.assertEqual(clean.value.working_tree, WorkingTreeState.CLEAN)
        original = (workspace / "module.txt").read_bytes()

        (workspace / "module.txt").write_bytes(b"staged-only owner bytes\n")
        self.git.git(workspace, "add", "module.txt")
        # The index still contains the new blob while the worktree is restored to HEAD.
        (workspace / "module.txt").write_bytes(original)

        observed = self.provider.observe(request)
        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS, observed)
        self.assertEqual(observed.value.working_tree, WorkingTreeState.DIRTY)
        self.assertNotEqual(observed.value.source_digest, clean.value.source_digest)

    def test_source_observation_hashes_tracked_edits_and_new_untracked_files(self):
        workspace = self.create_workspace("content-digests")
        request = self.source_request("content-digests")
        clean = self.provider.observe(request)
        self.assertEqual(clean.status, ProviderStatus.OBSERVED_SUCCESS, clean)

        (workspace / "module.txt").write_bytes(b"tracked working-tree edit\n")
        tracked = self.provider.observe(request)
        self.assertEqual(tracked.status, ProviderStatus.OBSERVED_SUCCESS, tracked)
        self.assertEqual(tracked.value.working_tree, WorkingTreeState.DIRTY)
        self.assertNotEqual(tracked.value.source_digest, clean.value.source_digest)
        self.assertIn(
            Sha256Digest(hashlib.sha256(b"tracked working-tree edit\n").hexdigest()),
            {fact.digest for fact in tracked.value.inputs},
        )

        new_bytes = b"new untracked file content\x00\xfe"
        (workspace / "added-after-base.bin").write_bytes(new_bytes)
        added = self.provider.observe(request)
        self.assertEqual(added.status, ProviderStatus.OBSERVED_SUCCESS, added)
        self.assertEqual(added.value.working_tree, WorkingTreeState.DIRTY)
        self.assertNotEqual(added.value.source_digest, tracked.value.source_digest)
        self.assertIn(
            Sha256Digest(hashlib.sha256(new_bytes).hexdigest()),
            {fact.digest for fact in added.value.inputs},
        )

    def test_read_only_qualification_and_source_observation_do_not_change_git_state(self):
        workspace = self.create_workspace("read-only")
        before_root = self.git.snapshot(self.git.repository)
        before_workspace = self.git.snapshot(workspace)

        self.provider.qualify_workspace(StableId("read-only"), self.target, StableId("qualify-read-only"))
        observed = self.provider.observe(self.source_request("read-only"))

        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS, observed)
        self.assertEqual(self.git.snapshot(self.git.repository), before_root)
        self.assertEqual(self.git.snapshot(workspace), before_workspace)

    def test_dirty_destination_with_staged_unstaged_and_untracked_files_is_preserved(self):
        workspace = self.create_workspace("dirty-destination")
        (workspace / "feature.txt").write_bytes(b"committed source work\n")
        self.git.git(workspace, "add", "feature.txt")
        self.git.git(workspace, "commit", "--quiet", "-m", "source change")
        source = self.git.git(workspace, "rev-parse", "HEAD").stdout.strip()

        (self.git.repository / "README.md").write_bytes(b"staged destination bytes\n")
        self.git.git(self.git.repository, "add", "README.md")
        (self.git.repository / "module.txt").write_bytes(b"unstaged destination bytes\n")
        (self.git.repository / "new destination file.bin").write_bytes(b"untracked\x00bytes")
        destination_before = self.git.snapshot(self.git.repository)
        request = self.integrate_request(
            "dirty-destination", source, operation="dirty-destination-independent",
        )

        result = self.provider.perform(request)

        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.DIRTY)
        self.assertEqual(self.git.snapshot(self.git.repository), destination_before)

    def test_index_only_staged_destination_blocks_integration(self):
        workspace = self.create_workspace("staged-destination")
        (workspace / "feature.txt").write_bytes(b"source work\n")
        self.git.git(workspace, "add", "feature.txt")
        self.git.git(workspace, "commit", "--quiet", "-m", "source change")
        source = self.git.git(workspace, "rev-parse", "HEAD").stdout.strip()

        original = (self.git.repository / "module.txt").read_bytes()
        (self.git.repository / "module.txt").write_bytes(b"staged-only destination\n")
        self.git.git(self.git.repository, "add", "module.txt")
        (self.git.repository / "module.txt").write_bytes(original)
        destination_before = self.git.snapshot(self.git.repository)
        request = self.integrate_request(
            "staged-destination", source, operation="staged-destination-independent",
        )

        result = self.provider.perform(request)

        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.DIRTY)
        self.assertEqual(self.git.snapshot(self.git.repository), destination_before)

    def test_requalification_rejects_workspace_rebound_to_detached_head(self):
        workspace = self.create_workspace("rebound")
        self.create_workspace("peer")
        prior = self.provider.qualify_workspace(StableId("rebound"), self.target, StableId("prior-proof"))
        peer = self.provider.qualify_workspace(StableId("peer"), self.target, StableId("peer-proof"))
        self.assertNotEqual(prior.isolation.index_file, peer.isolation.index_file)
        self.assertNotEqual(prior.isolation.head_ref, peer.isolation.head_ref)
        self.assertEqual(
            self.git.git(workspace, "symbolic-ref", "--quiet", "HEAD").stdout.strip(),
            str(prior.isolation.head_ref),
        )

        self.git.git(self.git.repository, "worktree", "remove", "--force", str(workspace))
        self.git.git(self.git.repository, "worktree", "add", "--quiet", "--detach", str(workspace), self.git.base)

        # A matching commit SHA is insufficient: the recorded workspace branch is no longer checked out.
        with self.assertRaises(GitProviderError):
            self.provider.qualify_workspace(StableId("rebound"), self.target, StableId("rebound-again"))

    def test_same_path_branch_and_base_recreated_peer_cannot_rebind_active_attempt(self):
        authority_path, project, _auth, issued, plan, provider, attempts = self._admission_fixture(count=2)
        active_workspace = StableId("same-binding-active")
        candidate_workspace = StableId("same-binding-candidate")
        active_path = self._create_workspace_with(provider, active_workspace)
        self._create_workspace_with(provider, candidate_workspace)
        target = plan.work_items[0].definition.ref
        old = provider.qualify_workspace(active_workspace, target, StableId("same-binding-original"))

        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            revision = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton=1"
            ).fetchone()[0]
            claim = attempts.claim(
                authority, issued.bearer_token, target, plan,
                idempotency_key=StableId("same-binding-first-claim"), expected_revision=revision,
                workspace_id=active_workspace,
            )

        branch_ref = str(old.isolation.head_ref)
        branch_short_name = branch_ref.removeprefix("refs/heads/")
        before_index_tree = self.git.git(active_path, "write-tree").stdout.strip()
        before_status = self.git.git(active_path, "status", "--porcelain=v2", "--untracked-files=all").stdout
        self.git.git(self.git.repository, "worktree", "remove", "--force", str(active_path))
        self.git.git(self.git.repository, "worktree", "add", "--quiet", str(active_path), branch_short_name)

        self.assertEqual(self.git.git(active_path, "rev-parse", "HEAD").stdout.strip(), self.git.base)
        self.assertEqual(self.git.git(active_path, "symbolic-ref", "--quiet", "HEAD").stdout.strip(), branch_ref)
        self.assertEqual(self.git.git(active_path, "write-tree").stdout.strip(), before_index_tree)
        self.assertEqual(
            self.git.git(active_path, "status", "--porcelain=v2", "--untracked-files=all").stdout,
            before_status,
        )
        try:
            replacement = provider.qualify_workspace(
                active_workspace, target, StableId("same-binding-recreated-query"),
            )
        except GitProviderError:
            replacement = None
        else:
            # Root, ref, destination and index-path hashes alone are insufficient
            # to bind a second Git worktree incarnation to the admitted attempt.
            self.assertNotEqual(replacement.isolation, old.isolation)

        with SQLiteAuthority.open_writer(authority_path, project) as authority:
            before = self._authority_counts(authority)
            with self.assertRaises(AttemptAdmissionDeniedError):
                attempts.claim(
                    authority, issued.bearer_token, plan.work_items[1].definition.ref, plan,
                    idempotency_key=StableId("same-binding-second-claim"), expected_revision=before[0],
                    workspace_id=candidate_workspace,
                )
            self.assertEqual(self._authority_counts(authority), before)
            self.assertEqual(claim.receipt.result["state"], "admitted")

    def test_crash_after_ref_advance_is_recovered_by_fresh_provider_without_duplicate_commit(self):
        workspace = self.create_workspace("restart-integration")
        (workspace / "feature.txt").write_bytes(b"feature\n")
        self.git.git(workspace, "add", "feature.txt")
        self.git.git(workspace, "commit", "--quiet", "-m", "source change")
        source = self.git.git(workspace, "rev-parse", "HEAD").stdout.strip()
        request = self.integrate_request("restart-integration", source, operation="restart-after-effect")
        stages: list[str] = []

        def interrupt(stage: str, _request: GitEffectRequest) -> None:
            stages.append(stage)
            if stage == "after_effect":
                raise RuntimeError("simulated process loss after destination CAS")

        interrupted_provider = GitRepositoryProvider(self.config, failure_hook=interrupt)
        interrupted = interrupted_provider.perform(request)
        self.assertEqual(interrupted.status, ProviderStatus.UNAVAILABLE)
        advanced = self.git.git(
            self.git.repository, "rev-parse", str(self.config.integration_ref)
        ).stdout.strip()
        commit_count = self.git.git(
            self.git.repository, "rev-list", "--count", str(self.config.integration_ref)
        ).stdout.strip()

        restarted_provider = GitRepositoryProvider(self.config)
        inspection = EffectInspectionRequest(
            self.context,
            request.operation_id,
            request.idempotency_key,
            provider_request_digest(request),
            StableId("restart-query"),
            request,
        )
        recovered = restarted_provider.inspect(inspection)
        self.assertEqual(recovered.status, ProviderStatus.OBSERVED_SUCCESS, recovered)
        self.assertEqual(recovered.correlation_id, inspection.correlation_id)
        self.assertEqual(recovered.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(str(recovered.value.external_ref), advanced)

        replay = restarted_provider.perform(request)
        self.assertEqual(replay.status, ProviderStatus.UNKNOWN, replay)
        self.assertIsNone(replay.receipt)
        self.assertEqual(
            self.git.git(self.git.repository, "rev-parse", str(self.config.integration_ref)).stdout.strip(),
            advanced,
        )
        self.assertEqual(
            self.git.git(self.git.repository, "rev-list", "--count", str(self.config.integration_ref)).stdout.strip(),
            commit_count,
        )
        self.assertEqual(stages, ["before_effect", "after_commit_object", "after_effect"])

    def test_crash_after_immutable_commit_object_preserves_identity_through_inspection_and_retry(self):
        workspace = self.create_workspace("commit-object-before-cas")
        (workspace / "feature.txt").write_bytes(b"effect after object creation\n")
        self.git.git(workspace, "add", "feature.txt")
        self.git.git(workspace, "commit", "--quiet", "-m", "source change")
        source = self.git.git(workspace, "rev-parse", "HEAD").stdout.strip()
        request = self.integrate_request(
            "commit-object-before-cas", source, operation="commit-object-before-cas-operation",
        )
        stages: list[str] = []

        def interrupt(stage: str, _request: GitEffectRequest) -> None:
            stages.append(stage)
            if stage == "after_commit_object":
                raise RuntimeError("simulated process loss after commit-tree and before ref CAS")

        interrupted = GitRepositoryProvider(self.config, failure_hook=interrupt).perform(request)
        self.assertEqual(interrupted.status, ProviderStatus.UNAVAILABLE)
        self.assertEqual(stages, ["before_effect", "after_commit_object"])
        operation_path = self.config.journal_root / "operations" / (
            hashlib.sha256(str(request.operation_id).encode()).hexdigest() + ".json"
        )
        before_inspection = json.loads(operation_path.read_text(encoding="ascii"))
        pending = before_inspection.get("pending_commit")
        self.assertIsInstance(pending, dict)
        pending_commit = pending.get("commit")
        self.assertIsInstance(pending_commit, str)
        self.assertEqual(
            self.git.git(self.git.repository, "cat-file", "-t", pending_commit).stdout.strip(), "commit"
        )
        self.assertEqual(self.provider.integration_head().value, str(request.expected_destination))

        restarted = GitRepositoryProvider(self.config)
        inspection = EffectInspectionRequest(
            self.context,
            request.operation_id,
            request.idempotency_key,
            provider_request_digest(request),
            StableId("commit-object-inspection-query"),
            request,
        )
        observed = restarted.inspect(inspection)
        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS, observed)
        self.assertEqual(observed.correlation_id, inspection.correlation_id)
        self.assertEqual(observed.value.disposition, GitEffectDisposition.NOT_APPLIED)
        after_inspection = json.loads(operation_path.read_text(encoding="ascii"))
        retained = after_inspection.get("pending_commit")
        self.assertIsInstance(retained, dict)
        self.assertEqual(retained.get("commit"), pending_commit)

        retried = restarted.retry_not_applied(request)
        self.assertEqual(retried.status, ProviderStatus.OBSERVED_SUCCESS, retried)
        self.assertEqual(retried.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(str(retried.value.external_ref), pending_commit)
        self.assertEqual(str(self.provider.integration_head()), pending_commit)

    def test_crash_before_workspace_effect_requires_inspection_then_explicit_retry(self):
        request = self.create_request("before-effect", operation="create-before-effect")
        stages: list[str] = []

        def interrupt(stage: str, _request: GitEffectRequest) -> None:
            stages.append(stage)
            if stage == "before_effect":
                raise RuntimeError("simulated loss before worktree creation")

        interrupted = GitRepositoryProvider(self.config, failure_hook=interrupt).perform(request)
        self.assertEqual(interrupted.status, ProviderStatus.UNAVAILABLE)
        path = self.provider.workspace_path_for(StableId("before-effect"))
        self.assertFalse(path.exists())

        restarted = GitRepositoryProvider(self.config)
        inspection = EffectInspectionRequest(
            self.context,
            request.operation_id,
            request.idempotency_key,
            provider_request_digest(request),
            StableId("before-effect-query"),
            request,
        )
        observed = restarted.inspect(inspection)
        self.assertEqual(observed.status, ProviderStatus.OBSERVED_SUCCESS, observed)
        self.assertEqual(observed.value.disposition, GitEffectDisposition.NOT_APPLIED)
        self.assertEqual(observed.correlation_id, inspection.correlation_id)
        self.assertFalse(path.exists())

        retried = restarted.retry_not_applied(request)
        self.assertEqual(retried.status, ProviderStatus.OBSERVED_SUCCESS, retried)
        self.assertEqual(retried.value.disposition, GitEffectDisposition.APPLIED)
        self.assertTrue(path.is_dir())
        replay = restarted.perform(request)
        self.assertEqual(replay.value.disposition, GitEffectDisposition.APPLIED)
        self.assertEqual(len(tuple(self.config.workspace_root.iterdir())), 1)

    def test_conflict_preserves_destination_and_source_indexes_and_bytes(self):
        workspace = self.create_workspace("conflicting-source")
        (workspace / "module.txt").write_bytes(b"source side\nsecond line\n")
        self.git.git(workspace, "add", "module.txt")
        self.git.git(workspace, "commit", "--quiet", "-m", "source edit")
        source = self.git.git(workspace, "rev-parse", "HEAD").stdout.strip()
        (self.git.repository / "module.txt").write_bytes(b"destination side\nsecond line\n")
        self.git.git(self.git.repository, "add", "module.txt")
        self.git.git(self.git.repository, "commit", "--quiet", "-m", "destination edit")
        destination_commit = self.git.git(self.git.repository, "rev-parse", "HEAD").stdout.strip()
        self.git.git(
            self.git.repository, "update-ref", str(self.config.integration_ref), destination_commit, self.git.base,
        )
        destination_before = self.git.snapshot(self.git.repository)
        source_before = self.git.snapshot(workspace)
        request = self.integrate_request(
            "conflicting-source", source, expected_destination=self.provider.integration_head().value,
            operation="independent-conflict",
        )

        result = self.provider.perform(request)

        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.CONFLICT)
        self.assertTrue(result.value.conflict_refs)
        self.assertEqual(self.git.snapshot(self.git.repository), destination_before)
        self.assertEqual(self.git.snapshot(workspace), source_before)

    def test_stale_destination_cas_is_refused_without_mutating_either_worktree(self):
        workspace = self.create_workspace("stale-cas")
        (workspace / "feature.txt").write_bytes(b"source work\n")
        self.git.git(workspace, "add", "feature.txt")
        self.git.git(workspace, "commit", "--quiet", "-m", "source change")
        source = self.git.git(workspace, "rev-parse", "HEAD").stdout.strip()
        reviewed_destination = self.provider.integration_head().value

        (self.git.repository / "destination.txt").write_bytes(b"advance destination\n")
        self.git.git(self.git.repository, "add", "destination.txt")
        self.git.git(self.git.repository, "commit", "--quiet", "-m", "advance destination")
        advanced_destination = self.git.git(self.git.repository, "rev-parse", "HEAD").stdout.strip()
        self.git.git(
            self.git.repository, "update-ref", str(self.config.integration_ref),
            advanced_destination, reviewed_destination,
        )
        advanced_snapshot = self.git.snapshot(self.git.repository)
        source_snapshot = self.git.snapshot(workspace)
        request = self.integrate_request(
            "stale-cas", source, expected_destination=reviewed_destination,
            operation="independent-stale-cas",
        )

        result = self.provider.perform(request)

        self.assertEqual(result.status, ProviderStatus.OBSERVED_SUCCESS, result)
        self.assertEqual(result.value.disposition, GitEffectDisposition.REJECTED)
        self.assertEqual(self.git.snapshot(self.git.repository), advanced_snapshot)
        self.assertEqual(self.git.snapshot(workspace), source_snapshot)

if __name__ == "__main__":
    unittest.main()
