"""Conservative local Git worktree, source, and integration provider.

The provider operates only on explicitly configured repository and scratch
roots. It never deletes or resets a worktree. Source identity includes every
non-`.git` file, including ignored and untracked content, except exact
repository-relative exclusions supplied in the trusted configuration. Git
effects have a provider journal separate from Todo's durable operation intent;
inspection reconstructs the result from refs/worktrees after a process crash.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
from typing import Protocol

from todo_orchestrator.contracts import (
    Attempt,
    AttemptState,
    DeclarationKind,
    DeclarationObservation,
    DeclarationObservationRequest,
    DeclarationStatus,
    EffectInspectionRequest,
    EntityRef,
    EvidenceInput,
    GitEffectDisposition,
    GitEffectObservation,
    GitEffectRequest,
    GitOperationKind,
    ProviderCallContext,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Sha256Digest,
    SourceObservation,
    SourceObservationRequest,
    StableId,
    WorkingTreeState,
    ArtifactAvailability,
    provider_request_digest,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceIsolation,
    WorkspaceQualification,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - this provider is POSIX-only by design
    fcntl = None


class GitProviderError(RuntimeError):
    """The configured Git repository or an effect could not be qualified."""


class GitCommandError(GitProviderError):
    def __init__(self, args: tuple[str, ...], returncode: int, stderr: str) -> None:
        self.args = args
        self.returncode = returncode
        super().__init__(f"git {args[0] if args else ''} failed ({returncode}): {stderr.strip()[:500]}")


class ProcessObserver(Protocol):
    def inspect(self, attempt: Attempt) -> ProcessLiveness: ...


class ChildActivityObserver(Protocol):
    def inspect(self, attempt: Attempt) -> ChildActivity: ...


@dataclass(frozen=True)
class GitRepositoryConfig:
    """Trusted local paths and refs for one repository integration boundary."""

    project_id: StableId
    repository_id: StableId
    repository_root: Path
    workspace_root: Path
    journal_root: Path
    base_ref: StableId
    integration_ref: StableId
    excluded_paths: tuple[str, ...] = (".todo-orchestrator",)
    provider_id: StableId = StableId("todo.git.local")
    version: str = "git-cli-1"
    command_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        for value, name in (
            (self.project_id, "project_id"), (self.repository_id, "repository_id"),
            (self.base_ref, "base_ref"), (self.integration_ref, "integration_ref"),
            (self.provider_id, "provider_id"),
        ):
            if not isinstance(value, StableId):
                raise TypeError(f"{name} must be a StableId")
        for value, name in ((self.repository_root, "repository_root"),
                             (self.workspace_root, "workspace_root"),
                             (self.journal_root, "journal_root")):
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute pathlib.Path")
        if not isinstance(self.excluded_paths, tuple) or any(not isinstance(item, str) for item in self.excluded_paths):
            raise TypeError("excluded_paths must be a tuple of repository-relative paths")
        if len(set(self.excluded_paths)) != len(self.excluded_paths):
            raise ValueError("excluded_paths must be unique")
        normalized: list[str] = []
        for item in self.excluded_paths:
            path = PurePosixPath(item)
            if path.is_absolute() or not item or any(part in {"", ".", ".."} for part in path.parts):
                raise ValueError("excluded paths must be normalized relative paths without traversal")
            if ".git" in path.parts:
                raise ValueError(".git is always excluded and must not be configured explicitly")
            normalized.append(path.as_posix())
        if self.base_ref.value.startswith("-") or not self.base_ref.value.startswith(("refs/heads/", "refs/tags/")):
            raise ValueError("base_ref must be a full branch or tag ref")
        if not self.integration_ref.value.startswith("refs/heads/") or self.integration_ref.value.startswith("-"):
            raise ValueError("integration_ref must be a full local branch ref")
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("version must be non-empty text")
        if (isinstance(self.command_timeout_seconds, bool) or not isinstance(self.command_timeout_seconds, (int, float))
                or self.command_timeout_seconds <= 0):
            raise ValueError("command_timeout_seconds must be positive")
        repository = self.repository_root.resolve(strict=True)
        if not repository.is_dir():
            raise ValueError("repository_root must be an existing directory")
        worktrees = self.workspace_root.resolve(strict=False)
        journal = self.journal_root.resolve(strict=False)
        if worktrees == repository or repository in worktrees.parents:
            raise ValueError("workspace_root must be outside repository_root")
        if journal == repository or repository in journal.parents:
            raise ValueError("journal_root must be outside repository_root")
        if journal == worktrees or worktrees in journal.parents or journal in worktrees.parents:
            raise ValueError("journal_root and workspace_root must be separate trees")
        object.__setattr__(self, "repository_root", repository)
        object.__setattr__(self, "workspace_root", worktrees)
        object.__setattr__(self, "journal_root", journal)
        object.__setattr__(self, "excluded_paths", tuple(normalized))


@dataclass(frozen=True)
class _ManifestEntry:
    path: bytes
    mode: str
    digest: str


class GitRepositoryProvider:
    """POSIX local Git provider with read-only host observations and safe effects."""

    def __init__(
        self,
        config: GitRepositoryConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        process_observer: ProcessObserver | None = None,
        child_observer: ChildActivityObserver | None = None,
        failure_hook: Callable[[str, GitEffectRequest], None] | None = None,
    ) -> None:
        if not isinstance(config, GitRepositoryConfig):
            raise TypeError("config must be a GitRepositoryConfig")
        if fcntl is None:
            raise GitProviderError("the local Git provider currently requires POSIX file locking")
        self.config = config
        self.identity = ProviderIdentity(config.provider_id, config.version)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.process_observer = process_observer
        self.child_observer = child_observer
        self.failure_hook = failure_hook
        self._assert_repository()

    def _environment(self) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }

    def _git(self, args: tuple[str, ...] | list[str], *, cwd: Path | None = None,
             check: bool = True) -> bytes:
        directory = cwd or self.config.repository_root
        command = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(directory), *args]
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._environment(), timeout=self.config.command_timeout_seconds, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitProviderError(f"could not complete local Git command {args[0] if args else ''}: {exc}") from exc
        if check and completed.returncode != 0:
            raise GitCommandError(tuple(args), completed.returncode,
                                  completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout

    def _assert_repository(self) -> Path:
        top = Path(os.fsdecode(self._git(["rev-parse", "--show-toplevel"]).strip())).resolve(strict=True)
        if top != self.config.repository_root:
            raise GitProviderError("repository_root is not the configured Git worktree root")
        common = self._common_git_dir(self.config.repository_root)
        if not common.is_dir():
            raise GitProviderError("Git common directory is unavailable")
        self._resolve_ref(self.config.base_ref)
        self._resolve_ref(self.config.integration_ref)
        return common

    def _common_git_dir(self, cwd: Path) -> Path:
        value = os.fsdecode(self._git(["rev-parse", "--git-common-dir"], cwd=cwd).strip())
        result = Path(value)
        if not result.is_absolute():
            result = cwd / result
        return result.resolve(strict=True)

    def _git_dir(self, cwd: Path) -> Path:
        value = os.fsdecode(self._git(["rev-parse", "--git-dir"], cwd=cwd).strip())
        result = Path(value)
        if not result.is_absolute():
            result = cwd / result
        return result.resolve(strict=True)

    def _resolve_ref(self, ref: StableId) -> str:
        value = os.fsdecode(self._git(["rev-parse", "--verify", f"{ref.value}^{{commit}}"], check=False).strip())
        if not value or any(char not in "0123456789abcdef" for char in value):
            raise GitProviderError(f"Git ref is missing or does not resolve to a commit: {ref}")
        return value

    def _workspace_token(self, workspace_id: StableId) -> str:
        return hashlib.sha256(str(workspace_id).encode("utf-8")).hexdigest()

    def _workspace_path(self, workspace_id: StableId) -> Path:
        return self.config.workspace_root / ("w-" + self._workspace_token(workspace_id))

    def _workspace_branch(self, workspace_id: StableId) -> StableId:
        return StableId("refs/heads/todo-orchestrator/workspaces/w-" + self._workspace_token(workspace_id))

    def _workspace_record_path(self, workspace_id: StableId) -> Path:
        return self.config.journal_root / "workspaces" / (self._workspace_token(workspace_id) + ".json")

    def _operation_record_path(self, operation_id: StableId) -> Path:
        return self.config.journal_root / "operations" / (hashlib.sha256(str(operation_id).encode()).hexdigest() + ".json")

    @contextmanager
    def _locked(self):
        lock_path = self.config.journal_root / "locks" / "repository.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _canonical(value: object) -> str:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))

    def _write_json(self, path: Path, value: Mapping[str, object], *, exclusive: bool = False) -> None:
        encoded = self._canonical(value).encode("ascii")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temp_name = tempfile.mkstemp(prefix=".git-provider-", dir=path.parent)
        temporary = Path(temp_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            if exclusive:
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    existing = json.loads(path.read_text(encoding="ascii"))
                    if existing != dict(value):
                        raise GitProviderError(f"provider journal identity collision at {path.name}")
            else:
                os.replace(temporary, path)
            self._sync_directory(path.parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _sync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_json(self, path: Path) -> dict[str, object] | None:
        try:
            value = json.loads(path.read_text(encoding="ascii"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise GitProviderError(f"provider journal record {path.name} is unreadable: {exc}") from exc
        if not isinstance(value, dict):
            raise GitProviderError(f"provider journal record {path.name} is malformed")
        return value

    def _workspace_record(self, workspace_id: StableId) -> dict[str, object] | None:
        record = self._read_json(self._workspace_record_path(workspace_id))
        if record is not None and (record.get("workspace_id") != str(workspace_id)
                                   or record.get("repository_id") != str(self.config.repository_id)):
            raise GitProviderError("workspace journal identity does not match the requested workspace")
        return record

    def _commit_manifest(self, commit: str) -> tuple[_ManifestEntry, ...]:
        output = self._git(["ls-tree", "-r", "-z", "--full-tree", commit])
        result: list[_ManifestEntry] = []
        excluded = self.config.excluded_paths
        for item in output.split(b"\0"):
            if not item:
                continue
            try:
                metadata, name = item.split(b"\t", 1)
                mode, object_type, oid = metadata.decode("ascii").split(" ")
            except (ValueError, UnicodeError) as exc:
                raise GitProviderError("Git returned an invalid tree entry") from exc
            path = PurePosixPath(os.fsdecode(name)).as_posix()
            if self._excluded(path, excluded):
                continue
            if object_type == "commit":
                raise GitProviderError("Git submodules require a separate trusted source observer")
            if object_type != "blob":
                raise GitProviderError("unsupported Git tree entry type")
            blob = self._git(["cat-file", "blob", oid])
            result.append(_ManifestEntry(name, mode, hashlib.sha256(blob).hexdigest()))
        return tuple(sorted(result, key=lambda entry: entry.path))

    def _filesystem_manifest(self, root: Path) -> tuple[_ManifestEntry, ...]:
        entries: list[_ManifestEntry] = []
        excluded = self.config.excluded_paths

        def walk(directory: Path, prefix: bytes = b"") -> None:
            try:
                children = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
            except OSError as exc:
                raise GitProviderError(f"cannot enumerate source directory {directory}: {exc}") from exc
            for child in children:
                name = os.fsencode(child.name)
                relative = name if not prefix else prefix + b"/" + name
                relative_text = PurePosixPath(os.fsdecode(relative)).as_posix()
                if self._excluded(relative_text, excluded):
                    continue
                try:
                    info = child.stat(follow_symlinks=False)
                except OSError as exc:
                    raise GitProviderError(f"cannot inspect source entry {relative_text}: {exc}") from exc
                if child.is_dir(follow_symlinks=False):
                    walk(Path(child.path), relative)
                elif child.is_symlink():
                    target = os.fsencode(os.readlink(child.path))
                    entries.append(_ManifestEntry(relative, "120000", hashlib.sha256(target).hexdigest()))
                elif child.is_file(follow_symlinks=False):
                    mode = "100755" if info.st_mode & 0o111 else "100644"
                    digest = hashlib.sha256()
                    try:
                        with open(child.path, "rb") as source:
                            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                                digest.update(chunk)
                    except OSError as exc:
                        raise GitProviderError(f"cannot read source file {relative_text}: {exc}") from exc
                    entries.append(_ManifestEntry(relative, mode, digest.hexdigest()))
                else:
                    raise GitProviderError(f"unsupported special source entry: {relative_text}")

        walk(root)
        return tuple(sorted(entries, key=lambda entry: entry.path))

    @staticmethod
    def _excluded(path: str, exclusions: tuple[str, ...]) -> bool:
        return any(part == ".git" for part in PurePosixPath(path).parts) or any(
            path == item or path.startswith(item + "/") for item in exclusions
        )

    @staticmethod
    def _manifest_digest(entries: tuple[_ManifestEntry, ...]) -> Sha256Digest:
        digest = hashlib.sha256()
        for entry in entries:
            digest.update(len(entry.path).to_bytes(8, "big"))
            digest.update(entry.path)
            digest.update(entry.mode.encode("ascii"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(entry.digest))
        return Sha256Digest(digest.hexdigest())

    def _tree_digest(self, commit: str) -> Sha256Digest:
        return self._manifest_digest(self._commit_manifest(commit))

    def qualified_revision(self, ref: StableId | None = None) -> QualifiedSourceRevision:
        """Return an immutable local commit identity and its source-tree digest."""
        selected = self.config.base_ref if ref is None else ref
        commit = self._resolve_ref(selected)
        return QualifiedSourceRevision(
            self.config.project_id, self.config.repository_id, StableId(commit), self._tree_digest(commit).hex,
        )

    def integration_head(self) -> StableId:
        """Read the current qualified destination commit for a later CAS request."""
        return StableId(self._resolve_ref(self.config.integration_ref))

    def workspace_path_for(self, workspace_id: StableId) -> Path:
        """Return the deterministic provider-managed location for an existing workspace ID."""
        if not isinstance(workspace_id, StableId):
            raise TypeError("workspace_id must be a StableId")
        return self._workspace_path(workspace_id)

    def _path_state(self, root: Path, head: str) -> tuple[tuple[_ManifestEntry, ...], SourceSafety]:
        current = self._filesystem_manifest(root)
        baseline = self._commit_manifest(head)
        return current, SourceSafety.CLEAN if current == baseline else SourceSafety.DIRTY

    def _assert_worktree(self, path: Path) -> tuple[Path, str, Path]:
        if not path.is_dir():
            raise GitProviderError("qualified workspace path is missing")
        root = Path(os.fsdecode(self._git(["rev-parse", "--show-toplevel"], cwd=path).strip())).resolve(strict=True)
        if root != path.resolve(strict=True):
            raise GitProviderError("qualified workspace top-level differs from its registered path")
        common = self._common_git_dir(path)
        if common != self._assert_repository():
            raise GitProviderError("workspace is not a linked worktree of the configured repository")
        head = os.fsdecode(self._git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=path).strip())
        git_dir = self._git_dir(path)
        index_path = Path(os.fsdecode(self._git(["rev-parse", "--path-format=absolute", "--git-path", "index"], cwd=path).strip()))
        if not index_path.is_absolute():
            index_path = path / index_path
        index_path = index_path.resolve(strict=True)
        if not index_path.is_file():
            raise GitProviderError("worktree has no independent Git index file")
        return common, head, index_path

    def _isolation(self, workspace_id: StableId, path: Path, branch: StableId) -> WorkspaceIsolation:
        common, _head, index_path = self._assert_worktree(path)
        root_identity = hashlib.sha256(os.fsencode(path.resolve(strict=True))).hexdigest()
        index_identity = hashlib.sha256(os.fsencode(index_path)).hexdigest()
        common_identity = hashlib.sha256(os.fsencode(common)).hexdigest()
        return WorkspaceIsolation(
            Sha256Digest(common_identity), Sha256Digest(root_identity), Sha256Digest(index_identity), branch,
        )

    def _receipt(self, *, request_digest: Sha256Digest, correlation_id: StableId,
                 provenance_ref: StableId, suffix: str) -> ProviderReceipt:
        return ProviderReceipt(
            StableId("gitreceipt-" + hashlib.sha256(
                f"{correlation_id}:{request_digest.hex}:{suffix}".encode("utf-8")
            ).hexdigest()),
            self.identity,
            correlation_id,
            request_digest,
            provenance_ref,
            self._now(),
        )

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise GitProviderError("provider clock must return an aware datetime")
        return value.astimezone(timezone.utc)

    def _qualification(self, workspace_id: StableId, target: EntityRef, correlation_id: StableId,
                       *, verify_ref: bool = True) -> WorkspaceQualification:
        record = self._workspace_record(workspace_id)
        if record is None:
            raise GitProviderError("workspace has no provider-owned creation record")
        path = self._workspace_path(workspace_id)
        base_ref = StableId(record["base_ref"])
        base_commit = str(record["base_commit"])
        branch_ref = StableId(record["branch_ref"])
        if branch_ref != self._workspace_branch(workspace_id):
            raise GitProviderError("workspace branch identity does not match its deterministic mapping")
        common, head, index_path = self._assert_worktree(path)
        if verify_ref:
            branch_head = self._resolve_ref(branch_ref)
            if branch_head != head:
                raise GitProviderError("workspace branch and checked-out HEAD have diverged")
        if not self._is_ancestor(base_commit, head):
            raise GitProviderError("workspace HEAD no longer descends from its qualified common base")
        destination = self.config.integration_ref
        destination_head = self._resolve_ref(destination)
        root_identity = Sha256Digest(hashlib.sha256(os.fsencode(path.resolve(strict=True))).hexdigest())
        index_identity = Sha256Digest(hashlib.sha256(os.fsencode(index_path)).hexdigest())
        common_identity = Sha256Digest(hashlib.sha256(os.fsencode(common)).hexdigest())
        isolation = WorkspaceIsolation(common_identity, root_identity, index_identity, branch_ref)
        request_material = {
            "workspace_id": str(workspace_id), "target": self._ref_value(target),
            "repository_id": str(self.config.repository_id), "base_ref": str(base_ref),
            "base_commit": base_commit, "base_digest": self._tree_digest(base_commit).hex,
            "destination_ref": str(destination), "destination_head": destination_head,
            "workspace_head": head, "isolation": {
                "repository_storage": common_identity.hex,
                "workspace_root": root_identity.hex, "index_file": index_identity.hex,
                "head_ref": str(branch_ref),
            },
        }
        request_digest = Sha256Digest(hashlib.sha256(self._canonical(request_material).encode("ascii")).hexdigest())
        receipt = self._receipt(request_digest=request_digest, correlation_id=correlation_id,
                                provenance_ref=StableId(base_commit), suffix="workspace")
        return WorkspaceQualification(
            workspace_id, self.config.repository_id,
            QualifiedSourceRevision(self.config.project_id, self.config.repository_id,
                                    StableId(base_commit), self._tree_digest(base_commit).hex),
            QualifiedDestination(self.config.project_id, self.config.repository_id, destination),
            receipt, isolation,
        )

    @staticmethod
    def _ref_value(ref: EntityRef) -> dict[str, object]:
        return {
            "project_id": str(ref.project_id), "kind": ref.kind.value,
            "entity_id": str(ref.entity_id),
            "definition_revision_id": None if ref.definition_revision_id is None else str(ref.definition_revision_id),
            "incarnation_id": None if ref.incarnation_id is None else str(ref.incarnation_id),
        }

    def _is_ancestor(self, ancestor: str, descendant: str) -> bool:
        # Git communicates this predicate with its exit code.
        command = ["git", "--no-replace-objects", "-C", str(self.config.repository_root),
                   "merge-base", "--is-ancestor", ancestor, descendant]
        try:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, env=self._environment(),
                                       timeout=self.config.command_timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitProviderError(f"cannot validate Git ancestry: {exc}") from exc
        return completed.returncode == 0

    def qualify_workspace(self, workspace_id: StableId, target: EntityRef,
                          correlation_id: StableId) -> WorkspaceQualification:
        if not isinstance(workspace_id, StableId) or not isinstance(correlation_id, StableId):
            raise TypeError("workspace_id and correlation_id must be StableId values")
        if not isinstance(target, EntityRef) or target.kind.value != "work_item":
            raise TypeError("target must be a qualified work-item reference")
        if target.project_id != self.config.project_id:
            raise GitProviderError("workspace target belongs to another project")
        with self._locked():
            return self._qualification(workspace_id, target, correlation_id)

    def observe(self, request: SourceObservationRequest) -> ProviderResult[SourceObservation]:
        if not isinstance(request, SourceObservationRequest):
            raise TypeError("request must be a SourceObservationRequest")
        try:
            if request.context.project_id != self.config.project_id or request.workspace_id is None or request.target is None:
                raise GitProviderError("source observation requires the exact configured project workspace and target")
            with self._locked():
                qualification = self._qualification(request.workspace_id, request.target, request.correlation_id)
                path = self._workspace_path(request.workspace_id)
                _common, head, _index = self._assert_worktree(path)
                entries, safety = self._path_state(path, head)
                source_digest = self._manifest_digest(entries)
                inputs = tuple(
                    EvidenceInput(
                        StableId("file-" + hashlib.sha256(entry.path).hexdigest()),
                        Sha256Digest(entry.digest),
                    )
                    for entry in entries
                )
                artifacts = tuple(self._artifact_availability(item.artifact_id, item.expected_digest)
                                  for item in request.artifacts)
                observation = SourceObservation(
                    self.config.repository_id, source_digest,
                    Sha256Digest(qualification.common_base.digest),
                    WorkingTreeState.CLEAN if safety is SourceSafety.CLEAN else WorkingTreeState.DIRTY,
                    inputs, artifacts,
                )
                receipt = self._receipt(
                    request_digest=provider_request_digest(request), correlation_id=request.correlation_id,
                    provenance_ref=request.workspace_id, suffix="source",
                )
                return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.correlation_id,
                                      self.identity, observation, receipt)
        except Exception as exc:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("git_source_unavailable"))

    def _artifact_availability(self, artifact_id: StableId, expected: Sha256Digest) -> ArtifactAvailability:
        raw = str(artifact_id)
        if not raw or any(char not in "0123456789abcdef" for char in raw) or len(raw) not in (40, 64):
            return ArtifactAvailability(artifact_id, False, None)
        kind = os.fsdecode(self._git(["cat-file", "-t", raw], check=False).strip())
        if kind not in {"blob", "tree", "commit"}:
            return ArtifactAvailability(artifact_id, False, None)
        if kind == "commit":
            digest = self._tree_digest(raw)
        elif kind == "tree":
            rows = self._git(["ls-tree", "-r", "-z", "--full-tree", raw])
            digest = Sha256Digest(hashlib.sha256(rows).hexdigest())
        else:
            digest = Sha256Digest(hashlib.sha256(self._git(["cat-file", "blob", raw])).hexdigest())
        return ArtifactAvailability(artifact_id, digest == expected, digest if digest == expected else None)

    def observe_declaration(self, request: DeclarationObservationRequest) -> ProviderResult[DeclarationObservation]:
        if not isinstance(request, DeclarationObservationRequest):
            raise TypeError("request must be a DeclarationObservationRequest")
        observation = DeclarationObservation(
            request.target, request.declaration_kind, request.declaration_digest,
            DeclarationStatus.UNRESOLVED,
        )
        receipt = self._receipt(
            request_digest=provider_request_digest(request), correlation_id=request.correlation_id,
            provenance_ref=request.workspace_id, suffix="declaration-unresolved",
        )
        return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.correlation_id,
                              self.identity, observation, receipt)

    def inspect_attempt(self, attempt: Attempt, workspace: WorkspaceQualification) -> AttemptSafetyObservation:
        if not isinstance(attempt, Attempt) or not isinstance(workspace, WorkspaceQualification):
            raise TypeError("attempt and workspace must be typed domain records")
        try:
            fresh = self.qualify_workspace(workspace.workspace_id, attempt.work_item, attempt.ref.entity_id)
            if (fresh.common_base != workspace.common_base or fresh.destination != workspace.destination
                    or fresh.isolation != workspace.isolation or fresh.receipt.provider != workspace.receipt.provider):
                raise GitProviderError("fresh workspace qualification differs from persisted attempt identity")
            path = self._workspace_path(workspace.workspace_id)
            _common, head, _index = self._assert_worktree(path)
            _entries, safety = self._path_state(path, head)
        except Exception:
            fresh = workspace
            safety = SourceSafety.UNKNOWN
        process = ProcessLiveness.UNKNOWN
        children = ChildActivity.UNKNOWN
        try:
            if self.process_observer is not None:
                value = self.process_observer.inspect(attempt)
                process = value if isinstance(value, ProcessLiveness) else ProcessLiveness.UNKNOWN
        except Exception:
            process = ProcessLiveness.UNKNOWN
        try:
            if self.child_observer is not None:
                value = self.child_observer.inspect(attempt)
                children = value if isinstance(value, ChildActivity) else ChildActivity.UNKNOWN
        except Exception:
            children = ChildActivity.UNKNOWN
        receipt = self._receipt(
            request_digest=Sha256Digest(hashlib.sha256(self._canonical({
                "attempt": self._ref_value(attempt.ref), "state": attempt.state.value,
                "lease_id": None if attempt.lease is None else str(attempt.lease.lease_id),
                "lease_expires_at": None if attempt.lease is None else attempt.lease.expires_at.isoformat(),
                "workspace": str(workspace.workspace_id), "source": safety.value,
                "process": process.value, "children": children.value,
                "head": None if safety is SourceSafety.UNKNOWN else head,
            }).encode("ascii")).hexdigest()),
            correlation_id=attempt.ref.entity_id, provenance_ref=fresh.common_base.ref, suffix="attempt-safety",
        )
        lease = attempt.lease
        return AttemptSafetyObservation(
            attempt.ref, attempt.state,
            StableId("missing-lease") if lease is None else lease.lease_id,
            self._now() if lease is None else lease.expires_at,
            fresh, safety, process, children, receipt,
        )

    def _request_value(self, request: GitEffectRequest) -> dict[str, object]:
        return {
            "context": {
                "project_id": str(request.context.project_id),
                "actor": self._ref_value(request.context.actor),
                "capability": self._ref_value(request.context.capability),
                "trusted_context_id": str(request.context.trusted_context_id),
                "scope_id": str(request.context.scope_id),
            },
            "operation_id": str(request.operation_id), "idempotency_key": str(request.idempotency_key),
            "operation": request.operation.value, "expected_source": request.expected_source.hex,
            "expected_authority_revision": request.expected_authority_revision,
            "workspace_id": None if request.workspace_id is None else str(request.workspace_id),
            "base_ref": None if request.base_ref is None else str(request.base_ref),
            "source_commit": None if request.source_commit is None else str(request.source_commit),
            "destination_ref": None if request.destination_ref is None else str(request.destination_ref),
            "expected_destination": None if request.expected_destination is None else str(request.expected_destination),
        }

    def _operation_journal(self, request: GitEffectRequest, state: str,
                           observation: GitEffectObservation | None = None,
                           receipt: ProviderReceipt | None = None) -> dict[str, object]:
        return {
            "format": "todo-orchestrator.git-provider-operation", "schema_version": 1,
            "operation_id": str(request.operation_id), "request_digest": provider_request_digest(request).hex,
            "request": self._request_value(request), "state": state,
            "observation": None if observation is None else self._observation_value(observation),
            "receipt": None if receipt is None else self._receipt_value(receipt),
            "updated_at": self._now().isoformat(timespec="microseconds"),
        }

    @staticmethod
    def _observation_value(observation: GitEffectObservation) -> dict[str, object]:
        return {
            "operation_id": str(observation.operation_id), "disposition": observation.disposition.value,
            "resulting_source": None if observation.resulting_source is None else observation.resulting_source.hex,
            "conflict_refs": [str(item) for item in observation.conflict_refs],
            "external_ref": None if observation.external_ref is None else str(observation.external_ref),
        }

    @staticmethod
    def _receipt_value(receipt: ProviderReceipt) -> dict[str, object]:
        return {
            "receipt_id": str(receipt.receipt_id),
            "provider": {"provider_id": str(receipt.provider.provider_id), "version": receipt.provider.version,
                         "contract_version": receipt.provider.contract_version},
            "correlation_id": str(receipt.correlation_id), "request_digest": receipt.request_digest.hex,
            "provenance_ref": str(receipt.provenance_ref),
            "observed_at": receipt.observed_at.isoformat(timespec="microseconds"),
        }

    def _result(self, request: GitEffectRequest, observation: GitEffectObservation,
                receipt: ProviderReceipt) -> ProviderResult[GitEffectObservation]:
        return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.operation_id,
                              self.identity, observation, receipt)

    def _record_result(self, request: GitEffectRequest, observation: GitEffectObservation) -> ProviderResult[GitEffectObservation]:
        digest = provider_request_digest(request)
        receipt = self._receipt(request_digest=digest, correlation_id=request.operation_id,
                                provenance_ref=self._provenance(request), suffix=observation.disposition.value)
        self._write_json(self._operation_record_path(request.operation_id),
                         self._operation_journal(request, observation.disposition.value, observation, receipt))
        return self._result(request, observation, receipt)

    def _provenance(self, request: GitEffectRequest) -> StableId:
        return request.source_commit or request.base_ref or request.workspace_id or self.config.integration_ref

    def perform(self, request: GitEffectRequest) -> ProviderResult[GitEffectObservation]:
        if not isinstance(request, GitEffectRequest):
            raise TypeError("request must be a GitEffectRequest")
        if request.context.project_id != self.config.project_id:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.operation_id,
                                  reason_code=StableId("git_project_mismatch"))
        try:
            with self._locked():
                path = self._operation_record_path(request.operation_id)
                prior = self._read_json(path)
                digest = provider_request_digest(request).hex
                if prior is not None:
                    if prior.get("request_digest") != digest or prior.get("request") != self._request_value(request):
                        return ProviderResult(ProviderStatus.UNAVAILABLE, request.operation_id,
                                              reason_code=StableId("git_operation_identity_conflict"))
                    inspected = self._inspect_locked(request)
                    if inspected is not None:
                        return inspected
                    return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.identity,
                                          reason_code=StableId("git_effect_recovery_required"))
                self._write_json(path, self._operation_journal(request, "executing"), exclusive=True)
                if self.failure_hook is not None:
                    self.failure_hook("before_effect", request)
                observation = self._perform_once(request)
                if self.failure_hook is not None:
                    self.failure_hook("after_effect", request)
                if self.failure_hook is not None:
                    self.failure_hook("before_receipt", request)
                return self._record_result(request, observation)
        except Exception as exc:
            if isinstance(exc, GitProviderError):
                reason = "git_effect_failed"
            else:
                reason = "git_effect_interrupted"
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.operation_id,
                                  reason_code=StableId(reason))

    def retry_not_applied(self, request: GitEffectRequest) -> ProviderResult[GitEffectObservation]:
        """Explicitly retry one operation only after inspection proves no effect."""
        if not isinstance(request, GitEffectRequest):
            raise TypeError("request must be a GitEffectRequest")
        try:
            with self._locked():
                path = self._operation_record_path(request.operation_id)
                prior = self._read_json(path)
                if (prior is None or prior.get("request_digest") != provider_request_digest(request).hex
                        or prior.get("request") != self._request_value(request)):
                    raise GitProviderError("explicit retry does not match a durable provider intent")
                inspection = self._inspect_request_locked(request)
                if inspection is None or inspection.disposition is not GitEffectDisposition.NOT_APPLIED:
                    raise GitProviderError("explicit retry requires a definitive NOT_APPLIED observation")
                self._write_json(path, self._operation_journal(request, "executing"))
                if self.failure_hook is not None:
                    self.failure_hook("before_effect", request)
                observation = self._perform_once(request)
                if self.failure_hook is not None:
                    self.failure_hook("after_effect", request)
                if self.failure_hook is not None:
                    self.failure_hook("before_receipt", request)
                return self._record_result(request, observation)
        except Exception:
            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.identity,
                                  reason_code=StableId("git_retry_unconfirmed"))

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[GitEffectObservation]:
        if not isinstance(request, EffectInspectionRequest):
            raise TypeError("request must be an EffectInspectionRequest")
        original = request.git_effect_request
        if original is None:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("git_inspection_request_missing"))
        try:
            with self._locked():
                if (original.operation_id != request.operation_id
                        or original.idempotency_key != request.idempotency_key
                        or provider_request_digest(original) != request.original_request_digest):
                    raise GitProviderError("inspection request differs from original Git operation")
                result = self._inspect_locked(original)
                if result is None:
                    return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.identity,
                                          reason_code=StableId("git_effect_state_unknown"))
                return result
        except Exception:
            return ProviderResult(ProviderStatus.UNAVAILABLE, request.correlation_id,
                                  reason_code=StableId("git_inspection_unavailable"))

    def _inspect_locked(self, request: GitEffectRequest) -> ProviderResult[GitEffectObservation] | None:
        path = self._operation_record_path(request.operation_id)
        record = self._read_json(path)
        if record is not None and record.get("request_digest") != provider_request_digest(request).hex:
            raise GitProviderError("provider journal operation digest differs from the original request")
        observation = self._inspect_request_locked(request)
        if observation is None:
            return None
        if record is not None and record.get("observation") == self._observation_value(observation):
            receipt_value = record.get("receipt")
            if isinstance(receipt_value, dict):
                receipt = self._receipt_from_value(receipt_value)
                return self._result(request, observation, receipt)
        return self._record_result(request, observation)

    def _inspect_request_locked(self, request: GitEffectRequest) -> GitEffectObservation | None:
        if request.operation is GitOperationKind.CREATE_WORKSPACE:
            if request.workspace_id is None or request.base_ref is None:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
            workspace_path = self._workspace_path(request.workspace_id)
            branch = self._workspace_branch(request.workspace_id)
            branch_head = self._git(["rev-parse", "--verify", f"{branch.value}^{{commit}}"], check=False).strip()
            if not workspace_path.exists() and not branch_head:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.NOT_APPLIED)
            metadata = self._workspace_record(request.workspace_id)
            if metadata is None or not workspace_path.exists() or not branch_head:
                return None
            try:
                base_oid = str(metadata["base_commit"])
                actual_base = self._resolve_ref(request.base_ref)
                head = self._resolve_ref(branch)
                common, _head, _index = self._assert_worktree(workspace_path)
                if (actual_base != base_oid or common != self._assert_repository()
                        or metadata.get("operation_id") != str(request.operation_id)):
                    return None
                if not self._is_ancestor(base_oid, head):
                    return None
                result = self._tree_digest(head)
                if result != request.expected_source:
                    return None
                return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                            result, (), branch)
            except Exception:
                return None
        if request.operation is GitOperationKind.INTEGRATE:
            if (request.workspace_id is None or request.source_commit is None
                    or request.destination_ref is None or request.expected_destination is None):
                return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
            if request.destination_ref != self.config.integration_ref:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
            current = self._git(["rev-parse", "--verify", f"{request.destination_ref.value}^{{commit}}"], check=False).strip()
            if not current:
                return None
            current_oid = os.fsdecode(current)
            expected_old = str(request.expected_destination)
            source_oid = str(request.source_commit)
            if current_oid == expected_old:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.NOT_APPLIED)
            try:
                parent_output = os.fsdecode(self._git(["show", "-s", "--format=%P", current_oid]).strip()).split()
                if parent_output == [expected_old, source_oid]:
                    merged_digest = self._tree_digest(current_oid)
                    return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                                merged_digest, (), StableId(current_oid))
                return None
            except Exception:
                return None
        return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)

    def _perform_once(self, request: GitEffectRequest) -> GitEffectObservation:
        if request.operation is GitOperationKind.CREATE_WORKSPACE:
            return self._create_workspace(request)
        if request.operation is GitOperationKind.INTEGRATE:
            return self._integrate(request)
        return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)

    def _create_workspace(self, request: GitEffectRequest) -> GitEffectObservation:
        if request.workspace_id is None or request.base_ref is None:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        base_oid = self._resolve_ref(request.base_ref)
        base_digest = self._tree_digest(base_oid)
        if base_digest != request.expected_source:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        self._resolve_ref(self.config.integration_ref)
        workspace_id = request.workspace_id
        destination = self._workspace_path(workspace_id)
        branch = self._workspace_branch(workspace_id)
        branch_head = self._git(["rev-parse", "--verify", f"{branch.value}^{{commit}}"], check=False).strip()
        if destination.exists() or branch_head:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        record = {
            "format": "todo-orchestrator.git-workspace", "schema_version": 1,
            "workspace_id": str(workspace_id), "repository_id": str(self.config.repository_id),
            "operation_id": str(request.operation_id), "base_ref": str(request.base_ref),
            "base_commit": base_oid, "base_digest": base_digest.hex,
            "branch_ref": str(branch), "destination_ref": str(self.config.integration_ref),
            "workspace_path": str(destination),
        }
        self._write_json(self._workspace_record_path(workspace_id), record, exclusive=True)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._git(["worktree", "add", "--branch", branch.value.removeprefix("refs/heads/"),
                   str(destination), base_oid])
        self._assert_worktree(destination)
        return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                    base_digest, (), branch)

    def _integrate(self, request: GitEffectRequest) -> GitEffectObservation:
        if (request.workspace_id is None or request.source_commit is None or request.destination_ref is None
                or request.expected_destination is None):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        if request.destination_ref != self.config.integration_ref:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        source_oid = str(request.source_commit)
        source_tree_digest = self._tree_digest(source_oid)
        if source_tree_digest != request.expected_source:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        workspace = self._workspace_record(request.workspace_id)
        if workspace is None:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        workspace_path = self._workspace_path(request.workspace_id)
        common, head, _index = self._assert_worktree(workspace_path)
        if common != self._assert_repository() or head != self._resolve_ref(StableId(workspace["branch_ref"])):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        if head != source_oid:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        _source_entries, source_safety = self._path_state(workspace_path, head)
        if source_safety is not SourceSafety.CLEAN:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.DIRTY)
        base_oid = str(workspace["base_commit"])
        if not self._is_ancestor(base_oid, source_oid):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        destination_ref = request.destination_ref.value
        current = self._resolve_ref(request.destination_ref)
        expected_old = str(request.expected_destination)
        if current != expected_old:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        _destination_entries, destination_safety = self._path_state(self.config.repository_root, current)
        if destination_safety is not SourceSafety.CLEAN:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.DIRTY)
        if source_oid == current or self._is_ancestor(source_oid, current):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        command = ["git", "--no-replace-objects", "-C", str(self.config.repository_root),
                   "merge-tree", "--write-tree", "--name-only", "-z", current, source_oid]
        try:
            merged = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=self._environment(),
                                    timeout=self.config.command_timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        if merged.returncode != 0:
            conflict_paths = _merge_conflict_paths(merged.stdout)
            return GitEffectObservation(request.operation_id, GitEffectDisposition.CONFLICT,
                                        None, conflict_paths)
        lines = merged.stdout.split(b"\0")
        if not lines or not lines[0]:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        tree_oid = os.fsdecode(lines[0]).strip()
        if not tree_oid or any(char not in "0123456789abcdef" for char in tree_oid):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        commit_env = self._environment()
        now = self._now().strftime("%Y-%m-%dT%H:%M:%S%z")
        commit_env.update({
            "GIT_AUTHOR_NAME": "Todo Orchestrator", "GIT_AUTHOR_EMAIL": "todo-orchestrator@localhost",
            "GIT_COMMITTER_NAME": "Todo Orchestrator", "GIT_COMMITTER_EMAIL": "todo-orchestrator@localhost",
            "GIT_AUTHOR_DATE": now, "GIT_COMMITTER_DATE": now,
        })
        commit = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(self.config.repository_root), "commit-tree",
             tree_oid, "-p", current, "-p", source_oid, "-m", f"Integrate {request.workspace_id}"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=commit_env, timeout=self.config.command_timeout_seconds, check=False,
        )
        if commit.returncode != 0:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        new_oid = os.fsdecode(commit.stdout).strip()
        # Use update-ref's expected-old parameter for an atomic compare-and-set.
        command = ["git", "--no-replace-objects", "-C", str(self.config.repository_root),
                   "update-ref", destination_ref, new_oid, expected_old]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self._environment(),
                                timeout=self.config.command_timeout_seconds, check=False)
        if result.returncode != 0:
            now_head = self._git(["rev-parse", "--verify", f"{destination_ref}^{{commit}}"], check=False).strip()
            if now_head and os.fsdecode(now_head) == expected_old:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        merged_digest = self._tree_digest(new_oid)
        return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                    merged_digest, (), StableId(new_oid))

    def _receipt_from_value(self, value: Mapping[str, object]) -> ProviderReceipt:
        provider = value["provider"]
        assert isinstance(provider, dict)
        return ProviderReceipt(
            StableId(value["receipt_id"]),
            ProviderIdentity(StableId(provider["provider_id"]), provider["version"], provider["contract_version"]),
            StableId(value["correlation_id"]), Sha256Digest(value["request_digest"]),
            StableId(value["provenance_ref"]), datetime.fromisoformat(value["observed_at"]),
        )


def _merge_conflict_paths(output: bytes) -> tuple[StableId, ...]:
    # `merge-tree --name-only -z` starts with the result tree and then emits
    # conflict-path fields. Path bytes are hashed to avoid leaking source names
    # through durable receipts while preserving attribution and uniqueness.
    values = [item for item in output.split(b"\0") if item]
    if values:
        values = values[1:]
    result: list[StableId] = []
    for item in values:
        candidate = item.split(b"\t")[-1]
        result.append(StableId("conflict-" + hashlib.sha256(candidate).hexdigest()))
    return tuple(sorted(set(result), key=str))


__all__ = ["GitProviderError", "GitRepositoryConfig", "GitRepositoryProvider"]
