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
from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
from typing import BinaryIO, Protocol

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
    excluded_paths: tuple[str, ...] = ()
    provider_id: StableId = StableId("todo.git.local")
    version: str = "git-cli-3"
    command_timeout_seconds: float = 30.0
    gitlink_policy: str = "reject"

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
        if self.gitlink_policy not in {"reject", "opaque_clean"}:
            raise ValueError("gitlink_policy must be 'reject' or 'opaque_clean'")
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


_GIT_OBJECT_BATCH_SIZE = 32
_GIT_OBJECT_READ_CHUNK = 1024 * 1024
_GIT_OBJECT_HEADER_LIMIT = 4096


class _BatchObjectReader:
    """Read cat-file batch records incrementally under one bounded process."""

    def __init__(self, stream: BinaryIO, *, command: tuple[str, ...], timeout: float) -> None:
        self.stream = stream
        self.command = command
        self.timeout = timeout
        self.buffer = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(stream, selectors.EVENT_READ)

    def close(self) -> None:
        self.selector.close()

    def _read_from_pipe(self, size: int, deadline: float) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(self.command, self.timeout)
        ready = self.selector.select(remaining)
        if not ready:
            raise subprocess.TimeoutExpired(self.command, self.timeout)
        chunk = os.read(self.stream.fileno(), min(size, 64 * 1024))
        if not chunk:
            raise EOFError("Git cat-file batch ended before its response was complete")
        return chunk

    def line(self, deadline: float) -> bytes:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                if newline + 1 > _GIT_OBJECT_HEADER_LIMIT:
                    raise ValueError("Git cat-file batch header is too long")
                value = bytes(self.buffer[:newline + 1])
                del self.buffer[:newline + 1]
                return value
            if len(self.buffer) >= _GIT_OBJECT_HEADER_LIMIT:
                raise ValueError("Git cat-file batch header is too long")
            self.buffer.extend(self._read_from_pipe(
                min(8192, _GIT_OBJECT_HEADER_LIMIT - len(self.buffer)), deadline,
            ))

    def exact(self, size: int, deadline: float, consume: Callable[[bytes], None]) -> None:
        remaining = size
        while remaining:
            if self.buffer:
                count = min(remaining, len(self.buffer), _GIT_OBJECT_READ_CHUNK)
                chunk = bytes(self.buffer[:count])
                del self.buffer[:count]
            else:
                chunk = self._read_from_pipe(min(remaining, _GIT_OBJECT_READ_CHUNK), deadline)
            consume(chunk)
            remaining -= len(chunk)

    def exact_bytes(self, size: int, deadline: float) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            if self.buffer:
                count = min(remaining, len(self.buffer), _GIT_OBJECT_READ_CHUNK)
                chunk = bytes(self.buffer[:count])
                del self.buffer[:count]
            else:
                chunk = self._read_from_pipe(min(remaining, _GIT_OBJECT_READ_CHUNK), deadline)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def has_extra_after_eof(self, deadline: float) -> bool:
        if self.buffer:
            return True
        try:
            self.buffer.extend(self._read_from_pipe(1, deadline))
        except EOFError:
            return False
        return bool(self.buffer)


@dataclass(frozen=True)
class _ManifestEntry:
    path: bytes
    mode: str
    digest: str
    coverage: str | None = field(default=None, compare=False)


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

    def _zero_oid(self) -> str:
        object_format = os.fsdecode(self._git(["rev-parse", "--show-object-format"]).strip())
        if object_format == "sha1":
            return "0" * 40
        if object_format == "sha256":
            return "0" * 64
        raise GitProviderError(f"unsupported Git object format: {object_format}")

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

    @staticmethod
    def _conflict_tree_ref(operation_id: StableId) -> str:
        return f"refs/todo-orchestrator/conflict-trees/{hashlib.sha256(str(operation_id).encode()).hexdigest()}"

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

    def _blob_digests(self, object_ids: list[str], *, cwd: Path | None = None) -> tuple[str, ...]:
        """Hash blob contents through bounded, sequential cat-file batches.

        Requests and responses are interleaved on one pipe, so neither side can
        fill the other's pipe while a caller waits. Blob bytes stream directly
        into SHA-256; memory use is independent of object size and batch output.
        """
        if not object_ids:
            return ()
        for object_id in object_ids:
            if (not isinstance(object_id, str) or len(object_id) not in {40, 64}
                    or any(char not in "0123456789abcdef" for char in object_id)):
                raise GitProviderError("Git returned an invalid object ID")

        results: list[str] = []
        directory = cwd or self.config.repository_root
        command = ("cat-file", "--batch")
        argv = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                "-C", str(directory), *command]
        timeout = self.config.command_timeout_seconds
        for offset in range(0, len(object_ids), _GIT_OBJECT_BATCH_SIZE):
            batch = object_ids[offset:offset + _GIT_OBJECT_BATCH_SIZE]
            try:
                with tempfile.TemporaryFile(mode="w+b") as error_output:
                    process = subprocess.Popen(
                        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=error_output, env=self._environment(), bufsize=0,
                    )
                    assert process.stdin is not None and process.stdout is not None
                    reader = _BatchObjectReader(process.stdout, command=command, timeout=timeout)
                    try:
                        for object_id in batch:
                            deadline = time.monotonic() + timeout
                            request = memoryview(object_id.encode("ascii") + b"\n")
                            while request:
                                written = process.stdin.write(request)
                                if not written:
                                    raise BrokenPipeError("Git cat-file batch closed its input")
                                request = request[written:]
                            header = reader.line(deadline)
                            fields = header[:-1].split(b" ")
                            if len(fields) != 3:
                                raise GitProviderError("Git returned an invalid cat-file batch header")
                            try:
                                returned_oid = fields[0].decode("ascii")
                                object_type = fields[1]
                                object_size = int(fields[2], 10)
                            except (UnicodeError, ValueError) as exc:
                                raise GitProviderError("Git returned an invalid cat-file batch header") from exc
                            if (returned_oid != object_id or object_type != b"blob"
                                    or object_size < 0 or fields[2] != str(object_size).encode("ascii")):
                                raise GitProviderError("Git cat-file batch returned the wrong object")
                            content_digest = hashlib.sha256()
                            object_digest = hashlib.new("sha1" if len(object_id) == 40 else "sha256")
                            object_digest.update(f"blob {object_size}\0".encode("ascii"))

                            def update_digests(chunk: bytes) -> None:
                                content_digest.update(chunk)
                                object_digest.update(chunk)

                            reader.exact(object_size, deadline, update_digests)
                            if reader.exact_bytes(1, deadline) != b"\n":
                                raise GitProviderError("Git cat-file batch record is truncated or malformed")
                            if object_digest.hexdigest() != object_id:
                                raise GitProviderError("Git blob bytes do not match the requested object ID")
                            results.append(content_digest.hexdigest())
                        process.stdin.close()
                        process.stdin = None
                        deadline = time.monotonic() + timeout
                        if reader.has_extra_after_eof(deadline):
                            raise GitProviderError("Git returned extra cat-file batch data")
                        try:
                            return_code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                        except subprocess.TimeoutExpired as exc:
                            try:
                                process.kill()
                            except ProcessLookupError:
                                pass
                            raise GitProviderError("Git cat-file batch exceeded its command timeout") from exc
                        if return_code != 0:
                            error_output.seek(0)
                            detail = error_output.read(64 * 1024).decode("utf-8", errors="replace")
                            raise GitCommandError(command, return_code, detail)
                    finally:
                        if process.poll() is None:
                            try:
                                process.kill()
                            except ProcessLookupError:
                                pass
                            process.wait()
                        if process.stdin is not None:
                            process.stdin.close()
                        process.stdout.close()
                        reader.close()
            except GitProviderError:
                raise
            except (OSError, EOFError, ValueError, BrokenPipeError, subprocess.TimeoutExpired) as exc:
                raise GitProviderError("could not read exact Git blob data from a bounded batch") from exc
        return tuple(results)

    def _commit_manifest(self, commit: str, *, cwd: Path | None = None,
                         excluded_paths: tuple[str, ...] | None = None) -> tuple[_ManifestEntry, ...]:
        output = self._git(["ls-tree", "-r", "-z", "--full-tree", commit], cwd=cwd)
        result: list[_ManifestEntry] = []
        blob_entries: list[tuple[bytes, str, str]] = []
        excluded = self.config.excluded_paths if excluded_paths is None else excluded_paths
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
                if mode != "160000" or self.config.gitlink_policy != "opaque_clean":
                    raise GitProviderError("Git submodules require an explicitly trusted committed-pointer policy")
                result.append(self._gitlink_entry(name, oid, "committed-pointer"))
                continue
            if object_type != "blob":
                raise GitProviderError("unsupported Git tree entry type")
            blob_entries.append((name, mode, oid))
        blob_digests = self._blob_digests([oid for _, _, oid in blob_entries], cwd=cwd)
        result.extend(
            _ManifestEntry(name, mode, digest)
            for (name, mode, _), digest in zip(blob_entries, blob_digests, strict=True)
        )
        return tuple(sorted(result, key=lambda entry: entry.path))

    @staticmethod
    def _gitlink_entry(path: bytes, oid: str, coverage: str) -> _ManifestEntry:
        if len(oid) not in {40, 64} or any(char not in "0123456789abcdef" for char in oid):
            raise GitProviderError("Git returned an invalid gitlink object ID")
        digest = hashlib.sha256(b"todo-orchestrator-gitlink-pointer-v1\0" + oid.encode("ascii")).hexdigest()
        return _ManifestEntry(path, "160000", digest, coverage)

    def _commit_gitlinks(self, commit: str, *, cwd: Path | None = None,
                         excluded_paths: tuple[str, ...] | None = None) -> dict[bytes, str]:
        output = self._git(["ls-tree", "-r", "-z", "--full-tree", commit], cwd=cwd)
        excluded = self.config.excluded_paths if excluded_paths is None else excluded_paths
        gitlinks: dict[bytes, str] = {}
        for item in output.split(b"\0"):
            if not item:
                continue
            try:
                metadata, name = item.split(b"\t", 1)
                mode, object_type, oid = metadata.decode("ascii").split(" ")
            except (ValueError, UnicodeError) as exc:
                raise GitProviderError("Git returned an invalid tree entry") from exc
            if mode == "160000" or object_type == "commit":
                if mode != "160000" or object_type != "commit":
                    raise GitProviderError("Git returned an invalid gitlink entry")
                if self._excluded(PurePosixPath(os.fsdecode(name)).as_posix(), excluded):
                    continue
                gitlinks[name] = oid
        return gitlinks

    def _observe_gitlink_path(self, root: Path, relative: bytes, oid: str) -> str:
        """Validate one committed gitlink without fetching or initializing it."""
        path = root / Path(os.fsdecode(relative))
        current = root
        for part in Path(os.fsdecode(relative)).parts[:-1]:
            current = current / part
            try:
                parent_info = current.lstat()
            except FileNotFoundError:
                return "uninitialized-pointer-only"
            except OSError as exc:
                raise GitProviderError(f"cannot inspect gitlink parent {current}: {exc}") from exc
            if not stat.S_ISDIR(parent_info.st_mode):
                raise GitProviderError(f"gitlink path traverses a non-directory parent: {current}")
        try:
            info = path.lstat()
        except FileNotFoundError:
            return "uninitialized-pointer-only"
        except OSError as exc:
            raise GitProviderError(f"cannot inspect gitlink {os.fsdecode(relative)}: {exc}") from exc
        if not path.is_dir() or path.is_symlink():
            raise GitProviderError(f"gitlink path is not a real directory: {os.fsdecode(relative)}")

        gitfile = path / ".git"
        try:
            git_info = gitfile.lstat()
        except FileNotFoundError:
            try:
                with os.scandir(path) as children:
                    has_children = next(children, None) is not None
            except OSError as exc:
                raise GitProviderError(f"cannot inspect uninitialized gitlink {os.fsdecode(relative)}: {exc}") from exc
            if has_children:
                raise GitProviderError(
                    f"uninitialized gitlink contains unverified content: {os.fsdecode(relative)}"
                )
            return "uninitialized-pointer-only"
        except OSError as exc:
            raise GitProviderError(f"cannot inspect gitlink metadata {os.fsdecode(relative)}: {exc}") from exc

        if os.path.islink(gitfile) or not stat.S_ISREG(git_info.st_mode):
            raise GitProviderError(f"gitlink .git metadata is not a regular gitfile: {os.fsdecode(relative)}")
        try:
            lines = gitfile.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise GitProviderError(f"cannot read gitlink gitfile {os.fsdecode(relative)}: {exc}") from exc
        if len(lines) != 1 or not lines[0].startswith("gitdir: ") or not lines[0][8:].strip():
            raise GitProviderError(f"gitlink .git metadata is malformed: {os.fsdecode(relative)}")
        raw_gitdir = Path(lines[0][8:].strip())
        declared_gitdir = raw_gitdir if raw_gitdir.is_absolute() else path / raw_gitdir
        try:
            declared_gitdir = declared_gitdir.resolve(strict=True)
            common = self._common_git_dir(root)
            modules_path = common / "modules"
            modules_info = modules_path.lstat()
            if not stat.S_ISDIR(modules_info.st_mode):
                raise GitProviderError("configured Git modules directory is not a real directory")
            trusted_modules = modules_path.resolve(strict=True)
        except (OSError, GitProviderError) as exc:
            raise GitProviderError(f"gitlink Git metadata cannot be resolved: {os.fsdecode(relative)}") from exc
        if declared_gitdir == trusted_modules or trusted_modules not in declared_gitdir.parents:
            raise GitProviderError(f"gitlink gitdir escapes the configured repository: {os.fsdecode(relative)}")
        if not declared_gitdir.is_dir():
            raise GitProviderError(f"gitlink gitdir is not a directory: {os.fsdecode(relative)}")

        top = Path(os.fsdecode(self._git(["rev-parse", "--show-toplevel"], cwd=path).strip())).resolve(strict=True)
        if top != path.resolve(strict=True):
            raise GitProviderError(f"gitlink worktree root does not match its path: {os.fsdecode(relative)}")
        actual_gitdir = self._git_dir(path)
        if actual_gitdir != declared_gitdir:
            raise GitProviderError(f"gitlink Git metadata resolves inconsistently: {os.fsdecode(relative)}")
        superproject = os.fsdecode(self._git(["rev-parse", "--show-superproject-working-tree"], cwd=path).strip())
        if not superproject or Path(superproject).resolve(strict=True) != root.resolve(strict=True):
            raise GitProviderError(f"gitlink is not bound to this superproject: {os.fsdecode(relative)}")
        actual_head = os.fsdecode(self._git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=path).strip())
        if actual_head != oid:
            raise GitProviderError(f"initialized gitlink does not match its committed pointer: {os.fsdecode(relative)}")

        # Nested gitlinks would require another level of trust/coverage policy.
        nested_tree = self._git(["ls-tree", "-r", "-z", "--full-tree", actual_head], cwd=path)
        if any(item.split(b"\t", 1)[0].split(b" ")[1:2] == [b"commit"]
               for item in nested_tree.split(b"\0") if item):
            raise GitProviderError(f"nested gitlinks are not covered by this provider: {os.fsdecode(relative)}")
        nested_baseline = self._commit_manifest(actual_head, cwd=path, excluded_paths=())
        nested_files = self._filesystem_manifest(path, actual_head, excluded_paths=())
        nested_index = self._index_manifest(path, excluded_paths=())
        if nested_files != nested_baseline or nested_index != nested_baseline:
            raise GitProviderError(f"initialized gitlink contains unverified changes: {os.fsdecode(relative)}")
        return "initialized-clean-at-committed-pointer"

    def _filesystem_manifest(self, root: Path, head: str | None = None, *,
                             excluded_paths: tuple[str, ...] | None = None) -> tuple[_ManifestEntry, ...]:
        entries: list[_ManifestEntry] = []
        excluded = self.config.excluded_paths if excluded_paths is None else excluded_paths
        gitlinks = self._commit_gitlinks(head, cwd=root, excluded_paths=excluded) \
            if head is not None and self.config.gitlink_policy == "opaque_clean" else {}
        observed_gitlinks: set[bytes] = set()

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
                gitlink_oid = gitlinks.get(relative)
                if gitlink_oid is not None:
                    coverage = self._observe_gitlink_path(root, relative, gitlink_oid)
                    entries.append(self._gitlink_entry(relative, gitlink_oid, coverage))
                    observed_gitlinks.add(relative)
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
        for relative, oid in gitlinks.items():
            if relative not in observed_gitlinks:
                coverage = self._observe_gitlink_path(root, relative, oid)
                entries.append(self._gitlink_entry(relative, oid, coverage))
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def _index_manifest(self, root: Path, *,
                        excluded_paths: tuple[str, ...] | None = None) -> tuple[_ManifestEntry, ...]:
        """Read the staged tree, including staged blobs absent from the worktree."""
        # Reading the index can otherwise launch a repository-configured
        # fsmonitor hook. Source observation must remain a local byte read.
        output = self._git(["-c", "core.fsmonitor=false", "ls-files", "--stage", "-z"], cwd=root)
        result: list[_ManifestEntry] = []
        blob_entries: list[tuple[bytes, str, str]] = []
        excluded = self.config.excluded_paths if excluded_paths is None else excluded_paths
        for item in output.split(b"\0"):
            if not item:
                continue
            try:
                metadata, name = item.split(b"\t", 1)
                mode, oid, stage = metadata.decode("ascii").split(" ")
            except (ValueError, UnicodeError) as exc:
                raise GitProviderError("Git returned an invalid index entry") from exc
            if not mode or not oid or stage not in {"0", "1", "2", "3"}:
                raise GitProviderError("Git returned an invalid index entry")
            if self._excluded(PurePosixPath(os.fsdecode(name)).as_posix(), excluded):
                continue
            # Stage zero matches the committed-tree format. Preserve conflict
            # stages in the manifest so distinct unmerged indexes stay distinct.
            indexed_mode = mode if stage == "0" else f"{mode}:{stage}"
            if mode == "160000":
                if self.config.gitlink_policy != "opaque_clean":
                    raise GitProviderError("Git submodules require an explicitly trusted committed-pointer policy")
                entry = self._gitlink_entry(name, oid, "index-pointer")
                result.append(_ManifestEntry(name, indexed_mode, entry.digest, entry.coverage))
            else:
                blob_entries.append((name, indexed_mode, oid))
        blob_digests = self._blob_digests([oid for _, _, oid in blob_entries], cwd=root)
        result.extend(
            _ManifestEntry(name, mode, digest)
            for (name, mode, _), digest in zip(blob_entries, blob_digests, strict=True)
        )
        return tuple(sorted(result, key=lambda entry: (entry.path, entry.mode, entry.digest)))

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

    def _source_identity_digest(self, content_digest: Sha256Digest) -> Sha256Digest:
        """Bind selected content to the trusted source-selection policy."""
        digest = hashlib.sha256(b"todo-orchestrator-git-source-identity-v3\0")
        exclusions = tuple(sorted(self.config.excluded_paths))
        digest.update(len(exclusions).to_bytes(8, "big"))
        for exclusion in exclusions:
            encoded = exclusion.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        digest.update(bytes.fromhex(content_digest.hex))
        return Sha256Digest(digest.hexdigest())

    def _source_digest(self, files: tuple[_ManifestEntry, ...],
                       index: tuple[_ManifestEntry, ...]) -> Sha256Digest:
        file_digest = self._manifest_digest(files)
        if files == index:
            # A clean tree and its qualified revision share one policy-bound identity.
            content_digest = file_digest
        else:
            index_digest = self._manifest_digest(index)
            digest = hashlib.sha256(b"todo-orchestrator-git-dirty-source-content-v1\0")
            digest.update(bytes.fromhex(file_digest.hex))
            digest.update(bytes.fromhex(index_digest.hex))
            content_digest = Sha256Digest(digest.hexdigest())
        return self._source_identity_digest(content_digest)

    def _tree_digest(self, commit: str) -> Sha256Digest:
        return self._source_identity_digest(self._manifest_digest(self._commit_manifest(commit)))

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

    def _path_state(self, root: Path, head: str) -> tuple[
        tuple[_ManifestEntry, ...], tuple[_ManifestEntry, ...], SourceSafety,
    ]:
        current = self._filesystem_manifest(root, head)
        index = self._index_manifest(root)
        baseline = self._commit_manifest(head)
        safety = SourceSafety.CLEAN if current == baseline and index == baseline else SourceSafety.DIRTY
        return current, index, safety

    def _assert_worktree(self, path: Path, expected_branch: StableId) -> tuple[Path, str, Path]:
        if not path.is_dir():
            raise GitProviderError("qualified workspace path is missing")
        root = Path(os.fsdecode(self._git(["rev-parse", "--show-toplevel"], cwd=path).strip())).resolve(strict=True)
        if root != path.resolve(strict=True):
            raise GitProviderError("qualified workspace top-level differs from its registered path")
        common = self._common_git_dir(path)
        if common != self._assert_repository():
            raise GitProviderError("workspace is not a linked worktree of the configured repository")
        head_ref = self._git(["symbolic-ref", "--quiet", "HEAD"], cwd=path, check=False).strip()
        if os.fsdecode(head_ref) != str(expected_branch):
            raise GitProviderError("workspace is not checking out its recorded branch ref")
        head = os.fsdecode(self._git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=path).strip())
        git_dir = self._git_dir(path)
        index_path = Path(os.fsdecode(self._git(["rev-parse", "--path-format=absolute", "--git-path", "index"], cwd=path).strip()))
        if not index_path.is_absolute():
            index_path = path / index_path
        index_path = index_path.resolve(strict=True)
        if not index_path.is_file():
            raise GitProviderError("worktree has no independent Git index file")
        return common, head, index_path

    def _checked_out_ref(self, path: Path) -> StableId | None:
        raw = self._git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=path, check=False).strip()
        if not raw:
            return None
        short = os.fsdecode(raw)
        return StableId(short if short.startswith("refs/") else f"refs/heads/{short}")

    def _ref_is_checked_out(self, ref: StableId) -> bool:
        listing = os.fsdecode(self._git(["worktree", "list", "--porcelain"]))
        for line in listing.splitlines():
            if line.startswith("branch ") and line.removeprefix("branch ") == ref.value:
                return True
        return False

    def _isolation(self, workspace_id: StableId, path: Path, branch: StableId) -> WorkspaceIsolation:
        common, _head, index_path = self._assert_worktree(path, branch)
        root_identity = hashlib.sha256(os.fsencode(path.resolve(strict=True))).hexdigest()
        index_identity = hashlib.sha256(os.fsencode(index_path)).hexdigest()
        common_identity = hashlib.sha256(os.fsencode(common)).hexdigest()
        record = self._workspace_record(workspace_id)
        admin_dir = self._git_dir(path)
        marker_path = admin_dir / "todo-orchestrator-worktree-token"
        try:
            marker = marker_path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise GitProviderError("managed worktree incarnation marker is unavailable") from exc
        if (record is None or not isinstance(record.get("worktree_nonce"), str)
                or marker != record["worktree_nonce"]):
            raise GitProviderError("managed worktree incarnation differs from its creation record")
        admin_identity = hashlib.sha256(marker.encode("ascii")).hexdigest()
        return WorkspaceIsolation(
            Sha256Digest(common_identity), Sha256Digest(root_identity), Sha256Digest(index_identity), branch,
            Sha256Digest(admin_identity),
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
        common, head, index_path = self._assert_worktree(path, branch_ref)
        if verify_ref:
            branch_head = self._resolve_ref(branch_ref)
            if branch_head != head:
                raise GitProviderError("workspace branch and checked-out HEAD have diverged")
        if not self._is_ancestor(base_commit, head):
            raise GitProviderError("workspace HEAD no longer descends from its qualified common base")
        destination = self.config.integration_ref
        if self._ref_is_checked_out(destination):
            raise GitProviderError("configured integration destination is checked out in a Git worktree")
        destination_head = self._resolve_ref(destination)
        isolation = self._isolation(workspace_id, path, branch_ref)
        common_identity = isolation.repository_storage
        base_digest = self._tree_digest(base_commit).hex
        request_material = {
            "workspace_id": str(workspace_id), "target": self._ref_value(target),
            "repository_id": str(self.config.repository_id), "base_ref": str(base_ref),
            "base_commit": base_commit, "base_digest": base_digest,
            "destination_ref": str(destination), "destination_head": destination_head,
            "workspace_head": head, "isolation": {
                "repository_storage": common_identity.hex,
                "workspace_root": isolation.workspace_root.hex, "index_file": isolation.index_file.hex,
                "head_ref": str(branch_ref),
                "worktree_admin": None if isolation.worktree_admin is None else isolation.worktree_admin.hex,
            },
        }
        request_digest = Sha256Digest(hashlib.sha256(self._canonical(request_material).encode("ascii")).hexdigest())
        common_base = QualifiedSourceRevision(
            self.config.project_id, self.config.repository_id, StableId(base_commit), base_digest,
        )
        receipt = self._receipt(request_digest=request_digest, correlation_id=correlation_id,
                                provenance_ref=StableId(base_commit), suffix="workspace")
        return WorkspaceQualification(
            workspace_id, self.config.repository_id,
            common_base,
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
            if request.context.project_id != self.config.project_id:
                raise GitProviderError("source observation belongs to another configured project")
            if request.base_ref is not None:
                # A pre-effect retry preview has no attempt or workspace yet. Observe only
                # the exact configured repository ref and return its immutable commit/tree
                # identity; do not create a worktree or infer an effect disposition.
                if any((request.attempt is not None, request.workspace_id is not None,
                        request.target is not None, request.contract is not None,
                        bool(request.artifacts))):
                    raise GitProviderError("base-ref observation must not include workspace-scoped inputs")
                with self._locked():
                    revision = self.qualified_revision(request.base_ref)
                    if (revision.project_id != self.config.project_id
                            or revision.repository_id != self.config.repository_id):
                        raise GitProviderError("qualified base ref belongs to another repository")
                    digest = Sha256Digest(revision.digest)
                    observation = SourceObservation(
                        self.config.repository_id, digest, digest, WorkingTreeState.CLEAN,
                        source_revision=revision.ref,
                    )
                    receipt = self._receipt(
                        request_digest=provider_request_digest(request),
                        correlation_id=request.correlation_id,
                        provenance_ref=request.base_ref,
                        suffix="source-base",
                    )
                    return ProviderResult(ProviderStatus.OBSERVED_SUCCESS, request.correlation_id,
                                          self.identity, observation, receipt)
            if request.workspace_id is None or request.target is None:
                raise GitProviderError("source observation requires the exact configured project workspace and target")
            with self._locked():
                qualification = self._qualification(request.workspace_id, request.target, request.correlation_id)
                path = self._workspace_path(request.workspace_id)
                _common, head, _index = self._assert_worktree(path, self._workspace_branch(request.workspace_id))
                entries, index_entries, safety = self._path_state(path, head)
                source_digest = self._source_digest(entries, index_entries)
                inputs = tuple(
                    EvidenceInput(
                        StableId(("gitlink-" + (entry.coverage or "pointer") + "-"
                                  if entry.mode.startswith("160000") else "file-")
                                 + hashlib.sha256(entry.path).hexdigest()),
                        Sha256Digest(entry.digest),
                    )
                    for entry in entries
                )
                if entries != index_entries:
                    inputs += tuple(
                        EvidenceInput(
                            StableId("index-" + hashlib.sha256(
                                entry.mode.encode("ascii") + b"\0" + entry.path
                            ).hexdigest()),
                            Sha256Digest(entry.digest),
                        )
                        for entry in index_entries
                    )
                artifacts = tuple(self._artifact_availability(item.artifact_id, item.expected_digest)
                                  for item in request.artifacts)
                observation = SourceObservation(
                    self.config.repository_id, source_digest,
                    Sha256Digest(qualification.common_base.digest),
                    WorkingTreeState.CLEAN if safety is SourceSafety.CLEAN else WorkingTreeState.DIRTY,
                    inputs, artifacts, StableId(head),
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
            if fresh.isolation is None:
                raise GitProviderError("fresh workspace qualification has no Git isolation identity")
            _common, head, _index = self._assert_worktree(path, fresh.isolation.head_ref)
            _entries, _index_entries, safety = self._path_state(path, head)
            source_digest = self._source_digest(_entries, _index_entries)
        except Exception:
            fresh = workspace
            safety = SourceSafety.UNKNOWN
            source_digest = None
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
                "source_digest": None if source_digest is None else source_digest.hex,
                "head": None if safety is SourceSafety.UNKNOWN else head,
            }).encode("ascii")).hexdigest()),
            correlation_id=attempt.ref.entity_id, provenance_ref=fresh.common_base.ref, suffix="attempt-safety",
        )
        lease = attempt.lease
        return AttemptSafetyObservation(
            attempt.ref, attempt.state,
            StableId("missing-lease") if lease is None else lease.lease_id,
            self._now() if lease is None else lease.expires_at,
            fresh, safety, process, children, receipt, source_digest,
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
            "target": None if request.target is None else self._ref_value(request.target),
            "attempt": None if request.attempt is None else self._ref_value(request.attempt),
            "run": None if request.run is None else self._ref_value(request.run),
            "assignment": None if request.assignment is None else self._ref_value(request.assignment),
            "requested_at": None if request.requested_at is None else request.requested_at.isoformat(timespec="microseconds"),
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
            "conflict_tree": None if observation.conflict_tree is None else str(observation.conflict_tree),
        }

    @staticmethod
    def _observation_from_value(value: object) -> GitEffectObservation | None:
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != {
            "operation_id", "disposition", "resulting_source", "conflict_refs", "external_ref", "conflict_tree",
        }:
            raise GitProviderError("provider operation journal observation is malformed")
        refs = value["conflict_refs"]
        if not isinstance(refs, list):
            raise GitProviderError("provider operation journal conflict refs are malformed")
        try:
            return GitEffectObservation(
                StableId(value["operation_id"]), GitEffectDisposition(value["disposition"]),
                None if value["resulting_source"] is None else Sha256Digest(value["resulting_source"]),
                tuple(StableId(item) for item in refs),
                None if value["external_ref"] is None else StableId(value["external_ref"]),
                None if value["conflict_tree"] is None else StableId(value["conflict_tree"]),
            )
        except (TypeError, ValueError) as exc:
            raise GitProviderError("provider operation journal observation is invalid") from exc

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
        path = self._operation_record_path(request.operation_id)
        journal = self._operation_journal(request, observation.disposition.value, observation, receipt)
        prior = self._read_json(path)
        if (observation.disposition is GitEffectDisposition.NOT_APPLIED and prior is not None
                and isinstance(prior.get("pending_commit"), dict)):
            journal["pending_commit"] = prior["pending_commit"]
        if (observation.disposition is GitEffectDisposition.CONFLICT and prior is not None
                and isinstance(prior.get("pending_conflict_tree"), dict)):
            journal["pending_conflict_tree"] = prior["pending_conflict_tree"]
        self._write_json(path, journal)
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
                    # A repeated perform may inspect an existing journal to
                    # prevent duplicate effects, but it must not invent a
                    # receipt for an execution whose original receipt was not
                    # durably written. Use the explicit query API to record a
                    # new, query-bound inspection receipt.
                    observation = self._inspect_request_locked(request)
                    if observation is not None:
                        recorded_observation = prior.get("observation")
                        if (recorded_observation is not None
                                and recorded_observation != self._observation_value(observation)):
                            return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.identity,
                                                  reason_code=StableId("git_effect_recovery_required"))
                        receipt_value = prior.get("receipt")
                        if isinstance(receipt_value, dict):
                            return self._result(request, observation, self._receipt_from_value(receipt_value))
                        # The effect is observable, but the process lost the
                        # original receipt before journaling it. Require the
                        # explicit inspect API, whose receipt binds the query.
                        return ProviderResult(ProviderStatus.UNKNOWN, request.operation_id, self.identity,
                                              reason_code=StableId("git_effect_recovery_required"))
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
                retry_record = self._operation_journal(request, "executing")
                if "pending_commit" in prior:
                    retry_record["pending_commit"] = prior["pending_commit"]
                self._write_json(path, retry_record)
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
                journal = self._read_json(self._operation_record_path(original.operation_id))
                observation = self._inspect_request_locked(original)
                original_receipt = None
                if (journal is not None
                        and journal.get("request_digest") == provider_request_digest(original).hex
                        and journal.get("request") == self._request_value(original)
                        and journal.get("observation") is not None
                        and journal.get("receipt") is not None):
                    recorded_observation = self._observation_from_value(journal["observation"])
                    if observation is not None and observation != recorded_observation:
                        return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.identity,
                                              reason_code=StableId("git_effect_state_changed"))
                    receipt_value = journal["receipt"]
                    if not isinstance(receipt_value, dict):
                        raise GitProviderError("provider operation journal receipt is malformed")
                    original_receipt = self._receipt_from_value(receipt_value)
                    if (original_receipt.provider != self.identity
                            or original_receipt.request_digest != provider_request_digest(original)
                            or original_receipt.correlation_id != original.operation_id
                            or original_receipt.provenance_ref != self._provenance(original)):
                        raise GitProviderError("provider operation journal receipt has the wrong identity")
                if observation is None:
                    return ProviderResult(ProviderStatus.UNKNOWN, request.correlation_id, self.identity,
                                          reason_code=StableId("git_effect_state_unknown"))
                status = (ProviderStatus.OBSERVED_SUCCESS
                          if observation.disposition in {GitEffectDisposition.APPLIED, GitEffectDisposition.CONFLICT,
                                                         GitEffectDisposition.NOT_APPLIED}
                          else ProviderStatus.OBSERVED_FAILURE)
                receipt = self._receipt(
                    request_digest=provider_request_digest(request),
                    correlation_id=request.correlation_id,
                    provenance_ref=self._provenance(original),
                    suffix=f"inspection-{request.correlation_id}",
                )
                if original_receipt is not None:
                    observation = GitEffectObservation(
                        observation.operation_id, observation.disposition, observation.resulting_source,
                        observation.conflict_refs, observation.external_ref, observation.conflict_tree,
                        original_receipt,
                    )
                return ProviderResult(status, request.correlation_id, self.identity, observation, receipt)
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
                common, _head, _index = self._assert_worktree(workspace_path, branch)
                marker = (self._git_dir(workspace_path) / "todo-orchestrator-worktree-token").read_text(
                    encoding="ascii",
                )
                if (actual_base != base_oid or common != self._assert_repository()
                        or metadata.get("operation_id") != str(request.operation_id)
                        or metadata.get("workspace_id") != str(request.workspace_id)
                        or metadata.get("base_ref") != str(request.base_ref)
                        or (request.source_commit is not None and metadata.get("base_commit") != str(request.source_commit))
                        or metadata.get("base_digest") != request.expected_source.hex
                        or not isinstance(metadata.get("worktree_nonce"), str)
                        or marker != metadata["worktree_nonce"]):
                    return None
                if not self._is_ancestor(base_oid, head):
                    return None
                base_digest = self._tree_digest(base_oid)
                if base_digest != request.expected_source:
                    return None
                return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                            base_digest, (), branch)
            except Exception:
                return None
        if request.operation is GitOperationKind.INTEGRATE:
            if (request.workspace_id is None or request.source_commit is None
                    or request.destination_ref is None or request.expected_destination is None):
                return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
            if request.destination_ref != self.config.integration_ref:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
            record = self._read_json(self._operation_record_path(request.operation_id))
            pending_conflict = None if record is None else record.get("pending_conflict_tree")
            if isinstance(pending_conflict, dict):
                try:
                    tree_oid = pending_conflict["tree"]
                    expected_old = str(request.expected_destination)
                    source_oid = str(request.source_commit)
                    conflicts = tuple(StableId(value) for value in pending_conflict["conflict_refs"])
                    pin = self._git(["rev-parse", "--verify", self._conflict_tree_ref(request.operation_id)], check=False).strip()
                    object_type = os.fsdecode(self._git(["cat-file", "-t", str(tree_oid)], check=False).strip())
                    if (pending_conflict.get("expected_old") == expected_old
                            and pending_conflict.get("source_commit") == source_oid
                            and pin and os.fsdecode(pin) == tree_oid and object_type == "tree"):
                        return GitEffectObservation(
                            request.operation_id, GitEffectDisposition.CONFLICT, None, conflicts,
                            StableId(self._conflict_tree_ref(request.operation_id)), StableId(tree_oid),
                        )
                except (KeyError, TypeError, ValueError):
                    return None
            current = self._git(["rev-parse", "--verify", f"{request.destination_ref.value}^{{commit}}"], check=False).strip()
            if not current:
                return None
            current_oid = os.fsdecode(current)
            expected_old = str(request.expected_destination)
            source_oid = str(request.source_commit)
            if current_oid == expected_old:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.NOT_APPLIED)
            pending_commit = None if record is None else record.get("pending_commit")
            if not isinstance(pending_commit, dict) or set(pending_commit) != {
                "commit", "expected_old", "source_commit", "tree",
            }:
                # Parent pairs alone do not prove this operation created the
                # destination commit: another operation can request the same
                # merge inputs. Without this operation's durable object ID,
                # keep the result unknown.
                return None
            commit_oid = pending_commit.get("commit")
            tree_oid = pending_commit.get("tree")
            if (pending_commit.get("expected_old") != expected_old
                    or pending_commit.get("source_commit") != source_oid
                    or not isinstance(commit_oid, str) or not isinstance(tree_oid, str)):
                return None
            try:
                commit_output = os.fsdecode(
                    self._git(["show", "-s", "--format=%T %P", commit_oid], check=False).strip(),
                ).split()
                commit_exists = len(commit_output) == 3 and commit_output == [tree_oid, expected_old, source_oid]
                if not commit_exists:
                    return None
                if current_oid == commit_oid or self._is_ancestor(commit_oid, current_oid):
                    merged_digest = self._tree_digest(commit_oid)
                    return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                                merged_digest, (), StableId(commit_oid))
                # The destination advanced elsewhere while this exact prepared
                # commit remains unpublished. A retry may safely reuse its
                # immutable ID only if the CAS destination remains unchanged.
                if current_oid == expected_old:
                    return GitEffectObservation(request.operation_id, GitEffectDisposition.NOT_APPLIED)
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
        if (base_digest != request.expected_source
                or (request.source_commit is not None and str(request.source_commit) != base_oid)):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        self._resolve_ref(self.config.integration_ref)
        workspace_id = request.workspace_id
        destination = self._workspace_path(workspace_id)
        branch = self._workspace_branch(workspace_id)
        branch_head = self._git(["rev-parse", "--verify", f"{branch.value}^{{commit}}"], check=False).strip()
        if destination.exists() or branch_head:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        record_path = self._workspace_record_path(workspace_id)
        prior = self._workspace_record(workspace_id)
        if prior is not None:
            if (prior.get("operation_id") != str(request.operation_id)
                    or prior.get("base_ref") != str(request.base_ref)
                    or prior.get("base_commit") != base_oid
                    or prior.get("base_digest") != base_digest.hex
                    or prior.get("branch_ref") != str(branch)
                    or prior.get("workspace_path") != str(destination)
                    or prior.get("destination_ref") != str(self.config.integration_ref)
                    or not isinstance(prior.get("worktree_nonce"), str)):
                return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
            record = prior
        else:
            record = {
            "format": "todo-orchestrator.git-workspace", "schema_version": 1,
            "workspace_id": str(workspace_id), "repository_id": str(self.config.repository_id),
            "operation_id": str(request.operation_id), "base_ref": str(request.base_ref),
            "base_commit": base_oid, "base_digest": base_digest.hex,
            "branch_ref": str(branch), "destination_ref": str(self.config.integration_ref),
            "workspace_path": str(destination),
            "worktree_nonce": secrets.token_hex(32),
            }
            self._write_json(record_path, record, exclusive=True)
            if self.failure_hook is not None:
                self.failure_hook("after_workspace_record", request)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._git(["worktree", "add", "-b", branch.value.removeprefix("refs/heads/"),
                   str(destination), base_oid])
        admin_dir = self._git_dir(destination)
        marker_path = admin_dir / "todo-orchestrator-worktree-token"
        descriptor = os.open(marker_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as marker_file:
                marker_file.write(record["worktree_nonce"])
                marker_file.flush()
                os.fsync(marker_file.fileno())
            self._sync_directory(admin_dir)
        except BaseException:
            # Preserve the worktree and record for explicit inspection/recovery;
            # never attempt cleanup after a partially published effect.
            raise
        self._assert_worktree(destination, branch)
        return GitEffectObservation(request.operation_id, GitEffectDisposition.APPLIED,
                                    base_digest, (), branch)

    def _integrate(self, request: GitEffectRequest) -> GitEffectObservation:
        if (request.workspace_id is None or request.source_commit is None or request.destination_ref is None
                or request.expected_destination is None):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        if request.destination_ref != self.config.integration_ref:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        if self._ref_is_checked_out(request.destination_ref):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        source_oid = str(request.source_commit)
        source_tree_digest = self._tree_digest(source_oid)
        if source_tree_digest != request.expected_source:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        workspace = self._workspace_record(request.workspace_id)
        if workspace is None:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        workspace_path = self._workspace_path(request.workspace_id)
        branch_ref = StableId(workspace["branch_ref"])
        common, head, _index = self._assert_worktree(workspace_path, branch_ref)
        if common != self._assert_repository() or head != self._resolve_ref(branch_ref):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        if head != source_oid:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.REJECTED)
        _source_entries, _source_index, source_safety = self._path_state(workspace_path, head)
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
        checked_out_ref = self._checked_out_ref(self.config.repository_root)
        if checked_out_ref is None:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        try:
            _root_common, root_head, _root_index = self._assert_worktree(self.config.repository_root, checked_out_ref)
        except GitProviderError:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        _destination_entries, _destination_index, destination_safety = self._path_state(
            self.config.repository_root, root_head,
        )
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
            output_fields = [item for item in merged.stdout.split(b"\0") if item]
            tree_oid = os.fsdecode(output_fields[0]).strip() if output_fields else ""
            if not tree_oid or any(char not in "0123456789abcdef" for char in tree_oid):
                return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
            journal_path = self._operation_record_path(request.operation_id)
            journal = self._read_json(journal_path)
            if journal is None or journal.get("request_digest") != provider_request_digest(request).hex:
                return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
            pending = {
                "tree": tree_oid, "expected_old": expected_old,
                "source_commit": source_oid, "conflict_refs": [str(item) for item in conflict_paths],
            }
            journal["pending_conflict_tree"] = pending
            self._write_json(journal_path, journal)
            pin_ref = self._conflict_tree_ref(request.operation_id)
            pin_result = subprocess.run(
                ["git", "--no-replace-objects", "-C", str(self.config.repository_root),
                 "update-ref", pin_ref, tree_oid, self._zero_oid()],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._environment(), timeout=self.config.command_timeout_seconds, check=False,
            )
            if pin_result.returncode != 0:
                existing = self._git(["rev-parse", "--verify", pin_ref], check=False).strip()
                if not existing or os.fsdecode(existing) != tree_oid:
                    return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
            return GitEffectObservation(request.operation_id, GitEffectDisposition.CONFLICT,
                                        None, conflict_paths, StableId(pin_ref), StableId(tree_oid))
        lines = merged.stdout.split(b"\0")
        if not lines or not lines[0]:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        tree_oid = os.fsdecode(lines[0]).strip()
        if not tree_oid or any(char not in "0123456789abcdef" for char in tree_oid):
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        journal_path = self._operation_record_path(request.operation_id)
        journal = self._read_json(journal_path)
        if journal is None or journal.get("request_digest") != provider_request_digest(request).hex:
            return GitEffectObservation(request.operation_id, GitEffectDisposition.UNKNOWN)
        pending = journal.get("pending_commit")
        new_oid = None
        if isinstance(pending, dict) and pending == {
            "commit": pending.get("commit"), "expected_old": expected_old,
            "source_commit": source_oid, "tree": tree_oid,
        }:
            pending_oid = pending.get("commit")
            if isinstance(pending_oid, str):
                parents = os.fsdecode(self._git(["show", "-s", "--format=%T %P", pending_oid], check=False).strip()).split()
                if len(parents) == 3 and parents == [tree_oid, expected_old, source_oid]:
                    new_oid = pending_oid
        if new_oid is None:
            commit_env = self._environment()
            commit_time = (request.requested_at or self._now()).strftime("%Y-%m-%dT%H:%M:%S%z")
            commit_env.update({
                "GIT_AUTHOR_NAME": "Todo Orchestrator", "GIT_AUTHOR_EMAIL": "todo-orchestrator@localhost",
                "GIT_COMMITTER_NAME": "Todo Orchestrator", "GIT_COMMITTER_EMAIL": "todo-orchestrator@localhost",
                "GIT_AUTHOR_DATE": commit_time, "GIT_COMMITTER_DATE": commit_time,
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
            # Record the commit object before the CAS. Its deterministic
            # identity is also recoverable from the immutable request timestamp
            # if the process dies in the narrow interval before this journal write.
            journal["pending_commit"] = {
                "commit": new_oid, "expected_old": expected_old, "source_commit": source_oid,
                "tree": tree_oid,
            }
            self._write_json(journal_path, journal)
            if self.failure_hook is not None:
                self.failure_hook("after_commit_object", request)
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
