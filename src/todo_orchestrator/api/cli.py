"""Command-line interface for the standalone Todo application."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from importlib import import_module
from importlib.machinery import PathFinder
from getpass import getpass
import os
from pathlib import Path
import sys
import uuid

from todo_orchestrator import __version__


class _SafeArgumentParser(argparse.ArgumentParser):
    """Keep argparse diagnostics useful without echoing supplied secrets."""

    def error(self, message: str) -> None:
        # argparse includes the rejected token and sometimes its following
        # value in `message` (for example an unknown --password option).
        # Print usage, but never reflect raw argv into terminal or logs.
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid command line\n")


class _TokenOutputUnavailable(RuntimeError):
    """A token destination could not be reserved before a command began."""


class _TokenDeliveryFailure(RuntimeError):
    """A state-changing command completed but its bearer could not be saved."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(operation)


class _ProviderFactoryError(RuntimeError):
    """An explicitly selected provider factory is invalid or untrusted."""


class _TokenReservation:
    """Exclusive mode-0600 output reserved before issuing or claiming a token."""

    def __init__(self, path: Path) -> None:
        destination = path.expanduser()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.descriptor = os.open(destination, flags, 0o600)
        except OSError as exc:
            raise _TokenOutputUnavailable("could not reserve private token output") from exc
        identity = os.fstat(self.descriptor)
        self.path = destination
        self.device = identity.st_dev
        self.inode = identity.st_ino
        self.published = False

    def publish(self, bearer: str, *, operation: str) -> None:
        try:
            encoded = bearer.encode("utf-8")
            offset = 0
            while offset < len(encoded):
                written = os.write(self.descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("token file write made no progress")
                offset += written
            os.fsync(self.descriptor)
            os.close(self.descriptor)
            self.descriptor = -1
            self.published = True
        except OSError as exc:
            self.discard()
            raise _TokenDeliveryFailure(operation) from exc

    def discard(self) -> None:
        if self.descriptor >= 0:
            try:
                os.close(self.descriptor)
            except OSError:
                pass
            self.descriptor = -1
        if self.published:
            return
        try:
            current = self.path.lstat()
            if current.st_dev == self.device and current.st_ino == self.inode:
                self.path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _add_root_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root", type=Path, default=Path.cwd(),
        help="project directory containing .todo-orchestrator/ (default: current directory)",
    )
    parser.add_argument(
        "--token-file", type=Path,
        help="read a bearer token from a private file (or set TODO_BEARER_TOKEN)",
    )
    parser.add_argument(
        "--provider-factory", metavar="MODULE:CALLABLE",
        help="explicitly load a trusted installed factory returning ProviderComposition",
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="todo",
        description="Standalone Todo Orchestrator workflow commands.",
        epilog="Help and version inspection do not open or initialize an authority.",
    )
    parser.add_argument("--version", action="version", version=f"todo {__version__}")
    _add_root_options(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="explicitly initialize a new authority")
    initialize.add_argument("--project-id", required=True)
    initialize.add_argument("--repository-id", required=True)
    initialize.add_argument("--authority-id")
    initialize.add_argument("--owner-credential-file", type=Path)
    initialize.add_argument("--token-output", type=Path, required=True,
                             help="new private file for the issued owner token; never overwritten")
    initialize.add_argument("--json", action="store_true")

    auth = commands.add_parser("auth", help="issue a scoped owner session")
    auth_commands = auth.add_subparsers(dest="auth_command", required=True)
    login = auth_commands.add_parser("login", help="authenticate the local owner")
    login.add_argument("--owner-credential-file", type=Path)
    login.add_argument("--token-output", type=Path, required=True,
                       help="new private file for the issued token; never overwritten")
    login.add_argument("--json", action="store_true")

    plan = commands.add_parser("plan", help="review and commit authored plan changes")
    plan_commands = plan.add_subparsers(dest="plan_command", required=True)
    preview = plan_commands.add_parser("preview", help="compile and preview a plan file")
    preview.add_argument("package", type=Path)
    preview.add_argument("--output", type=Path,
                         help="write the bounded versioned preview to a new file")
    preview.add_argument("--json", action="store_true")
    commit = plan_commands.add_parser("commit", help="commit an exact saved preview")
    commit.add_argument("package", type=Path)
    commit.add_argument("--preview", type=Path, required=True,
                        help="versioned preview file produced by `plan preview`")
    commit.add_argument("--idempotency-key", required=True)
    commit.add_argument("--json", action="store_true")

    dispatch = commands.add_parser(
        "dispatch", aliases=("claim",),
        help="claim or dispatch one eligible work item",
    )
    dispatch.add_argument("--work-item", required=True)
    dispatch.add_argument("--workspace-id", required=True)
    dispatch.add_argument("--plan-revision")
    dispatch.add_argument("--run-id")
    dispatch.add_argument("--assignment")
    dispatch.add_argument("--idempotency-key", required=True)
    dispatch.add_argument("--token-output", type=Path, required=True,
                          help="new private file for the scoped attempt token; never overwritten")
    dispatch.add_argument("--json", action="store_true")

    verify = commands.add_parser("verify", help="execute one authored verification requirement")
    verify.add_argument("--attempt", required=True)
    verify.add_argument("--requirement", required=True)
    verify.add_argument("--idempotency-key", required=True)
    verify.add_argument("--json", action="store_true")

    report = commands.add_parser("report", help="report a candidate work result")
    report.add_argument("--attempt", required=True)
    report.add_argument("--disposition", required=True,
                        choices=("completed", "evaluated_not_promoted", "no_change"))
    report.add_argument("--idempotency-key", required=True)
    report.add_argument("--json", action="store_true")

    for name in ("accept", "reject"):
        command = commands.add_parser(name, help=f"{name} a reported candidate result")
        command.add_argument("--attempt", required=True)
        command.add_argument("--candidate", required=True)
        command.add_argument("--idempotency-key", required=True)
        command.add_argument("--json", action="store_true")

    finish = commands.add_parser("finish", help="release a safely quiescent attempt")
    finish.add_argument("--attempt", required=True)
    finish.add_argument("--lease", required=True)
    finish.add_argument("--idempotency-key", required=True)
    finish.add_argument("--json", action="store_true")

    read = commands.add_parser("read", help="read the sanitized authority model")
    read.add_argument("--format", choices=("json", "markdown"), default="json")
    read.add_argument("--expected-revision", type=int)
    read.add_argument("--output", type=Path)

    recovery = commands.add_parser("recovery", help="inspect or apply a qualified recovery intent")
    recovery_commands = recovery.add_subparsers(dest="recovery_command", required=True)
    inspect = recovery_commands.add_parser("inspect", help="read-only attempt or effect inspection")
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--attempt")
    target.add_argument("--operation")
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument("--intent-output", type=Path,
                         help="write one currently offered intent as a versioned file (new path only)")
    inspect.add_argument("--intent-index", type=int, default=0,
                         help="zero-based intent index when writing an intent file")
    apply = recovery_commands.add_parser("apply", help="apply an exact saved recovery intent")
    apply.add_argument("--intent", type=Path, required=True)
    apply.add_argument("--idempotency-key", required=True)
    apply.add_argument("--json", action="store_true")

    export = commands.add_parser("export", help="export a read model or create/restore a private backup")
    export_commands = export.add_subparsers(dest="export_command", required=True)
    read_model = export_commands.add_parser("read-model", help="write the sanitized versioned projection")
    read_model.add_argument("--output", type=Path)
    read_model.add_argument("--format", choices=("json", "markdown"), default="json")
    read_model.add_argument("--expected-revision", type=int)
    backup = export_commands.add_parser("backup", help="create an explicit private SQLite backup")
    backup.add_argument("destination", type=Path)
    backup.add_argument("--expected-revision", type=int, required=True)
    backup.add_argument("--manifest-output", type=Path, required=True)
    restore = export_commands.add_parser("restore", help="restore a verified backup to a missing path")
    restore.add_argument("source", type=Path)
    restore.add_argument("destination", type=Path)
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--project-id", required=True)
    restore.add_argument("--authority-id", required=True)
    restore.add_argument("--expected-revision", type=int, required=True)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; help/version parsing stays independent of project state."""
    parser = _parser()
    command_line = list(sys.argv[1:] if argv is None else argv)
    if not command_line:
        parser.print_help()
        return 0
    arguments = parser.parse_args(command_line)
    # The application facade is imported only after parsing. This keeps help,
    # version, and malformed invocations free of project/provider discovery.
    return _run(arguments)


def _run(arguments: argparse.Namespace) -> int:
    """Route commands through the public application facade."""
    try:
        from todo_orchestrator.api import TodoApplication
        from todo_orchestrator.api.metadata import (
            PROJECT_METADATA_FORMAT, PROJECT_METADATA_VERSION,
            ProjectMetadataV1, read_project_metadata,
        )
        from todo_orchestrator.api.providers import ProviderComposition
        from todo_orchestrator.api.serialization import (
            PlanPreviewV1, recovery_intent_from_json, serialize_public_document,
        )
        from todo_orchestrator.contracts import EntityKind, EntityRef, OutcomeDisposition, StableId
        from todo_orchestrator.operations.export import (
            AuthorityExportService, restore_backup,
        )
        from todo_orchestrator.views.export import AuthorityBackupManifest
    except ImportError as exc:
        _error(f"application API is not ready ({type(exc).__name__})")
        return 2

    def stable(value: str | None) -> StableId | None:
        return None if value is None else StableId(value)

    def project_ref(session, kind: EntityKind, identifier: str) -> EntityRef:
        if kind is EntityKind.ATTEMPT:
            return session.attempt_ref(StableId(identifier))
        if kind is EntityKind.WORK_ITEM:
            return session.work_item_ref(StableId(identifier))
        if kind is EntityKind.REQUIREMENT:
            return session.requirement_ref(StableId(identifier))
        return session.ref(kind, StableId(identifier))

    sessions = []

    def providers_for(metadata):
        return _load_provider_composition(
            arguments.provider_factory, arguments.root, metadata, ProviderComposition,
        )

    def session_for(*, explicit_token: str | None = None):
        token = explicit_token or _read_bearer(arguments.token_file)
        if not token:
            raise ValueError("provide --token-file or set TODO_BEARER_TOKEN")
        metadata = read_project_metadata(arguments.root)
        session = TodoApplication.open(
            arguments.root, bearer_token=token, providers=providers_for(metadata),
        )
        sessions.append(session)
        return session

    try:
        if arguments.command == "init":
            reservation = _TokenReservation(arguments.token_output)
            try:
                credential = _read_owner_credential(arguments.owner_credential_file)
                authority_id = stable(arguments.authority_id)
                providers = None
                if arguments.provider_factory:
                    if authority_id is None:
                        authority_id = StableId("authority-" + uuid.uuid4().hex)
                    metadata = ProjectMetadataV1(
                        PROJECT_METADATA_FORMAT, PROJECT_METADATA_VERSION,
                        StableId(arguments.project_id), StableId(arguments.repository_id), authority_id,
                    )
                    providers = providers_for(metadata)
                session = TodoApplication.initialize(
                    arguments.root,
                    project_id=StableId(arguments.project_id),
                    repository_id=StableId(arguments.repository_id),
                    owner_credential=credential,
                    authority_id=authority_id,
                    providers=providers,
                )
                sessions.append(session)
                reservation.publish(session.bearer_token, operation="initialization")
            except BaseException:
                reservation.discard()
                raise
            return _emit({"project_id": str(session.metadata.project_id),
                           "authority_id": str(session.metadata.authority_id),
                           "token_file": str(arguments.token_output)}, arguments.json)

        if arguments.command == "auth":
            reservation = _TokenReservation(arguments.token_output)
            try:
                credential = _read_owner_credential(arguments.owner_credential_file)
                metadata = read_project_metadata(arguments.root)
                session = TodoApplication.login_owner(
                    arguments.root, owner_credential=credential, providers=providers_for(metadata),
                )
                sessions.append(session)
                reservation.publish(session.bearer_token, operation="owner login")
            except BaseException:
                reservation.discard()
                raise
            return _emit({"project_id": str(session.metadata.project_id),
                           "authority_id": str(session.metadata.authority_id),
                           "token_file": str(arguments.token_output)}, arguments.json)

        if arguments.command == "plan":
            session = session_for()
            package_json = _read_bounded_text(arguments.package)
            if arguments.plan_command == "preview":
                preview = session.preview_plan(package_json)
                encoded = preview.to_json()
                if arguments.output is not None:
                    _write_new_file(arguments.output, encoded)
                    print(f"Preview written to {arguments.output}")
                else:
                    print(encoded)
                return 3 if preview.has_conflicts else 0
            preview = PlanPreviewV1.from_json(_read_bounded_text(arguments.preview))
            receipt = session.commit_plan(
                package_json, preview, idempotency_key=StableId(arguments.idempotency_key),
            )
            return _emit(receipt, arguments.json)

        if arguments.command in {"dispatch", "claim"}:
            reservation = _TokenReservation(arguments.token_output)
            try:
                session = session_for()
                result = session.dispatch(
                    StableId(arguments.workspace_id),
                    idempotency_key=StableId(arguments.idempotency_key),
                    work_item=StableId(arguments.work_item), run_id=stable(arguments.run_id),
                    assignment=stable(arguments.assignment), plan_revision_id=stable(arguments.plan_revision),
                )
                reservation.publish(result.bearer_token, operation="dispatch")
            except BaseException:
                reservation.discard()
                raise
            return _emit(result, arguments.json)

        if arguments.command == "verify":
            session = session_for()
            result = session.verify(
                project_ref(session, EntityKind.ATTEMPT, arguments.attempt),
                project_ref(session, EntityKind.REQUIREMENT, arguments.requirement),
                idempotency_key=StableId(arguments.idempotency_key),
            )
            return _emit(result, arguments.json)

        if arguments.command == "report":
            session = session_for()
            result = session.report(
                project_ref(session, EntityKind.ATTEMPT, arguments.attempt),
                OutcomeDisposition(arguments.disposition),
                idempotency_key=StableId(arguments.idempotency_key),
            )
            return _emit(result, arguments.json)

        if arguments.command in {"accept", "reject"}:
            session = session_for()
            attempt_ref = project_ref(session, EntityKind.ATTEMPT, arguments.attempt)
            candidate_ref = project_ref(session, EntityKind.OUTCOME, arguments.candidate)
            method = session.accept if arguments.command == "accept" else session.reject
            return _emit(method(attempt_ref, candidate_ref,
                                idempotency_key=StableId(arguments.idempotency_key)), arguments.json)

        if arguments.command == "finish":
            session = session_for()
            result = session.finish(
                project_ref(session, EntityKind.ATTEMPT, arguments.attempt),
                StableId(arguments.lease), idempotency_key=StableId(arguments.idempotency_key),
            )
            return _emit(result, arguments.json)

        if arguments.command in {"read", "export"} and (
            arguments.command == "read" or arguments.export_command == "read-model"
        ):
            session = session_for()
            if arguments.command == "read":
                expected_revision = arguments.expected_revision
                output_path = arguments.output
                output_format = arguments.format
            else:
                expected_revision = arguments.expected_revision
                output_path = arguments.output
                output_format = arguments.format
            model = session.read_model(expected_revision=expected_revision)
            if output_format == "markdown":
                rendered = AuthorityExportService.render_markdown(model)
            else:
                rendered = model.to_json()
            if output_path is not None:
                _write_new_file(output_path, rendered)
                print(f"Read model written to {output_path}")
                return 0
            print(rendered)
            return 0

        if arguments.command == "recovery":
            session = session_for()
            if arguments.recovery_command == "inspect":
                if arguments.attempt is not None:
                    view = session.inspect_attempt(project_ref(session, EntityKind.ATTEMPT, arguments.attempt))
                else:
                    view = session.inspect_effect(project_ref(session, EntityKind.EXTERNAL_OPERATION,
                                                              arguments.operation))
                print(serialize_public_document("recovery_inspection", view))
                if arguments.intent_output is not None:
                    if arguments.intent_index < 0 or arguments.intent_index >= len(view.intents):
                        raise ValueError("requested recovery intent index is unavailable")
                    encoded = session.serialize("recovery_intent", view.intents[arguments.intent_index])
                    _write_new_file(arguments.intent_output, encoded)
                    print(f"Recovery intent written to {arguments.intent_output}")
                return 0
            intent = recovery_intent_from_json(_read_bounded_text(arguments.intent))
            result = session.apply_recovery(intent, idempotency_key=StableId(arguments.idempotency_key))
            return _emit(result, arguments.json)

        if arguments.command == "export":
            if arguments.export_command == "backup":
                session = session_for()
                result = session.backup(arguments.destination, expected_revision=arguments.expected_revision)
                _write_new_file(arguments.manifest_output, result.manifest.to_json())
                print(f"Backup written to {result.destination}; manifest written to {arguments.manifest_output}")
                return 0
            if arguments.export_command == "restore":
                manifest = AuthorityBackupManifest.from_json(_read_bounded_text(arguments.manifest))
                with restore_backup(
                    arguments.source, arguments.destination, manifest=manifest,
                    expected_project_id=StableId(arguments.project_id),
                    expected_authority_id=StableId(arguments.authority_id),
                    expected_semantic_revision=arguments.expected_revision,
                ):
                    pass
                print(f"Verified backup restored to {arguments.destination}")
                return 0

        _error("unsupported command")
        return 2
    except Exception as exc:
        # Error messages from injected providers or authored content are not
        # echoed to terminals. The exception class provides a useful category
        # without accidentally logging credentials or private payloads.
        _error(_safe_error(exc))
        return 2
    finally:
        for session in sessions:
            session.close()


def _read_bounded_text(path: Path, max_bytes: int = 1_048_576) -> str:
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError("input file exceeds its byte limit")
    return data.decode("utf-8")


def _read_bearer(token_file: Path | None) -> str | None:
    if token_file is not None:
        value = _read_bounded_text(token_file, 16 * 1024).strip()
        if not value:
            raise ValueError("token file is empty")
        return value
    return os.environ.get("TODO_BEARER_TOKEN")


def _read_owner_credential(path: Path | None) -> str:
    if path is not None:
        value = _read_bounded_text(path, 16 * 1024).rstrip("\r\n")
    else:
        value = os.environ.get("TODO_OWNER_CREDENTIAL")
        if value is None:
            value = getpass("Owner credential: ")
    if not value:
        raise ValueError("owner credential is empty")
    return value


def _write_new_file(path: Path, value: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(value)


def _emit(value: object, as_json: bool) -> int:
    if as_json:
        if hasattr(value, "to_json") and callable(value.to_json):
            print(value.to_json())
        else:
            from todo_orchestrator.api.serialization import serialize_public_document
            print(serialize_public_document("result", value))
    elif hasattr(value, "to_json") and callable(value.to_json):
        print(value.to_json())
    else:
        from todo_orchestrator.api.serialization import serialize_public_document
        print(serialize_public_document("result", value))
    return 0


def _error(message: str) -> None:
    print(f"todo: {message}", file=sys.stderr)


def _safe_error(exc: Exception) -> str:
    from todo_orchestrator.api.providers import ProviderUnavailableError
    from todo_orchestrator.api.application import InitializationIncompleteError
    if isinstance(exc, _ProviderFactoryError):
        return ("the explicitly selected provider factory could not be used; verify the trusted module:callable "
                "and returned ProviderComposition")
    if isinstance(exc, _TokenOutputUnavailable):
        return "token output could not be reserved; no token-issuing command was attempted"
    if isinstance(exc, _TokenDeliveryFailure):
        if exc.operation == "dispatch":
            return ("dispatch may have succeeded, but its bearer could not be saved; do not retry blindly. "
                    "Inspect the attempt and use authorized recovery before another claim")
        if exc.operation == "initialization":
            return ("initialization may have succeeded, but its owner bearer could not be saved; "
                    "preserve the authority and explicitly log in to issue a new session")
        return ("owner login may have succeeded, but its bearer could not be saved; "
                "repeat login with a new token path")
    if isinstance(exc, InitializationIncompleteError):
        return ("initialization is incomplete; preserve both authority and metadata files and inspect them "
                "before retrying")
    if isinstance(exc, ProviderUnavailableError):
        return f"required trusted provider unavailable: {exc.port}"
    if isinstance(exc, FileExistsError):
        return "destination already exists; refusing to replace it before mutation"
    if isinstance(exc, PermissionError):
        return "the current credential is not authorized for this operation"
    if isinstance(exc, (ValueError, TypeError)):
        return "invalid input or workflow precondition; inspect the plan or authority state"
    return f"operation failed ({type(exc).__name__}); inspect the authority before retrying"


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _load_provider_composition(specification, project_root, metadata, ProviderComposition):
    """Load only an explicitly named installed provider module.

    The project's root is removed from import search and each module origin is
    checked before execution. Provider config is supplied by the selected
    trusted factory, never inferred from project metadata or plan content.
    """
    if not specification:
        return None
    if not isinstance(specification, str) or specification.count(":") != 1:
        raise _ProviderFactoryError("factory must use MODULE:CALLABLE syntax")
    module_name, callable_name = specification.split(":", 1)
    if not module_name or not callable_name or not all(
        part.isidentifier() for part in module_name.split(".") + [callable_name]
    ):
        raise _ProviderFactoryError("factory must use MODULE:CALLABLE syntax")

    root = Path(project_root).expanduser().resolve(strict=False)
    safe_sys_path = []
    for entry in sys.path:
        candidate = Path(entry or os.getcwd()).expanduser().resolve(strict=False)
        if not _within(candidate, root):
            safe_sys_path.append(entry)

    parts = module_name.split(".")
    search_path = safe_sys_path
    full_name = ""
    try:
        for index, part in enumerate(parts):
            full_name = part if not full_name else full_name + "." + part
            spec = PathFinder.find_spec(full_name, search_path)
            if spec is None:
                raise _ProviderFactoryError("factory module was not found on the trusted import path")
            locations = tuple(spec.submodule_search_locations or ())
            origins = tuple(Path(item).resolve(strict=False) for item in locations)
            if spec.origin and spec.origin not in {"built-in", "frozen"}:
                origins += (Path(spec.origin).resolve(strict=False),)
            if any(_within(origin, root) for origin in origins):
                raise _ProviderFactoryError("factory code inside the selected project is not trusted")
            if index < len(parts) - 1:
                if not locations:
                    raise _ProviderFactoryError("factory module parent is not a package")
                search_path = list(locations)

        for part_index in range(1, len(parts) + 1):
            cached = sys.modules.get(".".join(parts[:part_index]))
            cached_path = getattr(cached, "__file__", None) if cached is not None else None
            if cached_path and _within(Path(cached_path), root):
                raise _ProviderFactoryError("factory code inside the selected project is not trusted")

        original_path = sys.path
        sys.path = safe_sys_path
        try:
            module = import_module(module_name)
        finally:
            sys.path = original_path
        module_path = getattr(module, "__file__", None)
        if module_path and _within(Path(module_path), root):
            raise _ProviderFactoryError("factory code inside the selected project is not trusted")
        factory = getattr(module, callable_name)
        if not callable(factory):
            raise _ProviderFactoryError("factory attribute is not callable")
        providers = factory(root, metadata)
        if not isinstance(providers, ProviderComposition):
            raise _ProviderFactoryError("factory must return ProviderComposition")
        return providers
    except _ProviderFactoryError:
        raise
    except Exception as exc:
        raise _ProviderFactoryError("explicit provider factory failed") from exc




if __name__ == "__main__":
    raise SystemExit(main())
