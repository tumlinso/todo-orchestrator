"""Domain-oriented, explicit standalone Todo application and session APIs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from todo_orchestrator.authority.auth import (
    AuthorityAuthService,
    AuthorizationRequirement,
    CapabilityDeniedError,
    RECOVERY_INSPECT_ACTION,
    RESOURCE_READ_ACTION,
    RESOURCE_RECONCILE_ACTION,
    RESOURCE_RELEASE_ACTION,
    RESOURCE_RESERVE_ACTION,
    _password_bytes,
    _unique_actions,
    _validate_grant,
)
from todo_orchestrator.authority.attempts import (
    ATTEMPT_SESSION_ACTIONS,
    AttemptService,
    CLAIM_ACTION,
    FINISH_ACTION,
    OUTCOME_REPORT_ACTION,
    VERIFICATION_ACTION,
    VERIFICATION_RECONCILE_ACTION,
    RECONCILE_ACTION,
)
from todo_orchestrator.authority.commands import CommandDispatcher
from todo_orchestrator.authority.declarations import DeclarationService
from todo_orchestrator.authority.sqlite import SQLiteAuthority
from todo_orchestrator.contracts import (
    Attempt,
    EntityKind,
    EntityRef,
    OutcomeDisposition,
    Project,
    ProviderIdentity,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.coordination.context import ContextService
from todo_orchestrator.coordination.service import (
    ATTEMPT_FINISH_ACTION,
    RUN_DISPATCH_ACTION,
    RUN_SCHEDULE_ACTION,
    CoordinationService,
    RunScheduleNotFoundError,
)
from todo_orchestrator.coordination.store import load_run_schedule
from todo_orchestrator.model import CommandReceipt, CommandResult, DispatchResult, RunSchedule
from todo_orchestrator.operations.export import (
    AUTHORITY_BACKUP_ACTION,
    AUTHORITY_READ_ACTION,
    AuthorityExportService,
    AuthorityBackupResult,
    AuthorityReadModelV1,
    restore_backup,
)
from todo_orchestrator.operations.inspection import RecoveryInspectionService
from todo_orchestrator.operations.lifecycle import (
    RUN_CLOSE_ACTION,
    RUN_RETIRE_ACTION,
    RunAssignmentHandoff,
    RunLifecycleService,
    UnresolvedRunAssignment,
)
from todo_orchestrator.operations.recovery import (
    RECOVERY_APPLY_ACTION_ID,
    RecoveryExecutionService,
    RecoveryIntentStaleError,
)
from todo_orchestrator.planning import CompiledPlan, PlanService
from todo_orchestrator.planning.changes import preview_changes
from todo_orchestrator.planning.package import compile_plan_json
from todo_orchestrator.planning.service import _snapshot as _plan_snapshot
from todo_orchestrator.providers.git import (
    CREATE_WORKSPACE_ACTION,
    INTEGRATE_ACTION,
    GitEffectOperationView,
    GitEffectService,
)
from todo_orchestrator.providers.execution.command import (
    COMMAND_VERIFIER_IDENTITY,
    CommandExecutionVerifier,
    RoutedVerificationProvider,
)
from todo_orchestrator.providers.resources.service import (
    RESOURCE_READ_ACTION,
    RESOURCE_RECONCILE_ACTION,
    RESOURCE_RELEASE_ACTION,
    RESOURCE_RESERVE_ACTION,
    ResourcePermitOperationView,
    ResourcePermitService,
)
from todo_orchestrator.verification import (
    ACCEPT_OUTCOME_ACTION,
    REJECT_CANDIDATE_ACTION,
    REPORT_CANDIDATE_ACTION,
    VERIFY_ACTION,
    CandidateReportView,
    OutcomeAcceptanceService,
    VerificationOperationView,
    VerificationService,
)
from todo_orchestrator.views.recovery import RecoveryInspection, RecoveryIntent
from todo_orchestrator.views.export import AuthorityBackupManifest

from .metadata import (
    AUTHORITY_RELATIVE_PATH,
    PROJECT_METADATA_RELATIVE_PATH,
    ProjectMetadataError,
    ProjectMetadataExistsError,
    ProjectMetadataV1,
    authority_path,
    project_metadata_path,
    read_project_metadata,
    write_project_metadata_no_replace,
)
from .providers import ProviderComposition, ProviderUnavailableError
from .serialization import (
    ApiDocumentV1,
    ApiReceiptV1,
    CandidateReceiptV1,
    DispatchReceiptV1,
    PlanPreviewV1,
    serialize_public_document,
)


class TodoApplicationError(RuntimeError):
    """Base public facade error for project/session configuration failures."""


class InitializationIncompleteError(TodoApplicationError):
    """Explicit initialization created one durable file but could not publish the other."""


class ProjectIdentityError(TodoApplicationError):
    """Injected providers or caller references do not match the project metadata."""


class PlanPreviewMismatchError(TodoApplicationError):
    """Commit was not given the exact current preview of this package and authority."""


class ProjectUnavailableError(TodoApplicationError):
    """Project metadata or its native authority is missing or cannot be opened."""


class TodoAuthenticationError(TodoApplicationError):
    """The supplied session token is unknown, expired, or revoked."""


class _ServiceBundle:
    def __init__(self, project: Project, providers: ProviderComposition) -> None:
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(self.dispatcher, clock=providers.clock)
        self.plan = PlanService(self.auth)
        self.attempts = None
        if providers.attempt_host is not None:
            self.attempts = AttemptService(self.auth, host=providers.attempt_host, clock=providers.clock)
        self.coordination = CoordinationService(self.auth, attempts=self.attempts)
        self.declarations = DeclarationService(self.auth)
        self.context = ContextService(self.auth, clock=providers.clock)
        self.verification = None
        has_verification = (
            providers.verification_provider is not None
            and providers.verification_identity is not None
        ) or providers.command_execution_provider is not None
        if providers.source_observer is not None and providers.source_identity is not None and has_verification:
            command_adapter = None
            if providers.command_execution_provider is not None:
                command_adapter = CommandExecutionVerifier(
                    providers.command_execution_provider,
                    execution_identity=providers.command_execution_identity,
                    adapter_identity=COMMAND_VERIFIER_IDENTITY,
                )
            routed = RoutedVerificationProvider(
                fallback=providers.verification_provider,
                fallback_identity=providers.verification_identity,
                command=command_adapter,
            )
            service_identity = providers.verification_identity or COMMAND_VERIFIER_IDENTITY
            self.verification = VerificationService(
                self.auth, source_observer=providers.source_observer,
                source_identity=providers.source_identity,
                provider=routed,
                provider_identity=service_identity,
                clock=providers.clock,
            )
        self.outcomes = None
        if providers.attempt_host is not None and providers.host_identity is not None and providers.source_observer is not None and providers.source_identity is not None:
            self.outcomes = OutcomeAcceptanceService(
                self.auth, source_observer=providers.source_observer,
                source_identity=providers.source_identity,
                host=providers.attempt_host, host_identity=providers.host_identity,
                declaration_observer=providers.declaration_observer,
                declaration_identity=providers.declaration_identity,
                clock=providers.clock,
            )
        self.git = None
        if providers.git_provider is not None:
            self.git = GitEffectService(
                self.auth, providers.git_provider,
                source_observer=providers.source_observer,
                source_identity=providers.source_identity,
                clock=providers.clock,
            )
        self.resource_permits = None
        if providers.resource_permit_provider is not None:
            self.resource_permits = ResourcePermitService(
                self.auth, providers.resource_permit_provider,
                provider_identity=providers.resource_permit_identity,
                clock=providers.clock,
            )
        self.lifecycle = RunLifecycleService(self.auth)
        self.export = AuthorityExportService(self.auth)
        self.inspection = None
        self.recovery = None
        if providers.attempt_host is not None:
            inspectors = {}
            if providers.git_provider is not None:
                inspectors["git"] = providers.git_provider
            if self.verification is not None:
                inspectors["verification"] = self.verification.provider
            self.inspection = RecoveryInspectionService(
                self.auth, host=providers.attempt_host, operation_inspectors=inspectors,
                source_observer=providers.source_observer, clock=providers.clock,
            )
            if self.attempts is not None:
                self.recovery = RecoveryExecutionService(
                    self.inspection, attempts=self.attempts, verification=self.verification,
                    git_effects=self.git, clock=providers.clock,
                )


DEFAULT_OWNER_ACTIONS = tuple(sorted({
    StableId("todo.plan.commit"), CLAIM_ACTION, *ATTEMPT_SESSION_ACTIONS,
    FINISH_ACTION,
    RUN_SCHEDULE_ACTION, RUN_DISPATCH_ACTION, ATTEMPT_FINISH_ACTION,
    VERIFY_ACTION, VERIFICATION_RECONCILE_ACTION, RECONCILE_ACTION,
    RESOURCE_RESERVE_ACTION, RESOURCE_RELEASE_ACTION, RESOURCE_READ_ACTION, RESOURCE_RECONCILE_ACTION,
    OUTCOME_REPORT_ACTION, REPORT_CANDIDATE_ACTION, ACCEPT_OUTCOME_ACTION,
    REJECT_CANDIDATE_ACTION, CREATE_WORKSPACE_ACTION, INTEGRATE_ACTION,
    RECOVERY_INSPECT_ACTION, RECOVERY_APPLY_ACTION_ID,
    RUN_CLOSE_ACTION, RUN_RETIRE_ACTION, AUTHORITY_READ_ACTION, AUTHORITY_BACKUP_ACTION,
    StableId("todo.context.read"), StableId("todo.context.finding.publish"),
    StableId("todo.context.finding.invalidate"),
    StableId("todo.decision.resolve"), StableId("todo.interface.publish"),
    StableId("todo.checkpoint.accept"), StableId("todo.barrier.release"),
    StableId("todo.rendezvous.arrive"), StableId("todo.blocker.open"),
    StableId("todo.blocker.clear"),
}))


class TodoApplication:
    """Explicit project initialization and existing-project session opening."""

    @classmethod
    def initialize(
        cls,
        project_root: str | os.PathLike[str],
        *,
        project_id: StableId,
        repository_id: StableId,
        owner_credential: str,
        providers: ProviderComposition | None = None,
        authority_id: StableId | None = None,
        owner_actions: tuple[StableId, ...] = DEFAULT_OWNER_ACTIONS,
        token_lifetime: timedelta = timedelta(days=30),
    ) -> "TodoSession":
        """Explicitly initialize missing project state; never repairs or replaces."""
        if not isinstance(project_id, StableId) or not isinstance(repository_id, StableId):
            raise TypeError("project_id and repository_id must be StableId values")
        _password_bytes(owner_credential)
        if not owner_credential.strip():
            raise ValueError("owner_credential must be non-empty text")
        if authority_id is None:
            authority_id = StableId("authority-" + uuid4().hex)
        if not isinstance(authority_id, StableId):
            raise TypeError("authority_id must be StableId or None")
        if not isinstance(token_lifetime, timedelta) or token_lifetime <= timedelta(0):
            raise ValueError("token_lifetime must be positive")
        if providers is not None and not isinstance(providers, ProviderComposition):
            raise TypeError("providers must be a ProviderComposition or None")
        owner_actions = _unique_actions(owner_actions)
        composition = providers or ProviderComposition()
        project = Project(project_id, authority_id)
        _check_provider_project(
            ProjectMetadataV1(
                "todo-orchestrator.project-metadata", 1, project_id, repository_id, authority_id,
            ),
            composition,
        )
        now = _now(composition.clock)
        expires_at = now + token_lifetime
        _validate_grant(project, project.ref, owner_actions, None, None, None, expires_at, now)
        root = Path(project_root).expanduser().resolve(strict=False)
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir():
            raise ProjectMetadataError("project root must be a directory")
        metadata_path = root / PROJECT_METADATA_RELATIVE_PATH
        db_path = root / AUTHORITY_RELATIVE_PATH
        occupied = tuple(Path(str(db_path) + suffix) for suffix in ("-wal", "-shm", "-journal"))
        if any(path.exists() or path.is_symlink() for path in (metadata_path, db_path, *occupied)):
            raise ProjectMetadataExistsError("project metadata, authority, or SQLite sidecar already exists")
        data_dir = metadata_path.parent
        if data_dir.is_symlink():
            raise ProjectMetadataError("project data directory must not be a symbolic link")
        if data_dir.exists() and any(data_dir.iterdir()):
            raise ProjectMetadataExistsError("project data directory contains existing state; refusing initialization")
        data_dir.mkdir(parents=True, exist_ok=True)
        metadata = ProjectMetadataV1(
            "todo-orchestrator.project-metadata", 1, project_id, repository_id, authority_id,
        )
        SQLiteAuthority.initialize(db_path, project)
        try:
            write_project_metadata_no_replace(root, metadata)
        except BaseException as exc:
            # The database may already be visible to another process. Preserve
            # it and report incomplete explicit initialization; never silently
            # remove or repair either durable file.
            raise InitializationIncompleteError(
                "authority was initialized but project metadata publication failed; preserve both files and inspect explicitly"
            ) from exc
        services = _ServiceBundle(project, composition)
        with SQLiteAuthority.open_writer(db_path, project) as authority:
            services.auth.enroll_local_owner(
                authority, owner_credential, label=str(project_id),
                idempotency_key=StableId("enroll-" + uuid4().hex),
            )
            issued = services.auth.login_local_owner(
                authority, owner_credential, actions=owner_actions, scope=project.ref,
                expires_at=expires_at,
                idempotency_key=StableId("owner-session-" + uuid4().hex),
            )
        return TodoSession(root, metadata, composition, services, issued.bearer_token)

    @classmethod
    def open(
        cls,
        project_root: str | os.PathLike[str],
        *,
        bearer_token: str,
        providers: ProviderComposition | None = None,
    ) -> "TodoSession":
        """Open and validate an existing project without initializing or repairing it."""
        try:
            metadata = read_project_metadata(project_root)
            root = Path(project_root).expanduser().resolve(strict=True)
            db_path = authority_path(root, metadata)
        except (ProjectMetadataError, OSError) as exc:
            raise ProjectUnavailableError("project metadata is missing or invalid") from exc
        composition = providers or ProviderComposition()
        _check_provider_project(metadata, composition)
        try:
            with SQLiteAuthority.open_reader(db_path, metadata.project):
                pass
        except Exception as exc:
            # Do not expose database/provider details in the stable public
            # error surface; open is validation only and never repairs state.
            from todo_orchestrator.authority.sqlite import AuthorityError
            if isinstance(exc, AuthorityError):
                raise ProjectUnavailableError("native project authority is missing or invalid") from exc
            raise
        if not isinstance(bearer_token, str) or not bearer_token:
            raise ValueError("bearer_token must be non-empty text")
        services = _ServiceBundle(metadata.project, composition)
        # Validate bearer without issuing authority or changing SQLite state.
        try:
            with SQLiteAuthority.open_reader(db_path, metadata.project) as authority:
                actor, capability_id = services.auth._actor_for_token(authority, _token_digest(bearer_token))
                with authority.read_transaction() as connection:
                    row = connection.execute(
                        "SELECT c.revoked, c.expires_at FROM capabilities AS c WHERE c.capability_id = ?",
                        (str(capability_id),),
                    ).fetchone()
                if row is None or row["revoked"]:
                    raise TodoAuthenticationError("session capability is unknown or revoked")
                expires_at = row["expires_at"]
                if expires_at is not None and datetime.fromisoformat(expires_at) <= _now(composition.clock):
                    raise TodoAuthenticationError("session capability has expired")
        except TodoAuthenticationError:
            raise
        except Exception as exc:
            from todo_orchestrator.authority.auth import AuthenticationFailedError
            if isinstance(exc, AuthenticationFailedError):
                raise TodoAuthenticationError("session bearer is invalid") from exc
            from todo_orchestrator.authority.sqlite import AuthorityError
            if isinstance(exc, AuthorityError):
                raise ProjectUnavailableError("native project authority is missing or invalid") from exc
            raise
        return TodoSession(root, metadata, composition, services, bearer_token)

    @classmethod
    def login_owner(
        cls,
        project_root: str | os.PathLike[str],
        *,
        owner_credential: str,
        providers: ProviderComposition | None = None,
        owner_actions: tuple[StableId, ...] = DEFAULT_OWNER_ACTIONS,
        token_lifetime: timedelta = timedelta(days=30),
    ) -> "TodoSession":
        """Issue a new explicit local-owner session for existing metadata/authority."""
        try:
            metadata = read_project_metadata(project_root)
            root = Path(project_root).expanduser().resolve(strict=True)
            db_path = authority_path(root, metadata)
        except (ProjectMetadataError, OSError) as exc:
            raise ProjectUnavailableError("project metadata is missing or invalid") from exc
        composition = providers or ProviderComposition()
        _check_provider_project(metadata, composition)
        services = _ServiceBundle(metadata.project, composition)
        try:
            with SQLiteAuthority.open_writer(db_path, metadata.project) as authority:
                issued = services.auth.login_local_owner(
                    authority, owner_credential, actions=owner_actions, scope=metadata.project.ref,
                    expires_at=_now(composition.clock) + token_lifetime,
                    idempotency_key=StableId("owner-session-" + uuid4().hex),
                )
        except Exception as exc:
            from todo_orchestrator.authority.auth import AuthenticationFailedError
            if isinstance(exc, AuthenticationFailedError):
                raise TodoAuthenticationError("local owner authentication failed") from exc
            from todo_orchestrator.authority.sqlite import AuthorityError
            if isinstance(exc, AuthorityError):
                raise ProjectUnavailableError("native project authority is missing or invalid") from exc
            raise
        return TodoSession(root, metadata, composition, services, issued.bearer_token)

    @staticmethod
    def restore_backup(
        source: str | os.PathLike[str], destination: str | os.PathLike[str], *,
        manifest: AuthorityBackupManifest, expected_project_id: StableId,
        expected_authority_id: StableId, expected_revision: int,
    ) -> SQLiteAuthority:
        """Explicitly restore a private backup to a missing SQLite authority path."""
        return restore_backup(
            source, destination, manifest=manifest,
            expected_project_id=expected_project_id,
            expected_authority_id=expected_authority_id,
            expected_semantic_revision=expected_revision,
        )


def _check_provider_project(metadata: ProjectMetadataV1, composition: ProviderComposition) -> None:
    provider = composition.git_provider
    if provider is not None and (
        provider.config.project_id != metadata.project_id
        or provider.config.repository_id != metadata.repository_id
    ):
        raise ProjectIdentityError("configured Git provider identity differs from project metadata")


def _now(clock) -> datetime:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("application clock must return an aware datetime")
    return value.astimezone(timezone.utc)


def _token_digest(token: str) -> str:
    from todo_orchestrator.authority.auth import _token_digest as digest
    return digest(token)


class TodoSession:
    """Short-lived facade over existing authorities and injected trusted ports."""

    def __init__(self, root: Path, metadata: ProjectMetadataV1, providers: ProviderComposition,
                 services: _ServiceBundle, bearer_token: str) -> None:
        self.root = root
        self.metadata = metadata
        self.project = metadata.project
        self.providers = providers
        self._services = services
        self._bearer_token = bearer_token
        self._closed = False

    def __repr__(self) -> str:
        return f"TodoSession(project_id={self.project.project_id!r}, authority_id={self.project.authority_id!r}, bearer_token=<redacted>)"

    @property
    def bearer_token(self) -> str:
        """The session's one-time bearer; never included in repr or API documents."""
        self._ensure_open()
        return self._bearer_token

    def write_bearer(self, path: str | os.PathLike[str]) -> None:
        from .serialization import _write_secret_no_replace
        self._ensure_open()
        _write_secret_no_replace(str(path), self._bearer_token)

    def close(self) -> None:
        self._closed = True
        self._bearer_token = ""

    def __enter__(self) -> "TodoSession":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise TodoApplicationError("Todo session is closed")

    @contextmanager
    def _reader(self) -> Iterator[SQLiteAuthority]:
        self._ensure_open()
        with SQLiteAuthority.open_reader(authority_path(self.root, self.metadata), self.project) as authority:
            yield authority

    @contextmanager
    def _writer(self) -> Iterator[SQLiteAuthority]:
        self._ensure_open()
        with SQLiteAuthority.open_writer(authority_path(self.root, self.metadata), self.project) as authority:
            yield authority

    def _required(self, service, port: str):
        self._ensure_open()
        if service is None:
            raise ProviderUnavailableError(port)
        return service

    def preview_plan(self, package_json: str) -> PlanPreviewV1:
        if not isinstance(package_json, str):
            raise TypeError("package_json must be UTF-8 JSON text")
        with self._reader() as authority:
            with authority.read_transaction() as connection:
                self._authorize_project_read(connection)
                compiled = compile_plan_json(package_json, self.project)
                if not compiled.ok or compiled.plan is None:
                    from todo_orchestrator.planning.service import PlanCommitError
                    raise PlanCommitError(
                        "plan compilation failed: " + "; ".join(item.code for item in compiled.diagnostics)
                    )
                changes = preview_changes(compiled.plan, _plan_snapshot(connection, self.project))
        return PlanPreviewV1.from_changes(changes, package_json)

    def _authorize_project_read(self, connection) -> None:
        """Authorize a project read in the same SQLite snapshot as its payload."""
        self._authorize_exact_action(connection, AUTHORITY_READ_ACTION, self.project.ref)

    def commit_plan(self, package_json: str, preview: PlanPreviewV1 | str, *,
                    idempotency_key: StableId) -> ApiReceiptV1:
        if isinstance(preview, str):
            preview = PlanPreviewV1.from_json(preview)
        if not isinstance(preview, PlanPreviewV1):
            raise TypeError("preview must be a PlanPreviewV1 or its canonical JSON")
        if preview.project_id != self.project.project_id or preview.authority_id != self.project.authority_id:
            raise PlanPreviewMismatchError("plan preview belongs to another project or authority")
        package_digest = Sha256Digest(hashlib.sha256(package_json.encode("utf-8")).hexdigest())
        if package_digest != preview.package_digest:
            raise PlanPreviewMismatchError("package text differs from the reviewed plan preview")
        with self._reader() as reader:
            current = self._services.plan.preview(reader, package_json)
        fresh = PlanPreviewV1.from_changes(current, package_json)
        if (fresh.change_digest != preview.change_digest
                or fresh.expected_authority_revision != preview.expected_authority_revision
                or fresh.expected_plan_revision_id != preview.expected_plan_revision_id
                or fresh.proposed_revision_id != preview.proposed_revision_id):
            raise PlanPreviewMismatchError("accepted plan or authority changed after preview")
        if preview.has_conflicts:
            raise PlanPreviewMismatchError("plan preview contains unresolved conflicts")
        with self._writer() as writer:
            result = self._services.plan.commit(
                writer, self._bearer_token, package_json,
                reviewed_digest=preview.change_digest, idempotency_key=idempotency_key,
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_plan_revision_id,
            )
        return ApiReceiptV1.from_result(result)

    def read_snapshot(self):
        with self._reader() as authority:
            with authority.read_transaction() as connection:
                self._authorize_project_read(connection)
                return _plan_snapshot(connection, self.project)

    def _accepted_plan(self, revision_id: StableId | None = None) -> CompiledPlan:
        with self._reader() as authority:
            try:
                return self._services.plan.load_accepted_plan(authority, revision_id)
            except Exception:
                raise

    def ref(self, kind: EntityKind | str, entity_id: StableId | str, *,
            definition_revision_id: StableId | str | None = None,
            incarnation_id: StableId | str | None = None) -> EntityRef:
        self._ensure_open()
        kind_value = kind if isinstance(kind, EntityKind) else EntityKind(kind)
        return EntityRef(
            self.project.project_id, kind_value,
            entity_id if isinstance(entity_id, StableId) else StableId(entity_id),
            None if definition_revision_id is None else (
                definition_revision_id if isinstance(definition_revision_id, StableId) else StableId(definition_revision_id)
            ),
            None if incarnation_id is None else (
                incarnation_id if isinstance(incarnation_id, StableId) else StableId(incarnation_id)
            ),
        )

    def work_item_ref(self, work_item_id: StableId | str,
                      plan_revision_id: StableId | None = None) -> EntityRef:
        item_id = work_item_id if isinstance(work_item_id, StableId) else StableId(work_item_id)
        plan = self._accepted_plan(plan_revision_id)
        matches = [item.definition.ref for item in plan.work_items if item.definition.work_item_id == item_id]
        if len(matches) != 1:
            raise ValueError("work item is absent or ambiguous in the selected accepted plan")
        return matches[0]

    def requirement_ref(self, requirement_id: StableId | str, *, work_item_id: StableId | str | None = None,
                        plan_revision_id: StableId | None = None) -> EntityRef:
        req_id = requirement_id if isinstance(requirement_id, StableId) else StableId(requirement_id)
        work_id = None if work_item_id is None else (work_item_id if isinstance(work_item_id, StableId) else StableId(work_item_id))
        plan = self._accepted_plan(plan_revision_id)
        matches = [item.definition.ref for item in plan.requirements
                   if item.definition.requirement_id == req_id
                   and (work_id is None or item.definition.work_item_id == work_id)]
        if len(matches) != 1:
            raise ValueError("requirement is absent or ambiguous in the selected accepted plan")
        return matches[0]

    def attempt_ref(self, attempt_id: StableId | str) -> EntityRef:
        return self.ref(EntityKind.ATTEMPT, attempt_id)

    def outcome_ref(self, outcome_id: StableId | str) -> EntityRef:
        return self.ref(EntityKind.OUTCOME, outcome_id)

    def run_ref(self, run_id: StableId | str) -> EntityRef:
        return self.ref(EntityKind.RUN, run_id)

    def assignment_ref(self, assignment_id: StableId | str) -> EntityRef:
        return self.ref(EntityKind.ASSIGNMENT, assignment_id)

    def _selector_ref(self, value, kind: EntityKind, *, plan_revision_id=None) -> EntityRef | None:
        if value is None:
            return None
        if isinstance(value, EntityRef):
            if value.project_id != self.project.project_id or value.kind is not kind:
                raise ValueError(f"selector must be a project-local {kind.value} reference")
            return value
        if kind is EntityKind.WORK_ITEM:
            return self.work_item_ref(value, plan_revision_id)
        return self.ref(kind, value)

    def open_run(self, plan_revision_id: StableId, schedule: RunSchedule, *,
                 idempotency_key: StableId, expected_revision: int | None = None) -> ApiReceiptV1:
        if not isinstance(plan_revision_id, StableId):
            raise TypeError("plan_revision_id must be StableId")
        plan = self._accepted_plan(plan_revision_id)
        with self._writer() as authority:
            result = self._services.coordination.open_run(
                authority, self._bearer_token, plan, schedule,
                idempotency_key=idempotency_key, expected_revision=expected_revision,
            )
        return ApiReceiptV1.from_result(result)

    def _authorized_run_schedule_row(self, connection, run: StableId):
        row = connection.execute(
            "SELECT r.plan_revision_id, s.schedule_digest FROM runs AS r "
            "JOIN run_schedules AS s USING (run_id) WHERE r.run_id = ?",
            (str(run),),
        ).fetchone()
        if row is None:
            raise RunScheduleNotFoundError(f"run schedule does not exist: {run}")
        plan_ref = EntityRef(
            self.project.project_id, EntityKind.PLAN_REVISION, StableId(row["plan_revision_id"])
        )
        self._authorize_exact_action(
            connection, RUN_SCHEDULE_ACTION, plan_ref,
            run=EntityRef(self.project.project_id, EntityKind.RUN, run),
        )
        return row

    def read_run(self, run_id: StableId | str):
        run = run_id if isinstance(run_id, StableId) else StableId(run_id)
        with self._reader() as authority:
            with authority.read_transaction() as connection:
                self._authorized_run_schedule_row(connection, run)
                view = load_run_schedule(connection, self.project, run)
                if view is None:
                    raise RunScheduleNotFoundError(f"run schedule does not exist: {run}")
                return view

    def run_schedule_digest(self, run_id: StableId | str) -> Sha256Digest:
        """Read the authenticated immutable schedule digest for close/retire CAS."""
        run = run_id if isinstance(run_id, StableId) else StableId(run_id)
        with self._reader() as authority:
            with authority.read_transaction() as connection:
                row = self._authorized_run_schedule_row(connection, run)
                return Sha256Digest(row["schedule_digest"])

    def dispatch(self, workspace_id: StableId | str, *, idempotency_key: StableId,
                 work_item: StableId | EntityRef | None = None,
                 run_id: StableId | EntityRef | None = None,
                 assignment: StableId | EntityRef | None = None,
                 plan_revision_id: StableId | None = None,
                 expected_revision: int | None = None) -> DispatchReceiptV1:
        coordination = self._required(self._services.attempts, "attempt_host")
        del coordination
        workspace = workspace_id if isinstance(workspace_id, StableId) else StableId(workspace_id)
        run_ref = self._selector_ref(run_id, EntityKind.RUN)
        if plan_revision_id is None and run_ref is not None:
            plan_revision_id = self.read_run(run_ref.entity_id).run.plan_revision.entity_id
        plan = self._accepted_plan(plan_revision_id)
        target_ref = self._selector_ref(work_item, EntityKind.WORK_ITEM, plan_revision_id=plan_revision_id)
        assignment_ref = self._selector_ref(assignment, EntityKind.ASSIGNMENT)
        with self._writer() as authority:
            result = self._services.coordination.dispatch(
                authority, self._bearer_token, plan, workspace_id=workspace,
                idempotency_key=idempotency_key, expected_revision=expected_revision,
                work_item=target_ref, run=run_ref, assignment=assignment_ref,
            )
        return DispatchReceiptV1(
            result.attempt.ref, result.attempt.work_item, result.attempt.run,
            result.attempt.assignment, result.attempt.lease.lease_id,
            result.receipt.semantic_revision, ApiReceiptV1.from_result(result.receipt), result.bearer_token,
        )

    def create_workspace(self, target: StableId | EntityRef, *, idempotency_key: StableId,
                         workspace_id: StableId | None = None,
                         run_id: StableId | EntityRef | None = None,
                         assignment: StableId | EntityRef | None = None,
                         plan_revision_id: StableId | None = None,
                         expected_revision: int | None = None) -> GitEffectOperationView:
        git = self._required(self._services.git, "git_effects")
        target_ref = self._selector_ref(target, EntityKind.WORK_ITEM, plan_revision_id=plan_revision_id)
        run_ref = self._selector_ref(run_id, EntityKind.RUN)
        assignment_ref = self._selector_ref(assignment, EntityKind.ASSIGNMENT)
        with self._writer() as authority:
            return git.create_workspace(
                authority, self._bearer_token, target_ref, idempotency_key=idempotency_key,
                workspace_id=workspace_id, expected_revision=expected_revision,
                run=run_ref, assignment=assignment_ref,
            )

    def integrate_attempt(self, attempt_ref: EntityRef | StableId, *, idempotency_key: StableId,
                           expected_revision: int | None = None) -> GitEffectOperationView:
        git = self._required(self._services.git, "git_effects")
        ref = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        with self._writer() as authority:
            return git.integrate_attempt(authority, self._bearer_token, ref,
                                         idempotency_key=idempotency_key,
                                         expected_revision=expected_revision)

    def verify(self, attempt_ref: EntityRef | StableId,
               requirement_ref: EntityRef | StableId, *, idempotency_key: StableId,
               expected_revision: int | None = None) -> VerificationOperationView:
        verifier = self._required(self._services.verification, "verification_provider_and_source_observer")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        if isinstance(requirement_ref, EntityRef):
            requirement = requirement_ref
        else:
            requirement = self.requirement_ref(requirement_ref)
        with self._writer() as authority:
            return verifier.execute(authority, self._bearer_token, attempt, requirement,
                                    idempotency_key=idempotency_key,
                                    expected_revision=expected_revision)

    def reserve_resource(self, attempt_ref: EntityRef | StableId, resource_class: StableId | str, units: int, *,
                         idempotency_key: StableId, expected_revision: int | None = None) -> ResourcePermitOperationView:
        service = self._required(self._services.resource_permits, "resource_permit_provider")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        resource = resource_class if isinstance(resource_class, StableId) else StableId(resource_class)
        with self._writer() as authority:
            return service.reserve(authority, self._bearer_token, attempt, resource, units,
                                   idempotency_key=idempotency_key, expected_revision=expected_revision)

    def inspect_resource(self, operation_ref: EntityRef | StableId) -> ResourcePermitOperationView:
        service = self._required(self._services.resource_permits, "resource_permit_provider")
        operation = operation_ref if isinstance(operation_ref, EntityRef) else operation_ref
        with self._reader() as authority:
            return service.inspect(authority, self._bearer_token, operation)

    def reconcile_resource(self, operation_ref: EntityRef | StableId, *, idempotency_key: StableId,
                           expected_revision: int | None = None) -> ResourcePermitOperationView:
        service = self._required(self._services.resource_permits, "resource_permit_provider")
        operation = operation_ref if isinstance(operation_ref, EntityRef) else operation_ref
        with self._writer() as authority:
            return service.reconcile(authority, self._bearer_token, operation,
                                     idempotency_key=idempotency_key,
                                     expected_revision=expected_revision)

    def retry_resource(self, operation_ref: EntityRef | StableId, *, idempotency_key: StableId,
                       expected_revision: int | None = None) -> ResourcePermitOperationView:
        """Retry only a same-identity effect freshly proven not applied."""
        service = self._required(self._services.resource_permits, "resource_permit_provider")
        operation = operation_ref if isinstance(operation_ref, EntityRef) else operation_ref
        with self._writer() as authority:
            return service.retry(authority, self._bearer_token, operation,
                                 idempotency_key=idempotency_key,
                                 expected_revision=expected_revision)

    def release_resource(self, operation_ref: EntityRef | StableId, *, idempotency_key: StableId,
                         expected_revision: int | None = None) -> ResourcePermitOperationView:
        service = self._required(self._services.resource_permits, "resource_permit_provider")
        operation = operation_ref if isinstance(operation_ref, EntityRef) else operation_ref
        with self._writer() as authority:
            return service.release(authority, self._bearer_token, operation,
                                   idempotency_key=idempotency_key,
                                   expected_revision=expected_revision)

    def report(self, attempt_ref: EntityRef | StableId, disposition: OutcomeDisposition | str, *,
               idempotency_key: StableId, expected_revision: int | None = None,
               note: str | None = None) -> CandidateReceiptV1:
        outcomes = self._required(self._services.outcomes, "host_and_source_observer")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        disposition_value = disposition if isinstance(disposition, OutcomeDisposition) else OutcomeDisposition(disposition)
        with self._writer() as authority:
            result, candidate = outcomes.report_candidate(
                authority, self._bearer_token, attempt, disposition_value,
                idempotency_key=idempotency_key, expected_revision=expected_revision, note=note,
            )
        view = self.read_candidate(candidate)
        return CandidateReceiptV1(candidate, attempt, view.target, disposition_value.value,
                                  result.receipt.semantic_revision, ApiReceiptV1.from_result(result))

    def read_candidate(self, candidate_ref: EntityRef | StableId) -> CandidateReportView:
        outcomes = self._required(self._services.outcomes, "host_and_source_observer")
        candidate = candidate_ref if isinstance(candidate_ref, EntityRef) else self.outcome_ref(candidate_ref)
        with self._reader() as authority:
            if candidate.project_id != self.project.project_id or candidate.kind is not EntityKind.OUTCOME:
                raise ValueError("candidate selector must be a project-local outcome reference")
            with authority.read_transaction() as connection:
                row = connection.execute(
                    "SELECT c.*, a.run_id, a.assignment_id FROM outcome_candidates AS c "
                    "JOIN attempts AS a USING(attempt_id) WHERE c.candidate_id = ?",
                    (str(candidate.entity_id),),
                ).fetchone()
                if row is None:
                    from todo_orchestrator.verification.acceptance import CandidateNotFoundError
                    raise CandidateNotFoundError("candidate was not found")
                target = EntityRef(
                    self.project.project_id, EntityKind.WORK_ITEM,
                    StableId(row["work_item_id"]), StableId(row["definition_revision_id"]),
                )
                attempt = EntityRef(self.project.project_id, EntityKind.ATTEMPT, StableId(row["attempt_id"]))
                run = None if row["run_id"] is None else EntityRef(
                    self.project.project_id, EntityKind.RUN, StableId(row["run_id"])
                )
                assignment = None if row["assignment_id"] is None else EntityRef(
                    self.project.project_id, EntityKind.ASSIGNMENT, StableId(row["assignment_id"])
                )
                try:
                    self._authorize_exact_action(connection, AUTHORITY_READ_ACTION, self.project.ref)
                except CapabilityDeniedError:
                    self._authorize_exact_action(
                        connection, OUTCOME_REPORT_ACTION, target,
                        run=run, assignment=assignment, attempt=attempt,
                    )
                source = json.loads(row["report_source_json"])
                return CandidateReportView(
                    candidate, attempt, target, OutcomeDisposition(row["disposition"]), row["note"],
                    row["state"], EntityRef(
                        self.project.project_id, EntityKind.ACTOR, StableId(row["reported_by_actor_id"]),
                        incarnation_id=StableId(row["reported_by_incarnation_id"]),
                    ), Sha256Digest(source["source_digest"]),
                    datetime.fromisoformat(row["reported_at"]).astimezone(timezone.utc),
                )

    def _authorize_exact_action(self, connection, action: StableId, scope: EntityRef, *,
                                run: EntityRef | None = None,
                                assignment: EntityRef | None = None,
                                attempt: EntityRef | None = None) -> None:
        digest = _token_digest(self._bearer_token)
        row = connection.execute(
            "SELECT c.actor_id, c.actor_incarnation_id FROM capability_tokens AS t "
            "JOIN capabilities AS c USING (capability_id) WHERE t.token_digest = ?",
            (digest,),
        ).fetchone()
        from todo_orchestrator.authority.auth import AuthenticationFailedError
        if row is None:
            raise AuthenticationFailedError("bearer token is unknown")
        actor = EntityRef(
            self.project.project_id, EntityKind.ACTOR, StableId(row["actor_id"]),
            incarnation_id=StableId(row["actor_incarnation_id"]),
        )
        self._services.auth._authorize_capability(
            connection, self.project, digest, actor,
            AuthorizationRequirement(action, scope, run, assignment, attempt),
        )

    def accept(self, attempt_ref: EntityRef | StableId, candidate_ref: EntityRef | StableId, *,
               idempotency_key: StableId, expected_revision: int | None = None) -> ApiReceiptV1:
        outcomes = self._required(self._services.outcomes, "host_and_source_observer")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        candidate = candidate_ref if isinstance(candidate_ref, EntityRef) else self.outcome_ref(candidate_ref)
        with self._writer() as authority:
            result = outcomes.accept_candidate(authority, self._bearer_token, attempt, candidate,
                                               idempotency_key=idempotency_key,
                                               expected_revision=expected_revision)
        return ApiReceiptV1.from_result(result)

    def reject(self, attempt_ref: EntityRef | StableId, candidate_ref: EntityRef | StableId, *,
               idempotency_key: StableId, expected_revision: int | None = None) -> ApiReceiptV1:
        outcomes = self._required(self._services.outcomes, "host_and_source_observer")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        candidate = candidate_ref if isinstance(candidate_ref, EntityRef) else self.outcome_ref(candidate_ref)
        with self._writer() as authority:
            result = outcomes.reject_candidate(authority, self._bearer_token, attempt, candidate,
                                               idempotency_key=idempotency_key,
                                               expected_revision=expected_revision)
        return ApiReceiptV1.from_result(result)

    def finish(self, attempt_ref: EntityRef | StableId, lease_id: StableId | str, *,
               idempotency_key: StableId, expected_revision: int | None = None) -> ApiReceiptV1:
        coordination = self._required(self._services.attempts, "attempt_host")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        lease = lease_id if isinstance(lease_id, StableId) else StableId(lease_id)
        with self._writer() as authority:
            result = self._services.coordination.finish(
                authority, self._bearer_token, attempt, lease,
                idempotency_key=idempotency_key, expected_revision=expected_revision,
            )
        return ApiReceiptV1.from_result(result)

    def inspect_attempt(self, attempt_ref: EntityRef | StableId) -> RecoveryInspection:
        inspection = self._required(self._services.inspection, "attempt_host")
        attempt = attempt_ref if isinstance(attempt_ref, EntityRef) else self.attempt_ref(attempt_ref)
        with self._reader() as authority:
            return inspection.inspect_attempt(authority, self._bearer_token, attempt)

    def inspect_effect(self, operation_ref: EntityRef | StableId) -> RecoveryInspection:
        inspection = self._required(self._services.inspection, "attempt_host")
        operation = operation_ref if isinstance(operation_ref, EntityRef) else self.ref(EntityKind.EXTERNAL_OPERATION, operation_ref)
        with self._reader() as authority:
            return inspection.inspect_effect(authority, self._bearer_token, operation)

    def apply_recovery(self, intent: RecoveryIntent, *, idempotency_key: StableId,
                       expected_revision: int | None = None):
        recovery = self._required(self._services.recovery, "attempt_host_and_recovery_apply")
        if isinstance(intent, str):
            from .serialization import recovery_intent_from_json
            intent = recovery_intent_from_json(intent)
        if not isinstance(intent, RecoveryIntent):
            raise TypeError("intent must be a typed RecoveryIntent or its canonical JSON document")
        with self._writer() as authority:
            return recovery.apply(authority, self._bearer_token, intent,
                                  idempotency_key=idempotency_key,
                                  expected_revision=expected_revision)

    def close_run(self, run_ref: EntityRef | StableId, schedule_digest: Sha256Digest, *,
                  idempotency_key: StableId, expected_revision: int) -> ApiReceiptV1:
        run = run_ref if isinstance(run_ref, EntityRef) else self.run_ref(run_ref)
        with self._writer() as authority:
            result = self._services.lifecycle.close_run(
                authority, self._bearer_token, run, schedule_digest=schedule_digest,
                idempotency_key=idempotency_key, expected_revision=expected_revision,
            )
        return ApiReceiptV1.from_result(result)

    def retire_run(self, run_ref: EntityRef | StableId, schedule_digest: Sha256Digest, *,
                   idempotency_key: StableId, expected_revision: int,
                   successor_run: EntityRef | StableId | None = None,
                   handoffs: tuple[RunAssignmentHandoff, ...] = (),
                   unresolved: tuple[UnresolvedRunAssignment, ...] = ()) -> ApiReceiptV1:
        run = run_ref if isinstance(run_ref, EntityRef) else self.run_ref(run_ref)
        successor = None if successor_run is None else (
            successor_run if isinstance(successor_run, EntityRef) else self.run_ref(successor_run)
        )
        with self._writer() as authority:
            result = self._services.lifecycle.retire_run(
                authority, self._bearer_token, run, schedule_digest=schedule_digest,
                idempotency_key=idempotency_key, expected_revision=expected_revision,
                successor_run=successor, handoffs=handoffs, unresolved=unresolved,
            )
        return ApiReceiptV1.from_result(result)

    def build_context(self, work_item: StableId | EntityRef, *,
                      run_id: StableId | EntityRef | None = None,
                      assignment: StableId | EntityRef | None = None,
                      attempt: StableId | EntityRef | None = None,
                      max_bytes: int = 16 * 1024):
        target = self._selector_ref(work_item, EntityKind.WORK_ITEM)
        run = self._selector_ref(run_id, EntityKind.RUN)
        assignment_ref = self._selector_ref(assignment, EntityKind.ASSIGNMENT)
        attempt_ref = self._selector_ref(attempt, EntityKind.ATTEMPT)
        with self._reader() as authority:
            return self._services.context.build_context(
                authority, self._bearer_token, target, run=run,
                assignment=assignment_ref, attempt=attempt_ref, max_bytes=max_bytes,
            )

    def serialize(self, kind: str, value: object, *, max_bytes: int = 512 * 1024) -> str:
        return serialize_public_document(kind, value, max_bytes=max_bytes)

    def read_model(self, *, expected_revision: int | None = None) -> AuthorityReadModelV1:
        with self._reader() as authority:
            return self._services.export.read_model(authority, self._bearer_token,
                                                    expected_revision=expected_revision)

    def backup(self, destination: str | os.PathLike[str], *, expected_revision: int) -> AuthorityBackupResult:
        with self._reader() as authority:
            return self._services.export.backup(authority, self._bearer_token, destination,
                                                expected_revision=expected_revision)

__all__ = [
    "DEFAULT_OWNER_ACTIONS", "InitializationIncompleteError", "PlanPreviewMismatchError",
    "ProjectIdentityError", "ProjectUnavailableError", "TodoAuthenticationError",
    "TodoApplication", "TodoApplicationError", "TodoSession",
]
