"""Independent I04 checks for public external-provider boundaries."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from todo_orchestrator.api import (
    ProviderComposition,
    ProviderUnavailableError,
    TodoApplication,
    TodoAuthenticationError,
)
from todo_orchestrator.authority import CapabilityDeniedError, SQLiteAuthority
from todo_orchestrator.authority.auth import AuthenticationFailedError
from todo_orchestrator.contracts import (
    CommandObservation,
    EffectInspectionRequest,
    Project,
    ProviderIdentity,
    ProviderReceipt,
    ProviderResult,
    ProviderStatus,
    Sha256Digest,
    SourceObservation,
    StableId,
    provider_request_digest,
)
from todo_orchestrator.contracts.providers import (
    CommandExecutionInspection,
    CommandExecutionRequest,
    CommandInspectionState,
    ResourcePermitInspection,
    ResourcePermitInspectionState,
    ResourcePermitRef,
    ResourcePermitRelease,
    ResourcePermitReleaseRequest,
    ResourcePermitRequest,
)
from todo_orchestrator.model import ProcessLiveness
from todo_orchestrator.providers.git import GitRepositoryConfig
from todo_orchestrator.views.recovery import RecoveryIntentKind, RecoveryOperationStatus

from tests.verification.test_git_independent import TemporaryGitRepository


NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
OWNER_CREDENTIAL = "I04 disposable provider fixture credential 953"
COMMAND_IDENTITY = ProviderIdentity(StableId("i04-command-provider"), "1")
RESOURCE_IDENTITY = ProviderIdentity(StableId("i04-resource-provider"), "1")
COMMAND_OUTPUT = "I04-SECRET-RAW-COMMAND-OUTPUT-must-never-persist"
COMMAND_OUTPUT_DIGEST = Sha256Digest(hashlib.sha256(COMMAND_OUTPUT.encode()).hexdigest())
RESOURCE_PERMIT_ID = StableId("I04-SECRET-RAW-RESOURCE-PERMIT-must-not-appear-in-events")


class FixedClock:
    def __init__(self, value: datetime = NOW):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class StoppedProcessObserver:
    def inspect(self, attempt):
        return ProcessLiveness.STOPPED


class EmptyChildObserver:
    def inspect(self, attempt):
        from todo_orchestrator.model import ChildActivity
        return ChildActivity.NONE


def _command_plan(project: Project, *, targets: tuple[str, ...] = ("verify",)) -> str:
    work_items = []
    requirements = []
    for target in targets:
        requirement_id = f"check-{target}"
        work_items.append({
            "id": target,
            "title": f"Verify {target}",
            "objective": "Exercise an authored command contract through the external provider port",
            "outcome": "A durable verification receipt records the authored command result",
            "scope": {"paths": [], "concepts": [target], "locks": []},
            "ownership": {"mode": "any", "actors": []},
            "requirement_groups": [{"kind": "check", "mode": "all", "members": [requirement_id]}],
            "acceptance": {
                "assertions": ["the exact command request is provider-bound"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
        })
        requirements.append({
            "id": requirement_id,
            "work_item_id": target,
            "kind": "check",
            "description": "Run the accepted command contract",
            "check_key": requirement_id,
            "verification": {
                "kind": "command",
                "version": 1,
                "config": {
                    "argv": ["trusted-check", "--format", "summary"],
                    "cwd": "src",
                    "timeout_seconds": 17,
                    "expected_exit_codes": [0],
                },
            },
            "required_evidence": [{
                "name": f"{target}-report", "kind": "command_result", "version": 1,
            }],
        })
    document = {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "i04-command-provider-test",
        "project": {
            "project_id": str(project.project_id),
            "authority_id": str(project.authority_id),
        },
        "work_items": work_items,
        "requirements": requirements,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


class LedgerCommandProvider:
    """Small persistent provider ledger for process-reopen and no-replay checks."""

    def __init__(self, path: Path, clock: FixedClock, *, execute_mode: str = "complete",
                 inspect_mode: str = "ledger"):
        self.path = path
        self.clock = clock
        self.execute_mode = execute_mode
        self.inspect_mode = inspect_mode

    def _read(self) -> dict[str, object]:
        if not self.path.exists():
            return {"execute_calls": [], "inspect_calls": [], "effects": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, value: dict[str, object]) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)

    @staticmethod
    def _receipt_value(receipt: ProviderReceipt) -> dict[str, str]:
        return {
            "receipt_id": str(receipt.receipt_id),
            "provider_id": str(receipt.provider.provider_id),
            "provider_version": receipt.provider.version,
            "provider_contract_version": str(receipt.provider.contract_version),
            "correlation_id": str(receipt.correlation_id),
            "request_digest": receipt.request_digest.hex,
            "provenance_ref": str(receipt.provenance_ref),
            "observed_at": receipt.observed_at.isoformat(),
        }

    @staticmethod
    def _request_value(request: CommandExecutionRequest) -> dict[str, object]:
        return {
            "operation_id": str(request.operation_id),
            "request_digest": provider_request_digest(request).hex,
            "expected_source": request.expected_source.hex,
            "expected_authority_revision": request.expected_authority_revision,
            "tool_id": str(request.tool_id),
            "argv": list(request.argv),
            "timeout_ms": request.timeout_ms,
            "workspace_id": None if request.workspace_id is None else str(request.workspace_id),
            "cwd": request.cwd,
            "stdout_digest": COMMAND_OUTPUT_DIGEST.hex,
            "started_at": NOW.isoformat(),
            "completed_at": NOW.isoformat(),
            "receipt": None,
        }

    @staticmethod
    def _observation(value: dict[str, object]) -> CommandObservation:
        return CommandObservation(
            StableId(value["operation_id"]), 0, False,
            datetime.fromisoformat(value["started_at"]),
            datetime.fromisoformat(value["completed_at"]),
            Sha256Digest(value["stdout_digest"]),
        )

    def _execution_receipt(self, value: dict[str, object]) -> ProviderReceipt:
        raw = value["receipt"]
        return ProviderReceipt(
            StableId(raw["receipt_id"]), COMMAND_IDENTITY, StableId(raw["correlation_id"]),
            Sha256Digest(raw["request_digest"]), StableId(raw["provenance_ref"]),
            datetime.fromisoformat(raw["observed_at"]),
        )

    def execute(self, request: CommandExecutionRequest) -> ProviderResult[CommandObservation]:
        ledger = self._read()
        ledger["execute_calls"].append(str(request.operation_id))
        if self.execute_mode == "unavailable":
            self._write(ledger)
            return ProviderResult(
                ProviderStatus.UNAVAILABLE, request.operation_id,
                reason_code=StableId("i04-command-unavailable"),
            )
        if self.execute_mode == "unknown":
            self._write(ledger)
            return ProviderResult(
                ProviderStatus.UNKNOWN, request.operation_id, COMMAND_IDENTITY,
                reason_code=StableId("i04-command-effect-unknown"),
            )

        value = self._request_value(request)
        receipt_correlation = (
            StableId("i04-wrong-correlation") if self.execute_mode == "mismatched-correlation"
            else request.operation_id
        )
        receipt = ProviderReceipt(
            StableId("i04-command-receipt-" + str(request.operation_id)),
            COMMAND_IDENTITY, receipt_correlation, provider_request_digest(request),
            request.operation_id, self.clock(),
        )
        value["receipt"] = self._receipt_value(receipt)
        if self.execute_mode != "mismatched-correlation":
            ledger["effects"][str(request.operation_id)] = value
        self._write(ledger)
        if self.execute_mode == "raise-after-effect":
            raise RuntimeError("fixture interruption after command effect")
        observation = self._observation(value)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, receipt_correlation, COMMAND_IDENTITY,
            observation, receipt,
        )

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[CommandExecutionInspection]:
        ledger = self._read()
        ledger["inspect_calls"].append(str(request.operation_id))
        self._write(ledger)
        if self.inspect_mode == "unknown":
            return ProviderResult(
                ProviderStatus.UNKNOWN, request.correlation_id, COMMAND_IDENTITY,
                reason_code=StableId("i04-command-inspection-unknown"),
            )
        effect = ledger["effects"].get(str(request.operation_id))
        if effect is None:
            state = (
                CommandInspectionState.RUNNING if self.inspect_mode == "running"
                else CommandInspectionState.NOT_STARTED
            )
            inspection = CommandExecutionInspection(request.operation_id, state)
        else:
            inspection = CommandExecutionInspection(
                request.operation_id, CommandInspectionState.COMPLETED,
                self._observation(effect), self._execution_receipt(effect),
            )
        receipt = ProviderReceipt(
            StableId("i04-command-inspection-receipt-" + str(request.correlation_id)),
            COMMAND_IDENTITY, request.correlation_id, provider_request_digest(request),
            request.operation_id, self.clock(),
        )
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.correlation_id, COMMAND_IDENTITY,
            inspection, receipt,
        )

    def counts(self) -> tuple[int, int]:
        ledger = self._read()
        return len(ledger["execute_calls"]), len(ledger["inspect_calls"])


class LedgerResourceProvider:
    """Typed external permit ledger; Todo receives no local capacity authority."""

    def __init__(self, clock: FixedClock):
        self.clock = clock
        self.permits: dict[StableId, ResourcePermitRef] = {}
        self.released: set[StableId] = set()
        self.reserve_requests: list[ResourcePermitRequest] = []
        self.release_requests: list[ResourcePermitReleaseRequest] = []
        self.inspection_requests: list[EffectInspectionRequest] = []

    def _receipt(self, correlation_id: StableId, request: object) -> ProviderReceipt:
        return ProviderReceipt(
            StableId(f"i04-resource-receipt-{correlation_id}"), RESOURCE_IDENTITY,
            correlation_id, provider_request_digest(request),
            request.operation_id, self.clock(),
        )

    def reserve(self, request: ResourcePermitRequest) -> ProviderResult[ResourcePermitRef]:
        self.reserve_requests.append(request)
        receipt = self._receipt(request.operation_id, request)
        assert request.scope_id is not None and request.lease_expires_at is not None
        permit = ResourcePermitRef(
            RESOURCE_PERMIT_ID, request.resource_class, request.scope_id, request.units,
            request.lease_expires_at, RESOURCE_IDENTITY, receipt.receipt_id,
        )
        self.permits[request.operation_id] = permit
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.operation_id, RESOURCE_IDENTITY, permit, receipt,
        )

    def release(self, request: ResourcePermitReleaseRequest) -> ProviderResult[ResourcePermitRelease]:
        self.release_requests.append(request)
        if self.permits.get(request.operation_id) != request.permit:
            # A release operation uses a distinct operation ID from its reserve;
            # resolve the stored permit by its opaque exact reference.
            if request.permit not in self.permits.values():
                return ProviderResult(
                    ProviderStatus.OBSERVED_FAILURE, request.operation_id, RESOURCE_IDENTITY,
                    reason_code=StableId("i04-resource-permit-not-found"),
                )
        receipt = self._receipt(request.operation_id, request)
        self.released.add(request.permit.permit_id)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.operation_id, RESOURCE_IDENTITY,
            ResourcePermitRelease(request.operation_id, request.permit.permit_id, True), receipt,
        )

    def inspect(self, request: EffectInspectionRequest) -> ProviderResult[ResourcePermitInspection]:
        self.inspection_requests.append(request)
        original_request = request.resource_permit_request
        if original_request is not None:
            operation_id = original_request.operation_id
        elif request.resource_permit_release_request is not None:
            operation_id = request.resource_permit_release_request.operation_id
        else:
            raise AssertionError("resource inspection must bind an exact permit request")
        permit = self.permits.get(operation_id)
        if permit is None:
            # A release operation inspects the permit carried by its exact request.
            release_request = request.resource_permit_release_request
            if release_request is not None:
                permit = release_request.permit
        state = (
            ResourcePermitInspectionState.RELEASED
            if permit is not None and permit.permit_id in self.released
            else ResourcePermitInspectionState.HELD
        )
        receipt = self._receipt(request.correlation_id, request)
        return ProviderResult(
            ProviderStatus.OBSERVED_SUCCESS, request.correlation_id, RESOURCE_IDENTITY,
            ResourcePermitInspection(request.operation_id, state, permit), receipt,
        )


class ExternalProviderIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-i04-provider-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _project(self, *, provider_mode="complete", inspection_mode="ledger",
                 token_lifetime=timedelta(days=1), targets=("verify",), resource_provider=None):
        clock = FixedClock()
        git_root = self.root / "git-fixture"
        git_root.mkdir()
        git_fixture = TemporaryGitRepository(git_root)
        project = Project(StableId("i04-provider-project"), StableId("i04-provider-authority"))
        repository_id = StableId("i04-provider-repository")
        provider = LedgerCommandProvider(
            self.root / "external-command-ledger.json", clock,
            execute_mode=provider_mode, inspect_mode=inspection_mode,
        )
        config = GitRepositoryConfig(
            project.project_id,
            repository_id,
            git_fixture.repository,
            self.root / "managed-workspaces",
            self.root / "provider-journal",
            StableId("refs/heads/main"),
            StableId("refs/heads/todo-integration"),
        )
        composition = ProviderComposition.local_git(
            config,
            process_observer=StoppedProcessObserver(),
            child_observer=EmptyChildObserver(),
            command_execution_provider=provider,
            command_execution_identity=COMMAND_IDENTITY,
            resource_permit_provider=resource_provider,
            resource_permit_identity=RESOURCE_IDENTITY if resource_provider is not None else None,
            clock=clock,
        )
        project_root = self.root / "project"
        project_root.mkdir()
        session = TodoApplication.initialize(
            project_root,
            project_id=project.project_id,
            repository_id=repository_id,
            authority_id=project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            providers=composition,
            token_lifetime=token_lifetime,
        )
        package = _command_plan(project, targets=targets)
        preview = session.preview_plan(package)
        session.commit_plan(package, preview, idempotency_key=StableId("i04-plan-commit"))
        return project, project_root, session, composition, provider, clock

    @staticmethod
    def _dispatch(session, target="verify"):
        workspace = StableId(f"i04-{target}-workspace")
        session.create_workspace(
            StableId(target), idempotency_key=StableId(f"i04-create-{target}-workspace"),
            workspace_id=workspace,
        )
        return session.dispatch(
            workspace, idempotency_key=StableId(f"i04-dispatch-{target}"),
            work_item=StableId(target),
        )

    def test_planning_without_providers_accepts_contract_and_missing_verifier_is_no_churn(self):
        project_root = self.root / "no-provider-project"
        project_root.mkdir()
        project = Project(StableId("i04-no-provider-project"), StableId("i04-no-provider-authority"))
        with TodoApplication.initialize(
            project_root,
            project_id=project.project_id,
            repository_id=StableId("i04-no-provider-repository"),
            authority_id=project.authority_id,
            owner_credential="I04 disposable no-provider planning credential 41",
            providers=ProviderComposition(),
        ) as session:
            package = _command_plan(project, targets=("planned-without-provider",))
            preview = session.preview_plan(package)
            self.assertFalse(preview.has_conflicts)
            committed = session.commit_plan(
                package, preview, idempotency_key=StableId("i04-no-provider-plan-commit")
            )
            before = session.read_model().semantic_revision

            with self.assertRaises(ProviderUnavailableError) as caught:
                session.verify(
                    StableId("unstarted-attempt"),
                    StableId("check-planned-without-provider"),
                    idempotency_key=StableId("i04-no-provider-verify"),
                )

            self.assertEqual(caught.exception.port, "verification_provider_and_source_observer")
            self.assertEqual(before, committed.semantic_revision)
            self.assertEqual(session.read_model().semantic_revision, before)

    def test_public_command_path_binds_authored_request_and_persists_only_digests(self):
        _project, _root, session, _composition, provider, _clock = self._project()
        with session:
            dispatched = self._dispatch(session)
            prepared_revision = session.read_model().semantic_revision
            view = session.verify(
                dispatched.attempt_ref,
                StableId("check-verify"),
                idempotency_key=StableId("i04-command-verify"),
            )

            self.assertEqual(view.state, "finalized")
            self.assertEqual(provider.counts(), (1, 0))
            ledger = json.loads((self.root / "external-command-ledger.json").read_text())
            self.assertEqual(len(ledger["effects"]), 1)
            effect = next(iter(ledger["effects"].values()))
            self.assertEqual(effect["argv"], ["trusted-check", "--format", "summary"])
            self.assertEqual(effect["cwd"], "src")
            self.assertEqual(effect["timeout_ms"], 17_000)
            self.assertEqual(effect["workspace_id"], "i04-verify-workspace")
            self.assertEqual(effect["expected_source"], view.source_digest.hex)
            self.assertEqual(effect["expected_authority_revision"], prepared_revision)
            # The persisted external-ledger entry was formed from the exact typed request.
            with session._reader() as authority:
                row = authority.connection.execute(
                    "SELECT request_json, observation_json FROM verification_attempts WHERE operation_id = ?",
                    (str(view.operation.entity_id),),
                ).fetchone()
                event_payloads = [
                    json.loads(item[0]) for item in authority.connection.execute(
                        "SELECT payload_json FROM authority_events ORDER BY semantic_revision, event_ordinal"
                    )
                ]
            request_json = json.loads(row["request_json"])
            self.assertEqual(request_json["contract"]["config"]["argv"], effect["argv"])
            self.assertEqual(request_json["contract"]["config"]["cwd"], effect["cwd"])
            self.assertEqual(request_json["workspace_id"], effect["workspace_id"])
            self.assertEqual(request_json["expected_authority_revision"], effect["expected_authority_revision"])
            observation = json.loads(row["observation_json"])
            self.assertEqual(observation["command_observation"]["stdout_digest"], COMMAND_OUTPUT_DIGEST.hex)
            encoded_events = json.dumps(event_payloads, sort_keys=True)
            self.assertNotIn(COMMAND_OUTPUT, encoded_events)
            self.assertNotIn(COMMAND_OUTPUT, json.dumps(observation, sort_keys=True))

    def test_attempt_session_verification_canonicalizes_source_input_order(self):
        _project, project_root, session, composition, provider, _clock = self._project()
        source_observer = composition.source_observer
        original_observe = source_observer.observe
        seen_input_orders = []

        def observe_reverse_sorted(request):
            result = original_observe(request)
            if result.status is not ProviderStatus.OBSERVED_SUCCESS or result.value is None:
                return result
            source = result.value
            inputs = tuple(sorted(source.inputs, key=lambda item: str(item.name), reverse=True))
            seen_input_orders.append(tuple(str(item.name) for item in inputs))
            return ProviderResult(
                result.status, result.correlation_id, result.provider,
                SourceObservation(
                    source.repository_id, source.source_digest, source.base_digest,
                    source.working_tree, inputs, source.artifacts, source.source_revision,
                ),
                result.receipt,
            )

        with session:
            dispatched = self._dispatch(session)
            with patch.object(source_observer, "observe", side_effect=observe_reverse_sorted):
                with TodoApplication.open(
                    project_root, bearer_token=dispatched.bearer_token, providers=composition,
                ) as attempt_session:
                    operation = attempt_session.verify(
                        dispatched.attempt_ref.entity_id, StableId("check-verify"),
                        idempotency_key=StableId("i04-derived-command-verify-input-order"),
                    )

        self.assertEqual(operation.state, "finalized")
        self.assertEqual(provider.counts(), (1, 0))
        self.assertGreaterEqual(len(seen_input_orders), 2)
        for inputs in seen_input_orders:
            self.assertGreater(len(inputs), 1)
            self.assertEqual(inputs, tuple(sorted(inputs, reverse=True)))

    def test_ambiguous_command_is_inspected_after_reopen_without_blind_retry(self):
        _project, project_root, session, composition, provider, clock = self._project(
            provider_mode="raise-after-effect",
        )
        dispatched = self._dispatch(session)
        interrupted = session.verify(
            dispatched.attempt_ref, StableId("check-verify"),
            idempotency_key=StableId("i04-command-interrupted"),
        )
        self.assertEqual(interrupted.state, "unknown")
        counts_before_reopen = provider.counts()
        self.assertEqual(counts_before_reopen[0], 1)
        token = session.bearer_token
        session.close()

        restarted_provider = LedgerCommandProvider(
            self.root / "external-command-ledger.json", clock,
            execute_mode="complete", inspect_mode="ledger",
        )
        restarted_composition = ProviderComposition(
            attempt_host=composition.attempt_host,
            host_identity=composition.host_identity,
            source_observer=composition.source_observer,
            source_identity=composition.source_identity,
            command_execution_provider=restarted_provider,
            command_execution_identity=COMMAND_IDENTITY,
            git_provider=composition.git_provider,
            clock=clock,
        )
        with TodoApplication.open(project_root, bearer_token=token, providers=restarted_composition) as reopened:
            inspection = reopened.inspect_effect(interrupted.operation)
            self.assertEqual(len(inspection.operations), 1)
            operation = inspection.operations[0]
            self.assertEqual(operation.status, RecoveryOperationStatus.EFFECT_OBSERVED)
            self.assertEqual(operation.verification_inspection.state.value, "completed")
            self.assertTrue(any(
                intent.kind is RecoveryIntentKind.RECONCILE_OBSERVED_EFFECT
                for intent in inspection.intents
            ))
            self.assertFalse(any(
                intent.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION
                for intent in inspection.intents
            ))
        counts_after_reopen = restarted_provider.counts()
        self.assertEqual(counts_after_reopen[0], 1)
        self.assertEqual(counts_after_reopen[1], counts_before_reopen[1] + 1)

    def test_mismatch_unavailable_and_unknown_inspection_do_not_offer_retry(self):
        _project, _project_root, session, _composition, provider, _clock = self._project(
            provider_mode="mismatched-correlation", inspection_mode="unknown",
            targets=("verify", "unavailable"),
        )
        with session:
            dispatched = self._dispatch(session)
            view = session.verify(
                dispatched.attempt_ref, StableId("check-verify"),
                idempotency_key=StableId("i04-command-mismatched"),
            )
            self.assertEqual(view.state, "unknown")
            self.assertIsNone(view.evidence_id)
            before_inspection = provider.counts()
            inspection = session.inspect_effect(view.operation)
            self.assertEqual(provider.counts(), (before_inspection[0], before_inspection[1] + 1))
            self.assertEqual(inspection.operations[0].status, RecoveryOperationStatus.UNCERTAIN)
            self.assertFalse(any(
                intent.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION
                for intent in inspection.intents
            ))

            provider.execute_mode = "unavailable"
            second_attempt = self._dispatch(session, "unavailable")
            second_view = session.verify(
                second_attempt.attempt_ref, StableId("check-unavailable"),
                idempotency_key=StableId("i04-command-unavailable"),
            )
            self.assertEqual(second_view.state, "unknown")
            unavailable_inspection = session.inspect_effect(second_view.operation)
            self.assertEqual(
                unavailable_inspection.operations[0].status, RecoveryOperationStatus.UNCERTAIN,
            )
            self.assertFalse(any(
                intent.kind is RecoveryIntentKind.RETRY_ORIGINAL_OPERATION
                for intent in unavailable_inspection.intents
            ))

    def test_expired_current_bearer_is_refused_before_external_command_execution(self):
        _project, project_root, session, composition, provider, clock = self._project(
            token_lifetime=timedelta(seconds=30),
        )
        dispatched = self._dispatch(session)
        token = session.bearer_token
        revision_before = session.read_model().semantic_revision
        clock.value += timedelta(seconds=31)

        with self.assertRaises((TodoAuthenticationError, CapabilityDeniedError, AuthenticationFailedError)):
            session.verify(
                dispatched.attempt_ref, StableId("check-verify"),
                idempotency_key=StableId("i04-expired-command-verify"),
            )
        with self.assertRaises(TodoAuthenticationError):
            TodoApplication.open(project_root, bearer_token=token, providers=composition)
        with SQLiteAuthority.open_reader(
            project_root / ".todo-orchestrator" / "authority.sqlite3",
            Project(StableId("i04-provider-project"), StableId("i04-provider-authority")),
        ) as authority:
            revision_after = authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
        self.assertEqual(revision_after, revision_before)
        self.assertEqual(provider.counts(), (0, 0))
        session.close()

    def test_resource_permit_reserve_inspect_release_keeps_event_payloads_digest_only(self):
        clock = FixedClock()
        provider = LedgerResourceProvider(clock)
        _project, _project_root, session, _composition, _command_provider, _clock = self._project(
            resource_provider=provider,
        )
        with session:
            dispatched = self._dispatch(session)
            revision_before_reserve = session.read_model().semantic_revision
            held = session.reserve_resource(
                dispatched.attempt_ref, "i04-resource-class", 2,
                idempotency_key=StableId("i04-resource-reserve"),
            )

            self.assertEqual(held.state.value, "held")
            self.assertEqual(held.resource_class, StableId("i04-resource-class"))
            self.assertEqual(held.units, 2)
            self.assertEqual(len(provider.reserve_requests), 1)
            request = provider.reserve_requests[0]
            self.assertEqual(request.attempt, dispatched.attempt_ref)
            self.assertEqual(request.expected_authority_revision, revision_before_reserve)
            self.assertEqual(held.permit_expires_at, request.lease_expires_at)
            self.assertEqual(
                held.permit_ref_digest,
                hashlib.sha256(str(RESOURCE_PERMIT_ID).encode("ascii")).hexdigest(),
            )
            self.assertNotIn(str(RESOURCE_PERMIT_ID), repr(held))
            revision_before_inspect = session.read_model().semantic_revision

            inspected = session.inspect_resource(held.operation_id)

            self.assertEqual(inspected.inspection_state, ResourcePermitInspectionState.HELD)
            self.assertEqual(session.read_model().semantic_revision, revision_before_inspect)
            self.assertEqual(len(provider.inspection_requests), 1)
            released = session.release_resource(
                held.operation_id, idempotency_key=StableId("i04-resource-release"),
            )

            self.assertEqual(released.state.value, "released")
            self.assertEqual(len(provider.release_requests), 1)
            self.assertEqual(provider.release_requests[0].permit, provider.permits[request.operation_id])
            with session._reader() as authority:
                event_payloads = [
                    json.loads(row[0]) for row in authority.connection.execute(
                        "SELECT payload_json FROM authority_events ORDER BY semantic_revision, event_ordinal"
                    )
                ]
                tables = {
                    row[0] for row in authority.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            encoded_events = json.dumps(event_payloads, sort_keys=True)
            self.assertNotIn(str(RESOURCE_PERMIT_ID), encoded_events)
            self.assertIn("resource_permit_operations", tables)
            self.assertNotIn("resource_capacity", tables)
            self.assertNotIn("resource_ownership", tables)


if __name__ == "__main__":
    unittest.main()
