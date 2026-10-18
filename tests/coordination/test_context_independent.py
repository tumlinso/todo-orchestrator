"""Independent public-flow tests for bounded, versioned worker context."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AttemptService, AuthorityAuthService, CapabilityDeniedError, CommandDispatcher, SQLiteAuthority,
)
from todo_orchestrator.authority.auth import AuthenticatedPrincipal
from todo_orchestrator.contracts import (
    ActorKind, EntityKind, EntityRef, Project, Sha256Digest, StableId,
)
from todo_orchestrator.contracts.providers import ProviderIdentity, ProviderReceipt
from todo_orchestrator.coordination.context import (
    CONTEXT_FINDING_INVALIDATE_ACTION, CONTEXT_FINDING_PUBLISH_ACTION, CONTEXT_READ_ACTION,
    ContextFindingConflictError,
    ContextService, serialize_context_capsule,
)
from todo_orchestrator.coordination.service import (
    CoordinationService, RUN_DISPATCH_ACTION, RUN_SCHEDULE_ACTION,
)
from todo_orchestrator.model.coordination import (
    LaneSpec, QueuePolicy, RunCharter, RunSchedule, ScheduledWork,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation, ChildActivity, ProcessLiveness, QualifiedDestination,
    QualifiedSourceRevision, SourceSafety, WorkspaceQualification,
)
from todo_orchestrator.planning import PlanService
from todo_orchestrator.model.context import (
    ContextCapsuleStatus, ContextChangeKind, ContextExpansionStatus, ContextFragmentKind,
)


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("context-project"), StableId("context-authority"))
OWNER_PASSWORD = "context fixture owner password 82"
PLAN_COMMIT = StableId("todo.plan.commit")
CLAIM_ACTION = StableId("todo.attempt.claim")
DELEGATE_ACTION = StableId("todo.capability.delegate")
HEARTBEAT_ACTION = StableId("todo.attempt.heartbeat")
RELEASE_ACTION = StableId("todo.attempt.release")
FINISH_ACTION = StableId("todo.attempt.finish")
CONTEXT_ACTIONS = (
    CONTEXT_READ_ACTION, CONTEXT_FINDING_PUBLISH_ACTION, CONTEXT_FINDING_INVALIDATE_ACTION,
)


class Clock:
    def __call__(self):
        return NOW


class Authenticator:
    provider_id = "context-test-provider"

    def authenticate(self, credential):
        actors = {
            "worker-a": AuthenticatedPrincipal("worker-a", ActorKind.AUTOMATION, "worker A"),
            "worker-b": AuthenticatedPrincipal("worker-b", ActorKind.AUTOMATION, "worker B"),
            "context-observer": AuthenticatedPrincipal("context-observer", ActorKind.SERVICE, "context observer"),
        }
        return actors.get(credential)


class Host:
    def qualify_workspace(self, workspace_id, target, correlation_id):
        provider = ProviderIdentity(StableId("context-host"), "1")
        repository = StableId("context-repository")
        base = QualifiedSourceRevision(PROJECT.project_id, repository, StableId("base"), "a" * 64)
        receipt = ProviderReceipt(
            StableId("context-qual-" + hashlib.sha256(str(correlation_id).encode()).hexdigest()[:12]),
            provider, correlation_id, Sha256Digest("b" * 64), base.ref, NOW,
        )
        return WorkspaceQualification(
            workspace_id, repository, base,
            QualifiedDestination(PROJECT.project_id, repository, StableId("main")), receipt,
        )

    def inspect_attempt(self, attempt, workspace):
        receipt = ProviderReceipt(
            StableId("context-inspect-" + hashlib.sha256(str(attempt.attempt_id).encode()).hexdigest()[:12]),
            ProviderIdentity(StableId("context-host"), "1"), attempt.attempt_id,
            Sha256Digest("c" * 64), workspace.common_base.ref, NOW,
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


def package_json():
    items = []
    for name in ("alpha", "beta"):
        items.append({
            "id": name, "title": name.title(), "objective": f"Deliver {name}",
            "outcome": f"{name} complete",
            "scope": {"paths": [{"path": f"src/{name}", "access": "write"}], "concepts": [], "locks": []},
            "acceptance": {"assertions": ["complete"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
            "references": [{"label": "specification", "uri": f"docs/{name}.md"}],
        })
    return json.dumps({
        "format": "todo-orchestrator.plan", "schema_version": 1, "package_id": "context-flow",
        "project": {"project_id": str(PROJECT.project_id), "authority_id": str(PROJECT.authority_id)},
        "work_items": items,
    }, sort_keys=True)


class ContextFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "context.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.clock = Clock()
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(self.dispatcher, clock=self.clock, authenticator=Authenticator())
        actions = (
            PLAN_COMMIT, RUN_SCHEDULE_ACTION, RUN_DISPATCH_ACTION, CLAIM_ACTION,
            HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION, DELEGATE_ACTION, *CONTEXT_ACTIONS,
        )
        with self.writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="owner", idempotency_key=StableId("context-enroll"),
                expected_revision=0,
            )
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD, actions=actions, scope=PROJECT.ref,
                expires_at=NOW + timedelta(days=1), idempotency_key=StableId("context-owner"),
                expected_revision=enrollment.receipt.semantic_revision,
            )
        self.plans = PlanService(self.auth)
        self.host = Host()
        self.attempts = AttemptService(self.auth, host=self.host, clock=self.clock)
        self.coordination = CoordinationService(self.auth, attempts=self.attempts)
        self.package = package_json()
        with self.writer() as authority:
            preview = self.plans.preview(authority, self.package)
            self.plans.commit(
                authority, self.owner.bearer_token, self.package, reviewed_digest=preview.digest,
                idempotency_key=StableId("context-plan-commit"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            self.plan = self.plans.load_accepted_plan(authority)
        self.work = {str(item.definition.work_item_id): item.definition.ref for item in self.plan.work_items}
        run_id = StableId("context-run")
        self.run = EntityRef(PROJECT.project_id, EntityKind.RUN, run_id)
        workers = {}
        for label in ("a", "b"):
            with self.writer() as authority:
                workers[label] = self.auth.delegate(
                    authority, self.owner.bearer_token, f"worker-{label}",
                    actions=(RUN_DISPATCH_ACTION, CLAIM_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION,
                             *CONTEXT_ACTIONS),
                    scope=self.plan.revision.ref, expires_at=NOW + timedelta(hours=4),
                    idempotency_key=StableId(f"context-dispatch-worker-{label}"), expected_revision=self.revision(),
                )
        schedule = RunSchedule(
            run_id, self.plan.revision.ref,
            (LaneSpec(StableId("parallel"), QueuePolicy.PARALLEL),),
            tuple(ScheduledWork(self.work[name], StableId("parallel"), workers[label].capability.actor)
                  for name, label in (("alpha", "a"), ("beta", "b"))),
            RunCharter("Build bounded context", ("Use current source refs",), ("Context stays scoped",)),
        )
        with self.writer() as authority:
            self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, schedule,
                idempotency_key=StableId("context-run-open"), expected_revision=self.revision(),
            )
        self.dispatches = {}
        with self.reader() as authority:
            view = self.coordination.read_run(authority, run_id)
        for label, name in (("a", "alpha"), ("b", "beta")):
            entry = next(item for item in view.entries if item.assignment.work_item == self.work[name])
            with self.writer() as authority:
                dispatch = self.coordination.dispatch(
                    authority, workers[label].bearer_token, self.plan,
                    workspace_id=StableId(f"context-workspace-{label}"),
                    idempotency_key=StableId(f"context-dispatch-{label}"), expected_revision=self.revision(),
                    work_item=self.work[name], run=self.run, assignment=entry.assignment.ref,
                )
            self.dispatches[label] = (dispatch, entry.assignment.ref)
        self.service = ContextService(self.auth, clock=self.clock)
        self.worker_contexts = {label: dispatch for label, (dispatch, _assignment) in self.dispatches.items()}
        dispatch, assignment = self.dispatches["a"]
        with self.writer() as authority:
            self.observer = self.auth.delegate(
                authority, self.owner.bearer_token, "context-observer",
                actions=(CONTEXT_READ_ACTION,), scope=self.work["alpha"],
                run=dispatch.attempt.run, assignment=assignment, attempt=dispatch.attempt.ref,
                expires_at=NOW + timedelta(hours=2),
                idempotency_key=StableId("context-observer-read-only"), expected_revision=self.revision(),
            )

    def writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    def revision(self):
        with self.reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def _context_args(self, label):
        dispatch, assignment = self.dispatches[label]
        return {
            "work_item": self.work["alpha" if label == "a" else "beta"],
            "run": dispatch.attempt.run,
            "assignment": assignment,
            "attempt": dispatch.attempt.ref,
        }

    def _build(self, label="a", **kwargs):
        args = self._context_args(label)
        args.update(kwargs)
        with self.reader() as authority:
            return self.service.build_context(
                authority, self.worker_contexts[label].bearer_token, **args,
            )

    def test_capsule_is_exactly_scoped_bounded_and_expansion_is_version_checked(self):
        args = self._context_args("a")
        capsule = self._build("a", max_bytes=65536)
        self.assertEqual(capsule.status, ContextCapsuleStatus.READY)
        self.assertEqual(capsule.manifest.work_item, args["work_item"])
        self.assertEqual(capsule.manifest.run, args["run"])
        self.assertEqual(capsule.manifest.assignment, args["assignment"])
        self.assertEqual(capsule.manifest.attempt, args["attempt"])
        self.assertEqual(capsule.manifest.plan_revision, self.plan.revision.ref)
        self.assertLessEqual(capsule.encoded_bytes, 65536)
        repeated = self._build("a", max_bytes=65536)
        self.assertEqual(repeated.manifest.digest, capsule.manifest.digest)
        self.assertEqual(repeated.manifest.fragments, capsule.manifest.fragments)
        source_fragment = next(item for item in capsule.fragments
                               if item.reference.kind is ContextFragmentKind.SOURCE_REFERENCES)
        self.assertIn("docs/alpha.md", source_fragment.payload_json)
        wire = serialize_context_capsule(capsule)
        self.assertEqual(len(wire.encode("utf-8")), capsule.encoded_bytes)
        for forbidden in ('"stdout"', '"stderr"', '"transcript"', '"message_body"'):
            self.assertNotIn(forbidden, wire)

        small = self._build("a", max_bytes=8000)
        self.assertLessEqual(len(serialize_context_capsule(small).encode("utf-8")), 8000)
        self.assertEqual(small.encoded_bytes, len(serialize_context_capsule(small).encode("utf-8")))
        self.assertEqual(small.status, ContextCapsuleStatus.PARTIAL)
        self.assertTrue(small.omitted)
        omitted = small.omitted[0]
        with self.reader() as authority:
            expanded = self.service.expand_fragment(
                authority, self.worker_contexts["a"].bearer_token, **args,
                fragment_id=omitted.fragment_id, expected_digest=omitted.digest,
                max_bytes=65536,
            )
        self.assertEqual(expanded.status, ContextExpansionStatus.READY)
        self.assertEqual(expanded.fragment.reference, omitted)
        revision_before_stale_expansion = self.revision()
        with self.reader() as authority:
            stale = self.service.expand_fragment(
                authority, self.worker_contexts["a"].bearer_token, **args,
                fragment_id=omitted.fragment_id, expected_digest=Sha256Digest("0" * 64),
                max_bytes=65536,
            )
        self.assertEqual(stale.status, ContextExpansionStatus.STALE)
        self.assertIsNone(stale.fragment)
        self.assertEqual(self.revision(), revision_before_stale_expansion)

    def test_exact_context_grant_cannot_read_another_assignment(self):
        beta = self._context_args("b")
        with self.reader() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.service.build_context(
                    authority, self.worker_contexts["a"].bearer_token, **beta,
                )

    def test_independent_observer_reads_exact_worker_context_without_mutation_rights(self):
        args = self._context_args("a")
        with self.reader() as authority:
            capsule = self.service.build_context(
                authority, self.observer.bearer_token, **args,
            )
        self.assertEqual(capsule.manifest.work_item, args["work_item"])
        self.assertEqual(capsule.manifest.attempt, args["attempt"])
        source_ref = next(item.reference for item in capsule.fragments
                          if item.reference.kind is ContextFragmentKind.SOURCE_REFERENCES)
        revision = self.revision()
        with self.writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.service.publish_finding(
                    authority, self.observer.bearer_token, args["work_item"],
                    "Observer read context only.", capsule.manifest, (source_ref,),
                    finding_id=StableId("context-observer-cannot-publish"),
                    expected_finding_version=None, run=args["run"], assignment=args["assignment"],
                    attempt=args["attempt"], idempotency_key=StableId("observer-publish-denied"),
                    expected_revision=revision,
                )
        self.assertEqual(self.revision(), revision)

    def test_findings_are_versioned_and_do_not_stale_their_own_source_manifest(self):
        initial = self._build("a", max_bytes=65536)
        work_fragment = next(
            item.reference for item in initial.fragments
            if item.reference.kind is ContextFragmentKind.SOURCE_REFERENCES
        )
        finding_id = StableId("context-finding-1")
        with self.writer() as authority:
            first = self.service.publish_finding(
                authority, self.worker_contexts["a"].bearer_token,
                summary="The current task scope is clear.", source_manifest=initial.manifest,
                source_fragments=(work_fragment,), finding_id=finding_id,
                expected_finding_version=None, **self._context_args("a"),
                idempotency_key=StableId("context-finding-v1"), expected_revision=self.revision(),
            )
        self.assertEqual(first.receipt.result["version"], 1)

        after_first = self._build("a", previous_manifest=initial.manifest, max_bytes=65536)
        self.assertEqual(after_first.manifest.source_digest, initial.manifest.source_digest)
        finding_delta = [change for change in after_first.changes
                         if change.current is not None and change.current.kind is ContextFragmentKind.FINDINGS]
        self.assertTrue(finding_delta)
        self.assertIn(finding_delta[0].kind, {ContextChangeKind.ADDED, ContextChangeKind.CHANGED})
        self.assertTrue(all(
            change.kind is ContextChangeKind.UNCHANGED
            or (change.current is not None and change.current.kind in {
                ContextFragmentKind.FINDINGS, ContextFragmentKind.SCOPED_DELTAS,
            })
            for change in after_first.changes
        ))

        with self.writer() as authority:
            second = self.service.publish_finding(
                authority, self.worker_contexts["a"].bearer_token,
                summary="The task scope remains clear after review.",
                source_manifest=after_first.manifest, source_fragments=(work_fragment,),
                finding_id=finding_id, expected_finding_version=1,
                **self._context_args("a"), idempotency_key=StableId("context-finding-v2"),
                expected_revision=self.revision(),
            )
        self.assertEqual(second.receipt.result["version"], 2)

        # A finding identity is bound to its original work/context. A different
        # scoped worker cannot move that identity into another work item's history.
        beta_capsule = self._build("b", max_bytes=65536)
        beta_source = next(
            item.reference for item in beta_capsule.fragments
            if item.reference.kind is ContextFragmentKind.SOURCE_REFERENCES
        )
        revision_before_cross_scope = self.revision()
        with self.writer() as authority:
            with self.assertRaises((ContextFindingConflictError, CapabilityDeniedError)):
                self.service.publish_finding(
                    authority, self.worker_contexts["b"].bearer_token,
                    summary="Attempted cross-work finding reuse.",
                    source_manifest=beta_capsule.manifest, source_fragments=(beta_source,),
                    finding_id=finding_id, expected_finding_version=2,
                    **self._context_args("b"),
                    idempotency_key=StableId("context-finding-cross-scope"),
                    expected_revision=revision_before_cross_scope,
                )
        self.assertEqual(self.revision(), revision_before_cross_scope)

        after_second = self._build("a", previous_manifest=after_first.manifest, max_bytes=65536)
        finding_change = next(change for change in after_second.changes
                              if change.current is not None and change.current.kind is ContextFragmentKind.FINDINGS)
        self.assertEqual(finding_change.kind, ContextChangeKind.CHANGED)
        finding_payload = json.loads(next(
            item.payload_json for item in after_second.fragments
            if item.reference.kind is ContextFragmentKind.FINDINGS
        ))
        self.assertIn("The task scope remains clear after review.", json.dumps(finding_payload))
        self.assertIn('"version":2', json.dumps(finding_payload, separators=(",", ":")))

        with self.writer() as authority:
            invalidated = self.service.invalidate_finding(
                authority, self.worker_contexts["a"].bearer_token,
                finding_id=finding_id, finding_version=2,
                reason="The task scope changed.", source_manifest=after_second.manifest,
                **self._context_args("a"), idempotency_key=StableId("context-finding-invalidate"),
                expected_revision=self.revision(),
            )
        self.assertEqual(invalidated.receipt.result["version"], 2)
        after_invalidation = self._build("a", previous_manifest=after_second.manifest, max_bytes=65536)
        self.assertTrue(any(change.kind is ContextChangeKind.CHANGED
                            and change.current is not None
                            and change.current.kind is ContextFragmentKind.FINDINGS
                            for change in after_invalidation.changes))
        invalidation_payload = json.loads(next(
            item.payload_json for item in after_invalidation.fragments
            if item.reference.kind is ContextFragmentKind.FINDINGS
        ))
        self.assertIn("The task scope changed.", json.dumps(invalidation_payload))

    def test_untrusted_context_notes_are_rejected_without_authority_churn(self):
        capsule = self._build("a", max_bytes=65536)
        fragment = next(item.reference for item in capsule.fragments
                        if item.reference.kind is ContextFragmentKind.SOURCE_REFERENCES)
        revision = self.revision()
        with self.writer() as authority:
            with self.assertRaises(ValueError):
                self.service.publish_finding(
                    authority, self.worker_contexts["a"].bearer_token,
                    summary="Authorization: Basic YWxpY2U6Y29ycmVjdGhvcnNlYmF0dGVyeXN0YXBsZQ==",
                    source_manifest=capsule.manifest, source_fragments=(fragment,),
                    finding_id=StableId("context-secret-finding"), expected_finding_version=None,
                    **self._context_args("a"), idempotency_key=StableId("context-secret-rejected"),
                    expected_revision=revision,
                )
        self.assertEqual(self.revision(), revision)


if __name__ == "__main__":
    unittest.main()
