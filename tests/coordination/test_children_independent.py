"""Public SQLite/Auth flows for restricted child execution."""

from datetime import timedelta
import unittest

from todo_orchestrator.authority.attempts import (
    AttemptTransitionError, CLAIM_ACTION, FINISH_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION,
)
from todo_orchestrator.authority.auth import AuthenticationFailedError, CapabilityDeniedError
from todo_orchestrator.contracts import EntityKind, EntityRef, OutcomeDisposition, ProviderIdentity, StableId
from todo_orchestrator.coordination.children import ChildExecutionDeniedError, ChildExecutionService
from todo_orchestrator.model import AttemptScopeSnapshot
from todo_orchestrator.model.children import (
    CHILD_CANDIDATE_SUBMIT_ACTION,
    CHILD_CANCEL_ACTION,
    CHILD_DELEGATE_ACTION,
    CHILD_READ_ACTION,
    CHILD_REVIEW_ACTION,
    CHILD_RETRY_ACTION,
    CHILD_STOP_RECONCILE_ACTION,
    CHILD_WRITE_ACTION,
    ChildCandidateDecision,
    ChildExecutionState,
)

from tests.verification import test_execution_independent as verification_fixture
from todo_orchestrator.verification.acceptance import (
    ACCEPT_OUTCOME_ACTION,
    REPORT_CANDIDATE_ACTION,
    CandidateDeniedError,
    OutcomeAcceptanceService,
)

OWNER_ACTIONS = verification_fixture.OWNER_ACTIONS
OWNER_PASSWORD = verification_fixture.OWNER_PASSWORD
PROJECT = verification_fixture.PROJECT


CHILD_ACTIONS = (
    CHILD_DELEGATE_ACTION,
    CHILD_RETRY_ACTION,
    CHILD_REVIEW_ACTION,
    CHILD_CANCEL_ACTION,
    CHILD_STOP_RECONCILE_ACTION,
    CHILD_READ_ACTION,
    CHILD_WRITE_ACTION,
    CHILD_CANDIDATE_SUBMIT_ACTION,
)
CHILD_WORKER_ACTIONS = (CHILD_READ_ACTION, CHILD_WRITE_ACTION, CHILD_CANDIDATE_SUBMIT_ACTION)


class ChildExecutionIndependentTests(unittest.TestCase):
    """Reuse the isolated plan/host fixture, with a real parent attempt."""

    def setUp(self):
        self.fixture = verification_fixture.IndependentVerificationExecutionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.work = self.work_ref("verify")
        context = next(item.context for item in self.plan.work_items
                       if item.definition.ref == self.work)
        self.parent_scope = AttemptScopeSnapshot(
            tuple((str(item["path"]), str(item["access"])) for item in context.scope["paths"]),
            tuple((str(item["name"]), str(item["mode"])) for item in context.scope["locks"]),
        )
        parent_actions = tuple(dict.fromkeys((
            *OWNER_ACTIONS,
            CLAIM_ACTION,
            FINISH_ACTION,
            HEARTBEAT_ACTION,
            RELEASE_ACTION,
            REPORT_CANDIDATE_ACTION,
            ACCEPT_OUTCOME_ACTION,
            *CHILD_ACTIONS,
        )))
        with self.open_writer() as authority:
            self.owner = self.auth.login_local_owner(
                authority,
                OWNER_PASSWORD,
                actions=parent_actions,
                scope=PROJECT.ref,
                expires_at=self.clock() + timedelta(hours=1),
                idempotency_key=StableId("c05-owner-token"),
                expected_revision=self.revision(),
            )
            self.parent_capability = self.auth.delegate(
                authority,
                self.owner.bearer_token,
                "worker-verify",
                actions=(CLAIM_ACTION, FINISH_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION,
                         REPORT_CANDIDATE_ACTION, ACCEPT_OUTCOME_ACTION, *CHILD_ACTIONS),
                scope=self.work,
                expires_at=self.clock() + timedelta(minutes=30),
                idempotency_key=StableId("c05-parent-capability"),
                expected_revision=self.revision(),
            )
        with self.open_writer() as authority:
            claim = self.attempts.claim(
                authority,
                self.parent_capability.bearer_token,
                self.work,
                self.plan,
                workspace_id=StableId("c05-parent-workspace"),
                idempotency_key=StableId("c05-parent-claim"),
                expected_revision=self.revision(),
            )
        self.parent_attempt = EntityRef(
            PROJECT.project_id,
            EntityKind.ATTEMPT,
            StableId(claim.receipt.result["attempt_id"]),
        )
        self.children = ChildExecutionService(self.auth, attempts=self.attempts)
        self.outcomes = OutcomeAcceptanceService(
            self.auth,
            source_observer=self.source,
            source_identity=verification_fixture.SOURCE_IDENTITY,
            host=self.host,
            host_identity=ProviderIdentity(StableId("v02-attempt-host"), "1"),
            clock=self.clock,
        )

    def __getattr__(self, name):
        fixture = self.__dict__.get("fixture")
        if fixture is not None and hasattr(fixture, name):
            return getattr(fixture, name)
        raise AttributeError(name)

    def child_scope(self, name="one"):
        return AttemptScopeSnapshot(((f"src/verify/{name}", "write"),), ())

    def start_child(self, *, execution_id="c05-child-one", logical_id="c05-logical-one",
                    scope=None, actions=CHILD_WORKER_ACTIONS, retry_of=None, key=None):
        with self.open_writer() as authority:
            return self.children.start_child(
                authority,
                self.parent_capability.bearer_token,
                self.parent_attempt,
                "worker-other",
                execution_id=StableId(execution_id),
                logical_id=StableId(logical_id),
                scope=scope or self.child_scope(),
                actions=tuple(actions),
                retry_of=None if retry_of is None else StableId(retry_of),
                idempotency_key=StableId(key or execution_id + "-start"),
                expected_revision=self.revision(),
            )

    def test_child_rights_are_attenuated_and_cannot_use_parent_attempt_authority(self):
        child = self.start_child()
        self.assertEqual(set(child.view.actions), set(CHILD_WORKER_ACTIONS))
        self.assertLess(set(child.view.actions), set(self.parent_capability.capability.actions))
        self.assertNotEqual(child.view.capability_id, self.parent_capability.capability.capability_id)
        self.assertEqual(child.view.parent_attempt, self.parent_attempt)
        self.assertEqual(child.view.target, self.work)

        before_sibling_conflict = self.state_snapshot()
        with self.assertRaises(ChildExecutionDeniedError):
            self.start_child(
                execution_id="c05-overlapping-sibling",
                logical_id="c05-overlapping-logical",
                scope=self.child_scope("one/nested"),
            )
        self.assertEqual(self.state_snapshot(), before_sibling_conflict)
        disjoint = self.start_child(
            execution_id="c05-disjoint-sibling",
            logical_id="c05-disjoint-logical",
            scope=self.child_scope("two"),
        )
        self.assertEqual(disjoint.view.state, ChildExecutionState.ACTIVE)
        read_only = self.start_child(
            execution_id="c05-read-only-child",
            logical_id="c05-read-only-logical",
            scope=AttemptScopeSnapshot((("src/verify/read-only", "read"),), ()),
            actions=(CHILD_READ_ACTION,),
        )
        self.assertEqual(read_only.view.actions, (CHILD_READ_ACTION,))
        self.assertNotIn(CHILD_WRITE_ACTION, read_only.view.actions)

        before = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.coordination.finish(
                    authority, child.bearer_token, self.parent_attempt,
                    self._parent_lease_id(), idempotency_key=StableId("c05-child-finish-denied"),
                    expected_revision=self.revision(),
                )
            with self.assertRaises(CapabilityDeniedError):
                self.attempts.claim(
                    authority, child.bearer_token, self.work, self.plan,
                    workspace_id=StableId("c05-child-cannot-claim"),
                    idempotency_key=StableId("c05-child-claim-denied"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.state_snapshot(), before)

        with self.assertRaises(ChildExecutionDeniedError):
            self.start_child(
                execution_id="c05-equal-scope",
                logical_id="c05-equal-scope-logical",
                scope=self.parent_scope,
            )
        with self.assertRaises(CapabilityDeniedError):
            self.start_child(
                execution_id="c05-action-escape",
                logical_id="c05-action-escape-logical",
                actions=(*CHILD_WORKER_ACTIONS, CLAIM_ACTION),
            )

    def test_candidate_review_is_separate_from_parent_outcome_and_native_occupancy(self):
        child = self.start_child()
        with self.open_writer() as authority:
            candidate = self.children.submit_candidate(
                authority, child.bearer_token, child.view.execution_id,
                candidate_id=StableId("c05-candidate-one"),
                summary="Implement the isolated change",
                idempotency_key=StableId("c05-candidate-submit"),
                expected_revision=self.revision(),
            )
        self.assertEqual(candidate.execution_id, child.view.execution_id)

        with self.open_writer() as authority:
            review = self.children.review_candidate(
                authority, self.parent_capability.bearer_token,
                child.view.execution_id, candidate.candidate_id,
                ChildCandidateDecision.ACCEPTED,
                review_id=StableId("c05-review-one"),
                idempotency_key=StableId("c05-review-key"),
                expected_revision=self.revision(),
            )
        self.assertEqual(review.decision, ChildCandidateDecision.ACCEPTED)
        self.assertEqual(self.read_child(child.view.execution_id).review.decision,
                         ChildCandidateDecision.ACCEPTED)

        # Child review is distinct from parent outcome authority. A child has
        # neither report nor accept rights; native child occupancy also blocks
        # an otherwise authorized parent candidate report under the writer.
        before_report = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(CandidateDeniedError):
                self.outcomes.report_candidate(
                    authority, self.parent_capability.bearer_token, self.parent_attempt,
                    OutcomeDisposition.COMPLETED,
                    idempotency_key=StableId("c05-parent-report-blocked"),
                    expected_revision=self.revision(),
                )
            with self.assertRaises(CapabilityDeniedError):
                self.outcomes.report_candidate(
                    authority, child.bearer_token, self.parent_attempt,
                    OutcomeDisposition.COMPLETED,
                    idempotency_key=StableId("c05-child-report-denied"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.state_snapshot(), before_report)

        # The injected host reports NONE; native child authority must still
        # block parent finish until a fresh stop reconciliation is recorded.
        before = self.state_snapshot()
        with self.open_writer() as authority:
            with self.assertRaises(AttemptTransitionError):
                self.coordination.finish(
                    authority, self.parent_capability.bearer_token,
                    self.parent_attempt, self._parent_lease_id(),
                    idempotency_key=StableId("c05-parent-finish-blocked"),
                    expected_revision=self.revision(),
                )
            with self.assertRaises(AttemptTransitionError):
                self.attempts.release(
                    authority, self.parent_capability.bearer_token,
                    self.parent_attempt, self._parent_lease_id(),
                    idempotency_key=StableId("c05-parent-release-blocked"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.state_snapshot(), before)
        with self.open_reader() as authority:
            self.assertEqual(authority.connection.execute(
                "SELECT count(*) FROM outcomes WHERE attempt_id = ?",
                (str(self.parent_attempt.entity_id),),
            ).fetchone()[0], 0)

        with self.open_writer() as authority:
            self.children.reconcile_stopped(
                authority, self.parent_capability.bearer_token,
                child.view.execution_id,
                idempotency_key=StableId("c05-child-stop"),
                expected_revision=self.revision(),
            )
        self.assertEqual(self.read_child(child.view.execution_id).state, ChildExecutionState.STOPPED)

    def test_cancel_restart_and_retry_preserve_logical_identity_and_revoke_old_token(self):
        first = self.start_child()
        old_child_expiry = first.view.expires_at
        self.clock.value += timedelta(minutes=1)
        with self.open_writer() as authority:
            heartbeat = self.attempts.heartbeat(
                authority, self.parent_capability.bearer_token, self.parent_attempt,
                self._parent_lease_id(), self.plan,
                idempotency_key=StableId("c05-parent-heartbeat"),
                expected_revision=self.revision(),
            )
        parent_expiry = self._parent_lease_expiry()
        renewed_child = self.read_child(first.view.execution_id)
        self.assertGreater(renewed_child.expires_at, old_child_expiry)
        self.assertLessEqual(renewed_child.expires_at, parent_expiry)
        self.assertEqual(renewed_child.expires_at, parent_expiry)
        self.assertEqual(heartbeat.receipt.result["lease_expires_at"], parent_expiry.isoformat(timespec="microseconds"))

        with self.open_writer() as authority:
            self.children.request_cancel(
                authority, self.parent_capability.bearer_token, first.view.execution_id,
                cancellation_id=StableId("c05-cancel-one"),
                idempotency_key=StableId("c05-cancel-key"),
                expected_revision=self.revision(),
            )

        reopened_children = ChildExecutionService(self.auth, attempts=self.attempts)
        with self.open_reader() as authority:
            persisted = reopened_children.read_execution(
                authority, self.parent_capability.bearer_token, first.view.execution_id,
            )
        self.assertEqual(persisted.state, ChildExecutionState.CANCEL_REQUESTED)
        before_stop = self.state_snapshot()
        with self.open_reader() as authority:
            self.assertEqual(reopened_children.read_execution(
                authority, self.parent_capability.bearer_token, first.view.execution_id,
            ).logical_id, StableId("c05-logical-one"))
        self.assertEqual(self.state_snapshot(), before_stop)
        with self.open_writer() as authority:
            with self.assertRaises(AttemptTransitionError):
                self.coordination.finish(
                    authority, self.parent_capability.bearer_token,
                    self.parent_attempt, self._parent_lease_id(),
                    idempotency_key=StableId("c05-finish-canceled-child"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.state_snapshot(), before_stop)

        with self.open_writer() as authority:
            reopened_children.reconcile_stopped(
                authority, self.parent_capability.bearer_token, first.view.execution_id,
                idempotency_key=StableId("c05-stop-canceled"),
                expected_revision=self.revision(),
            )
        second = self.start_child(
            execution_id="c05-child-two", logical_id="c05-logical-one",
            retry_of="c05-child-one", key="c05-child-two-start",
        )
        self.assertEqual(second.view.logical_id, first.view.logical_id)
        self.assertEqual(second.view.ordinal, first.view.ordinal + 1)
        self.assertNotEqual(second.view.execution_id, first.view.execution_id)
        self.assertNotEqual(second.view.capability_id, first.view.capability_id)
        with self.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                reopened_children.submit_candidate(
                    authority, first.bearer_token, first.view.execution_id,
                    candidate_id=StableId("c05-stale-token-candidate"),
                    summary="stale token must not be reusable",
                    idempotency_key=StableId("c05-stale-token-submit"),
                    expected_revision=self.revision(),
                )

        with self.open_writer() as authority:
            reopened_children.request_cancel(
                authority, self.parent_capability.bearer_token, second.view.execution_id,
                cancellation_id=StableId("c05-cancel-two"),
                idempotency_key=StableId("c05-cancel-two-key"),
                expected_revision=self.revision(),
            )
        with self.open_writer() as authority:
            reopened_children.reconcile_stopped(
                authority, self.parent_capability.bearer_token, second.view.execution_id,
                idempotency_key=StableId("c05-stop-two"),
                expected_revision=self.revision(),
            )
        third = self.start_child(
            execution_id="c05-child-three", logical_id="c05-logical-one",
            retry_of="c05-child-two", key="c05-child-three-start",
        )
        self.assertEqual(third.view.ordinal, 3)
        with self.open_writer() as authority:
            reopened_children.request_cancel(
                authority, self.parent_capability.bearer_token, third.view.execution_id,
                cancellation_id=StableId("c05-cancel-three"),
                idempotency_key=StableId("c05-cancel-three-key"),
                expected_revision=self.revision(),
            )
        with self.open_writer() as authority:
            reopened_children.reconcile_stopped(
                authority, self.parent_capability.bearer_token, third.view.execution_id,
                idempotency_key=StableId("c05-stop-three"),
                expected_revision=self.revision(),
            )
        before_retry_limit = self.state_snapshot()
        with self.assertRaises(ChildExecutionDeniedError) as denied:
            self.start_child(
                execution_id="c05-child-four", logical_id="c05-logical-one",
                retry_of="c05-child-three", key="c05-child-four-start",
            )
        self.assertIn("retry bound", str(denied.exception))
        self.assertEqual(self.state_snapshot(), before_retry_limit)

    def read_child(self, execution_id):
        with self.open_reader() as authority:
            return self.children.read_execution(
                authority, self.parent_capability.bearer_token, StableId(str(execution_id)),
            )

    def _parent_lease_id(self):
        with self.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_id FROM attempts WHERE attempt_id = ?",
                (str(self.parent_attempt.entity_id),),
            ).fetchone()
        return StableId(row[0])

    def _parent_lease_expiry(self):
        with self.open_reader() as authority:
            row = authority.connection.execute(
                "SELECT lease_expires_at FROM attempts WHERE attempt_id = ?",
                (str(self.parent_attempt.entity_id),),
            ).fetchone()
        from datetime import datetime
        return datetime.fromisoformat(row[0])
