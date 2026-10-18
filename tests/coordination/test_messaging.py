"""Public SQLite/authentication flows for durable scoped messaging."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.authority import (
    AttemptService, AuthorityAuthService, CapabilityDeniedError, CommandDispatcher, SQLiteAuthority,
)
from todo_orchestrator.authority.attempts import FINISH_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION
from todo_orchestrator.authority.auth import AuthenticatedPrincipal
from todo_orchestrator.contracts import (
    ActorKind, EntityKind, EntityRef, Project, Sha256Digest, StableId,
)
from todo_orchestrator.contracts.providers import ProviderIdentity, ProviderReceipt
from todo_orchestrator.coordination import (
    AnswerConflictError, CoordinationService, CursorError, LaneSpec, MessagingService,
    MessageScopeError, MessageType, PayloadRejectedError,
    QUESTION_ANSWER_ACTION, MESSAGE_READ_ACTION, MESSAGE_SEND_ACTION,
    QueuePolicy, RUN_DISPATCH_ACTION, RunCharter, RunSchedule, ScheduledWork,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation, ChildActivity, ProcessLiveness, QualifiedDestination,
    QualifiedSourceRevision, SourceSafety, WorkspaceQualification,
)
from todo_orchestrator.planning import PlanService, compile_plan_json


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT = Project(StableId("message-project"), StableId("message-authority"))
OWNER_PASSWORD = "message fixture owner password 82"
PLAN_COMMIT = StableId("todo.plan.commit")
SCHEDULE_ACTION = StableId("todo.run.schedule")
CLAIM_ACTION = StableId("todo.attempt.claim")
DELEGATE_ACTION = StableId("todo.capability.delegate")


class Clock:
    def __call__(self):
        return NOW


class Authenticator:
    provider_id = "messaging-test-provider"

    def authenticate(self, credential):
        actors = {
            "worker-a": AuthenticatedPrincipal("worker-a", ActorKind.AUTOMATION, "worker A"),
            "worker-b": AuthenticatedPrincipal("worker-b", ActorKind.AUTOMATION, "worker B"),
            "outsider": AuthenticatedPrincipal("outsider", ActorKind.SERVICE, "outsider"),
        }
        return actors.get(credential)


class Host:
    def qualify_workspace(self, workspace_id, target, correlation_id):
        provider = ProviderIdentity(StableId("message-host"), "1")
        base = QualifiedSourceRevision(PROJECT.project_id, StableId("message-repo"), StableId("base"), "a" * 64)
        receipt = ProviderReceipt(
            StableId("message-qual-" + hashlib.sha256(str(correlation_id).encode()).hexdigest()[:12]),
            provider, correlation_id, Sha256Digest("b" * 64), base.ref, NOW,
        )
        return WorkspaceQualification(
            workspace_id, StableId("message-repo"), base,
            QualifiedDestination(PROJECT.project_id, StableId("message-repo"), StableId("main")), receipt,
        )

    def inspect_attempt(self, attempt, workspace):
        receipt = ProviderReceipt(
            StableId("message-inspect-" + hashlib.sha256(str(attempt.attempt_id).encode()).hexdigest()[:12]),
            ProviderIdentity(StableId("message-host"), "1"), attempt.attempt_id,
            Sha256Digest("c" * 64), workspace.common_base.ref, NOW,
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


def package_json():
    work = []
    for name in ("alpha", "beta", "gamma"):
        work.append({
            "id": name, "title": name.title(), "objective": f"Deliver {name}",
            "outcome": f"{name} complete",
            "scope": {"paths": [{"path": f"src/{name}", "access": "write"}], "concepts": [], "locks": []},
            "acceptance": {"assertions": ["complete"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
        })
    return json.dumps({
        "format": "todo-orchestrator.plan", "schema_version": 1, "package_id": "message-flow",
        "project": {"project_id": str(PROJECT.project_id), "authority_id": str(PROJECT.authority_id)},
        "work_items": work,
        "interfaces": [{"id": "shared-api", "title": "Shared API", "version": "1.0",
                         "contract": {"format": "json"}, "producers": [], "consumers": [],
                         "compatibility": "evolvable"}],
    }, sort_keys=True)


class MessagingFlowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "authority.sqlite3"
        SQLiteAuthority.initialize(self.path, PROJECT)
        self.dispatcher = CommandDispatcher()
        self.auth = AuthorityAuthService(self.dispatcher, clock=Clock(), authenticator=Authenticator())
        with self.writer() as authority:
            enrollment = self.auth.enroll_local_owner(
                authority, OWNER_PASSWORD, label="owner", idempotency_key=StableId("msg-enroll"),
                expected_revision=0,
            )
            self.owner = self.auth.login_local_owner(
                authority, OWNER_PASSWORD,
                actions=(PLAN_COMMIT, SCHEDULE_ACTION, RUN_DISPATCH_ACTION, CLAIM_ACTION, DELEGATE_ACTION,
                         HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION,
                         MESSAGE_SEND_ACTION, MESSAGE_READ_ACTION, QUESTION_ANSWER_ACTION),
                scope=PROJECT.ref, expires_at=NOW + timedelta(days=1),
                idempotency_key=StableId("msg-owner-token"),
                expected_revision=enrollment.receipt.semantic_revision,
            )
        self.plans = PlanService(self.auth)
        self.host = Host()
        self.attempts = AttemptService(self.auth, host=self.host, clock=Clock())
        self.coordination = CoordinationService(self.auth, attempts=self.attempts)
        self.messages = MessagingService(self.auth)
        self.package = package_json()
        compiled = compile_plan_json(self.package, PROJECT)
        self.assertTrue(compiled.ok, compiled.diagnostics)
        with self.writer() as authority:
            preview = self.plans.preview(authority, self.package)
            self.plans.commit(
                authority, self.owner.bearer_token, self.package, reviewed_digest=preview.digest,
                idempotency_key=StableId("msg-plan-commit"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            self.plan = self.plans.load_accepted_plan(authority)
        self.interface = EntityRef(PROJECT.project_id, EntityKind.INTERFACE, StableId("shared-api"))
        self.work = {str(item.definition.work_item_id): item.definition.ref for item in self.plan.work_items}
        self.workers = {}
        for label in ("a", "b"):
            with self.writer() as authority:
                issued = self.auth.delegate(
                    authority, self.owner.bearer_token, f"worker-{label}",
                    actions=(RUN_DISPATCH_ACTION, CLAIM_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION,
                             MESSAGE_SEND_ACTION,
                             MESSAGE_READ_ACTION, QUESTION_ANSWER_ACTION),
                    scope=self.plan.revision.ref, expires_at=NOW + timedelta(hours=4),
                    idempotency_key=StableId(f"msg-worker-{label}"), expected_revision=self.revision(),
                )
            self.workers[label] = issued
        self.run = EntityRef(PROJECT.project_id, EntityKind.RUN, StableId("message-run"))
        self.schedule()
        self.dispatches = {}
        with self.open_reader() as authority:
            view = self.coordination.read_run(authority, self.run.entity_id)
        for entry in view.entries:
            label = "a" if entry.assignment.work_item == self.work["alpha"] else "b"
            with self.writer() as authority:
                dispatch = self.coordination.dispatch(
                    authority, self.workers[label].bearer_token, self.plan,
                    workspace_id=StableId(f"workspace-{label}"), idempotency_key=StableId(f"dispatch-{label}"),
                    expected_revision=self.revision(), work_item=entry.assignment.work_item,
                    run=self.run, assignment=entry.assignment.ref,
                )
            self.dispatches[label] = (dispatch, entry.assignment.ref)

    def writer(self):
        return SQLiteAuthority.open_writer(self.path, PROJECT)

    def open_reader(self):
        return SQLiteAuthority.open_reader(self.path, PROJECT)

    def revision(self):
        with self.open_reader() as authority:
            return authority.connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]

    def schedule(self):
        actors = {label: issued.capability.actor for label, issued in self.workers.items()}
        schedule = RunSchedule(
            self.run.entity_id, self.plan.revision.ref,
            (LaneSpec(StableId("parallel"), QueuePolicy.PARALLEL),),
            tuple(ScheduledWork(self.work[name], StableId("parallel"), actors[label])
                  for name, label in (("alpha", "a"), ("beta", "b"))),
            RunCharter("Coordinate workers", ("Use exact scoped messages",), ("Both assignments are dispatched",)),
        )
        with self.writer() as authority:
            self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, schedule,
                idempotency_key=StableId("msg-run-schedule"), expected_revision=self.revision(),
            )

    def context(self, label):
        dispatch, assignment = self.dispatches[label]
        return dispatch.attempt.run, assignment, dispatch.attempt.ref

    def test_workers_exchange_question_using_distinct_attempt_contexts(self):
        run_a, assignment_a, attempt_a = self.context("a")
        run_b, assignment_b, attempt_b = self.context("b")
        self.assertNotEqual(attempt_a, attempt_b)
        self.assertNotEqual(assignment_a, assignment_b)
        question_expected_revision = self.revision()
        with self.writer() as authority:
            question = self.messages.ask(
                authority, self.workers["a"].bearer_token, self.interface,
                (self.workers["b"].capability.actor,), subject="Interface question",
                body="Does the payload use JSON?", context_run=run_a, context_assignment=assignment_a,
                context_attempt=attempt_a, idempotency_key=StableId("msg-question"),
                expected_revision=question_expected_revision,
            )
        question_id = StableId(question.receipt.result["message_id"])
        revision_after_question = self.revision()
        with self.writer() as authority:
            replay = self.messages.ask(
                authority, self.workers["a"].bearer_token, self.interface,
                (self.workers["b"].capability.actor,), subject="Interface question",
                body="Does the payload use JSON?", context_run=run_a, context_assignment=assignment_a,
                context_attempt=attempt_a, idempotency_key=StableId("msg-question"),
                expected_revision=question_expected_revision,
            )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, question.receipt)
        self.assertEqual(self.revision(), revision_after_question)
        with self.open_reader() as authority:
            status = self.messages.inbox_status(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
            )
        self.assertEqual(status.unread_count, 1)
        with self.writer() as authority:
            inbox = self.messages.sync_inbox(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
                idempotency_key=StableId("msg-sync-b"), expected_revision=self.revision(),
            )
        self.assertEqual(len(inbox.messages), 1)
        self.assertEqual(inbox.messages[0].message_type, MessageType.QUESTION)
        self.assertEqual(inbox.messages[0].context_attempt, attempt_a)
        with self.writer() as authority:
            inbox_replay = self.messages.sync_inbox(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
                idempotency_key=StableId("msg-sync-b"), expected_revision=inbox.receipt.receipt.semantic_revision - 1,
            )
        self.assertTrue(inbox_replay.receipt.replayed)
        self.assertEqual(inbox_replay.messages, inbox.messages)
        with self.writer() as authority:
            answer = self.messages.answer(
                authority, self.workers["b"].bearer_token, question_id, body="Yes, JSON.",
                context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
                idempotency_key=StableId("msg-answer"), expected_revision=self.revision(),
            )
        after_answer = self.revision()
        with self.writer() as authority:
            with self.assertRaises(AnswerConflictError):
                self.messages.answer(
                    authority, self.workers["b"].bearer_token, question_id, body="second answer",
                    context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
                    idempotency_key=StableId("msg-answer-second"), expected_revision=self.revision(),
                )
        self.assertEqual(self.revision(), after_answer)
        with self.writer() as authority:
            inbox_a = self.messages.sync_inbox(
                authority, self.workers["a"].bearer_token, self.interface,
                context_run=run_a, context_assignment=assignment_a, context_attempt=attempt_a,
                idempotency_key=StableId("msg-sync-a"), expected_revision=self.revision(),
            )
        self.assertEqual([message.reply_to for message in inbox_a.messages], [question_id])
        read_to = inbox_a.messages[0].sequence
        with self.writer() as authority:
            self.messages.mark_read(
                authority, self.workers["a"].bearer_token, self.interface, through_sequence=read_to,
                context_run=run_a, context_assignment=assignment_a, context_attempt=attempt_a,
                idempotency_key=StableId("msg-read-a"), expected_revision=self.revision(),
            )
        with self.open_reader() as authority:
            status = self.messages.inbox_status(
                authority, self.workers["a"].bearer_token, self.interface,
                context_run=run_a, context_assignment=assignment_a, context_attempt=attempt_a,
            )
        self.assertEqual(status.unread_count, 0)
        self.assertEqual(answer.receipt.result["message_id"], str(inbox_a.messages[0].message_id))
        with self.writer() as authority:
            with self.assertRaises(CursorError):
                self.messages.mark_read(
                    authority, self.workers["a"].bearer_token, self.interface,
                    through_sequence=read_to - 1, context_run=run_a, context_assignment=assignment_a,
                    context_attempt=attempt_a, idempotency_key=StableId("msg-read-backwards"),
                    expected_revision=self.revision(),
                )

    def test_recipient_membership_does_not_grant_read_action_and_foreign_recipient_is_rejected(self):
        with self.writer() as authority:
            outsider = self.auth.delegate(
                authority, self.owner.bearer_token, "outsider",
                actions=(RUN_DISPATCH_ACTION, CLAIM_ACTION, HEARTBEAT_ACTION, RELEASE_ACTION, FINISH_ACTION),
                scope=self.plan.revision.ref,
                expires_at=NOW + timedelta(hours=1), idempotency_key=StableId("msg-outsider"),
                expected_revision=self.revision(),
            )
        run_a, assignment_a, attempt_a = self.context("a")
        before_foreign = self.revision()
        with self.writer() as authority:
            with self.assertRaises(MessageScopeError):
                self.messages.ask(
                    authority, self.workers["a"].bearer_token, self.interface,
                    (EntityRef(StableId("foreign-project"), EntityKind.ACTOR, StableId("outside"),
                               incarnation_id=StableId("outside-inc")),),
                    subject="Foreign", body="No", context_run=run_a, context_assignment=assignment_a,
                    context_attempt=attempt_a, idempotency_key=StableId("msg-foreign"),
                    expected_revision=self.revision(),
                )
        self.assertEqual(self.revision(), before_foreign)
        with self.writer() as authority:
            question = self.messages.ask(
                authority, self.workers["a"].bearer_token, self.interface,
                (outsider.capability.actor,), subject="Scoped delivery", body="Can you read this?",
                context_run=run_a, context_assignment=assignment_a, context_attempt=attempt_a,
                idempotency_key=StableId("msg-outsider-question"), expected_revision=self.revision(),
            )
        with self.open_reader() as authority:
            before_denied = self.revision()
            with self.assertRaises(CapabilityDeniedError):
                self.messages.inbox_status(authority, outsider.bearer_token, self.interface)
        self.assertEqual(self.revision(), before_denied)
        with self.writer() as authority:
            with self.assertRaises(CapabilityDeniedError):
                self.messages.sync_inbox(authority, outsider.bearer_token, self.interface,
                                          idempotency_key=StableId("msg-outsider-sync"),
                                          expected_revision=self.revision())
        self.assertEqual(self.revision(), before_denied)
        self.assertTrue(question.receipt.changed)

    def test_inbox_and_cursor_are_partitioned_by_run(self):
        run_a, assignment_a, attempt_a = self.context("a")
        with self.writer() as authority:
            question = self.messages.ask(
                authority, self.workers["a"].bearer_token, self.interface,
                (self.workers["b"].capability.actor,), subject="Run A only", body="Private to run A",
                context_run=run_a, context_assignment=assignment_a, context_attempt=attempt_a,
                idempotency_key=StableId("msg-run-a-question"), expected_revision=self.revision(),
            )
        run_a_message = StableId(question.receipt.result["message_id"])
        run_a_assignment_b, run_a_attempt_b = self.context("b")[1:]
        with self.open_reader() as authority:
            run_a_sequence = authority.connection.execute(
                "SELECT sequence FROM coordination_messages WHERE message_id = ?", (str(run_a_message),)
            ).fetchone()[0]

        run_b = EntityRef(PROJECT.project_id, EntityKind.RUN, StableId("message-run-b"))
        run_b_schedule = RunSchedule(
            run_b.entity_id, self.plan.revision.ref,
            (LaneSpec(StableId("parallel-b"), QueuePolicy.PARALLEL),),
            (ScheduledWork(self.work["gamma"], StableId("parallel-b"), self.workers["b"].capability.actor),),
            RunCharter("Separate run", ("Messages stay partitioned",), ("Run B has its own inbox",)),
        )
        with self.writer() as authority:
            self.coordination.open_run(
                authority, self.owner.bearer_token, self.plan, run_b_schedule,
                idempotency_key=StableId("msg-run-b-schedule"), expected_revision=self.revision(),
            )
        with self.open_reader() as authority:
            run_b_view = self.coordination.read_run(authority, run_b.entity_id)
        run_b_assignment = run_b_view.entries[0].assignment.ref
        with self.writer() as authority:
            run_b_dispatch = self.coordination.dispatch(
                authority, self.workers["b"].bearer_token, self.plan,
                workspace_id=StableId("workspace-b-run-b"),
                idempotency_key=StableId("msg-dispatch-b-run-b"), expected_revision=self.revision(),
                work_item=self.work["gamma"], run=run_b, assignment=run_b_assignment,
            )
        run_b_attempt = run_b_dispatch.attempt.ref
        with self.writer() as authority:
            run_b_message = self.messages.send(
                authority, self.workers["b"].bearer_token, self.interface,
                (self.workers["b"].capability.actor,), message_type=MessageType.STATUS,
                subject="Run B only", body="Later message in run B", context_run=run_b,
                context_assignment=run_b_assignment, context_attempt=run_b_attempt,
                idempotency_key=StableId("msg-run-b-status"), expected_revision=self.revision(),
            )
        run_b_message_id = StableId(run_b_message.receipt.result["message_id"])

        with self.open_reader() as authority:
            run_b_status = self.messages.inbox_status(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=run_b_assignment, context_attempt=run_b_attempt,
            )
        self.assertEqual(run_b_status.unread_count, 1)
        with self.writer() as authority:
            run_b_page = self.messages.sync_inbox(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=run_b_assignment, context_attempt=run_b_attempt,
                idempotency_key=StableId("msg-sync-run-b"), expected_revision=self.revision(),
            )
        self.assertEqual([item.message_id for item in run_b_page.messages], [run_b_message_id])
        self.assertEqual(run_b_page.messages[0].context_run, run_b)
        self.assertLess(run_a_sequence, run_b_page.messages[0].sequence)
        with self.writer() as authority:
            with self.assertRaises(CursorError):
                self.messages.mark_read(
                    authority, self.workers["b"].bearer_token, self.interface,
                    through_sequence=run_a_sequence,
                    context_run=run_b, context_assignment=run_b_assignment, context_attempt=run_b_attempt,
                    idempotency_key=StableId("msg-read-cross-run"), expected_revision=self.revision(),
                )

        run_a_assignment_b, run_a_attempt_b = self.context("b")[1:]
        with self.open_reader() as authority:
            run_a_status = self.messages.inbox_status(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_a, context_assignment=run_a_assignment_b, context_attempt=run_a_attempt_b,
            )
        self.assertEqual(run_a_status.unread_count, 1)
        self.assertEqual(run_a_status.delivered_sequence, 0)
        self.assertEqual(run_a_status.read_sequence, 0)
        with self.writer() as authority:
            run_a_page = self.messages.sync_inbox(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_a, context_assignment=run_a_assignment_b, context_attempt=run_a_attempt_b,
                idempotency_key=StableId("msg-sync-run-a-partition"), expected_revision=self.revision(),
            )
        self.assertEqual([item.message_id for item in run_a_page.messages], [run_a_message])
        with self.writer() as authority:
            self.messages.mark_read(
                authority, self.workers["b"].bearer_token, self.interface,
                through_sequence=run_a_page.messages[0].sequence,
                context_run=run_a, context_assignment=run_a_assignment_b, context_attempt=run_a_attempt_b,
                idempotency_key=StableId("msg-read-run-a-partition"), expected_revision=self.revision(),
            )
        with self.writer() as authority:
            self.messages.mark_read(
                authority, self.workers["b"].bearer_token, self.interface,
                through_sequence=run_b_page.messages[0].sequence,
                context_run=run_b, context_assignment=run_b_assignment, context_attempt=run_b_attempt,
                idempotency_key=StableId("msg-read-run-b-partition"), expected_revision=self.revision(),
            )
        with self.open_reader() as authority:
            self.assertEqual(self.messages.inbox_status(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_a, context_assignment=run_a_assignment_b, context_attempt=run_a_attempt_b,
            ).unread_count, 0)
            self.assertEqual(self.messages.inbox_status(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=run_b_assignment, context_attempt=run_b_attempt,
            ).unread_count, 0)

    def test_unbound_messages_use_the_separate_run_free_inbox(self):
        with self.writer() as authority:
            question = self.messages.ask(
                authority, self.workers["a"].bearer_token, self.interface,
                (self.workers["b"].capability.actor,), subject="Unbound", body="No run context",
                idempotency_key=StableId("msg-unbound-question"), expected_revision=self.revision(),
            )
        with self.writer() as authority:
            page = self.messages.sync_inbox(
                authority, self.workers["b"].bearer_token, self.interface,
                idempotency_key=StableId("msg-sync-unbound"), expected_revision=self.revision(),
            )
        self.assertEqual([item.message_id for item in page.messages], [StableId(question.receipt.result["message_id"])])
        run_b, assignment_b, attempt_b = self.context("b")
        with self.open_reader() as authority:
            self.assertEqual(self.messages.inbox_status(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
            ).unread_count, 0)

    def test_decision_and_interface_change_messages_are_informational_only(self):
        run_a, assignment_a, attempt_a = self.context("a")
        with self.open_reader() as authority:
            before = tuple(authority.connection.execute(
                "SELECT (SELECT COUNT(*) FROM declaration_facts), "
                "(SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM assignments), "
                "(SELECT COUNT(*) FROM attempts)"
            ).fetchone())
        for message_type, key, subject, body in (
            (MessageType.DECISION, "msg-informational-decision", "Decision notice", "Option B was selected."),
            (MessageType.INTERFACE_CHANGE, "msg-informational-interface", "Interface notice", "Payload field added."),
        ):
            with self.writer() as authority:
                self.messages.send(
                    authority, self.workers["a"].bearer_token, self.interface,
                    (self.workers["b"].capability.actor,), message_type=message_type,
                    subject=subject, body=body, context_run=run_a, context_assignment=assignment_a,
                    context_attempt=attempt_a, idempotency_key=StableId(key),
                    expected_revision=self.revision(),
                )
        run_b, assignment_b, attempt_b = self.context("b")
        with self.writer() as authority:
            inbox = self.messages.sync_inbox(
                authority, self.workers["b"].bearer_token, self.interface,
                context_run=run_b, context_assignment=assignment_b, context_attempt=attempt_b,
                idempotency_key=StableId("msg-sync-informational"), expected_revision=self.revision(),
            )
        self.assertEqual([item.message_type for item in inbox.messages],
                         [MessageType.DECISION, MessageType.INTERFACE_CHANGE])
        with self.open_reader() as authority:
            after = tuple(authority.connection.execute(
                "SELECT (SELECT COUNT(*) FROM declaration_facts), "
                "(SELECT COUNT(*) FROM runs), (SELECT COUNT(*) FROM assignments), "
                "(SELECT COUNT(*) FROM attempts)"
            ).fetchone())
        self.assertEqual(after, before)
    def test_issued_bearer_in_message_body_is_rejected_without_authority_churn(self):
        run_a, assignment_a, attempt_a = self.context("a")
        before_revision = self.revision()
        with self.writer() as authority:
            with self.assertRaises(PayloadRejectedError):
                self.messages.send(
                    authority, self.workers["a"].bearer_token, self.interface,
                    (self.workers["b"].capability.actor,), message_type=MessageType.STATUS,
                    subject="Status", body=f"credential {self.workers['b'].bearer_token}",
                    context_run=run_a, context_assignment=assignment_a, context_attempt=attempt_a,
                    idempotency_key=StableId("msg-secret-body"), expected_revision=before_revision,
                )
        self.assertEqual(self.revision(), before_revision)
        with self.open_reader() as authority:
            count = authority.connection.execute("SELECT COUNT(*) FROM coordination_messages").fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
