from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import tempfile
from threading import Barrier, Event, Lock
import unittest

from todo_orchestrator.authority import CommandDispatcher, SQLiteAuthority
from todo_orchestrator.authority.commands import (
    CommandHandlerContractError,
    CommandActorNotRegisteredError,
    IdempotencyConflictError,
    StaleAuthorityRevisionError,
)
from todo_orchestrator.contracts import EntityKind, EntityRef, Project, StableId
from todo_orchestrator.model import CommandEffect, CommandEnvelope


@dataclass(frozen=True)
class SetActorLabel:
    label: str


@dataclass
class MutableSetActorLabel:
    label: str


class SetActorLabelHandler:
    kind = "actor.set_label"
    command_type = SetActorLabel

    def canonical_payload(self, command: SetActorLabel):
        return {"label": command.label}

    def apply(self, context, command: SetActorLabel):
        changed = context.execute(
            "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ? AND label IS NOT ?",
            (command.label, str(context.actor.entity_id), str(context.actor.incarnation_id), command.label),
        ).rowcount == 1
        if not changed:
            return CommandEffect(False, {"label": command.label})
        return CommandEffect(
            True,
            {"label": command.label},
            "actor.label_changed",
            {"actor_id": str(context.actor.entity_id), "label": command.label},
        )


class SnapshotBarrierHandler(SetActorLabelHandler):
    kind = "actor.snapshot_barrier"
    command_type = MutableSetActorLabel

    def __init__(self):
        self.captured = Event()
        self.continue_execution = Event()
        self._first_payload = True
        self._lock = Lock()

    def canonical_payload(self, command: MutableSetActorLabel):
        with self._lock:
            pause = self._first_payload
            self._first_payload = False
        if pause:
            self.captured.set()
            if not self.continue_execution.wait(timeout=3):
                raise TimeoutError("test did not release the handler")
        return {"label": command.label}


class RaiseAfterWriteHandler(SetActorLabelHandler):
    kind = "actor.raise_after_write"

    def apply(self, context, command):
        context.execute(
            "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ?",
            (command.label, str(context.actor.entity_id), str(context.actor.incarnation_id)),
        )
        raise RuntimeError("handler failed after mutation")


class LyingNoOpHandler(SetActorLabelHandler):
    kind = "actor.lie_noop"

    def apply(self, context, command):
        context.execute(
            "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ?",
            (command.label, str(context.actor.entity_id), str(context.actor.incarnation_id)),
        )
        return CommandEffect(False, {"label": command.label})


class MaliciousHandler(SetActorLabelHandler):
    def __init__(self, statement: str):
        self.kind = "actor.malicious." + str(abs(hash(statement)))
        self.statement = statement

    def apply(self, context, command):
        context.execute(self.statement)
        return CommandEffect(False, {})


class BootstrapActorHandler(SetActorLabelHandler):
    kind = "actor.bootstrap"
    allows_unregistered_actor = True

    def apply(self, context, command):
        context.execute(
            "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, 'human', ?)",
            (str(context.actor.entity_id), str(context.actor.incarnation_id), command.label),
        )
        return CommandEffect(True, {"label": command.label}, "actor.enrolled", {})


def project() -> Project:
    return Project(StableId("project-1"), StableId("authority-1"))


def actor() -> EntityRef:
    return EntityRef(
        StableId("project-1"), EntityKind.ACTOR, StableId("agent-1"), incarnation_id=StableId("incarnation-1")
    )


class CommandAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite3"
        self.project = project()
        self.actor = actor()
        SQLiteAuthority.initialize(self.path, self.project)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with authority.write_transaction() as connection:
                connection.execute(
                    "INSERT INTO actors(actor_id, incarnation_id, kind, label) VALUES (?, ?, ?, ?)",
                    (str(self.actor.entity_id), str(self.actor.incarnation_id), "automation", "before"),
                )

    def envelope(self, label: str, key: str = "request-1", revision: int = 0) -> CommandEnvelope[SetActorLabel]:
        return CommandEnvelope(SetActorLabel(label), StableId(key), revision, self.actor)

    def dispatcher(self, handler=None) -> CommandDispatcher:
        return CommandDispatcher([handler or SetActorLabelHandler()])

    def test_authorization_rechecks_before_exact_retry_without_writes(self):
        dispatcher = self.dispatcher()
        envelope = self.envelope("after")
        seen = []

        def allow(connection, command, handler, actor_ref):
            self.assertTrue(connection.in_transaction)
            self.assertEqual(actor_ref, self.actor)
            self.assertIsInstance(handler, SetActorLabelHandler)
            seen.append(command.label)

        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            first = dispatcher._execute_authorized(authority, envelope, allow)
            repeated = dispatcher._execute_authorized(authority, envelope, allow)
        self.assertEqual(seen, ["after", "after"])
        self.assertEqual(first.receipt, repeated.receipt)
        before = self.snapshot()

        def deny(*_args):
            raise PermissionError("grant revoked")

        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with self.assertRaises(PermissionError):
                dispatcher._execute_authorized(authority, envelope, deny)
        self.assertEqual(self.snapshot(), before)

    def test_authorization_guard_is_read_only_and_requires_explicit_raise(self):
        dispatcher = self.dispatcher()
        before = self.snapshot()
        for statement in ("UPDATE actors SET label = 'bad'", "COMMIT", "PRAGMA user_version = 99"):
            with self.subTest(statement=statement):
                def invalid_guard(connection, *_args):
                    connection.execute(statement)
                with SQLiteAuthority.open_writer(self.path, self.project) as authority:
                    with self.assertRaises(sqlite3.DatabaseError):
                        dispatcher._execute_authorized(authority, self.envelope("after"), invalid_guard)
                self.assertEqual(self.snapshot(), before)
        with SQLiteAuthority.open_writer(self.path, self.project) as authority:
            with self.assertRaises(CommandHandlerContractError):
                dispatcher._execute_authorized(authority, self.envelope("after"), lambda *_args: False)
        self.assertEqual(self.snapshot(), before)

    def test_first_actor_bootstrap_commits_atomically_and_cannot_add_second_actor(self):
        path = Path(self.directory.name) / "bootstrap.sqlite3"
        SQLiteAuthority.initialize(path, self.project)

        class FailingBootstrap(BootstrapActorHandler):
            def apply(self, context, command):
                super().apply(context, command)
                raise RuntimeError("interrupted enrollment")

        with SQLiteAuthority.open_writer(path, self.project) as authority:
            with self.assertRaises(RuntimeError):
                self.dispatcher(FailingBootstrap()).execute(authority, self.envelope("owner"))
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM actors").fetchone()[0], 0)
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM authority_events").fetchone()[0], 0)
            self.assertEqual(authority.connection.execute("SELECT semantic_revision FROM authority_meta").fetchone()[0], 0)
            result = self.dispatcher(BootstrapActorHandler()).execute(authority, self.envelope("owner"))
            self.assertEqual(result.receipt.semantic_revision, 1)
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM actors").fetchone()[0], 1)
            other_actor = EntityRef(self.project.project_id, EntityKind.ACTOR, StableId("other"), incarnation_id=StableId("other-inc"))
            second = CommandEnvelope(SetActorLabel("other"), StableId("second"), 1, other_actor)
            with self.assertRaises(CommandActorNotRegisteredError):
                self.dispatcher(BootstrapActorHandler()).execute(authority, second)
            self.assertEqual(authority.connection.execute("SELECT count(*) FROM actors").fetchone()[0], 1)

    def snapshot(self):
        with SQLiteAuthority.open_reader(self.path, self.project) as authority:
            connection = authority.connection
            revision = connection.execute(
                "SELECT semantic_revision FROM authority_meta WHERE singleton = 1"
            ).fetchone()[0]
            actor_row = connection.execute("SELECT label FROM actors").fetchone()[0]
            counts = tuple(
                connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("authority_events", "command_receipts", "command_idempotency")
            )
            return revision, actor_row, counts

    def test_changed_command_commits_one_revision_event_and_receipt(self):
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            result = self.dispatcher().execute(writer, self.envelope("after"))
        self.assertFalse(result.replayed)
        self.assertTrue(result.receipt.changed)
        self.assertEqual(result.receipt.semantic_revision, 1)
        self.assertEqual(self.snapshot(), (1, "after", (1, 1, 1)))

    def test_exact_retry_after_reopen_returns_durable_receipt_without_churn(self):
        dispatcher = self.dispatcher()
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            first = dispatcher.execute(writer, self.envelope("after"))
        with SQLiteAuthority.open_writer(self.path, self.project) as reopened:
            retry = dispatcher.execute(reopened, self.envelope("after"))
        self.assertTrue(retry.replayed)
        self.assertEqual(retry.receipt, first.receipt)
        self.assertEqual(self.snapshot(), (1, "after", (1, 1, 1)))

    def test_reused_idempotency_key_with_different_payload_is_rejected_without_churn(self):
        dispatcher = self.dispatcher()
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            dispatcher.execute(writer, self.envelope("after"))
            with self.assertRaises(IdempotencyConflictError):
                dispatcher.execute(writer, self.envelope("different"))
        self.assertEqual(self.snapshot(), (1, "after", (1, 1, 1)))

    def test_stale_distinct_request_is_rejected_without_receipt_or_event(self):
        dispatcher = self.dispatcher()
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            dispatcher.execute(writer, self.envelope("after"))
            with self.assertRaises(StaleAuthorityRevisionError):
                dispatcher.execute(writer, self.envelope("another", key="request-2"))
        self.assertEqual(self.snapshot(), (1, "after", (1, 1, 1)))

    def test_no_op_records_receipt_without_revision_event_or_fingerprint_churn(self):
        dispatcher = self.dispatcher()
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            before = dispatcher.logical_fingerprint(writer)
            first = dispatcher.execute(writer, self.envelope("before"))
            after = dispatcher.logical_fingerprint(writer)
            retry = dispatcher.execute(writer, self.envelope("before"))
        self.assertFalse(first.receipt.changed)
        self.assertEqual(first.receipt.semantic_revision, 0)
        self.assertEqual(before, after)
        self.assertTrue(retry.replayed)
        self.assertEqual(retry.receipt, first.receipt)
        self.assertEqual(self.snapshot(), (0, "before", (0, 1, 1)))

    def test_handler_exception_after_write_rolls_back_everything(self):
        dispatcher = self.dispatcher(RaiseAfterWriteHandler())
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with self.assertRaisesRegex(RuntimeError, "after mutation"):
                dispatcher.execute(writer, self.envelope("must roll back"))
        self.assertEqual(self.snapshot(), (0, "before", (0, 0, 0)))

    def test_handler_that_mutates_but_reports_no_op_is_rolled_back(self):
        dispatcher = self.dispatcher(LyingNoOpHandler())
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with self.assertRaisesRegex(CommandHandlerContractError, "reported a no-op"):
                dispatcher.execute(writer, self.envelope("must roll back"))
        self.assertEqual(self.snapshot(), (0, "before", (0, 0, 0)))

    def test_missing_actor_incarnation_cannot_create_provenance(self):
        missing_actor = EntityRef(
            StableId("project-1"), EntityKind.ACTOR, StableId("missing"), incarnation_id=StableId("inc-1")
        )
        envelope = CommandEnvelope(SetActorLabel("after"), StableId("request-1"), 0, missing_actor)
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with self.assertRaises(CommandActorNotRegisteredError):
                self.dispatcher().execute(writer, envelope)
        self.assertEqual(self.snapshot(), (0, "before", (0, 0, 0)))

    def test_mutation_context_blocks_transaction_pragma_schema_and_dispatcher_tables(self):
        statements = (
            "PRAGMA user_version = 99",
            "BEGIN",
            "CREATE TABLE accidental(value TEXT)",
            "UPDATE authority_meta SET semantic_revision = 99",
            "INSERT INTO authority_events(event_id, semantic_revision, event_ordinal, event_kind, payload_json, "
            "occurred_at, actor_id, actor_incarnation_id) "
            "VALUES ('forged', 1, 0, 'forged', '{}', 'now', 'agent-1', 'incarnation-1')",
            "DELETE FROM command_idempotency",
        )
        for index, statement in enumerate(statements):
            with self.subTest(statement=statement):
                handler = MaliciousHandler(statement)
                with SQLiteAuthority.open_writer(self.path, self.project) as writer:
                    with self.assertRaises(sqlite3.DatabaseError):
                        self.dispatcher(handler).execute(writer, self.envelope("after", key=f"malicious-{index}"))
                self.assertEqual(self.snapshot(), (0, "before", (0, 0, 0)))

    def test_mutation_context_rejects_multiple_statements(self):
        handler = MaliciousHandler("UPDATE actors SET label = 'bad'; UPDATE actors SET label = 'worse'")
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            with self.assertRaises(sqlite3.ProgrammingError):
                self.dispatcher(handler).execute(writer, self.envelope("after"))
        self.assertEqual(self.snapshot(), (0, "before", (0, 0, 0)))

    def test_same_request_concurrent_dispatch_has_one_commit_and_one_replay(self):
        dispatcher = self.dispatcher()
        barrier = Barrier(2)

        def run():
            with SQLiteAuthority.open_writer(self.path, self.project) as writer:
                barrier.wait(timeout=2)
                return dispatcher.execute(writer, self.envelope("after"))

        with ThreadPoolExecutor(max_workers=2) as executor:
            first, second = list(executor.map(lambda _: run(), range(2)))
        self.assertCountEqual((first.replayed, second.replayed), (False, True))
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(self.snapshot(), (1, "after", (1, 1, 1)))

    def test_mutable_caller_command_is_snapshotted_before_digest_and_apply(self):
        handler = SnapshotBarrierHandler()
        dispatcher = self.dispatcher(handler)
        original = MutableSetActorLabel("bound-before-mutation")
        envelope = CommandEnvelope(original, StableId("snapshot-key"), 0, self.actor)

        def execute():
            with SQLiteAuthority.open_writer(self.path, self.project) as writer:
                return dispatcher.execute(writer, envelope)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(execute)
            self.assertTrue(handler.captured.wait(timeout=3))
            original.label = "changed-while-handler-waited"
            handler.continue_execution.set()
            first = future.result(timeout=3)

        self.assertEqual(self.snapshot(), (1, "bound-before-mutation", (1, 1, 1)))
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            exact_retry = dispatcher.execute(
                writer,
                CommandEnvelope(MutableSetActorLabel("bound-before-mutation"), StableId("snapshot-key"), 0, self.actor),
            )
            with self.assertRaises(IdempotencyConflictError):
                dispatcher.execute(writer, envelope)
        self.assertEqual(exact_retry.receipt, first.receipt)
        self.assertTrue(exact_retry.replayed)
        self.assertEqual(self.snapshot(), (1, "bound-before-mutation", (1, 1, 1)))

    def test_history_and_delta_are_revision_ordered_and_fingerprint_ignores_wal_layout(self):
        dispatcher = self.dispatcher()
        with SQLiteAuthority.open_writer(self.path, self.project) as writer:
            dispatcher.execute(writer, self.envelope("one", key="one"))
            dispatcher.execute(writer, self.envelope("two", key="two", revision=1))
            fingerprint_before = dispatcher.logical_fingerprint(writer)
            writer.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            fingerprint_after = dispatcher.logical_fingerprint(writer)
        with SQLiteAuthority.open_reader(self.path, self.project) as reader:
            events = dispatcher.history(reader)
            delta = dispatcher.delta(reader, 1)
        self.assertEqual([event.semantic_revision for event in events], [1, 2])
        self.assertEqual([event.actor for event in events], [self.actor, self.actor])
        self.assertEqual(delta.since_revision, 1)
        self.assertEqual(delta.current_revision, 2)
        self.assertEqual([event.semantic_revision for event in delta.events], [2])
        self.assertEqual(fingerprint_before, fingerprint_after)


if __name__ == "__main__":
    unittest.main()
