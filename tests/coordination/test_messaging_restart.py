"""Independent service reconstruction checks against persisted inbox receipts."""

from datetime import timedelta
import unittest

from todo_orchestrator.authority import AuthorityAuthService, AuthenticationFailedError, CommandDispatcher
from todo_orchestrator.contracts import StableId
from todo_orchestrator.coordination import MessagingService

from tests.coordination import test_messaging as fixtures


class InboxRestartTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.MessagingFlowTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def fresh_service(self, clock=fixtures.Clock()):
        return MessagingService(AuthorityAuthService(
            CommandDispatcher(), clock=clock, authenticator=fixtures.Authenticator(),
        ))

    def send(self, key):
        f = self.f
        with f.writer() as authority:
            return f.messages.send(
                authority, f.workers['a'].bearer_token, f.interface,
                (f.workers['b'].capability.actor,), subject='Progress', body='Review is ready.',
                idempotency_key=StableId(key), expected_revision=f.revision(),
            )

    def test_restart_replays_exact_page_without_rewinding_durable_cursor(self):
        f = self.f
        first = self.send('restart-first')
        second = self.send('restart-second')
        before_sync = f.revision()
        with f.writer() as authority:
            page = f.messages.sync_inbox(
                authority, f.workers['b'].bearer_token, f.interface, limit=1,
                idempotency_key=StableId('restart-sync'), expected_revision=before_sync,
            )
        with f.writer() as authority:
            f.messages.mark_read(
                authority, f.workers['b'].bearer_token, f.interface,
                through_sequence=page.delivered_sequence,
                idempotency_key=StableId('restart-read'), expected_revision=f.revision(),
            )
        service = self.fresh_service()
        stable_revision = f.revision()
        with f.writer() as authority:
            replay = service.sync_inbox(
                authority, f.workers['b'].bearer_token, f.interface, limit=1,
                idempotency_key=StableId('restart-sync'), expected_revision=before_sync,
            )
        self.assertEqual(replay.messages, page.messages)
        self.assertEqual(replay.receipt.receipt, page.receipt.receipt)
        self.assertEqual(f.revision(), stable_revision)
        self.assertEqual(str(replay.messages[0].message_id), first.receipt.result['message_id'])
        with f.open_reader() as authority:
            status = service.inbox_status(authority, f.workers['b'].bearer_token, f.interface)
        self.assertEqual(status.read_sequence, page.delivered_sequence)
        self.assertEqual(status.unread_count, 1)
        with f.writer() as authority:
            next_page = service.sync_inbox(
                authority, f.workers['b'].bearer_token, f.interface, limit=1,
                idempotency_key=StableId('restart-next'), expected_revision=stable_revision,
            )
        self.assertEqual(str(next_page.messages[0].message_id), second.receipt.result['message_id'])

    def test_expired_capability_cannot_replay_delivered_page_after_restart(self):
        f = self.f
        self.send('expired-first')
        with f.writer() as authority:
            f.messages.sync_inbox(
                authority, f.workers['b'].bearer_token, f.interface,
                idempotency_key=StableId('expired-sync'), expected_revision=f.revision(),
            )
        service = self.fresh_service(lambda: fixtures.NOW + timedelta(days=2))
        stable_revision = f.revision()
        with f.writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                service.sync_inbox(
                    authority, f.workers['b'].bearer_token, f.interface,
                    idempotency_key=StableId('expired-sync'), expected_revision=stable_revision,
                )
        self.assertEqual(f.revision(), stable_revision)
