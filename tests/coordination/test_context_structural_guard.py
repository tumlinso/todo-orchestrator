"""Independent regressions for credential-bearing identities and finding scope."""

from copy import deepcopy
import json
import unittest

from todo_orchestrator.contracts import StableId
from todo_orchestrator.coordination.context import (
    ContextFindingConflictError, ContextUnavailableError,
)
from todo_orchestrator.model.context import ContextFragmentKind
from tests.coordination import test_context_independent as fixtures


class ContextStructuralGuardTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ContextFlowTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    @staticmethod
    def work_reference(capsule):
        return next(ref for ref in capsule.manifest.fragments
                    if ref.kind is ContextFragmentKind.WORK_ITEM)

    def test_issued_bearer_as_authored_work_id_cannot_escape_through_manifest(self):
        f = self.f
        secret = f.owner.bearer_token
        document = json.loads(f.package)
        item = deepcopy(document['work_items'][0])
        item.update(id=secret, title='Opaque named work',
                    scope={'paths': [], 'concepts': [], 'locks': []})
        document['work_items'].append(item)
        source = json.dumps(document)
        with f.writer() as authority:
            preview = f.plans.preview(authority, source)
            f.plans.commit(
                authority, f.owner.bearer_token, source, reviewed_digest=preview.digest,
                idempotency_key=StableId('structural-secret-plan'),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            plan = f.plans.load_accepted_plan(authority)
        target = next(work.definition.ref for work in plan.work_items
                      if str(work.definition.work_item_id) == secret)
        before = f.revision()
        with f.reader() as authority:
            with self.assertRaises(ContextUnavailableError) as raised:
                f.service.build_context(authority, f.owner.bearer_token, target)
        self.assertFalse(secret in str(raised.exception), 'error must not echo the credential')
        self.assertEqual(f.revision(), before)

    def test_issued_bearer_as_finding_id_is_rejected_before_receipt_or_storage(self):
        f = self.f
        capsule = f._build('a', max_bytes=65536)
        secret = f.worker_contexts['a'].bearer_token
        before = f.revision()
        with f.writer() as authority:
            with self.assertRaises(ContextUnavailableError) as raised:
                f.service.publish_finding(
                    authority, secret, summary='The task scope was reviewed.',
                    source_manifest=capsule.manifest,
                    source_fragments=(self.work_reference(capsule),),
                    finding_id=StableId(secret), expected_finding_version=None,
                    **f._context_args('a'), idempotency_key=StableId('structural-secret-finding'),
                    expected_revision=before,
                )
        self.assertFalse(secret in str(raised.exception), 'error must not echo the credential')
        self.assertEqual(f.revision(), before)
        with f.reader() as authority:
            self.assertEqual(authority.connection.execute(
                'SELECT count(*) FROM context_finding_versions WHERE finding_id = ?', (secret,),
            ).fetchone()[0], 0)
            self.assertEqual(authority.connection.execute(
                'SELECT count(*) FROM command_idempotency WHERE idempotency_key = ?',
                ('structural-secret-finding',),
            ).fetchone()[0], 0)

    def test_finding_identity_cannot_move_between_bound_and_run_free_contexts(self):
        f = self.f
        bound = f._build('a', max_bytes=65536)
        identifier = StableId('context-bound-finding')
        with f.writer() as authority:
            f.service.publish_finding(
                authority, f.worker_contexts['a'].bearer_token,
                summary='The assigned task scope was reviewed.', source_manifest=bound.manifest,
                source_fragments=(self.work_reference(bound),), finding_id=identifier,
                expected_finding_version=None, **f._context_args('a'),
                idempotency_key=StableId('context-bound-finding-first'), expected_revision=f.revision(),
            )
        target = f._context_args('a')['work_item']
        with f.reader() as authority:
            unbound = f.service.build_context(authority, f.owner.bearer_token, target,
                                             max_bytes=65536)
        before = f.revision()
        with f.writer() as authority:
            with self.assertRaises(ContextFindingConflictError):
                f.service.publish_finding(
                    authority, f.owner.bearer_token, target,
                    'This note belongs to the separate run-free context.', unbound.manifest,
                    (self.work_reference(unbound),), finding_id=identifier,
                    expected_finding_version=1,
                    idempotency_key=StableId('context-bound-finding-move'), expected_revision=before,
                )
        self.assertEqual(f.revision(), before)
        current = f._build('a', max_bytes=65536)
        findings = next(fragment for fragment in current.fragments
                        if fragment.reference.kind is ContextFragmentKind.FINDINGS)
        self.assertIn('The assigned task scope was reviewed.', findings.payload_json)
