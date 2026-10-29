"""Terminal integration recovery requires accepted provenance and a current source fence."""
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from todo_orchestrator.contracts import (
    EntityKind, EntityRef, EvidenceInput, GitEffectRequest, GitOperationKind,
    ProviderCallContext, ProviderIdentity, ProviderReceipt, Sha256Digest,
    SourceObservation, StableId, WorkingTreeState,
)
from todo_orchestrator.model import AttemptAuthoringHandoff, AttemptAuthoringHandoffRequest, authoring_handoff_request_digest
from todo_orchestrator.operations.inspection import RecoveryInspectionService
from todo_orchestrator.providers.git.service import _source_value
from todo_orchestrator.verification.acceptance import _authoring_handoff_value


class AcceptedGitRetryTests(unittest.TestCase):
    def setUp(self):
        project=StableId('project'); attempt=EntityRef(project,EntityKind.ATTEMPT,StableId('attempt'))
        target=EntityRef(project,EntityKind.WORK_ITEM,StableId('work'),definition_revision_id=StableId('definition'))
        actor=EntityRef(project,EntityKind.ACTOR,StableId('actor'),incarnation_id=StableId('incarnation'))
        capability=EntityRef(project,EntityKind.CAPABILITY,StableId('capability'))
        self.identity=ProviderIdentity(StableId('provider'),'1',1)
        source_digest=Sha256Digest('a'*64);commit=StableId('b'*40);tree=StableId('c'*40)
        self.source=SourceObservation(StableId('repo'),source_digest,Sha256Digest('d'*64),WorkingTreeState.CLEAN,
                                      (EvidenceInput(StableId('input'),Sha256Digest('e'*64)),),source_revision=commit)
        request=AttemptAuthoringHandoffRequest(project,StableId('authority'),attempt,StableId('old-lease'),
                                               StableId('workspace'),StableId('handback-key'))
        receipt=ProviderReceipt(StableId('receipt'),self.identity,attempt.entity_id,
            authoring_handoff_request_digest(request,commit,tree,source_digest),commit,datetime.now(timezone.utc))
        self.proof=AttemptAuthoringHandoff(request,commit,tree,source_digest,receipt)
        self.request=GitEffectRequest(ProviderCallContext(project,actor,capability,StableId('host'),StableId('scope')),
            StableId('operation'),StableId('operation-key'),GitOperationKind.INTEGRATE,source_digest,5,
            workspace_id=request.workspace_id,source_commit=commit,attempt=attempt,target=target)
        self.provenance={'source':_source_value(self.source),
                         'host_safety':{'authoring_handoff':_authoring_handoff_value(self.proof)}}
        self.authority=SimpleNamespace(read_transaction=lambda:nullcontext(None),project=SimpleNamespace())
        self.service=object.__new__(RecoveryInspectionService)
        self.service.operation_inspectors={'git':SimpleNamespace(identity=self.identity)}
        self.service.host=SimpleNamespace(authoring_handoff_for=lambda _attempt:self.proof)

    def check(self,request=None,source=None):
        with patch('todo_orchestrator.providers.git.service._accepted_identity',
                   return_value=(self.provenance,{},'digest')), patch(
                       'todo_orchestrator.operations.inspection._stored_attempt',
                       return_value=(SimpleNamespace(lease=None),{})):
            return self.service._accepted_integration_fenced_for_retry(
                self.authority,request or self.request,source or self.source)

    def test_exact_fence_preserves_no_lease_and_does_not_claim_process_stopped(self):
        self.assertTrue(self.check())
        self.assertFalse(self.service._host_safe_for_retry(None,self.request.attempt,self.request.attempt))

    def test_missing_mismatched_fence_and_changed_full_source_are_not_retryable(self):
        original=self.proof
        for field,value in [('attempt',EntityRef(self.request.context.project_id,EntityKind.ATTEMPT,StableId('other'))),
                            ('workspace_id',StableId('other-workspace'))]:
            request=replace(original.request,**{field:value})
            receipt=replace(original.receipt,correlation_id=request.attempt.entity_id,
                request_digest=authoring_handoff_request_digest(request,original.source_commit,original.source_tree,original.source_digest))
            self.proof=replace(original,request=request,receipt=receipt)
            self.assertFalse(self.check())
        self.proof=None
        self.assertFalse(self.check())
        self.proof=original
        self.assertFalse(self.check(source=replace(self.source,inputs=())))
        self.assertFalse(self.check(source=replace(self.source,working_tree=WorkingTreeState.DIRTY)))
        self.assertFalse(self.check(request=replace(self.request,operation=GitOperationKind.COMMIT)))

    def test_rejected_or_tampered_accepted_provenance_cannot_use_host_fence(self):
        with patch('todo_orchestrator.providers.git.service._accepted_identity',side_effect=ValueError('denied')):
            self.assertFalse(self.service._accepted_integration_fenced_for_retry(self.authority,self.request,self.source))
        self.provenance['host_safety']['authoring_handoff']=None
        self.assertFalse(self.check())
