"""Focused validation of the trusted verifier boundary."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import unittest

from todo_orchestrator.contracts import (
    CommandObservation,
    EntityKind,
    EntityRef,
    EvidenceInput,
    EvidenceKind,
    EvidenceResult,
    EvidenceRequirement,
    ProviderIdentity,
    ProviderReceipt,
    Sha256Digest,
    StableId,
    VerificationContract,
    VerificationEvidenceFact,
    VerificationObservation,
    VerificationRequest,
    provider_request_digest,
)
from todo_orchestrator.contracts.providers import ProviderCallContext
from todo_orchestrator.verification.service import (
    VerificationObservationMismatchError,
    VerificationService,
    _contract_digest,
)


NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
PROJECT_ID = StableId("execution-boundary-project")
IDENTITY = ProviderIdentity(StableId("execution-boundary-verifier"), "v1")


class _CommandObservationValidator:
    def validate_observation(self, request, observation):
        receipt = observation.command_receipt
        return bool(
            receipt is not None and receipt.provider == IDENTITY
            and receipt.correlation_id == request.operation_id
            and receipt.provenance_ref == request.operation_id
        )


class VerificationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.service = object.__new__(VerificationService)
        self.service.provider_identity = IDENTITY
        self.service.provider = _CommandObservationValidator()
        self.service.clock = lambda: NOW
        self.contract = VerificationContract.from_mapping({
            "kind": "command", "version": 1, "config": {"argv": ["test-check"]},
        })
        self.operation = StableId("execution-boundary-operation")
        self.actor = EntityRef(
            PROJECT_ID, EntityKind.ACTOR, StableId("execution-boundary-actor"),
            incarnation_id=StableId("execution-boundary-incarnation"),
        )
        self.request = VerificationRequest(
            ProviderCallContext(
                PROJECT_ID, self.actor,
                EntityRef(PROJECT_ID, EntityKind.CAPABILITY, StableId("execution-boundary-capability")),
                StableId("execution-boundary-context"), StableId("execution-boundary-scope"),
            ),
            EntityRef(PROJECT_ID, EntityKind.ATTEMPT, StableId("execution-boundary-attempt")),
            EntityRef(PROJECT_ID, EntityKind.REQUIREMENT, StableId("execution-boundary-requirement"),
                      StableId("execution-boundary-definition")),
            self.operation, StableId("execution-boundary-idempotency"), IDENTITY.provider_id,
            Sha256Digest("1" * 64), _contract_digest(self.contract),
            (EvidenceInput(StableId("manifest"), Sha256Digest("2" * 64)),),
            self.contract, StableId("execution-boundary-workspace"), IDENTITY.version,
            (EvidenceRequirement(StableId("report"), EvidenceKind.COMMAND_RESULT),),
        )
        self.fact = VerificationEvidenceFact(
            StableId("report"), EvidenceKind.COMMAND_RESULT, 1, Sha256Digest("3" * 64),
        )

    def observation(self, *, version="v1", fact=None):
        return VerificationObservation(
            self.operation, EvidenceResult.PASS, IDENTITY.provider_id, version,
            self.request.expected_source, self.request.contract_digest, self.request.inputs,
            (), (self.fact if fact is None else fact,),
            CommandObservation(self.operation, 0, False, NOW - timedelta(seconds=1), NOW),
            ProviderReceipt(StableId("execution-boundary-command-receipt"), IDENTITY,
                            self.operation, Sha256Digest("5" * 64), self.operation, NOW),
        )

    def receipt(self, *, observed_at=NOW):
        return ProviderReceipt(
            StableId("execution-boundary-receipt"), IDENTITY, self.operation,
            provider_request_digest(self.request), self.operation, observed_at,
        )

    def validate(self, observation=None, receipt=None):
        self.service._validate_observation(
            observation or self.observation(), self.request, receipt or self.receipt(),
            authorized_at=NOW - timedelta(seconds=1),
        )

    def test_valid_receipt_and_exact_named_evidence_are_accepted(self):
        self.validate()

    def test_provider_version_must_match_the_persisted_identity(self):
        with self.assertRaises(VerificationObservationMismatchError):
            self.validate(self.observation(version="unconfigured-version"))

    def test_provider_must_supply_exact_authored_evidence_name_kind_and_version(self):
        wrong_fact = VerificationEvidenceFact(
            StableId("different-report"), EvidenceKind.COMMAND_RESULT, 1, Sha256Digest("4" * 64),
        )
        with self.assertRaises(VerificationObservationMismatchError):
            self.validate(self.observation(fact=wrong_fact))

    def test_receipt_must_be_inside_the_authorized_operation_interval(self):
        for observed_at in (NOW - timedelta(seconds=2), NOW + timedelta(seconds=1)):
            with self.subTest(observed_at=observed_at), self.assertRaises(VerificationObservationMismatchError):
                self.validate(receipt=self.receipt(observed_at=observed_at))


if __name__ == "__main__":
    unittest.main()
