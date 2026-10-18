"""Internal, process-local proof that a recovery intent was freshly approved.

The proof is issued only by the recovery execution service after it has
reauthorized the principal and re-inspected the exact R01 intent. It is not a
credential and cannot replace writer-side capability, revision, lease, source,
or operation checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json

from todo_orchestrator.contracts import EntityRef, Sha256Digest, StableId
from todo_orchestrator.model import AttemptSafetyObservation


_RECOVERY_APPROVAL_SEAL = object()


@dataclass(frozen=True)
class RecoveryApproval:
    intent_kind: str
    actor: EntityRef
    capability_id: StableId
    target: EntityRef
    attempt: EntityRef | None
    run: EntityRef | None
    assignment: EntityRef | None
    operation: EntityRef | None
    intent_digest: Sha256Digest
    authority_revision: int
    expected_lease_id: StableId | None
    expected_lease_expires_at: datetime | None
    expected_source_digest: Sha256Digest | None
    host_observation: AttemptSafetyObservation | None
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._seal is not _RECOVERY_APPROVAL_SEAL:
            raise ValueError("recovery approvals are issued only by the recovery execution service")
        if not isinstance(self.intent_kind, str) or not self.intent_kind:
            raise ValueError("intent_kind must be non-empty text")
        if not isinstance(self.actor, EntityRef) or not isinstance(self.capability_id, StableId):
            raise TypeError("recovery approval requires an authenticated actor and capability")
        if not isinstance(self.target, EntityRef):
            raise TypeError("target must be an EntityRef")
        if not isinstance(self.intent_digest, Sha256Digest):
            raise TypeError("intent_digest must be a Sha256Digest")
        if type(self.authority_revision) is not int or self.authority_revision < 0:
            raise ValueError("authority_revision must be a non-negative integer")
        if self.expected_lease_id is not None and not isinstance(self.expected_lease_id, StableId):
            raise TypeError("expected_lease_id must be a StableId or None")
        if self.expected_source_digest is not None and not isinstance(self.expected_source_digest, Sha256Digest):
            raise TypeError("expected_source_digest must be a Sha256Digest or None")
        if self.host_observation is not None and not isinstance(self.host_observation, AttemptSafetyObservation):
            raise TypeError("host_observation must be an AttemptSafetyObservation or None")

    def __deepcopy__(self, memo):
        return self


def _issue_recovery_approval(**values: object) -> RecoveryApproval:
    """Trusted in-process issuance seam; callers must first reauthorize and inspect."""
    return RecoveryApproval(**values, _seal=_RECOVERY_APPROVAL_SEAL)  # type: ignore[arg-type]


def _is_recovery_approval(value: object) -> bool:
    return isinstance(value, RecoveryApproval) and value._seal is _RECOVERY_APPROVAL_SEAL


def _recovery_approval_digest(value: RecoveryApproval) -> str:
    """Return a stable audit binding for one sealed approval's exact evidence."""
    if not _is_recovery_approval(value):
        raise TypeError("a sealed RecoveryApproval is required")
    observation = value.host_observation
    host = None
    if observation is not None:
        receipt = observation.receipt
        host = {
            "attempt": str(observation.attempt.entity_id),
            "state": observation.observed_state.value,
            "lease_id": str(observation.lease_id),
            "lease_expires_at": observation.observed_lease_expires_at.isoformat(),
            "workspace_id": str(observation.workspace.workspace_id),
            "source": observation.source.value,
            "source_digest": None if observation.source_digest is None else observation.source_digest.hex,
            "process": observation.process.value,
            "children": observation.children.value,
            "receipt": {
                "receipt_id": str(receipt.receipt_id),
                "provider_id": str(receipt.provider.provider_id),
                "provider_version": receipt.provider.version,
                "contract_version": receipt.provider.contract_version,
                "correlation_id": str(receipt.correlation_id),
                "request_digest": receipt.request_digest.hex,
                "provenance_ref": str(receipt.provenance_ref),
                "observed_at": receipt.observed_at.isoformat(),
            },
        }
    payload = {
        "intent_kind": value.intent_kind,
        "actor": [str(value.actor.project_id), str(value.actor.entity_id), str(value.actor.incarnation_id)],
        "capability_id": str(value.capability_id),
        "target": [str(value.target.project_id), value.target.kind.value,
                   str(value.target.entity_id), str(value.target.definition_revision_id)],
        "attempt": None if value.attempt is None else str(value.attempt.entity_id),
        "run": None if value.run is None else str(value.run.entity_id),
        "assignment": None if value.assignment is None else str(value.assignment.entity_id),
        "operation": None if value.operation is None else str(value.operation.entity_id),
        "intent_digest": value.intent_digest.hex,
        "authority_revision": value.authority_revision,
        "expected_lease_id": None if value.expected_lease_id is None else str(value.expected_lease_id),
        "expected_lease_expires_at": None if value.expected_lease_expires_at is None
            else value.expected_lease_expires_at.isoformat(),
        "expected_source_digest": None if value.expected_source_digest is None
            else value.expected_source_digest.hex,
        "host_observation": host,
    }
    encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


__all__ = ["RecoveryApproval"]
