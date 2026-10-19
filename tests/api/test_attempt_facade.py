"""Attempt leases are reachable through the public session and trusted host port."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api import ProviderComposition, TodoApplication
from todo_orchestrator.contracts import (
    Project,
    ProviderIdentity,
    ProviderReceipt,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.model import (
    AttemptSafetyObservation,
    ChildActivity,
    ProcessLiveness,
    QualifiedDestination,
    QualifiedSourceRevision,
    SourceSafety,
    WorkspaceQualification,
)


NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
OWNER_CREDENTIAL = "public attempt facade credential 618"


def _package(project: Project) -> str:
    return json.dumps({
        "format": "todo-orchestrator.plan", "schema_version": 1,
        "package_id": "public-attempt-facade", "project": {
            "project_id": str(project.project_id), "authority_id": str(project.authority_id),
        },
        "work_items": [{
            "id": "attempt-work", "title": "Claim through the session",
            "objective": "Exercise authenticated claim and lease methods",
            "outcome": "Claim, heartbeat and release are public API operations",
            "scope": {"paths": [{"path": "src/work", "access": "write"}], "concepts": [], "locks": []},
            "acceptance": {"assertions": ["lease methods run"], "required_evidence": [],
                           "allowed_dispositions": ["completed"]},
            "ownership": {"mode": "any", "actors": []},
        }],
    }, sort_keys=True, separators=(",", ":"))


class _Host:
    identity = ProviderIdentity(StableId("attempt-facade-host"), "1")

    def __init__(self, project_id: StableId):
        self.project_id = project_id
        self.repository_id = StableId("attempt-facade-repository")

    def qualify_workspace(self, workspace_id, target, correlation_id):
        base = QualifiedSourceRevision(
            self.project_id, self.repository_id, StableId("attempt-facade-base"), "a" * 64,
        )
        receipt = ProviderReceipt(
            StableId("attempt-facade-qual-" + str(correlation_id)), self.identity,
            correlation_id, Sha256Digest("b" * 64), base.ref, NOW,
        )
        return WorkspaceQualification(
            workspace_id, self.repository_id, base,
            QualifiedDestination(self.project_id, self.repository_id, StableId("attempt-facade-main")),
            receipt,
        )

    def inspect_attempt(self, attempt, workspace):
        receipt = ProviderReceipt(
            StableId("attempt-facade-inspect-" + str(attempt.attempt_id)), self.identity,
            attempt.attempt_id, Sha256Digest("c" * 64), workspace.common_base.ref, NOW,
        )
        return AttemptSafetyObservation(
            attempt.ref, attempt.state, attempt.lease.lease_id, attempt.lease.expires_at,
            workspace, SourceSafety.CLEAN, ProcessLiveness.STOPPED, ChildActivity.NONE, receipt,
        )


class AttemptFacadeTests(unittest.TestCase):
    def test_claim_heartbeat_and_release_use_the_public_host_bound_facade(self):
        temporary = tempfile.TemporaryDirectory(prefix="todo-attempt-facade-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "project"
        root.mkdir()
        project = Project(StableId("attempt-facade-project"), StableId("attempt-facade-authority"))
        host = _Host(project.project_id)
        providers = ProviderComposition(
            attempt_host=host,
            host_identity=host.identity,
            clock=lambda: NOW,
        )
        with TodoApplication.initialize(
            root,
            project_id=project.project_id,
            repository_id=host.repository_id,
            authority_id=project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            providers=providers,
        ) as session:
            package_json = _package(project)
            preview = session.preview_plan(package_json)
            committed = session.commit_plan(
                package_json, preview, idempotency_key=StableId("attempt-facade-commit"),
            )
            plan_revision = StableId(committed.result["plan_revision_id"])
            claimed = session.claim_attempt(
                "attempt-work", "attempt-facade-workspace", plan_revision_id=plan_revision,
                idempotency_key=StableId("attempt-facade-claim"),
            )
            attempt_id = StableId(claimed.result["attempt_id"])
            lease_id = StableId(claimed.result["lease_id"])
            self.assertTrue(claimed.changed)

            renewed = session.heartbeat_attempt(
                attempt_id, lease_id, plan_revision_id=plan_revision,
                idempotency_key=StableId("attempt-facade-heartbeat"),
            )
            self.assertTrue(renewed.changed)
            renewed_lease = StableId(renewed.result["lease_id"])
            released = session.release_attempt(
                attempt_id, renewed_lease, idempotency_key=StableId("attempt-facade-release"),
            )
            self.assertTrue(released.changed)


if __name__ == "__main__":
    unittest.main()
