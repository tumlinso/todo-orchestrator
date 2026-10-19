"""The public application facade exposes authenticated declaration/context writes."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from todo_orchestrator.api import TodoApplication
from todo_orchestrator.authority.auth import CapabilityDeniedError
from todo_orchestrator.contracts import Project, StableId
from todo_orchestrator.model.context import ContextFragmentKind


OWNER_CREDENTIAL = "public facade declarations and findings credential 441"


def _package(project: Project) -> str:
    return json.dumps({
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "public-declaration-context-facade",
        "project": {
            "project_id": str(project.project_id),
            "authority_id": str(project.authority_id),
        },
        "work_items": [{
            "id": "facade-work",
            "title": "Exercise declaration and context APIs",
            "objective": "Resolve a native declaration and publish a sourced finding",
            "outcome": "Both operations have authenticated facade receipts",
            "scope": {"paths": [], "concepts": ["facade"], "locks": []},
            "acceptance": {
                "assertions": ["declaration and finding are durable"],
                "required_evidence": [],
                "allowed_dispositions": ["completed"],
            },
            "ownership": {"mode": "any", "actors": []},
        }],
        "decisions": [{
            "id": "facade-choice",
            "title": "Facade choice",
            "question": "Should the public facade expose declaration writes?",
            "options": [{"id": "yes", "description": "Yes"}, {"id": "no", "description": "No"}],
            "resolvers": [],
            "unknowns": [],
        }],
    }, sort_keys=True, separators=(",", ":"))


class DeclarationContextFacadeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="todo-declaration-context-api-")
        self.addCleanup(self.temporary.cleanup)
        self.project = Project(StableId("facade-context-project"), StableId("facade-context-authority"))
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()

    def initialize(self, *, owner_actions=None):
        options = {} if owner_actions is None else {"owner_actions": owner_actions}
        return TodoApplication.initialize(
            self.root,
            project_id=self.project.project_id,
            repository_id=StableId("facade-context-repository"),
            authority_id=self.project.authority_id,
            owner_credential=OWNER_CREDENTIAL,
            **options,
        )

    def _accept_plan(self, session):
        package_json = _package(self.project)
        preview = session.preview_plan(package_json)
        committed = session.commit_plan(
            package_json, preview, idempotency_key=StableId("facade-context-plan-commit"),
        )
        return StableId(committed.result["plan_revision_id"])

    def test_public_declaration_and_context_writes_roundtrip(self):
        with self.initialize() as session:
            plan_revision_id = self._accept_plan(session)
            decision = session.resolve_decision(
                "facade-choice", "yes", "Select the option through TodoSession.",
                plan_revision_id=plan_revision_id,
                idempotency_key=StableId("facade-context-decision"),
            )
            self.assertTrue(decision.changed)
            opened = session.open_blocker(
                "facade-choice", "A review is temporarily blocking the selected decision.",
                plan_revision_id=plan_revision_id,
                idempotency_key=StableId("facade-context-blocker-open"),
            )
            self.assertTrue(opened.changed)
            cleared = session.clear_blocker(
                "facade-choice", "The review is complete.",
                plan_revision_id=plan_revision_id,
                idempotency_key=StableId("facade-context-blocker-clear"),
            )
            self.assertTrue(cleared.changed)

            work_item = session.work_item_ref("facade-work", plan_revision_id)
            capsule = session.build_context(work_item)
            source_refs = tuple(
                item for item in capsule.manifest.fragments
                if item.kind not in {ContextFragmentKind.FINDINGS, ContextFragmentKind.SCOPED_DELTAS}
            )
            finding = session.publish_finding(
                work_item,
                "The public declaration and context facade is available.",
                session.serialize("context-manifest", capsule.manifest),
                source_refs,
                idempotency_key=StableId("facade-context-finding"),
            )
            self.assertTrue(finding.changed)

            refreshed = session.build_context(work_item)
            findings = next(
                item for item in refreshed.fragments
                if item.reference.kind is ContextFragmentKind.FINDINGS
            )
            rendered = json.loads(findings.payload_json)
            self.assertIn(
                "The public declaration and context facade is available.",
                json.dumps(rendered),
            )

    def test_public_declaration_write_obeys_capability_before_mutating(self):
        with self.initialize(owner_actions=(
            StableId("todo.plan.commit"), StableId("todo.authority.read"),
        )) as session:
            plan_revision_id = self._accept_plan(session)
            before = session.read_model().semantic_revision
            with self.assertRaises(CapabilityDeniedError):
                session.resolve_decision(
                    "facade-choice", "yes", "This session has no declaration-write action.",
                    plan_revision_id=plan_revision_id,
                    idempotency_key=StableId("facade-context-denied-decision"),
                )
            self.assertEqual(session.read_model().semantic_revision, before)


if __name__ == "__main__":
    unittest.main()
