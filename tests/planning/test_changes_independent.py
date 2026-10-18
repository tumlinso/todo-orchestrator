"""Independent adversarial coverage for pure plan-change preview."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from todo_orchestrator.contracts.domain import (
    Attempt,
    AttemptState,
    EntityKind,
    EntityRef,
    Project,
    Sha256Digest,
    StableId,
)
from todo_orchestrator.planning import (
    AcceptedSnapshot,
    AdoptionReceipt,
    ChangeKind,
    VerifiedAdoption,
    compile_plan,
    parse_plan_json,
    preview_changes,
)

try:
    from .test_package import package_document
except ImportError:
    from test_package import package_document


PROJECT = Project(StableId("project-a"), StableId("authority-a"))


def compile_document(document, *, adoptions=(), source_name="independent-fixture"):
    parsed = parse_plan_json(json.dumps(document), source_name=source_name)
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    compiled = compile_plan(parsed.package, PROJECT, adoption_facts=tuple(adoptions))
    if not compiled.ok:
        raise AssertionError(compiled.diagnostics)
    return compiled.plan


def make_snapshot(plan, *, revision=41, attempts=()):
    return AcceptedSnapshot(
        authority_id=PROJECT.authority_id,
        project_id=PROJECT.project_id,
        authority_revision=revision,
        accepted_plan=plan,
        attempts=tuple(attempts),
    )


def work_ref(plan, identifier):
    return next(item.definition.ref for item in plan.work_items if item.definition.work_item_id == StableId(identifier))


class IndependentPlanChangePreviewTests(unittest.TestCase):
    def test_preview_is_a_pure_semantic_noop_across_source_metadata_and_order(self):
        document = package_document()
        with tempfile.TemporaryDirectory() as temporary:
            absent_source = Path(temporary) / "must-not-be-created.json"
            document["source_manifests"][0]["location"] = str(absent_source)
            accepted = compile_document(document, source_name="accepted.json")

            cosmetically_changed = copy.deepcopy(document)
            cosmetically_changed["work_items"].reverse()
            cosmetically_changed["source_manifests"].reverse()
            cosmetically_changed["provenance"] = {"source": "different", "producer": "another-tool"}
            cosmetically_changed["generation_metadata"] = {"generator": "new-generator", "parameters": {"seed": 99}}
            proposed = compile_document(cosmetically_changed, source_name="proposal.json")

            first = preview_changes(proposed, make_snapshot(accepted))
            second = preview_changes(accepted, make_snapshot(accepted))

            self.assertTrue(first.is_noop)
            self.assertEqual(first.digest, second.digest)
            self.assertEqual(first.expected_authority_revision, 41)
            self.assertEqual(first.proposed_revision_id, accepted.revision.plan_revision_id)
            self.assertFalse(absent_source.exists())

    def test_omitted_optional_record_field_preserves_while_explicit_empty_clears(self):
        original = package_document()
        accepted = compile_document(original)
        original_build = next(item for item in accepted.work_items if item.definition.work_item_id == StableId("build"))

        partial_record = {
            key: copy.deepcopy(original_build_value)
            for key, original_build_value in original["work_items"][0].items()
            if key in {"id", "title", "objective", "outcome", "scope", "acceptance"}
        }
        partial_record["title"] = "Build package, revised"
        partial = {
            "format": original["format"],
            "schema_version": original["schema_version"],
            "package_id": "partial-preserve",
            "project": copy.deepcopy(original["project"]),
            "work_items": [partial_record],
        }
        preserve = preview_changes(compile_document(partial), make_snapshot(accepted))
        preserve_op = next(op for op in preserve.operations if op.kind is ChangeKind.REVISE and op.entity_id == StableId("build"))
        self.assertEqual(preserve_op.after_value["references"], tuple(dict(item) for item in original_build.context.references))
        self.assertIn(work_ref(accepted, "verify"), preserve.effective_definitions)

        explicit_clear = copy.deepcopy(partial)
        explicit_clear["package_id"] = "partial-clear"
        explicit_clear["work_items"][0]["references"] = []
        clear = preview_changes(compile_document(explicit_clear), make_snapshot(accepted))
        clear_op = next(op for op in clear.operations if op.kind is ChangeKind.REVISE and op.entity_id == StableId("build"))
        self.assertEqual(clear_op.after_value["references"], ())
        self.assertNotEqual(clear.digest, preserve.digest)
        self.assertIn(work_ref(accepted, "verify"), clear.effective_definitions)

    def test_multiple_active_attempt_conflicts_are_order_independent(self):
        original = package_document()
        accepted = compile_document(original)
        changed = copy.deepcopy(original)
        changed["work_items"][0]["title"] = "Build revised"
        changed["work_items"][1]["title"] = "Verify revised"
        actor = EntityRef(PROJECT.project_id, EntityKind.ACTOR, StableId("maintainer"), incarnation_id=StableId("incarnation-1"))
        attempts = (
            Attempt(StableId("attempt-build-a"), PROJECT.project_id, work_ref(accepted, "build"), actor, AttemptState.ACTIVE),
            Attempt(StableId("attempt-build-b"), PROJECT.project_id, work_ref(accepted, "build"), actor, AttemptState.ACTIVE),
            Attempt(StableId("attempt-verify"), PROJECT.project_id, work_ref(accepted, "verify"), actor, AttemptState.ACTIVE),
        )

        forward = preview_changes(compile_document(changed), make_snapshot(accepted, attempts=attempts))
        reverse = preview_changes(compile_document(changed), make_snapshot(accepted, attempts=tuple(reversed(attempts))))

        active = [item for item in forward.conflicts if item.code == "active_attempt_requires_transition"]
        self.assertEqual(len(active), 3)
        self.assertEqual({str(item.related.entity_id) for item in active}, {"attempt-build-a", "attempt-build-b", "attempt-verify"})
        self.assertEqual(forward.conflicts, reverse.conflicts)
        self.assertEqual(forward.digest, reverse.digest)

    def test_effective_graph_detects_cycle_through_omitted_accepted_definition(self):
        accepted_document = package_document()
        accepted_document["dependencies"] = [{
            "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "verify"},
            "mode": "all",
            "members": [{
                "relation": "completion",
                "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
            }],
        }]
        accepted = compile_document(accepted_document)
        omitted_target = work_ref(accepted, "verify")
        proposal_document = {
            "format": accepted_document["format"],
            "schema_version": accepted_document["schema_version"],
            "package_id": "introduce-cycle",
            "project": copy.deepcopy(accepted_document["project"]),
            "work_items": [copy.deepcopy(accepted_document["work_items"][0])],
            "requirements": copy.deepcopy(accepted_document["requirements"]),
            "dependencies": [{
                "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
                "mode": "all",
                "members": [{
                    "relation": "completion",
                    "target": {
                        "project_id": "project-a", "kind": "work_item", "entity_id": "verify",
                        "revision_id": str(omitted_target.definition_revision_id),
                    },
                }],
            }],
        }

        preview = preview_changes(compile_document(proposal_document), make_snapshot(accepted))

        self.assertIn("blocking_cycle", {item.code for item in preview.diagnostics})

    def test_foreign_adoption_contract_change_remains_a_typed_dependency_change(self):
        foreign = EntityRef(StableId("project-b"), EntityKind.INTERFACE, StableId("external-api"))

        def plan_with_digest(digest):
            document = package_document()
            document["dependencies"] = [{
                "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
                "mode": "all",
                "members": [{
                    "relation": "interface_version",
                    "expected_version": "1.2",
                    "target": {
                        "project_id": "project-b", "kind": "interface", "entity_id": "external-api",
                        "adoption_receipt": {
                            "receipt_id": "receipt-api", "authority_id": "authority-b", "contract_digest": digest,
                        },
                    },
                }],
            }]
            receipt = AdoptionReceipt(StableId("receipt-api"), StableId("authority-b"), Sha256Digest(digest))
            fact = VerifiedAdoption(StableId("verification-api"), "interface", foreign, receipt, "1.2", "evolvable")
            return compile_document(document, adoptions=(fact,))

        accepted = plan_with_digest("a" * 64)
        proposed = plan_with_digest("b" * 64)
        changes = preview_changes(proposed, make_snapshot(accepted))

        dependency_ops = [op for op in changes.operations if op.entity_kind == "dependency"]
        self.assertEqual({op.kind for op in dependency_ops}, {ChangeKind.UNLINK, ChangeKind.LINK})
        self.assertTrue(any(op.related_before == foreign for op in dependency_ops))
        self.assertTrue(any(op.related_after == foreign for op in dependency_ops))
        self.assertNotEqual(accepted.revision.plan_revision_id, proposed.revision.plan_revision_id)


if __name__ == "__main__":
    unittest.main()
