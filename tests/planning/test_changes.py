import copy
import json
import unittest
from datetime import datetime, timezone

from todo_orchestrator.contracts.domain import Attempt, AttemptState, EntityKind, EntityRef, Outcome, OutcomeDisposition, Project, Sha256Digest, StableId
from todo_orchestrator.planning import (
    AdoptionReceipt,
    AcceptedSnapshot,
    ChangeKind,
    ExplicitRetirement,
    VerifiedAdoption,
    compile_plan,
    parse_plan_json,
    preview_changes,
)
if __package__:
    from .test_package import package_document
else:
    from test_package import package_document


PROJECT = Project(StableId("project-a"), StableId("authority-a"))


def compiled(document):
    parsed = parse_plan_json(json.dumps(document))
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    result = compile_plan(parsed.package, PROJECT)
    if not result.ok:
        raise AssertionError(result.diagnostics)
    return result.plan


def compiled_with_adoption(document, digest):
    parsed = parse_plan_json(json.dumps(document))
    if not parsed.ok:
        raise AssertionError(parsed.diagnostics)
    reference = EntityRef(StableId("project-b"), EntityKind.WORK_ITEM, StableId("external"), StableId("external-rev"))
    receipt = AdoptionReceipt(StableId("receipt-1"), StableId("authority-b"), digest)
    result = compile_plan(parsed.package, PROJECT, adoption_facts=(
        VerifiedAdoption(StableId("verification-1"), "work_item", reference, receipt),
    ))
    if not result.ok:
        raise AssertionError(result.diagnostics)
    return result.plan


def snapshot(plan, *, revision=7, attempts=(), outcomes=(), locks=()):
    return AcceptedSnapshot(
        authority_id=PROJECT.authority_id,
        project_id=PROJECT.project_id,
        authority_revision=revision,
        accepted_plan=plan,
        attempts=tuple(attempts),
        outcomes=tuple(outcomes),
        locked_work_items=tuple(locks),
    )


class PlanChangePreviewTests(unittest.TestCase):
    def test_same_package_is_a_deterministic_noop(self):
        plan = compiled(package_document())
        first = preview_changes(plan, snapshot(plan))
        second = preview_changes(plan, snapshot(plan))
        self.assertTrue(first.is_noop)
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.expected_revision_id, plan.revision.plan_revision_id)
        self.assertEqual(first.expected_authority_revision, 7)
        self.assertEqual(set(first.effective_definitions), {
            *(item.definition.ref for item in plan.work_items),
            *(item.definition.ref for item in plan.requirements),
            *(EntityRef(PROJECT.project_id, {
                "checkpoints": EntityKind.CHECKPOINT, "interfaces": EntityKind.INTERFACE,
                "decisions": EntityKind.DECISION, "barriers": EntityKind.BARRIER,
                "rendezvous": EntityKind.BARRIER, "invariants": EntityKind.INVARIANT,
            }[item.kind], item.declaration_id) for item in plan.declarations),
        })

    def test_initial_import_has_explicit_no_plan_precondition(self):
        proposal = compiled(package_document())
        initial = AcceptedSnapshot(PROJECT.authority_id, PROJECT.project_id, 0, None)
        changes = preview_changes(proposal, initial)
        self.assertIsNone(changes.expected_revision_id)
        self.assertEqual(changes.expected_authority_revision, 0)
        self.assertIn(ChangeKind.CREATE, {operation.kind for operation in changes.operations})
        self.assertTrue(all(operation.before is None for operation in changes.operations if operation.kind is ChangeKind.CREATE))
        self.assertFalse(changes.conflicts)

    def test_authority_revision_is_a_digest_precondition(self):
        plan = compiled(package_document())
        seven = preview_changes(plan, snapshot(plan, revision=7))
        eight = preview_changes(plan, snapshot(plan, revision=8))
        self.assertNotEqual(seven.digest, eight.digest)
        self.assertEqual(eight.expected_authority_revision, 8)

    def test_partial_package_preserves_omitted_records_and_optional_fields(self):
        original = package_document()
        accepted = compiled(original)
        partial = {
            key: copy.deepcopy(value)
            for key, value in original.items()
            if key in {"format", "schema_version", "project"}
        }
        partial.update({"package_id": "partial", "work_items": [{
            "id": "build", "title": "Build package, revised", "objective": "Create the package",
            "outcome": "A tested package exists", "scope": copy.deepcopy(original["work_items"][0]["scope"]),
            "acceptance": copy.deepcopy(original["work_items"][0]["acceptance"]),
        }]})
        proposed = compiled(partial)
        changes = preview_changes(proposed, snapshot(accepted))
        revisions = [op for op in changes.operations if op.kind is ChangeKind.REVISE and op.entity_kind == "work_item"]
        self.assertEqual(len(revisions), 1)
        self.assertEqual(revisions[0].entity_id, StableId("build"))
        self.assertEqual(revisions[0].before_value["ownership"], revisions[0].after_value["ownership"])
        self.assertEqual(revisions[0].before_value["requirement_groups"], revisions[0].after_value["requirement_groups"])
        self.assertEqual(revisions[0].before_value["scope"], revisions[0].after_value["scope"])
        effective_build = next(item for item in changes.effective_plan.work_items if item.definition.work_item_id == StableId("build"))
        self.assertEqual(effective_build.context.motivation, accepted.work_items[0].context.motivation)
        self.assertEqual(effective_build.context.references, accepted.work_items[0].context.references)
        self.assertEqual(effective_build.context.ownership, accepted.work_items[0].context.ownership)
        retained = set(changes.effective_definitions)
        self.assertIn(accepted.work_items[1].definition.ref, retained)
        self.assertIn(EntityRef(PROJECT.project_id, EntityKind.INTERFACE, StableId("package-api")), retained)
        self.assertFalse(changes.diagnostics)

    def test_unrelated_replan_preserves_unchanged_definition_identity(self):
        original = package_document()
        accepted = compiled(original)
        revised = copy.deepcopy(original)
        revised["work_items"][0]["title"] = "Build package v2"
        changes = preview_changes(compiled(revised), snapshot(accepted))
        verify_ref = next(item.definition.ref for item in accepted.work_items if item.definition.work_item_id == StableId("verify"))
        self.assertIn(verify_ref, changes.effective_definitions)
        self.assertFalse(any(op.entity_id == StableId("verify") and op.kind in {ChangeKind.CREATE, ChangeKind.REVISE} for op in changes.operations))

    def test_requirement_only_change_revises_owner_bundle_and_binds_requirement(self):
        original = package_document()
        accepted = compiled(original)
        revised = copy.deepcopy(original)
        revised["requirements"][0]["description"] = "Run all package tests"
        owner_ref = accepted.work_items[0].definition.ref
        changes = preview_changes(compiled(revised), snapshot(accepted))
        owner_revision = next(op.after for op in changes.operations if op.entity_kind == "work_item" and op.entity_id == StableId("build") and op.kind is ChangeKind.REVISE)
        requirement_revision = next(op.after for op in changes.operations if op.entity_kind == "requirement" and op.entity_id == StableId("tests") and op.kind is ChangeKind.REVISE)
        self.assertNotEqual(owner_revision, owner_ref)
        self.assertEqual(requirement_revision.definition_revision_id, owner_revision.definition_revision_id)

        active_attempt = Attempt(
            StableId("attempt-build"), PROJECT.project_id, owner_ref,
            EntityRef(PROJECT.project_id, EntityKind.ACTOR, StableId("maintainer"), incarnation_id=StableId("incarnation-1")),
            AttemptState.ACTIVE,
        )
        blocked = preview_changes(compiled(revised), snapshot(accepted, attempts=(active_attempt,)))
        self.assertIn("active_attempt_requires_transition", {conflict.code for conflict in blocked.conflicts})

    def test_dependency_only_change_revises_source_work_bundle(self):
        original = package_document()
        accepted = compiled(original)
        revised = copy.deepcopy(original)
        revised["dependencies"][0]["members"][0] = {
            "relation": "completion",
            "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
        }
        changes = preview_changes(compiled(revised), snapshot(accepted))
        source_old = next(item.definition.ref for item in accepted.work_items if item.definition.work_item_id == StableId("verify"))
        source_new = next(op.after for op in changes.operations if op.entity_kind == "work_item" and op.entity_id == StableId("verify") and op.kind is ChangeKind.REVISE)
        self.assertNotEqual(source_old, source_new)
        self.assertTrue(all(op.after == source_new for op in changes.operations if op.entity_kind in {"dependency", "dependency_group"} and op.entity_id == StableId("verify")))

    def test_explicit_empty_section_is_not_retirement(self):
        document = package_document()
        accepted = compiled(document)
        document["interfaces"] = []
        proposed = compiled(document)
        changes = preview_changes(proposed, snapshot(accepted))
        self.assertFalse(any(op.kind is ChangeKind.RETIRE for op in changes.operations))
        self.assertIn(EntityRef(PROJECT.project_id, EntityKind.INTERFACE, StableId("package-api")), changes.effective_definitions)

    def test_explicit_retirement_is_exact_and_preserves_terminal_history(self):
        plan = compiled(package_document())
        work = plan.work_items[0].definition.ref
        accepted_by = EntityRef(PROJECT.project_id, EntityKind.ACTOR, StableId("maintainer"), incarnation_id=StableId("incarnation-1"))
        outcome = Outcome(
            StableId("outcome-1"), PROJECT.project_id, work, 1, OutcomeDisposition.COMPLETED,
            accepted_by, datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        changes = preview_changes(
            plan, snapshot(plan, outcomes=(outcome,)),
            explicit_retirements=(ExplicitRetirement(work),),
        )
        self.assertTrue(any(op.kind is ChangeKind.RETIRE and op.before == work for op in changes.operations))
        self.assertIn("accepted_outcome_preserved", {conflict.code for conflict in changes.conflicts})
        self.assertNotIn(work, changes.effective_definitions)

    def test_retirement_revalidates_final_graph_membership(self):
        plan = compiled(package_document())
        work = next(item.definition.ref for item in plan.work_items if item.definition.work_item_id == StableId("build"))
        changes = preview_changes(plan, snapshot(plan), explicit_retirements=(ExplicitRetirement(work),))
        self.assertIn("retired_definition_still_referenced", {item.code for item in changes.diagnostics})

    def test_changed_source_manifest_is_a_reviewed_semantic_operation(self):
        original = package_document()
        accepted = compiled(original)
        revised = copy.deepcopy(original)
        revised["source_manifests"][0]["sha256"] = "c" * 64
        changes = preview_changes(compiled(revised), snapshot(accepted))
        operation = next(item for item in changes.operations if item.entity_kind == "plan_metadata")
        self.assertEqual(operation.relation, "source_manifests")
        self.assertNotEqual(operation.before_value, operation.after_value)

    def test_active_work_revisions_and_weakened_gates_are_blocked_per_definition(self):
        document = package_document()
        accepted = compiled(document)
        revised = copy.deepcopy(document)
        revised["work_items"][0]["title"] = "Revised build"
        revised["work_items"][1]["title"] = "Revised verification"
        target_ids = {"build", "verify"}
        attempts = tuple(
            Attempt(
                StableId(f"attempt-{identifier}"), PROJECT.project_id,
                accepted_item.definition.ref,
                EntityRef(PROJECT.project_id, EntityKind.ACTOR, StableId("maintainer"), incarnation_id=StableId("incarnation-1")),
                AttemptState.ACTIVE,
            )
            for identifier in sorted(target_ids)
            for accepted_item in accepted.work_items if str(accepted_item.definition.work_item_id) == identifier
        )
        changes = preview_changes(compiled(revised), snapshot(accepted, attempts=attempts))
        active = [conflict for conflict in changes.conflicts if conflict.code == "active_attempt_requires_transition"]
        self.assertEqual({str(conflict.subject.entity_id) for conflict in active}, target_ids)

        weaker = copy.deepcopy(document)
        weaker["work_items"][0]["acceptance"]["allowed_dispositions"] = ["completed", "accepted_negative"]
        weakened = preview_changes(compiled(weaker), snapshot(accepted, attempts=(attempts[0],)))
        self.assertIn("active_attempt_requires_transition", {conflict.code for conflict in weakened.conflicts})

    def test_frozen_interface_contract_cannot_be_revised_in_place(self):
        document = package_document()
        document["interfaces"][0]["compatibility"] = "frozen"
        accepted = compiled(document)
        revised = copy.deepcopy(document)
        revised["interfaces"][0]["contract"]["python"] = ">=3.12"
        changes = preview_changes(compiled(revised), snapshot(accepted))
        self.assertIn("frozen_interface_revision", {conflict.code for conflict in changes.conflicts})

    def test_dependency_member_changes_are_typed_link_operations(self):
        document = package_document()
        accepted = compiled(document)
        revised = copy.deepcopy(document)
        revised["dependencies"][0]["members"][0] = {
            "relation": "completion",
            "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
        }
        changes = preview_changes(compiled(revised), snapshot(accepted))
        self.assertIn(ChangeKind.UNLINK, {op.kind for op in changes.operations})
        self.assertIn(ChangeKind.LINK, {op.kind for op in changes.operations})

    def test_change_payloads_are_recursively_immutable(self):
        original = package_document()
        accepted = compiled(original)
        revised = copy.deepcopy(original)
        revised["work_items"][0]["title"] = "Revised"
        changes = preview_changes(compiled(revised), snapshot(accepted))
        operation = next(op for op in changes.operations if op.kind is ChangeKind.REVISE and op.entity_kind == "work_item")
        with self.assertRaises((AttributeError, TypeError)):
            operation.after_value["scope"]["paths"].append({"path": "bad", "access": "write"})
        self.assertNotEqual(changes.digest, "")

    def test_changed_adoption_contract_is_a_real_requirement_change(self):
        document = package_document()
        requirement = document["requirements"][0]
        requirement["kind"] = "prerequisite"
        requirement.pop("check_key")
        requirement["target"] = {
            "project_id": "project-b", "kind": "work_item", "entity_id": "external",
            "revision_id": "external-rev", "adoption_receipt": {
                "receipt_id": "receipt-1", "authority_id": "authority-b", "contract_digest": "a" * 64,
            },
        }
        document["work_items"][0]["requirement_groups"][0]["kind"] = "prerequisite"
        accepted = compiled_with_adoption(document, Sha256Digest("a" * 64))
        changed = copy.deepcopy(document)
        changed["requirements"][0]["target"]["adoption_receipt"]["contract_digest"] = "b" * 64
        changed_plan = compiled_with_adoption(changed, Sha256Digest("b" * 64))
        changes = preview_changes(changed_plan, snapshot(accepted))
        self.assertTrue(any(op.entity_kind == "requirement" and op.entity_id == StableId("tests") and op.kind is ChangeKind.REVISE for op in changes.operations))


if __name__ == "__main__":
    unittest.main()
