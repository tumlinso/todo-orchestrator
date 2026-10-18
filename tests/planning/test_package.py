import json
import unittest
from dataclasses import replace

from todo_orchestrator.contracts.domain import EntityKind, EntityRef, Project, RequirementMode, Sha256Digest, StableId
from todo_orchestrator.planning import (
    AdoptionReceipt,
    ConditionExpression,
    ConditionResult,
    ConditionStatus,
    DecisionObservation,
    VerifiedAdoption,
    compile_plan,
    evaluate_blocking_group,
    evaluate_condition,
    parse_plan_json,
)


def package_document():
    return {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "example-plan",
        "project": {"project_id": "project-a", "authority_id": "authority-a"},
        "provenance": {"source": "fixture", "producer": "test"},
        "source_manifests": [
            {"id": "source-b", "location": "inputs/b.json", "sha256": "b" * 64},
            {"id": "source-a", "location": "inputs/a.json", "sha256": "a" * 64},
        ],
        "generation_metadata": {"generator": "fixture-gen", "parameters": {"temperature": 0}},
        "work_items": [{
            "id": "build",
            "title": "Build package",
            "objective": "Create the package",
            "motivation": "Enable reuse",
            "outcome": "A tested package exists",
            "scope": {
                "paths": [{"path": "src/todo_orchestrator", "access": "write"}],
                "concepts": ["package"],
                "locks": [{"name": "package-metadata", "mode": "exclusive"}],
            },
            "acceptance": {
                "assertions": ["tests pass"],
                "required_evidence": ["test-report"],
                "allowed_dispositions": ["completed"],
            },
            "ownership": {"mode": "any", "actors": [{
                "project_id": "project-a", "kind": "actor", "entity_id": "maintainer",
                "incarnation_id": "incarnation-1",
            }]},
            "alternatives": [{"id": "reuse", "description": "Reuse existing package"}],
            "unknowns": ["target python matrix"],
            "delegated_judgment": ["select formatting"],
            "references": [{"label": "spec", "uri": "docs/spec.md"}],
            "requirement_groups": [{"kind": "check", "mode": "all", "members": ["tests"]}],
        }, {
            "id": "verify",
            "title": "Verify package",
            "objective": "Confirm package behavior",
            "outcome": "Package behavior is verified",
            "scope": {"paths": [], "concepts": ["verification"]},
            "acceptance": {"assertions": ["verification passes"], "required_evidence": [], "allowed_dispositions": ["completed"]},
            "supersedes": [{"project_id": "project-a", "kind": "work_item", "entity_id": "old-verify", "revision_id": "revision-old"}],
        }],
        "requirements": [{"id": "tests", "work_item_id": "build", "kind": "check", "description": "Run unit tests", "check_key": "unit-tests"}],
        "checkpoints": [{
            "id": "tested", "title": "Tests pass",
            "acceptance": {"assertions": ["all pass"], "required_evidence": [], "allowed_dispositions": ["completed"]},
            "unknowns": [], "producers": [],
        }],
        "interfaces": [{
            "id": "package-api", "title": "Package API", "version": "1.2",
            "contract": {"python": ">=3.11"},
            "producers": [{"project_id": "project-a", "kind": "work_item", "entity_id": "build"}],
            "consumers": [{"project_id": "project-a", "kind": "work_item", "entity_id": "verify"}],
            "compatibility": "evolvable",
        }],
        "decisions": [{
            "id": "format", "title": "Choose format", "question": "Which format?",
            "options": [{"id": "json", "description": "JSON"}, {"id": "yaml", "description": "YAML"}], "selected_option_id": None,
            "unknowns": [], "resolvers": [],
        }],
        "barriers": [{
            "id": "serial-gate", "title": "Serial gate", "mode": "all",
            "participants": [{"project_id": "project-a", "kind": "work_item", "entity_id": "build"}],
        }],
        "rendezvous": [{
            "id": "review", "title": "Review", "mode": "all",
            "participants": [{"project_id": "project-a", "kind": "work_item", "entity_id": "build"}],
        }],
        "invariants": [{
            "id": "standalone", "statement": "No Project Control dependency",
            "applies_to": [{"project_id": "project-a", "kind": "work_item", "entity_id": "build"}],
        }],
        "dependencies": [{
            "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "verify"},
            "mode": "all",
            "members": [{
                "relation": "rendezvous_met",
                "target": {"project_id": "project-a", "kind": "rendezvous", "entity_id": "review"},
                "condition": {"op": "decision_equals", "decision_id": "format", "option_id": "json"},
            }],
        }],
    }


class PlanPackageTests(unittest.TestCase):
    def parse(self, document):
        return parse_plan_json(json.dumps(document))

    def test_compile_preserves_authored_metadata_and_typed_references(self):
        parsed = self.parse(package_document())
        self.assertTrue(parsed.ok, parsed.diagnostics)
        plan_result = compile_plan(parsed.package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertTrue(plan_result.ok, plan_result.diagnostics)
        plan = plan_result.plan
        self.assertIsNotNone(plan)
        item = plan.work_items[0]
        self.assertEqual(item.context.objective, "Create the package")
        self.assertEqual(item.context.scope["locks"][0]["name"], "package-metadata")
        self.assertEqual(item.context.ownership.actors[0].reference.incarnation_id, StableId("incarnation-1"))
        self.assertEqual(len(plan.source_manifests), 2)
        self.assertEqual(plan.source_manifests[0].source_id, StableId("source-a"))
        self.assertEqual(plan.generation_metadata["generator"], "fixture-gen")
        self.assertEqual(plan.work_items[1].definition.supersedes[0].definition_revision_id, StableId("revision-old"))
        self.assertEqual(len(plan.requirements), 1)
        self.assertEqual([item.kind for item in plan.declarations], ["checkpoints", "interfaces", "decisions", "barriers", "rendezvous", "invariants"])
        self.assertEqual(plan.blocking_groups[0].members[0].target.declared_kind, "rendezvous")
        self.assertEqual(plan.blocking_groups[0].members[0].condition.op, "decision_equals")
        self.assertTrue(plan_result.graph_validation.ok)
        node_kinds = {node.kind for node in plan_result.graph_validation.nodes}
        self.assertTrue({"work_item", "requirement", "evidence", "checkpoint", "interface", "decision", "barrier", "rendezvous", "invariant"}.issubset(node_kinds))

    def test_cross_type_cycle_has_a_stable_witness(self):
        document = package_document()
        document["checkpoints"][0]["producers"] = [
            {"project_id": "project-a", "kind": "work_item", "entity_id": "build"}
        ]
        document["dependencies"].append({
            "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
            "mode": "all",
            "members": [{
                "relation": "checkpoint_accepted",
                "target": {"project_id": "project-a", "kind": "checkpoint", "entity_id": "tested"},
            }],
        })
        target = Project(StableId("project-a"), StableId("authority-a"))
        first = compile_plan(self.parse(document).package, target)
        second = compile_plan(self.parse(document).package, target)
        self.assertIsNone(first.plan)
        self.assertEqual(first.diagnostics[0].code, "blocking_cycle")
        self.assertEqual(first.diagnostics, second.diagnostics)
        self.assertEqual({node.kind for node in first.graph_validation.cycles[0].nodes}, {"work_item", "checkpoint"})

    def test_condition_decision_reference_participates_in_cycle_graph(self):
        document = package_document()
        document["decisions"][0]["resolvers"] = [
            {"project_id": "project-a", "kind": "work_item", "entity_id": "verify"}
        ]
        result = compile_plan(self.parse(document).package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertIsNone(result.plan)
        self.assertEqual(result.diagnostics[0].code, "blocking_cycle")
        relations = {edge.relation for edge in result.graph_validation.cycles[0].edges}
        self.assertIn("condition_decision", relations)
        self.assertIn("decision_resolver", relations)

    def test_rendezvous_dependency_source_keeps_its_declared_kind(self):
        document = package_document()
        document["dependencies"].extend([
            {
                "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
                "mode": "all",
                "members": [{"relation": "rendezvous_met", "target": {"project_id": "project-a", "kind": "rendezvous", "entity_id": "review"}}],
            },
            {
                "source": {"project_id": "project-a", "kind": "rendezvous", "entity_id": "review"},
                "mode": "all",
                "members": [{"relation": "completion", "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"}}],
            },
        ])
        result = compile_plan(self.parse(document).package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertIsNone(result.plan)
        witness = result.graph_validation.cycles[0]
        self.assertEqual({node.kind for node in witness.nodes}, {"rendezvous", "work_item"})

    def test_containment_is_validated_separately_from_blocking_dependencies(self):
        document = package_document()
        document["interfaces"][0]["producers"] = []
        document["interfaces"][0]["consumers"] = []
        document["work_items"][1]["parent_id"] = "build"
        document["dependencies"] = [{
            "source": {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
            "mode": "all",
            "members": [{
                "relation": "completion",
                "target": {"project_id": "project-a", "kind": "work_item", "entity_id": "verify"},
            }],
        }]
        valid = compile_plan(self.parse(document).package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertTrue(valid.ok, valid.diagnostics)
        self.assertFalse(valid.graph_validation.cycles)

        document["work_items"][0]["parent_id"] = "verify"
        cyclic_lineage = compile_plan(self.parse(document).package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertIsNone(cyclic_lineage.plan)
        self.assertEqual(cyclic_lineage.diagnostics[0].code, "lineage_cycle")

    def test_graph_size_limit_returns_diagnostic_before_recursive_walk(self):
        document = package_document()
        template = document["work_items"][1]
        for index in range(520):
            extra = dict(template)
            extra.update({"id": f"extra-{index:04d}", "title": "Extra", "objective": "Bound graph size", "outcome": "Bounded"})
            extra.pop("supersedes", None)
            extra.pop("parent_id", None)
            document["work_items"].append(extra)
        result = compile_plan(self.parse(document).package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertIsNone(result.plan)
        self.assertEqual(result.diagnostics[0].code, "graph_too_large")

    def test_record_order_and_object_key_order_have_stable_digest(self):
        first = package_document()
        second = package_document()
        second["work_items"] = list(reversed(second["work_items"]))
        second["checkpoints"] = list(reversed(second["checkpoints"]))
        second["source_manifests"] = list(reversed(second["source_manifests"]))
        first_text = json.dumps(first, separators=(",", ":"))
        second_text = json.dumps(second, separators=(",", ":"), sort_keys=True)
        a = parse_plan_json(first_text)
        b = parse_plan_json(second_text)
        self.assertEqual(a.package.content_digest, b.package.content_digest)
        target = Project(StableId("project-a"), StableId("authority-a"))
        self.assertEqual(compile_plan(a.package, target).plan.revision.plan_revision_id,
                         compile_plan(b.package, target).plan.revision.plan_revision_id)
        self.assertNotEqual(a.package.source_digest, b.package.source_digest)

    def test_source_manifest_digest_is_validated_and_generation_is_nonsemantic(self):
        document = package_document()
        base = self.parse(document)
        document["generation_metadata"]["generator"] = "different-generator"
        changed_generation = self.parse(document)
        self.assertEqual(base.package.content_digest, changed_generation.package.content_digest)
        document["source_manifests"][0]["sha256"] = "not-a-digest"
        self.assertEqual(self.parse(document).diagnostics[0].code, "invalid_digest")

    def test_omitted_and_explicitly_empty_sections_remain_distinct(self):
        omitted = package_document()
        omitted.pop("interfaces")
        explicit_empty = package_document()
        explicit_empty["interfaces"] = []
        parsed_omitted = self.parse(omitted)
        parsed_empty = self.parse(explicit_empty)
        self.assertTrue(parsed_omitted.ok, parsed_omitted.diagnostics)
        self.assertTrue(parsed_empty.ok, parsed_empty.diagnostics)
        self.assertNotEqual(parsed_omitted.package.content_digest, parsed_empty.package.content_digest)
        self.assertNotIn("interfaces", parsed_omitted.package.supplied_sections)
        self.assertIn("interfaces", parsed_empty.package.supplied_sections)
        target = Project(StableId("project-a"), StableId("authority-a"))
        plan = compile_plan(parsed_omitted.package, target).plan
        self.assertNotIn("interfaces", plan.canonical_json)

    def test_unknown_fields_and_duplicate_json_keys_fail_closed(self):
        document = package_document()
        document["unrecognized"] = True
        self.assertEqual(self.parse(document).diagnostics[0].code, "unknown_field")
        duplicate = '{"format":"todo-orchestrator.plan","format":"todo-orchestrator.plan"}'
        self.assertEqual(parse_plan_json(duplicate).diagnostics[0].code, "duplicate_json_key")

    def test_unsafe_or_ambiguous_scope_path_is_rejected(self):
        for path, code in (("../secret", "unsafe_path"), ("src/*.py", "ambiguous_path"), ("src//x", "unsafe_path")):
            document = package_document()
            document["work_items"][0]["scope"]["paths"][0]["path"] = path
            self.assertEqual(self.parse(document).diagnostics[0].code, code)

    def test_foreign_reference_requires_exact_revision_and_receipt(self):
        document = package_document()
        document["dependencies"][0]["members"][0]["target"] = {
            "project_id": "project-b", "kind": "work_item", "entity_id": "external-work"
        }
        self.assertEqual(self.parse(document).diagnostics[0].code, "ambiguous_reference")
        target = document["dependencies"][0]["members"][0]["target"]
        target["revision_id"] = "rev-1"
        self.assertEqual(self.parse(document).diagnostics[0].code, "foreign_reference_unadopted")
        target.update({
            "adoption_receipt": {
                "receipt_id": "receipt-1", "authority_id": "authority-b", "contract_digest": "0" * 64
            },
        })
        document["dependencies"][0]["members"][0]["relation"] = "completion"
        parsed = self.parse(document)
        self.assertTrue(parsed.ok, parsed.diagnostics)
        project = Project(StableId("project-a"), StableId("authority-a"))
        unverified = compile_plan(parsed.package, project)
        self.assertIsNone(unverified.plan)
        self.assertEqual(unverified.diagnostics[0].code, "foreign_reference_unverified")
        receipt = AdoptionReceipt(StableId("receipt-1"), StableId("authority-b"), Sha256Digest("0" * 64))
        fact = VerifiedAdoption(
            verification_id=StableId("verification-1"),
            declared_kind="work_item",
            reference=EntityRef(StableId("project-b"), EntityKind.WORK_ITEM, StableId("external-work"), StableId("rev-1")),
            receipt=receipt,
        )
        verified = compile_plan(parsed.package, project, adoption_facts=(fact,))
        self.assertTrue(verified.ok, verified.diagnostics)
        foreign_ref = verified.plan.blocking_groups[0].members[0].target.reference
        self.assertEqual(foreign_ref.project_id, StableId("project-b"))
        self.assertEqual(len(verified.plan.verified_adoptions), 1)

    def test_interface_version_compatibility_is_concrete(self):
        document = package_document()
        document["dependencies"][0]["members"] = [{
            "relation": "interface_version",
            "target": {"project_id": "project-a", "kind": "interface", "entity_id": "package-api"},
            "expected_version": "1.1",
        }]
        parsed = self.parse(document)
        self.assertTrue(parsed.ok, parsed.diagnostics)
        result = compile_plan(parsed.package, Project(StableId("project-a"), StableId("authority-a")))
        self.assertTrue(result.ok, result.diagnostics)
        self.assertEqual(result.plan.blocking_groups[0].members[0].expected_version, "1.1")
        document["interfaces"][0]["compatibility"] = "frozen"
        self.assertEqual(self.parse(document).diagnostics[0].code, "incompatible_interface_version")

    def test_condition_and_quorum_evaluation_preserves_unknown_states(self):
        parsed = self.parse(package_document())
        result = compile_plan(parsed.package, Project(StableId("project-a"), StableId("authority-a")))
        condition = result.plan.blocking_groups[0].members[0].condition
        self.assertEqual(evaluate_condition(condition, {}).status, ConditionStatus.UNRESOLVED)
        self.assertEqual(
            evaluate_condition(condition, {"format": DecisionObservation(ConditionStatus.UNAVAILABLE)}).status,
            ConditionStatus.UNAVAILABLE,
        )
        selected = {"format": DecisionObservation(ConditionStatus.SATISFIED, "json")}
        self.assertEqual(evaluate_condition(condition, selected).status, ConditionStatus.SATISFIED)
        self.assertEqual(
            evaluate_condition(condition, {"format": DecisionObservation(ConditionStatus.SATISFIED, "yaml")}).status,
            ConditionStatus.UNSATISFIED,
        )
        negated = ConditionExpression("not", (("condition", condition),))
        conjunction = ConditionExpression("all", (("conditions", (condition, negated)),))
        disjunction = ConditionExpression("any", (("conditions", (condition, negated)),))
        self.assertEqual(evaluate_condition(negated, {}).status, ConditionStatus.UNRESOLVED)
        self.assertEqual(evaluate_condition(conjunction, selected).status, ConditionStatus.UNSATISFIED)
        self.assertEqual(evaluate_condition(disjunction, selected).status, ConditionStatus.SATISFIED)

        group = replace(result.plan.blocking_groups[0], members=result.plan.blocking_groups[0].members * 3,
                        mode=RequirementMode.QUORUM, quorum=2)
        satisfied = ConditionResult(ConditionStatus.SATISFIED)
        unresolved = ConditionResult(ConditionStatus.UNRESOLVED)
        unavailable = ConditionResult(ConditionStatus.UNAVAILABLE)
        unsatisfied = ConditionResult(ConditionStatus.UNSATISFIED)
        self.assertEqual(evaluate_blocking_group(group, [satisfied, unresolved, unsatisfied], selected).status,
                         ConditionStatus.UNRESOLVED)
        self.assertEqual(evaluate_blocking_group(group, [satisfied, satisfied, unavailable], selected).status,
                         ConditionStatus.SATISFIED)
        self.assertEqual(evaluate_blocking_group(group, [satisfied, unsatisfied, unavailable], selected).status,
                         ConditionStatus.UNAVAILABLE)

        inactive = replace(group.members[0], condition=ConditionExpression(
            "decision_equals", (("decision_id", "format"), ("option_id", "yaml"))))
        active = replace(group.members[0], condition=condition)
        any_group = replace(group, members=(inactive, active), mode=RequirementMode.ANY, quorum=None)
        quorum_group = replace(group, members=(inactive, active), mode=RequirementMode.QUORUM, quorum=1)
        self.assertEqual(evaluate_blocking_group(any_group, [satisfied, unsatisfied], selected).status,
                         ConditionStatus.UNSATISFIED)
        self.assertEqual(evaluate_blocking_group(quorum_group, [satisfied, unsatisfied], selected).status,
                         ConditionStatus.UNSATISFIED)
        all_inactive = replace(group, members=(inactive, inactive), mode=RequirementMode.ANY, quorum=None)
        self.assertEqual(evaluate_blocking_group(all_inactive, [unsatisfied, unsatisfied], selected).status,
                         ConditionStatus.SATISFIED)

    def test_unsupported_conditions_and_unresolved_ids_are_diagnostics(self):
        document = package_document()
        document["dependencies"][0]["members"][0]["condition"] = {"op": "python", "source": "pass"}
        self.assertEqual(self.parse(document).diagnostics[0].code, "unsupported_condition")
        document = package_document()
        document["dependencies"][0]["members"][0]["condition"] = {
            "op": "decision_equals", "decision_id": "missing", "option_id": "json"
        }
        self.assertEqual(self.parse(document).diagnostics[0].code, "unknown_decision")

    def test_target_mismatch_is_rejected_without_io(self):
        parsed = self.parse(package_document())
        result = compile_plan(parsed.package, Project(StableId("other"), StableId("authority-a")))
        self.assertIsNone(result.plan)
        self.assertEqual(result.diagnostics[0].code, "target_mismatch")

    def test_unpaired_surrogates_are_diagnostics_and_valid_pairs_normalize(self):
        raw_invalid = '{"format":"todo-orchestrator.plan","objective":"' + "\ud800" + '"}'
        self.assertEqual(parse_plan_json(raw_invalid).diagnostics[0].code, "invalid_unicode")
        document = package_document()
        document["work_items"][0]["objective"] = "valid \U0001f642"
        escaped = json.dumps(document, ensure_ascii=True)
        parsed = parse_plan_json(escaped)
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual(parsed.package.document["work_items"][0]["objective"], "valid \U0001f642")
        invalid_escaped = escaped.replace("valid \\ud83d\\ude42", "bad \\ud800")
        self.assertEqual(parse_plan_json(invalid_escaped).diagnostics[0].code, "invalid_unicode")

    def test_cross_kind_ids_are_typed_and_not_confused(self):
        document = package_document()
        document["checkpoints"][0]["id"] = "build"
        parsed = self.parse(document)
        self.assertTrue(parsed.ok, parsed.diagnostics)

    def test_barrier_and_rendezvous_share_one_identity_namespace(self):
        document = package_document()
        document["rendezvous"][0]["id"] = document["barriers"][0]["id"]
        parsed = self.parse(document)
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, "duplicate_id")

    def test_barrier_and_rendezvous_quorums_reject_duplicate_qualified_participants(self):
        for section in ("barriers", "rendezvous"):
            with self.subTest(section=section):
                document = package_document()
                declaration = document[section][0]
                declaration["mode"] = "quorum"
                declaration["quorum"] = 2
                declaration["participants"] = [
                    {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
                    {"project_id": "project-a", "kind": "work_item", "entity_id": "build"},
                    {"project_id": "project-a", "kind": "work_item", "entity_id": "verify"},
                ]
                parsed = self.parse(document)
                self.assertFalse(parsed.ok)
                self.assertEqual(parsed.diagnostics[0].code, "duplicate_participant")

    def test_participant_identity_keeps_distinct_qualified_references(self):
        document = package_document()
        document["barriers"][0]["participants"] = [
            {"project_id": "project-b", "kind": "work_item", "entity_id": "same", "revision_id": "rev-a",
             "adoption_receipt": {"receipt_id": "receipt-a", "authority_id": "authority-b", "contract_digest": "a" * 64}},
            {"project_id": "project-b", "kind": "work_item", "entity_id": "same", "revision_id": "rev-b",
             "adoption_receipt": {"receipt_id": "receipt-b", "authority_id": "authority-b", "contract_digest": "b" * 64}},
        ]
        parsed = self.parse(document)
        self.assertTrue(parsed.ok, parsed.diagnostics)
        participants = parsed.package.document["barriers"][0]["participants"]
        self.assertEqual([item["revision_id"] for item in participants], ["rev-a", "rev-b"])


if __name__ == "__main__":
    unittest.main()
