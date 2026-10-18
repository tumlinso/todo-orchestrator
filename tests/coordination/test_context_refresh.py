"""Refresh, provenance, paging, and durable replay checks for worker context."""

from dataclasses import dataclass
from datetime import timedelta
import base64
import hashlib
import json
from unittest.mock import patch
import unittest

from todo_orchestrator.authority import AuthorityAuthService, CommandDispatcher, DeclarationService, SQLiteAuthority
from todo_orchestrator.authority.auth import AuthorizationRequirement
from todo_orchestrator.authority.declarations import DECISION_RESOLVE_ACTION
from todo_orchestrator.authority.commands import MutationContext
from todo_orchestrator.contracts import EntityKind, EntityRef, Sha256Digest, StableId
from todo_orchestrator.coordination.context import (
    CONTEXT_READ_ACTION, ContextService, serialize_context_capsule, serialize_context_expansion,
)
from todo_orchestrator.model import CommandEffect
from todo_orchestrator.model.context import ContextCapsuleStatus, ContextExpansionStatus, ContextFragmentKind

from tests.coordination import test_context_independent as fixtures


def _declaration_package() -> str:
    document = json.loads(fixtures.package_json())
    gamma = dict(document["work_items"][0])
    gamma.update({
        "id": "gamma", "title": "Gamma", "objective": "Deliver gamma", "outcome": "gamma complete",
        "scope": {"paths": [{"path": "src/gamma", "access": "write"}], "concepts": [], "locks": []},
        "references": [{"label": "gamma specification", "uri": "docs/gamma.md"}],
    })
    document["work_items"].append(gamma)
    document["source_manifests"] = [
        {"id": "alpha-spec", "location": "docs/alpha.md", "sha256": "a" * 64},
        {"id": "beta-spec", "location": "docs/beta.md", "sha256": "b" * 64},
        {"id": "gamma-spec", "location": "docs/gamma.md", "sha256": "c" * 64},
    ]
    document["decisions"] = [{
        "id": "runtime-choice", "title": "Runtime choice", "question": "Which option?",
        "options": [{"id": "one", "description": "Option one"}, {"id": "two", "description": "Option two"}],
        "resolvers": [], "unknowns": [],
    }]
    document["dependencies"] = [{
        "source": {"project_id": str(fixtures.PROJECT.project_id), "kind": "work_item", "entity_id": "gamma"},
        "mode": "all",
        "members": [{
            "relation": "decision_resolved",
            "target": {"project_id": str(fixtures.PROJECT.project_id), "kind": "decision", "entity_id": "runtime-choice"},
        }],
    }]
    return json.dumps(document, ensure_ascii=False, sort_keys=True)


def _new_flow(package_json: str | None = None):
    flow = fixtures.ContextFlowTests()
    if package_json is None:
        flow.setUp()
    else:
        with patch.object(fixtures, "package_json", return_value=package_json):
            flow.setUp()
    return flow


def _run_free_context(flow, work_item, *, previous_manifest=None, max_bytes=65536, since_revision=None):
    with flow.reader() as authority:
        return flow.service.build_context(
            authority, flow.owner.bearer_token, work_item,
            previous_manifest=previous_manifest, max_bytes=max_bytes, since_revision=since_revision,
        )


def _fragment(capsule, kind):
    return next(item for item in capsule.fragments if item.reference.kind is kind)


def _finding_payload(capsule):
    return json.loads(_fragment(capsule, ContextFragmentKind.FINDINGS).payload_json)


def _expand(flow, capsule, kind, work_item, *, run=None, assignment=None, attempt=None):
    ref = next(item for item in capsule.manifest.fragments if item.kind is kind)
    with flow.reader() as authority:
        return flow.service.expand_fragment(
            authority, flow.owner.bearer_token, work_item, run=run, assignment=assignment,
            attempt=attempt, fragment_id=ref.fragment_id, expected_digest=ref.digest, max_bytes=65536,
            since_revision=capsule.manifest.since_revision,
        )


def _expanded_json(flow, capsule, kind, work_item, *, run=None, assignment=None, attempt=None, max_bytes=65536):
    ref = next(item for item in capsule.manifest.fragments if item.kind is kind)
    parts = bytearray()
    offset = None
    while True:
        with flow.reader() as authority:
            page = flow.service.expand_fragment(
                authority, flow.owner.bearer_token, work_item, run=run, assignment=assignment,
                attempt=attempt, fragment_id=ref.fragment_id, expected_digest=ref.digest,
                max_bytes=max_bytes, offset=offset, since_revision=capsule.manifest.since_revision,
            )
        if page.status is not ContextExpansionStatus.READY:
            raise AssertionError(f"fragment expansion did not complete: {page.status} {page.reason}")
        if page.fragment is not None:
            return json.loads(page.fragment.payload_json)
        parts.extend(base64.b64decode(page.chunk_base64))
        if page.next_offset is None:
            self_digest = hashlib.sha256(parts).hexdigest()
            if self_digest != page.content_digest.hex:
                raise AssertionError("expanded fragment digest did not match")
            return json.loads(parts)
        offset = page.next_offset


class ContextRefreshTests(unittest.TestCase):
    def test_declaration_fact_provenance_and_selective_refresh_staleness(self):
        flow = _new_flow(_declaration_package())
        self.addCleanup(flow.doCleanups)
        with flow.writer() as authority:
            flow.owner = flow.auth.login_local_owner(
                authority, fixtures.OWNER_PASSWORD,
                actions=(fixtures.PLAN_COMMIT, fixtures.RUN_SCHEDULE_ACTION, fixtures.RUN_DISPATCH_ACTION,
                         fixtures.CLAIM_ACTION, fixtures.HEARTBEAT_ACTION, fixtures.RELEASE_ACTION,
                         fixtures.FINISH_ACTION, fixtures.DELEGATE_ACTION, *fixtures.CONTEXT_ACTIONS,
                         DECISION_RESOLVE_ACTION),
                scope=fixtures.PROJECT.ref, expires_at=fixtures.NOW + timedelta(days=1),
                idempotency_key=StableId("context-refresh-owner"), expected_revision=flow.revision(),
            )
        gamma = flow.work["gamma"]
        beta = flow.work["beta"]
        initial = _run_free_context(flow, gamma)
        declaration_body = json.loads(_fragment(initial, ContextFragmentKind.DECLARATIONS).payload_json)
        decision_row = next(item for item in declaration_body["declarations"]
                            if item["declaration_id"] == "runtime-choice")
        self.assertEqual(decision_row["canonical_fact"]["accepted_plan_revision"]["entity_id"],
                         str(flow.plan.revision.plan_revision_id))
        self.assertIsNone(decision_row["canonical_fact"]["latest_fact"])
        self.assertEqual(len(decision_row["canonical_fact"]["accepted_declaration_digest"]), 64)

        source_ref = _fragment(initial, ContextFragmentKind.SOURCE_REFERENCES).reference
        work_ref = _fragment(initial, ContextFragmentKind.WORK_ITEM).reference
        declarations_ref = _fragment(initial, ContextFragmentKind.DECLARATIONS).reference
        beta_initial = _run_free_context(flow, beta)
        beta_source_ref = _fragment(beta_initial, ContextFragmentKind.SOURCE_REFERENCES).reference
        finding_receipts = {}
        for name, ref, summary in (
            ("source", source_ref, "Gamma source was reviewed."),
            ("work", work_ref, "Gamma work remains scoped."),
            ("decision", declarations_ref, "The decision is unresolved."),
        ):
            with flow.writer() as authority:
                result = flow.service.publish_finding(
                    authority, flow.owner.bearer_token, gamma, summary, initial.manifest, (ref,),
                    finding_id=StableId("gamma-finding-" + name), expected_finding_version=None,
                    idempotency_key=StableId("gamma-finding-key-" + name), expected_revision=flow.revision(),
                )
                finding_receipts[name] = result
        with flow.writer() as authority:
            beta_result = flow.service.publish_finding(
                authority, flow.owner.bearer_token, beta, "Beta's own source was reviewed.",
                beta_initial.manifest, (beta_source_ref,), finding_id=StableId("beta-source-finding"),
                expected_finding_version=None, idempotency_key=StableId("beta-source-finding-key"),
                expected_revision=flow.revision(),
            )
        self.assertTrue(all(result.receipt.changed for result in finding_receipts.values()))
        self.assertTrue(beta_result.receipt.changed)

        decision_service = DeclarationService(flow.auth, clock=flow.clock)
        decision = EntityRef(fixtures.PROJECT.project_id, EntityKind.DECISION, StableId("runtime-choice"))
        with flow.writer() as authority:
            resolution = decision_service.resolve_decision(
                authority, flow.owner.bearer_token, flow.plan.revision.ref, decision,
                StableId("one"), "Keep the dependency on the stable runtime option.",
                idempotency_key=StableId("context-resolve-runtime-choice"), expected_revision=flow.revision(),
            )
        self.assertTrue(resolution.receipt.changed)
        resolved = _run_free_context(flow, gamma, previous_manifest=initial.manifest)
        body = json.loads(_fragment(resolved, ContextFragmentKind.DECLARATIONS).payload_json)
        decision_row = next(item for item in body["declarations"] if item["declaration_id"] == "runtime-choice")
        canonical = decision_row["canonical_fact"]
        current = canonical["current_resolution"]
        self.assertEqual(current["option_id"], "one")
        self.assertEqual(current["rationale"], "Keep the dependency on the stable runtime option.")
        self.assertEqual(current["semantic_revision"], resolution.receipt.semantic_revision)
        self.assertEqual(canonical["latest_fact"]["fact_id"], current["fact_id"])
        self.assertEqual(canonical["latest_fact"]["fact_sequence"], current["fact_sequence"])
        with flow.reader() as authority:
            fact = authority.connection.execute(
                "SELECT fact_id, fact_sequence, semantic_revision FROM declaration_facts "
                "WHERE declaration_kind = 'decision' AND declaration_id = 'runtime-choice' "
                "AND fact_kind = 'decision_resolved'"
            ).fetchone()
        self.assertEqual(current["fact_id"], fact["fact_id"])
        self.assertEqual(current["fact_sequence"], fact["fact_sequence"])
        self.assertEqual(current["semantic_revision"], fact["semantic_revision"])

        with flow.reader() as authority:
            findings_capsule = flow.service.build_context(authority, flow.owner.bearer_token, gamma)
        findings = {StableId(item["finding_id"]): item for item in _finding_payload(findings_capsule)["findings"]}
        self.assertTrue(findings[StableId("gamma-finding-decision")]["stale_source"])
        self.assertFalse(findings[StableId("gamma-finding-work")]["stale_source"])
        self.assertFalse(findings[StableId("gamma-finding-source")]["stale_source"])

        # A later source manifest refresh changes gamma's source fragment while
        # preserving the exact authored work definitions and beta's source view.
        updated_document = json.loads(flow.package)
        next(item for item in updated_document["source_manifests"] if item["id"] == "gamma-spec")["sha256"] = "d" * 64
        updated = json.dumps(updated_document, ensure_ascii=False, sort_keys=True)
        with flow.writer() as authority:
            preview = flow.plans.preview(authority, updated)
            flow.plans.commit(
                authority, flow.owner.bearer_token, updated, reviewed_digest=preview.digest,
                idempotency_key=StableId("context-source-refresh-plan"),
                expected_authority_revision=preview.expected_authority_revision,
                expected_plan_revision_id=preview.expected_revision_id,
            )
            flow.plan = flow.plans.load_accepted_plan(authority)
        flow.package = updated
        new_work = {str(item.definition.work_item_id): item.definition.ref for item in flow.plan.work_items}
        self.assertEqual(new_work["gamma"], gamma)
        self.assertEqual(new_work["beta"], beta)
        refreshed = _run_free_context(flow, gamma, previous_manifest=resolved.manifest)
        changed_source_kinds = {
            change.current.kind for change in refreshed.changes
            if change.current is not None and change.current.kind in {
                ContextFragmentKind.WORK_ITEM, ContextFragmentKind.DECLARATIONS,
                ContextFragmentKind.SOURCE_REFERENCES,
            } and change.kind.value != "unchanged"
        }
        self.assertIn(ContextFragmentKind.SOURCE_REFERENCES, changed_source_kinds)
        self.assertNotIn(ContextFragmentKind.WORK_ITEM, changed_source_kinds)
        self.assertEqual(changed_source_kinds, {
            ContextFragmentKind.DECLARATIONS, ContextFragmentKind.SOURCE_REFERENCES,
        })
        with flow.reader() as authority:
            refreshed_findings_capsule = flow.service.build_context(authority, flow.owner.bearer_token, gamma)
        current_findings = {
            StableId(item["finding_id"]): item for item in _finding_payload(refreshed_findings_capsule)["findings"]
        }
        self.assertFalse(current_findings[StableId("gamma-finding-work")]["stale_source"])
        self.assertTrue(current_findings[StableId("gamma-finding-source")]["stale_source"])
        self.assertTrue(current_findings[StableId("gamma-finding-decision")]["stale_source"])
        beta_refreshed = _run_free_context(flow, beta, previous_manifest=beta_initial.manifest)
        self.assertEqual(_fragment(beta_refreshed, ContextFragmentKind.SOURCE_REFERENCES).reference,
                         beta_source_ref)
        with flow.reader() as authority:
            beta_findings_capsule = flow.service.build_context(authority, flow.owner.bearer_token, beta)
        beta_findings = {
            StableId(item["finding_id"]): item for item in _finding_payload(beta_findings_capsule)["findings"]
        }
        self.assertFalse(beta_findings[StableId("beta-source-finding")]["stale_source"])

    def test_since_revision_delta_is_ordered_and_truncation_is_explicit(self):
        flow = _new_flow()
        self.addCleanup(flow.doCleanups)
        target = flow.work["alpha"]
        baseline = flow.revision()

        @dataclass(frozen=True)
        class DeltaCommand:
            work_item: EntityRef
            ordinal: int

        class DeltaHandler:
            kind = "test.context.delta"
            command_type = DeltaCommand

            def authorization_requirement(self, command):
                return AuthorizationRequirement(CONTEXT_READ_ACTION, command.work_item)

            def canonical_payload(self, command):
                return {"work_item_id": str(command.work_item.entity_id), "ordinal": command.ordinal}

            def apply(self, context: MutationContext, command: DeltaCommand):
                context.execute(
                    "UPDATE actors SET label = ? WHERE actor_id = ? AND incarnation_id = ?",
                    (f"delta-{command.ordinal}", str(context.actor.entity_id), str(context.actor.incarnation_id)),
                )
                return CommandEffect(True, {"ordinal": command.ordinal}, "test.context.delta", {
                    "work_item_id": str(command.work_item.entity_id), "ordinal": command.ordinal,
                })

        flow.dispatcher.register(DeltaHandler())
        for ordinal in range(101):
            expected = flow.revision()
            with flow.writer() as authority:
                flow.auth.execute(
                    authority, flow.owner.bearer_token, DeltaCommand(target, ordinal),
                    idempotency_key=StableId(f"context-delta-{ordinal}"), expected_revision=expected,
                )
        capsule = _run_free_context(flow, target, since_revision=baseline)
        deltas = _expanded_json(flow, capsule, ContextFragmentKind.SCOPED_DELTAS, target)
        self.assertEqual(deltas["after_revision"], baseline)
        self.assertEqual(deltas["through_revision"], flow.revision())
        self.assertTrue(deltas["truncated"])
        self.assertEqual(len(deltas["events"]), 100)
        revisions = [item["semantic_revision"] for item in deltas["events"]]
        self.assertEqual(revisions, sorted(revisions))
        self.assertGreater(revisions[0], baseline)

    def test_minimum_capsule_and_large_fragment_have_real_bounded_routes(self):
        flow = _new_flow()
        self.addCleanup(flow.doCleanups)
        small = flow._build("a", max_bytes=4096)
        wire = serialize_context_capsule(small).encode("utf-8")
        self.assertEqual(len(wire), small.encoded_bytes)
        self.assertLessEqual(len(wire), 4096)
        self.assertEqual(small.status, ContextCapsuleStatus.PARTIAL)
        self.assertTrue(small.omitted)

        document = json.loads(fixtures.package_json())
        alpha = next(item for item in document["work_items"] if item["id"] == "alpha")
        alpha["references"] = [
            {"label": f"source-{index}", "uri": f"docs/{index}-" + ("x" * 390)}
            for index in range(20)
        ]
        large_flow = _new_flow(json.dumps(document, ensure_ascii=False, sort_keys=True))
        self.addCleanup(large_flow.doCleanups)
        capsule = large_flow._build("a", max_bytes=65536)
        source = _fragment(capsule, ContextFragmentKind.SOURCE_REFERENCES)
        descriptor = json.loads(source.payload_json)
        self.assertTrue(descriptor["reference_only"])
        self.assertEqual(descriptor["expansion"]["content_digest"], descriptor["content_digest"])
        assembled = bytearray()
        offset = None
        while True:
            with large_flow.reader() as authority:
                page = large_flow.service.expand_fragment(
                    authority, large_flow.worker_contexts["a"].bearer_token,
                    **large_flow._context_args("a"), fragment_id=source.reference.fragment_id,
                    expected_digest=source.reference.digest, max_bytes=4096, offset=offset,
                )
            self.assertEqual(page.status, ContextExpansionStatus.READY)
            self.assertLessEqual(len(serialize_context_expansion(page).encode("utf-8")), 4096)
            assembled.extend(base64.b64decode(page.chunk_base64))
            if page.next_offset is None:
                self.assertEqual(page.total_bytes, len(assembled))
                self.assertEqual(hashlib.sha256(assembled).hexdigest(), page.content_digest.hex)
                break
            offset = page.next_offset
        expanded = json.loads(assembled)
        self.assertEqual(len(expanded["references"]["work_references"]), 20)

    def test_finding_exact_retry_survives_new_service_and_connection(self):
        flow = _new_flow()
        self.addCleanup(flow.doCleanups)
        capsule = flow._build("a", max_bytes=65536)
        source = _fragment(capsule, ContextFragmentKind.WORK_ITEM).reference
        args = flow._context_args("a")
        expected = flow.revision()
        with flow.writer() as authority:
            first = flow.service.publish_finding(
                authority, flow.worker_contexts["a"].bearer_token, args["work_item"],
                "Durable finding survives service reconstruction.", capsule.manifest, (source,),
                finding_id=StableId("context-reopen-finding"), expected_finding_version=None,
                run=args["run"], assignment=args["assignment"], attempt=args["attempt"],
                idempotency_key=StableId("context-reopen-finding-key"), expected_revision=expected,
            )
        self.assertTrue(first.receipt.changed)

        restarted_auth = AuthorityAuthService(
            CommandDispatcher(), clock=flow.clock, authenticator=fixtures.Authenticator(),
        )
        restarted_service = ContextService(restarted_auth, clock=flow.clock)
        with flow.writer() as authority:
            replay = restarted_service.publish_finding(
                authority, flow.worker_contexts["a"].bearer_token, args["work_item"],
                "Durable finding survives service reconstruction.", capsule.manifest, (source,),
                finding_id=StableId("context-reopen-finding"), expected_finding_version=None,
                run=args["run"], assignment=args["assignment"], attempt=args["attempt"],
                idempotency_key=StableId("context-reopen-finding-key"), expected_revision=expected,
            )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt.receipt_id, first.receipt.receipt_id)
        self.assertEqual(replay.receipt.semantic_revision, first.receipt.semantic_revision)
        with flow.reader() as authority:
            after_restart = restarted_service.build_context(
                authority, flow.worker_contexts["a"].bearer_token, **args, max_bytes=65536,
            )
        found = _finding_payload(after_restart)["findings"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["finding_id"], "context-reopen-finding")
        self.assertEqual(found[0]["summary"], "Durable finding survives service reconstruction.")

