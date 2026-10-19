"""Deterministic model-based qualification across planning and admission seams.

These tests use small generated state spaces and disposable SQLite authorities.
They qualify native services; they do not prove behavior for unbounded graphs or
arbitrary external provider implementations.
"""

from copy import deepcopy
from datetime import timedelta
import json
import multiprocessing
import random
import unittest

from todo_orchestrator.authority import AttemptAdmissionDeniedError, StaleAuthorityRevisionError
from todo_orchestrator.authority.attempts import CLAIM_ACTION
from todo_orchestrator.authority.auth import AuthenticatedPrincipal, AuthenticationFailedError
from todo_orchestrator.contracts import ActorKind, Project, StableId
from todo_orchestrator.model import (
    EligibilityRequest,
    EligibilityStatus,
    LaneSpec,
    QueuePolicy,
    ScheduledWork,
)
from todo_orchestrator.planning import compile_plan, parse_plan_json

from tests.authority import test_attempts_independent as attempt_fixtures
from tests.planning import test_commit_independent as commit_fixtures
from tests.coordination import test_scheduling_independent as scheduling_fixtures


GRAPH_PROJECT = Project(StableId("q02-graph-project"), StableId("q02-graph-authority"))


def _graph_document(node_count: int, edges: set[tuple[int, int]]) -> dict[str, object]:
    """Build a valid package whose only varying semantics are work dependencies."""
    dependencies = []
    for source in range(node_count):
        targets = sorted(target for edge_source, target in edges if edge_source == source)
        if targets:
            dependencies.append({
                "source": {
                    "project_id": str(GRAPH_PROJECT.project_id),
                    "kind": "work_item",
                    "entity_id": f"node-{source}",
                },
                "mode": "all",
                "members": [
                    {
                        "relation": "completion",
                        "target": {
                            "project_id": str(GRAPH_PROJECT.project_id),
                            "kind": "work_item",
                            "entity_id": f"node-{target}",
                        },
                    }
                    for target in targets
                ],
            })
    return {
        "format": "todo-orchestrator.plan",
        "schema_version": 1,
        "package_id": "q02-generated-dependency-graph",
        "project": {
            "project_id": str(GRAPH_PROJECT.project_id),
            "authority_id": str(GRAPH_PROJECT.authority_id),
        },
        "work_items": [
            {
                "id": f"node-{index}",
                "title": f"Node {index}",
                "objective": "Exercise generated graph validation",
                "outcome": "The graph is classified against an independent oracle",
                "scope": {"paths": [], "concepts": []},
                "acceptance": {
                    "assertions": [],
                    "required_evidence": [],
                    "allowed_dispositions": ["completed"],
                },
            }
            for index in range(node_count)
        ],
        "dependencies": dependencies,
    }


def _has_directed_cycle(node_count: int, edges: set[tuple[int, int]]) -> bool:
    """Independent Kahn topological-sort oracle; self-edges are cycles."""
    outgoing = {node: set() for node in range(node_count)}
    indegree = {node: 0 for node in range(node_count)}
    for source, target in edges:
        if target not in outgoing[source]:
            outgoing[source].add(target)
            indegree[target] += 1
    ready = [node for node, degree in indegree.items() if degree == 0]
    visited = 0
    while ready:
        source = ready.pop()
        visited += 1
        for target in outgoing[source]:
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    return visited != node_count


class _WorkerAuthenticator:
    provider_id = "q02-model-worker-authenticator"

    def authenticate(self, credential):
        if credential == "q02-worker-credential":
            return AuthenticatedPrincipal("q02-model-worker", ActorKind.AUTOMATION, "model worker")
        return None


class SafetyModelQualificationTests(unittest.TestCase):
    def _fixture(self, fixture_type):
        fixture = fixture_type()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_exhaustive_three_node_and_seeded_graphs_match_independent_cycle_oracle(self):
        cases: list[tuple[int, set[tuple[int, int]]]] = []
        for mask in range(1 << 9):
            edges = {
                (source, target)
                for source in range(3)
                for target in range(3)
                if mask & (1 << (source * 3 + target))
            }
            cases.append((3, edges))

        generator = random.Random(20261019)
        for _ in range(48):
            count = generator.randint(4, 6)
            edges = {
                (source, target)
                for source in range(count)
                for target in range(count)
                if generator.random() < 0.24
            }
            cases.append((count, edges))

        for index, (node_count, edges) in enumerate(cases):
            with self.subTest(case=index, node_count=node_count, edges=sorted(edges)):
                parsed = parse_plan_json(json.dumps(_graph_document(node_count, edges), sort_keys=True))
                self.assertTrue(parsed.ok, parsed.diagnostics)
                result = compile_plan(parsed.package, GRAPH_PROJECT)
                has_cycle = _has_directed_cycle(node_count, edges)
                if has_cycle:
                    self.assertIsNone(result.plan)
                    self.assertIn("blocking_cycle", {diagnostic.code for diagnostic in result.diagnostics})
                else:
                    self.assertIsNotNone(result.plan, result.diagnostics)
                    self.assertTrue(result.graph_validation.ok)

    def test_plan_ingestion_state_machine_keeps_noop_cas_and_replay_invariants(self):
        fixture = self._fixture(commit_fixtures.PlanCommitIndependentTests)
        initial_document = fixture.simple_document()
        initial_json = fixture.package_text(initial_document)

        with fixture.open_writer() as authority:
            initial_preview = fixture.plans.preview(authority, initial_json)
            initial = fixture.plans.commit(
                authority,
                fixture.root.bearer_token,
                initial_json,
                reviewed_digest=initial_preview.digest,
                idempotency_key=StableId("q02-model-initial-plan"),
                expected_authority_revision=initial_preview.expected_authority_revision,
                expected_plan_revision_id=initial_preview.expected_revision_id,
            )
        self.assertTrue(initial.receipt.changed)
        accepted_revision = initial.receipt.semantic_revision

        # Reordering authored work is canonical-equivalent: it must not add a
        # semantic revision even though the review envelope is independently built.
        reordered_document = deepcopy(initial_document)
        reordered_document["work_items"].reverse()
        reordered_json = fixture.package_text(reordered_document)
        with fixture.open_reader() as authority:
            reordered_preview = fixture.plans.preview(authority, reordered_json)
        self.assertTrue(reordered_preview.is_noop)
        with fixture.open_writer() as authority:
            no_op = fixture.plans.commit(
                authority,
                fixture.root.bearer_token,
                reordered_json,
                reviewed_digest=reordered_preview.digest,
                idempotency_key=StableId("q02-model-canonical-reorder"),
                expected_authority_revision=reordered_preview.expected_authority_revision,
                expected_plan_revision_id=reordered_preview.expected_revision_id,
            )
        self.assertFalse(no_op.receipt.changed)
        self.assertEqual(fixture.stable_state()[1], accepted_revision)

        stale_document = deepcopy(initial_document)
        stale_document["work_items"][0]["title"] = "Stale reviewed title"
        stale_json = fixture.package_text(stale_document)
        with fixture.open_reader() as authority:
            stale_preview = fixture.plans.preview(authority, stale_json)

        winner_document = deepcopy(initial_document)
        winner_document["work_items"][0]["title"] = "Committed winning title"
        winner_json = fixture.package_text(winner_document)
        with fixture.open_writer() as authority:
            winner_preview = fixture.plans.preview(authority, winner_json)
            winner = fixture.plans.commit(
                authority,
                fixture.root.bearer_token,
                winner_json,
                reviewed_digest=winner_preview.digest,
                idempotency_key=StableId("q02-model-winner"),
                expected_authority_revision=winner_preview.expected_authority_revision,
                expected_plan_revision_id=winner_preview.expected_revision_id,
            )
        self.assertEqual(winner.receipt.semantic_revision, accepted_revision + 1)
        committed_state = fixture.stable_state()
        with fixture.open_writer() as authority:
            with self.assertRaises(StaleAuthorityRevisionError):
                fixture.plans.commit(
                    authority,
                    fixture.root.bearer_token,
                    stale_json,
                    reviewed_digest=stale_preview.digest,
                    idempotency_key=StableId("q02-model-stale-preview"),
                    expected_authority_revision=stale_preview.expected_authority_revision,
                    expected_plan_revision_id=stale_preview.expected_revision_id,
                )
        self.assertEqual(fixture.stable_state(), committed_state)

        with fixture.open_writer() as authority:
            replay = fixture.plans.commit(
                authority,
                fixture.root.bearer_token,
                winner_json,
                reviewed_digest=winner_preview.digest,
                idempotency_key=StableId("q02-model-winner"),
                expected_authority_revision=winner_preview.expected_authority_revision,
                expected_plan_revision_id=winner_preview.expected_revision_id,
            )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, winner.receipt)
        self.assertEqual(fixture.stable_state(), committed_state)

    def test_advisory_and_claim_share_serial_and_revocation_decisions(self):
        fixture = self._fixture(scheduling_fixtures.IndependentSchedulingTests)
        fixture.auth.authenticator = _WorkerAuthenticator()
        lane = LaneSpec(StableId("q02-serial-lane"), QueuePolicy.SERIAL, scheduling_fixtures.ROLE_BUILD)
        first_target, second_target = fixture.work("work-alpha"), fixture.work("work-delta")
        schedule = fixture.schedule(
            "q02-serial-run",
            lanes=(lane,),
            work=(ScheduledWork(first_target, lane.lane_id), ScheduledWork(second_target, lane.lane_id)),
            charter=fixture.charter(),
        )
        fixture.open_run(schedule, key="q02-serial-open")
        run_view = fixture.read_run("q02-serial-run")
        first_entry = next(entry for entry in run_view.entries if entry.assignment.work_item == first_target)
        second_entry = next(entry for entry in run_view.entries if entry.assignment.work_item == second_target)

        def advisory(entry, workspace_id, actor):
            target = entry.assignment.work_item
            request = EligibilityRequest(
                target,
                actor,
                CLAIM_ACTION,
                fixture.revision(),
                run=run_view.run.ref,
                assignment=entry.assignment.ref,
            )
            qualification = fixture.host.qualify_workspace(
                StableId(workspace_id), target, StableId("q02-correlation-" + workspace_id)
            )
            with fixture.open_reader() as authority:
                return fixture.attempts.eligibility.evaluate_read(
                    authority,
                    request,
                    fixture.plan,
                    workspace_qualifications={target: qualification},
                )

        self.assertIs(
            advisory(first_entry, "q02-first-workspace", fixture.owner.capability.actor).status,
            EligibilityStatus.ALLOWED,
        )
        first_claim = fixture.claim(
            fixture.owner.bearer_token, run_view.run, first_entry,
            "q02-first-claim", "q02-first-workspace",
        )
        serial_decision = advisory(second_entry, "q02-second-workspace", fixture.owner.capability.actor)
        self.assertIs(serial_decision.status, EligibilityStatus.BLOCKED)
        self.assertIn("serial_lane_occupied", {cause.code for cause in serial_decision.causes})
        before_serial_refusal = fixture.state_snapshot()
        with self.assertRaises(AttemptAdmissionDeniedError) as serial_refusal:
            fixture.claim(
                fixture.owner.bearer_token, run_view.run, second_entry,
                "q02-second-claim", "q02-second-workspace",
            )
        self.assertEqual(
            {cause.code for cause in serial_refusal.exception.decision.causes},
            {cause.code for cause in serial_decision.causes},
        )
        self.assertEqual(fixture.state_snapshot(), before_serial_refusal)
        self.assertTrue(first_claim.receipt.changed)

        # A separately delegated worker can claim disjoint work. Once its family
        # is revoked, advisory and transactional entrypoints both refuse it.
        with fixture.open_writer() as authority:
            child = fixture.auth.delegate(
                authority,
                fixture.owner.bearer_token,
                "q02-worker-credential",
                actions=(CLAIM_ACTION,),
                scope=fixture.plan.project.ref,
                expires_at=fixture.clock() + timedelta(hours=1),
                idempotency_key=StableId("q02-worker-delegate"),
                expected_revision=fixture.revision(),
            )
        child_target = fixture.work("work-gamma")
        with fixture.open_writer() as authority:
            worker_claim = fixture.attempts.claim(
                authority,
                child.bearer_token,
                child_target,
                fixture.plan,
                workspace_id=StableId("q02-worker-workspace"),
                idempotency_key=StableId("q02-worker-claim"),
                expected_revision=fixture.revision(),
            )
        with fixture.open_writer() as authority:
            fixture.auth.revoke_family(
                authority,
                fixture.owner.bearer_token,
                child.capability.capability_id,
                idempotency_key=StableId("q02-worker-revoke"),
                expected_revision=fixture.revision(),
            )

        revoke_target = fixture.work("work-delta")
        revoke_request = EligibilityRequest(
            revoke_target,
            child.capability.actor,
            CLAIM_ACTION,
            fixture.revision(),
        )
        revoke_qualification = fixture.host.qualify_workspace(
            StableId("q02-revoked-workspace"), revoke_target, StableId("q02-revoked-correlation")
        )
        with fixture.open_reader() as authority:
            revoked_decision = fixture.attempts.eligibility.evaluate_read(
                authority,
                revoke_request,
                fixture.plan,
                workspace_qualifications={revoke_target: revoke_qualification},
            )
        self.assertIsNot(revoked_decision.status, EligibilityStatus.ALLOWED)
        before_revoked_claim = fixture.state_snapshot()
        with fixture.open_writer() as authority:
            with self.assertRaises(AuthenticationFailedError):
                fixture.attempts.claim(
                    authority,
                    child.bearer_token,
                    revoke_target,
                    fixture.plan,
                    workspace_id=StableId("q02-revoked-workspace"),
                    idempotency_key=StableId("q02-revoked-claim"),
                    expected_revision=fixture.revision(),
                )
        self.assertEqual(fixture.state_snapshot(), before_revoked_claim)
        self.assertTrue(worker_claim.receipt.changed)

    def test_three_process_same_scope_claim_race_has_one_winner_and_no_loser_churn(self):
        fixture = self._fixture(attempt_fixtures.IndependentAttemptAuthorityTests)
        tokens = tuple(fixture.issue_owner(key=f"q02-racer-token-{index}") for index in range(3))
        baseline_revision = fixture.revision()
        with fixture.open_reader() as authority:
            baseline = tuple(authority.connection.execute(
                "SELECT (SELECT count(*) FROM attempts), (SELECT count(*) FROM authority_events), "
                "(SELECT count(*) FROM command_receipts), (SELECT count(*) FROM command_idempotency)"
            ).fetchone())

        context = multiprocessing.get_context("fork")
        gate = context.Barrier(len(tokens))
        results = context.Queue()
        processes = [
            context.Process(
                target=attempt_fixtures._claim_in_process,
                args=(str(fixture.path), fixture.project, fixture.plan, token.bearer_token,
                      baseline_revision, index, gate, results),
            )
            for index, token in enumerate(tokens, start=1)
        ]
        try:
            for process in processes:
                process.start()
            outcomes = [results.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=30)
                self.assertFalse(process.is_alive(), "claim process did not terminate")
                self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            results.close()

        successes = [outcome for outcome in outcomes if outcome[0] == "ok"]
        refusals = [outcome for outcome in outcomes if outcome[0] == "error"]
        self.assertEqual(len(successes), 1, outcomes)
        self.assertEqual(len(refusals), 2, outcomes)
        self.assertTrue(all(outcome[1] in {
            AttemptAdmissionDeniedError.__name__, StaleAuthorityRevisionError.__name__,
        } for outcome in refusals), outcomes)
        with fixture.open_reader() as authority:
            after = tuple(authority.connection.execute(
                "SELECT (SELECT count(*) FROM attempts), (SELECT count(*) FROM authority_events), "
                "(SELECT count(*) FROM command_receipts), (SELECT count(*) FROM command_idempotency)"
            ).fetchone())
        self.assertEqual(after, tuple(value + 1 for value in baseline))
        self.assertEqual(fixture.revision(), baseline_revision + 1)


if __name__ == "__main__":
    unittest.main()
