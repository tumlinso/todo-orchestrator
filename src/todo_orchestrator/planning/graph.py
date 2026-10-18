"""Pure heterogeneous plan graph validation and condition evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

from todo_orchestrator.contracts.domain import EntityKind, EntityRef, RequirementMode, StableId

from .package import (
    CompiledPlan,
    ConditionExpression,
    DiagnosticSeverity,
    PlanDiagnostic,
    QualifiedReference,
)


class ConditionStatus(str, Enum):
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNRESOLVED = "unresolved"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, order=True)
class ConditionCause:
    code: str
    subject: str
    message: str


@dataclass(frozen=True)
class ConditionResult:
    status: ConditionStatus
    causes: tuple[ConditionCause, ...] = ()


@dataclass(frozen=True)
class DecisionObservation:
    """A decision value supplied by the caller; this package performs no I/O."""

    status: ConditionStatus
    option_id: str | None = None


@dataclass(frozen=True, order=True)
class PlanNode:
    project_id: str
    kind: str
    entity_id: str
    revision_id: str = ""

    @property
    def label(self) -> str:
        revision = f"@{self.revision_id}" if self.revision_id else ""
        return f"{self.project_id}/{self.kind}:{self.entity_id}{revision}"


@dataclass(frozen=True)
class PlanGraphEdge:
    source: PlanNode
    target: PlanNode
    relation: str
    path: str
    conditional: bool = False


@dataclass(frozen=True)
class GraphCycle:
    edges: tuple[PlanGraphEdge, ...]
    kind: str = "blocking"

    @property
    def nodes(self) -> tuple[PlanNode, ...]:
        return tuple(edge.source for edge in self.edges) + (self.edges[-1].target,)


@dataclass(frozen=True)
class GraphValidation:
    nodes: tuple[PlanNode, ...]
    edges: tuple[PlanGraphEdge, ...]
    lineage_edges: tuple[PlanGraphEdge, ...]
    cycles: tuple[GraphCycle, ...]
    diagnostics: tuple[PlanDiagnostic, ...]

    @property
    def ok(self) -> bool:
        return not self.diagnostics


def _node_from_ref(reference: QualifiedReference | EntityRef, plan: CompiledPlan) -> PlanNode:
    if isinstance(reference, QualifiedReference):
        ref = reference.reference
        kind = reference.declared_kind
    else:
        ref = reference
        kind = ref.kind.value
    revision = ref.definition_revision_id
    if revision is None and ref.project_id == plan.project.project_id and kind in {"work_item", "requirement"}:
        revision = plan.revision.plan_revision_id
    return PlanNode(str(ref.project_id), kind, str(ref.entity_id), "" if revision is None else str(revision))


def _raw_ref(raw: Mapping[str, object], plan: CompiledPlan) -> PlanNode:
    kind = str(raw["kind"])
    revision = raw.get("revision_id")
    if revision is None and str(raw["project_id"]) == str(plan.project.project_id) and kind in {"work_item", "requirement"}:
        revision = plan.revision.plan_revision_id
    return PlanNode(str(raw["project_id"]), kind, str(raw["entity_id"]), "" if revision is None else str(revision))


def _condition_decisions(expression: ConditionExpression | None) -> tuple[str, ...]:
    if expression is None:
        return ()
    arguments = dict(expression.arguments)
    if expression.op == "decision_equals":
        return (str(arguments["decision_id"]),)
    children = []
    nested = arguments.get("condition")
    if isinstance(nested, ConditionExpression):
        children.extend(_condition_decisions(nested))
    for child in arguments.get("conditions", ()):
        if isinstance(child, ConditionExpression):
            children.extend(_condition_decisions(child))
    return tuple(sorted(set(children)))


def _condition_edges(expression: ConditionExpression | None, source: PlanNode, project_id: str, decision_ids: set[str], path: str) -> list[PlanGraphEdge]:
    edges = []
    for decision_id in _condition_decisions(expression):
        if decision_id in decision_ids:
            edges.append(PlanGraphEdge(
                source, PlanNode(project_id, "decision", decision_id), "condition_decision", path, True
            ))
    return edges


def _find_cycles(nodes: Sequence[PlanNode], edges: Sequence[PlanGraphEdge], kind: str) -> tuple[GraphCycle, ...]:
    adjacency: dict[PlanNode, list[PlanGraphEdge]] = {node: [] for node in nodes}
    for edge in edges:
        adjacency.setdefault(edge.source, []).append(edge)
        adjacency.setdefault(edge.target, [])
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda edge: (edge.target, edge.relation, edge.path, edge.conditional))

    index = 0
    stack: list[PlanNode] = []
    on_stack: set[PlanNode] = set()
    indexes: dict[PlanNode, int] = {}
    lowlinks: dict[PlanNode, int] = {}
    components: list[tuple[PlanNode, ...]] = []

    def strongconnect(node: PlanNode) -> None:
        nonlocal index
        indexes[node] = lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for edge in adjacency[node]:
            target = edge.target
            if target not in indexes:
                strongconnect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if lowlinks[node] == indexes[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(tuple(sorted(component)))

    for node in sorted(adjacency):
        if node not in indexes:
            strongconnect(node)

    cycles = []
    for component in sorted(components, key=lambda members: members[0]):
        allowed = set(component)
        cyclic = len(component) > 1 or any(edge.target == component[0] for edge in adjacency[component[0]])
        if not cyclic:
            continue
        start = component[0]
        path: list[PlanGraphEdge] = []
        active: set[PlanNode] = {start}

        def witness(node: PlanNode) -> bool:
            for edge in adjacency[node]:
                if edge.target not in allowed:
                    continue
                if edge.target == start:
                    path.append(edge)
                    return True
                if edge.target in active:
                    continue
                path.append(edge)
                active.add(edge.target)
                if witness(edge.target):
                    return True
                active.remove(edge.target)
                path.pop()
            return False

        if witness(start):
            cycles.append(GraphCycle(tuple(path), kind))
    return tuple(cycles)


def validate_plan_graph(plan: CompiledPlan) -> GraphValidation:
    """Validate all declared blocking, producer, participant and lineage edges."""
    nodes: set[PlanNode] = set()
    edges: list[PlanGraphEdge] = []
    lineage_edges: list[PlanGraphEdge] = []

    def add_node(node: PlanNode) -> None:
        nodes.add(node)

    def add_edge(source: PlanNode, target: PlanNode, relation: str, path: str, conditional: bool = False) -> None:
        add_node(source)
        add_node(target)
        edges.append(PlanGraphEdge(source, target, relation, path, conditional))

    declaration_kind = {
        "checkpoints": "checkpoint", "interfaces": "interface", "decisions": "decision",
        "barriers": "barrier", "rendezvous": "rendezvous", "invariants": "invariant",
    }
    for item in plan.work_items:
        source = _node_from_ref(item.definition.ref, plan)
        add_node(source)
        if item.definition.parent is not None:
            target = _node_from_ref(item.definition.parent, plan)
            nodes.add(target)
            lineage_edges.append(PlanGraphEdge(source, target, "parent", "$/work_items/parent_id"))
        for reference in item.definition.supersedes:
            target = _node_from_ref(reference, plan)
            nodes.add(target)
            lineage_edges.append(PlanGraphEdge(source, target, "supersedes", "$/work_items/supersedes"))

    for index, requirement in enumerate(plan.requirements):
        requirement_node = _node_from_ref(requirement.definition.ref, plan)
        owner_ref = EntityRef(
            plan.project.project_id,
            EntityKind.WORK_ITEM,
            requirement.definition.work_item_id,
            requirement.definition.definition_revision_id,
        )
        owner_node = _node_from_ref(owner_ref, plan)
        add_edge(owner_node, requirement_node, "requirement_member", f"$/requirements/{index}")
        if requirement.target is not None:
            add_edge(requirement_node, _node_from_ref(requirement.target, plan), "prerequisite", f"$/requirements/{index}/target")
        else:
            evidence = PlanNode(str(plan.project.project_id), "evidence", str(requirement.definition.check_key))
            add_edge(requirement_node, evidence, "check_evidence", f"$/requirements/{index}/check_key")

    decision_ids = {str(item.declaration_id) for item in plan.declarations if item.kind == "decisions"}
    for declaration in plan.declarations:
        kind = declaration_kind[declaration.kind]
        source = PlanNode(str(plan.project.project_id), kind, str(declaration.declaration_id))
        add_node(source)
        payload = declaration.payload
        if declaration.kind in {"checkpoints", "interfaces"}:
            for index, reference in enumerate(payload.get("producers", ())):
                add_edge(source, _raw_ref(reference, plan), "producer", f"$/{declaration.kind}/{declaration.declaration_id}/producers/{index}")
        if declaration.kind == "interfaces":
            for index, reference in enumerate(payload.get("consumers", ())):
                add_edge(_raw_ref(reference, plan), source, "interface_consumer", f"$/interfaces/{declaration.declaration_id}/consumers/{index}")
        if declaration.kind == "decisions":
            for index, reference in enumerate(payload.get("resolvers", ())):
                add_edge(source, _raw_ref(reference, plan), "decision_resolver", f"$/decisions/{declaration.declaration_id}/resolvers/{index}")
        if declaration.kind in {"barriers", "rendezvous"}:
            for index, reference in enumerate(payload.get("participants", ())):
                add_edge(source, _raw_ref(reference, plan), "participant", f"$/{declaration.kind}/{declaration.declaration_id}/participants/{index}")

    for group_index, group in enumerate(plan.blocking_groups):
        source = _node_from_ref(group.source, plan)
        add_node(source)
        for member_index, member in enumerate(group.members):
            path = f"$/dependencies/{group_index}/members/{member_index}"
            add_edge(source, _node_from_ref(member.target, plan), member.relation.value, path, member.condition is not None)
            edges.extend(_condition_edges(member.condition, source, str(plan.project.project_id), decision_ids, f"{path}/condition"))

    ordered_nodes = tuple(sorted(nodes))
    ordered_edges = tuple(sorted(edges, key=lambda edge: (edge.source, edge.target, edge.relation, edge.path, edge.conditional)))
    ordered_lineage_edges = tuple(sorted(lineage_edges, key=lambda edge: (edge.source, edge.target, edge.relation, edge.path)))
    if len(ordered_nodes) > 512 or len(ordered_edges) + len(ordered_lineage_edges) > 4096:
        diagnostic = PlanDiagnostic(
            "graph_too_large",
            "plan graph exceeds the v1 compiler limit of 512 nodes or 4096 edges",
            "$/graph",
        )
        return GraphValidation(ordered_nodes, ordered_edges, ordered_lineage_edges, (), (diagnostic,))
    cycles = _find_cycles(ordered_nodes, ordered_edges, "blocking") + _find_cycles(ordered_nodes, ordered_lineage_edges, "lineage")
    cycles = tuple(sorted(cycles, key=lambda cycle: (cycle.kind, cycle.edges[0].source, cycle.edges[0].path)))
    diagnostics = tuple(
        PlanDiagnostic(
            "blocking_cycle" if cycle.kind == "blocking" else "lineage_cycle",
            ("blocking" if cycle.kind == "blocking" else "lineage") + " graph cycle: " + " -> ".join(edge.source.label for edge in cycle.edges) + " -> " + cycle.edges[-1].target.label,
            cycle.edges[0].path,
            DiagnosticSeverity.ERROR,
        )
        for cycle in cycles
    )
    return GraphValidation(ordered_nodes, ordered_edges, ordered_lineage_edges, cycles, diagnostics)


def evaluate_results(mode: RequirementMode, quorum: int | None, results: Sequence[ConditionResult]) -> ConditionResult:
    """Apply shared all/any/quorum logic to already observed typed results."""
    causes = tuple(sorted({cause for result in results for cause in result.causes}))
    satisfied = sum(result.status is ConditionStatus.SATISFIED for result in results)
    unsatisfied = sum(result.status is ConditionStatus.UNSATISFIED for result in results)
    unresolved = sum(result.status is ConditionStatus.UNRESOLVED for result in results)
    unavailable = sum(result.status is ConditionStatus.UNAVAILABLE for result in results)
    if mode is RequirementMode.ALL:
        if unsatisfied:
            return ConditionResult(ConditionStatus.UNSATISFIED, causes)
        if unavailable:
            return ConditionResult(ConditionStatus.UNAVAILABLE, causes)
        if unresolved:
            return ConditionResult(ConditionStatus.UNRESOLVED, causes)
        return ConditionResult(ConditionStatus.SATISFIED, causes)
    needed = 1 if mode is RequirementMode.ANY else quorum
    if needed is None:
        return ConditionResult(ConditionStatus.UNAVAILABLE, causes + (ConditionCause("invalid_quorum", "group", "quorum is missing"),))
    if satisfied >= needed:
        return ConditionResult(ConditionStatus.SATISFIED, causes)
    possible = satisfied + unresolved + unavailable
    if possible < needed:
        return ConditionResult(ConditionStatus.UNSATISFIED, causes)
    if unavailable:
        return ConditionResult(ConditionStatus.UNAVAILABLE, causes)
    if unresolved:
        return ConditionResult(ConditionStatus.UNRESOLVED, causes)
    return ConditionResult(ConditionStatus.UNSATISFIED, causes)


def evaluate_condition(
    expression: ConditionExpression,
    decisions: Mapping[str, DecisionObservation],
) -> ConditionResult:
    """Evaluate bounded condition trees using supplied facts only."""
    arguments = dict(expression.arguments)
    if expression.op == "decision_equals":
        decision_id = str(arguments["decision_id"])
        option_id = str(arguments["option_id"])
        observation = decisions.get(decision_id)
        if observation is None:
            return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause("decision_missing", decision_id, "no decision observation was supplied"),))
        if observation.status is ConditionStatus.UNAVAILABLE:
            return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause("decision_unavailable", decision_id, "decision authority could not be observed"),))
        if observation.status is ConditionStatus.UNSATISFIED:
            return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause("invalid_decision_observation", decision_id, "decision observations describe resolution, not condition truth"),))
        if observation.status is ConditionStatus.UNRESOLVED or observation.option_id is None:
            return ConditionResult(ConditionStatus.UNRESOLVED, (ConditionCause("decision_unresolved", decision_id, "decision has no selected option"),))
        return ConditionResult(
            ConditionStatus.SATISFIED if observation.option_id == option_id else ConditionStatus.UNSATISFIED,
            (ConditionCause("decision_option", decision_id, f"selected option is {observation.option_id!r}"),),
        )
    if expression.op == "not":
        child = arguments["condition"]
        result = evaluate_condition(child, decisions)
        inverse = {
            ConditionStatus.SATISFIED: ConditionStatus.UNSATISFIED,
            ConditionStatus.UNSATISFIED: ConditionStatus.SATISFIED,
            ConditionStatus.UNRESOLVED: ConditionStatus.UNRESOLVED,
            ConditionStatus.UNAVAILABLE: ConditionStatus.UNAVAILABLE,
        }[result.status]
        return ConditionResult(inverse, result.causes)
    if expression.op in {"all", "any"}:
        mode = RequirementMode.ALL if expression.op == "all" else RequirementMode.ANY
        children = [evaluate_condition(child, decisions) for child in arguments["conditions"]]
        return evaluate_results(mode, None, children)
    return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause("unsupported_condition", expression.op, "condition operator was not compiled"),))


def evaluate_blocking_group(
    group,
    blockers: Sequence[ConditionResult],
    decisions: Mapping[str, DecisionObservation] | None = None,
) -> ConditionResult:
    """Evaluate blocker facts and their activation conditions with one policy."""
    decisions = decisions or {}
    if len(blockers) > len(group.members):
        return ConditionResult(ConditionStatus.UNAVAILABLE, (ConditionCause("extra_blocker_observation", "group", "more blocker observations were supplied than group members"),))
    edge_results = []
    inactive_causes = []
    for index, member in enumerate(group.members):
        blocker = blockers[index] if index < len(blockers) else ConditionResult(
            ConditionStatus.UNRESOLVED,
            (ConditionCause("blocker_missing", str(member.target.reference.entity_id), "no blocker observation was supplied"),),
        )
        if member.condition is None:
            edge_results.append(blocker)
            continue
        condition = evaluate_condition(member.condition, decisions)
        if condition.status is ConditionStatus.UNSATISFIED:
            inactive_causes.extend(condition.causes)
            continue
        elif condition.status is not ConditionStatus.SATISFIED:
            edge_results.append(condition)
        else:
            edge_results.append(ConditionResult(blocker.status, tuple(sorted(set(condition.causes + blocker.causes)))))
    if not edge_results:
        # No condition selected an active obligation; inactive alternatives do
        # not count as positive votes for any/quorum groups.
        return ConditionResult(ConditionStatus.SATISFIED, tuple(sorted(set(inactive_causes))))
    combined = evaluate_results(group.mode, group.quorum, edge_results)
    return ConditionResult(combined.status, tuple(sorted(set(combined.causes + tuple(inactive_causes)))))


__all__ = [
    "ConditionCause", "ConditionResult", "ConditionStatus", "DecisionObservation", "GraphCycle",
    "GraphValidation", "PlanGraphEdge", "PlanNode", "evaluate_blocking_group", "evaluate_condition",
    "evaluate_results", "validate_plan_graph",
]
