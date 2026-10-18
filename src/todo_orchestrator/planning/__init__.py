"""Pure plan-package parsing and compilation."""

from .package import (
    AdoptionReceipt,
    BlockerRelation,
    BlockingEdge,
    BlockingGroup,
    CompileResult,
    CompiledPlan,
    ConditionExpression,
    DiagnosticSeverity,
    OwnershipConstraint,
    ParseResult,
    PlanDeclaration,
    PlanDiagnostic,
    PlanPackageInput,
    PlannedRequirement,
    PlannedWorkItem,
    QualifiedReference,
    SourceManifest,
    VerifiedAdoption,
    compile_plan,
    compile_plan_json,
    parse_plan_json,
)
from .graph import (
    ConditionCause,
    ConditionResult,
    ConditionStatus,
    DecisionObservation,
    GraphCycle,
    GraphValidation,
    PlanGraphEdge,
    PlanNode,
    evaluate_blocking_group,
    evaluate_condition,
    evaluate_results,
    validate_plan_graph,
)
from .changes import (
    AcceptedSnapshot,
    AffectedWork,
    ChangeConflict,
    ChangeKind,
    ChangeOperation,
    ChangeSet,
    ExplicitRetirement,
    preview_changes,
)
from .snapshot import (
    SNAPSHOT_FORMAT, SNAPSHOT_SCHEMA_VERSION, accepted_plan_payload,
    decode_accepted_plan, definition_bundle_payloads, encode_accepted_plan,
    encode_accepted_snapshot, materialize_accepted_plan,
)
from .service import PlanCommitError, PlanService

__all__ = [
    "AdoptionReceipt", "BlockerRelation", "BlockingEdge", "BlockingGroup", "CompileResult",
    "CompiledPlan", "ConditionExpression", "DiagnosticSeverity", "OwnershipConstraint", "ParseResult",
    "PlanDeclaration", "PlanDiagnostic", "PlanPackageInput", "PlannedRequirement", "PlannedWorkItem",
    "QualifiedReference", "SourceManifest", "VerifiedAdoption", "compile_plan", "compile_plan_json", "parse_plan_json",
    "ConditionCause", "ConditionResult", "ConditionStatus", "DecisionObservation", "GraphCycle",
    "GraphValidation", "PlanGraphEdge", "PlanNode", "evaluate_blocking_group", "evaluate_condition",
    "evaluate_results", "validate_plan_graph",
    "AcceptedSnapshot", "AffectedWork", "ChangeConflict", "ChangeKind", "ChangeOperation",
    "ChangeSet", "ExplicitRetirement", "preview_changes",
    "SNAPSHOT_FORMAT", "SNAPSHOT_SCHEMA_VERSION", "accepted_plan_payload",
    "decode_accepted_plan", "definition_bundle_payloads", "encode_accepted_plan",
    "materialize_accepted_plan",
    "encode_accepted_snapshot",
    "PlanCommitError", "PlanService",
]
