# Reference implementation map — copy, adapt or retire

This is a **source-guided starting index**, not a command to copy everything. These paths were read from the existing `project-control` workspace on 2026-10-18. The new implementer must inspect the exact local source checkout and test corpus before copying code. The original project may have changed afterward.

| Existing source | Useful behavior / observation | Preferred treatment |
|---|---|---|
| `src/todo_orchestrator/db.py` | SQLite WAL, transactions, retry, revision + event commit | Retain core pattern; enforce no-op/idempotent command receipts and read-only initialization |
| `migrations.py` | Full schema history, constraints, many cumulative compatibility migrations | Reference for migration; new normalized schema, explicit converter instead of retaining old table layout |
| `config.py` | Project ID and state location; Git-common state association | Keep project-local durable identity, decouple from PC and make state selection predictable |
| `authority.py` | Logical fingerprint independent of SQLite page layout | Retain principle; prefer scoped semantic versions for high-frequency admission |
| `events.py` | Append-only history/change cursor | Retain, with typed event identities and authority facts |
| `projections.py` | Atomic Markdown/JSON projection, snapshots and restore | Retain projections; make restore explicit, schema-qualified and operator-authorized |
| `service.py` | Broad application service and terminal transitions | Refactor into domain commands; stop mixing plan/execution/gates/locks in one universal class |
| `plan.py` | Plan validation, diff, transaction apply, selective replan, run synthesis | **Primary redesign**: typed compiler/change sets; break up upsert, no-op savepoint simulation and synthetic compatibility run |
| `graph.py`, `barriers.py` | Dependency and barrier checking | Unify typed graph and whole-blocker cycle analysis |
| `readiness.py` | Scored candidates and readiness explanations | Move to one shared eligibility evaluator; scoring remains separate scheduling policy |
| `ownership.py` | Path scope conflict, locks and isolated-overlap proof | Preserve qualified isolation logic; unify with read model/admission |
| `claims.py`, `sessions.py` | Single-claim safety, leases and recovery quarantine | Preserve semantics, represent per-attempt ownership; host-agnostic identity |
| `resources.py`, `cuda_gate.py` | Resource leases, NVIDIA discovery and CUDA-run invocation | **Move physical interlocks out**; only provider reservation contracts in Todo |
| `gates.py`, `evidence.py` | Required checks, input fingerprint, resource reservations and evidence acceptance | Split requirement policy, attempt/receipt, provider runner and outcome acceptance; recheck current identity |
| `checkpoints.py`, `completion.py` | Checkpoint finalization and historical accepted-gate provenance | Preserve; integrate into canonical outcome/requirement lifecycle |
| `interfaces.py` | Frozen contracts, revisions and consumers | Preserve typed interface/producer/consumer contracts; keep source reading in providers |
| `child_execution.py` | Bounded child attempts and parent acceptance | Preserve as subordinate attempt behavior, not a second full task engine |
| `workflow/foundation.py` | Typed identity, lineage, payload budget and roles | Preserve essential invariants; remove old names and arbitrary hard-coded fallback list |
| `workflow/runs.py` | Immutable charter revisions | Model as run configuration referring to accepted plan; avoid duplicated authoritative briefs |
| `workflow/lanes.py` | Serial queues, deterministic dispatch, run assignment | Reuse scheduling semantics in Assignment/Attempt model |
| `workflow/capabilities.py` | Opaque hash-only grants and lineage | Preserve and generalize host-authenticated actor/grant model |
| `workflow/protocol.py` | Capability-enforced tool boundary, operation envelopes | Retain bounded receipts, avoid unrelated status coercions and skill-name hardcoding |
| `workflow/service.py` | Run coordination, integration lifecycle, handoff, delegation | Break large action router into domain services; preserve transactional semantics |
| `workflow/messages.py` | Typed bounded message/decision/recipient/receipt | Retain; version contract and unify condition semantics |
| `workflow/rendezvous.py` | All/quorum/producer synchronization | Retain as typed dependency condition, not a second independent barrier system |
| `workflow/context_fragments.py` | Versioned bounded context with secret screening | Retain one authoritative source of authored plan text; derive fragments and deltas |
| `workflow/workspaces.py` | Worktree provisioning, artifact queue, integration and conflict preservation | Retain conservative Git algorithms behind a source-effects provider; introduce common effect receipts |
| `workflow/recovery.py`, `retirement.py` | Safety-first recovery, approval, quiescent run replacement | Preserve tests and safety; unify interrupted attempt/effect/replacement transitions |
| `semantic/lifecycle.py`, `semantic/state.py`, `semantic/workflow.py` | Normalized effective state and advisory parallel group | Rebuild read views from one canonical rule engine; remove ID-prefix program heuristics |
| `read_port.py` | Verified in-process read-only facade | Retain versioned read API but remove CLI-argument parsing inside Python service |
| `runtime_identity.py` | Delegates to PC runtime identity | Reverse dependency: Todo should own standalone source/package identity; PC validates selected version |
| `runtime/` | Source fingerprint/contracts and an umbrella facade | Split source observation/provider contracts from physical runtime / background jobs |
| `background/` | Separate job queue, process runner, host global coordinator | **Out of Todo scope**: move to execution/physical-resource service where needed; don't copy as core |
| `project_control/preledger.py` | Deterministic machine-plan lowering and provenance | Absorb into Todo as versioned legacy importer; new canonical plan format independent |
| `project_control/mutation.py` | Trusted project mapping, optimistic approval and direct native plan SQL | PC should become thin adapter; typed Todo service owns final plan transaction |
| `project_control/workflow_binding.py`, `workflow_tools.py` | Verified lazy Python protocol binding and MCP transport | PC owns transport and installed version selection, Todo owns protocol semantics |
| `project_control/todo_authority.py`, `adapters/todo.py`, `snapshot.py` | Read adapter, authority normalization, snapshot composition | Preserve PC view composition but have normalized public Todo read models |

## Behavioral reference tests to carry forward

Useful tests inspected: `tests/test_todo_authority.py`, `tests/test_todo_git_adapters.py`, `tests/test_workflow_binding.py`, `tests/test_workflow_read_model.py`, `tests/test_preledger.py`, `tests/test_workflow_tools.py`. These cover parts of the integration surface, not the full Todo core; the implementing agent should locate the bundled Todo's own tests in the original tree and construct isolated parity fixtures. References in these tests to sibling `src/todo_orchestrator`, old schema hashes and historical fallback behavior should not automatically become new product requirements.

## Known concrete debt that warrants change

1. `plan.py` reconstructs status/result and owned fields during task upsert, with no-op and diff based on trial write/rollback; isolate declarations from execution and compute typed changes first.
2. `graph.validate_acyclic()` checks parent and direct task edges, while actual dependency types also include checkpoints, interfaces, barriers and decisions; a full typed blocker graph is needed.
3. `semantic/workflow.py::_isolated_overlap_is_safe()` uses weaker conditions than `ownership.py::_isolated_merge_overlap_allowed()`; remove separate policy implementations.
4. `gates.py` combines database leases, process execution and later completion/evidence transactions; an attempt/effect/receipt lifecycle improves interrupted-operation reasoning. Gate identity must be refreshed on acceptance.
5. `service.py` can restore a snapshot when a writable DB is absent; that should require explicit restoration authorization.
6. `workflow/service.py` and `workflow/protocol.py` combine many unrelated coordination actions and backward-compatible public-status coercions; favor cohesive typed commands and meaningful results.
7. `workflow/context_fragments.py` plus `plan.py` copy previously authored brief data as a preservation fix; track canonical authored facts and derive brief versions.
8. `sessions.py` derives identity from Codex environment variables; injectable trusted identities make the product genuinely standalone.
9. Runtime/GPU bindings and package identity assume Project Control installations; remove reverse imports and direct CUDA controller paths.

**Avoid false precision:** this map is grounded in source inspection but is not a complete proof that a current bug is exploitable. Validate each proposed correctness fix with a focused test before changing behavior.
