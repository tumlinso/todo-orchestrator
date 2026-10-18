# Product specification — todo-orchestrator

## Product charter

Build `todo-orchestrator`, a standalone, local-first **transactional planning and work orchestration engine** for multiple human and automated workers. It preserves authoritative intent and execution history across sessions; supports complex plans without forcing needless procedural micro-steps; admits concurrent work safely; requires evidence for accepted claims of completion; and provides fail-closed, non-destructive recovery after interruptions.

The original Todo implementation is **reference material** for tested behavior, safeguards, and reusable algorithms, not the architecture to carry forward. The new product must be usable independently of Project Control, Codex, any model provider, and GPU hardware. Project Control consumes its public API and contributes trusted host integrations. The Git repository/distribution/skill name is `todo-orchestrator` (hyphenated); the Python import package can use a valid short identifier such as `todo`.

The design should minimize **conceptual duplication** rather than file count. Use creativity where it gives simpler invariants, clearer contracts, or stronger correctness. Do not rename or replace a working algorithm purely for novelty.

## Users and use cases

**Coding agents:** A worker receives a scoped, concise assignment, can understand why it is eligible, and records results without needing to understand internal tables. A coordinator can decompose work, communicate decisions and delegate bounded subtasks. An independent validator can inspect and accept evidence.

**Engineering/research project owners:** A user imports a machine-generated plan, reviews a deterministic diff, admits work in parallel where safe, and can adjust future work while preserving completed and in-flight commitments. Accepted negative results and no-change outcomes are valid when the acceptance contract allows them.

**Other applications:** The Python/CLI API can power scripts or non-AI work queues; no mandatory agent-specific protocol or SCM assumption for purely abstract work.

## Required outcomes

1. **First-class machine planning.** Define and version a structured package input; compile it into typed work/requirement definitions, preserving provenance and uncertainty. Accept legacy `project-control-preledger` / `proposed_todos.json` through an isolated converter, not as the canonical model. Reject ambiguous refs and unknown semantics instead of guessing.
2. **Controlled evolution.** Preview and commit deterministic change sets. Support incremental addition, revisions, alternatives, explicit supersession and precise impact explanations. Omission never silently deletes existing work. Protect active assignments, accepted completions, and frozen contracts from implicit edits.
3. **Canonical truth.** Project-local SQLite owns committed definitions, assignments, attempts, claims, decisions, outcome receipts, and semantic event history. A real mutation and its event/revision are atomic. Reads never bootstrap or repair absent state. History is durable and stable across external file changes.
4. **Safe scheduling.** One shared eligibility/authorization policy calculates readable blocker explanations and decides claim admission under the same rules. Distinguish a read-time candidate from a claim reservation. Resolve direct and indirect condition cycles. Support optional serial queues and qualified concurrent work.
5. **Scoped actors and delegation.** Host-supplied principals, bounded grants, claim/attempt leases, role action restrictions and rights-subset rules for delegated children. Capability names/handles are opaque; no caller-written role string constitutes authentication. No untrusted widening of file or worker scope.
6. **Durable coordination.** First-class runs and assignments, typed messages/questions, decisions, synchronization barriers, interface handoffs and bounded context references. Human-readable work packets are derived from accepted plan facts; Todo is not a transcript or source-code archive.
7. **Evidence-backed outcomes.** Typed verification requirements and immutable evidence from trusted execution/verification providers. Record the exact source/inputs and verifier version. The current applicability of evidence is evaluated at final acceptance; historical acceptance remains immutable when sources later change.
8. **Safe external effects.** Durable intents and receipts for operations that cross SQLite (Git worktree creation, integration, command execution). Never claim exactly-once external effects. Recognize unknown/ambiguous states, reconcile by observation, and preserve dirty or conflicting work.
9. **Recovery as product functionality.** Identify expired, live, unknown, clean, dirty and quarantined attempts; produce a reviewable recovery proposal and apply an authorized revision-checked decision. Explicit restore is distinct from normal startup. Retire or replace runs without losing history.
10. **Independent distribution and integration.** Package, CLI, Python API and skill that work without PC. PC uses versioned public read/command interfaces and trusts Todo as semantic writer; PC remains responsible for MCP, workspace registry, source intelligence and host admission policy.

## Behavior and ergonomics

A simple standalone project should require few concepts: initialize explicitly, ingest/define work, see what's ready, claim, report evidence, finish. A rich multi-agent run may use lanes, delegated children, contracts, synchronization, isolation and validation; these are opt-in complexity, **not mandatory ceremony for every task**. Users should see stable reason codes and suggested next actions, not opaque status rewrites.

Work items describe **outcomes**, not instructions to run one command per todo. The plan may preserve motivation, end state, risks, assumptions, alternative approaches and discretion left to workers. This content informs the assignment but never substitutes for machine-checkable safety and authorization.

## Out-of-scope system ownership

- Physical GPU interlocks, accelerator topology, quiescence, preemption and hardware allocation are a **separate subsystem**. Todo may depend on a reservation receipt; it must not own or duplicate the physical reservation authority.
- Model selection, inference, prompt strategy, local worker supervision, network agents, job execution pools and background process runners belong to agent/execution hosts.
- Deep source parsing, semantic indexing, repository search and project knowledge inference belong to Project Control/Observatory or another provider. Todo commits adopted facts only when authorized; advisory findings never become dependencies automatically.
- A monolithic MCP server inside Todo is not required. The standalone skill documents how to use the CLI/API, while PC supplies any MCP transport.
- No distributed database, mandatory central daemon, new queue broker, speculative event-sourcing rewrite or broad microservice architecture for this milestone.

## Completion definition

An acceptable v1 is not merely module skeletons. It implements the product flows above on disposable projects, passes concurrency/plan/evidence/crash tests, supports an independent CLI and PC adapter, and provides a qualified, opt-in migration procedure. Its final code need not match this proposed directory layout, but any significant change of domain ownership or safety invariant must be justified in the design record.

## Delivery ordering

Reference-baseline and accepted domain model first; SQLite/authority and plan compilation second; unified admission and coordination third; evidence/external effects and recovery fourth; standalone API, PC adapter, qualification and explicit cutover last. Some modules can be developed independently once common contracts are frozen. Broad agent fan-out is conditional on demonstrated workspace isolation, not on the presence of multiple lane records.
