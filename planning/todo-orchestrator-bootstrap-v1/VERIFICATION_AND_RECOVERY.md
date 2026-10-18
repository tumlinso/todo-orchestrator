# Verification, external operations, evidence and recovery

## Separation of responsibility

Todo owns the **criteria** for accepting work and the durable acceptance decision; a verifier/execution provider owns actual command execution, external GPU resources or source probing. Todo need not know how to run a CUDA controller, reserve hardware, or serve a model. It may retain an externally observed permit and require its validity during an operation.

## Typed requirements

Support commands, file/existence predicates, artifacts, benchmark/predicate thresholds, interfaces, checkpoints, manual owner acceptance and domain-specific provider verifiers via explicit versioned contracts. A required criterion is not weakened because an agent says it passed. A `failed` process, `evaluated_not_promoted` benchmark and successful `no_change_required` outcome are different kinds of results; record their semantics faithfully.

## Evidence lifecycle

Verification attempt: authorized → executing → observed → accepted/rejected/stale/uncertain. Store exact requirement version, verifier type/version, command/provider reference, input source identity (including relevant file contents and interfaces), execution context, immutable evidence references and result. Large stdout, stderr and binary artifacts belong in identified external stores, not canonical messages/events.

Before accepting successful completion, recheck applicable input fingerprint and requirement revision against trusted current observations under guarded authority. A passing result for old input remains historical evidence but is not current proof. If external observation cannot be atomically held with the DB, use an expected identity and final guarded observation/receipt protocol with a clear stop condition on races. Do not assert impossible cross-boundary atomicity.

## External operation lifecycle

Each nontransactional operation records an intent with a stable idempotency key, authorized scope, expected source state and provider identity, then executes, observes an effect receipt, and finalizes in SQLite. On crash or a missing/ambiguous receipt, reconcile the *actual effect* before retry. Preserve work if confidence is insufficient. This abstraction serves workspace provisioning, Git apply/integration, verification commands and any future host action, while concrete mechanisms stay in providers.

The old `workflow/workspaces.py` already follows reserve → Git effect → activate, and intentionally leaves generated worktrees for inspection when DB activation fails. Preserve that behavior. Do not hard-reset uncommitted work, delete conflict worktrees or replay an effect whose first execution may have succeeded.

## Recovery, retirement and restoration

Recovery inspection is a read-only diagnosis, with typed blockers and a previewable exact recovery plan. Executing recovery requires trusted principal approval, fresh expected authority, and rechecked process/source state. An expired lease may be released if **proven** clean; changed/unknown-owned work is quarantined, not reassigned destructively. Children and external effects are considered before revoking parent authority.

Run retirement and selective replanning should not require a specialized pile of SQL hacks: they are authorized operations over a coherent domain model, preserving accepted outcomes, source lineage, outstanding artifacts and explicit successor handoffs. An entire active run cannot be silently retired by importing a new plan.

Snapshots/export and projections are derived from authoritative data, with schema and logical fingerprint identity. **No automatic restoration of a missing SQLite authority when a snapshot exists**; a qualified recovery operation verifies backup identity, compatibility and chronology. Historical completion receipts and accepted negative outcomes remain available after schema migration.

## Failure-injection acceptance

- Crash after operation intent but before external effect; inspect/retry or safely cancel.
- Crash after an external Git effect but before receipt finalization; reconcile without repeating destructively.
- Crash after evidence output but before acceptance transaction; recover durable evidence and revalidate source.
- Modify source or an interface while a long-running gate is executing; do not mark new inputs verified.
- Retire run/replan with a dirty active attempt; reject or preserve under explicit handoff, no deletion.
- Restart without SQLite but with a snapshot; report unavailability until deliberate qualified restoration.

Evidence from these tests is part of final release qualification, not just convenience logs.
