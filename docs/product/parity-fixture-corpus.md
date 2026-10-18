# Native parity fixture corpus

Read-only preparation uses the primary reference at
`/home/tumlinson/skills_dev/todo-orchestrator`, captured at
`bfa9238985dfeb2368bad076f1cc51bfdadbae92`. Test fingerprints are recorded in
`reference-baseline.json`. Original tests were inspected and hashed, not run.
Do not combine this corpus with the distinct vendored Project Control snapshot.

| Native area | Reference tests under `tests/` | Behavior to adapt and verify |
| --- | --- | --- |
| C03/C04 | `test_workflow_messages_rendezvous.py`, `test_workflow_context_fragments.py` | Recipient filtering, monotonic cursors, transactional answers, bounded payloads, explicit blockers and fragment invalidation |
| C05 | `test_child_execution_core.py`, `test_child_execution_v2.py`, `test_workflow_foundation.py` | Attenuated scope and rights, durable child results, parent-mediated acceptance |
| R01/R02 | `test_v2_recovery_migration_context.py` | Read-only diagnosis, clean expiry versus dirty quarantine, precise evidence invalidation |
| R03 | `test_workflow_plan_snapshot.py`, `test_as1_foreign_source_port.py` | Omitted-work preservation, frozen interfaces and no-op revisions |
| R04 | `test_v2_foundation.py` | Read-only export and snapshot identity; restoration requires a separately authorized native operation |
| Q02/Q03 | `test_v2_concurrency.py`, `test_v2_graph_coordination.py`, `test_workflow_isolated_claims.py`, `test_workflow_runs_lanes.py`, `test_workflow_completion_provenance.py`, `v2_helpers.py` | Claim contention, blocking graph safety, physical workspace isolation, stale evidence and missing artifacts |

Fixtures must exercise the new native services using temporary authorities,
Git repositories and provider stores. Source resemblance and original test names
are not proof of native parity. Record actual assertions, commands, source
identity and results when the fixtures are implemented for Q01–Q03.

Intentional standalone differences include explicit identity-bound restoration,
native versioned plan contracts, and provider-owned host effects. Legacy import,
Project Control adapters and cutover remain excluded. Host-specific lane and
execution behavior must be adapted through the standalone boundaries rather
than copied as a dependency on the original runtime.
