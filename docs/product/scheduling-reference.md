# Scheduling reference qualification

Read-only reference: `skills_dev/todo-orchestrator`, commit
`bfa9238985dfeb2368bad076f1cc51bfdadbae92`. The original checkout and authority
are preserved. This note records source and test-corpus inspection; the original
tests were not executed as part of this check.

| Behavior | Original evidence | Standalone treatment |
|---|---|---|
| Independent serial lanes | `todo_orchestrator/workflow/lanes.py` enforces a lane head and one active dispatch; `tests/test_workflow_runs_lanes.py` exercises concurrent dispatch in distinct lanes. | Preserve per-lane serial occupancy, plus the shared scope and isolation policy. A default lane is local to its run; it is not a project-wide lock. |
| Stale occupancy | `reconcile_stale_dispatches_in_transaction` in `workflow/lanes.py:463`; `test_stale_dispatch_is_attention_not_silent_reassignment` in `tests/test_workflow_runs_lanes.py:315`. | Preserve unresolved work and block its serial lane until explicit safe reconciliation. The old stale-heartbeat test does not prove safe handling of unavailable process observations. |
| Roles and grants | `workflow/roles.py`, `workflow/capabilities.py`, and `test_public_action_policy_is_the_role_and_capability_intersection` in `tests/test_workflow_protocol_mcp.py:328`. | Preserve the separation: lane role requirements restrict valid capability grants; labels do not grant authority. |
| Simple authored plans | `plan.py` synthesizes `compat-v2` run/lane state; `tests/test_workflow_plan_snapshot.py` checks that compatibility projection. | Replace compatibility synthesis with native defaults. Manual lane declarations are optional, and direct task claims can remain run-free. |

Serial occupancy, source isolation, and capability authorization are separate
conditions. A different lane or run never proves independent source ownership.
Real workspace qualification remains a provider concern; fixture host receipts
do not establish physical Git isolation. Runnable standalone behavior and
intentional differences must be included in the TO-Q01 parity matrix and later
end-to-end qualification.
