# Recovery and preservation evidence

This map records which executable fixtures support the Q03 recovery claims.
The system test uses only temporary SQLite, provider-journal, workspace, and
Git repository paths. Git effects are real; process and verifier behavior in
the separate unit fixtures is injected and is not a claim about production
process supervision or external verifier deployment.

| Recovery assertion | Executable evidence | What the test establishes |
| --- | --- | --- |
| A real external effect can complete before Todo records its receipt, and a fresh process can recover it | `tests/system/test_recovery_workflow.py::RecoveryWorkflowProcessRestartTests.test_real_git_effect_is_inspected_then_reconciled_after_process_loss` | A subprocess exits with `os._exit(73)` at the native Git provider's `after_effect` seam. The worktree exists while both durable operation rows remain `executing` with no observation or receipt. A second process opens the public application API, inspects without changing the exported read model, then applies one source-bound `reconcile_observed_effect` intent. The reconciliation process makes zero calls to Git `perform`; the operation finalizes once. Repository and worktree snapshots (HEAD, index bytes, status, and file bytes) remain unchanged, the worktree count stays at two, and an explicit backup contains the finalized operation and authority history. |
| Lower-level recovery can inspect and reconcile an interrupted Git workspace effect | `tests/recovery/test_recovery_independent.py::ObservedGitEffectRecoveryIndependentTests.test_interrupted_applied_workspace_effect_is_reconciled_once_by_separate_approver` | Exercises the Git effect service and recovery service directly, including unchanged authority state during inspection and exact intent application. This is complementary service-level evidence; it is not a process restart. |
| Definitive no-effect recovery retries only the original request | `tests/recovery/test_recovery_independent.py::ObservedGitEffectRecoveryIndependentTests.test_proven_not_started_git_workspace_effect_is_retried_once_by_recovery_approver`; `tests/verification/test_execution_independent.py::IndependentVerificationExecutionTests.test_proven_not_started_requires_explicit_retry_of_same_operation` | A fresh inspection must prove `NOT_APPLIED`/`NOT_STARTED`; the explicit retry preserves the original operation/request identity. Unknown or executing effects do not authorize blind replay. |
| A source change after review cannot be treated as current success | `tests/verification/test_execution_independent.py::IndependentVerificationExecutionTests.test_trusted_source_observer_change_marks_historical_evidence_stale`; `tests/verification/test_acceptance_independent.py::IndependentOutcomeAcceptanceTests.test_source_and_artifact_change_after_final_preflight_is_rechecked_before_commit`; `tests/verification/test_git_service.py::GitEffectServiceIntegrationTests.test_clean_commit_after_acceptance_is_refused_without_intent_or_ref_churn` | Changed source is retained as stale historical evidence, acceptance is refused if source or artifact changes at the final guard, and Git integration refuses a clean commit made after the accepted source identity. |
| Dirty work remains intact, while live/unknown writers stay blocked | `tests/recovery/test_recovery_independent.py::DirtyWorkspaceHandoffIndependentTests.test_stopped_dirty_workspace_is_requeued_without_changing_any_git_bytes`; `tests/recovery/test_inspection_independent.py::RecoveryInspectionIndependentTests.test_expired_live_and_unknown_workspace_stay_blocked_while_dirty_gets_handoff` | Staged index bytes, unstaged tracked content, and untracked binary files survive stale-preview refusal, writer-time race refusal, and the approved stopped-writer handoff. Live/unknown process or child observations produce no recovery intent; only a trusted stopped writer can receive the dirty-preserving handoff. |
| Git conflicts, dirty destinations, and stale compare-and-swap do not overwrite source or destination data | `tests/verification/test_git_independent.py::GitProviderIndependentTests.test_conflict_preserves_destination_and_source_indexes_and_bytes`; `tests/verification/test_git_independent.py::GitProviderIndependentTests.test_dirty_destination_with_staged_unstaged_and_untracked_files_is_preserved`; `tests/verification/test_git_independent.py::GitProviderIndependentTests.test_stale_destination_cas_is_refused_without_mutating_either_worktree` | Real temporary repositories verify preservation of both indexes and file bytes for conflicts, refusal against staged/unstaged/untracked destination changes, and refusal when the destination ref advances after review. |
| Export retains evidence and immutable authority history | `tests/system/test_recovery_workflow.py::RecoveryWorkflowProcessRestartTests.test_real_git_effect_is_inspected_then_reconciled_after_process_loss`; `tests/recovery/test_export_independent.py::ExportIndependentTests.test_read_model_and_backup_restore_preserve_evidence_and_event_history` | The integrated case backs up the recovered Git operation and checks its finalized state and event count. The export fixture separately verifies accepted outcome, evidence, artifact, provenance, and event history survive a validated explicit restore. |

Run the integrated case with:

```sh
PYTHONPATH=src:. python -S -m unittest tests.system.test_recovery_workflow -v
```

The integrated restart case covers an unattached native `CREATE_WORKSPACE`
effect after physical creation and before receipt persistence. Integration
ref-advance recovery, verifier-ledger restart, staged dirty handoff, current
source drift, and Git conflict/CAS behavior remain qualified by their listed
focused fixtures rather than repeated in the system test. These temporary
provider fixtures do not qualify operating-system process discovery,
third-party provider uptime, or deployment-specific filesystem durability.
