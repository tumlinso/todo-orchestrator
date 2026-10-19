# Release evidence matrix

This is an evidence index, not a release approval. It maps the scoped product gates P-01–P-08 and P-11 and domain invariants I-01–I-14 to current tests and records. `Evidenced` means the named assertions ran on disposable fixtures; it does not certify every host or production topology.

## Current qualification checkpoint

| Area | State | Evidence and boundary |
| --- | --- | --- |
| Q01 legacy parity | Accepted | Eight selected tests passed in isolated `-B -S` subprocesses at primary `skills_dev` source revision `bfa9238985dfeb2368bad076f1cc51bfdadbae92`; manifest `tests/qualification/legacy-corpus.v1.json`, matrix `docs/qualification/parity-matrix-v1.json`. Only the listed assertions ran. |
| Q02 safety model | Accepted at development revision 199 | `docs/qualification/safety-model.md` describes 512 exhaustive 3-item graphs, 48 seeded 4–6 item graphs, stale/no-op/revocation checks, a three-process same-work claim race and the accepted multiworker scenario (`tests/system/test_standalone_workflow.py::test_two_workers_conflicts_rejection_retry_current_verification_close_and_export`). This is bounded model/test evidence, not a proof for arbitrary graph size or filesystem topology. |
| I01 standalone interface | Accepted at development revision 184 | `docs/architecture/standalone-interfaces.md`; its recorded check was 408/408 with a 141-file source manifest. The later I04 source suite below is the broader pin. |
| I04 external providers | Accepted at development revision 210 | Final integrated isolated source suite: 427 tests passed in 183.031 s on Python 3.13.11. Source-set SHA-256 `ab5b5ae3d84d3e1e59818e80fd996588082340fcdb0040e895b2d5b9f7e2dc2f`, pinned in `release-source-pin.json`. Wheel candidate SHA-256 `dee4b5e8f95d033934bbc0445ed37d9ed5f705bf8f29c4dd980fbd84e25efdff`, recorded in `wheel-candidate.v1.json`. Fixture/provider evidence only; no real command executor, resource hardware, or production host is qualified. |
| Q03 failure/restart qualification | Accepted at development revision 204 | Q03 lifecycle record and `tests/system/test_recovery_workflow.py::test_real_git_effect_is_inspected_then_reconciled_after_process_loss`; bounded failure/restart coverage is present. |
| Q05 release documentation | Acceptance state | README, operator guide, release matrix, source pin, and wheel-candidate manifest are integrated. See `todos/to-q05.md` for the authoritative task state. |

## Scoped product gates

| Gate | Status | Evidence | Limit or change |
| --- | --- | --- | --- |
| P-01 Standalone | Evidenced | `tests/package/test_wheel.py`; `tests/api/test_standalone_independent.py`; `tests/api/test_cli.py`; I01 record. | Temporary offline wheel/import and API fixtures; no external installation or production packaging sign-off. |
| P-02 Ingestion | Evidenced | `tests/planning/test_package.py`; `test_changes.py`; `test_service.py`; Q01 parity matrix. | New versioned typed package is canonical; legacy markdown/proposed-todos importer is excluded as TO-P05. |
| P-03 Safe revision | Evidenced | `tests/planning/test_changes_independent.py`; `test_commit_independent.py`; `test_service.py`. | Preview/commit preserves omitted work and history; covered through disposable SQLite authorities. |
| P-04 Concurrency | Evidenced, bounded | Q02 model tests; `tests/authority/test_attempts_independent.py`; `tests/authority/test_eligibility_independent.py`. | Local SQLite process races and tested scope policies only; no claim for network filesystems. |
| P-05 Delegation | Evidenced | `tests/coordination/test_child_scope.py`; `test_children_independent.py`. | Child grants are scoped and attenuated; candidate review is distinct from parent outcome acceptance. Product P-05 delegation is in scope. |
| P-06 Evidence | Evidenced | `tests/verification/test_contracts.py`; `test_execution_independent.py`; `test_acceptance_independent.py`. | Injected trusted providers and temporary source/artifact stores; does not qualify arbitrary external verifier implementations. |
| P-07 External effects | Evidenced, bounded | Q03 accepted at development revision 204; `tests/system/test_recovery_workflow.py::test_real_git_effect_is_inspected_then_reconciled_after_process_loss`; I04 provider tests in the 420-test log; `tests/providers/test_external_independent.py`. | No real remote executor, physical resource provider, or hardware is qualified. |
| P-08 Recovery | Evidenced on disposable fixtures | `tests/recovery/test_inspection_independent.py`; `test_recovery_independent.py`; `test_lifecycle_independent.py`; `test_export_independent.py`; R01–R04 records. | No power-loss/boot test or arbitrary process supervisor proof. Restore is explicit; prior schemas are not migrated. |
| P-11 Ergonomics | Evidenced on bounded public flows | `tests/api/test_standalone_independent.py::test_new_project_public_plan_claim_report_accept_and_finish_with_native_git`; `tests/system/test_standalone_workflow.py::test_two_workers_conflicts_rejection_retry_current_verification_close_and_export`. | Demonstrates one minimal path and one scoped two-worker journey, not an operator-scale deployment. |
| P-09 / P-10 | Excluded | Removed from the derived standalone plan. | Project Control integration and migration/cutover require separate operator direction. |

## Domain invariants

| Invariant | Status | Evidence | Qualification boundary |
| --- | --- | --- | --- |
| I-01 Single semantic writer | Evidenced | `tests/authority/test_sqlite.py`; `test_commands.py`; `src/todo_orchestrator/authority/README.md`. | SQLite authority and derived views tested on temporary files. |
| I-02 Atomic mutations | Evidenced | `tests/authority/test_commands.py::test_handler_exception_after_write_rolls_back_everything`; `test_same_request_concurrent_dispatch_has_one_commit_and_one_replay`. | Command transaction/replay predicates, not cross-system atomicity. |
| I-03 Intent/effects separation | Evidenced | `tests/planning/test_changes.py`; `tests/planning/test_service.py`; accepted outcome tests. | Explicit transitions preserve historical records; behavior is bounded to covered transitions. |
| I-04 Full graph safety | Evidenced | `tests/planning/test_package.py::test_cross_type_cycle_has_a_stable_witness`; `test_condition_and_quorum_evaluation_preserves_unknown_states`; Q02 generated graph model. | Finite graph corpus plus focused heterogeneous cycles; not a proof for unbounded input. |
| I-05 Atomic claim admission | Evidenced | `tests/authority/test_attempts_independent.py::test_two_process_claim_race_has_one_commit_and_no_loser_event_churn`; Q02 three-process same-target race. | Local disposable SQLite and injected observations. |
| I-06 Bounded authority | Evidenced | `tests/authority/test_auth_independent.py`; `tests/coordination/test_children_independent.py`; `tests/api/test_read_authorization.py`. | Authenticated actors and test credentials; no external identity provider qualification. |
| I-07 Source/provider trust | Evidenced at contract boundary | `tests/contracts/test_providers.py`; `tests/verification/test_git_base_observation.py`; `tests/planning/test_changes.py::PlanChangePreviewTests.test_changed_adoption_contract_is_a_real_requirement_change`. | Trust depends on the host selecting and operating the provider correctly. |
| I-08 Evidence provenance | Evidenced | `tests/verification/test_execution_independent.py`; `tests/verification/test_acceptance_independent.py`. | Test providers and temporary Git/artifact stores. |
| I-09 Accepted outcome integrity | Evidenced | `tests/verification/test_acceptance_independent.py`; `tests/verification/test_contracts.py`. | Negative/no-change results require authored policy and typed evidence; no arbitrary result is accepted. |
| I-10 Preserve uncertain work | Evidenced, bounded | Q03 accepted at development revision 204; `tests/recovery/test_recovery_independent.py`; `tests/recovery/test_inspection_boundaries.py`; `tests/system/test_recovery_workflow.py`. | Disposable Git/SQLite/provider fixtures only; no arbitrary host supervisor, power-loss, or network-filesystem qualification. |
| I-11 Explicit recovery/restoration | Evidenced | `tests/recovery/test_inspection_independent.py`; `test_recovery_independent.py`; `test_export_independent.py`. | No automatic migration; restored credentials reflect backup time. |
| I-12 Resource ownership boundary | Evidenced at logical provider interface | `tests/providers/test_external_independent.py`; `docs/architecture/external-providers.md`. | Physical resource capacity and hardware scheduling remain the external provider's responsibility. |
| I-13 Typed communication | Evidenced | `tests/coordination/test_messaging.py`; `test_messaging_restart.py`; `test_context_independent.py`; `test_declarations.py`. | Bounded common credential-pattern checks cannot detect every arbitrary secret in prose. |
| I-14 No forced ceremony | Evidenced | `tests/api/test_standalone_independent.py`; `tests/coordination/test_scheduling_independent.py`. | Minimal flow uses assignment-free work; advanced runs/lanes remain optional. |

## Explicit exclusions and release blockers

- Legacy import **TO-P05** is excluded. It is separate from product P-05 delegation, which remains in scope.
- Project Control rewiring, ingestion transfer, cutover rehearsal, and product P-09/P-10 are excluded. No active Project Control instance, service, other tool, or production authority is in this release scope.
- Schema v20 is the only supported version; v1–v19 are rejected without migration. Do not describe this as an upgrade path.
- The final integrated source-suite result and source pin are recorded above and in `release-source-pin.json`. Q05 acceptance is governed by `todos/to-q05.md`; this evidence matrix does not replace its task record.
- Runtime checks use disposable authorities, temporary Git repositories, and injected providers. No production deployment, real host/process supervisor, real external command executor, physical resource/hardware provider, network filesystem, or power-loss durability has been qualified.

## Final integrated source check

All 427 tests passed in 183.031 seconds on Python 3.13.11.
The exact command is `env PYTHONPATH=src python -S -m unittest discover -s tests -p 'test_*.py' -v`.
The log is `/tmp/todo-orchestrator-release-tests.log`. The accompanying
`release-source-pin.json` hashes 159 source, test, metadata, skill, and reference files;
its canonical source-set SHA-256 is `ab5b5ae3d84d3e1e59818e80fd996588082340fcdb0040e895b2d5b9f7e2dc2f`.
This is the qualified 0.1.0 candidate source snapshot. Q05 task acceptance is recorded separately by the root owner.
