# Sealed-release cutover — 2026-10-21

Completed the operator-authorized standalone Todo release deployment.

- Project Control **0.4.2**, tool schema **12**, built from commit `0811a3a55298fe9617ed9e9f6266e4cf4f66fbe5`.
- Independently installed Todo Orchestrator **0.2.1**, wheel SHA-256 `3f37c89fa2fb73612e2ecd88124b40c7e14f4f7d70580e1fa4bd5609357ad305`.
- Todo package fingerprint `613ec4537777eb0c434906f3b87493aea757d97c31e34de9518b9e29bfe0db33`.
- Project Control package fingerprint `0a74cb3517b8dcacb31ee6949714ae0fd2837c616d060a17b787bfd3c07af9ea`.
- Immutable candidate: `/home/tumlinson/.local/state/project-control/venvs/pc-sealed-0.4.2-0811a3a`.
- Release-manifest SHA-256: `fa4db87f7b178c84f6b2f0a09947d441897cfbe744042f7bfd444dfb7229e460`.

## Activated paths

`~/.local/state/project-control/current` selects this candidate. The standard
CLI, Codex registration, HTTP observer service, and demand-only inference
launcher resolve through it. The observer is active on its existing loopback
port 8768. Inference remains inactive until requested. Explicit `pc-dev`
development remains available separately. Existing stdio sessions may retain
their loaded code until reconnecting; they were preserved for ongoing work.

## Qualification

31 focused installer, runtime binding, release-identity, provider and doctor
checks passed. Negative checks cover modified Todo bytes, symlinked code,
incorrect manifest digests and missing Project Control identity. The installed
candidate also cleared deliberately stale Python and release environment pins.

Candidate and live fresh MCP clients match the pre-switch schemas exactly:
observer 11, coder 12, mutator 16. A registered Project Control workspace read
returned `no_work`. Live `/version` reports 0.4.2 and `/readyz` reports core
ready with the pinned independent Todo fingerprint. All 20 registered
workspaces read successfully; all 21 repository authority identities and
nondecreasing revisions were verified. Two existing active attempts were
preserved; V200 progressed during the operation. All four optional skills
remain available. The sealed local receiver binding was verified without
starting models or GPU work.

This was focused release qualification, not a full test-suite pass. Legacy
CLI-profile tests still refer to removed APIs and old fixtures; those unrelated
failures are not represented as passing. No new engine functionality was added.

## Rollback and branch closure

Private rollback files, consistent supported authority backups, exact original
source commit `07849abd39af476fcd0c6fc3828bf77d6b51b1a9`, its copied Python
environment, operational receipts, and a pre-closure Git bundle are retained at:

`/mnt/block/project-control-sealed-release/20261021T145104Z`

The preserved source runtime was checked independently and read all 20
workspaces. `python /mnt/block/project-control-sealed-release/20261021T145104Z/rollback.py` restores the prior launch configuration,
selects the preserved source runtime, restores the prior release pointer, and
restarts the observer. It does **not** restore or rewind semantic authorities.
The previous sealed candidate and original source environments remain intact.

Historical branch content was audited against integration commits and later
successor code. Remaining researcher evidence guidance was adapted in `e00aa0e`.
Obsolete test-harness shims remain historical, rather than being reintroduced.
Merge `c4a7554` makes all historical heads reachable from main without changing
the accepted tree. Exact mappings for 184 prior local/remote refs are retained
in annotated `archive/sealed-cutover-20261021/...` tags, pushed before deletion,
and `/mnt/block/project-control-sealed-release/20261021T145104Z/branch-map.json`.

Closed 111 local and 73 remote Project Control branches. Preserved
all present worktree directories and their data; 38 checked-out branches were
detached at the identical commit. Only missing worktree registrations were
pruned. Project Control and Todo Orchestrator now retain only main/origin/main.
GitHub reports no open pull requests in either repository. Other repositories'
branches and active tasks were not changed.
