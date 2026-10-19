# Todo Orchestrator operator guide

This guide documents standalone Todo Orchestrator 0.2.0 alpha and the registered-workspace client boundary. The 0.1.0 standalone baseline passed 427 fixture tests; the 0.2.0 source suite and migration/import rehearsals are tracked separately in [the cutover qualification record](../../planning/cutover-v1/README.md). Fixture evidence does not qualify production host supervision, real command executors, hardware resource scheduling, power-loss recovery, or network filesystems.

## Registered Project Control workspaces

Use the Project Control native workflow tools rather than the standalone CLI
for a registered workspace. The host selects the registered authority and
binds identity, profile, credentials, repository, and providers. Common tools
are `todo_read_authority`, `todo_preview_plan`, `todo_commit_plan`,
`todo_open_run`, `todo_create_workspace`, `todo_dispatch_attempt`,
`todo_verify_attempt`, `todo_report_outcome`, `todo_accept_outcome`,
`todo_finish_attempt`, and `todo_inspect_attempt`. Plan commit takes the exact
preview returned by `todo_preview_plan` and an idempotency key. Other mutating
calls use typed native IDs and the same idempotency discipline. Never supply
filesystem paths or bearer credentials as selectors.

Use `todo_read_legacy_current_tasks`, `todo_search_legacy_history`, and
`todo_read_legacy_project_context` to inspect imported status, linked archive
history, and preserved project declarations. Legacy completion assertions are
not native verification. Unresolved or unknown external effects remain
attention items and are not replayed. Legacy snapshot preview/import tools are
mutator-only operations controlled by the operator migration procedure. For
the exact schema and full operation list, follow the active Project Control
tool manifest.

The standalone CLI instructions below apply to a separate authority opened
directly through Todo Orchestrator; they do not select a registered Project
Control authority.

## Install in isolation

Use a new project-local virtual environment. Do not install into the Project Control runtime or an environment that resolves the legacy `todo_orchestrator` package.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/todo --version
.venv/bin/todo --help
```

Python 3.11 or newer is required (qualified on Python 3.13.11). CLI version is 0.1.0. There are no runtime dependencies; a build/install needs local pip and setuptools 68+. If using the source checkout without installing, run with `PYTHONPATH=src python -S -m todo_orchestrator`. SQLite authority initialization requires supported POSIX filesystem behavior.

Help and version are state-free. `init` is the only creation command; `open` and reads do not initialize, repair, migrate, or restore missing state.

## Owner authentication and bearer files

Keep the owner credential and issued bearer outside the project tree. Prefer a secret manager or a file with owner-only permissions. The CLI also supports an interactive non-echoing owner prompt. Do not pass credentials as command-line values or put tokens in plan files, notes, or logs.

```sh
umask 077
mkdir -p "$HOME/.local/share/todo-orchestrator"
.venv/bin/todo --root /path/to/new-project init \
  --project-id project-id --repository-id repository-id \
  --token-output "$HOME/.local/share/todo-orchestrator/project.token"
```

`init` refuses existing project metadata or authority state. It reserves a new mode-0600 token destination before creating authority state and never overwrites an existing destination. Owner login is a separate operation for an existing authority:

```sh
.venv/bin/todo --root /path/to/project auth login \
  --token-output "$HOME/.local/share/todo-orchestrator/project.token"
```

Subsequent commands use `--token-file PATH` or `TODO_BEARER_TOKEN`. Dispatch can issue an attempt-scoped bearer only to a new private token path. If a command reports token-delivery uncertainty after state may have changed, inspect the authority before retrying; do not assume the command did nothing.

## Review and commit plans

A plan is a versioned JSON package. Use the repository's `references/quickstart-plan.json` as the smallest complete two-item example, or author a package using the format documented by the planning reference. The top-level `dependencies` field expresses cross-item ordering; `requirement_groups` express checks/prerequisites owned by one item.

```sh
.venv/bin/todo --root /path/to/project --token-file "$TOKEN" \
  plan preview plan.json --output /tmp/plan-preview.json

# Inspect the complete preview, conflicts, diagnostics, expected revisions, and digest.
.venv/bin/todo --root /path/to/project --token-file "$TOKEN" \
  plan commit plan.json --preview /tmp/plan-preview.json \
  --idempotency-key plan-change-001
```

Commit requires the exact preview and current revision preconditions. A semantic no-op does not advance the authority revision. Omitted definitions remain current; explicit retirement and successor lineage are reviewed operations. Do not hand-edit the authority database or generated projections.

## Dispatch, verify, report, accept, and release

Dispatch selects an eligible work item and creates an attempt-scoped token. The standalone CLI requires explicit workspace and idempotency IDs. Run/assignment selectors are optional for assignment-free work.

```sh
.venv/bin/todo --root /path/to/project --token-file "$TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  dispatch --work-item write --workspace-id "$WORKSPACE_ID" \
  --idempotency-key dispatch-001 \
  --token-output "$HOME/.local/share/todo-orchestrator/attempt-001.token"
```

The factory is trusted executable configuration. It receives the resolved project root and validated metadata and must return `ProviderComposition`. The CLI does not import provider code from the plan, metadata, or project directory. Configure repository identity, base ref, and integration ref deliberately. Do not rely on inferred current checkout state. The CLI does not create workspaces. Provision one first through the public API and use the returned identifier; do not fabricate or guess it:

```python
from todo_orchestrator.contracts.domain import StableId
from todo_orchestrator.api import TodoApplication

with TodoApplication.open(project_root, bearer_token=token, providers=providers) as session:
    operation = session.create_workspace(
        "write", idempotency_key=StableId("workspace-create-write")
    )
    workspace_id = operation.request.workspace_id
```

The trusted `providers` composition must be configured for the same project. Use IDs returned by dispatch and candidate reporting in the later examples; the `$..._ID` values below are placeholders.

Use the attempt token for only its scoped work. Run each authored verification requirement with a fresh idempotency key. A verification pass is evidence, not acceptance. Then report a candidate and have an authorized independent actor accept or reject it:

```sh
.venv/bin/todo --root /path/to/project --token-file "$ATTEMPT_TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  verify --attempt "$ATTEMPT_ID" --requirement "$REQUIREMENT_ID" --idempotency-key verify-001

.venv/bin/todo --root /path/to/project --token-file "$ATTEMPT_TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  report --attempt "$ATTEMPT_ID" --disposition completed --idempotency-key report-001

.venv/bin/todo --root /path/to/project --token-file "$REVIEWER_TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  accept --attempt "$ATTEMPT_ID" --candidate "$CANDIDATE_ID" --idempotency-key accept-001
```

If no outcome is being accepted, safe release is a separate command and requires trusted attempt-host observation:

```sh
.venv/bin/todo --root /path/to/project --token-file "$ATTEMPT_TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  finish --attempt "$ATTEMPT_ID" --lease "$LEASE_ID" --idempotency-key finish-001
```

`evaluated_not_promoted` and `no_change` are separate dispositions, allowed only by authored policy and supported evidence. Use a provider factory on each provider-backed invocation, including dispatch, verify, report, accept/reject, finish, and recovery operations; the CLI loads no provider composition implicitly. A failed correctness check or provider error is not a scientific negative result. Acceptance rechecks evidence and source applicability. Acceptance finalizes the attempt. `finish --attempt ... --lease ...` is a safe release for work with no accepted outcome; it is not a follow-up after acceptance.

Without trusted host/source/verifier providers, provider-dependent commands return an unavailable error and do not manufacture evidence. Local Git support is an explicit provider profile, not an automatic project behavior.

## External execution and resource permits

Command execution and resource permits are Python API integrations through explicitly configured trusted providers; they are not automatic CLI behavior. See [the provider contract guide](../architecture/external-providers.md) for exact operations and receipts. Resource providers own physical capacity and scheduling. Todo records permit state and fails closed when a provider is unavailable or a release is unresolved; it does not allocate GPUs or manage hardware.

## Read, backup, and explicit restore

The sanitized read model and the full SQLite backup serve different purposes. The read model includes authored plan meaning and canonical declaration facts, but omits authentication verifier/token digests, message/finding bodies, and provider request/receipt payloads. Authored domain text is retained; the read model is not a universal secret scanner.

A backup is a private point-in-time SQLite artifact and contains authentication state (password hashes and token digests). Keep it encrypted and access-controlled. It does not prove later credential revocation or external evidence freshness.

```sh
.venv/bin/todo --root /path/to/project --token-file "$TOKEN" \
  read --format json --output /tmp/read-model.json

.venv/bin/todo --root /path/to/project --token-file "$TOKEN" \
  export backup /secure/backups/project.sqlite \
  --expected-revision 42 --manifest-output /secure/backups/project.manifest.json
```

Restore is explicit, validates artifact integrity, database identity, schema and expected revision, and publishes only to a missing destination. It never replaces an existing path. CLI restore writes a verified database file only; it does not create project metadata or grant a writable session. The Python `TodoApplication.restore_backup(...)` API returns a read-only authority for inspection. Resuming writes from restored credentials is outside this operator procedure:

```sh
.venv/bin/todo export restore /secure/backups/project.sqlite \
  /secure/restore/project-authority.sqlite3 \
  --manifest /secure/backups/project.manifest.json \
  --project-id project-id --authority-id authority-id --expected-revision 42
```

After restore, authentication matches backup time. Check current credential status separately before authorizing further writes.

## Interrupted work and recovery

Inspection is read-only. It reports the exact attempt or external operation, trusted observations, blockers, and currently offered intents. It does not reconcile or retry effects.

```sh
.venv/bin/todo --root /path/to/project --token-file "$RECOVERY_TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  recovery inspect --attempt "$ATTEMPT_ID" --intent-output /tmp/recovery-intent.json

# Review the exact versioned intent file, then apply it under a current grant.
.venv/bin/todo --root /path/to/project --token-file "$RECOVERY_TOKEN" \
  --provider-factory trusted_install.providers:for_project \
  recovery apply --intent /tmp/recovery-intent.json --idempotency-key recovery-001
```

A recovery grant needs both inspect and apply authority on the exact target/context. Application rechecks the intent, expected state, and fresh provider evidence. Unknown/live writers, dirty or changed source, active children, pending candidates, and ambiguous effects stay blocked unless an exact supported handoff/reconcile intent is available. Dirty handoff preserves workspace bytes; it does not clean, reset, merge, or accept work.

## Schema compatibility and support boundary

Schema v21 is current. `migrate()` upgrades only an exact, identity-checked schema-v20 authority; opening never migrates automatically. V1–v19 remain unsupported, and there is no downgrade path. Use temporary authorities for migration qualification, never a production or Project Control authority.

The standalone CLI reports version 0.2.0. The latest source qualification runtime was Python 3.13.11. The CLI, API, source suite, and injected temporary providers have fixture-level evidence. There is no qualification claim for arbitrary host supervisors, production Git topology, real command executors, hardware/resource runtimes, power loss, or network filesystems. Project Control integration has been implemented in an isolated source snapshot and qualified with fixture and import rehearsal evidence; production deployment and live cutover remain pending. See the operator status and rollback notes before any deployment action.
