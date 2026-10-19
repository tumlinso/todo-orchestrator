# Todo Orchestrator

Todo Orchestrator is a standalone, local-first workflow engine for versioned plans, safely admitted work, evidence-backed outcomes, and non-destructive recovery. Its SQLite authority is the semantic source of truth; reads do not create, repair, migrate, or restore state.

Todo Orchestrator **0.2.0 alpha** adds explicit legacy-state import, linked historical records, and public host/session and coordination interfaces. The prior standalone 0.1.0 release passed 427 fixture tests; qualification of this continuation is tracked separately in [the cutover plan](planning/cutover-v1/README.md).

Project Control hosts the independently installed engine through its public API. It retains workspace registration, client authorization, source tools, process supervision, and physical resource ownership. The engine itself has no Project Control dependency. Original implementations and authorities are preserved for history and rollback.

## Quick start

For standalone development, use a fresh environment. Python 3.11+ is required; the package has no runtime dependencies. Build tooling must provide setuptools 68+. Project Control installs its explicitly pinned wheel into a separate host environment.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/todo --help
```

Initialize a new project explicitly. Keep the bearer file outside the repository; the CLI reserves a new mode-0600 file and never overwrites one. If no credential file is supplied, the CLI prompts for the owner credential without echoing it.

```sh
umask 077
mkdir -p "$HOME/.local/share/todo-orchestrator"
.venv/bin/todo --root /path/to/new-project init \
  --project-id example-project --repository-id example-repository \
  --authority-id example-authority \
  --token-output "$HOME/.local/share/todo-orchestrator/example.token"
```

Preview then commit a plan using the exact saved review. From the repository root, `references/quickstart-plan.json` is a complete two-work-item example whose `review` item depends on `write`.

```sh
.venv/bin/todo --root /path/to/new-project \
  --token-file "$HOME/.local/share/todo-orchestrator/example.token" \
  plan preview references/quickstart-plan.json --output /tmp/plan-preview.json

.venv/bin/todo --root /path/to/new-project \
  --token-file "$HOME/.local/share/todo-orchestrator/example.token" \
  plan commit references/quickstart-plan.json --preview /tmp/plan-preview.json \
  --idempotency-key quickstart-initial-plan
```

Plan commit uses the preview's expected authority and plan revisions. Omitted plan records are preserved; deletion requires an explicit reviewed retirement.

## Working safely

Dispatch, verification, Git effects, and recovery that needs host observations require trusted providers. The default provider composition is empty and fails closed. A caller may pass a `ProviderComposition` through the Python API or explicitly select an installed `--provider-factory package.module:callable`. A factory is trusted executable code: do not load one from a plan or project directory, and configure its repository and refs deliberately. No provider means no fabricated “stopped”, “clean”, or “passed” evidence.

The main command flow is `dispatch` → `verify` (when required) → `report` → separately authorized `accept`. `finish` safely releases an attempt without accepting an outcome; acceptance itself finalizes and revokes the attempt. Inspect recovery first and apply only the exact current intent it returns.

See [the operator guide](docs/operations/operator-guide.md) for credentials, provider setup, backups, restore, recovery, and schema limits. See the [release evidence matrix](docs/qualification/release.md) and [source pin](docs/qualification/release-source-pin.json) for qualification evidence and boundaries.

## Storage and compatibility

Each project has a local `.todo-orchestrator/authority.sqlite3`. Schema v21 supports an explicit upgrade from the released native v20 schema. Older development schemas remain unsupported. Legacy Project Control authorities use a separate previewed import into a fresh native authority; they are never upgraded in place. Imported completion assertions retain legacy provenance and do not become native verification outcomes. Backup/restore is explicit and restore refuses an existing destination. SQLite initialization currently requires a POSIX filesystem with hard-link and directory-sync support.

Do not edit authority SQLite files or generated task projections by hand. Tests and examples use temporary projects. Production changes require explicit operator direction; the authorized all-workspace replacement is recorded in the cutover plan.
