# Command guide

This guide documents the standalone `todo` interface. The executable help is the
source for available subcommands. Global `--root`, `--token-file`, and optional
`--provider-factory` options go before the subcommand. Examples assume the
current directory is the project root.

## Safe use

- Use `todo --help` and the relevant subcommand help before constructing a command.
- Use a credential file with restrictive permissions or the supported environment
  variable for bearer credentials. Do not put passwords or bearer tokens in normal
  command-line arguments, shell history, task notes, or logs.
- `todo init` is explicit and refuses an existing authority or metadata file. It
  needs project and repository IDs and writes the newly issued owner bearer only
  to a new token path. `todo auth login` issues a new owner session for an existing
  authority; it does not initialize one.
- Pass plan documents by file path. Review the preview digest, preconditions,
  conflicts, and diagnostics before committing.
- Use disposable workspaces and SQLite databases for examples and tests. Never
  point setup or restore examples at an existing authority without explicit intent.

## Common commands

Initialize a new authority and keep the token outside the repository:

```sh
todo --root /path/to/project init \
  --project-id project-example --repository-id repository-example \
  --owner-credential-file /secure/path/owner-credential \
  --token-output /secure/path/todo-owner.token
```

Preview and then commit the exact preview:

```sh
todo --root /path/to/project --token-file /secure/path/todo-owner.token \
  plan preview planning/plan.json --output /tmp/plan-preview.json
todo --root /path/to/project --token-file /secure/path/todo-owner.token \
  plan commit planning/plan.json --preview /tmp/plan-preview.json \
  --idempotency-key plan-2026-10-19
```

### Express a prerequisite

The [quickstart plan](quickstart-plan.json) is a complete two-task example. It
uses the top-level `dependencies` array to say that `review` waits for `write`:

```json
"dependencies": [{
  "source": {"project_id": "example-project", "kind": "work_item", "entity_id": "review"},
  "mode": "all",
  "members": [{
    "relation": "completion",
    "target": {"project_id": "example-project", "kind": "work_item", "entity_id": "write"}
  }]
}]
```

`source` is the work item being blocked; `target` is the work item whose
completion it requires. A work item's `requirement_groups` serve a different
purpose: they group that item's own check and prerequisite requirements. They do
not express cross-item completion ordering. The example can be compiled and
committed in a disposable project whose IDs match its `project` object:

```sh
todo --root /tmp/todo-quickstart init \
  --project-id example-project --repository-id example-repository \
  --authority-id example-authority --token-output /tmp/todo-quickstart.token
todo --root /tmp/todo-quickstart --token-file /tmp/todo-quickstart.token \
  plan preview references/quickstart-plan.json --output /tmp/quickstart-preview.json
todo --root /tmp/todo-quickstart --token-file /tmp/todo-quickstart.token \
  plan commit references/quickstart-plan.json --preview /tmp/quickstart-preview.json \
  --idempotency-key quickstart-initial-plan
```

Read a sanitized projection or create an explicit full backup:

```sh
todo --root /path/to/project --token-file /secure/path/todo-owner.token \
  export read-model --output /tmp/todo-read-model.json
todo --root /path/to/project --token-file /secure/path/todo-owner.token \
  export backup /secure/backups/todo.sqlite \
  --expected-revision 12 --manifest-output /secure/backups/todo.manifest.json
```

The default CLI profile does not invent Git refs or host observations. Dispatch,
verification, and other provider-backed operations require trusted provider
composition; without it, the operation reports a typed unavailable condition.
The CLI never discovers provider code from project metadata, plans, or the
selected project directory. An operator may explicitly select an installed
trusted factory with `--provider-factory package.module:factory`. The factory is
called with the resolved project root and validated project metadata and must
return `ProviderComposition`. Treat this as executable trusted configuration:
the factory can perform the operations allowed by the providers it returns.
Use the same explicit base and integration refs that the provider configuration
requires; the CLI does not infer them from a checkout.

### Command checks and resource permits

An authored `command` verification check is run through the normal `todo verify`
workflow only when `ProviderComposition` includes a command execution provider
and identity plus a source observer and identity. The accepted contract supplies
a tool ID, argument vector, working directory, timeout, and allowed exit codes.
The host-controlled provider
decides how to interpret the tool ID. Todo does not execute a shell string or
store raw process output; provider receipts and output digests flow through the
usual verification and acceptance checks. A successful command check does not
accept the work item.

Resource permits currently have a Python API, not CLI subcommands. Configure
`resource_permit_provider` and its identity in `ProviderComposition`, then call
the session methods with the exact attempt and idempotency key:

```python
from todo_orchestrator.contracts import StableId

permit = session.reserve_resource(
    attempt_ref, "cpu-slot", 1, idempotency_key=StableId("reserve-cpu-slot")
)
current = session.inspect_resource(permit.operation_id)  # read-only
```

The external provider owns the physical permit and capacity. Todo stores the
durable request, provider identity, receipt, state, and a digest of the opaque
permit reference. If the operation becomes unknown, inspect and reconcile it;
the service retries a reservation only after a fresh observation proves that
the same request is absent, or retries a release only while the same permit is
still held. Expiry alone does not release the permit. Unresolved permit
operations block attempt release and outcome reporting/acceptance. See
[external execution and resource permits](../docs/architecture/external-providers.md)
for the complete method set and failure states.

The current CLI exposes these command shapes:

```text
todo init --project-id ID --repository-id ID --token-output PATH
todo --provider-factory trusted_setup.providers:for_project ...
todo auth login --token-output PATH
todo plan preview PACKAGE [--output PATH]
todo plan commit PACKAGE --preview FILE --idempotency-key KEY
todo dispatch --work-item ID --workspace-id ID --idempotency-key KEY --token-output PATH
todo verify --attempt ID --requirement ID --idempotency-key KEY
todo report --attempt ID --disposition completed|evaluated_not_promoted|no_change --idempotency-key KEY
todo accept|reject --attempt ID --candidate ID --idempotency-key KEY
todo finish --attempt ID --lease ID --idempotency-key KEY
todo recovery inspect (--attempt ID | --operation ID) [--intent-output FILE] [--intent-index N]
todo recovery apply --intent FILE --idempotency-key KEY
todo export read-model [--format json|markdown]
todo export backup DEST --expected-revision N --manifest-output FILE
todo export restore SOURCE DEST --manifest FILE --project-id ID --authority-id ID --expected-revision N
```

## Workflow boundaries

Plan preview is read-only. Plan commit requires the exact reviewed digest and
expected authority and plan revision. A reported candidate is not accepted work;
acceptance has its own authorization and evidence checks. Recovery inspection is
read-only; applying a recovery intent is a separate revision-checked command.

When inspection offers recovery intents, save the exact reviewed intent without
editing it and apply that file separately:

```sh
todo --root /path/to/project --token-file /secure/path/todo-owner.token \
  recovery inspect --attempt attempt-id --intent-output /tmp/recovery-intent.json
todo --root /path/to/project --token-file /secure/path/todo-owner.token \
  recovery apply --intent /tmp/recovery-intent.json --idempotency-key recovery-2026-10-19
```

The inspection JSON contains the complete read-only view. `--intent-index` selects
an offered intent by its zero-based position when more than one is available.
Intent output is a separate versioned file and is never silently refreshed before
application; stale intent preconditions fail closed.

Authority read models are sanitized semantic projections. A private SQLite backup
contains authentication state from its point in time. Restore requires a trusted
manifest and exact expected identity and revision, and it refuses to replace an
existing path. See [export and restore](../docs/architecture/export-and-restore.md)
for the storage and integrity boundaries.
