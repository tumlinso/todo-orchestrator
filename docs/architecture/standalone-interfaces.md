# Standalone application and CLI interfaces

## Public application boundary

`todo_orchestrator.api` is the supported Python entry point for a local
standalone authority. `TodoApplication.initialize(...)` explicitly creates a
new project authority and returns an owner session; `open(...)` opens an
existing authority with a bearer; `login_owner(...)` separately authenticates
the local owner and issues a session. Opening and reading do not create,
repair, migrate, or restore missing state. Session methods cover plan preview
and commit, run scheduling, dispatch, verification, candidate reporting and
acceptance, safe release, recovery, lifecycle, and export. Their versioned
DTOs have bounded serializers; bearer material is excluded from those
serializations and is available only in the active session or an explicit
private token file.

Provider ports are explicit trusted dependencies. `ProviderComposition()` is
empty by default; a workflow action that needs a host, source, verifier,
declaration, or Git observation fails as unavailable when that port is absent.
`ProviderComposition.local_git(...)` is an explicit profile builder that
requires a caller-selected repository and base/integration refs, plus host
observers for process and child safety. Missing process evidence remains
unknown. The application does not infer provider configuration or evidence
from a plan, the repository metadata, or a local checkout.

## CLI contract

The `todo` executable is also available as `python -m todo_orchestrator`. Global
`--root` chooses the project; `--token-file` or `TODO_BEARER_TOKEN` supplies a
bearer. Owner authentication uses a private credential file,
`TODO_OWNER_CREDENTIAL`, or an interactive prompt. No credential is accepted
as a normal password command-line argument. `init`, owner login, and dispatch
reserve an exclusive mode-0600 token destination before their state transition;
they never overwrite a token file. If state mutation succeeds but token
delivery fails, the CLI reports that state may have changed and gives an
operation-specific recovery instruction instead of suggesting a blind retry.

CLI plan preview is read-only and emits a bounded versioned review document.
Plan commit requires the exact saved preview and its revision preconditions.
The quickstart in [the command guide](../../references/command-guide.md) and
[its JSON plan](../../references/quickstart-plan.json) demonstrate that a
top-level `dependencies` group blocks `review` on `write` completion;
`requirement_groups` are item-owned checks and prerequisites, not cross-item
ordering. Candidate reporting is separate from accepting a result. `finish`
releases work without accepting an outcome.

Provider-backed commands are unavailable by default. The CLI supports an
explicit installed factory selected with
`--provider-factory package.module:callable`; it passes the resolved project
root and validated metadata and requires a `ProviderComposition` result. This
is executable trusted configuration. The CLI refuses to discover modules from
the selected project tree and never loads provider configuration from authored
plan data. A factory can exercise only the trusted providers it returns.

`read` / `export read-model` return a sanitized projection. `export backup`
creates a private full SQLite backup and a separate manifest; `export restore`
requires an explicit manifest, identity, and revision, and only publishes to a
missing destination. A backup retains point-in-time authentication records and
cannot establish later token revocation or external source freshness.

## I01 qualification record

The accepted I01 interface change is commit `56257a7` (`feat: add recovery,
lifecycle, export, and standalone interfaces`), accepted at development
authority revision 184 after required gate 183. Its recorded source checks were
408/408 in 149.960 seconds. The corresponding qualified source manifest is
`/tmp/todo-orchestrator-i01-qualified-source-manifest.json`: it names 141 files
and carries embedded SHA-256
`360d54ed340075d29b99e23645a6f53a64ad3c88a9b5590da3e6a97c36d5d873`. The
manifest is an external evidence artifact rather than a repository file; the
digest above is the manifest's embedded source-set digest.

The independently exercised public CLI/native-Git path is in
[`tests/api/test_provider_cli_independent.py`](../../tests/api/test_provider_cli_independent.py).
It uses a disposable Git repository, an explicitly selected trusted provider
factory, a temporary authority, and mode-0600 bearer files to run plan
preview/commit, workspace setup, dispatch, candidate report, separate accept,
safe finish, and sanitized read. It does not establish suitability for a
production repository or external host. The no-provider CLI path remains a
safe stop: provider-dependent dispatch reports the missing trusted port and
does not advance authority revision. The skill and CLI tests cover this
unavailable behavior; they do not manufacture a stopped-process or verifier
result.

This qualification is bounded to the accepted I01 public interface and its
disposable tests. It is not full release qualification, does not qualify every
provider implementation or host environment, and does not authorize changes
to Project Control, the preserved original implementation, or any production
authority.
