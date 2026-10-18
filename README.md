# Todo Orchestrator

Todo Orchestrator is being prepared as a standalone, independently usable workflow engine. The redesign will draw on the existing implementation while progressively copying and adapting functionality and preserving the original implementation throughout.

Development has begun from the preserved bootstrap package. The Python library provides an authenticated SQLite authority, guarded plan revisions, shared admission and run/attempt coordination, durable verification, provenance-preserving outcome acceptance, native Git workspace/integration effects, scoped coordination messages, and authorized declaration facts. Messaging and declaration synchronization were accepted at development authority revision 131; bounded worker context was accepted at revision 136. Subordinate execution, recovery tooling, the complete workflow CLI, and release qualification remain under development.

- Repository: [tumlinso/todo-orchestrator](https://github.com/tumlinso/todo-orchestrator)
- Project Control workspace and repository ID: `todo-orchestrator`.
- Project identity and workflow configuration: `.todo-orchestrator/project.json`.
- Codex guidance: [AGENTS.md](AGENTS.md). Future planning material: [planning/](planning/).

The [standalone development plan](planning/standalone-v1/README.md) tracks 32 deliverables. Project Control integration, cutover, and optional legacy import are excluded. The active Project Control instance, its other tools, the original implementation, and legacy authorities stay unchanged. Only this repository's development Todo authority is used for task tracking; its tracked snapshots and Markdown task files are generated projections.

See the [source baseline](docs/product/reference-baseline.md), [domain model](docs/architecture/domain-model.md), [provider boundary](docs/architecture/provider-contracts.md), [worker context](docs/architecture/worker-context.md), and [SQLite policy](src/todo_orchestrator/authority/README.md). Follow `.editorconfig`, keep changes scoped, and run `git diff --check` before review.

Python 3.11+ is required; there are no runtime dependencies. The initial `todo` CLI provides help and version only. Run it from source without importing a preinstalled legacy Todo package:

```sh
PYTHONPATH=src python -S -m todo_orchestrator --help
PYTHONPATH=src python -S -m todo_orchestrator --version
```

Run the checks:

```sh
python scripts/check_reference_baseline.py
python -S -m unittest discover -s tests/reference -v
PYTHONPATH=src python -S -m unittest discover -s tests/contracts -v
PYTHONPATH=src python -S -m unittest discover -s tests/authority -v
PYTHONPATH=src python -S -m unittest discover -s tests/planning -v
PYTHONPATH=src python -S -m unittest discover -s tests/package -t tests -v
PYTHONPATH=src python -S -m unittest discover -s tests/smoke -t tests -v
```

Package tests require locally installed pip and setuptools 68+ for an offline wheel build. They build and install only into temporary directories, then verify the installed module paths with site packages disabled. SQLite and Git smoke fixtures also use temporary directories; Git must be available to run its fixture test. For an editable development installation, use a fresh repository-local virtual environment; never install into the active Project Control runtime.

SQLite initialization currently requires a POSIX filesystem supporting hard links and directory synchronization. Schema v18 is the only supported version; reopening accepts v18, while the migration entry point rejects unsupported versions without rewriting them. There is no migration path for v1-v17. Runtime tests use disposable databases, never this repository's development Todo authority.

The optional `python scripts/check_reference_baseline.py --verify-external` checks the captured original source/test fingerprints read-only. These checks cover baseline integrity, value contracts, package isolation, and storage behavior. They do not qualify a complete workflow runtime or power-loss recovery.
