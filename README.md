# Todo Orchestrator

Todo Orchestrator is being prepared as a standalone, independently usable workflow engine. The redesign will draw on the existing implementation while progressively copying and adapting functionality and preserving the original implementation throughout.

This repository currently contains only development scaffolding. The comprehensive bootstrap package is expected before implementation or architectural planning begins.

- Repository: [tumlinso/todo-orchestrator](https://github.com/tumlinso/todo-orchestrator)
- Project Control workspace and repository ID: `todo-orchestrator`.
- Project identity and workflow configuration: `.todo-orchestrator/project.json`.
- Codex guidance: [AGENTS.md](AGENTS.md). Future planning material: [planning/](planning/).

Use Project Control for task workflow. Todo's SQLite database in Git metadata is the live authority; tracked snapshots and Markdown task files are generated projections. No tasks are defined yet.

Follow `.editorconfig`, keep changes scoped, and run `git diff --check` before review. Build tooling, dependencies, tests, packaging, and licensing will be established with the bootstrap package; no implementation environment is required for this scaffold.
