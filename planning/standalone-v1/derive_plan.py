#!/usr/bin/env python3
"""Derive the standalone Todo plan from the preserved bootstrap package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "planning/todo-orchestrator-bootstrap-v1/machine/todo-orchestrator.todo-plan.json"
OUTPUT = Path(__file__).with_name("todo-orchestrator-standalone-v1.todo-plan.json")
EXCLUDED = {"TO-I02", "TO-I03", "TO-P05", "TO-Q04"}


def derive() -> dict:
    plan = json.loads(SOURCE.read_text())
    task_by_id = {task["id"]: task for task in plan["tasks"]}

    plan["tasks"] = [task for task in plan["tasks"] if task["id"] not in EXCLUDED]
    task_by_id = {task["id"]: task for task in plan["tasks"]}

    for task in plan["tasks"]:
        task["depends_on"] = [
            dependency
            for dependency in task.get("depends_on", [])
            if dependency.get("task_id") not in EXCLUDED
        ]
        task["parallel_policy"] = "serial"
        for paths_key in ("exclusive_paths", "forbidden_paths", "read_paths"):
            task.get("scope", {})[paths_key] = [
                path.replace("src/todo/", "src/todo_orchestrator/")
                for path in task.get("scope", {}).get(paths_key, [])
            ]

    # Assign the first foundation outcomes to distinct, reviewable artifacts.
    task_by_id["TO-F01"]["scope"]["exclusive_paths"] = [
        "docs/product",
        "docs/architecture",
        "tests/reference",
        "scripts/check_reference_baseline.py",
    ]
    task_by_id["TO-F02"]["scope"]["exclusive_paths"] = [
        "docs/product",
        "docs/architecture",
        "src/todo_orchestrator/contracts",
        "tests/contracts",
    ]
    task_by_id["TO-F03"]["scope"]["exclusive_paths"] = [
        "src/todo_orchestrator",
        "tests/package",
        "tests/smoke",
        "pyproject.toml",
        "README.md",
        "AGENTS.md",
    ]

    task_by_id["TO-FOUNDATION"]["objective"] = (
        "Define the standalone product, baseline semantics, and trust boundaries before changing source."
    )
    task_by_id["TO-INTEGRATION"]["title"] = "Standalone interfaces and provider contracts"
    task_by_id["TO-INTEGRATION"]["objective"] = (
        "Expose independently usable Python, CLI, and skill interfaces with trusted provider contracts."
    )
    task_by_id["TO-QUALIFICATION"]["title"] = "Standalone qualification and release"
    task_by_id["TO-QUALIFICATION"]["objective"] = (
        "Prove standalone safety, compatibility, packaging, recovery, and release readiness."
    )

    task_by_id["TO-F01"]["objective"] = (
        "Read the original Todo implementation as reference material. Identify observable invariants, "
        "Todo contracts, tests, and historical compatibility layers. Record which behavior is "
        "product-essential and which is incidental or obsolete."
    )
    task_by_id["TO-F01"]["motivation"] = task_by_id["TO-F01"]["objective"]
    task_by_id["TO-F04"]["scope"]["exclusive_paths"] = [
        "docs/architecture",
        "src/todo_orchestrator/contracts",
        "tests/contracts",
    ]
    task_by_id["TO-F04"]["objective"] = (
        "Define standalone trust and provider interfaces for identity/authorization, repository/source "
        "observation, Git workspace effects, process execution, resource reservations, and evidence receipts."
    )
    task_by_id["TO-F04"]["motivation"] = task_by_id["TO-F04"]["objective"]

    task_by_id["TO-I01"]["scope"]["exclusive_paths"] = [
        "src/todo_orchestrator/api",
        "src/todo_orchestrator/providers/execution",
        "src/todo_orchestrator/providers/resources",
        "SKILL.md",
        "references",
    ]
    task_by_id["TO-I04"]["depends_on"] = [
        {"task_id": "TO-I01", "type": "task"},
        {"task_id": "TO-V02", "type": "task"},
    ]
    task_by_id["TO-I04"]["title"] = "Define standalone external execution and resource providers"
    task_by_id["TO-I04"]["objective"] = (
        "Define how standalone Todo requests externally owned resource permits and execution receipts. "
        "Keep background worker supervision and CUDA-specific paths outside the canonical engine."
    )
    task_by_id["TO-I04"]["motivation"] = task_by_id["TO-I04"]["objective"]

    task_by_id["TO-Q01"]["objective"] = (
        "Build disposable fixtures from the old Todo implementation for plans, claim contention, "
        "delegation, gates, integration, dirty recovery, and semantics. Classify intentional behavior changes."
    )
    task_by_id["TO-Q01"]["motivation"] = task_by_id["TO-Q01"]["objective"]
    task_by_id["TO-Q05"]["title"] = "Deliver standalone release and operator documentation"
    task_by_id["TO-Q05"]["objective"] = (
        "Complete standalone README, API/CLI/skill reference, schema and backup/restore docs, "
        "operational guide, release/source pin, and qualification evidence."
    )
    task_by_id["TO-Q05"]["motivation"] = task_by_id["TO-Q05"]["objective"]
    task_by_id["TO-Q05"]["scope"]["exclusive_paths"] = [
        "README.md",
        "docs/qualification",
        "docs/operations",
        "SKILL.md",
        "references",
        "tests/system",
        "tests/qualification",
    ]
    task_by_id["TO-Q05"]["depends_on"] = [
        {"task_id": "TO-I04", "type": "task"},
        {"task_id": "TO-Q02", "type": "task"},
        {"task_id": "TO-Q03", "type": "task"},
    ]
    task_by_id["TO-Q05"]["completion_contract"]["assertions"] = [
        "End-to-end scenario runs on a disposable project and produces inspectable receipts.",
        "Package/version identity independent of host installation layout is tested.",
        "Release gate documents unsupported providers and remaining risks.",
    ]

    task_by_id["TO-ROOT"]["title"] = "Deliver standalone todo-orchestrator v1"
    task_by_id["TO-ROOT"]["objective"] = (
        "Deliver an independently usable, transactional workflow and planning engine for Todo Orchestrator."
    )
    task_by_id["TO-ROOT"]["completion_contract"]["assertions"] = [
        "Every workstream has been formally qualified and closed.",
        "No legacy or production authority was mutated or converted; development tracking used only this repository's Todo authority through supported APIs.",
        "Release identity, backup/restore, and operator documentation are complete.",
    ]

    run = plan["runs"][0]
    run["charter"]["objective"] = (
        "Build todo-orchestrator as an independently usable, trustworthy planning and workflow authority."
    )
    run["charter"]["acceptance_conditions"] = [
        "Plan compiler and guarded revisions",
        "Single admission policy and durable attempts",
        "Source-bound evidence and safe external effects",
        "Explicit recovery and opt-in backup/restore interfaces",
        "Standalone CLI, Python, skill, and provider interfaces",
    ]
    run["charter"]["boundaries"] = [
        "Use this repository's standalone Todo authority for development tracking through its supported API. Do not mutate legacy or production Todo authorities.",
        "Copy and adapt original Todo code incrementally into this repository while preserving the original implementation.",
        "Project Control integration, reconfiguration, service changes, and cutover are outside this plan.",
        "No GPU interlocks, model inference, background worker supervision, or source intelligence inside Todo.",
        "Qualify behavior parity before intentionally changing contract semantics.",
    ]
    run["charter"]["implementation_notes"] = (
        "Tasks are outcome-sized; implementing agent chooses detailed substeps. Keep execution serial "
        "until source isolation is qualified; do not fan out across a shared checkout."
    )
    for lane in run.get("lanes", []):
        lane["tasks"] = [task_id for task_id in lane["tasks"] if task_id not in EXCLUDED]

    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the derived plan is stale")
    args = parser.parse_args()
    rendered = json.dumps(derive(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != rendered:
            print(f"stale derived plan: {OUTPUT}")
            return 1
        print(f"derived plan is current: {OUTPUT}")
        return 0
    OUTPUT.write_text(rendered)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
