#!/usr/bin/env python3
"""Validate the Todo source baseline; external checkouts are optional/read-only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

DECISIONS = {"retain", "adapt", "isolate", "exclude", "retire"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs/product/reference-baseline.json"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate(manifest: dict) -> None:
    _require(manifest.get("schema_version") == 1, "unsupported schema_version")
    sources = manifest.get("sources")
    _require(isinstance(sources, list) and len(sources) >= 2, "need both source checkouts")
    for source in sources:
        for key in ("name", "root", "git_root", "relative_prefix", "revision", "branch"):
            _require(bool(source.get(key)), f"source missing {key}")
        _require(source["full_status_before"] == source["full_status_after"], "full checkout status changed")
        _require(not source["todo_scoped_status_before"] and not source["todo_scoped_status_after"], "Todo paths were not clean")
        hashes = source.get("hashes", [])
        _require(bool(hashes), "source has no preservation hashes")
        for item in hashes:
            _require(bool(item.get("path")), "source hash has no path")
            _require(SHA256.fullmatch(item.get("sha256_before", "")) is not None, "invalid before hash")
            _require(item.get("sha256_before") == item.get("sha256_after"), "source hash changed during baseline capture")
    inventory = manifest.get("inventory")
    _require(isinstance(inventory, list) and len(inventory) >= 10, "capability inventory is incomplete")
    _require(len({row.get("id") for row in inventory}) == len(inventory), "duplicate capability id")
    for row in inventory:
        _require(all(row.get(key) for key in ("id", "capability", "source_refs", "tests", "treatment", "observation")), "incomplete capability row")
        _require(set(row["treatment"]) <= DECISIONS and bool(row["treatment"]), "invalid treatment decision")
    fixtures = manifest.get("fixtures")
    _require(isinstance(fixtures, list) and len(fixtures) >= 8, "fixture descriptions are incomplete")
    _require(len({fixture.get("id") for fixture in fixtures}) == len(fixtures), "duplicate fixture id")
    for fixture in fixtures:
        _require(all(fixture.get(key) for key in ("id", "setup", "actions", "assertions")), "incomplete fixture description")
    test_hashes = manifest.get("test_fingerprints", [])
    _require(len(test_hashes) >= 8, "test corpus fingerprints are incomplete")
    for item in test_hashes:
        _require(bool(item.get("path")) and SHA256.fullmatch(item.get("sha256_before", "")) is not None, "invalid test fingerprint")
        _require(item.get("sha256_before") == item.get("sha256_after"), "test fingerprint changed during baseline capture")
    _require(bool(manifest.get("evidence_limits")), "evidence limits are required")


def verify_external(source: dict, check_git: bool = True) -> list[str]:
    """Read-only verification of one captured checkout and its selected files."""
    root = Path(source["root"])
    git_root = Path(source["git_root"])
    problems = []
    if not root.is_dir() or not git_root.is_dir():
        return [f"missing checkout: {root}"]
    if check_git:
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
        head = subprocess.run(["git", "-C", str(git_root), "rev-parse", "HEAD"], capture_output=True, text=True, env=env)
        if head.returncode or head.stdout.strip() != source["revision"]:
            problems.append(f"revision differs: {git_root}")
        paths = source.get("verification_paths", [source["relative_prefix"]])
        status = subprocess.run(["git", "-C", str(git_root), "status", "--short", "--untracked-files=all", "--", *paths], capture_output=True, text=True, env=env)
        if status.returncode or status.stdout.strip():
            problems.append(f"Todo paths are dirty or status failed: {git_root}")
    for item in source["hashes"]:
        path = root / item["path"]
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            actual = "missing"
        if actual != item["sha256_after"]:
            problems.append(f"hash differs: {path}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--verify-external", action="store_true", help="read-only check of captured external checkouts")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text())
        validate(manifest)
        if args.verify_external:
            problems = [problem for source in manifest["sources"] for problem in verify_external(source)]
            if problems:
                raise ValueError("; ".join(problems))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"reference baseline: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"reference baseline: OK ({len(manifest['inventory'])} capabilities, {len(manifest['fixtures'])} fixture descriptions)")
    if args.verify_external:
        print("external source fingerprints and clean Todo paths: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
