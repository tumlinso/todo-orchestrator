"""Shared validation and safety queries for durable child-execution rows."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from todo_orchestrator.contracts import StableId
from todo_orchestrator.model import AttemptScopeSnapshot

from .eligibility import EligibilityAdapterError, _scope_snapshot_payload


def decode_child_scope(encoded: object, digest: object) -> AttemptScopeSnapshot:
    if not isinstance(encoded, str) or not isinstance(digest, str):
        raise EligibilityAdapterError("stored child scope snapshot is not text")
    if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != digest:
        raise EligibilityAdapterError("stored child scope digest does not match")
    try:
        value = json.loads(encoded)
        if not isinstance(value, dict) or set(value) != {"locks", "paths"}:
            raise ValueError("unexpected snapshot fields")
        scope = AttemptScopeSnapshot(
            tuple(tuple(item) for item in value["paths"]),
            tuple(tuple(item) for item in value["locks"]),
        )
        if _scope_snapshot_payload(scope) != encoded:
            raise ValueError("scope snapshot encoding is not canonical")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EligibilityAdapterError(f"stored child scope snapshot is invalid: {exc}") from exc
    return scope


def parent_children_resolved(connection: sqlite3.Connection, parent_attempt_id: StableId) -> bool:
    """Whether every child is physically stopped and any candidate was reviewed."""
    row = connection.execute(
        "SELECT 1 FROM child_executions AS execution "
        "LEFT JOIN child_candidates AS candidate USING(execution_id) "
        "LEFT JOIN child_candidate_reviews AS review USING(candidate_id) "
        "WHERE execution.parent_attempt_id = ? AND (execution.state <> 'stopped' "
        "OR (candidate.candidate_id IS NOT NULL AND review.review_id IS NULL)) LIMIT 1",
        (str(parent_attempt_id),),
    ).fetchone()
    return row is None


def require_parent_children_resolved(connection: sqlite3.Connection, parent_attempt_id: StableId) -> None:
    if not parent_children_resolved(connection, parent_attempt_id):
        raise ValueError("parent attempt has an unresolved child execution or candidate")


__all__ = ["decode_child_scope", "parent_children_resolved", "require_parent_children_resolved"]
