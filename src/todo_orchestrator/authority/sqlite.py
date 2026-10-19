"""A small, explicit SQLite authority for one Todo Orchestrator project.

Opening a store never creates or migrates it. Initialization publishes a fully
created schema atomically, and migrations are an explicit operation. This
module owns SQLite connection and transaction mechanics only; semantic
commands, revision changes, receipts, and event payloads belong to later
authority services.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Iterator, Mapping

from todo_orchestrator.contracts import EntityKind, Project, StableId
from todo_orchestrator.contracts.verification import EvidenceRequirement, VerificationContract


APPLICATION_ID = 0x544F444F  # ASCII "TODO"
SCHEMA_VERSION = 20
DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0
MAX_BUSY_TIMEOUT_SECONDS = 60.0


class AuthorityError(RuntimeError):
    """Base class for authority open and initialization errors."""


class AuthorityNotFoundError(AuthorityError, FileNotFoundError):
    """The requested authority file does not exist."""


class AuthorityAlreadyExistsError(AuthorityError, FileExistsError):
    """Initialization cannot replace an existing file."""


class AuthorityPublicationDurabilityUncertainError(AuthorityError):
    """The authority was published, but its directory entry could not be synced."""


class UnsupportedAuthorityPlatformError(AuthorityError):
    """This platform cannot provide the POSIX directory-sync initialization contract."""


class AuthorityIdentityMismatchError(AuthorityError):
    """The file belongs to a different project or authority identity."""


class UnsupportedSchemaVersionError(AuthorityError):
    """The file's schema version is not supported by this package."""


class InvalidAuthorityError(AuthorityError):
    """The file is not a valid Todo Orchestrator authority."""


class ReadOnlyAuthorityError(AuthorityError):
    """A write transaction was requested from a read-only connection."""


@dataclass(frozen=True)
class MigrationResult:
    """Result of the explicit migration check supported by this version."""

    from_version: int
    to_version: int


@dataclass(frozen=True)
class DefinitionVersionRecord:
    """One immutable, complete work-definition bundle keyed by exact version."""

    definition_revision_id: StableId
    entity_id: StableId
    canonical_json: str
    content_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.definition_revision_id, StableId) or not isinstance(self.entity_id, StableId):
            raise TypeError("definition version identity fields must be StableId values")
        _validate_canonical_digest(self.canonical_json, self.content_digest, "work definition")


@dataclass(frozen=True)
class PlanWorkMembership:
    """An exact work-definition version selected by an accepted plan revision."""

    work_item_id: StableId
    definition_revision_id: StableId

    def __post_init__(self) -> None:
        if not isinstance(self.work_item_id, StableId) or not isinstance(self.definition_revision_id, StableId):
            raise TypeError("plan work membership fields must be StableId values")


@dataclass(frozen=True)
class PlanRevisionSnapshotRecord:
    """Canonical full accepted snapshot plus its exact mixed definition membership."""

    plan_revision_id: StableId
    canonical_json: str
    snapshot_digest: str
    definitions: tuple[DefinitionVersionRecord, ...]
    work_items: tuple[PlanWorkMembership, ...]
    sequence: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.plan_revision_id, StableId):
            raise TypeError("plan_revision_id must be a StableId")
        _validate_canonical_digest(self.canonical_json, self.snapshot_digest, "accepted plan snapshot")
        if not isinstance(self.definitions, tuple) or any(
            not isinstance(item, DefinitionVersionRecord) for item in self.definitions
        ):
            raise TypeError("definitions must be a tuple of DefinitionVersionRecord values")
        if not isinstance(self.work_items, tuple) or any(
            not isinstance(item, PlanWorkMembership) for item in self.work_items
        ):
            raise TypeError("work_items must be a tuple of PlanWorkMembership values")
        if self.sequence is not None and (type(self.sequence) is not int or self.sequence < 1):
            raise ValueError("sequence must be a positive integer when loaded from an authority")
        definition_keys = {(item.entity_id, item.definition_revision_id) for item in self.definitions}
        membership_keys = {(item.work_item_id, item.definition_revision_id) for item in self.work_items}
        if len(definition_keys) != len(self.definitions) or len(membership_keys) != len(self.work_items):
            raise ValueError("definition versions and plan work membership must be unique")
        if len({item.work_item_id for item in self.work_items}) != len(self.work_items):
            raise ValueError("a plan snapshot selects only one definition version per work item")
        if definition_keys != membership_keys:
            raise ValueError("snapshot definitions must exactly match its work-item membership")


def _canonical_json_object(encoded: str, name: str) -> dict[str, Any]:
    if not isinstance(encoded, str):
        raise TypeError(f"{name} canonical_json must be a string")
    try:
        value = json.loads(encoded, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError(f"{name} is not canonical UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict) or canonical != encoded:
        raise ValueError(f"{name} must be a canonical JSON object")
    return value


def _validate_canonical_digest(encoded: str, digest: str, name: str) -> None:
    _canonical_json_object(encoded, name)
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{name} content_digest must be lowercase SHA-256 hex")
    actual = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    if actual != digest:
        raise ValueError(f"{name} digest does not match its canonical JSON")


_SCHEMA_STATEMENTS = (
    """CREATE TABLE authority_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        project_id TEXT NOT NULL,
        authority_id TEXT NOT NULL,
        semantic_revision INTEGER NOT NULL DEFAULT 0 CHECK (semantic_revision >= 0),
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE plan_revisions (
        plan_revision_id TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL UNIQUE CHECK (sequence > 0),
        based_on_revision_id TEXT,
        state TEXT NOT NULL CHECK (state IN ('proposed', 'validated', 'accepted')),
        source TEXT,
        content_digest TEXT,
        producer TEXT,
        authored_by_actor_id TEXT,
        authored_by_incarnation_id TEXT,
        CHECK ((authored_by_actor_id IS NULL) = (authored_by_incarnation_id IS NULL)),
        CHECK (content_digest IS NULL OR (length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*')),
        FOREIGN KEY (based_on_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (authored_by_actor_id, authored_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE plan_revision_snapshots (
        plan_revision_id TEXT PRIMARY KEY,
        canonical_json TEXT NOT NULL,
        snapshot_digest TEXT NOT NULL CHECK (
            length(snapshot_digest) = 64 AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id)
    )""",
    """CREATE TABLE work_items (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        title TEXT NOT NULL,
        outcome TEXT NOT NULL,
        parent_work_item_id TEXT,
        parent_definition_revision_id TEXT,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL CHECK (
            length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
        ),
        PRIMARY KEY (work_item_id, definition_revision_id),
        CHECK ((parent_work_item_id IS NULL) = (parent_definition_revision_id IS NULL)),
        CHECK (parent_work_item_id IS NULL OR parent_work_item_id <> work_item_id
               OR parent_definition_revision_id <> definition_revision_id),
        FOREIGN KEY (parent_work_item_id, parent_definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE plan_revision_work_items (
        plan_revision_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        PRIMARY KEY (plan_revision_id, work_item_id),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE work_item_supersessions (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        superseded_work_item_id TEXT NOT NULL,
        superseded_definition_revision_id TEXT NOT NULL,
        PRIMARY KEY (work_item_id, definition_revision_id,
                     superseded_work_item_id, superseded_definition_revision_id),
        CHECK (work_item_id <> superseded_work_item_id
               OR definition_revision_id <> superseded_definition_revision_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (superseded_work_item_id, superseded_definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE requirements (
        requirement_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('prerequisite', 'check')),
        description TEXT NOT NULL,
        target_project_id TEXT,
        target_kind TEXT,
        target_entity_id TEXT,
        target_definition_revision_id TEXT,
        check_key TEXT,
        verification_json TEXT NOT NULL DEFAULT 'null',
        required_evidence_json TEXT NOT NULL DEFAULT '[]',
        PRIMARY KEY (requirement_id, definition_revision_id),
        UNIQUE (work_item_id, definition_revision_id, requirement_id),
        CHECK (
            (kind = 'prerequisite' AND target_project_id IS NOT NULL
             AND target_kind IS NOT NULL AND target_entity_id IS NOT NULL
             AND check_key IS NULL AND target_kind IN ('work_item', 'checkpoint', 'interface', 'barrier', 'decision')
             AND ((target_kind = 'work_item' AND target_definition_revision_id IS NOT NULL)
                  OR (target_kind <> 'work_item' AND target_definition_revision_id IS NULL)))
            OR
            (kind = 'check' AND target_project_id IS NULL AND target_kind IS NULL AND target_entity_id IS NULL
             AND target_definition_revision_id IS NULL AND check_key IS NOT NULL)
        ),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE requirement_groups (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        group_ordinal INTEGER NOT NULL CHECK (group_ordinal >= 0),
        kind TEXT NOT NULL CHECK (kind IN ('prerequisite', 'check')),
        mode TEXT NOT NULL CHECK (mode IN ('all', 'any', 'quorum')),
        quorum INTEGER,
        PRIMARY KEY (work_item_id, definition_revision_id, group_ordinal),
        CHECK ((mode = 'quorum' AND quorum IS NOT NULL AND quorum > 0)
               OR (mode <> 'quorum' AND quorum IS NULL)),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id)
    )""",
    """CREATE TABLE requirement_group_members (
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        group_ordinal INTEGER NOT NULL,
        member_ordinal INTEGER NOT NULL CHECK (member_ordinal >= 0),
        requirement_id TEXT NOT NULL,
        PRIMARY KEY (work_item_id, definition_revision_id, group_ordinal, member_ordinal),
        UNIQUE (work_item_id, definition_revision_id, group_ordinal, requirement_id),
        FOREIGN KEY (work_item_id, definition_revision_id, group_ordinal)
            REFERENCES requirement_groups(work_item_id, definition_revision_id, group_ordinal),
        FOREIGN KEY (work_item_id, definition_revision_id, requirement_id)
            REFERENCES requirements(work_item_id, definition_revision_id, requirement_id)
    )""",
    """CREATE TRIGGER plan_revision_snapshots_no_update
        BEFORE UPDATE ON plan_revision_snapshots
        BEGIN SELECT RAISE(ABORT, 'accepted plan snapshots are append-only'); END""",
    """CREATE TRIGGER plan_revision_snapshots_no_delete
        BEFORE DELETE ON plan_revision_snapshots
        BEGIN SELECT RAISE(ABORT, 'accepted plan snapshots are append-only'); END""",
    """CREATE TRIGGER work_items_no_update
        BEFORE UPDATE ON work_items
        BEGIN SELECT RAISE(ABORT, 'work-item definition versions are append-only'); END""",
    """CREATE TRIGGER work_items_no_delete
        BEFORE DELETE ON work_items
        BEGIN SELECT RAISE(ABORT, 'work-item definition versions are append-only'); END""",
    """CREATE TRIGGER plan_revision_work_items_no_update
        BEFORE UPDATE ON plan_revision_work_items
        BEGIN SELECT RAISE(ABORT, 'accepted plan membership is append-only'); END""",
    """CREATE TRIGGER plan_revision_work_items_no_delete
        BEFORE DELETE ON plan_revision_work_items
        BEGIN SELECT RAISE(ABORT, 'accepted plan membership is append-only'); END""",
    """CREATE TRIGGER work_item_supersessions_no_update
        BEFORE UPDATE ON work_item_supersessions
        BEGIN SELECT RAISE(ABORT, 'work-item supersessions are append-only'); END""",
    """CREATE TRIGGER work_item_supersessions_no_delete
        BEFORE DELETE ON work_item_supersessions
        BEGIN SELECT RAISE(ABORT, 'work-item supersessions are append-only'); END""",
    """CREATE TRIGGER requirements_no_update
        BEFORE UPDATE ON requirements
        BEGIN SELECT RAISE(ABORT, 'requirement definitions are append-only'); END""",
    """CREATE TRIGGER requirements_no_delete
        BEFORE DELETE ON requirements
        BEGIN SELECT RAISE(ABORT, 'requirement definitions are append-only'); END""",
    """CREATE TRIGGER requirement_groups_no_update
        BEFORE UPDATE ON requirement_groups
        BEGIN SELECT RAISE(ABORT, 'requirement groups are append-only'); END""",
    """CREATE TRIGGER requirement_groups_no_delete
        BEFORE DELETE ON requirement_groups
        BEGIN SELECT RAISE(ABORT, 'requirement groups are append-only'); END""",
    """CREATE TRIGGER requirement_group_members_no_update
        BEFORE UPDATE ON requirement_group_members
        BEGIN SELECT RAISE(ABORT, 'requirement group members are append-only'); END""",
    """CREATE TRIGGER requirement_group_members_no_delete
        BEFORE DELETE ON requirement_group_members
        BEGIN SELECT RAISE(ABORT, 'requirement group members are append-only'); END""",
    """CREATE TABLE actors (
        actor_id TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('human', 'automation', 'service')),
        label TEXT,
        PRIMARY KEY (actor_id, incarnation_id)
    )""",
    """CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        plan_revision_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'retired')),
        created_by_actor_id TEXT,
        created_by_incarnation_id TEXT,
        CHECK ((created_by_actor_id IS NULL) = (created_by_incarnation_id IS NULL)),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (created_by_actor_id, created_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE assignments (
        assignment_id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        assignee_actor_id TEXT,
        assignee_incarnation_id TEXT,
        run_id TEXT,
        CHECK ((assignee_actor_id IS NULL) = (assignee_incarnation_id IS NULL)),
        UNIQUE (assignment_id, run_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (assignee_actor_id, assignee_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )""",
    """CREATE TABLE run_schedules (
        run_id TEXT PRIMARY KEY,
        schedule_json TEXT NOT NULL,
        schedule_digest TEXT NOT NULL CHECK (
            length(schedule_digest) = 64 AND schedule_digest NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )""",
    """CREATE TABLE run_lanes (
        run_id TEXT NOT NULL,
        lane_id TEXT NOT NULL,
        lane_ordinal INTEGER NOT NULL CHECK (lane_ordinal >= 0),
        queue_policy TEXT NOT NULL CHECK (queue_policy IN ('serial', 'parallel')),
        required_role TEXT,
        isolation_policy TEXT NOT NULL CHECK (isolation_policy IN ('shared_scopes', 'qualified_workspaces')),
        PRIMARY KEY (run_id, lane_id),
        UNIQUE (run_id, lane_ordinal),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )""",
    """CREATE TABLE run_queue (
        assignment_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        lane_id TEXT NOT NULL,
        queue_position INTEGER NOT NULL CHECK (queue_position >= 0),
        UNIQUE (run_id, lane_id, queue_position),
        FOREIGN KEY (assignment_id, run_id) REFERENCES assignments(assignment_id, run_id),
        FOREIGN KEY (run_id, lane_id) REFERENCES run_lanes(run_id, lane_id)
    )""",
    """CREATE TABLE attempts (
        attempt_id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN (
            'admitted', 'active', 'reported', 'accepted', 'rejected', 'released',
            'expired', 'uncertain', 'quarantined'
        )),
        assignment_id TEXT,
        run_id TEXT,
        lease_id TEXT,
        lease_expires_at TEXT,
        CHECK ((lease_id IS NULL) = (lease_expires_at IS NULL)),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (actor_id, actor_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id)
    )""",
    """CREATE TABLE capabilities (
        capability_id TEXT PRIMARY KEY,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        parent_capability_id TEXT,
        scope_kind TEXT NOT NULL CHECK (scope_kind IN (
            'project', 'plan_revision', 'work_item', 'requirement', 'run', 'assignment',
            'attempt', 'actor', 'capability', 'evidence', 'artifact', 'outcome',
            'external_operation', 'checkpoint', 'interface', 'barrier', 'decision'
        )),
        scope_entity_id TEXT NOT NULL,
        scope_definition_revision_id TEXT,
        scope_incarnation_id TEXT,
        run_id TEXT,
        assignment_id TEXT,
        attempt_id TEXT,
        expires_at TEXT,
        revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
        CHECK ((scope_kind IN ('work_item', 'requirement')) = (scope_definition_revision_id IS NOT NULL)),
        CHECK ((scope_kind = 'actor') = (scope_incarnation_id IS NOT NULL)),
        FOREIGN KEY (actor_id, actor_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (parent_capability_id) REFERENCES capabilities(capability_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id),
        FOREIGN KEY (assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TABLE capability_tokens (
        capability_id TEXT PRIMARY KEY,
        token_digest TEXT NOT NULL UNIQUE CHECK (
            length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (capability_id) REFERENCES capabilities(capability_id)
    )""",
    """CREATE TABLE local_owner_credentials (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        actor_id TEXT NOT NULL,
        bootstrap_incarnation_id TEXT NOT NULL,
        salt BLOB NOT NULL CHECK (length(salt) = 16),
        password_digest BLOB NOT NULL CHECK (length(password_digest) = 32),
        scrypt_n INTEGER NOT NULL CHECK (scrypt_n >= 4096),
        scrypt_r INTEGER NOT NULL CHECK (scrypt_r > 0),
        scrypt_p INTEGER NOT NULL CHECK (scrypt_p > 0),
        FOREIGN KEY (actor_id, bootstrap_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE capability_actions (
        capability_id TEXT NOT NULL,
        action_ordinal INTEGER NOT NULL CHECK (action_ordinal >= 0),
        action TEXT NOT NULL,
        PRIMARY KEY (capability_id, action_ordinal),
        UNIQUE (capability_id, action),
        FOREIGN KEY (capability_id) REFERENCES capabilities(capability_id)
    )""",
    """CREATE TABLE attempt_capabilities (
        attempt_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        PRIMARY KEY (attempt_id, capability_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (capability_id) REFERENCES capabilities(capability_id)
    )""",
    """CREATE TABLE attempt_workspace_qualifications (
        attempt_id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        base_project_id TEXT NOT NULL,
        base_ref TEXT NOT NULL,
        base_digest TEXT NOT NULL CHECK (length(base_digest) = 64 AND base_digest NOT GLOB '*[^0-9a-f]*'),
        destination_project_id TEXT NOT NULL,
        destination_ref TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        provider_version TEXT NOT NULL,
        provider_contract_version INTEGER NOT NULL CHECK (provider_contract_version > 0),
        receipt_id TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
        provenance_ref TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        isolation_json TEXT NOT NULL,
        isolation_digest TEXT NOT NULL CHECK (
            length(isolation_digest) = 64 AND isolation_digest NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TABLE attempt_scope_snapshots (
        attempt_id TEXT PRIMARY KEY,
        scope_json TEXT NOT NULL,
        scope_digest TEXT NOT NULL CHECK (
            length(scope_digest) = 64 AND scope_digest NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE UNIQUE INDEX one_live_attempt_per_work_item_definition
        ON attempts(work_item_id, definition_revision_id)
        WHERE state IN ('admitted', 'active', 'reported')""",
    """CREATE TRIGGER attempt_workspace_qualifications_no_update
        BEFORE UPDATE ON attempt_workspace_qualifications
        BEGIN SELECT RAISE(ABORT, 'attempt workspace qualifications are append-only'); END""",
    """CREATE TRIGGER attempt_workspace_qualifications_no_delete
        BEFORE DELETE ON attempt_workspace_qualifications
        BEGIN SELECT RAISE(ABORT, 'attempt workspace qualifications are append-only'); END""",
    """CREATE TRIGGER attempt_scope_snapshots_no_update
        BEFORE UPDATE ON attempt_scope_snapshots
        BEGIN SELECT RAISE(ABORT, 'attempt scope snapshots are append-only'); END""",
    """CREATE TRIGGER attempt_scope_snapshots_no_delete
        BEFORE DELETE ON attempt_scope_snapshots
        BEGIN SELECT RAISE(ABORT, 'attempt scope snapshots are append-only'); END""",
    """CREATE TABLE child_executions (
        execution_id TEXT PRIMARY KEY,
        parent_attempt_id TEXT NOT NULL,
        logical_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
        retry_of_execution_id TEXT,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        child_actor_id TEXT NOT NULL,
        child_incarnation_id TEXT NOT NULL,
        capability_id TEXT NOT NULL UNIQUE,
        scope_json TEXT NOT NULL,
        scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64 AND scope_digest NOT GLOB '*[^0-9a-f]*'),
        actions_json TEXT NOT NULL,
        actions_digest TEXT NOT NULL CHECK (length(actions_digest) = 64 AND actions_digest NOT GLOB '*[^0-9a-f]*'),
        state TEXT NOT NULL CHECK (state IN ('active', 'candidate', 'cancel_requested', 'stopped')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (parent_attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (retry_of_execution_id) REFERENCES child_executions(execution_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (child_actor_id, child_incarnation_id) REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (capability_id) REFERENCES capabilities(capability_id),
        UNIQUE (parent_attempt_id, logical_id, ordinal)
    )""",
    """CREATE INDEX child_executions_by_parent_state
        ON child_executions(parent_attempt_id, state, logical_id, ordinal)""",
    """CREATE TRIGGER child_execution_identity_immutable
        BEFORE UPDATE ON child_executions
        WHEN OLD.execution_id IS NOT NEW.execution_id OR OLD.parent_attempt_id IS NOT NEW.parent_attempt_id
          OR OLD.logical_id IS NOT NEW.logical_id OR OLD.ordinal IS NOT NEW.ordinal
          OR OLD.retry_of_execution_id IS NOT NEW.retry_of_execution_id
          OR OLD.work_item_id IS NOT NEW.work_item_id OR OLD.definition_revision_id IS NOT NEW.definition_revision_id
          OR OLD.child_actor_id IS NOT NEW.child_actor_id OR OLD.child_incarnation_id IS NOT NEW.child_incarnation_id
          OR OLD.capability_id IS NOT NEW.capability_id OR OLD.scope_json IS NOT NEW.scope_json
          OR OLD.scope_digest IS NOT NEW.scope_digest OR OLD.actions_json IS NOT NEW.actions_json
          OR OLD.actions_digest IS NOT NEW.actions_digest OR OLD.created_at IS NOT NEW.created_at
        BEGIN SELECT RAISE(ABORT, 'child execution identity and authority are immutable'); END""",
    """CREATE TRIGGER child_execution_state_transition_guard
        BEFORE UPDATE ON child_executions
        WHEN NOT (
            (OLD.state = 'active' AND NEW.state IN ('candidate', 'cancel_requested', 'stopped'))
            OR (OLD.state = 'candidate' AND NEW.state IN ('cancel_requested', 'stopped'))
            OR (OLD.state = 'cancel_requested' AND NEW.state = 'stopped')
        )
        BEGIN SELECT RAISE(ABORT, 'child execution state transition is invalid'); END""",
    """CREATE TRIGGER child_executions_no_delete
        BEFORE DELETE ON child_executions
        BEGIN SELECT RAISE(ABORT, 'child executions are durable records'); END""",
    """CREATE TABLE child_candidates (
        candidate_id TEXT PRIMARY KEY,
        execution_id TEXT NOT NULL UNIQUE,
        summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 4096),
        artifacts_json TEXT NOT NULL,
        artifacts_digest TEXT NOT NULL CHECK (length(artifacts_digest) = 64 AND artifacts_digest NOT GLOB '*[^0-9a-f]*'),
        submitted_by_actor_id TEXT NOT NULL,
        submitted_by_incarnation_id TEXT NOT NULL,
        submitted_at TEXT NOT NULL,
        FOREIGN KEY (execution_id) REFERENCES child_executions(execution_id),
        FOREIGN KEY (submitted_by_actor_id, submitted_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TRIGGER child_candidates_no_update
        BEFORE UPDATE ON child_candidates
        BEGIN SELECT RAISE(ABORT, 'child candidates are append-only'); END""",
    """CREATE TRIGGER child_candidates_no_delete
        BEFORE DELETE ON child_candidates
        BEGIN SELECT RAISE(ABORT, 'child candidates are append-only'); END""",
    """CREATE TABLE child_candidate_reviews (
        review_id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL UNIQUE,
        decision TEXT NOT NULL CHECK (decision IN ('accepted', 'rejected')),
        reviewer_actor_id TEXT NOT NULL,
        reviewer_incarnation_id TEXT NOT NULL,
        reason TEXT CHECK (reason IS NULL OR length(reason) <= 2048),
        reviewed_at TEXT NOT NULL,
        FOREIGN KEY (candidate_id) REFERENCES child_candidates(candidate_id),
        FOREIGN KEY (reviewer_actor_id, reviewer_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TRIGGER child_candidate_reviews_no_update
        BEFORE UPDATE ON child_candidate_reviews
        BEGIN SELECT RAISE(ABORT, 'child candidate reviews are append-only'); END""",
    """CREATE TRIGGER child_candidate_reviews_no_delete
        BEFORE DELETE ON child_candidate_reviews
        BEGIN SELECT RAISE(ABORT, 'child candidate reviews are append-only'); END""",
    """CREATE TABLE child_cancellations (
        cancellation_id TEXT PRIMARY KEY,
        execution_id TEXT NOT NULL UNIQUE,
        requested_by_actor_id TEXT NOT NULL,
        requested_by_incarnation_id TEXT NOT NULL,
        reason TEXT CHECK (reason IS NULL OR length(reason) <= 2048),
        requested_at TEXT NOT NULL,
        FOREIGN KEY (execution_id) REFERENCES child_executions(execution_id),
        FOREIGN KEY (requested_by_actor_id, requested_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TRIGGER child_cancellations_no_update
        BEFORE UPDATE ON child_cancellations
        BEGIN SELECT RAISE(ABORT, 'child cancellation requests are append-only'); END""",
    """CREATE TRIGGER child_cancellations_no_delete
        BEFORE DELETE ON child_cancellations
        BEGIN SELECT RAISE(ABORT, 'child cancellation requests are append-only'); END""",
    """CREATE TABLE child_stop_observations (
        execution_id TEXT PRIMARY KEY,
        parent_attempt_id TEXT NOT NULL,
        lease_id TEXT NOT NULL,
        lease_expires_at TEXT NOT NULL,
        observation_json TEXT NOT NULL,
        receipt_id TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        FOREIGN KEY (execution_id) REFERENCES child_executions(execution_id),
        FOREIGN KEY (parent_attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TRIGGER child_stop_observations_no_update
        BEFORE UPDATE ON child_stop_observations
        BEGIN SELECT RAISE(ABORT, 'child stop observations are append-only'); END""",
    """CREATE TRIGGER child_stop_observations_no_delete
        BEFORE DELETE ON child_stop_observations
        BEGIN SELECT RAISE(ABORT, 'child stop observations are append-only'); END""",
    """CREATE TABLE artifacts (
        artifact_id TEXT PRIMARY KEY,
        provider_id TEXT NOT NULL,
        external_ref TEXT NOT NULL,
        content_digest TEXT,
        UNIQUE (provider_id, external_ref),
        CHECK (content_digest IS NULL OR (length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'))
    )""",
    """CREATE TRIGGER artifacts_identity_and_digest_guard
        BEFORE UPDATE ON artifacts
        WHEN OLD.provider_id != NEW.provider_id OR OLD.external_ref != NEW.external_ref
          OR (OLD.content_digest IS NOT NULL AND NEW.content_digest IS NOT OLD.content_digest)
          OR (OLD.content_digest IS NULL AND NEW.content_digest IS NULL)
        BEGIN SELECT RAISE(ABORT, 'artifact identity is immutable and content digest may be pinned once'); END""",
    """CREATE TRIGGER artifacts_no_delete
        BEFORE DELETE ON artifacts
        BEGIN SELECT RAISE(ABORT, 'artifact records are append-only'); END""",
    """CREATE TABLE evidence (
        evidence_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        requirement_id TEXT,
        requirement_definition_revision_id TEXT,
        operation_id TEXT,
        result TEXT NOT NULL CHECK (result IN ('pass', 'fail', 'inconclusive')),
        verifier_id TEXT NOT NULL,
        verifier_version TEXT NOT NULL,
        contract_digest TEXT NOT NULL CHECK (length(contract_digest) = 64 AND contract_digest NOT GLOB '*[^0-9a-f]*'),
        source_digest TEXT CHECK (source_digest IS NULL OR (length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*')),
        observed_at TEXT NOT NULL,
        CHECK ((requirement_id IS NULL) = (requirement_definition_revision_id IS NULL)),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (operation_id) REFERENCES external_operations(operation_id),
        FOREIGN KEY (requirement_id, requirement_definition_revision_id)
            REFERENCES requirements(requirement_id, definition_revision_id)
    )""",
    """CREATE TABLE evidence_inputs (
        evidence_id TEXT NOT NULL,
        input_name TEXT NOT NULL,
        input_digest TEXT NOT NULL CHECK (length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*'),
        PRIMARY KEY (evidence_id, input_name),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
    )""",
    """CREATE TABLE evidence_artifacts (
        evidence_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        PRIMARY KEY (evidence_id, artifact_id),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
        FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
    )""",
    """CREATE TABLE evidence_facts (
        evidence_id TEXT NOT NULL,
        fact_name TEXT NOT NULL,
        fact_kind TEXT NOT NULL CHECK (fact_kind IN (
            'command_result', 'file_observation', 'artifact_reference', 'benchmark_sample',
            'predicate_result', 'interface_observation', 'checkpoint_receipt',
            'manual_attestation', 'provider_receipt'
        )),
        fact_version INTEGER NOT NULL CHECK (fact_version > 0),
        fact_digest TEXT NOT NULL CHECK (length(fact_digest) = 64 AND fact_digest NOT GLOB '*[^0-9a-f]*'),
        artifact_id TEXT,
        value_json TEXT,
        PRIMARY KEY (evidence_id, fact_name),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
        FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
    )""",
    """CREATE TABLE outcomes (
        outcome_id TEXT PRIMARY KEY,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version > 0),
        disposition TEXT NOT NULL CHECK (disposition IN (
            'completed', 'accepted_negative', 'no_change', 'evaluated_not_promoted', 'failed', 'superseded'
        )),
        accepted_by_actor_id TEXT NOT NULL,
        accepted_by_incarnation_id TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        attempt_id TEXT,
        UNIQUE (work_item_id, definition_revision_id, version),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (accepted_by_actor_id, accepted_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TABLE outcome_evidence (
        outcome_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        PRIMARY KEY (outcome_id, evidence_id),
        FOREIGN KEY (outcome_id) REFERENCES outcomes(outcome_id),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
    )""",
    """CREATE TABLE outcome_candidates (
        candidate_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        disposition TEXT NOT NULL CHECK (disposition IN (
            'completed', 'accepted_negative', 'no_change', 'evaluated_not_promoted', 'failed'
        )),
        note TEXT,
        report_source_json TEXT NOT NULL,
        report_receipt_json TEXT NOT NULL,
        reported_by_actor_id TEXT NOT NULL,
        reported_by_incarnation_id TEXT NOT NULL,
        reported_at TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'rejected')),
        outcome_id TEXT UNIQUE,
        UNIQUE (candidate_id, attempt_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (reported_by_actor_id, reported_by_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (outcome_id) REFERENCES outcomes(outcome_id)
    )""",
    """CREATE TABLE outcome_provenance (
        outcome_id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL UNIQUE,
        canonical_json TEXT NOT NULL,
        content_digest TEXT NOT NULL CHECK (
            length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
        ),
        FOREIGN KEY (outcome_id) REFERENCES outcomes(outcome_id),
        FOREIGN KEY (candidate_id) REFERENCES outcome_candidates(candidate_id)
    )""",
    """CREATE TABLE declaration_facts (
        fact_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        fact_id TEXT NOT NULL UNIQUE,
        plan_revision_id TEXT NOT NULL,
        declaration_kind TEXT NOT NULL CHECK (declaration_kind IN (
            'decision', 'interface', 'checkpoint', 'barrier', 'rendezvous'
        )),
        declaration_id TEXT NOT NULL,
        declaration_digest TEXT NOT NULL CHECK (
            length(declaration_digest) = 64 AND declaration_digest NOT GLOB '*[^0-9a-f]*'
        ),
        fact_kind TEXT NOT NULL CHECK (fact_kind IN (
            'decision_resolved', 'interface_published', 'checkpoint_accepted',
            'barrier_released', 'rendezvous_arrived', 'blocker_opened', 'blocker_cleared'
        )),
        participant_project_id TEXT,
        participant_kind TEXT,
        participant_entity_id TEXT,
        participant_definition_revision_id TEXT,
        participant_incarnation_id TEXT,
        payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision > 0),
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        CHECK (
            (fact_kind = 'rendezvous_arrived'
             AND participant_project_id IS NOT NULL AND participant_kind IS NOT NULL
             AND participant_entity_id IS NOT NULL
             AND ((participant_kind IN ('work_item', 'requirement') AND participant_definition_revision_id IS NOT NULL
                   AND participant_incarnation_id IS NULL)
                  OR (participant_kind = 'actor' AND participant_definition_revision_id IS NULL
                      AND participant_incarnation_id IS NOT NULL)
                  OR (participant_kind NOT IN ('work_item', 'requirement', 'actor')
                      AND participant_definition_revision_id IS NULL AND participant_incarnation_id IS NULL)))
            OR
            (fact_kind <> 'rendezvous_arrived'
             AND participant_project_id IS NULL AND participant_kind IS NULL AND participant_entity_id IS NULL
             AND participant_definition_revision_id IS NULL AND participant_incarnation_id IS NULL)
        ),
        CHECK (
            (declaration_kind = 'decision' AND fact_kind IN ('decision_resolved', 'blocker_opened', 'blocker_cleared'))
            OR (declaration_kind = 'interface' AND fact_kind IN ('interface_published', 'blocker_opened', 'blocker_cleared'))
            OR (declaration_kind = 'checkpoint' AND fact_kind IN ('checkpoint_accepted', 'blocker_opened', 'blocker_cleared'))
            OR (declaration_kind = 'barrier' AND fact_kind IN ('barrier_released', 'blocker_opened', 'blocker_cleared'))
            OR (declaration_kind = 'rendezvous' AND fact_kind IN ('rendezvous_arrived', 'blocker_opened', 'blocker_cleared'))
        ),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (actor_id, actor_incarnation_id) REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE UNIQUE INDEX declaration_rendezvous_participant_once
        ON declaration_facts(
            declaration_kind, declaration_id, declaration_digest,
            participant_project_id, participant_kind, participant_entity_id,
            COALESCE(participant_definition_revision_id, ''),
            COALESCE(participant_incarnation_id, '')
        ) WHERE fact_kind = 'rendezvous_arrived'""",
    """CREATE TABLE coordination_messages (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK (sequence > 0),
        message_id TEXT NOT NULL UNIQUE,
        project_id TEXT NOT NULL,
        scope_kind TEXT NOT NULL CHECK (scope_kind IN (
            'project', 'plan_revision', 'work_item', 'requirement', 'run', 'assignment', 'attempt', 'actor',
            'capability', 'evidence', 'artifact', 'outcome', 'external_operation', 'checkpoint', 'interface',
            'barrier', 'decision', 'invariant'
        )),
        scope_entity_id TEXT NOT NULL,
        scope_definition_revision_id TEXT,
        scope_incarnation_id TEXT,
        message_type TEXT NOT NULL CHECK (message_type IN (
            'question', 'answer', 'decision', 'interface_change', 'status', 'artifact', 'conflict', 'handoff'
        )),
        sender_actor_id TEXT NOT NULL,
        sender_incarnation_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        context_run_id TEXT,
        context_assignment_id TEXT,
        context_attempt_id TEXT,
        subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
        body_text TEXT CHECK (body_text IS NULL OR length(body_text) <= 8192),
        content_ref_project_id TEXT,
        content_ref_kind TEXT,
        content_ref_entity_id TEXT,
        content_ref_definition_revision_id TEXT,
        content_ref_incarnation_id TEXT,
        content_digest TEXT,
        reply_to_message_id TEXT,
        CHECK (
            (scope_kind IN ('work_item', 'requirement') AND scope_definition_revision_id IS NOT NULL
             AND scope_incarnation_id IS NULL)
            OR (scope_kind = 'actor' AND scope_definition_revision_id IS NULL AND scope_incarnation_id IS NOT NULL)
            OR (scope_kind NOT IN ('work_item', 'requirement', 'actor')
                AND scope_definition_revision_id IS NULL AND scope_incarnation_id IS NULL)
        ),
        CHECK (context_assignment_id IS NULL OR context_run_id IS NOT NULL),
        CHECK (
            (content_ref_project_id IS NULL AND content_ref_kind IS NULL AND content_ref_entity_id IS NULL
             AND content_ref_definition_revision_id IS NULL AND content_ref_incarnation_id IS NULL
             AND content_digest IS NULL)
            OR (content_ref_project_id = project_id AND content_ref_kind = 'artifact'
                AND content_ref_entity_id IS NOT NULL AND content_ref_definition_revision_id IS NULL
                AND content_ref_incarnation_id IS NULL AND content_digest IS NOT NULL
                AND length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*')
        ),
        CHECK (body_text IS NOT NULL OR content_ref_entity_id IS NOT NULL),
        CHECK ((message_type = 'answer' AND reply_to_message_id IS NOT NULL)
               OR (message_type <> 'answer' AND reply_to_message_id IS NULL)),
        UNIQUE (reply_to_message_id),
        FOREIGN KEY (sender_actor_id, sender_incarnation_id) REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (context_run_id) REFERENCES runs(run_id),
        FOREIGN KEY (context_assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (context_attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (content_ref_entity_id) REFERENCES artifacts(artifact_id),
        FOREIGN KEY (reply_to_message_id) REFERENCES coordination_messages(message_id)
    )""",
    """CREATE INDEX coordination_messages_by_scope_sequence
        ON coordination_messages(scope_kind, scope_entity_id, sequence)""",
    """CREATE INDEX coordination_messages_by_context
        ON coordination_messages(context_run_id, context_assignment_id, context_attempt_id, sequence)""",
    """CREATE TABLE coordination_message_recipients (
        message_id TEXT NOT NULL,
        recipient_actor_id TEXT NOT NULL,
        recipient_incarnation_id TEXT NOT NULL,
        PRIMARY KEY (message_id, recipient_actor_id, recipient_incarnation_id),
        FOREIGN KEY (message_id) REFERENCES coordination_messages(message_id),
        FOREIGN KEY (recipient_actor_id, recipient_incarnation_id) REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE INDEX coordination_message_recipients_by_actor
        ON coordination_message_recipients(recipient_actor_id, recipient_incarnation_id, message_id)""",
    """CREATE TABLE coordination_message_cursors (
        cursor_id TEXT PRIMARY KEY,
        recipient_actor_id TEXT NOT NULL,
        recipient_incarnation_id TEXT NOT NULL,
        context_run_id TEXT,
        scope_kind TEXT NOT NULL CHECK (scope_kind IN (
            'project', 'plan_revision', 'work_item', 'requirement', 'run', 'assignment', 'attempt', 'actor',
            'capability', 'evidence', 'artifact', 'outcome', 'external_operation', 'checkpoint', 'interface',
            'barrier', 'decision', 'invariant'
        )),
        scope_entity_id TEXT NOT NULL,
        scope_definition_revision_id TEXT,
        scope_incarnation_id TEXT,
        delivered_sequence INTEGER NOT NULL DEFAULT 0 CHECK (delivered_sequence >= 0),
        read_sequence INTEGER NOT NULL DEFAULT 0 CHECK (read_sequence >= 0 AND read_sequence <= delivered_sequence),
        updated_at TEXT NOT NULL,
        CHECK (context_run_id IS NULL OR context_run_id <> ''),
        CHECK (
            (scope_kind IN ('work_item', 'requirement') AND scope_definition_revision_id IS NOT NULL
             AND scope_incarnation_id IS NULL)
            OR (scope_kind = 'actor' AND scope_definition_revision_id IS NULL AND scope_incarnation_id IS NOT NULL)
            OR (scope_kind NOT IN ('work_item', 'requirement', 'actor')
                AND scope_definition_revision_id IS NULL AND scope_incarnation_id IS NULL)
        ),
        FOREIGN KEY (recipient_actor_id, recipient_incarnation_id) REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (context_run_id) REFERENCES runs(run_id)
    )""",
    """CREATE UNIQUE INDEX coordination_message_cursors_identity
        ON coordination_message_cursors(
            recipient_actor_id, recipient_incarnation_id, COALESCE(context_run_id, ''), scope_kind, scope_entity_id,
            COALESCE(scope_definition_revision_id, ''), COALESCE(scope_incarnation_id, '')
        )""",
    """CREATE TRIGGER declaration_facts_no_update
        BEFORE UPDATE ON declaration_facts
        BEGIN SELECT RAISE(ABORT, 'declaration facts are append-only'); END""",
    """CREATE TRIGGER declaration_facts_no_delete
        BEFORE DELETE ON declaration_facts
        BEGIN SELECT RAISE(ABORT, 'declaration facts are append-only'); END""",
    """CREATE TRIGGER coordination_messages_no_update
        BEFORE UPDATE ON coordination_messages
        BEGIN SELECT RAISE(ABORT, 'coordination messages are append-only'); END""",
    """CREATE TRIGGER coordination_messages_no_delete
        BEFORE DELETE ON coordination_messages
        BEGIN SELECT RAISE(ABORT, 'coordination messages are append-only'); END""",
    """CREATE TRIGGER coordination_message_recipients_no_update
        BEFORE UPDATE ON coordination_message_recipients
        BEGIN SELECT RAISE(ABORT, 'message recipients are append-only'); END""",
    """CREATE TRIGGER coordination_message_recipients_no_delete
        BEFORE DELETE ON coordination_message_recipients
        BEGIN SELECT RAISE(ABORT, 'message recipients are append-only'); END""",
    """CREATE TRIGGER coordination_messages_answer_guard
        BEFORE INSERT ON coordination_messages
        WHEN NEW.reply_to_message_id IS NOT NULL
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1 FROM coordination_messages AS question
                WHERE question.message_id = NEW.reply_to_message_id
                  AND question.message_type = 'question'
                  AND question.project_id = NEW.project_id
                  AND question.scope_kind = NEW.scope_kind
                  AND question.scope_entity_id = NEW.scope_entity_id
                  AND question.scope_definition_revision_id IS NEW.scope_definition_revision_id
                  AND question.scope_incarnation_id IS NEW.scope_incarnation_id
            ) THEN RAISE(ABORT, 'answer must match an existing question scope') END;
        END""",
    """CREATE TRIGGER coordination_message_cursors_no_delete
        BEFORE DELETE ON coordination_message_cursors
        BEGIN SELECT RAISE(ABORT, 'message cursors are monotonic and cannot be deleted'); END""",
    """CREATE TRIGGER coordination_message_cursors_insert_guard
        BEFORE INSERT ON coordination_message_cursors
        WHEN NEW.delivered_sequence <> 0 OR NEW.read_sequence <> 0
        BEGIN SELECT RAISE(ABORT, 'message cursor watermarks must start at zero'); END""",
    """CREATE TRIGGER coordination_message_cursors_update_guard
        BEFORE UPDATE ON coordination_message_cursors
        WHEN NEW.cursor_id <> OLD.cursor_id
          OR NEW.recipient_actor_id <> OLD.recipient_actor_id
          OR NEW.recipient_incarnation_id <> OLD.recipient_incarnation_id
          OR NEW.context_run_id IS NOT OLD.context_run_id
          OR NEW.scope_kind <> OLD.scope_kind
          OR NEW.scope_entity_id <> OLD.scope_entity_id
          OR NEW.scope_definition_revision_id IS NOT OLD.scope_definition_revision_id
          OR NEW.scope_incarnation_id IS NOT OLD.scope_incarnation_id
          OR NEW.delivered_sequence < OLD.delivered_sequence
          OR NEW.read_sequence < OLD.read_sequence
        BEGIN SELECT RAISE(ABORT, 'message cursor identity and watermarks are monotonic'); END""",
    """CREATE TRIGGER coordination_message_cursors_sequence_guard
        BEFORE UPDATE ON coordination_message_cursors
        WHEN NEW.delivered_sequence > 0 AND NOT EXISTS (
            SELECT 1 FROM coordination_messages AS message
            JOIN coordination_message_recipients AS recipient USING (message_id)
            WHERE message.sequence = NEW.delivered_sequence
              AND recipient.recipient_actor_id = NEW.recipient_actor_id
              AND recipient.recipient_incarnation_id = NEW.recipient_incarnation_id
              AND message.context_run_id IS NEW.context_run_id
              AND message.scope_kind = NEW.scope_kind
              AND message.scope_entity_id = NEW.scope_entity_id
              AND message.scope_definition_revision_id IS NEW.scope_definition_revision_id
              AND message.scope_incarnation_id IS NEW.scope_incarnation_id
        )
        BEGIN SELECT RAISE(ABORT, 'delivered cursor must identify a message delivered to this recipient and scope'); END""",
    """CREATE TABLE external_operations (
        operation_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
        state TEXT NOT NULL CHECK (state IN (
            'prepared', 'executing', 'observed', 'finalized', 'failed', 'unknown', 'not_applied'
        )),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        attempt_id TEXT,
        external_ref TEXT,
        receipt_digest TEXT,
        CHECK (receipt_digest IS NULL OR (length(receipt_digest) = 64 AND receipt_digest NOT GLOB '*[^0-9a-f]*')),
        CHECK (state NOT IN ('observed', 'finalized') OR receipt_digest IS NOT NULL),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id)
    )""",
    """CREATE TRIGGER external_operation_identity_immutable
        BEFORE UPDATE ON external_operations
        WHEN OLD.operation_id IS NOT NEW.operation_id OR OLD.kind IS NOT NEW.kind
          OR OLD.idempotency_key IS NOT NEW.idempotency_key OR OLD.request_digest IS NOT NEW.request_digest
          OR OLD.created_at IS NOT NEW.created_at OR OLD.attempt_id IS NOT NEW.attempt_id
        BEGIN SELECT RAISE(ABORT, 'external operation identity is immutable'); END""",
    """CREATE TRIGGER external_operation_state_transition_guard
        BEFORE UPDATE ON external_operations
        WHEN NOT (
            (OLD.state = 'prepared' AND NEW.state IN ('executing', 'unknown', 'not_applied'))
            OR (OLD.state = 'executing' AND NEW.state IN ('observed', 'failed', 'unknown', 'not_applied'))
            OR (OLD.state = 'unknown' AND NEW.state IN ('observed', 'failed', 'not_applied'))
            OR (OLD.state = 'unknown' AND NEW.state = 'executing' AND EXISTS (
                SELECT 1 FROM verification_attempts AS v
                WHERE v.operation_id = OLD.operation_id AND v.state = 'executing'
            ))
            OR (OLD.state = 'not_applied' AND NEW.state IN ('executing', 'unknown'))
            OR (OLD.state = 'observed' AND NEW.state IN ('finalized', 'failed', 'unknown'))
        )
        BEGIN SELECT RAISE(ABORT, 'external operation state transition is invalid'); END""",
    """CREATE TABLE resource_permit_operations (
        operation_id TEXT PRIMARY KEY,
        operation_kind TEXT NOT NULL CHECK (operation_kind IN ('reserve', 'release')),
        attempt_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        run_id TEXT,
        assignment_id TEXT,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        resource_class_id TEXT NOT NULL,
        units INTEGER NOT NULL CHECK (units > 0),
        scope_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        request_json TEXT NOT NULL,
        request_digest TEXT NOT NULL CHECK (
            length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
        ),
        expected_authority_revision INTEGER NOT NULL CHECK (expected_authority_revision > 0),
        original_operation_id TEXT,
        state TEXT NOT NULL CHECK (state IN (
            'prepared', 'executing', 'held', 'released', 'unknown', 'not_applied', 'failed'
        )),
        permit_json TEXT,
        provider_receipt_json TEXT,
        inspection_json TEXT,
        reason_code TEXT,
        provider_identity_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        CHECK ((operation_kind = 'reserve' AND original_operation_id IS NULL)
            OR (operation_kind = 'release' AND original_operation_id IS NOT NULL)),
        CHECK (state NOT IN ('held', 'released') OR (permit_json IS NOT NULL AND provider_receipt_json IS NOT NULL)),
        FOREIGN KEY (operation_id) REFERENCES external_operations(operation_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id),
        FOREIGN KEY (assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (actor_id, actor_incarnation_id) REFERENCES actors(actor_id, incarnation_id),
        FOREIGN KEY (original_operation_id) REFERENCES resource_permit_operations(operation_id)
    )""",
    """CREATE TRIGGER resource_permit_operation_identity_immutable
        BEFORE UPDATE ON resource_permit_operations
        WHEN OLD.operation_id IS NOT NEW.operation_id OR OLD.operation_kind IS NOT NEW.operation_kind
          OR OLD.attempt_id IS NOT NEW.attempt_id OR OLD.work_item_id IS NOT NEW.work_item_id
          OR OLD.definition_revision_id IS NOT NEW.definition_revision_id
          OR OLD.run_id IS NOT NEW.run_id OR OLD.assignment_id IS NOT NEW.assignment_id
          OR OLD.actor_id IS NOT NEW.actor_id OR OLD.actor_incarnation_id IS NOT NEW.actor_incarnation_id
          OR OLD.resource_class_id IS NOT NEW.resource_class_id OR OLD.units IS NOT NEW.units
          OR OLD.scope_id IS NOT NEW.scope_id OR OLD.idempotency_key IS NOT NEW.idempotency_key
          OR OLD.request_json IS NOT NEW.request_json OR OLD.request_digest IS NOT NEW.request_digest
          OR OLD.expected_authority_revision IS NOT NEW.expected_authority_revision
          OR OLD.original_operation_id IS NOT NEW.original_operation_id OR OLD.created_at IS NOT NEW.created_at
        BEGIN SELECT RAISE(ABORT, 'resource permit intent identity is immutable'); END""",
    """CREATE TRIGGER resource_permit_operation_state_transition_guard
        BEFORE UPDATE ON resource_permit_operations
        WHEN NOT (
            (OLD.state = 'prepared' AND NEW.state IN ('executing', 'unknown', 'not_applied'))
            OR (OLD.state = 'executing' AND NEW.state IN ('held', 'released', 'unknown', 'failed', 'not_applied'))
            OR (OLD.state = 'unknown' AND NEW.state IN ('held', 'released', 'unknown', 'not_applied'))
            OR (OLD.state = 'not_applied' AND NEW.state IN ('executing', 'unknown'))
            OR (OLD.state = 'held' AND NEW.state IN ('held', 'released', 'unknown'))
        )
        BEGIN SELECT RAISE(ABORT, 'resource permit state transition is invalid'); END""",
    """CREATE TRIGGER resource_permit_operations_no_delete
        BEFORE DELETE ON resource_permit_operations
        BEGIN SELECT RAISE(ABORT, 'resource permit operations are append-only'); END""",
    """CREATE TABLE git_effect_operations (
        operation_id TEXT PRIMARY KEY,
        request_json TEXT NOT NULL,
        request_digest TEXT NOT NULL CHECK (
            length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
        ),
        state TEXT NOT NULL CHECK (state IN (
            'prepared', 'executing', 'applied', 'conflict', 'dirty', 'rejected',
            'not_applied', 'unknown', 'finalized'
        )),
        observation_json TEXT,
        provider_receipt_json TEXT,
        updated_at TEXT NOT NULL,
        CHECK ((state IN ('applied', 'conflict', 'dirty', 'rejected', 'not_applied', 'finalized')
                AND observation_json IS NOT NULL AND provider_receipt_json IS NOT NULL)
            OR state NOT IN ('applied', 'conflict', 'dirty', 'rejected', 'not_applied', 'finalized')),
        FOREIGN KEY (operation_id) REFERENCES external_operations(operation_id)
    )""",
    """CREATE TRIGGER git_effect_request_immutable
        BEFORE UPDATE ON git_effect_operations
        WHEN OLD.request_json IS NOT NEW.request_json OR OLD.request_digest IS NOT NEW.request_digest
        BEGIN SELECT RAISE(ABORT, 'Git effect intent is immutable'); END""",
    """CREATE TRIGGER git_effect_state_transition_guard
        BEFORE UPDATE ON git_effect_operations
        WHEN NOT (
            (OLD.state = 'prepared' AND NEW.state IN ('executing', 'not_applied', 'unknown'))
            OR (OLD.state = 'executing' AND NEW.state IN ('applied', 'conflict', 'dirty', 'rejected', 'not_applied', 'unknown'))
            OR (OLD.state = 'unknown' AND NEW.state IN ('applied', 'conflict', 'dirty', 'rejected', 'not_applied', 'unknown'))
            OR (OLD.state = 'not_applied' AND NEW.state IN ('executing', 'unknown', 'not_applied'))
            OR (OLD.state IN ('applied', 'conflict', 'dirty', 'rejected', 'not_applied') AND NEW.state = 'finalized')
        )
        BEGIN SELECT RAISE(ABORT, 'Git effect state transition is invalid'); END""",
    """CREATE TRIGGER git_effect_operations_no_delete
        BEFORE DELETE ON git_effect_operations
        BEGIN SELECT RAISE(ABORT, 'Git effect operations are append-only'); END""",
    """CREATE TABLE verification_attempts (
        operation_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        requirement_id TEXT NOT NULL,
        requirement_definition_revision_id TEXT NOT NULL,
        plan_revision_id TEXT NOT NULL,
        verifier_id TEXT NOT NULL,
        verifier_version TEXT NOT NULL,
        contract_json TEXT NOT NULL,
        contract_digest TEXT NOT NULL CHECK (length(contract_digest) = 64 AND contract_digest NOT GLOB '*[^0-9a-f]*'),
        source_digest TEXT NOT NULL CHECK (length(source_digest) = 64 AND source_digest NOT GLOB '*[^0-9a-f]*'),
        inputs_json TEXT NOT NULL,
        source_receipt_json TEXT NOT NULL,
        request_json TEXT NOT NULL,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
        state TEXT NOT NULL CHECK (state IN ('prepared', 'executing', 'observed', 'not_started', 'finalized', 'rejected', 'stale', 'unknown', 'failed')),
        observation_json TEXT,
        provider_receipt_json TEXT,
        final_source_receipt_json TEXT,
        inspection_json TEXT,
        evidence_id TEXT,
        stale_reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finalized_at TEXT,
        FOREIGN KEY (operation_id) REFERENCES external_operations(operation_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (requirement_id, requirement_definition_revision_id)
            REFERENCES requirements(requirement_id, definition_revision_id),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id),
        CHECK ((state IN ('finalized', 'rejected', 'stale') AND evidence_id IS NOT NULL
                AND observation_json IS NOT NULL AND provider_receipt_json IS NOT NULL
                AND final_source_receipt_json IS NOT NULL AND finalized_at IS NOT NULL)
            OR state NOT IN ('finalized', 'rejected', 'stale'))
    )""",
    """CREATE TABLE authority_events (
        event_id TEXT PRIMARY KEY,
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision > 0),
        event_ordinal INTEGER NOT NULL CHECK (event_ordinal >= 0),
        event_kind TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        UNIQUE (semantic_revision, event_ordinal),
        FOREIGN KEY (actor_id, actor_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE command_receipts (
        receipt_id TEXT PRIMARY KEY,
        command_kind TEXT NOT NULL,
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision >= 0),
        changed INTEGER NOT NULL CHECK (changed IN (0, 1)),
        event_id TEXT UNIQUE,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        result_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        CHECK ((changed = 1) = (event_id IS NOT NULL)),
        FOREIGN KEY (event_id) REFERENCES authority_events(event_id),
        FOREIGN KEY (actor_id, actor_incarnation_id)
            REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TABLE command_idempotency (
        idempotency_key TEXT PRIMARY KEY,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
        receipt_id TEXT NOT NULL UNIQUE,
        FOREIGN KEY (receipt_id) REFERENCES command_receipts(receipt_id)
    )""",
    """CREATE TRIGGER authority_events_no_update
        BEFORE UPDATE ON authority_events
        BEGIN SELECT RAISE(ABORT, 'authority events are append-only'); END""",
    """CREATE TRIGGER authority_events_no_delete
        BEFORE DELETE ON authority_events
        BEGIN SELECT RAISE(ABORT, 'authority events are append-only'); END""",
    """CREATE TRIGGER command_receipts_no_update
        BEFORE UPDATE ON command_receipts
        BEGIN SELECT RAISE(ABORT, 'command receipts are append-only'); END""",
    """CREATE TRIGGER command_receipts_no_delete
        BEFORE DELETE ON command_receipts
        BEGIN SELECT RAISE(ABORT, 'command receipts are append-only'); END""",
    """CREATE TRIGGER command_idempotency_no_update
        BEFORE UPDATE ON command_idempotency
        BEGIN SELECT RAISE(ABORT, 'command idempotency records are append-only'); END""",
    """CREATE TRIGGER command_idempotency_no_delete
        BEFORE DELETE ON command_idempotency
        BEGIN SELECT RAISE(ABORT, 'command idempotency records are append-only'); END""",
    """CREATE TRIGGER run_schedules_no_update
        BEFORE UPDATE ON run_schedules
        BEGIN SELECT RAISE(ABORT, 'run schedules are append-only'); END""",
    """CREATE TRIGGER run_schedules_no_delete
        BEFORE DELETE ON run_schedules
        BEGIN SELECT RAISE(ABORT, 'run schedules are append-only'); END""",
    """CREATE TRIGGER run_lanes_no_update
        BEFORE UPDATE ON run_lanes
        BEGIN SELECT RAISE(ABORT, 'run lane policies are append-only'); END""",
    """CREATE TRIGGER run_lanes_no_delete
        BEFORE DELETE ON run_lanes
        BEGIN SELECT RAISE(ABORT, 'run lane policies are append-only'); END""",
    """CREATE TRIGGER assignments_no_update
        BEFORE UPDATE ON assignments
        BEGIN SELECT RAISE(ABORT, 'assignments are append-only'); END""",
    """CREATE TRIGGER assignments_no_delete
        BEFORE DELETE ON assignments
        BEGIN SELECT RAISE(ABORT, 'assignments are append-only'); END""",
    """CREATE TRIGGER run_queue_no_update
        BEFORE UPDATE ON run_queue
        BEGIN SELECT RAISE(ABORT, 'run queue entries are append-only'); END""",
    """CREATE TRIGGER run_queue_no_delete
        BEFORE DELETE ON run_queue
        BEGIN SELECT RAISE(ABORT, 'run queue entries are append-only'); END""",
    """CREATE TRIGGER evidence_facts_no_update
        BEFORE UPDATE ON evidence_facts
        BEGIN SELECT RAISE(ABORT, 'evidence facts are append-only'); END""",
    """CREATE TRIGGER evidence_facts_no_delete
        BEFORE DELETE ON evidence_facts
        BEGIN SELECT RAISE(ABORT, 'evidence facts are append-only'); END""",
    """CREATE TRIGGER evidence_no_update
        BEFORE UPDATE ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END""",
    """CREATE TRIGGER evidence_no_delete
        BEFORE DELETE ON evidence
        BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END""",
    """CREATE TRIGGER evidence_inputs_no_update
        BEFORE UPDATE ON evidence_inputs
        BEGIN SELECT RAISE(ABORT, 'evidence inputs are append-only'); END""",
    """CREATE TRIGGER evidence_inputs_no_delete
        BEFORE DELETE ON evidence_inputs
        BEGIN SELECT RAISE(ABORT, 'evidence inputs are append-only'); END""",
    """CREATE TRIGGER evidence_artifacts_no_update
        BEFORE UPDATE ON evidence_artifacts
        BEGIN SELECT RAISE(ABORT, 'evidence artifacts are append-only'); END""",
    """CREATE TRIGGER evidence_artifacts_no_delete
        BEFORE DELETE ON evidence_artifacts
        BEGIN SELECT RAISE(ABORT, 'evidence artifacts are append-only'); END""",
    """CREATE TRIGGER outcome_candidates_no_delete
        BEFORE DELETE ON outcome_candidates
        BEGIN SELECT RAISE(ABORT, 'outcome candidates are append-only'); END""",
    """CREATE TRIGGER outcome_candidates_transition_guard
        BEFORE UPDATE ON outcome_candidates
        WHEN NOT (
            OLD.state = 'pending'
            AND NEW.state IN ('accepted', 'rejected')
            AND NEW.candidate_id = OLD.candidate_id
            AND NEW.attempt_id = OLD.attempt_id
            AND NEW.work_item_id = OLD.work_item_id
            AND NEW.definition_revision_id = OLD.definition_revision_id
            AND NEW.disposition = OLD.disposition
            AND NEW.note IS OLD.note
            AND NEW.report_source_json = OLD.report_source_json
            AND NEW.report_receipt_json = OLD.report_receipt_json
            AND NEW.reported_by_actor_id = OLD.reported_by_actor_id
            AND NEW.reported_by_incarnation_id = OLD.reported_by_incarnation_id
            AND NEW.reported_at = OLD.reported_at
            AND ((NEW.state = 'accepted' AND NEW.outcome_id IS NOT NULL)
                 OR (NEW.state = 'rejected' AND NEW.outcome_id IS NULL))
        )
        BEGIN SELECT RAISE(ABORT, 'outcome candidate transition is invalid'); END""",
    """CREATE TRIGGER outcome_provenance_no_update
        BEFORE UPDATE ON outcome_provenance
        BEGIN SELECT RAISE(ABORT, 'outcome provenance is immutable'); END""",
    """CREATE TRIGGER outcome_provenance_no_delete
        BEFORE DELETE ON outcome_provenance
        BEGIN SELECT RAISE(ABORT, 'outcome provenance is immutable'); END""",
    """CREATE TABLE context_finding_versions (
        finding_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version > 0),
        work_item_id TEXT NOT NULL,
        definition_revision_id TEXT NOT NULL,
        plan_revision_id TEXT NOT NULL,
        run_id TEXT,
        assignment_id TEXT,
        attempt_id TEXT,
        summary TEXT NOT NULL,
        source_manifest_digest TEXT NOT NULL CHECK (
            length(source_manifest_digest) = 64 AND source_manifest_digest NOT GLOB '*[^0-9a-f]*'
        ),
        source_fragments_json TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision > 0),
        created_at TEXT NOT NULL,
        PRIMARY KEY (finding_id, version),
        CHECK ((run_id IS NULL AND assignment_id IS NULL AND attempt_id IS NULL)
            OR (run_id IS NOT NULL AND assignment_id IS NOT NULL AND attempt_id IS NOT NULL)),
        FOREIGN KEY (work_item_id, definition_revision_id)
            REFERENCES work_items(work_item_id, definition_revision_id),
        FOREIGN KEY (plan_revision_id) REFERENCES plan_revisions(plan_revision_id),
        FOREIGN KEY (run_id) REFERENCES runs(run_id),
        FOREIGN KEY (assignment_id) REFERENCES assignments(assignment_id),
        FOREIGN KEY (attempt_id) REFERENCES attempts(attempt_id),
        FOREIGN KEY (actor_id, actor_incarnation_id) REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE INDEX context_finding_versions_scope
        ON context_finding_versions(work_item_id, definition_revision_id, run_id, assignment_id, attempt_id,
                                    finding_id, version)""",
    """CREATE TABLE context_finding_invalidations (
        finding_id TEXT NOT NULL,
        finding_version INTEGER NOT NULL,
        reason TEXT NOT NULL,
        source_manifest_digest TEXT NOT NULL CHECK (
            length(source_manifest_digest) = 64 AND source_manifest_digest NOT GLOB '*[^0-9a-f]*'
        ),
        source_fragments_json TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        actor_incarnation_id TEXT NOT NULL,
        semantic_revision INTEGER NOT NULL CHECK (semantic_revision > 0),
        created_at TEXT NOT NULL,
        PRIMARY KEY (finding_id, finding_version),
        FOREIGN KEY (finding_id, finding_version)
            REFERENCES context_finding_versions(finding_id, version),
        FOREIGN KEY (actor_id, actor_incarnation_id) REFERENCES actors(actor_id, incarnation_id)
    )""",
    """CREATE TRIGGER context_finding_versions_no_update
        BEFORE UPDATE ON context_finding_versions
        BEGIN SELECT RAISE(ABORT, 'context finding versions are append-only'); END""",
    """CREATE TRIGGER context_finding_versions_no_delete
        BEFORE DELETE ON context_finding_versions
        BEGIN SELECT RAISE(ABORT, 'context finding versions are append-only'); END""",
    """CREATE TRIGGER context_finding_invalidations_no_update
        BEFORE UPDATE ON context_finding_invalidations
        BEGIN SELECT RAISE(ABORT, 'context finding invalidations are append-only'); END""",
    """CREATE TRIGGER context_finding_invalidations_no_delete
        BEFORE DELETE ON context_finding_invalidations
        BEGIN SELECT RAISE(ABORT, 'context finding invalidations are append-only'); END""",
)


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE (type = 'index' AND name GLOB 'sqlite_autoindex_*') OR substr(name, 1, 7) <> 'sqlite_' "
        "ORDER BY type, name, tbl_name"
    ).fetchall()
    return tuple(tuple(row) for row in rows)


def _compile_schema_signature() -> tuple[tuple[object, ...], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        return _schema_signature(connection)
    finally:
        connection.close()


# Schema v20 is frozen. Compare SQLite definitions with a signature compiled
# once from the trusted source DDL rather than validating table names alone.
_SCHEMA_SIGNATURE = _compile_schema_signature()

_REQUIRED_TABLES = frozenset({
    "authority_meta", "plan_revisions", "plan_revision_snapshots", "work_items", "plan_revision_work_items",
    "work_item_supersessions", "requirements", "requirement_groups", "requirement_group_members",
    "actors", "runs", "assignments", "run_schedules", "run_lanes", "run_queue",
    "attempts", "capabilities", "capability_tokens",
    "local_owner_credentials", "capability_actions",
    "attempt_capabilities", "attempt_workspace_qualifications", "attempt_scope_snapshots",
    "child_executions", "child_candidates", "child_candidate_reviews", "child_cancellations",
    "child_stop_observations",
    "artifacts", "evidence", "evidence_inputs", "evidence_artifacts", "evidence_facts",
    "outcomes", "outcome_evidence", "outcome_candidates", "outcome_provenance",
    "external_operations", "git_effect_operations", "verification_attempts", "resource_permit_operations", "authority_events",
    "declaration_facts", "coordination_messages", "coordination_message_recipients",
    "coordination_message_cursors",
    "context_finding_versions", "context_finding_invalidations",
    "command_receipts", "command_idempotency",
})


def _project_identity(project: Project) -> tuple[str, str]:
    if not isinstance(project, Project):
        raise TypeError("project must be a contracts.Project")
    return str(project.project_id), str(project.authority_id)


def _snapshot_envelope(record: PlanRevisionSnapshotRecord) -> dict[str, Any]:
    value = _canonical_json_object(record.canonical_json, "accepted plan snapshot")
    expected = {
        "format", "schema_version", "authority_id", "project_id", "semantic_revision",
        "plan_revision_id", "based_on_revision_id", "effective_plan",
    }
    if set(value) != expected:
        raise ValueError("accepted plan snapshot has unsupported or missing envelope fields")
    if value["format"] != "todo-orchestrator.accepted-snapshot" or value["schema_version"] != 1:
        raise ValueError("accepted plan snapshot format or schema version is unsupported")
    if not isinstance(value["effective_plan"], dict):
        raise ValueError("accepted plan snapshot effective_plan must be an object")
    for key in ("authority_id", "project_id", "plan_revision_id"):
        if not isinstance(value[key], str):
            raise ValueError(f"accepted plan snapshot {key} must be a string")
        StableId(value[key])
    if value["plan_revision_id"] != str(record.plan_revision_id):
        raise ValueError("accepted plan snapshot identity does not match its record")
    based_on = value["based_on_revision_id"]
    if based_on is not None:
        if not isinstance(based_on, str):
            raise ValueError("accepted plan snapshot based_on_revision_id must be a string or null")
        StableId(based_on)
        if based_on == value["plan_revision_id"]:
            raise ValueError("accepted plan snapshot cannot be based on itself")
    if type(value["semantic_revision"]) is not int or value["semantic_revision"] < 1:
        raise ValueError("accepted plan snapshot semantic_revision must be a positive integer")
    return value


def _qualified_ref(value: Any, name: str) -> tuple[str, str, str, str | None, str | None]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a qualified reference object")
    allowed = {"project_id", "kind", "entity_id", "revision_id", "incarnation_id", "adoption_receipt"}
    required = {"project_id", "kind", "entity_id", "revision_id", "incarnation_id"}
    if not required <= set(value) or set(value) - allowed:
        raise ValueError(f"{name} has unsupported or missing qualified-reference fields")
    project_id = value["project_id"]
    kind_value = value["kind"]
    entity_id = value["entity_id"]
    revision_id = value["revision_id"]
    incarnation_id = value["incarnation_id"]
    if not all(isinstance(item, str) for item in (project_id, kind_value, entity_id)):
        raise ValueError(f"{name} project_id, kind, and entity_id must be strings")
    StableId(project_id)
    StableId(entity_id)
    try:
        kind = EntityKind(kind_value)
    except ValueError as exc:
        raise ValueError(f"{name} has an unknown entity kind") from exc
    if revision_id is not None:
        if not isinstance(revision_id, str):
            raise ValueError(f"{name} revision_id must be a string or null")
        StableId(revision_id)
    if incarnation_id is not None:
        if not isinstance(incarnation_id, str):
            raise ValueError(f"{name} incarnation_id must be a string or null")
        StableId(incarnation_id)
    if (kind in {EntityKind.WORK_ITEM, EntityKind.REQUIREMENT}) != (revision_id is not None):
        raise ValueError(f"{name} has an invalid definition-revision qualification")
    if (kind is EntityKind.ACTOR) != (incarnation_id is not None):
        raise ValueError(f"{name} has an invalid actor-incarnation qualification")
    return project_id, kind.value, entity_id, revision_id, incarnation_id


def _bundle_projection(record: DefinitionVersionRecord, local_project_id: str) -> dict[str, Any]:
    bundle = _canonical_json_object(record.canonical_json, "work definition bundle")
    if bundle.get("format") != "todo-orchestrator.work-bundle" or bundle.get("schema_version") != 1:
        raise ValueError("work definition bundle format or schema version is unsupported")
    if bundle.get("work_item_id") != str(record.entity_id) or bundle.get("definition_revision_id") != str(record.definition_revision_id):
        raise ValueError("work definition bundle identity does not match its version record")
    work = bundle.get("work")
    requirements = bundle.get("requirements")
    blockers = bundle.get("outgoing_blockers")
    if not isinstance(work, dict) or not isinstance(requirements, dict) or not isinstance(blockers, list):
        raise ValueError("work definition bundle must contain work, requirements, and outgoing_blockers")
    if work.get("id") != str(record.entity_id) or not isinstance(work.get("title"), str) or not isinstance(work.get("outcome"), str):
        raise ValueError("work definition bundle has invalid normalized title or outcome")

    parent = work.get("parent_ref")
    parent_id = None
    parent_revision = None
    if parent is not None:
        parent_project, parent_kind, parent_id, parent_revision, _ = _qualified_ref(parent, "work.parent_ref")
        if parent_project != local_project_id or parent_kind != EntityKind.WORK_ITEM.value or parent_revision is None:
            raise ValueError("work.parent_ref must identify a versioned work item")
        if work.get("parent_id") != parent_id:
            raise ValueError("work.parent_id and work.parent_ref disagree")
    elif work.get("parent_id") is not None:
        raise ValueError("work.parent_id requires the exact work.parent_ref")

    supersedes = work.get("supersedes")
    groups = work.get("requirement_groups")
    if not isinstance(supersedes, list) or not isinstance(groups, list):
        raise ValueError("work definition bundle supersedes and requirement_groups must be arrays")
    superseded_refs = []
    for index, ref in enumerate(supersedes):
        ref_project_id, kind, entity_id, revision_id, incarnation_id = _qualified_ref(ref, f"work.supersedes[{index}]")
        if ref_project_id != local_project_id or kind != EntityKind.WORK_ITEM.value or revision_id is None or incarnation_id is not None:
            raise ValueError("work.supersedes entries must be versioned work-item references")
        superseded_refs.append((ref_project_id, entity_id, revision_id))

    normalized_requirements = []
    seen_requirement_ids = set()
    for key, requirement in sorted(requirements.items()):
        if not isinstance(key, str) or not isinstance(requirement, dict):
            raise ValueError("work definition requirements must map ids to objects")
        requirement_id = requirement.get("id")
        if requirement_id != key or requirement.get("work_item_id") != str(record.entity_id):
            raise ValueError("requirement identity or owner does not match its work bundle")
        StableId(requirement_id)
        if requirement_id in seen_requirement_ids:
            raise ValueError("work definition bundle repeats a requirement id")
        seen_requirement_ids.add(requirement_id)
        kind = requirement.get("kind")
        description = requirement.get("description")
        target = requirement.get("target")
        check_key = requirement.get("check_key")
        verification = requirement.get("verification")
        required_evidence = requirement.get("required_evidence", [])
        if not isinstance(description, str):
            raise ValueError("requirement description must be a string")
        if kind == "prerequisite":
            if not isinstance(target, dict) or check_key is not None:
                raise ValueError("prerequisite requirement must have a target and no check_key")
            target_project, target_kind, target_id, target_revision, target_incarnation = _qualified_ref(
                target, f"requirement {requirement_id} target"
            )
            if target_kind not in {"work_item", "checkpoint", "interface", "barrier", "decision"}:
                raise ValueError("prerequisite target kind is unsupported")
            if target_kind == "work_item" and target_revision is None:
                raise ValueError("work-item prerequisite target must include its exact definition revision")
            if target_kind != "work_item" and target_revision is not None:
                raise ValueError("non-work prerequisite target cannot include a definition revision")
            if target_incarnation is not None:
                raise ValueError("prerequisite targets cannot be actor incarnations")
        elif kind == "check":
            if target is not None or not isinstance(check_key, str):
                raise ValueError("check requirement must have a check_key and no target")
            StableId(check_key)
            target_project = target_kind = target_id = target_revision = None
        else:
            raise ValueError("requirement kind must be prerequisite or check")
        if verification is not None:
            normalized_verification = VerificationContract.from_mapping(verification).to_mapping()
            if normalized_verification != verification:
                raise ValueError("verification contract must use its canonical normalized shape")
        else:
            normalized_verification = None
        if not isinstance(required_evidence, list):
            raise ValueError("required_evidence must be an array")
        normalized_evidence = [EvidenceRequirement.from_mapping(value).to_mapping() for value in required_evidence]
        if normalized_evidence != required_evidence or len({item["name"] for item in normalized_evidence}) != len(normalized_evidence):
            raise ValueError("required_evidence must use canonical unique typed entries")
        if normalized_evidence and normalized_verification is None:
            raise ValueError("required evidence must be bound to a verification contract")
        verification_json = json.dumps(normalized_verification, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        required_evidence_json = json.dumps(normalized_evidence, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        normalized_requirements.append({
            "id": requirement_id,
            "kind": kind,
            "description": description,
            "target_project_id": target_project,
            "target_kind": target_kind,
            "target_entity_id": target_id,
            "target_definition_revision_id": target_revision,
            "check_key": check_key,
            "verification_json": verification_json,
            "required_evidence_json": required_evidence_json,
        })

    normalized_groups = []
    grouped_ids = set()
    for ordinal, group in enumerate(groups):
        if not isinstance(group, dict) or not isinstance(group.get("members"), list):
            raise ValueError("requirement groups must contain a member list")
        kind = group.get("kind")
        mode = group.get("mode")
        quorum = group.get("quorum")
        members = group["members"]
        if kind not in {"prerequisite", "check"} or mode not in {"all", "any", "quorum"}:
            raise ValueError("requirement group kind or mode is unsupported")
        if not members or any(not isinstance(item, str) for item in members) or len(set(members)) != len(members):
            raise ValueError("requirement group members must be non-empty unique requirement ids")
        if mode == "quorum":
            if type(quorum) is not int or not 1 <= quorum <= len(members):
                raise ValueError("requirement quorum is outside the group size")
        elif quorum is not None:
            raise ValueError("non-quorum requirement group cannot store a quorum")
        for member in members:
            req = next((item for item in normalized_requirements if item["id"] == member), None)
            if req is None or req["kind"] != kind or member in grouped_ids:
                raise ValueError("requirement group member is missing, wrong-kind, or repeated")
            grouped_ids.add(member)
        normalized_groups.append({"ordinal": ordinal, "kind": kind, "mode": mode,
                                  "quorum": quorum, "members": tuple(members)})

    return {
        "work": work,
        "title": work["title"],
        "outcome": work["outcome"],
        "parent_work_item_id": parent_id,
        "parent_definition_revision_id": parent_revision,
        "supersedes": tuple(superseded_refs),
        "requirements": tuple(normalized_requirements),
        "groups": tuple(normalized_groups),
    }


def _snapshot_membership(value: Mapping[str, Any]) -> dict[str, str]:
    effective = value["effective_plan"]
    refs = effective.get("definition_refs")
    if not isinstance(refs, dict) or not isinstance(refs.get("work_items"), dict):
        raise ValueError("accepted snapshot effective_plan must contain definition_refs.work_items")
    result = refs["work_items"]
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in result.items()):
        raise ValueError("accepted snapshot work definition refs must map work-item ids to revision ids")
    for key, item in result.items():
        StableId(key)
        StableId(item)
    return dict(result)


def _validate_snapshot_record(
    record: PlanRevisionSnapshotRecord,
    project: Project,
    *,
    sequence: int = 1,
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    envelope = _snapshot_envelope(record)
    project_id, authority_id = _project_identity(project)
    if envelope["project_id"] != project_id or envelope["authority_id"] != authority_id:
        raise ValueError("accepted snapshot project or authority identity does not match")
    refs = _snapshot_membership(envelope)
    expected_refs = {str(item.work_item_id): str(item.definition_revision_id) for item in record.work_items}
    if refs != expected_refs:
        raise ValueError("accepted snapshot definition_refs do not match typed membership records")
    projections = {}
    for definition in record.definitions:
        key = (str(definition.entity_id), str(definition.definition_revision_id))
        projections[key] = _bundle_projection(definition, project_id)
    if set(projections) != {(str(item.work_item_id), str(item.definition_revision_id)) for item in record.work_items}:
        raise ValueError("accepted snapshot bundles do not exactly match its selected work versions")
    requirements = envelope["effective_plan"].get("definition_refs", {}).get("requirements")
    if requirements is not None:
        if not isinstance(requirements, dict):
            raise ValueError("accepted snapshot requirement definition refs must be an object")
        expected_requirements = {
            item["id"]: key[1]
            for key, projection in projections.items()
            for item in projection["requirements"]
        }
        if requirements != expected_requirements:
            raise ValueError("accepted snapshot requirement refs do not match their owning work versions")

    # Reconstruct the accepted typed plan and re-derive every work bundle from
    # its actual authored fields. This binds the full snapshot (scope, gates,
    # ownership, adoption facts, and declarations included) to the version
    # registry instead of trusting caller-provided digest metadata alone.
    from todo_orchestrator.planning.snapshot import (
        accepted_plan_payload,
        decode_accepted_plan,
        definition_bundle_payloads,
    )
    decoded = decode_accepted_plan(record.canonical_json, project, sequence=sequence)
    if accepted_plan_payload(decoded) != envelope["effective_plan"]:
        raise ValueError("accepted snapshot effective plan does not round-trip through its typed codec")
    decoded_bundles = {
        (item["entity_id"], item["definition_revision_id"]): (item["canonical_json"], item["content_digest"])
        for item in definition_bundle_payloads(decoded)
    }
    supplied_bundles = {
        (str(item.entity_id), str(item.definition_revision_id)): (item.canonical_json, item.content_digest)
        for item in record.definitions
    }
    if decoded_bundles != supplied_bundles:
        raise ValueError("accepted snapshot work bundles do not match its complete typed plan")
    return envelope, projections


def _verify_definition_projection(
    connection: sqlite3.Connection,
    record: DefinitionVersionRecord,
    projection: Mapping[str, Any],
) -> None:
    key = (str(record.entity_id), str(record.definition_revision_id))
    row = connection.execute(
        "SELECT title, outcome, parent_work_item_id, parent_definition_revision_id, canonical_json, content_digest "
        "FROM work_items WHERE work_item_id = ? AND definition_revision_id = ?", key,
    ).fetchone()
    if row is None or tuple(row) != (
        projection["title"], projection["outcome"], projection["parent_work_item_id"],
        projection["parent_definition_revision_id"], record.canonical_json, record.content_digest,
    ):
        raise InvalidAuthorityError("stored work definition version does not match its canonical bundle")

    requirements = connection.execute(
        "SELECT requirement_id, kind, description, target_project_id, target_kind, target_entity_id, "
        "target_definition_revision_id, check_key, verification_json, required_evidence_json FROM requirements "
        "WHERE work_item_id = ? AND definition_revision_id = ? ORDER BY requirement_id", key,
    ).fetchall()
    expected_requirements = tuple(
        (item["id"], item["kind"], item["description"], item["target_project_id"], item["target_kind"],
         item["target_entity_id"], item["target_definition_revision_id"], item["check_key"],
         item["verification_json"], item["required_evidence_json"])
        for item in projection["requirements"]
    )
    if tuple(tuple(row) for row in requirements) != expected_requirements:
        raise InvalidAuthorityError("stored normalized requirements do not match their canonical work bundle")

    groups = connection.execute(
        "SELECT group_ordinal, kind, mode, quorum FROM requirement_groups "
        "WHERE work_item_id = ? AND definition_revision_id = ? ORDER BY group_ordinal", key,
    ).fetchall()
    expected_groups = tuple(
        (group["ordinal"], group["kind"], group["mode"], group["quorum"])
        for group in projection["groups"]
    )
    if tuple(tuple(row) for row in groups) != expected_groups:
        raise InvalidAuthorityError("stored requirement groups do not match their canonical work bundle")
    members = connection.execute(
        "SELECT group_ordinal, member_ordinal, requirement_id FROM requirement_group_members "
        "WHERE work_item_id = ? AND definition_revision_id = ? ORDER BY group_ordinal, member_ordinal", key,
    ).fetchall()
    expected_members = tuple(
        (group["ordinal"], member_ordinal, requirement_id)
        for group in projection["groups"]
        for member_ordinal, requirement_id in enumerate(group["members"])
    )
    if tuple(tuple(row) for row in members) != expected_members:
        raise InvalidAuthorityError("stored requirement group members do not match their canonical work bundle")

    supersessions = connection.execute(
        "SELECT superseded_work_item_id, superseded_definition_revision_id FROM work_item_supersessions "
        "WHERE work_item_id = ? AND definition_revision_id = ? "
        "ORDER BY superseded_work_item_id, superseded_definition_revision_id", key,
    ).fetchall()
    expected_supersessions = tuple(sorted(
        ((item[1], item[2]) for item in projection["supersedes"]),
    ))
    if tuple(tuple(row) for row in supersessions) != expected_supersessions:
        raise InvalidAuthorityError("stored work-item supersessions do not match their canonical work bundle")


def load_plan_revision_snapshot(
    connection: sqlite3.Connection,
    project: Project,
    revision_id: StableId | str,
) -> PlanRevisionSnapshotRecord:
    """Load and cross-validate an accepted snapshot, membership, and version registry.

    Call this inside a consistent reader transaction or an existing writer
    transaction. It never creates, migrates, repairs, or silently normalizes
    authority data.
    """

    if not isinstance(project, Project):
        raise TypeError("project must be a contracts.Project")
    revision_text = str(revision_id)
    try:
        StableId(revision_text)
        row = connection.execute(
            "SELECT plan_revision_id, sequence, based_on_revision_id, state, content_digest "
            "FROM plan_revisions WHERE plan_revision_id = ?", (revision_text,),
        ).fetchone()
        snapshot = connection.execute(
            "SELECT canonical_json, snapshot_digest FROM plan_revision_snapshots WHERE plan_revision_id = ?",
            (revision_text,),
        ).fetchone()
        if row is None or snapshot is None or row["state"] != "accepted":
            raise InvalidAuthorityError("accepted plan revision or its immutable snapshot is missing")
        stored_json = snapshot["canonical_json"]
        stored_digest = snapshot["snapshot_digest"]
        _validate_canonical_digest(stored_json, stored_digest, "stored accepted plan snapshot")
        if row["content_digest"] != stored_digest:
            raise InvalidAuthorityError("accepted plan row digest does not match its immutable snapshot")
        envelope = _canonical_json_object(stored_json, "stored accepted plan snapshot")
        if envelope.get("plan_revision_id") != revision_text:
            raise InvalidAuthorityError("accepted plan snapshot revision identity is inconsistent")
        if envelope.get("based_on_revision_id") != row["based_on_revision_id"]:
            raise InvalidAuthorityError("accepted plan snapshot parent revision is inconsistent")
        if (envelope.get("project_id") != str(project.project_id)
                or envelope.get("authority_id") != str(project.authority_id)):
            raise InvalidAuthorityError("accepted plan snapshot project or authority identity does not match")
        memberships = connection.execute(
            "SELECT work_item_id, definition_revision_id FROM plan_revision_work_items "
            "WHERE plan_revision_id = ? ORDER BY work_item_id", (revision_text,),
        ).fetchall()
        membership_pairs = tuple((item["work_item_id"], item["definition_revision_id"]) for item in memberships)
        snapshot_refs = _snapshot_membership(envelope)
        if snapshot_refs != {work_id: def_id for work_id, def_id in membership_pairs}:
            raise InvalidAuthorityError("stored plan membership does not match the accepted snapshot refs")

        definitions = []
        projections = []
        for work_id, definition_revision_id in membership_pairs:
            version = connection.execute(
                "SELECT canonical_json, content_digest FROM work_items "
                "WHERE work_item_id = ? AND definition_revision_id = ?",
                (work_id, definition_revision_id),
            ).fetchone()
            if version is None:
                raise InvalidAuthorityError("accepted plan selects a missing work definition version")
            definition = DefinitionVersionRecord(
                StableId(definition_revision_id), StableId(work_id), version["canonical_json"], version["content_digest"]
            )
            definitions.append(definition)
            projections.append(_bundle_projection(definition, str(project.project_id)))
        record = PlanRevisionSnapshotRecord(
            StableId(revision_text), stored_json, stored_digest,
            tuple(definitions), tuple(PlanWorkMembership(StableId(work_id), StableId(definition_revision_id))
                                      for work_id, definition_revision_id in membership_pairs),
            sequence=row["sequence"],
        )
        _validate_snapshot_record(record, project, sequence=row["sequence"])
        for definition, projection in zip(record.definitions, projections):
            _verify_definition_projection(connection, definition, projection)
        return record
    except InvalidAuthorityError:
        raise
    except (sqlite3.Error, TypeError, ValueError, KeyError) as exc:
        raise InvalidAuthorityError(f"accepted plan snapshot is invalid: {exc}") from exc


def _insert_definition_projections(context: Any, record: DefinitionVersionRecord, projection: Mapping[str, Any]) -> None:
    work_id = str(record.entity_id)
    revision_id = str(record.definition_revision_id)
    for item in projection["supersedes"]:
        context.execute(
            "INSERT INTO work_item_supersessions(work_item_id, definition_revision_id, "
            "superseded_work_item_id, superseded_definition_revision_id) VALUES (?, ?, ?, ?)",
            (work_id, revision_id, item[1], item[2]),
        )
    for item in projection["requirements"]:
        context.execute(
            "INSERT INTO requirements(requirement_id, definition_revision_id, work_item_id, kind, description, "
            "target_project_id, target_kind, target_entity_id, target_definition_revision_id, check_key, "
            "verification_json, required_evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item["id"], revision_id, work_id, item["kind"], item["description"],
             item["target_project_id"], item["target_kind"], item["target_entity_id"],
             item["target_definition_revision_id"], item["check_key"], item["verification_json"],
             item["required_evidence_json"]),
        )
    for group in projection["groups"]:
        context.execute(
            "INSERT INTO requirement_groups(work_item_id, definition_revision_id, group_ordinal, kind, mode, quorum) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (work_id, revision_id, group["ordinal"], group["kind"], group["mode"], group["quorum"]),
        )
        for member_ordinal, requirement_id in enumerate(group["members"]):
            context.execute(
                "INSERT INTO requirement_group_members(work_item_id, definition_revision_id, group_ordinal, "
                "member_ordinal, requirement_id) VALUES (?, ?, ?, ?, ?)",
                (work_id, revision_id, group["ordinal"], member_ordinal, requirement_id),
            )


def store_plan_revision_snapshot(
    context: Any,
    record: PlanRevisionSnapshotRecord,
    *,
    based_on_revision_id: StableId | str | None = None,
) -> PlanRevisionSnapshotRecord:
    """Atomically persist one accepted canonical snapshot and its exact versions.

    This helper is valid only inside the dispatcher's active writer transaction.
    Exact work versions may be reused across plans only when their complete
    canonical bundle and every normalized projection match byte-for-byte.
    """

    authority = getattr(context, "authority", None)
    if not isinstance(record, PlanRevisionSnapshotRecord) or authority is None:
        raise TypeError("store_plan_revision_snapshot requires a MutationContext and typed snapshot record")
    if not getattr(authority, "write_transaction_active", False):
        raise AuthorityError("accepted plan snapshots must be stored inside an active writer transaction")
    if getattr(context, "project", None) != authority.project:
        raise AuthorityError("mutation context and authority project identities differ")
    envelope, projections = _validate_snapshot_record(record, authority.project)
    if record.sequence is not None:
        raise ValueError("sequence is allocated by the authority and cannot be supplied by the caller")
    expected_parent = envelope["based_on_revision_id"]
    if based_on_revision_id is not None and str(based_on_revision_id) != expected_parent:
        raise ValueError("based_on_revision_id does not match the canonical snapshot envelope")
    if envelope["semantic_revision"] != context.starting_revision + 1:
        raise AuthorityError("accepted snapshot semantic revision must be the command's next revision")
    connection = authority.connection
    meta = connection.execute("SELECT semantic_revision FROM authority_meta WHERE singleton = 1").fetchone()
    if meta is None or meta[0] != context.starting_revision:
        raise AuthorityError("mutation context does not match current authority revision")
    latest = connection.execute(
        "SELECT plan_revision_id FROM plan_revisions WHERE state = 'accepted' ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    latest_id = None if latest is None else latest["plan_revision_id"]
    if latest_id != expected_parent:
        raise AuthorityError("accepted snapshot parent is not the current accepted plan revision")
    if expected_parent is not None:
        load_plan_revision_snapshot(connection, authority.project, expected_parent)

    sequence_row = connection.execute("SELECT COALESCE(MAX(sequence), 0) + 1 FROM plan_revisions").fetchone()
    sequence = sequence_row[0]
    actor_id = str(context.actor.entity_id)
    incarnation_id = str(context.actor.incarnation_id)
    context.execute(
        "INSERT INTO plan_revisions(plan_revision_id, sequence, based_on_revision_id, state, source, "
        "content_digest, producer, authored_by_actor_id, authored_by_incarnation_id) "
        "VALUES (?, ?, ?, 'accepted', NULL, ?, NULL, ?, ?)",
        (str(record.plan_revision_id), sequence, expected_parent, record.snapshot_digest, actor_id, incarnation_id),
    )

    pending = {(str(item.entity_id), str(item.definition_revision_id)): item for item in record.definitions}
    new_versions: set[tuple[str, str]] = set()
    while pending:
        progressed = False
        for key in tuple(sorted(pending)):
            item = pending[key]
            projection = projections[key]
            existing = connection.execute(
                "SELECT title, outcome, parent_work_item_id, parent_definition_revision_id, canonical_json, content_digest "
                "FROM work_items WHERE work_item_id = ? AND definition_revision_id = ?", key,
            ).fetchone()
            if existing is not None:
                _verify_definition_projection(connection, item, projection)
                del pending[key]
                progressed = True
                continue
            parent_key = None
            if projection["parent_work_item_id"] is not None:
                parent_key = (projection["parent_work_item_id"], projection["parent_definition_revision_id"])
                parent_exists = connection.execute(
                    "SELECT 1 FROM work_items WHERE work_item_id = ? AND definition_revision_id = ?", parent_key,
                ).fetchone() is not None
                if not parent_exists and parent_key in pending:
                    continue
                if not parent_exists:
                    raise AuthorityError("work definition references a missing exact parent version")
            context.execute(
                "INSERT INTO work_items(work_item_id, definition_revision_id, title, outcome, parent_work_item_id, "
                "parent_definition_revision_id, canonical_json, content_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (key[0], key[1], projection["title"], projection["outcome"],
                 projection["parent_work_item_id"], projection["parent_definition_revision_id"],
                 item.canonical_json, item.content_digest),
            )
            new_versions.add(key)
            del pending[key]
            progressed = True
        if not progressed:
            raise AuthorityError("work definition parent references contain a cycle")

    for membership in record.work_items:
        context.execute(
            "INSERT INTO plan_revision_work_items(plan_revision_id, work_item_id, definition_revision_id) "
            "VALUES (?, ?, ?)",
            (str(record.plan_revision_id), str(membership.work_item_id), str(membership.definition_revision_id)),
        )

    for item in record.definitions:
        key = (str(item.entity_id), str(item.definition_revision_id))
        projection = projections[key]
        if key in new_versions:
            _insert_definition_projections(context, item, projection)
        else:
            _verify_definition_projection(connection, item, projection)

    context.execute(
        "INSERT INTO plan_revision_snapshots(plan_revision_id, canonical_json, snapshot_digest) VALUES (?, ?, ?)",
        (str(record.plan_revision_id), record.canonical_json, record.snapshot_digest),
    )
    return load_plan_revision_snapshot(connection, authority.project, record.plan_revision_id)


def _path(path: str | os.PathLike[str]) -> Path:
    try:
        raw = Path(os.fspath(path)).expanduser()
    except TypeError as exc:
        raise TypeError("path must be path-like") from exc
    if raw.is_symlink():
        raise InvalidAuthorityError("authority path must not be a symbolic link")
    absolute = Path(os.path.abspath(raw))
    if not absolute.parent.is_dir():
        raise FileNotFoundError(f"authority parent directory does not exist: {absolute.parent}")
    return absolute


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("busy_timeout must be a number of seconds")
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= MAX_BUSY_TIMEOUT_SECONDS:
        raise ValueError(f"busy_timeout must be finite and between 0 and {MAX_BUSY_TIMEOUT_SECONDS} seconds")
    return result


def _sync_directory(path: Path) -> None:
    """Ask the POSIX filesystem to make a published directory entry durable."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _connect(path: Path, mode: str, timeout: float) -> sqlite3.Connection:
    uri = f"{path.as_uri()}?mode={mode}"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=timeout, isolation_level=None)
    except sqlite3.Error as exc:
        if mode == "ro" and not path.exists():
            raise AuthorityNotFoundError(f"authority does not exist: {path}") from exc
        raise InvalidAuthorityError(f"cannot open authority at {path}: {exc}") from exc
    connection.row_factory = sqlite3.Row
    return connection


def _pragma_int(connection: sqlite3.Connection, name: str) -> int:
    row = connection.execute(f"PRAGMA {name}").fetchone()
    if row is None or type(row[0]) is not int:
        raise InvalidAuthorityError(f"authority has no valid PRAGMA {name}")
    return row[0]


def _validate(connection: sqlite3.Connection, project: Project) -> None:
    expected_project_id, expected_authority_id = _project_identity(project)
    try:
        application_id = _pragma_int(connection, "application_id")
        schema_version = _pragma_int(connection, "user_version")
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"cannot read SQLite authority identity: {exc}") from exc

    if application_id != APPLICATION_ID:
        raise InvalidAuthorityError("SQLite file is not a Todo Orchestrator authority")
    if schema_version != SCHEMA_VERSION:
        raise UnsupportedSchemaVersionError(
            f"authority schema version {schema_version} is unsupported; this package supports {SCHEMA_VERSION}"
        )

    try:
        row = connection.execute(
            "SELECT project_id, authority_id, semantic_revision FROM authority_meta WHERE singleton = 1"
        ).fetchone()
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority metadata is unreadable: {exc}") from exc
    if row is None:
        raise InvalidAuthorityError("authority metadata row is missing")
    if row["project_id"] != expected_project_id or row["authority_id"] != expected_authority_id:
        raise AuthorityIdentityMismatchError("authority project or authority identity does not match the requested project")
    if type(row["semantic_revision"]) is not int or row["semantic_revision"] < 0:
        raise InvalidAuthorityError("authority semantic revision is invalid")

    try:
        if _schema_signature(connection) != _SCHEMA_SIGNATURE:
            raise InvalidAuthorityError("authority schema does not match the frozen schema-v20 definition")
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority schema is unreadable: {exc}") from exc

    try:
        tables = frozenset(
            item[0]
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND substr(name, 1, 7) <> 'sqlite_'"
            )
        )
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority schema is unreadable: {exc}") from exc
    missing = _REQUIRED_TABLES - tables
    if missing:
        raise InvalidAuthorityError("authority schema is incomplete: " + ", ".join(sorted(missing)))
    try:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    except sqlite3.Error as exc:
        raise InvalidAuthorityError(f"authority journal mode is unreadable: {exc}") from exc
    if str(journal_mode).lower() != "wal":
        raise InvalidAuthorityError("authority is not using the required WAL journal mode")


def _configure(connection: sqlite3.Connection, *, readonly: bool, timeout: float) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
    if readonly:
        connection.execute("PRAGMA query_only = ON")
    # A new SQLite connection defaults to FULL. Do not issue a synchronous
    # write-affecting pragma here: it can wait behind another active writer.


class SQLiteAuthority:
    """One validated connection to one project-local authority.

    Connections are deliberately thread-confined by sqlite3. Open one writer
    connection per writer thread; SQLite serializes `BEGIN IMMEDIATE` writers
    while WAL readers retain a consistent snapshot.
    """

    def __init__(
        self,
        path: Path,
        project: Project,
        connection: sqlite3.Connection,
        *,
        readonly: bool,
    ) -> None:
        self.path = path
        self.project = project
        self.readonly = readonly
        self._connection = connection
        self._closed = False
        self._write_transaction_active = False

    @classmethod
    def initialize(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> None:
        """Create a new schema-v20 authority without replacing an existing path.

        The database is built in a private same-directory temporary file and
        published with an atomic hard link, so readers see either no authority
        or a fully committed one. Only this explicit method creates a database.
        """

        if os.name != "posix":
            raise UnsupportedAuthorityPlatformError(
                "authority initialization requires POSIX directory fsync support"
            )
        project_id, authority_id = _project_identity(project)
        timeout = _timeout(busy_timeout)
        destination = _path(path)
        if destination.exists() or destination.is_symlink():
            raise AuthorityAlreadyExistsError(f"authority already exists: {destination}")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.init-", suffix=".sqlite3", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect(temporary, "rw", timeout)
            connection.execute("PRAGMA foreign_keys = ON")
            journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise InvalidAuthorityError("SQLite refused WAL journal mode during initialization")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            connection.execute(
                "INSERT INTO authority_meta(singleton, project_id, authority_id, semantic_revision, created_at) "
                "VALUES (1, ?, ?, 0, ?)",
                (project_id, authority_id, created_at),
            )
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.execute("COMMIT")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise InvalidAuthorityError(f"new authority failed integrity check: {integrity}")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or checkpoint[0] != 0:
                raise InvalidAuthorityError("new authority could not checkpoint its initialization WAL")
            connection.close()
            connection = None

            # The hard link is atomic and refuses to replace a concurrent winner.
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise AuthorityAlreadyExistsError(f"authority already exists: {destination}") from exc
            try:
                _sync_directory(destination.parent)
            except OSError as exc:
                raise AuthorityPublicationDurabilityUncertainError(
                    f"authority was published at {destination}, but syncing its parent directory failed; "
                    f"publication durability is uncertain: {exc}"
                ) from exc
        except BaseException:
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                connection.close()
            raise
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(str(temporary) + suffix).unlink()
                except FileNotFoundError:
                    pass

    @classmethod
    def open_reader(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> SQLiteAuthority:
        """Open an existing authority using SQLite `mode=ro` and `query_only`."""

        timeout = _timeout(busy_timeout)
        authority_path = _path(path)
        if not authority_path.exists():
            raise AuthorityNotFoundError(f"authority does not exist: {authority_path}")
        connection = _connect(authority_path, "ro", timeout)
        try:
            _validate(connection, project)
            _configure(connection, readonly=True, timeout=timeout)
        except BaseException:
            connection.close()
            raise
        return cls(authority_path, project, connection, readonly=True)

    @classmethod
    def open_writer(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> SQLiteAuthority:
        """Open an existing authority for explicit write transactions.

        A read-only preflight validates application, schema, and project
        identity before a read-write connection is opened. Metadata is checked
        again on the writer connection before any write-affecting PRAGMA.
        """

        timeout = _timeout(busy_timeout)
        authority_path = _path(path)
        if not authority_path.exists():
            raise AuthorityNotFoundError(f"authority does not exist: {authority_path}")
        preflight = _connect(authority_path, "ro", timeout)
        try:
            _validate(preflight, project)
        finally:
            preflight.close()

        connection = _connect(authority_path, "rw", timeout)
        try:
            _validate(connection, project)
            _configure(connection, readonly=False, timeout=timeout)
            try:
                synchronous = _pragma_int(connection, "synchronous")
            except sqlite3.Error as exc:
                raise InvalidAuthorityError(f"cannot read writer SQLite synchronous mode: {exc}") from exc
            if synchronous != 2:  # SQLite defines 2 as FULL.
                raise InvalidAuthorityError("writer SQLite connection is not using FULL synchronous durability")
        except BaseException:
            connection.close()
            raise
        return cls(authority_path, project, connection, readonly=False)

    @classmethod
    def migrate(
        cls,
        path: str | os.PathLike[str],
        project: Project,
        *,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> MigrationResult:
        """Validate the current schema; no schema migration is implemented yet.

        Schema v18 is the only supported version. A current v18 authority is a
        no-op. Older versions and every other unsupported version are rejected
        without opening the file writable; this method never guesses a
        conversion or restores a backup.
        """

        with cls.open_reader(path, project, busy_timeout=busy_timeout) as authority:
            version = _pragma_int(authority.connection, "user_version")
        return MigrationResult(version, version)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._closed:
            raise AuthorityError("authority connection is closed")
        return self._connection

    @contextmanager
    def read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Hold a consistent SQLite read snapshot for a group of queries."""

        connection = self.connection
        if connection.in_transaction:
            raise AuthorityError("nested authority transactions are not supported")
        connection.execute("BEGIN")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Acquire SQLite's single-writer reservation and roll back on failure."""

        if self.readonly:
            raise ReadOnlyAuthorityError("cannot write through a read-only authority connection")
        connection = self.connection
        if connection.in_transaction:
            raise AuthorityError("nested authority transactions are not supported")
        connection.execute("BEGIN IMMEDIATE")
        self._write_transaction_active = True
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            self._write_transaction_active = False

    @property
    def write_transaction_active(self) -> bool:
        """Whether this connection holds the authority's explicit writer transaction."""
        return self._write_transaction_active

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteAuthority:
        if self._closed:
            raise AuthorityError("authority connection is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


__all__ = [
    "APPLICATION_ID",
    "SCHEMA_VERSION",
    "DefinitionVersionRecord",
    "PlanRevisionSnapshotRecord",
    "PlanWorkMembership",
    "DEFAULT_BUSY_TIMEOUT_SECONDS",
    "MAX_BUSY_TIMEOUT_SECONDS",
    "AuthorityAlreadyExistsError",
    "AuthorityError",
    "AuthorityIdentityMismatchError",
    "AuthorityNotFoundError",
    "InvalidAuthorityError",
    "MigrationResult",
    "ReadOnlyAuthorityError",
    "SQLiteAuthority",
    "UnsupportedAuthorityPlatformError",
    "UnsupportedSchemaVersionError",
    "load_plan_revision_snapshot",
    "store_plan_revision_snapshot",
]
