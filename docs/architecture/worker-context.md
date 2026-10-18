# Bounded worker context

`ContextService` derives a task context capsule from the exact accepted plan and
current authority facts. Capsules are read views, not persisted work briefs. A
manifest binds the exact plan revision, work-definition revision, optional
run/assignment/attempt tuple, and the ordered fragment IDs and digests. The
canonical source digest covers plan, work, assignment, declaration, and source
reference fragments. It excludes findings and event deltas, so publishing a
finding or adding unrelated events does not invalidate the source it cites.

`build_context()` requires `todo.context.read` for the exact work and supplied
context. Run, assignment, and attempt must be supplied together and must match
the scheduled work. A worker can read through its dispatch-derived grant. An
independent observer can read that same exact context with a separately
authorized `todo.context.read` grant; the observer does not impersonate the
attempt actor and gains no write actions. A grant for another work/context is
denied. The capsule includes authored objective, scope, acceptance, ownership,
references, exact run assignment details when requested, relevant native
declaration facts, metadata-only scoped event deltas, and authored findings.
Inbox messages, file bodies, raw logs, and transcripts are excluded.

Capsules are serialized as canonical compact UTF-8 JSON by
`serialize_context_capsule()`. `encoded_bytes` is the encoded byte count,
including the count field itself. The default limit is 16 KiB; requests are
bounded to 4–64 KiB. The limit includes the entire serialized envelope. If all
fragment bodies do not fit, the capsule is marked `partial` and returns omitted
typed references. In a verified 4096-byte-budget case, packing returned a
4071-byte partial capsule with the remaining fragment omitted.

`expand_fragment()` requires the omitted reference's expected digest and returns
`ready`, `stale`, or `unavailable`. A fragment that fits is returned whole. A
larger fragment is returned as bounded chunks: each ready response includes a
base64-encoded UTF-8 byte slice, its byte `offset`, `total_bytes`, a
`content_digest`, and `next_offset`. Request the next slice with that
`next_offset` until it is null; concatenate the decoded bytes in order and
verify their SHA-256 against `content_digest`. The expected digest identifies
the manifest fragment; for a reference-only fragment, `content_digest`
identifies the expanded content. The 2048-byte chunk target may shrink to fit
the complete serialized response envelope. One verified 10,505-byte expansion
completed in six bounded requests. Stale or unavailable responses carry no
content. Deltas are bounded metadata, ordered by semantic revision and event
ordinal. A `truncated` marker means the window is incomplete; it is not a
continuation cursor.

Context findings are authored facts, not capsule prose. `publish_finding()`
appends a version tied to the exact work/run/assignment/attempt and source
manifest, and requires typed references to exact source fragments. The writer
recomputes that source manifest before storing the finding. Findings can cite
only plan, work, assignment, declaration, or source-reference fragments, never
the findings or event-delta fragment. A later version preserves earlier
versions. `invalidate_finding()` appends a reason against one exact current
version; it does not erase or rewrite the finding. A refreshed capsule marks a
finding `stale_source` when any cited source fragment no longer has its recorded
digest.

Finding summaries and invalidation reasons pass through bounded checks for
common credential and uncontrolled-log shapes. This is a hygiene filter, not a
guarantee that arbitrary sensitive information will be detected.

The derived capsule and its manifest are not stored. SQLite schema v18 adds
append-only finding-version and finding-invalidation records. Existing schemas
v1–v17 are refused by this alpha build; no migration is provided. C04 passed its required coordination gate at development authority revision
135 and was accepted at revision 136. The integrated source suite passed 323
tests; three additional structural-credential/context regressions passed and
were included in the completion gate. Independent probes verified bounded
paging, source-version freshness, and message privacy. Subordinate execution
and the complete standalone worker workflow remain under development.

The manifest binds the requested `since_revision` cursor. Expansion accepts the
same cursor when reopening a delta fragment. A pathological structural envelope
that cannot fit reports `ContextUnavailableError.required_bytes` so the caller
can retry with a sufficient budget; it does not change task state.
