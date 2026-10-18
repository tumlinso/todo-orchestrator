# Accepted plan revisions

A plan revision selects exact work-definition versions. The plan's identity
and sequence describe its place in accepted history; they do not require every
selected definition to have been created in that revision. A selective replan
retains unchanged definitions and their existing attempts, requirements, and
accepted outcomes.

One work-definition bundle contains the work's authored context, ownership,
scope, acceptance policy, owned requirements, and outgoing dependencies.
Changing a bundle creates a new definition version. An exact version must
never acquire a different scope, gate, dependency target, or parent binding.
Requirements share their owner's definition version. Supersession preserves
predecessor references; retirement removes current membership rather than
deleting historical records.

Compilation and change preview are pure. Preview consumes an explicit snapshot
and binds both the semantic authority revision and the accepted plan identity.
Initial import binds the absence of an accepted plan. Omitted records and
optional fields are preserved; retirement requires an explicit exact reference.
The final merged graph, including retained definitions, must remain valid.

Commit uses the authenticated command boundary. Under the same writer
transaction it checks the current authority and accepted-plan preconditions,
recomputes the reviewed changes, refuses conflicts, and writes normalized
definitions, exact membership, a complete canonical snapshot, and the command's
event, receipt, and idempotency record. A preview digest is an integrity
precondition, not authorization. Active or accepted work cannot be changed by
an unconditional upsert.

Accepted snapshots and definition bundles are canonical JSON with SHA-256
digests. Existing exact versions are reusable only when their stored meaning
matches. Reload reconstructs typed values; admission compares actual runtime
contents to the trusted stored snapshot rather than trusting a caller-supplied
digest field. Historical snapshots remain available after subsequent changes.

Exact command retries return their original receipt, subject to current
authentication. A new request whose intent makes no semantic change records a
no-op receipt without a new semantic revision or event. Reverting earlier
content after an intervening change is a new accepted revision, not an overwrite
of the earlier history.

These rules concern the standalone engine and disposable runtime fixtures.
They do not authorize importing or changing an existing Project Control or
legacy Todo authority.
