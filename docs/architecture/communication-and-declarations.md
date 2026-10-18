# Communication and declaration facts

Todo Orchestrator separates collaboration messages from authoritative workflow
facts. `MessagingService` stores scoped, append-only messages and questions;
`DeclarationService` records authorized decisions, interface publications,
checkpoint acceptances, barrier releases, rendezvous arrivals, and blocker
changes. A message labelled `decision` or `interface_change` is only an
informational notice. It does not resolve a decision, publish an interface,
or change readiness.

## Scoped communication

`MessagingService.send()` accepts typed message kinds `question`, `decision`,
`interface_change`, `status`, `artifact`, `conflict`, and `handoff`. `ask()` is
the question convenience method; `answer()` records at most one answer to an
existing question. Messages require explicit project-local actor-incarnation
recipients and an exact entity scope. Large or structured content can be
referenced by an artifact `EntityRef` and SHA-256 digest.

When a message has run context, reads and inbox cursors are partitioned by that
run. Assignments and attempts may differ within the same run, allowing workers
on separate assignments to collaborate. An unbound message belongs to a
separate run-free inbox. A capability must still authorize the caller's exact
scope and supplied context; recipient membership only grants delivery and
does not grant access to other work or actions. Questions and answers retain
their own sender contexts, and an answer must match the original question's
scope and run.

Inbox cursors are keyed by recipient actor incarnation, exact message scope,
and run (including `NULL` as the distinct unbound partition). Delivered and
read watermarks only move forward. A sync returns only messages after that
partition's delivered watermark; marking read requires a delivered message in
the same partition. Exact command retries return their original receipts.

Subjects and inline bodies have bounded size and pass a conservative guard for
common credential and uncontrolled-log shapes, including known issued bearer
tokens. This is not arbitrary-secret detection. Sensitive or large material
should use a separately governed artifact reference rather than inline text.

## Authoritative declarations

`DeclarationService` exposes separately authorized operations to resolve a
decision, publish an interface, accept a checkpoint, release a barrier, record
a rendezvous arrival, and open or clear a blocker. `load_plan_declaration()`
loads a declaration from the exact accepted plan snapshot. `SQLiteDeclarationObserver`
reports current native facts for an exact accepted declaration; missing or
inconsistent facts remain unknown. A declaration's presence or its producers'
completion alone does not prove that it was accepted, published, released, or
arrived.

Barrier release requires accepted outcomes for its exact participant definitions,
combined with the shared all/any/quorum evaluator. Each outcome must satisfy its
work definition's allowed dispositions; an explicitly permitted negative result
can count. Release authorization cannot bypass those conditions. Rendezvous
conditions instead combine explicit, authorized participant arrivals.
Barriers and rendezvous share the typed barrier reference namespace, so their
IDs must differ. Both reject duplicate qualified participants rather than
counting one participant multiple times toward a quorum.

Declaration facts are append-only and bind the accepted plan revision, typed
declaration identity, and declaration digest. A blocker affects readiness only
through its declared typed conditions. Messages do not write these facts and
do not alter admission state. The SQLite `declaration_facts` table and the
message tables therefore represent distinct records with distinct actions and
authorization paths.

The current SQLite schema is v17. Schema v16 introduced declaration facts and
scoped messages; schema v17 added run-partitioned inbox cursors. Initialization
and reopen support only the current schema; no v1-v16 migration is provided.
C03 passed its required coordination gate at development authority revision 130
and was accepted at revision 131. The integrated source suite passed 314 tests.
Independent fixture probes also exercised separate accept-only and read-only
principals, denied report-only observation, and verified cross-run cursor
isolation. These checks do not qualify live service integration, power-loss
recovery, or the unfinished standalone release.
