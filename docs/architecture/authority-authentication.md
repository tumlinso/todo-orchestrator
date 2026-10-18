# Authority authentication and capability grants

`AuthorityAuthService` is the public credential boundary for local authority
commands. A client presents a bearer token and typed command; the service gets
the actor incarnation from the token record. A registered command handler must
derive an `AuthorizationRequirement` from its private command snapshot. Client
role names and caller-constructed `Actor` values are not accepted as proof.

First use is an explicit one-time local owner enrollment. It is atomic and
revisioned through the dispatcher, and is allowed only while the authority has
no actors. The local process with write access to an unowned authority is the
bootstrap trust boundary. Its password is stored as a salted scrypt digest.
Owner login checks that credential and creates a fresh actor incarnation and a
finite, explicitly scoped root capability. A host may instead supply a trusted
`PrincipalAuthenticator` at service construction; the service trusts that
provider's authenticated subject, kind, and label. It does not treat an
`AuthenticatedPrincipal` created by a remote caller as authenticated.

Bearer tokens contain 256 bits of random material. SQLite stores only their
SHA-256 digests. `IssuedCapability` returns the plaintext once with its durable
receipt; events, receipt results, idempotency records, and the authority file
never contain that plaintext. If an exact issuance retry finds the durable
receipt, the API raises `CapabilityDeliveryUncertainError` and does not mint a
replacement secret for the original grant.

Delegation must narrow rights: child actions are a subset, context restrictions
are inherited or added, expiry is no later than the parent, the recipient is a
different actor, and scope is equal or narrower. Project scope may narrow to
any typed project-local scope; a plan-revision scope also covers work-item and
requirement definitions from that exact revision. Other scopes require an exact
qualified entity match. Readiness and authentication share this containment rule.
Family revocation
marks the selected grant and descendants in one transaction.

For authenticated commands, the dispatcher runs the service's read-only
authorization callback under `BEGIN IMMEDIATE` before idempotency replay. It
re-reads token digest, actor incarnation, revocation, expiry from the injected
current clock, action, scope, and run/assignment/attempt bindings. Refusal
therefore leaves semantic rows, revision, event, receipt, and idempotency state
unchanged, including on retries. The raw `CommandDispatcher.execute()` API is
trusted in-process infrastructure and deliberately bypasses this public auth
service; it must not be exposed to an untrusted client. Callers that need an
exact retry must reuse the original `expected_revision`; omitting it asks the
service to read the latest revision and makes a later call a different request.

Outcome APIs additionally use the narrow `replay_authorized` lookup for an
already recorded semantic request. It checks current actor, capability, scope
and context under the writer lock; the API then matches command kind and exact
stored report/finalization intent before exposing the original receipt. This
permits lost-response retries after terminal state or a stale original revision
without rerunning providers. Changed intent and revoked grants remain refused.

| Outcome action | Authority |
| --- | --- |
| `todo.outcome.report` | Attempt actor; dispatch may derive it only from a parent that grants it |
| `todo.outcome.accept` | Separately authorized acceptance actor |
| `todo.outcome.reject` | Separately authorized rejection actor |
| `todo.outcome.read` | Current scoped grant for external applicability observations |
| `todo.outcome.manual.<role>` | Additional grant for a selected manual criterion; exact authored human incarnation also required |

Manual roles are `owner`, `maintainer`, `reviewer` and `project_admin`. Acceptance,
rejection and manual-role actions are not automatically issued to a worker
session. A read uses its genuine grant reference; historical records cannot mint
provider authority.

This service establishes local principals and enforces grant lineage. Future
commands must still validate referenced entity existence, lifecycle state,
lease ownership, evidence policy, and operation-specific authorization scope.
Python composition and an injected authenticator are trust boundaries; this
module does not sandbox hostile code already executing in the engine process.
