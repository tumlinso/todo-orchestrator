# Planning and admission safety model

The Q02 qualification adds a bounded, deterministic model check across plan
compilation, plan commit, advisory eligibility, transactional claim, capability
revocation, serial queue admission, and competing SQLite writers. It uses only
temporary authority files and the repository's existing test fixtures.

## Generated graph corpus

tests/qualification/test_safety_model.py enumerates every directed simple
dependency graph over three work items: all 512 edge sets, including self-edges.
It also generates 48 graphs with four to six work items using random.Random
seed 20261019. For each graph, an independent Kahn topological-sort oracle
classifies whether a cycle exists. The plan compiler must accept every DAG and
reject every cyclic graph with a blocking_cycle diagnostic.

This graph generator covers work-item completion dependencies. Cross-kind
cycles and containment rules have focused examples in
tests/planning/test_package.py; the generated oracle does not replace those
typed graph cases.

## Authority transition model

The plan-ingestion sequence commits a simple package, reverses its authored
work-item order, and checks that canonical-equivalent input is a no-op with no
semantic revision increase. It then captures a stale preview, commits a
competing semantic revision, and verifies that the stale commit is refused
without changing the authority fingerprint or revision. Replaying the exact
winning command returns the original receipt and leaves state unchanged.

The eligibility/admission sequence places two assignments on one serial lane.
It checks that the first assignment is advisory-allowed and claimable, then
that the second assignment is advisory-blocked and transactionally refused
with the same policy cause and no state churn. A delegated worker claims
disjoint work; after its capability family is revoked, advisory evaluation and
the claim entrypoint both refuse further use, and the failed claim makes no
authority change.

Finally, three independent processes start a claim for the same work item
against one temporary SQLite authority and one captured revision. Exactly one
may commit. Each loser must receive the typed admission or stale-revision
refusal, and the event, receipt, idempotency, attempt, and semantic-revision
counts must advance only for the winner.

## Running the qualification

Run the focused model tests with:

    PYTHONPATH=src:. python -S -m unittest tests.qualification.test_safety_model -v

Run the full qualification directory with:

    PYTHONPATH=src:. python -S -m unittest discover -s tests/qualification -p 'test_*.py' -v

These checks qualify the tested package inputs, service composition, and
SQLite concurrency on this Python/runtime environment. The exhaustive graph
space is intentionally small; the seeded larger cases and existing focused
tests provide additional shape diversity but are not a proof over arbitrary
graph sizes. The claim race uses independent processes and a temporary local
SQLite file; it does not claim qualification for network filesystems, arbitrary
provider behavior, or production deployment topology.
