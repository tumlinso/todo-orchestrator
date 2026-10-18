# Git provider checkpoint history

Commit `495f4e5` captured unfinished V04 development: the local Git provider,
physical workspace isolation records, schema 13 storage and Git fixtures were
preliminary. That checkpoint did not qualify native Git workflow execution or
overlapping admission.

Its remaining work included the authenticated durable Git effect service and its
command-kernel intent lifecycle, provider-facing independent verification, and
restart/reconciliation qualification. Source observation also needed to account for
index-only staged changes: the checkpoint filesystem comparison could miss staged
content when the working file has been restored to its committed contents.

Keep development claims serial and preserve dirty, staged, untracked and
conflicted content. No live Project Control or legacy authority changes are
part of this work.

Checkpoint validation: `PYTHONPATH=src python -S -m unittest discover -s tests
-p 'test_*.py'` ran 258 tests with 10 failures and 54 errors. Failures span the
unfinished Git provider, admission and attempt-dependent workflows; this
checkpoint was not a passing development baseline. The reference baseline,
derived-plan consistency and whitespace checks passed.

Subsequent development resolved these gaps. V04 closed at revision 123 after its
required gate passed, and the verification workstream closed at revision 125.
The integrated source suite passed 290 tests. Current behavior and coverage
limits are documented in [local Git effects](git-effects.md); the supported
native schema at V04 acceptance was 15. The historical failures above describe
the saved commit, not the accepted V04 baseline.

The next checkpoint also includes unfinished C03 declarations and messaging,
with native schema 17. C03 remains open; the full source suite has not been
requalified after these changes. Coordination checks and remaining issues are
recorded in the checkpoint commit message.
