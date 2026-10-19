# Q01 parity matrix

`parity-matrix-v1.json` records the bounded source-to-standalone comparison for
TO-Q01. It separates classification from execution evidence: a selected legacy
test may pass without exercising every assertion in its fixture, and a native
counterpart listed here is not evidence unless it appears in a cited run.

The primary legacy reference is the `skills_dev` standalone package at commit
`bfa9238985dfeb2368bad076f1cc51bfdadbae92`, captured in
[`docs/product/reference-baseline.json`](../product/reference-baseline.json).
The separate vendored Project Control copy at
`fba161b1dc6ed4399c1a3818071eacdb9b80c17` is not combined with this corpus.
Both are preserved references; neither was modified by Q01.

The qualification worker ran eight selected legacy tests with the helper
`tests/v2_helpers.py::V2Repo`, which provisions temporary SQLite and Git state.
The checked-in [legacy corpus manifest](../../tests/qualification/legacy-corpus.v1.json)
pins the source revision, test IDs, and reference hashes; the isolated harness
runs each case in its own `-B -S` child interpreter. The exact command and
result are in the matrix. Other baseline fixtures remain explicitly partial or
unrun. Native counterpart tests were present in the accepted isolated 420-test
run recorded there; this is evidence for those assertions only, not blanket
behavioral parity. The Q01 documentation and corpus harness were added after
that native source manifest was captured.

Classifications mean:

- `retained`: the safety or user-visible property remains materially the same.
- `adapted`: the purpose remains, but the standalone contract or enforcement
  boundary is intentionally different.
- `unsupported`: the legacy behavior has no supported standalone equivalent in
  this v1 scope; this is not a promise to add it later.
- `excluded`: the operator explicitly removed the work from this standalone
  effort.

The explicit exclusions are legacy import (**TO-P05**), Project Control
rewiring/ingestion/cutover (**TO-I02**, **TO-I03**, **TO-Q04**), and product
Project Control integration/migration (**P-09**, **P-10**). Product P-05
delegation is in scope and is not the excluded TO-P05 importer.

This matrix is not a release sign-off, migration authorization, or claim that
the original tests were all run. It does not authorize touching the active
Project Control instance or any production authority.
