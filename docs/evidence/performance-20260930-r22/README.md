# R22 Base DN validation qualification

Source baseline: `984ada3` (R21 production). Current source lives in
`/var/tmp/ldap-go-base-identity-20260930`. The production delta replaces Base
search's parsed physical-DN reconstruction with the existing error-equivalent
validator and an identity-key hint. Scope, filter, ACL and result selection
remain on the original path. No result caching, CGO or storage format change.

The baseline executable is `/var/tmp/ldap-go-perf-20260930-r21/current`, not R19
or the rejected R20 executable. The generic same-process SDK benchmark reuses
the R21 final test binary. Network scripts use the rebuilt pinned OpenLDAP
reference and recovered 100k fixture from R20.

## Evidence boundaries

- `base.cpu`, `base.mem` and `base-profile.txt` are baseline exploratory profiles.
  Profiling includes setup, index creation, SDK work and cleanup, so whole-profile
  percentages are not isolated server request cost. Handler stack filtering
  identified avoidable DN reconstruction.
- Three 1s alternating same-process network observations show Base allocations
  changing from 496 to 446 and bytes from about 25859 to 24382 per operation.
  Latency is variable; allocation savings are not proof of latency parity.
- All independent-server runs use seven 1000-call SDK batches on each endpoint.
  Calls rotate endpoints and verify LDAP results/identity. Default, explicit ACL
  and startup/port-swap remain separate.
- The original default run is preserved as `network-preliminary-default` because
  a brief `go tool pprof` report was generated during that run. It is excluded
  from final primary statistics. The replacement was decided for this scheduling
  contamination, not based on the direction of its measured results.
- `network-final-*` contains the designated final runs. The summary verifies
  756 completed batches and nine canonical exports only after all final runs
  complete. Canonical data excludes generated operational attributes and does
  not imply MDB layout identity or universal OpenLDAP compatibility.
- Compare and equality/Bind observations are unchanged-path sentinels. Only
  Base presence search changes its DN representation internally; other old
  group discovery, traversal, broad reads and writes are not rerun here.

Acceptance remains each common operation matching OpenLDAP. Faster writes do
not compensate for slower reads, and no universal speedup is claimed.

## Result

Final Base paired time reductions are 2.0% default, 1.2% explicit ACL, 1.5%
startup/port swap. Component Base handler times improve roughly 7%-10%, with
49 fewer allocations. The same-process SDK/server case removes 50 allocations
but has approximately flat median latency. Negative observations in other
operations remain in tables.md and summary.json, including the 5.6% slower
swap Group1000 missing comparison. No causality/no-regression claim is made.

Full tests pass (server 170.682s, schema 98.100s, storage 23.524s, webadmin 0.289s),
vet passes and all 355 native differential checks pass in 11.072s. New focused
tests pass on both the production baseline and candidate. The first focused
run failed due fixture expectations and callback-test plumbing; these test
errors were fixed without changing the production delta. Both logs are retained.

Final summary: 756 batches, 9 matching canonical exports. Preliminary-default
has 3 additional matching exports and is not pooled. Each export has 100002
entries, cksum 2143929969, 42712438 bytes. Physical MDB layout and generated
operational attributes are not asserted equal.

source-from-984ada3.patch reconstructs all three changed Go files. Component
baseline binary uses the R21 isolated source plus the same two new test files;
its production logic equals 984ada3. Actual production build metadata and
executable hashes are retained. JSON is gzip-compressed; decompress archived
JSON files before running summarize.mjs on an archive copy. Benchmark scripts
reference disposable local 100k seeds and the R20 rebuilt native environment;
see the R20 recovery evidence for provenance. SHA256SUMS covers all artifacts.

TCP input buffering remains an unrelated, unintegrated prototype in a separate
worktree. It is not part of this source reconstruction or qualification.

Validated isolated implementation commit: `4566990`; integrated main commit:
`baf3811`. Their changed Go files are identical. The measured production binary
was built before committing; build-current.txt preserves its actual metadata.
