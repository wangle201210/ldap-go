# R21 DN comparison prefix qualification

Acceptance is per common operation against OpenLDAP, as explicitly selected by
the user. Faster writes cannot offset slower reads. This qualification is not a
claim that the overall goal has been reached.

Production baseline: main `17e0390`, with unchanged R19 production logic. The
network baseline is the retained R19 executable at
`/var/tmp/ldap-go-perf-20260930-r20-request/before`, not the rejected R20
`current` executable. Candidate source is the isolated worktree
`/var/tmp/ldap-go-normalized-prefix-20260930`.

Validated source commit: `c9dfa66`; integrated main commit: `b9db7f3`.
Their nine changed Go files are identical. The production executable was built
before committing; actual build metadata is retained separately.

The runtime retains bounded, immutable prefixes of successfully normalized DN
values for exact member Compare on groups of at least 32 values. Every reuse
checks Registry identity, schema generation and the current raw bytes at the
same position. It is neither an entry/result cache nor an authorization cache.
Get, ACL, referral, assertion and error/early-match ordering are retained.

Limits: one newly retained value per call, 4096 positions, 256 KiB accounted per
token, 64 records and 8 MiB accounted live plus reserved per runtime cache.
The latter includes pinned retired records, but is not a process RSS bound;
old/new runtimes, the existing DN cache and parser temporaries are separate.

## Measurement boundaries

- `fill-eight-source` and the original schema logs preserve the rejected
  eight-value fill experiment. Artificial DN-cache-reset last/missing calls
  approximately doubled, so this configuration is not shipped.
- `single-fill-reset-episode.txt` measures the revised one-value fill. The reset
  benchmark clears the existing DN cache on each call and includes reset cost.
  It is a component diagnostic, not a controlled cold-process/network test.
- Each Episode is 1001 calls beginning with no prefix. Registry/DN caches are
  shared across episodes. Last and missing episodes allocate about 19.5 MB
  while constructing successive immutable prefixes; this cost is retained.
- Handler microbenchmarks use three alternating before/current 500 ms repeats.
  The benchmark's repeated loops progressively warm the prefix. They do not
  represent first-use latency or server-only end-to-end throughput.
- `network.sh` uses the existing shared SDK benchmark, 100,000 users, seven
  1000-call batches and independent writable APFS fixture copies. Default,
  explicit ACL and startup/port-swap runs remain separate. The first measured
  group batch includes progressive warming; subsequent batches are hot. No
  warm-only result is substituted for the recorded batch samples.
- Bind, Base and equality are rerun as unchanged-path regression sentinels.
  Timings are medians of batch totals, not medians of request percentiles.
- Relative performance = `OpenLDAP/current * 100%`. Time reduction relative to
  the paired baseline = `(1-current/before)*100%`; negative values mean slower.
- Each run exports all three endpoints after disposable benchmark cleanup.
  All 100002 user-data entries must match the recovered canonical fixture.
  Physical MDB layout and generated operational attributes are not compared.

All Go builds/tests/benchmarks use `CGO_ENABLED=0`. Performance work is serial;
no concurrent tests/builds or independent benchmarks are intentionally run.
Static subagent review is separate from runtime verification.

## Final result

Primary large-group last/missing time reductions are 11.7%/13.7% with default
access and 14.2%/11.5% with explicit ACL. The independent startup/port swap
observes 12.8%/14.3%. All other observations, including first-member and
unchanged-path slowdowns, remain in `tables.md` and `summary.json`.

Final runs are the `network-final-*` directories. The earlier `network-default`,
`network-explicit` and `network-swap` directories use the prototype before
stack-based attribute-name lookup and the raw-identical first-member guard.
Their results are not pooled with final results. All JSON samples are archived
with gzip compression. `summarize.mjs` runs against the original uncompressed
audit directory; decompress the archived files before using it elsewhere.

Final source-from-17e0390.patch reconstructs the complete code and tests from
the baseline. Binary build metadata is preserved without inventing VCS fields.
Source files under `prototype/` are component snapshots, not a complete source
reconstruction of every exploratory executable.

Full tests, vet and 355 native differential checks pass; see the final logs.
Final summary verifies 756 completed batches and nine matching canonical
exports. The three prototype runs have nine additional matching exports.
Canonical per-export contents: 100002 entries, cksum 2143929969, 42712438 bytes.
The fixture itself is not duplicated in Git. Scripts refer to local disposable
100k seeds and the rebuilt native environment, documented in the R20 evidence.
`SHA256SUMS` checks all archived evidence files.
