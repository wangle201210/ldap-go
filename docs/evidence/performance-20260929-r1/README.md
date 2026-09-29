# September 29, 2026 R1 evidence

Source: `/var/tmp/ldap-go-perf-20260929-r1`; baseline `059e82d`.
The [report](../../common-ldap-performance.md) records mixed results and the
continuing parity goal. The [R7 archive](../../common-ldap-performance-20260924-r7.md)
is the byte-identical previous report. Later routing prototypes are excluded.

## Retained evidence

- `explicit-final/` and `default-final/`: every smoke/hot/distributed/group JSON,
  concurrent batch and export check. Both scripts completed with exit 0.
- `online/`: all 90 warmup, probe, fast, user-Bind, long-DN and long-password
  JSON files, plus CLI `timings.tsv` and export/RSS `validation.tsv`.
- `writes/`: all nine original probes, startup timings and export/RSS checks.
  Twenty operations per write stage; native results remain in this set.
- `write-recheck/`: all 14 probes, startup timings and export/RSS checks for
  seven alternating before/current pairs, 100 writes per stage and `n=2`
  initial reads. No new native result; no pooling with original writes.
  Add remains 7.8% slower; original Add/Modify regressions remain reportable.
- `write-matched/`: a separately controlled fixture experiment, seven alternating
  pairs and 100 writes per stage with `n=2` initial reads. All 14 processes use
  `-fixture-token 92cd12ef4156461e9e2807136111af53` and the same run DN.
  The runner changed; the server executable did not. Add's earlier slowdown
  does not reproduce, but shared-host timing cannot establish DN layout as its
  cause. Earlier regressions remain; these samples are not pooled with them.
- All six completed scripts have `*.log.txt` completion records. All 52
  exports match 100,002 entries, checksum 2143929969, 42,712,438 canonical bytes.
  The original 24 exports and each later set of 14 remain separately identified.
- `go-test.txt`, `go-vet.txt`, `openldap-differential.txt` and focused test logs
  preserve completed validation. Coordinator-confirmed vet success has an empty
  log. Native logs have 355 PASS records, no failures/skips and terminal PASS.
  `ssha-fuzz-final.txt` records 1,490,445 executions in 10 seconds and PASS.
  `fixture-token-test.txt` and `fixture-token-vet.txt` validate the later runner
  option independently; vet's empty log is expected. Default random fixtures
  remain, and existing OUs are rejected before cleanup rather than adopted.
- `access-bench.txt`, `schema-bench.txt`, `ssha-bench-final.txt` retain every
  component repetition and variant. `diagnostics/ssha-preliminary/` is earlier
  evidence, excluded from final component medians.
- `diagnostics/storage-rejected/` preserves both storage logs and the reverted
  benchmark source as text. The one-candidate case increased 403 to 432 B/op,
  with 10 allocations unchanged. Production and benchmark changes were reverted;
  this is rejected diagnostic evidence, not an accepted optimization.

## Grouping and calculations

`medians.tsv` contains 72 common endpoint groups keyed by run, batch, stage,
method, member count and endpoint. Each is the median of three `total_ms`
batches. SSHA/plaintext, hot/distributed and 10/1,000-member groups are separate.
Smoke is excluded. Common CLI repeat 0 is warmup, and 1-3 are measured.
Recalculate saved common reports from this directory, without a workload:

```sh
python3 ../common-performance-20260924-r7/calculate.py.txt explicit-final default-final --output medians.tsv
```

`broad-medians.tsv` contains 144 groups keyed by suite, variant, stage,
operation count, endpoint and unit. Online `probe` and `fast` use three batches
per fresh process, nine samples per endpoint; their 20/1,000-call stages never
mix. `user-bind`, `long-dn` and `long-password` each include measured repeats
0, 1 and 2 per process. `warmup.json` is retained but excluded. CLI full-prefix
uses nine wall-clock samples; other CLI stages use three. RSS medians use three
`rss_bytes` values per suite/endpoint. Original writes have three samples per
endpoint/stage, including separately recorded setup and cleanup diagnostics.
The unchanged `helpers/fast-probe.go.txt` is archived from
`/var/tmp/ldap-go-perf-round6-20260923/fast-probe.go`: its `baseSearch` reads the
fixed `c.Base` container, while `indexedEquality`, `compareTrue` and
`compareFalse` use `sampleUID(c, i)` across the 100k user range. Root equality
and Compare are distributed workloads, separate from hot non-root reads.

`write-recheck-medians.tsv` has eight groups: four write stages, 100 operations,
seven samples per endpoint. Source probes retain all initial-read, setup,
verification and cleanup records. These timings do not replace the originals.
`write-matched-medians.tsv` has eight independent groups with the same 100-write,
seven-sample grouping, restricted to the fixed fixture-token experiment.
All tables take medians of all eligible batch totals, not medians of paired
percentages. Relative performance is `openldap/current*100`; time reduction
is `(1-current/before)*100`, calculated before rounding. Frequency is qualitative.

## Profile and replay provenance

`profile/` retains the unchanged helper, process logs and four workload JSONs.
The helper intentionally invokes the legacy
`/var/tmp/ldap-go-common-perf-20260924-r7/ldapcommonbench`, not the current common
runner. Its default is three group stages, but the actual saved workload sets
`LDAP_GO_PERF_STAGES=memberEquality`: ten warmup requests, a warm heap snapshot,
then 10,000 measured requests and a second heap snapshot. Setup and cleanup are
part of the profiled process interval. `query-alloc-before.txt` and
`query-alloc-current.txt` were extracted by the coordinator from existing
profiles, without remeasurement. Use the `cum` value on `trySmallNonRootSearch`
in these focused `alloc_space` reports: 249.03 to 204.04 MiB (18.1% lower).
The displayed top-node sum and whole-profile total are different quantities.
This is sampled cumulative query allocation, not total process memory,
per-request allocation, RSS or latency. Raw profile binaries and test executables
are excluded.

`common-explicit.sh.txt`, `common-default.sh.txt`, `full-read.sh.txt`,
`full-write.sh.txt`, `write-recheck.sh.txt` and `write-matched.sh.txt` preserve replay
recipes. The common
scripts already required `LDAP_BENCH_PASSWORD`; read/write copies replace
literal fixture credentials with required environment variables. Writes also
require `LDAP_BENCH_USER_PASSWORD`. No timing or workload logic was changed.

Replays retain the persistent native environment at
`/var/tmp/ldap-go-openldap-reference-audit-2.6/openldap-reference.env`, source
fixtures under `/var/tmp/ldap-go-perf-round4-20260922/online-accepted`, the
round4 `ldapbench`, round6 `fast-probe`, round2 `ldifcanonical`, and audit-local
`before`, `current`, `ldapcommonbench`, `user-probe` and `extended-probe` binaries.
The matched-DN replay uses audit-local `ldapbench-fixed`, whose optional token
flag is documented in the [runner README](../../../internal/cmd/ldapbench/README.md).
Common replays also need audit-local `member-acl.db`/`member-index.db` and the
round15 canonical reference. These existing local dependencies are not bundled.
Supply matching fixture credentials and unused output directories before replay.
No secrets, database files, LDIF/large exports or executables are archived.

Frozen server executable SHA-256 supplied by the coordinator:

```text
before (059e82d)  9d77bb8edafc272b239a40af57fa8ce5518ee4c758f45ab75dd50e7d15850981
current           9cac059895ac9fff6999e9ce958b1a1f6f3f44ddd447a065e98a94726a5f9df7
```

Documentation work only reads completed evidence and calculates statistics;
it ran no tests, builds, benchmarks or profiles and made no commits. Causal
investigation continues; neither uniform latency gain nor overall parity is proven.
