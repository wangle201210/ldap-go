# September 29, 2026 R2 evidence

Source: `/var/tmp/ldap-go-perf-20260929-r2`; baseline `b55f670`.
The [report](../../common-ldap-performance.md) retains gains and regressions;
overall parity remains unproven and the goal active. The
[R1 archive](../../common-ldap-performance-20260929-r1.md) is byte-identical to
the previous report. Later query-trace diagnostics are excluded.
The completed per-request interleaved literal/uppercase-root follow-up uses
runner-only changes. Original serial read evidence and regressions remain
unchanged; follow-up tables are separate, with three additional export checks.
It uses seven repeats per case, per-request rotation and WhoAmI outside each
SDK timer. Its fixed-base Root Base and distributed UID equality/Compare match
the old fast probe's primary calls, but that probe did not perform WhoAmI after
every request. The follow-up's isolated OU/eight-user fixture, service Bind and
cleanup also generate untimed server work. Observer/fixture/sequence differences
prevent treating it as an identical workload or replacing the originals.
See the actual [repository runner README](../../../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages);
no harness patch is archived. `root-paired/` retains both measured JSONs, both
smoke JSONs, three server warmup JSONs and `validation.tsv` unchanged.

The completed concurrent recheck is separately scoped: six fresh Go processes
in alternating pairs, `n=2` read-only SDK warmup, concurrent warmup repeat 0,
then three measured eight-client x 1,000-query batches per process. Every client
in every batch passed exact UID sequence/count checks. The nine post-warmup
samples per version have medians 338/338 ms before/current (0.0% reduction).
All samples remain, including before 501 ms and current 571 ms. The original
57.7% slowdown did not reproduce without the preceding full workload; changed
sequence/warmup history prevents causal disproof. No native measurement or
full export was performed, so the total remains 27 and originals stay intact.
Only `concurrent-recheck/timings.tsv`, six warmup JSONs, the completion log and
redacted replay are archived. The coordinator confirmed script exit 0 and all
six process checks passed; this run is not pooled with either prior concurrent check.

## Completed evidence

- `explicit-final/` and `default-final/` retain all smoke/hot/distributed/group
  JSONs, concurrent batches and export checks. Both scripts completed with exit 0.
- `online/` retains all 117 JSONs: warmup, three probes, three literal-root fast
  batches, three uppercase-root batches, user Bind and extended-fixture probes
  for each of nine processes. CLI timings and export/RSS checks are unchanged.
- `writes/` retains nine probes, startup timings and export/RSS checks. All
  before/current/OpenLDAP runs use token `92cd12ef4156461e9e2807136111af53`,
  the same run DN and 20 writes per stage. This changed fixture is not pooled
  with R1 random-token runs or its separate 100-write experiments.
- The four `*.log.txt` files record completion; the coordinator confirmed all
  four exit codes were 0. All 24 original exports match 100,002 entries, checksum
  2143929969 and 42,712,438 canonical bytes. Common SDK errors, counts, repeats
  and cleanup passed. Read-stage errors are empty. Write stages have 20
  postcondition checks each, 40 for ModifyDN; cleanup has 104 operations and
  two verification operations, all without errors.
- `root-paired.log.txt` records follow-up completion (coordinator-confirmed exit
  0). Its three exports match the same fixture, bringing R2's total to **27**.
  Each client-DN case has 105 measured samples: five stages, three endpoints,
  seven repeats, 1,000 attempted/completed/timed requests per sample. Both
  smoke reports have 15 samples of two calls; all reports have empty errors,
  27 setup Adds and all three endpoint cleanups complete. Each primary request
  has an untimed WhoAmI check; verification requests are retained separately.
- `root-sdk-test.txt` and `root-sdk-vet.txt` preserve the later runner's package
  checks. Tests and vet passed, with an empty vet log, as confirmed by the
  coordinator. Server executable identities remain unchanged.
- `go-test.txt`, `go-vet.txt` and `openldap-differential.txt` are final completed
  logs. Server tests took 133.975 s; some packages were cached. The coordinator
  confirmed vet success; its log is empty. Native validation has 355 PASS
  records, no failures/skips and terminal PASS.

## Grouping

`medians.tsv` has 72 groups keyed by run, batch, stage, method, member count
and endpoint. Each median uses three `total_ms` batches. SSHA/plaintext,
hot/distributed and group sizes stay separate; smoke is excluded. Common CLI
repeat 0 is warmup, 1-3 are measured. [Common tables](common-tables.md).
Recalculate those saved reports from this directory without a workload:

```sh
python3 ../common-performance-20260924-r7/calculate.py.txt explicit-final default-final --output medians.tsv
```

`read-medians.tsv` has 108 groups keyed by variant, stage, operation count,
endpoint and unit. `probe`, `fast` and `normalized-root` each have nine batches
per endpoint; their counts and client DN variants never mix. Uppercase root
uses `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`. Root Base reads the fixed container;
equality and both Compare stages use distributed UIDs across 100k, as shown by
the [unchanged fast-probe source](../performance-20260929-r1/helpers/fast-probe.go.txt).
User/extended probes include measured repeats 0-2. Warmup JSONs are retained
but excluded. CLI full-prefix uses nine samples, other CLI stages three.
RSS uses three `rss_bytes` samples. [All read tables](read-tables.md).

`write-medians.tsv` has 54 groups with variant, stage, count, endpoint and unit:
three samples each for all probe stages, startup and RSS. Setup, verification
and cleanup are outside the reported Add/Modify/ModifyDN/Delete stage totals.
All samples remain. Ratios use unrounded endpoint medians, not medians of paired
percentages: relative is `openldap/current*100`, time reduction is
`(1-current/before)*100`. Frequency labels are qualitative.

`root-paired-medians.tsv` has 30 endpoint groups keyed by client-DN variant,
exact `root_bind_dn`, stage, method and endpoint. Each is the median of seven
1,000-call `total_ms` batches. All samples remain; neither smoke nor warmup
contributes to these medians. Literal/uppercase cases and original serial
fast-probe results are never pooled. Verification/fixture work is outside the
SDK timer but changes the server workload and observation sequence.

## Components and diagnostics

`root-component-integrated.txt` compares guard versus old predicate with **new
routing on both sides**, three samples per database-count/case/variant. It
isolates the guard; it is not the full baseline/current SDK comparison.
Normalized-root timing regressions remain, with equal allocation counts.

`diagnostics/routing-isolated/` is the isolated `059e82d` routing component
comparison, with equivalent before/current logic and prototype validation.
Its before label is not the R2 server baseline. Avoided 904-byte value copies
are not 904 B/op heap savings. `diagnostics/root-prototype/` preserves the
initial roughly 30% normalized-root slowdown; `root-pre-integration/` retains
the intermediate repair log. `pre-final-validation/` retains the earlier full
test run. None is pooled with the integrated component or SDK measurements.
There is no new R2 allocation-profile claim or archived query-trace experiment.

## Replay and identity

`common-explicit.sh.txt`, `common-default.sh.txt`, `full-read.sh.txt`,
`full-write.sh.txt` and `root-paired.sh.txt` preserve the replay recipes.
`concurrent-recheck.sh.txt` preserves the additional Go-only replay and its
per-client assertions; only credential literals are replaced with the required
environment variable, with no timing or workload changes.
Common and root-paired scripts already require
`LDAP_BENCH_PASSWORD`; read/write copies replace fixture credential literals
with required environment variables. Writes also require `LDAP_BENCH_USER_PASSWORD`.
Timing and workload logic remain unchanged. Existing dependencies include:

- Persistent native environment:
  `/var/tmp/ldap-go-openldap-reference-audit-2.6/openldap-reference.env`.
- Fixtures: `/var/tmp/ldap-go-perf-round4-20260922/online-accepted`; common runs
  also use audit-local `member-acl.db`/`member-index.db` and the round15 canonical reference.
- Round4 `ldapbench`, round6 `fast-probe`, round2 `ldifcanonical`; audit-local
  `before`, `current`, `ldapcommonbench`, `ldapcommonbench-root`, `user-probe`,
  `extended-probe` and `ldapbench-fixed`. These binaries/fixtures are dependencies,
  not bundled evidence. Root-paired uses `member-index.db` and the new root-capable
  client; all server binaries remain the frozen R2 identities below.

Supply matching fixture credentials and unused output directories for replay.
No passwords, binaries, databases, profiles, LDIF or large exports are archived.
Frozen server executable SHA-256 supplied by the coordinator:

```text
before (b55f670)  9cac059895ac9fff6999e9ce958b1a1f6f3f44ddd447a065e98a94726a5f9df7
current           d93aea5cd433bbe3b20805074de8e670286f57eefa2ead015a5028dd53de189f
```

Documentation preparation reads completed evidence and calculates statistics;
it ran no tests, builds, benchmarks or profiles and made no commits.
