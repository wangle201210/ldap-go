# Common LDAP performance qualification

September 29, 2026, R1: baseline `059e82d`, frozen executable `current`,
100,000 users, Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Results are mixed; overall latency improvement and OpenLDAP parity remain
unproven. The optimization goal remains active.** Explicit-ACL direct group
discovery improves 11.4% and the 1,000-member group Base workload improves 7.2%.
SSHA Bind is 1.0% slower with explicit ACLs and 0.7% slower with default access.
**Original 20-operation writes regress: Add is 10.9% slower and Modify 15.7%
slower.** Add remains 7.8% slower in the separate random-DN, 100-operation
recheck; that slowdown does not reproduce with matched DNs (0.0% reduction).
Shared-host measurements do not establish random DN layout as the cause.

The [R7 archive](common-ldap-performance-20260924-r7.md) preserves the previous
report verbatim. [Evidence index](evidence/performance-20260929-r1/README.md).

## Scope and method

Three changes are measured: direct `accessSubject` values for known wrappers
with live callbacks; schema `[]byte` DN-cache hits without the temporary copy;
and SSHA stack buffers plus `bytes.IndexByte` in `splitScheme`. Cache limits
remain 128 entries, 1 MiB estimated retained data, 1,024 input bytes and depth
32, with owned data and schema invalidation. Authorization/password checks,
algorithms, work factors, snapshots and error behavior remain. Later routing
prototypes and the rejected storage experiment are outside this executable.

Common SDK tables use medians of three `total_ms` batches, grouped by run,
batch, stage, method, member count and endpoint. Endpoints rotate per request;
only SDK calls are timed. Setup, verification, connection and cleanup are
excluded. All samples are retained; SSHA/plaintext, hot/distributed and group
sizes remain separate. Hot reads use `scale-001001`; distributed reads sample
1,000 users across the 100k range. User reads retain size limit 2; nested BFS
retains limit 6 and uses 417 searches per 100 traversals. All common endpoints
use uid/member/objectClass equality indexes and plaintext loopback LDAP.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`; negative means slower.
Ratios use unrounded medians. Frequency is qualitative, not measured traffic.
[All 72 common medians](evidence/performance-20260929-r1/medians.tsv).

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 110.75 ms | 111.85 ms | 87.20 ms | 78.0% | -1.0% |
| Wrong password, SSHA | Low | 1,000 | 106.42 ms | 103.76 ms | 80.62 ms | 77.7% | 2.5% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 111.31 ms | 113.95 ms | 89.34 ms | 78.4% | -2.4% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 104.06 ms | 102.46 ms | 80.76 ms | 78.8% | 1.5% |
| Non-root Base, hot | High | 1,000 | 127.39 ms | 125.99 ms | 94.58 ms | 75.1% | 1.1% |
| Non-root equality, hot | Very high | 1,000 | 133.76 ms | 131.69 ms | 95.36 ms | 72.4% | 1.5% |
| Non-root Base, distributed | High | 1,000 | 147.38 ms | 152.38 ms | 101.90 ms | 66.9% | -3.4% |
| Non-root equality, distributed | Very high | 1,000 | 152.53 ms | 152.81 ms | 105.28 ms | 68.9% | -0.2% |
| Direct group discovery | High | 100 | 19.87 ms | 17.61 ms | 11.45 ms | 65.1% | 11.4% |
| Group Base, 10 members | Medium | 100 | 16.42 ms | 15.29 ms | 10.76 ms | 70.4% | 6.9% |
| Group Base, 1,000 members | Medium | 100 | 106.90 ms | 99.16 ms | 91.88 ms | 92.7% | 7.2% |
| Nested membership, client BFS | Medium-high | 100 traversals | 59.83 ms | 59.68 ms | 43.09 ms | 72.2% | 0.2% |

[Raw samples and export checks](evidence/performance-20260929-r1/explicit-final/).

## Default access

No explicit ACL rules; otherwise the same common-operation method.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 97.38 ms | 98.08 ms | 78.17 ms | 79.7% | -0.7% |
| Wrong password, SSHA | Low | 1,000 | 96.24 ms | 95.29 ms | 77.41 ms | 81.2% | 1.0% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 99.87 ms | 99.87 ms | 78.89 ms | 79.0% | <0.1% slower |
| Wrong password, plaintext diagnostic | Low | 1,000 | 97.51 ms | 95.34 ms | 75.50 ms | 79.2% | 2.2% |
| Non-root Base, hot | High | 1,000 | 107.60 ms | 105.17 ms | 80.83 ms | 76.9% | 2.3% |
| Non-root equality, hot | Very high | 1,000 | 117.91 ms | 119.04 ms | 89.80 ms | 75.4% | -1.0% |
| Non-root Base, distributed | High | 1,000 | 124.14 ms | 122.62 ms | 82.44 ms | 67.2% | 1.2% |
| Non-root equality, distributed | Very high | 1,000 | 131.39 ms | 131.29 ms | 92.08 ms | 70.1% | 0.1% |
| Direct group discovery | High | 100 | 20.91 ms | 20.43 ms | 13.49 ms | 66.0% | 2.3% |
| Group Base, 10 members | Medium | 100 | 14.86 ms | 14.52 ms | 10.50 ms | 72.3% | 2.3% |
| Group Base, 1,000 members | Medium | 100 | 98.23 ms | 96.99 ms | 87.91 ms | 90.6% | 1.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 55.04 ms | 55.61 ms | 41.24 ms | 74.2% | -1.0% |

[Raw samples and export checks](evidence/performance-20260929-r1/default-final/).
Small and mixed changes do not establish a general latency improvement.

## Broader reads

Three fresh processes per endpoint ran in rotating order. SDK rows are
medians of nine batches: `user-bind.json` for SSHA, `fast-*.json` for 1,000-call
root operations, and `probe-1/2/3.json` for 20 scans per process. These are
separate from the interleaved common SDK matrix. In the archived
[fast probe](evidence/performance-20260929-r1/helpers/fast-probe.go.txt), root
Base repeatedly reads the fixed `c.Base` container; root equality and both
Compare stages use `sampleUID(c, i)` across the 100k user range.
CLI rows time wall-clock
execution, including startup/Bind: full prefix has nine batches, other CLI
rows three. No methods or operation counts are pooled. Warmups are retained
but excluded; user-probe repeats 0, 1 and 2 are all measured.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA; 1,000 | 9 | 93.46 | 96.66 | 70.79 | 73.2% | -3.4% |
| Wrong password, SSHA; 1,000 | 9 | 88.68 | 93.27 | 73.00 | 78.3% | -5.2% |
| Root Bind; 1,000 | 9 | 76.32 | 72.97 | 65.26 | 89.4% | 4.4% |
| Root Base, hot container; 1,000 | 9 | 102.93 | 97.23 | 83.03 | 85.4% | 5.5% |
| Root equality, distributed; 1,000 | 9 | 107.73 | 106.40 | 89.86 | 84.5% | 1.2% |
| Root Compare true, distributed; 1,000 | 9 | 105.70 | 105.90 | 70.34 | 66.4% | -0.2% |
| Root Compare false, distributed; 1,000 | 9 | 109.65 | 102.37 | 70.76 | 69.1% | 6.6% |
| Prefix substring scans; 20 | 9 | 923.99 | 921.86 | 619.19 | 67.2% | 0.2% |
| Negative substring scans; 20 | 9 | 919.12 | 917.40 | 617.32 | 67.3% | 0.2% |
| CLI full prefix; 100k returned | 9 | 650.00 | 632.00 | 557.00 | 88.1% | 2.8% |
| CLI indexed queries; 10,000 | 3 | 814.00 | 855.00 | 708.00 | 82.8% | -5.0% |
| CLI concurrent indexed; 8 x 1,000 | 3 | 307.00 | 299.00 | 305.00 | 102.0% | 2.6% |
| CLI paged traversal; 2 x 100k | 3 | 1299.00 | 1323.00 | 1207.00 | 91.2% | -1.8% |
| CLI negative unindexed equality; 10 | 3 | 238.00 | 252.00 | 383.00 | 152.0% | -5.9% |

The separate common root-bound CLI check (eight clients x 1,000 queries)
has before/current/native medians of **313/330/322 ms with explicit ACLs**
and **308/302/325 ms with default access**. Its repeat 0 is warmup; repeats
1-3 supply the medians. It is not pooled with the fresh-process replay above.

[Raw read evidence](evidence/performance-20260929-r1/online/) and
[144 broader medians](evidence/performance-20260929-r1/broad-medians.tsv)
retain stage, count and fixture variants. Long-DN and long-password probes
are diagnostic evidence, separate from the short-fixture tables.

## Original writes and RSS

Twenty leaf operations per stage, three fresh processes per endpoint.
SDK setup, postcondition verification and cleanup are outside each timed
stage; durability settings are unchanged. All original samples, including
the Add and Modify regressions, remain in this comparison.

| Workload | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 16.89 | 18.73 | 99.36 | 530.5% | -10.9% |
| Modify, unindexed description | 8.37 | 9.68 | 90.69 | 936.5% | -15.7% |
| ModifyDN | 29.50 | 29.96 | 108.81 | 363.2% | -1.5% |
| Delete | 21.23 | 20.73 | 100.08 | 482.8% | 2.4% |

RSS is the median of three process samples in bytes, taken after each
workload and before export. Read RSS is 0.8% lower; write RSS is 7.8% higher.

| RSS after workload (bytes) | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Read/authentication | 428,752,896 | 425,508,864 | 152,879,104 |
| Writes | 395,247,616 | 426,082,304 | 141,787,136 |

[Original write probes and checks](evidence/performance-20260929-r1/writes/).

## Separate write recheck

Seven fresh before/current process pairs in alternating order, 100 operations
per write stage and `n=2` initial read operations. Medians use seven samples
per endpoint, with no pooling into the original 20-operation/native table.
There is no new OpenLDAP measurement.

| 100 operations | Before (ms) | Current (ms) | Time reduction |
| --- | ---: | ---: | ---: |
| Add | 90.142 | 97.217 | -7.8% |
| Modify, unindexed description | 43.912 | 42.607 | 3.0% |
| ModifyDN | 134.403 | 137.967 | -2.7% |
| Delete | 111.060 | 107.066 | 3.6% |

**The Add slowdown persists; there is no uniform gain.**
[Raw recheck](evidence/performance-20260929-r1/write-recheck/) and
[separate medians](evidence/performance-20260929-r1/write-recheck-medians.tsv).

### Matched-DN experiment

Another seven alternating fresh-process pairs explicitly change the fixture
factor: the runner's optional `-fixture-token` uses
`92cd12ef4156461e9e2807136111af53` for the same run DN in all 14 processes.
The server executable is unchanged. The runner retains random DNs by default
and rejects an existing fixture OU before cleanup; it does not adopt that OU.
Batch size remains 100, with `n=2` initial reads and no new native measurement.

| 100 operations, matched DN | Before (ms) | Current (ms) | Time reduction |
| --- | ---: | ---: | ---: |
| Add | 87.580 | 87.539 | 0.0% |
| Modify, unindexed description | 43.831 | 43.239 | 1.4% |
| ModifyDN | 137.567 | 132.370 | 3.8% |
| Delete | 104.439 | 105.371 | -0.9% |

The earlier Add slowdown did not reproduce under this controlled fixture.
This does not establish that random DN layout caused it: time, host conditions
and the fixture factor differ between runs. Original regressions remain
evidence; there is no uniform gain. [Matched-DN probes](evidence/performance-20260929-r1/write-matched/)
and [separate medians](evidence/performance-20260929-r1/write-matched-medians.tsv)
are not pooled with either earlier write series.

## Component and allocation evidence

Component medians isolate the changed paths; they are not SDK latency results.

| Component | Before/legacy | Current | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Known-wrapper ACL subject, 3 samples | 65.89 ns | 28.18 ns | 128 to 0 | 1 to 0 |
| Warm DN-cache input, string/bytes, 3 samples | 66.00 ns | 49.98 ns | 48 to 0 | 1 to 0 |
| SSHA default correct password, 2 final samples | 186.90 ns | 113.35 ns | 108 to 4 | 4 to 1 |

Distributed DN-cache inputs retain 2,760 B/op and 128 allocs/op; no general
cold/distributed benefit is claimed. Full component variants and preliminary
SSHA diagnostics are preserved separately in the evidence index.

The archived [before](evidence/performance-20260929-r1/profile/query-alloc-before.txt)
and [current](evidence/performance-20260929-r1/profile/query-alloc-current.txt)
`alloc_space` text extracts show **249.03 to 204.04 MiB, 18.1% lower sampled
cumulative allocation at `trySmallNonRootSearch`**. This is neither per-operation
allocation nor RSS, retained heap or a whole-process latency result. The
[profile helper and workload records](evidence/performance-20260929-r1/profile/)
use the legacy R7 client: ten warmup requests, then 10,000 `memberEquality`
requests with `LDAP_GO_PERF_STAGES=memberEquality`. They are diagnostic and
separate from the common SDK latency matrix; no profile was rerun for this report.

The rejected storage micro-optimization increased the one-candidate case
from **403 to 432 B/op with 10 allocs/op unchanged**. Production and benchmark
source were reverted; its [diagnostic samples and source](evidence/performance-20260929-r1/diagnostics/storage-rejected/)
are not accepted optimization evidence.

## Validation, identity and limits

- Coordinator-confirmed Go tests and vet passed; the empty vet log is expected.
  Native differential logs contain 355 PASS records, no failures/skips and
  terminal PASS. Final SSHA fuzzing passed 1,490,445 cases in 10 seconds.
- Both common scripts, full read and original full write completed with exit 0.
  SDK errors are empty, repeats/counts and cleanup/postconditions are complete.
  **All 24 original exports** match 100,002 entries, POSIX checksum 2143929969
  and 42,712,438 canonical bytes: six common, nine read and nine write.
- Both separate 100-operation write experiments exited 0; all 28 exports match
  the same fixture, bringing completed export checks to **52**. Their SDK write
  postconditions and cleanup passed. The fixture-token package tests passed;
  its separately archived vet log is empty.
- The [R2 operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
  remains outside the passing native matrix. No race-detector result is claimed.
  Shared-host samples do not establish causality, general compatibility or
  deployment capacity. The broader parity goal remains active and unproven.

Frozen executable SHA-256 supplied by the coordinator:

```text
before (059e82d)  9d77bb8edafc272b239a40af57fa8ce5518ee4c758f45ab75dd50e7d15850981
current           9cac059895ac9fff6999e9ce958b1a1f6f3f44ddd447a065e98a94726a5f9df7
```

Source audit: `/var/tmp/ldap-go-perf-20260929-r1`. The evidence index records
replay dependencies, retained samples and grouping. Replays require fixture
passwords through environment variables and preserve the persistent native
environment path. Passwords, binaries, databases and large exports are excluded.
Documentation preparation ran no tests, builds, benchmarks or profiles.
