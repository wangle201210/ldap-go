# Common LDAP performance qualification

September 29, 2026, R3: baseline `a9de7d4`, frozen executable `current`,
100,000 users, Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Results are mixed; overall parity remains unachieved and the goal active.**
Versus baseline `a9de7d4`, common SSHA Bind improves 5.1% with explicit ACLs
and 0.5% with default access. Distributed non-root Base/equality is **1.8-3.8%
slower**, explicit-ACL 1,000-member group Base **7.6% slower**, and paired
literal-root Bind **6.5% slower**. Fixed-fixture ModifyDN is **13.5% slower**
in the original 20-operation batches; that slowdown does not reproduce in
the separate 100-operation recheck, whose other rows remain mixed. Component
gains do not establish uniform SDK improvement, and shared-host timings do
not establish causality.

The [R2 archive](common-ldap-performance-20260929-r2.md) preserves the previous
report verbatim. [R3 evidence index](evidence/performance-20260929-r3/README.md).

## Change and method

`directory.ValidateDN([]byte)` uses the existing strict `simpleDNDepthBytes`
path or the original `parseDN` fallback without rendering. DN and
NameOptionalUID schema validators call it per value; no validation cache is
added. `operationQueue.pendingAfterPushLocked` counts a virtual append instead
of creating a temporary counting slice. Notifications and scheduling are
unchanged. No configuration, password algorithm/work-factor or CGO changes
are included.

Common tables use medians of three `total_ms` batches. Endpoints rotate per
request; only SDK calls are timed, excluding setup, connection, verification
and cleanup. All samples remain grouped by run, batch, stage, method, member
count and endpoint; SSHA/plaintext, hot/distributed and group sizes stay
separate. Hot reads use `scale-001001`; distributed reads sample 1,000 users
across 100k. User reads retain limit 2; nested BFS retains limit 6 and uses
417 searches per 100 traversals. Common endpoints use uid/member/objectClass
equality indexes and plaintext loopback LDAP.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `a9de7d4`;
negative means slower. Ratios use unrounded medians; 0.0% denotes rounding,
not identical times. Frequency is qualitative. [All 72 common medians](evidence/performance-20260929-r3/medians.tsv).

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 103.67 ms | 98.39 ms | 78.81 ms | 80.1% | 5.1% |
| Wrong password, SSHA | Low | 1,000 | 124.06 ms | 103.23 ms | 94.29 ms | 91.3% | 16.8% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 98.83 ms | 99.85 ms | 79.81 ms | 79.9% | -1.0% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 98.80 ms | 101.77 ms | 80.71 ms | 79.3% | -3.0% |
| Non-root Base, hot | High | 1,000 | 108.36 ms | 104.06 ms | 83.31 ms | 80.1% | 4.0% |
| Non-root equality, hot | Very high | 1,000 | 134.90 ms | 131.73 ms | 101.88 ms | 77.3% | 2.4% |
| Non-root Base, distributed | High | 1,000 | 135.26 ms | 138.34 ms | 95.73 ms | 69.2% | -2.3% |
| Non-root equality, distributed | Very high | 1,000 | 145.08 ms | 150.58 ms | 106.64 ms | 70.8% | -3.8% |
| Direct group discovery | High | 100 | 19.42 ms | 17.73 ms | 12.96 ms | 73.1% | 8.7% |
| Group Base, 10 members | Medium | 100 | 12.64 ms | 12.78 ms | 9.70 ms | 75.9% | -1.1% |
| Group Base, 1,000 members | Medium | 100 | 95.97 ms | 103.24 ms | 92.18 ms | 89.3% | -7.6% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.85 ms | 60.17 ms | 45.95 ms | 76.4% | -2.3% |

## Default access

No explicit ACL rules; otherwise the same common-operation method.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 102.82 ms | 102.32 ms | 91.55 ms | 89.5% | 0.5% |
| Wrong password, SSHA | Low | 1,000 | 98.83 ms | 99.30 ms | 81.23 ms | 81.8% | -0.5% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 92.71 ms | 92.17 ms | 75.98 ms | 82.4% | 0.6% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 90.92 ms | 93.27 ms | 73.24 ms | 78.5% | -2.6% |
| Non-root Base, hot | High | 1,000 | 115.55 ms | 114.50 ms | 92.69 ms | 81.0% | 0.9% |
| Non-root equality, hot | Very high | 1,000 | 113.88 ms | 112.39 ms | 88.76 ms | 79.0% | 1.3% |
| Non-root Base, distributed | High | 1,000 | 128.23 ms | 130.48 ms | 94.27 ms | 72.2% | -1.8% |
| Non-root equality, distributed | Very high | 1,000 | 150.58 ms | 154.59 ms | 116.07 ms | 75.1% | -2.7% |
| Direct group discovery | High | 100 | 16.66 ms | 16.47 ms | 11.65 ms | 70.7% | 1.1% |
| Group Base, 10 members | Medium | 100 | 14.01 ms | 13.70 ms | 10.73 ms | 78.3% | 2.2% |
| Group Base, 1,000 members | Medium | 100 | 115.36 ms | 113.42 ms | 98.68 ms | 87.0% | 1.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.32 ms | 55.40 ms | 43.01 ms | 77.6% | 5.0% |

## Serial broader reads: literal root

Three fresh processes per endpoint run in rotating order. SDK rows use nine
batches: `user-bind.json` for SSHA, `fast-1/2/3.json` for 1,000-call root
stages, and `probe-1/2/3.json` for 20 scans. User-probe repeats 0-2 are all
measured; `warmup.json` is retained but excluded. Literal root binds as
`cn=admin,dc=scale,dc=qualification`. Root Base reads the fixed base container;
equality and both Compare stages use distributed UIDs across the 100k range.
CLI rows time wall-clock execution including client startup/Bind: nine
full-prefix batches, three for each other CLI stage. Methods/counts are not pooled.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA; 1,000 calls | 9 | 96.97 | 93.02 | 70.18 | 75.4% | 4.1% |
| Wrong password, SSHA; 1,000 calls | 9 | 91.04 | 87.53 | 70.98 | 81.1% | 3.9% |
| Root Bind; 1,000 calls | 9 | 70.33 | 69.61 | 64.30 | 92.4% | 1.0% |
| Root Base, hot container; 1,000 calls | 9 | 101.26 | 97.30 | 82.56 | 84.9% | 3.9% |
| Root equality, distributed; 1,000 calls | 9 | 107.74 | 108.08 | 88.00 | 81.4% | -0.3% |
| Root Compare true, distributed; 1,000 calls | 9 | 107.65 | 102.66 | 71.95 | 70.1% | 4.6% |
| Root Compare false, distributed; 1,000 calls | 9 | 106.98 | 98.74 | 70.23 | 71.1% | 7.7% |
| Prefix substring scans; 20 scans | 9 | 939.26 | 919.73 | 622.27 | 67.7% | 2.1% |
| Negative substring scans; 20 scans | 9 | 930.25 | 915.91 | 621.13 | 67.8% | 1.5% |
| CLI full prefix, 100k returned | 9 | 638.00 | 627.00 | 591.00 | 94.3% | 1.7% |
| CLI indexed queries, 10,000 | 3 | 847.00 | 875.00 | 669.00 | 76.5% | -3.3% |
| CLI concurrent indexed, 8 x 1,000 | 3 | 297.00 | 307.00 | 306.00 | 99.7% | -3.4% |
| CLI paged traversal, 2 x 100k | 3 | 1290.00 | 1311.00 | 1125.00 | 85.8% | -1.6% |
| CLI negative unindexed equality, 10 | 3 | 249.00 | 241.00 | 382.00 | 158.5% | 3.2% |

The separate common root-bound CLI checks, eight clients x 1,000 queries,
have before/current/native medians **365/343/369 ms, explicit**, and
**317/303/317 ms, default**. Repeat 0 is warmup; repeats 1-3 are measured.
These common-run checks are separate from the fresh-process replay above.

## Serial broader reads: uppercase root

`normalized-root-1/2/3.json` supplies nine batches per endpoint with client
Bind DN `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`. This spelling identifies the same
root account. Base remains the hot container; equality/Compare remain
distributed. These samples are not pooled with literal root or paired-root SDK.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Root Bind; 1,000 calls | 9 | 77.35 | 73.17 | 64.94 | 88.7% | 5.4% |
| Root Base, hot container; 1,000 calls | 9 | 110.48 | 106.78 | 82.70 | 77.5% | 3.3% |
| Root equality, distributed; 1,000 calls | 9 | 115.83 | 115.25 | 86.48 | 75.0% | 0.5% |
| Root Compare true, distributed; 1,000 calls | 9 | 124.46 | 111.15 | 69.80 | 62.8% | 10.7% |
| Root Compare false, distributed; 1,000 calls | 9 | 114.89 | 110.82 | 69.21 | 62.5% | 3.5% |

[All 108 read median groups](evidence/performance-20260929-r3/read-medians.tsv)
retain variant, stage, count and endpoint. [Read evidence and diagnostic tables](evidence/performance-20260929-r3/read-tables.md)
also preserve long-DN/long-password variants separately.

## Interleaved root SDK

Each row is the median of seven batches of 1,000 primary SDK calls per
endpoint. The [repository runner](../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
rotates endpoints per request, followed by untimed WhoAmI checks. Primary
calls retain fixed-base Root Base and distributed UID equality/Compare.
The old fast probe verified responses without per-request WhoAmI. This
runner also creates an isolated OU/eight-user fixture and performs service
Bind and cleanup. Untimed observer/fixture work still loads the server:
these results cannot replace or be pooled with the serial read workload.

Literal client DN: `cn=admin,dc=scale,dc=qualification`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 82.82 | 88.21 | 82.85 | 93.9% | -6.5% |
| Root Base, hot container | 125.67 | 127.05 | 105.41 | 83.0% | -1.1% |
| Root equality, distributed | 150.09 | 150.02 | 119.15 | 79.4% | 0.0% |
| Root Compare true, distributed | 132.42 | 130.98 | 91.99 | 70.2% | 1.1% |
| Root Compare false, distributed | 140.07 | 137.48 | 94.61 | 68.8% | 1.8% |

Uppercase client DN: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 106.00 | 104.89 | 98.91 | 94.3% | 1.0% |
| Root Base, hot container | 132.38 | 136.67 | 103.99 | 76.1% | -3.2% |
| Root equality, distributed | 130.78 | 124.69 | 99.32 | 79.7% | 4.6% |
| Root Compare true, distributed | 128.93 | 129.69 | 85.71 | 66.1% | -0.6% |
| Root Compare false, distributed | 143.67 | 142.90 | 97.22 | 68.0% | 0.5% |

[All 30 paired-root medians](evidence/performance-20260929-r3/root-paired-medians.tsv)
and [raw records](evidence/performance-20260929-r3/root-paired/) retain both
DN variants and every repeat; smoke and startup warmups are excluded.

## Fixed-fixture writes and RSS

Twenty operations per stage, three fresh processes per endpoint. All nine
before/current/OpenLDAP instances use fixed token
`92cd12ef4156461e9e2807136111af53` and the same run DN, as in R2's fixed-write
method. Setup, SDK postconditions and cleanup are outside timed write stages;
durability settings are unchanged. No cross-round samples are pooled.

| Twenty operations | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 19.30 | 15.77 | 95.04 | 602.7% | 18.3% |
| Modify, unindexed description | 9.01 | 8.71 | 91.11 | 1046.2% | 3.3% |
| ModifyDN | 25.52 | 28.98 | 94.83 | 327.3% | -13.5% |
| Delete | 21.83 | 18.91 | 97.47 | 515.5% | 13.4% |

**ModifyDN's original 13.5% slowdown is retained.** The completed recheck uses
seven alternating fresh before/current process pairs, the same fixed token,
100 writes per stage and `n=2` initial reads. Each median uses seven samples.
There is no new native result; these different batch sizes and initial-read
counts are not pooled with or substituted for the original 20-operation rows.

| 100 operations, same fixed DN | Before (ms) | Current (ms) | Time reduction |
| --- | ---: | ---: | ---: |
| Add | 93.268 | 92.685 | 0.6% |
| Modify, unindexed description | 43.735 | 45.797 | -4.7% |
| ModifyDN | 141.860 | 136.484 | 3.8% |
| Delete | 103.593 | 106.127 | -2.4% |

The ModifyDN slowdown did not reproduce at the larger batch size. Modify and
Delete are slower in this recheck; neither uniform gains nor causality are
established. [All recheck probes](evidence/performance-20260929-r3/write-recheck/)
and [separate medians](evidence/performance-20260929-r3/write-recheck-medians.tsv)
retain every sample.

RSS medians use three byte measurements after each workload, before export.
Read RSS is **11.3% higher** and write RSS **0.4% higher**. These are process
RSS observations, not allocation profiles or per-request memory measurements.

| RSS after workload (bytes) | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Read/authentication | 434,356,224 | 483,229,696 | 151,601,152 |
| Writes | 412,418,048 | 414,105,600 | 141,295,616 |

[Write probes and checks](evidence/performance-20260929-r3/writes/),
[all 54 write median groups](evidence/performance-20260929-r3/write-medians.tsv).

## Component evidence

Three repetitions per case, medians. These isolate component operations, not
LDAP request latency. DN parsing/rendering is compared with validation only.

| DN case | Parse (ns/op) | Validate (ns/op) | B/op, parse to validate | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Simple | 1,617 | 60.92 | 872 to 0 | 50 to 0 |
| Escaped | 1,810 | 908.1 | 968 to 520 | 54 to 28 |
| Multi-AVA | 2,073 | 1,007 | 1,080 to 568 | 62 to 31 |
| Invalid | 1,230 | 1,266 | 720 to 720 | 33 to 33 |

The invalid case is **2.9% slower**, with unchanged allocation counts.
[All DN samples](evidence/performance-20260929-r3/dn-bench.txt).

| Queue case | Reference (ns/op) | Current (ns/op) | B/op, reference to current | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Idle concurrent admission | 5.521 | 3.059 | 0 to 0 | 0 to 0 |
| Full scan, 1,024 entries | 2,935 | 761.8 | 9,472 to 0 | 1 to 0 |

Idle reference counting was already stack-optimized: **both idle paths
allocate zero heap bytes**. No claim is made that one heap allocation was
removed on every request. Full-scan current samples are 761.8/764.2/720.8 ns;
761.8 ns is their median. [Every queue case and repetition](evidence/performance-20260929-r3/queue-bench.txt)
is retained. No new R3 allocation-profile claim is made.

## Validation and identity

All five original scripts exited 0. Common/paired SDK errors, counts, repeats
and cleanup checks passed. All read-stage errors are empty; write
postconditions and cleanup passed. **All 27 original exports match** 100,002 entries,
POSIX checksum 2143929969 and 42,712,438 canonical bytes: six common, three
paired-root, nine read, nine write.
The larger write recheck also exited 0; all 14 exports match the same fixture,
bringing the total to **41**. Its stage errors are empty, write postconditions
passed, and cleanup completed for every process.

Final Go tests passed (server 137.480 s; some packages cached), and the
coordinator confirmed vet exit 0 with an empty log. Native differential
validation has 355 PASS records, no failures/skips and terminal PASS
(11.795 s). DN fuzzing passed 1,177,275 executions. No race-detector result
is claimed. The [September 24 R2 operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Deployment performance, general
compatibility and overall parity remain unproven; optimization continues.

Executable SHA-256 read from the frozen audit files:

```text
before (a9de7d4)  d93aea5cd433bbe3b20805074de8e670286f57eefa2ead015a5028dd53de189f
current           365079e52a578b2180f8fb10d2a647be9d5dd663177587f0a105b63e0ccbb5f3
```

Audit: `/var/tmp/ldap-go-perf-20260929-r3`. The evidence index records replay
dependencies and grouping. Archived replays require environment passwords;
binaries, databases, profiles and large exports are excluded. Documentation
preparation ran no tests, builds, benchmarks or profiles and made no commits.
