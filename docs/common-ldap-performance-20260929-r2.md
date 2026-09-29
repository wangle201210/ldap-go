# Common LDAP performance qualification

September 29, 2026, R2: baseline `b55f670`, frozen executable `current`,
100,000 users, Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Results remain mixed; overall OpenLDAP parity is unproven and the goal stays
active.** Versus baseline `b55f670`, common non-root Base/equality medians improve
2.9-11.3% with default access and 4.5-5.4% with explicit ACLs. However, broader
literal-root equality is **14.5% slower**, false Compare **10.0% slower**, and
the fresh-process concurrent CLI check **57.7% slower**. Fixed-fixture Add and
Delete are **3.9% and 10.0% slower**. These regressions remain in the evidence;
shared-host measurements do not establish their cause or a uniform gain.
The separate interleaved follow-up shows literal-root equality 9.6% faster
and false Compare 0.1% faster, but uppercase-root equality 2.9% slower.
Its different observer, fixture and request sequence do not invalidate the
original serial results or establish the cause of their regressions.

The [R1 archive](common-ldap-performance-20260929-r1.md) preserves the previous
report verbatim. [R2 evidence index](evidence/performance-20260929-r2/README.md).

## Scope and method

DN relation helpers extract only the normalizer instead of copying the
904-byte database value, preserving snapshot and evaluation order. `isRoot`
adds a pure negative guard with a conservative identity hint, avoiding extra
normalized-root allocations and handling zero DNs safely. `localProjectionReadOnly`
uses an indexed pointer where no external callbacks run. Authentication, ACL
decisions, password algorithms/work factors and cache bounds are unchanged.

Common tables use medians of three `total_ms` batches. Endpoints rotate per
request; only SDK calls are timed, excluding setup, connection, verification
and cleanup. All samples remain, grouped by run, batch, stage, method, member
count and endpoint. SSHA/plaintext, hot/distributed and group sizes stay
separate. Hot reads target `scale-001001`; distributed reads sample 1,000 users
across 100k. User reads retain limit 2; nested BFS retains limit 6 and uses
417 searches per 100 traversals. Common endpoints have uid/member/objectClass
equality indexes and plaintext loopback LDAP.

`Relative = OpenLDAP/current * 100%`; 100% means parity.
`Time reduction = (1-current/before) * 100%`, versus baseline `b55f670`;
negative means slower. Ratios use unrounded medians; 0.0% is rounding, not
identical times. Frequency is qualitative. [All 72 common medians](evidence/performance-20260929-r2/medians.tsv).

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 95.61 ms | 95.78 ms | 75.73 ms | 79.1% | -0.2% |
| Wrong password, SSHA | Low | 1,000 | 98.75 ms | 98.41 ms | 77.94 ms | 79.2% | 0.3% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 97.51 ms | 97.48 ms | 76.73 ms | 78.7% | 0.0% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 91.64 ms | 91.66 ms | 74.08 ms | 80.8% | <0.1% slower |
| Non-root Base, hot | High | 1,000 | 115.63 ms | 110.38 ms | 87.10 ms | 78.9% | 4.5% |
| Non-root equality, hot | Very high | 1,000 | 119.88 ms | 114.25 ms | 88.80 ms | 77.7% | 4.7% |
| Non-root Base, distributed | High | 1,000 | 133.97 ms | 126.69 ms | 89.20 ms | 70.4% | 5.4% |
| Non-root equality, distributed | Very high | 1,000 | 131.64 ms | 125.10 ms | 90.68 ms | 72.5% | 5.0% |
| Direct group discovery | High | 100 | 18.70 ms | 17.37 ms | 11.79 ms | 67.9% | 7.1% |
| Group Base, 10 members | Medium | 100 | 14.66 ms | 13.27 ms | 10.48 ms | 78.9% | 9.5% |
| Group Base, 1,000 members | Medium | 100 | 96.90 ms | 95.60 ms | 88.50 ms | 92.6% | 1.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 58.27 ms | 56.98 ms | 41.52 ms | 72.9% | 2.2% |

## Default access

No explicit ACL rules; otherwise the same common-operation method.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 89.37 ms | 89.35 ms | 70.77 ms | 79.2% | 0.0% |
| Wrong password, SSHA | Low | 1,000 | 99.06 ms | 100.33 ms | 80.38 ms | 80.1% | -1.3% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 98.32 ms | 98.14 ms | 79.32 ms | 80.8% | 0.2% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 93.43 ms | 93.96 ms | 74.75 ms | 79.6% | -0.6% |
| Non-root Base, hot | High | 1,000 | 113.12 ms | 108.68 ms | 87.90 ms | 80.9% | 3.9% |
| Non-root equality, hot | Very high | 1,000 | 121.82 ms | 118.26 ms | 93.65 ms | 79.2% | 2.9% |
| Non-root Base, distributed | High | 1,000 | 135.42 ms | 126.90 ms | 91.50 ms | 72.1% | 6.3% |
| Non-root equality, distributed | Very high | 1,000 | 147.47 ms | 130.79 ms | 113.02 ms | 86.4% | 11.3% |
| Direct group discovery | High | 100 | 17.90 ms | 17.19 ms | 12.11 ms | 70.4% | 4.0% |
| Group Base, 10 members | Medium | 100 | 14.92 ms | 14.72 ms | 11.37 ms | 77.2% | 1.3% |
| Group Base, 1,000 members | Medium | 100 | 100.19 ms | 99.85 ms | 90.09 ms | 90.2% | 0.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 56.51 ms | 54.73 ms | 40.87 ms | 74.7% | 3.1% |

## Broader reads: literal root

Three fresh processes per endpoint run in rotating order. SDK rows have nine
batches: `user-bind.json` for SSHA, `fast-1/2/3.json` for 1,000-call root stages
and `probe-1/2/3.json` for 20 scans. User-probe repeats 0-2 are all measured;
`warmup.json` is retained but excluded. Literal root binds as
`cn=admin,dc=scale,dc=qualification`. Root Base reads the fixed base container;
equality and both Compare stages sample UIDs across the 100k range.
CLI rows use wall-clock timing including client startup/Bind: nine full-prefix
batches, three for each other CLI stage. Methods/counts are never pooled.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA; 1,000 calls | 9 | 97.46 | 99.12 | 74.93 | 75.6% | -1.7% |
| Wrong password, SSHA; 1,000 calls | 9 | 89.37 | 97.57 | 74.81 | 76.7% | -9.2% |
| Root Bind; 1,000 calls | 9 | 71.12 | 67.28 | 76.27 | 113.4% | 5.4% |
| Root Base, hot container; 1,000 calls | 9 | 102.70 | 100.64 | 84.98 | 84.4% | 2.0% |
| Root equality, distributed; 1,000 calls | 9 | 106.65 | 122.07 | 93.28 | 76.4% | -14.5% |
| Root Compare true, distributed; 1,000 calls | 9 | 107.71 | 105.61 | 73.24 | 69.4% | 2.0% |
| Root Compare false, distributed; 1,000 calls | 9 | 105.00 | 115.47 | 70.54 | 61.1% | -10.0% |
| Prefix substring scans; 20 scans | 9 | 931.43 | 973.28 | 624.07 | 64.1% | -4.5% |
| Negative substring scans; 20 scans | 9 | 920.02 | 937.92 | 640.83 | 68.3% | -1.9% |
| CLI full prefix, 100k returned | 9 | 663.00 | 675.00 | 620.00 | 91.9% | -1.8% |
| CLI indexed queries, 10,000 | 3 | 896.00 | 985.00 | 885.00 | 89.8% | -9.9% |
| CLI concurrent indexed, 8 x 1,000 | 3 | 286.00 | 451.00 | 322.00 | 71.4% | -57.7% |
| CLI paged traversal, 2 x 100k | 3 | 1406.00 | 1397.00 | 1231.00 | 88.1% | 0.6% |
| CLI negative unindexed equality, 10 | 3 | 263.00 | 264.00 | 434.00 | 164.4% | -0.4% |

The separate common root-bound CLI check, eight clients x 1,000 queries, has
before/current/native medians **309/314/325 ms, explicit**, and
**309/303/327 ms, default**. Repeat 0 is warmup; repeats 1-3 are measured.
These common-run checks remain separate from the fresh-process regression.

The original fresh-process concurrent batches are 286/282/322 ms before and
451/311/462 ms current; none is discarded.

### Separate concurrent recheck

Six fresh Go processes in alternating pairs use an `n=2` read-only SDK warmup,
concurrent warmup repeat 0, then three measured eight-client x 1,000-query
batches per process. Every client in every batch passed exact UID sequence
and count checks. Medians use all nine post-warmup samples per Go version.

| Eight clients x 1,000 queries | Before (ms) | Current (ms) | Time reduction |
| --- | ---: | ---: | ---: |
| Separate concurrent recheck | 338 | 338 | 0.0% |

The original 57.7% slowdown did not reproduce without the preceding full
workload. Different sequence and warmup history prevent a causal disproof or
replacement of the original results. All samples remain, including the
501 ms before and 571 ms current outliers. There is no new native measurement
or full export; R2's export total remains 27.
[Timings](evidence/performance-20260929-r2/concurrent-recheck/timings.tsv),
[completion log](evidence/performance-20260929-r2/concurrent-recheck.log.txt),
[replay](evidence/performance-20260929-r2/concurrent-recheck.sh.txt).

## Broader reads: uppercase root

`normalized-root-1/2/3.json` supplies nine batches per endpoint using client
Bind DN `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`. This spelling identifies the same
root account; it is a separate client-DN variant, never pooled with literal
root. Base remains the hot container; equality/Compare remain distributed.

| Workload | Batches/endpoint | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Root Bind; 1,000 calls | 9 | 75.45 | 74.40 | 69.01 | 92.7% | 1.4% |
| Root Base, hot container; 1,000 calls | 9 | 101.91 | 102.51 | 84.46 | 82.4% | -0.6% |
| Root equality, distributed; 1,000 calls | 9 | 112.02 | 116.41 | 89.80 | 77.1% | -3.9% |
| Root Compare true, distributed; 1,000 calls | 9 | 109.15 | 110.73 | 76.54 | 69.1% | -1.4% |
| Root Compare false, distributed; 1,000 calls | 9 | 112.11 | 105.12 | 72.64 | 69.1% | 6.2% |

[Read medians](evidence/performance-20260929-r2/read-medians.tsv) retain all
108 stage/count/variant/endpoint groups. [Read evidence and diagnostic tables](evidence/performance-20260929-r2/read-tables.md)
also preserve long-DN/long-password variants separately.

## Interleaved root follow-up

The completed follow-up uses seven repeats per literal/uppercase client-DN
case, 1,000 primary SDK calls per stage/endpoint/repeat. Medians use all seven
`total_ms` batches; smoke and warmup records remain separate.
The [repository runner](../internal/cmd/ldapcommonbench/README.md#optional-root-sdk-stages)
keeps the fast probe's primary SDK calls: fixed-base Root Base and distributed
UID equality/Compare. It rotates endpoints per request and performs WhoAmI
after every timed request, outside the SDK timer. The old fast probe verified
responses without that per-request WhoAmI observer. The follow-up also creates
an isolated OU/eight-user fixture and runs service Bind and cleanup. These
untimed operations still add server work: the observer, fixture and execution
sequence differ, so results must stay separate and cannot replace the originals.

Literal client DN: `cn=admin,dc=scale,dc=qualification`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 84.14 | 85.26 | 82.22 | 96.4% | -1.3% |
| Root Base, hot container | 114.74 | 115.16 | 95.76 | 83.2% | -0.4% |
| Root equality, distributed | 145.31 | 131.29 | 109.05 | 83.1% | 9.6% |
| Root Compare true, distributed | 131.17 | 129.63 | 91.49 | 70.6% | 1.2% |
| Root Compare false, distributed | 125.06 | 124.90 | 87.26 | 69.9% | 0.1% |

Uppercase client DN: `CN=ADMIN,DC=SCALE,DC=QUALIFICATION`.

| 1,000 calls | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 79.34 | 81.01 | 77.30 | 95.4% | -2.1% |
| Root Base, hot container | 115.50 | 113.98 | 91.02 | 79.9% | 1.3% |
| Root equality, distributed | 126.57 | 130.24 | 102.28 | 78.5% | -2.9% |
| Root Compare true, distributed | 126.61 | 126.42 | 82.84 | 65.5% | 0.2% |
| Root Compare false, distributed | 125.19 | 126.86 | 81.41 | 64.2% | -1.3% |

The original literal-root equality/false-Compare slowdowns do not reproduce
in this different workload. Bind is slower in both variants, and uppercase
equality/false Compare are slower. Neither series establishes uniform gains
or causality. [All 30 endpoint medians](evidence/performance-20260929-r2/root-paired-medians.tsv)
and [raw follow-up evidence](evidence/performance-20260929-r2/root-paired/) retain
both DN variants, all measured batches and both smoke reports.

## Fixed-fixture writes and RSS

Twenty operations per stage, three fresh processes per endpoint, with fixed
token `92cd12ef4156461e9e2807136111af53` and the same run DN in **all nine
before/current/OpenLDAP instances**. Setup, SDK postcondition checks and
cleanup are outside timed write stages; durability settings are unchanged.
This fixture differs from R1's original random-token runs: no cross-round
pooling or direct R1-table comparison is made. No additional R2 write recheck
is included.

| Twenty operations | Before (ms) | Current (ms) | OpenLDAP (ms) | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 18.36 | 19.07 | 108.84 | 570.8% | -3.9% |
| Modify, unindexed description | 11.09 | 10.60 | 113.05 | 1066.4% | 4.4% |
| ModifyDN | 33.44 | 27.33 | 116.31 | 425.5% | 18.3% |
| Delete | 20.96 | 23.06 | 113.71 | 493.1% | -10.0% |

RSS medians use three byte measurements after each workload, before export.
Read RSS is 1.2% lower; write RSS is 16.3% higher. These observations are not
allocation profiles or per-operation memory measurements.

| RSS after workload (bytes) | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Read/authentication | 437,059,584 | 431,603,712 | 100,270,080 |
| Writes | 367,853,568 | 427,687,936 | 141,770,752 |

[Write probes and checks](evidence/performance-20260929-r2/writes/),
[all 54 write median groups](evidence/performance-20260929-r2/write-medians.tsv).

## Component evidence

The [integrated root component](evidence/performance-20260929-r2/root-component-integrated.txt)
compares the old predicate with the guard **both using new routing**, three
repetitions each. It isolates the guard, not the full baseline-to-current SDK
change. Non-root hot allocations fall; normalized-root allocations stay equal
and its timings remain slightly slower.

| Hot case / databases | Old predicate (ns) | Guard (ns) | B/op, old to guard | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Non-root / 1 | 1,488 | 777.2 | 232 to 120 | 8 to 4 |
| Non-root / 8 | 7,479 | 5,011 | 1,408 to 960 | 50 to 32 |
| Non-root / 32 | 27,983 | 20,144 | 5,440 to 3,840 | 194 to 128 |
| Normalized root / 1 | 1,483 | 1,495 | 232 to 232 | 8 to 8 |
| Normalized root / 8 | 7,408 | 7,796 | 1,408 to 1,408 | 50 to 50 |
| Normalized root / 32 | 28,121 | 28,617 | 5,440 to 5,440 | 194 to 194 |

[Routing prototype samples](evidence/performance-20260929-r2/diagnostics/routing-isolated/routing-prototype-bench.txt)
are an isolated `059e82d` component comparison of equivalent routing logic,
not SDK results or a `b55f670` server comparison. Avoiding a 904-byte value copy
is not a 904 B/op heap-allocation claim. The initial root prototype's roughly
30% normalized-root slowdown and intermediate repair are preserved as
diagnostics, separate from the integrated samples. **No new R2 allocation
profile claim is made.** Later query-trace diagnostics are outside this round.

## Validation and identity

All four original scripts exited 0. Common SDK errors, repeat/count and cleanup checks
passed; all read-stage errors are empty; write postconditions and cleanup
passed. **All 24 original exports match** 100,002 entries, POSIX checksum 2143929969
and 42,712,438 canonical bytes: six common, nine read, nine write.
The root-paired follow-up also exited 0 with three matching exports, bringing
R2's total to **27**. Both smoke reports and all 210 measured samples have no
errors and complete cleanup; every measured sample verifies 1,000 primary SDK
calls. Runner package tests and vet passed in separately archived logs.

Coordinator-confirmed final Go tests passed (server 133.975 s; some packages
cached), and vet passed with an empty log. Native differential validation has
355 PASS records, no failures/skips and terminal PASS. Earlier prototype
validation is separate. No race-detector result is claimed. The
[September 24 R2 operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. General compatibility, deployment
capacity and overall parity remain unproven; optimization continues.

Frozen executable SHA-256 supplied by the coordinator:

```text
before (b55f670)  9cac059895ac9fff6999e9ce958b1a1f6f3f44ddd447a065e98a94726a5f9df7
current           d93aea5cd433bbe3b20805074de8e670286f57eefa2ead015a5028dd53de189f
```

Audit: `/var/tmp/ldap-go-perf-20260929-r2`. The evidence index records replay
dependencies and grouping. Passwords are environment-only in archived replays;
binaries, databases, profiles and large exports are excluded. Documentation
preparation ran no tests, builds, benchmarks or profiles and made no commits.
