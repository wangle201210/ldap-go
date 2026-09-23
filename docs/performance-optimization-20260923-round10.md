# Bind routing and retained DN metadata

Baseline: `fc58dd4`. This continues the
[common-operation investigation](performance-optimization-20260923-round9.md).
All Go builds and accepted checks use `CGO_ENABLED=0`.

## Changes

Legacy database routing compares already parsed display RDNs directly when
both forms are simple single-AVA ASCII. It preserves case-folded comparison of
the displayed forms rather than comparing schema identities. Complex,
uninitialized or unsupported forms use the original parse/normalize path.
Databases with a normalizer always retain their normalizer, including callbacks
and errors. This avoids repeated parsing when ordinary requests are checked
against the legacy `cn=config` suffix. Password-policy DN normalization also
opts into the existing bounded cache when using the retained runtime registry;
the original configuration-DN check and custom-normalizer path remain.

Both password-Bind snapshots reuse the existing immutable object-class
classifier for subentry/alias/referral rejection, with its original fallback.
External-password preverification compacts the independently owned values
returned by `AttributeValues`, instead of copying each permitted password value
again. It retains value order, per-value ACL checks, both snapshots and ordered
local/external verification. Password hashes, work factors, lockout/counter
updates, cancellation and final-snapshot verification are unchanged.

The naming-context index reuses a physical key's owned identity suffix only
after complete decoding, validation and normalization establish exact equality.
Rows sharing a parent reuse one parent-key string. The parent group is removed
when the last child identity disappears, including duplicate-owner transitions.
Each row and shared parent is charged to the existing estimated memory budget;
the 256 MiB budget is unchanged. The index still validates changed rows and
retains rollback, invalidation, schema and global duplicate semantics. No new
unbounded intern table, entry payload cache or on-disk format is added.

Map backing capacity can retain a high-water allocation after deletion, and
same-identity replacements can retain original node/winner key storage alongside
the latest row key. Budget accounting remains conservative estimation rather
than exact heap measurement.

## Evidence and Method

The baseline profile executes 60k successful/failed user Binds with a temporary
SSHA user in the disposable 100k fixture. It includes the user setup and cleanup;
the warm and final profile boundaries force GC. The retained-heap profile
attributes about 80.6 MiB of 84.7 MiB to naming-context metadata. This diagnostic
is not a production RSS or request-latency measurement.

The online replay uses the same 100k fixture, indexes and OpenLDAP 2.6.13 build
as round 9: three fresh processes per implementation in rotating order, three
batches of 1,000 short operations and user Binds per process, three batches of
20 scan queries, full-prefix/paged output checks, 10k indexed queries and eight
concurrent clients. Authentication checks every result and WhoAmI after each
batch. Its temporary user is removed before full canonical exports are compared.
No benchmarks run concurrently with builds/tests; no timing outliers are removed.

The application changes leave password-policy, SASL, remote backend and general
DN fallback behavior in place. Any reported authentication speedup is specific
to the measured ordinary local SSHA configuration, not a reduction of password
work factors or an authentication-result cache.

## Component and Heap Results

Three 300ms samples of comparing `cn=config` with an ordinary four-RDN user
DN give medians of **2,250 ns, 1,120 bytes and 65 allocations** for reparsing
both displays, versus **94.4 ns and zero allocations** for the guarded direct
comparison. This is routing comparison only, not a complete Bind.
[Raw component measurements](evidence/performance-20260923-round10/routing-bench.txt).

The same diagnostic 60k-Bind workload has sampled retained heap of
**84.66 MiB before and 52.14 MiB current** (-38.4%). Naming-context metadata
accounts for approximately 80.63 and 48.11 MiB respectively. Sampled cumulative
allocation, subtracting the warm profile, decreases from **3,214.77 to
2,296.28 MiB** (-28.6%). Setup/cleanup are included and sampling introduces
measurement uncertainty. Forced-GC diagnostic figures must not be read as RSS
or unprofiled latency measurements.
[Heap before](evidence/performance-20260923-round10/heap-before.txt),
[heap current](evidence/performance-20260923-round10/heap-current.txt),
[allocation before](evidence/performance-20260923-round10/alloc-before.txt),
[allocation current](evidence/performance-20260923-round10/alloc-current.txt).

## Validation

The [full cgo-disabled suite](evidence/performance-20260923-round10/go-test.txt),
[vet](evidence/performance-20260923-round10/go-vet.txt), and
[focused tests](evidence/performance-20260923-round10/focused.txt) passed.
[Native OpenLDAP differential checks](evidence/performance-20260923-round10/openldap-differential.txt)
passed 200 checks including subtests, with no skips. A
[display-comparison differential fuzz run](evidence/performance-20260923-round10/display-fuzz.txt)
passed 402,461 executions in 20 seconds. No cgo or race-detector run is used.

Tests compare routing against the original parse-based functions across legacy,
schema-aware, case-exact, alias/OID, multi-AVA, escaped and empty DNs; custom
normalizer calls/errors retain their order. Authentication coverage includes
candidate ownership after reader mutation, ACL decisions for every value,
mixed local/RADIUS ordering, external verification outside the transaction,
and deletion/type changes between the two snapshots. Metadata tests include
duplicate winners, global parent transitions, repeated replacement, pruning,
budget accounting, retained heap, rollback and randomized updates.

## 100k Online Results

Nine-batch medians, three batches per fresh process and three processes per
implementation. Negative before/current time change is faster. Relative
performance is `OpenLDAP / current * 100%`, where larger is better.

| Stage, 1,000 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 172.91 ms | 132.30 ms | 69.13 ms | -23.5% | 52.2% |
| User Bind, wrong password | 170.45 ms | 132.95 ms | 70.75 ms | -22.0% | 53.2% |
| Root Bind | 106.73 ms | 88.75 ms | 66.51 ms | -16.8% | 74.9% |
| Base search | 101.98 ms | 103.91 ms | 84.25 ms | +1.9% | 81.1% |
| Indexed equality | 110.36 ms | 110.24 ms | 91.05 ms | -0.1% | 82.6% |
| Compare true | 111.56 ms | 109.18 ms | 73.21 ms | -2.1% | 67.0% |
| Compare false | 110.91 ms | 108.19 ms | 71.68 ms | -2.5% | 66.3% |

The same processes retain the original scan and traversal workloads:

| Workload | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| Prefix substring, 20 | 1,115.18 ms | 1,123.83 ms | 620.02 ms | +0.8% |
| Negative substring, 20 | 1,108.07 ms | 1,115.04 ms | 620.66 ms | +0.6% |
| Full prefix, 100k returned | 575 ms | 576 ms | 509 ms | +0.2% |
| Indexed CLI searches, 10,000 | 824 ms | 812 ms | 635 ms | -1.5% |
| Concurrent indexed, 8 x 1,000 | 228 ms | 232 ms | 230 ms | +1.8% |
| Paged traversal, 2 x 100k | 1,150 ms | 1,156 ms | 1,074 ms | +0.5% |
| Unindexed negative equality, 10 | 208 ms | 208 ms | 375 ms | 0.0% |

Small query differences in either direction are not stable improvement claims.
This round materially reduces ordinary authentication work; it does not improve
the substring scan algorithm or establish overall parity. Native and Go timings
vary on the shared host, so comparisons use same-run samples, not earlier
absolute times. No outliers were excluded.

Read/auth workload RSS medians are **467.2 / 442.5 / 145.2 MiB**
before/current/native, a **5.3%** current/before decrease. The three current
samples range from 397.9 to 541.6 MiB; RSS is much more variable than the
forced-GC retained-heap diagnostic. No claim equates those two measurements.

All nine runs passed SDK assertions and produced identical ordinary-attribute
exports: 100,002 entries, 42,712,438 canonical bytes, POSIX checksum
`2143929969`. Full-prefix and paged output contained 100,000 unique people.
[Long SDK samples](evidence/performance-20260923-round10/long-timings.json),
[20-operation samples](evidence/performance-20260923-round10/sdk-timings.json),
[traversal/concurrency samples](evidence/performance-20260923-round10/online-timings.tsv),
and [export/RSS checks](evidence/performance-20260923-round10/sdk-validation.tsv)
are retained.

## Write Regression

The same snapshot was checked with 20 entries per write stage, three fresh
processes per implementation in rotating order. SDK postcondition queries,
setup and cleanup are separate from each timed operation. Medians:

| Twenty operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 17.45 ms | 16.60 ms | 95.42 ms | -4.9% | 574.9% |
| Modify, unindexed description | 9.29 ms | 9.37 ms | 90.09 ms | +0.8% | 961.8% |
| ModifyDN | 24.53 ms | 27.93 ms | 102.22 ms | +13.9% | 366.0% |
| Delete | 18.78 ms | 18.09 ms | 92.74 ms | -3.7% | 512.7% |

The apparent ModifyDN increase warranted a larger recheck: three fresh processes
per version in current/before, before/current, current/before order, 100 entries
per write stage. No native measurement was taken in this recheck.

| One hundred operations | Before | Current | Time change |
| --- | ---: | ---: | ---: |
| Add | 85.50 ms | 88.26 ms | +3.2% |
| Modify | 44.04 ms | 45.69 ms | +3.7% |
| ModifyDN | 131.00 ms | 125.51 ms | -4.2% |
| Delete | 99.77 ms | 101.55 ms | +1.8% |

The larger test did not reproduce the 13.9% ModifyDN increase. Both sets are
retained; no overall write-speed improvement is claimed for this round. The
small sequential leaf-write fixture, existing durability settings and warm
index/cache conditions do not represent all production workloads.

The original write replay's RSS medians were 391.1 / 345.1 / 136.0 MiB
before/current/native. All fifteen write/recheck runs passed SDK postconditions
and produced the same complete canonical export as the nine read/auth runs.
[Write timings](evidence/performance-20260923-round10/write-timings.json),
[write validation](evidence/performance-20260923-round10/write-validation.tsv),
[larger recheck](evidence/performance-20260923-round10/write-recheck.json), and
[recheck validation](evidence/performance-20260923-round10/write-recheck-validation.tsv).

## Executables

Accepted executable SHA-256:

```text
before  5c669cc0497a9c825d8b9c3788ff12231d2518c617e8fb032a3126a11a669584
current bfa4b76c8bda1660df89a681bef9e11921ded3cd85a0270e17cf7ab6cfe81239
```

Exact local replay scripts, profiles and temporary probe sources are under
`/var/tmp/ldap-go-perf-round13-20260923`. The source snapshots are unchanged;
per-run disposable databases are removed after export validation and process exit.
