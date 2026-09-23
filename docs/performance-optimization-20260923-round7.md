# DN construction and Bind routing

Baseline: `9d66cbc`. This continues the
[read](performance-optimization-20260923-round5.md) and
[write](performance-optimization-20260923-round6.md) investigations. All Go
builds, tests and benchmarks use `CGO_ENABLED=0`.

## Changes

- Identity encoding computes exact varint/payload capacity before appending.
  Short identity keys use local byte buffers before creating the owned output
  string; larger values use heap buffers. Binary and Base64 bytes are unchanged,
  with no unsafe conversion or retained borrowed data.
- A single-AVA RDN no longer constructs temporary AVA arrays or invokes sorts.
  It shares the existing normalization and canonical-name callbacks, preserving
  their order, alias-collision checks, error behavior and ownership. Multi-AVA
  RDNs retain the general ordering path.
- Naming-context inference requests the parent identity key directly instead
  of constructing a complete parent DN. It also stores each map key once and
  sorts only the resulting context keys. All rows are still validated and
  normalized; duplicate overwrite rules, orphans and result ordering remain.
- Ordinary Simple Bind reuses the database already selected for its security
  checks. Disabled backend probes no longer repeat routing/normalization.
  Enabled handlers retain their order and original implementation. Lastbind
  first scans the operation's retained database configuration for an enabled
  overlay, avoiding DN work when none exists. No new feature cache, credential
  cache, password shortcut or weaker work factor is introduced.

Naming-context refresh remains O(N), and Delete/ModifyDN still have full
hierarchy scans. These changes reduce repeated construction rather than
eliminating the underlying scan requirements.

## Component Evidence

Three 300ms samples per identity-encoding case, against the old append/encoding
implementation in the same binary; medians:

| Identity | Reference | Current | Allocated bytes | Allocation count |
| --- | ---: | ---: | ---: | ---: |
| One RDN | 126.8 ns | 56.3 ns | 248 / 64 | 5 / 1 |
| Four RDNs | 328.8 ns | 151.2 ns | 1,032 / 240 | 7 / 1 |
| Sixteen RDNs | 1,041 ns | 752.3 ns | 4,120 / 2,496 | 9 / 3 |

The 100k naming-context fixture is identical on baseline and current production
code, compiled using a Go overlay for the two changed baseline files. Three
samples of three scans each exclude fixture construction and commits:

| Metadata naming-context scan | Before | Current | Change |
| --- | ---: | ---: | ---: |
| Time | 511.52 ms | 406.16 ms | -20.6% |
| Allocated bytes | 489,287,994 | 302,686,650 | -38.1% |
| Allocations | 12,000,524 | 8,400,530 | -30.0% |

These are component results, not complete LDAP operation timings. The earlier
diagnostic CPU/heap profile included fixture setup and is not substituted for
these unprofiled measurements.
[Encoding samples](evidence/performance-20260923-round7/encode-bench.txt),
[scan baseline](evidence/performance-20260923-round7/naming-before-bench.txt),
and [scan current](evidence/performance-20260923-round7/naming-current-bench.txt)
are retained.

## 100k Read Replay

The preceding round's disposable fixture, native OpenLDAP 2.6.13, limits and
client commands are unchanged. Three fresh processes per implementation run
in rotating order. SDK stages have two warmup operations then three batches of
20 operations per process. The table reports nine-batch medians; batches in one
process are not independent process samples. Negative time change is faster;
relative performance is `OpenLDAP / current * 100%`, where larger is better.

| SDK stage, 20 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 8.34 ms | 4.50 ms | 2.35 ms | -46.0% | 52.1% |
| Base search | 3.20 ms | 3.26 ms | 2.65 ms | +2.0% | 81.4% |
| Indexed equality | 3.35 ms | 3.55 ms | 2.82 ms | +6.2% | 79.4% |
| Compare true | 3.98 ms | 4.33 ms | 2.29 ms | +8.7% | 52.8% |
| Compare false | 4.32 ms | 3.98 ms | 2.31 ms | -7.9% | 57.9% |
| Substring prefix | 1,183.67 ms | 1,176.99 ms | 624.05 ms | -0.6% | 53.0% |
| Substring negative | 1,180.80 ms | 1,163.14 ms | 627.82 ms | -1.5% | 54.0% |

Other workloads use one batch per process, except full-prefix traversal, which
has three per process. Client execution and output-file writing are included.

| Workload | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full prefix, 100k returned | 707 ms | 712 ms | 649 ms | +0.7% | 91.2% |
| Indexed equality, 10,000 | 804 ms | 821 ms | 594 ms | +2.1% | 72.4% |
| Concurrent indexed, 8 x 1,000 | 232 ms | 228 ms | 235 ms | -1.7% | 103.1% |
| Paged traversal, 2 x 100k | 1,417 ms | 1,438 ms | 1,339 ms | +1.5% | 93.1% |
| Unindexed negative equality, 10 | 205 ms | 202 ms | 347 ms | -1.5% | 171.8% |

Small-operation results showed mixed changes, so a separate longer recheck
used the same SDK functions for Bind, base/equality searches and Compare, with
20 warmup operations and three 1,000-operation batches per process. Three
processes per version alternated current/before, before/current, current/before.
No native result was collected in this recheck. Nine-batch medians:

| Stage, 1,000 operations | Before | Current | Time change |
| --- | ---: | ---: | ---: |
| Root Bind | 309.93 ms | 160.94 ms | -48.1% |
| Base search | 103.76 ms | 102.18 ms | -1.5% |
| Indexed equality | 111.21 ms | 107.34 ms | -3.5% |
| Compare true | 149.96 ms | 139.60 ms | -6.9% |
| Compare false | 151.06 ms | 143.44 ms | -5.0% |

The longer recheck did not reproduce the short-batch regressions; it does not
prove regression-free performance for every workload. Original samples are
retained, not replaced. Read-workload RSS medians were 328.3 / 362.5 / 94.1 MiB
for before/current/native, an observed **10.4% increase**. Sampling occurs after
the mixed workload without forced GC, with overlapping process ranges. This
round does not claim lower memory usage for reads.

Evidence: [SDK samples](evidence/performance-20260923-round7/sdk-timings.json),
[command-line workloads](evidence/performance-20260923-round7/online-timings.tsv),
[longer recheck](evidence/performance-20260923-round7/short-recheck.json), and
[export/RSS checks](evidence/performance-20260923-round7/sdk-validation.tsv).

## 100k Write Replay

Three fresh processes per implementation use the same rotating order and
three entries per write stage. The SDK verifies each write, cleans up its
temporary OU/users, and then exports the complete directory. Setup, cleanup and
verification times are recorded separately. This is a sequential regression
workload, not a concurrent write-capacity benchmark.

| Stage, three operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 2.02 ms | 1.51 ms | 0.31 ms | -25.6% | 20.5% |
| Add | 2,390.91 ms | 1,917.53 ms | 13.36 ms | -19.8% | 0.70% |
| Modify, unindexed description | 2.49 ms | 2.51 ms | 14.38 ms | +0.7% | 572.7% |
| ModifyDN | 3,632.67 ms | 3,099.54 ms | 14.31 ms | -14.7% | 0.46% |
| Delete | 3,456.14 ms | 2,973.12 ms | 15.88 ms | -14.0% | 0.53% |

Add, ModifyDN and Delete remain far slower than native OpenLDAP. Their scans
are still O(N). Small Modify and user-Bind totals are noisy; unchanged password
work factors and existing storage durability settings must be considered when
comparing implementations. Post-write RSS medians were 642.5 / 531.8 / 133.8 MiB,
a 17.2% current/before decrease; this does not negate the read-workload RSS rise.

All eighteen main read/write runs passed request validation and produced
identical ordinary-attribute exports: 100,002 entries, 42,712,438 canonical
bytes, POSIX checksum `2143929969`. Full-prefix/paged traversals returned all
100,000 unique people. The longer read-only recheck also passed SDK assertions.
[Write samples](evidence/performance-20260923-round7/write-sdk-timings.json),
[write export checks](evidence/performance-20260923-round7/write-validation.tsv),
and [per-process reports](evidence/performance-20260923-round7/) are retained.

Executable SHA-256:

```text
before  e46886800e26f7d50b7432c5ac512e3889d739f84e5b4ba072885501d90bdfed
current 5c21f9bb700643e3256b3194a0344a0425be2cd80513ffa6b06b68893872a680
```

Local scripts and raw output are under `/var/tmp/ldap-go-perf-round10-20260923`.
Disposable database copies were removed after each server exited to limit disk
usage; source snapshots and exported evidence were retained. This is a verified
checkpoint at which optimization was paused at the user's request, not a claim
of complete OpenLDAP performance parity.

## Validation

Tests compare exact identity bytes over varint and buffer-size boundaries,
independent output ownership, old/new normalization results and callback
errors, alias collisions, mixed single/multi-AVA names, escaping, parent keys,
buffer mutation and renormalization. Bind tests cover success/failure/rebind,
identity clearing, root-password and restriction reloads, control/security
precedence, and lastbind enable/remove/re-enable on an existing connection.

The [full suite](evidence/performance-20260923-round7/go-test.txt),
[vet](evidence/performance-20260923-round7/go-vet.txt), and
[native OpenLDAP differential checks](evidence/performance-20260923-round7/openldap-differential.txt)
passed (194 including subtests, no skips). A
[normalization differential fuzz run](evidence/performance-20260923-round7/normalize-fuzz.txt)
passed 69,314 executions. No race-detector result is claimed with cgo disabled.

The final style review changed the context-key sort from `sort.Strings` to
`slices.Sort` and used integer ranges in two new tests. The performance binaries
above precede these equivalent style edits; the final
[focused regression run](evidence/performance-20260923-round7/final-focused.txt)
covers naming contexts, DN normalization/encoding/parent keys, Bind routing and
lastbind lifecycle. The frozen normalization reference intentionally retains
the baseline algorithm for differential testing.
