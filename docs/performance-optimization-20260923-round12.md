# Common substring scan overhead

Baseline: `9581b3d`. All Go builds and validation use `CGO_ENABLED=0`.
This continues the [protocol work](performance-optimization-20260923-round11.md)
with the same 100k fixture and native OpenLDAP 2.6.13 reference.

## Profile and Scope

The current-version diagnostic profile samples 20 prefix scans over the
existing disposable snapshot. DN identity/scope validation accounts for about
47% of sampled CPU, binary row decoding 24%, and attribute-name role lookup
16%. These are cumulative and potentially overlapping categories, not
independent percentages to add. Profiling has only one second of CPU samples;
online repeated measurements remain authoritative for latency.
[Baseline profile](evidence/performance-20260923-round12/substring-before-cpu.txt).

The changes target common short DN identity framing, one-byte stored field
lengths/counts, and repeated attribute-name classification within one substring
scan. Generic decoding and validation remain the fallback. Classification
does not cache values or results, and the original search visitor still handles
special entries, projection, visibility, deadlines and limits.

OpenLDAP's local `servers/slapd/filterentry.c:test_substrings_filter` uses
parsed attribute descriptions and matching-rule pointers. Reusing classification
for repeated descriptions follows that principle within the existing Go
representation, without changing the stored format or bypassing ACL checks.

## Validation and Measurements

The [full cgo-disabled suite](evidence/performance-20260923-round12/go-test.txt),
[vet](evidence/performance-20260923-round12/go-vet.txt), and
[200 native differential checks, including subtests](evidence/performance-20260923-round12/openldap-differential.txt)
passed. No checks in the native selection were skipped. RDN structural
validation passed [677,227 differential fuzz executions](evidence/performance-20260923-round12/dn-rdn-fuzz.txt);
the complete scope/error path passed [85,089 executions](evidence/performance-20260923-round12/dn-scope-fuzz.txt).

The short RDN recognizer checks both nested cardinalities, every one-byte length,
the nonempty attribute and exact final framing. Larger or nonminimal varints
retain the original validator. Stored-field/count fast paths keep the original
generic parser for unsupported input. Differential tests compare bytes, nilness,
capacity, input aliasing, full decoded entries and error chains against the old
consumers, including malformed, nonminimal and overflowing encodings.

The per-scan cursor retains at most 64 owned descriptions of at most 128 bytes
each, and admits at most 256 copies over its entire lifetime. Exhaustion affects
only caching: roles still use the same plan lookup. Long descriptions and large
rows do not refund admissions. This bounds both retained description bytes
(8 KiB) and cumulative copied bytes (32 KiB), in addition to the fixed cursor
metadata. Values and class flags are recomputed for every entry. The immutable
plan stays shareable; each sequential scan owns its cursor. Tests cover layouts,
options, aliases/subtypes, Unicode, changed values, schema snapshots, nil
semantics, independent cursors and cache exhaustion. The server's existing
optimized/general-filter and special-entry comparisons also pass.

## Component Measurements

Three 300ms samples, medians. Attribute-classification measurements include
matching but exclude cursor warmup; alternating layouts exhaust the copy budget
before timing. Both paths allocate zero bytes in these steady-state cases.

| Eleven-attribute workload | Immutable plan | Scan cursor |
| --- | ---: | ---: |
| Stable layout, hit | 195.8 ns | 70.14 ns |
| Stable layout, miss | 194.7 ns | 73.75 ns |
| Alternating layouts, hit | 195.7 ns | 128.1 ns |
| Alternating layouts, miss | 230.8 ns | 147.2 ns |

Warmup and the bounded name copies are real per-query costs, not a claim of
zero allocation for creating a cursor. [Raw cursor samples](evidence/performance-20260923-round12/cursor-bench.txt).

| DN validation workload | Before | Current | Bytes / allocations, unchanged |
| --- | ---: | ---: | ---: |
| Common ASCII DN | 171.8 ns | 154.2 ns | 0 / 0 |
| OID attribute | 165.5 ns | 152.1 ns | 0 / 0 |
| Multi-AVA fallback | 1,109 ns | 1,154 ns | 552 / 27 |
| Escaped fallback | 1,015 ns | 1,386 ns | 520 / 24 |

The baseline benchmark uses the unchanged `9581b3d` directory source through
a Go overlay. The initial escaped-fallback samples vary from 1,082 to 1,620 ns;
the apparent slowdown is retained and rechecked separately.
[Before](evidence/performance-20260923-round12/dn-before-bench.txt),
[current](evidence/performance-20260923-round12/dn-current-bench.txt).

Five-sample reverse-order rechecks gave before/current 1,108 / 1,192 ns for
multi-AVA and 1,005 / 1,115 ns for escaped DNs. A further interleaved sequence
(current/before, before/current, current/before) gave 1,185 / 1,290 ns and
1,225 / 1,140 ns respectively. These fallback inputs leave the ASCII recognizer
before the changed RDN helper; no validation work is removed from their path.
The mixed timing results, including slower cases, are retained rather than
claimed as a fallback improvement or a universal no-regression guarantee.
[Reverse before](evidence/performance-20260923-round12/dn-fallback-before-recheck.txt),
[reverse current](evidence/performance-20260923-round12/dn-fallback-current-recheck.txt),
[paired before](evidence/performance-20260923-round12/dn-fallback-paired-before.txt),
[paired current](evidence/performance-20260923-round12/dn-fallback-paired-current.txt).

| Stored primitive | Original | Current |
| --- | ---: | ---: |
| Short field | 3.163 ns | 2.695 ns |
| Short count | 2.934 ns | 2.134 ns |
| 128-byte field | 3.810 ns | 4.000 ns |
| Count 128 | 3.588 ns | 5.972 ns |
| Nonminimal field | 3.799 ns | 4.003 ns |
| Nonminimal count | 3.597 ns | 3.834 ns |

All six primitive cases remain allocation-free. Malformed varints retain the
same one-error allocation. Long/nonminimal inputs pay an additional short-path
check; no universal speedup is claimed. Count-128 samples also show substantial
timing variation. [Raw primitive samples](evidence/performance-20260923-round12/codec-bench.txt).
Five longer count-128 samples give 3.742 / 4.156 ns before/current, with no
allocations: the extra guard has a small cost on this fallback input.
[Count recheck](evidence/performance-20260923-round12/count-long-recheck.txt).

The diagnostic profile after integration has 930 ms sampled CPU versus 1,000 ms
before; name-role lookup no longer appears among the top 25 nodes. The short
sample duration does not establish an end-to-end speedup.
[Current profile](evidence/performance-20260923-round12/substring-current-cpu.txt).

## Online Results

The same snapshot and indexes were used by three fresh processes per
implementation in rotating order. Each process ran three batches of 20 scan
queries, three batches of 1,000 ordinary short operations and authentication,
and the traversal/concurrency probes. All nine runs passed SDK assertions and
produced the same complete ordinary-attribute export: 100,002 entries,
42,712,438 canonical bytes, POSIX checksum `2143929969`.

Medians, retaining every sample. Relative performance is
`OpenLDAP / current * 100%`; larger is better.

| Workload | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Prefix substring, 20 | 1,107.52 ms | 906.59 ms | 618.63 ms | -18.1% | 68.2% |
| Negative substring, 20 | 1,101.03 ms | 900.94 ms | 621.25 ms | -18.2% | 69.0% |
| Full prefix, 100k returned | 595 ms | 555 ms | 509 ms | -6.7% | 91.7% |
| Indexed CLI searches, 10,000 | 856 ms | 769 ms | 631 ms | -10.2% | 82.1% |
| Concurrent indexed, 8 x 1,000 | 265 ms | 199 ms | 203 ms | -24.9% | 102.0% |
| Paged traversal, 2 x 100k | 1,341 ms | 1,157 ms | 1,047 ms | -13.7% | 90.5% |
| Unindexed negative equality, 10 | 226 ms | 204 ms | 344 ms | -9.7% | 168.6% |

| Stage, 1,000 operations | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| User Bind, SSHA | 136.03 ms | 125.84 ms | 67.60 ms |
| User Bind, wrong password | 131.59 ms | 121.55 ms | 68.80 ms |
| Root Bind | 140.57 ms | 84.35 ms | 62.63 ms |
| Base search | 161.10 ms | 97.85 ms | 80.96 ms |
| Indexed equality | 149.21 ms | 102.83 ms | 87.67 ms |
| Compare true | 122.15 ms | 102.38 ms | 67.16 ms |
| Compare false | 111.67 ms | 99.06 ms | 68.21 ms |

The scan reduction is the intended workload benefit. The much larger apparent
short-operation gains are not attributed to the code: batches vary considerably,
and the 20-operation probes have different before/current timing directions.
An interleaved recheck is recorded separately. RSS medians after read/auth work
were 398.2 / 414.2 / 95.6 MiB before/current/native. No memory reduction is claimed.

[Scan samples](evidence/performance-20260923-round12/sdk-timings.json),
[short-operation samples](evidence/performance-20260923-round12/long-timings.json),
[long-DN/password samples](evidence/performance-20260923-round12/extended-timings.json),
[traversal samples](evidence/performance-20260923-round12/online-timings.tsv),
[export/RSS checks](evidence/performance-20260923-round12/sdk-validation.tsv).

## Short-Operation Rechecks

The first recheck kept one warmed process of each implementation resident,
sent only one client workload at a time, rotated implementation order for each
workload, and increased each batch to 3,000 operations. Three rounds with three
batches each give nine samples per metric. This reduces temporal separation
but is not the same process/memory condition as the initial replay.

| Stage, 3,000 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 384.81 ms | 380.35 ms | 195.69 ms | -1.2% | 51.5% |
| User Bind, wrong password | 432.81 ms | 397.27 ms | 205.56 ms | -8.2% | 51.7% |
| Root Bind | 265.74 ms | 269.17 ms | 194.37 ms | +1.3% | 72.2% |
| Base search | 299.48 ms | 308.35 ms | 245.55 ms | +3.0% | 79.6% |
| Indexed equality | 318.27 ms | 321.94 ms | 268.46 ms | +1.2% | 83.4% |
| Compare true | 312.03 ms | 325.59 ms | 209.41 ms | +4.3% | 64.3% |
| Compare false | 314.67 ms | 326.94 ms | 210.78 ms | +3.9% | 64.5% |

Long-DN Compare in this batch recheck appeared 12-21% slower, opposite to the
initial replay. A final probe therefore rotated the endpoint after *every*
request, including the first endpoint's position. It created identical short-DN,
202-byte-DN and 256-byte-password SSHA users in each disposable directory, warmed
each operation, and verified every response plus WhoAmI after each batch.
Each row below is the median of three batches of 3,000 calls per endpoint,
summing only that endpoint's timed calls. Setup, cleanup and identity checks are
excluded. Every nonmatching Compare uses a 256-byte assertion; the wrong Bind
password remains short. Root Bind uses the same root DN in every fixture.

| Request-paired workload, 3,000 calls | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| Short DN, successful Bind | 373.60 ms | 370.77 ms | 212.12 ms | -0.8% |
| Short DN, wrong password | 441.28 ms | 457.87 ms | 282.84 ms | +3.8% |
| Short-DN fixture, Root Bind | 302.85 ms | 326.49 ms | 254.01 ms | +7.8% |
| Short DN, matching Compare | 351.42 ms | 352.62 ms | 256.20 ms | +0.3% |
| Short DN, nonmatching Compare | 312.63 ms | 313.21 ms | 215.98 ms | +0.2% |
| Long DN, successful Bind | 434.81 ms | 443.05 ms | 231.04 ms | +1.9% |
| Long DN, wrong password | 518.27 ms | 516.36 ms | 297.51 ms | -0.4% |
| Long-DN fixture, Root Bind | 257.38 ms | 264.73 ms | 209.26 ms | +2.9% |
| Long DN, matching Compare | 323.46 ms | 325.04 ms | 219.23 ms | +0.5% |
| Long DN, nonmatching Compare | 325.82 ms | 325.53 ms | 220.69 ms | -0.1% |
| Long password, successful Bind | 377.77 ms | 374.84 ms | 213.39 ms | -0.8% |
| Long-password fixture, short wrong password | 368.72 ms | 375.06 ms | 210.63 ms | +1.7% |
| Long-password fixture, Root Bind | 253.95 ms | 257.71 ms | 202.28 ms | +1.5% |
| Long-password fixture, matching Compare | 301.21 ms | 300.17 ms | 206.46 ms | -0.3% |
| Long-password fixture, nonmatching Compare | 319.96 ms | 319.17 ms | 220.57 ms | -0.2% |

The large long-DN Compare regression did not reproduce with per-request
rotation. Authentication and Root Bind remain mixed, including slower results.
Neither the large initial gains nor a blanket no-regression statement is
supported for short operations. This round's accepted benefit is the repeated
substring scan reduction, with bounded classification state and unchanged
functional checks. Authentication, scans and memory still trail native OpenLDAP
in material workloads; the performance goal is not complete.

Both rechecks passed their SDK assertions and three full ordinary-attribute
exports each. Combined with the read and write replays, 24 complete exports
matched the same canonical fixture.
[Batch samples](evidence/performance-20260923-round12/interleaved-timings.json),
[extended batch samples](evidence/performance-20260923-round12/interleaved-extended-timings.json),
[batch export checks](evidence/performance-20260923-round12/interleaved-validation.tsv),
[per-request samples](evidence/performance-20260923-round12/request-paired-samples.json),
[per-request export checks](evidence/performance-20260923-round12/request-paired-validation.tsv).

## Write Regression

Twenty leaf entries per stage, three fresh processes per implementation in
rotating order. Setup, SDK postcondition verification and cleanup are outside
the measured operations. All nine full ordinary-attribute exports matched the
same canonical data as the read replay.

| Twenty operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 17.58 ms | 15.46 ms | 110.41 ms | -12.0% | 714.0% |
| Modify, unindexed description | 7.78 ms | 8.23 ms | 116.95 ms | +5.8% | 1,420.8% |
| ModifyDN | 26.22 ms | 28.39 ms | 111.31 ms | +8.3% | 392.0% |
| Delete | 18.76 ms | 18.60 ms | 117.94 ms | -0.9% | 634.2% |

Mixed small-batch write timings are retained; this is not a write-path speedup
claim. The fixture and existing durability settings do not represent all
production workloads.
[Write samples](evidence/performance-20260923-round12/write-timings.json),
[export checks](evidence/performance-20260923-round12/write-validation.tsv).

## Reproduction

The accepted baseline is the previous round's executable whose source became
`9581b3d`; current adds this round's three production changes. Both use Go 1.26.4,
darwin/arm64 and `CGO_ENABLED=0`, with the same dependencies and build settings.
SHA-256:

```text
before  7d39057484e2849576dba6abe8d075460d483d0c5f81d1d5173f375742af113f
current 2c99009916ddd3dcb00091be38d3004a151ba819ec1d86bfc8047ac93bd163b4
```

Benchmarks ran without concurrent builds/tests. Timing outliers remain in the
raw samples. Disposable servers were stopped after validation; source snapshots
were unchanged. Local artifacts are under `/var/tmp/ldap-go-perf-round15-20260923`.
The exact local [read replay](evidence/performance-20260923-round12/replay.sh.txt),
[write replay](evidence/performance-20260923-round12/write-replay.sh.txt),
[batch recheck](evidence/performance-20260923-round12/interleaved.sh.txt),
[per-request replay](evidence/performance-20260923-round12/request-paired.sh.txt)
and [paired SDK probe](evidence/performance-20260923-round12/paired-probe.go.txt)
require the existing qualification fixtures/probes at their recorded paths.
Use the repository's [comparison runner](../scripts/qualification/compare-openldap.sh)
and [100k setup instructions](openldap-100k-evidence.md#reproduction-and-limits)
for a fresh environment.
