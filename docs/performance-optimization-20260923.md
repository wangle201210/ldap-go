# Substring scanning and DN reuse

Baseline: `205b61b`. Measurements were collected on September 22-23, 2026,
Asia/Shanghai, on the same shared Apple M1 Pro host and OpenLDAP 2.6.13 reference.
All Go builds, tests, and benchmarks use `CGO_ENABLED=0`.

## Changes

Unindexed, unsorted root substring searches can use a read-only Bolt iterator.
It reuses bounded attribute/value descriptors, validates every DN before its
callback, and copies retained output through the existing selection path.
Ordinary attribute selections, including `*`, are supported. Operational
projections, overlays that can retain or change input, non-root ACL filtering,
paging, sorting, synchronization, unsupported readers and writable transactions
retain their original paths. No stored format or index configuration changes.

The substring matcher prepares fixed assertions and schema information once
when a root query must scan. Indexed queries do not incur this preparation.
Prepared matching now handles ordered-value prefixes and skips invalid values
before trying later values, just like top-level `Filter.MatchWith`. Missing or
undefined results collapse to false only at the root. General matcher errors
and nested three-valued filter behavior remain unchanged.

Naming-context inference reuses the legacy DN parsed during binding validation
for configuration-subtree classification and current-schema normalization.
`DN.NormalizeWith` preserves the original parsed attributes and does not mutate
shared DNs. Inference still scans and validates every record, including
overwritten duplicates, and preserves normalizer call/error order. Unknown
readers and codec fallback paths keep the existing behavior. This optimization
does not substitute the stored identity for normalization under the current schema.

## Repeated 100k SDK comparison

Each implementation ran three fresh processes from independent copies of the
same contiguous-UID 100k fixture used in round four. Each process ran a two-query
warmup per stage, then three SDK batches of 20 operations per stage. The order
was `before-1 current-1 openldap-1 current-2 openldap-2 before-2 openldap-3
before-3 current-3`. Values below are medians of nine batches; the three batches
inside one process are not independent process samples. No forced GC or OS-cache
eviction was used. The probe checked search DNs, exact values/counts and Compare
booleans on every operation.

| Stage, 20 operations | Before | Current | OpenLDAP | Time change | OpenLDAP / current |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 8.06 ms | 8.05 ms | 2.72 ms | -0.1% | 33.7% |
| Base search | 3.48 ms | 3.28 ms | 2.68 ms | -5.8% | 81.7% |
| Indexed equality | 3.53 ms | 3.41 ms | 2.69 ms | -3.4% | 79.1% |
| Compare true | 9.21 ms | 9.20 ms | 2.23 ms | -0.1% | 24.3% |
| Compare false | 8.77 ms | 9.13 ms | 2.15 ms | +4.1% | 23.5% |
| Substring prefix | 9,397.24 ms | 3,939.83 ms | 619.51 ms | -58.1% | 15.7% |
| Substring negative | 9,454.42 ms | 3,938.06 ms | 625.17 ms | -58.3% | 15.9% |

Time change is `(current / before - 1) * 100%`; negative is faster. The last
column uses `OpenLDAP / current * 100%`, so larger is better. Small differences
on the non-substring stages are not evidence of stable gains or regressions:
for example, Compare-false batches range from 8.46-9.76 ms before and 8.41-9.75 ms
current. All raw samples are retained. No performance gain is claimed for those
unmodified operation paths.

The UID index remains equality-only. The substring requests still scan the
directory and remain about six times slower than OpenLDAP. These measurements
do not replace the earlier 10,000-query/paging workload or its memory samples.

All nine whole-directory exports matched byte for byte: 100,002 ordinary-attribute
entries, 42,712,438 canonical bytes, POSIX checksum `2143929969`.
Raw [SDK timings](evidence/performance-20260923/sdk-timings.json) and
[export validation](evidence/performance-20260923/sdk-validation.tsv) are retained.

Executable SHA-256 values:

```text
before  95cc0f52506dcf5ef8228da06583142898cebd0e265490c616a8e10f838b2de5
current 1a736be382980f7321de5c6a243de241d80b4335358aa8ea98075be7bd3a9e6d
```

## Component evidence

The physical-scan benchmark compares both iterators in the same binary on 10k
entries. Median time was 20.97 ms versus 5.71 ms (-72.8%), and allocation was
28.96 MB versus 1.61 MB (-94.4%). This isolates scanning and does not include the
complete LDAP filter/projection/response path.

The naming-inference comparison compiles the identical new benchmark fixture
on the baseline and current implementations. Three one-second samples isolate
the metadata inference stage on a read snapshot, with setup and transactions
outside the timed loop:

| Entries | Before | Current | Time change | Allocated bytes before / current |
| --- | ---: | ---: | ---: | ---: |
| 10k | 78.73 ms | 49.72 ms | -36.8% | 63.00 MB / 49.40 MB |
| 100k | 792.75 ms | 508.30 ms | -35.9% | 625.29 MB / 489.29 MB |

This is a component improvement, not a new end-to-end Add/Delete/ModifyDN
measurement. The metadata scan remains O(N).

Raw evidence: [physical scan](evidence/performance-20260923/physical-bench.txt),
[naming baseline](evidence/performance-20260923/naming-before.txt),
[naming current](evidence/performance-20260923/naming-current.txt).

A diagnostic profile of 20 repeated prefix scans still shows costs in schema
name case-folding, value normalization, DN validation/scope decoding, and owned
DN/identity strings. It allocates approximately 832 MiB during that workload.
This harness forces GC at profile boundaries and is not an RSS benchmark.
[CPU](evidence/performance-20260923/substring-cpu.txt) and
[allocation](evidence/performance-20260923/substring-alloc.txt) summaries identify
the remaining work rather than claiming the whole path has reached OpenLDAP.

## Validation and next work

Full Go tests and vet passed. The native OpenLDAP differential run passed
15 top-level tests, 194 including subtests, without skips or failures.
Reference tests cover V1/V2/V3/JSON decoding, cancellation checkpoints, callback
stops, late corruption, output ownership after Bolt unmap, root/non-root results,
limits, types-only and wildcard selections, ordered values, aliases and malformed
matching values. DN normalization tests check immutability, canonical alias
collisions, current-schema recomputation, and original error/call order.

The [full test log](evidence/performance-20260923/go-test.txt) and
[native differential log](evidence/performance-20260923/openldap-differential.txt)
are retained. The reusable [SDK probe](../internal/cmd/ldapbench/README.md) runs
against explicitly supplied disposable servers. Complete binaries, database
copies, JSON reports and profiles are retained at
`/var/tmp/ldap-go-perf-round5-20260922` on the qualification host.

Eliminating per-write naming-context scans requires transactionally tracked
changes and a global topology/contributor index. The
[incremental inference design](naming-context-incremental-design.md) records
its correctness requirements and is explicitly **not implemented**. Performance
optimization remains ongoing; this report is a verified checkpoint.
