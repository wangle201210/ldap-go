# Cached paging and allocation optimization

This round compares against `5e781d9` on the same 100k fixture used by the
[preceding round](performance-optimization-20260922-round2.md). All Go builds,
tests, profiling, and benchmarks explicitly use `CGO_ENABLED=0`.

## Changes and behavior

- Attribute descriptions without `;` return their trimmed name without
  allocating an empty options map or a split slice. Options, including empty,
  repeated, language, and binary options, keep the existing parser. Callers only
  read the option maps, so a nil empty map has the same matching behavior.
- The Bolt DN migration marker's physical key is constructed in one byte
  buffer. The key bytes, transaction reads, cancellation checkpoints, missing
  marker fallback, and format-version validation remain unchanged. This adds
  no readiness cache and changes no stored format.
- A paging snapshot cache hit shares the cache's immutable item array and
  creates an independent cursor. It avoids the old lookup copy and first
  continuation copy. Cache publication still copies the caller's array; first
  snapshot construction is unchanged. Cache admission still uses the input
  capacity, and each client's memory charge uses the same copied capacity as
  before. Continuations still require the original second reservation. Cache
  replacement, eviction, cancellation, and storage revision invalidation keep
  their existing behavior.

No filter, ACL, authentication, result-order, database, or wire-format rules
were changed. The former copying cache lookup remains only as a test reference.

## Same-run 100k comparison

The [primary comparison](openldap-100k-evidence.md#final-online-replay) records
the exact workload, OpenLDAP values, and process order. Both Go versions ran
three processes from independent copies of the same database. Each process
ran one first batch and three repeated batches. Values below are medians of
three first batches or nine repeated batches; RSS has three samples. These are
observed changes, not confidence intervals or guaranteed improvements.

Change is `(current / before - 1) * 100%`; negative means less time or memory.
This differs from the OpenLDAP-relative percentage in the main comparison.

| Metric | Before | Current | Change |
| --- | ---: | ---: | ---: |
| Indexed, first 10,000 queries | 890 ms | 848 ms | -4.7% |
| Indexed, repeated 10,000 queries | 692 ms | 639 ms | -7.7% |
| Negative, first ten queries | 317 ms | 240 ms | -24.3% |
| Negative, repeated ten queries | 31 ms | 31 ms | 0.0% |
| First full objectClass traversal | 938 ms | 826 ms | -11.9% |
| Two repeated objectClass traversals | 841 ms | 825 ms | -1.9% |
| Concurrent indexed, 8 x 1,000 | 258 ms | 266 ms | +3.1% |
| RSS after mixed workload | 340.3 MiB | 253.1 MiB | -25.6% |

The concurrency median was slightly slower, so a separate check repeated only
that workload after warming indexed, negative, and paging requests. Process
order was `before-1 current-1 current-2 before-2 before-3 current-3`, with seven
batches per process. Its 21-sample medians were **246 ms before and 237 ms
current** (-3.7%); ranges were 231-290 ms and 231-265 ms. These overlapping
samples and the reversed difference do not establish a stable regression or a
stable concurrency improvement. The original +3.1% result is retained above.

The host runs other applications. Small differences, including the 1.9% paging
change, should not be treated as stable speedups. First-query differences also
include allocation/GC effects from preceding workloads. RSS is a post-workload
sample, not peak memory: OpenLDAP itself ranged from 95.4 to 144.5 MiB in this
run. Its earlier 94.3 MiB median is not substituted into the latest comparison.

All nine primary runs and six concurrency checks returned the same 100,002
ordinary-attribute entries: 42,712,504 canonical bytes, POSIX checksum
`648440320`, with byte-for-byte comparisons. Indexed/negative/concurrent result
counts and 100,000 unique people in the paged result were also checked.

Raw evidence:
[timings](evidence/performance-20260922-round3/online-timings.tsv),
[validation](evidence/performance-20260922-round3/online-validation.tsv),
[concurrency recheck](evidence/performance-20260922-round3/concurrency-recheck-timings.tsv),
[recheck validation](evidence/performance-20260922-round3/concurrency-recheck-validation.tsv).

Executable SHA-256 values:

```text
before  8c2a32480b33dd317f3495ce2d1cd0d95975ad58f985c2f5ece517f80fc9ad64
current ede86fab5a54a118733f3ed2927a60f96acda611ed144b85980e363c5dc36d1a
```

## Allocation evidence

Focused benchmarks compare retained reference implementations in the same
test binary. Results are medians of five samples for attribute parsing and
paging, and three for metadata keys.

| Operation | Before | Current | Allocated bytes before / current |
| --- | ---: | ---: | ---: |
| Parse `uid` description | 51.54 ns | 6.299 ns | 64 / 0 |
| Build ordinary database marker key | 105.4 ns | 41.92 ns | 240 / 80 |
| 100k paging cache lookup plus first clone | 7.04 ms | 54.77 ns | ~48,005,170 / 96 |

The last benchmark isolates array lookup/copying and memory accounting. It does
not encode or send entries and is **not** an end-to-end paging speedup claim.
It confirms that each cached traversal avoids roughly 45.8 MiB of array
allocations. Empty and 64 KiB binary partition keys also retain identical bytes;
ordinary nonempty marker keys fall from four allocations to one.

A diagnostic profile of 90,000 distinct indexed queries measured about
1,005 MiB allocated before versus 947 MiB with only the attribute parser change.
This is intermediate allocation evidence, not final RSS or latency. The
profiling harness forces GC at boundaries; the online comparison does not.

Evidence: [attribute parser](evidence/performance-20260922-round3/schema-bench.txt),
[metadata key](evidence/performance-20260922-round3/metadata-key-bench.txt),
[paging cache](evidence/performance-20260922-round3/paging-bench.txt),
[before profile](evidence/performance-20260922-round3/cold-alloc-before.txt),
[parser-only profile](evidence/performance-20260922-round3/cold-alloc-schema-only.txt).

## Validation and reproduction

Full package tests and vet passed. The native OpenLDAP differential run passed
15 top-level tests, 194 including subtests, with no skips or failures. Focused
tests cover immutable cache ownership, independent cursors, replacement and
eviction, cancellation cleanup, exact capacity charges and double-admission
thresholds, and continuation across writes. Attribute parser fuzzing completed
105,908 comparisons; marker-key fuzzing completed 303,559 comparisons.

```sh
CGO_ENABLED=0 go test -p=1 ./... -count=1 -timeout=10m
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test ./internal/schema -run '^$' -bench '^BenchmarkSplitAttributeDescription$' -benchmem
CGO_ENABLED=0 go test ./internal/storage -run '^$' -bench '^BenchmarkBoltSchemaAwareDNMigrationMetadataKey$' -benchmem
CGO_ENABLED=0 go test ./internal/server -run '^$' -bench '^BenchmarkPagedSnapshotCacheHit$' -benchmem
```

[Full tests](evidence/performance-20260922-round3/go-test.txt),
[focused paging tests](evidence/performance-20260922-round3/paging-focused.txt),
[native differential tests](evidence/performance-20260922-round3/openldap-differential.txt),
and [metadata-key fuzzing](evidence/performance-20260922-round3/metadata-key-fuzz.txt)
are retained. The complete replay drivers, binaries, database copies, LDIF, and
profiles remain under `/var/tmp/ldap-go-perf-round3-20260922` on the qualification
host. For fresh-data reproduction, use the repository's
[100k comparison command](openldap-100k-evidence.md#reproduction-and-limits).

First indexed queries, first broad paging, and memory still trail OpenLDAP in
the primary run. Import, writes, startup, and file size were not remeasured;
their earlier results remain separately labeled in the main report.
