# Name lookup and candidate normalization

This round follows `ec18938` and the
[substring scanning report](performance-optimization-20260923.md). All Go
builds and checks use `CGO_ENABLED=0`; the directory, index and wire formats
remain unchanged.

## Implementation

Prepared substring and object-class matchers recognize both canonical schema
names and their registered spellings. Known nonmatching attributes are recorded
too, so descriptions such as `createTimestamp` do not require a temporary
lowercase string for every scanned entry. Unknown spellings still use the
original `schemaKey` path, including whitespace and Unicode behavior. Object
class values use the same direct lookup with the original fallback.

Attribute-name tables are immutable and shared within one registry. The cache
holds at most 16 targets and 1 MiB of conservatively estimated table storage.
Oversized tables are not cached. Attribute registration, replacement,
configuration-schema installation and allowed-schema installation invalidate
the cache; clones start empty. Eviction or invalidation never changes published
tables. Schema and cache locks follow one consistent order.

Prepared matching can borrow a short candidate value when an ASCII check proves
that case-ignore or case-exact normalization would leave its bytes unchanged.
Whitespace, non-ASCII and values longer than 128 bytes use the original
normalizer. Octet-string matching also reads its candidate directly. Assertions
are always normalized into owned storage before these candidate-only shortcuts
are installed. Ordered prefixes are still validated and removed first; postal
lists and other matching rules retain their existing implementations.

The search visitor skips dynlist work only when its configuration is absent,
and nestgroup work only when the projection cache is globally disabled.
Frontend inheritance, active projections, ManageDsaIT, paging filter rewrites
and error handling are preserved.

## Component checks

Known-spelling object-class classification over a typical entry took a median
189 ns versus 693 ns for the same-table folding reference, with zero versus nine
allocations (0 versus 144 bytes). This isolates name handling, not the complete
LDAP request.

Two regressions were identified during development and addressed before the
final comparison:

- Rebuilding all known-name tables per query increased preparation from about
  82 us to 191 us. Cache hits now prepare the same assertion in about 0.58 us
  and 400 bytes instead of 3,008 bytes. First misses still build the larger
  table; these warm-cache figures do not describe a cold first query.
- An unbounded ASCII precheck made a 1,281-byte value with trailing whitespace
  slower: about 1.60 us became 2.64 us in the case-exact component test. The
  128-byte bound removes that extra large-value scan. The final measured
  fallback was 1.61 us versus 1.65 us for the reference, with identical
  allocations. Small timing differences are not a stable speedup claim.

The unbounded precheck and uncached-table implementation are not shipped.
The retained benchmarks cover short/long values, early/late fallback, Unicode,
invalid UTF-8, control bytes, nil/empty slices and assertion ownership.

Evidence: [name lookup](evidence/performance-20260923-round2/names-bench.txt),
[baseline preparation](evidence/performance-20260923-round2/prepare-before.txt),
[uncached experiment](evidence/performance-20260923-round2/prepare-current.txt),
[cached preparation](evidence/performance-20260923-round2/prepare-cached.txt),
[bounded ASCII comparison](evidence/performance-20260923-round2/ascii-bounded-bench.txt).

## 100k SDK comparison

The same Go SDK, fixture, filters, selections and process order as the previous
round were used: three processes each for before/current/OpenLDAP, two warmup
operations per read/Bind/Compare stage, then three batches of 20 operations.
The table uses nine-batch medians. Batches within a process are not independent
process samples. No forced GC or OS-cache eviction was used.

| Stage, 20 operations | Before | Current | OpenLDAP | Time change | OpenLDAP / current |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 7.72 ms | 8.22 ms | 2.81 ms | +6.5% | 34.1% |
| Base search | 3.24 ms | 3.34 ms | 2.91 ms | +3.3% | 86.9% |
| Indexed equality | 3.29 ms | 3.38 ms | 2.70 ms | +2.8% | 79.7% |
| Compare true | 8.93 ms | 9.44 ms | 2.34 ms | +5.6% | 24.8% |
| Compare false | 9.05 ms | 9.35 ms | 2.21 ms | +3.3% | 23.7% |
| Substring prefix | 3,936.58 ms | 2,629.05 ms | 621.25 ms | -33.2% | 23.6% |
| Substring negative | 3,911.01 ms | 2,619.87 ms | 621.75 ms | -33.0% | 23.7% |

Time change is `(current / before - 1) * 100%`; negative is faster. The last
column is `OpenLDAP / current * 100%`, where larger is better. Substrings still
take about 4.2 times the reference time. No end-to-end write claim is added.

The increases on short operations were retained and rechecked separately with
1,000 operations per stage. That supplemental probe omitted substring stages;
both versions used the same probe binary, three fresh processes and three
batches per process, in current/before/before/current/current/before order.

| Stage, 1,000 operations | Before | Current | Time change |
| --- | ---: | ---: | ---: |
| Root Bind | 364.35 ms | 371.35 ms | +1.9% |
| Base search | 115.90 ms | 115.58 ms | -0.3% |
| Indexed equality | 113.70 ms | 112.66 ms | -0.9% |
| Compare true | 394.72 ms | 400.43 ms | +1.4% |
| Compare false | 432.52 ms | 441.16 ms | +2.0% |

The recheck reduced the differences but did not prove that every other operation
is faster or unchanged. Bind/Compare retained small positive differences, with
overlapping sample ranges on this shared host. No stable improvement or causal
regression is asserted for those stages; the raw results remain visible for
further profiling.

All nine primary runs and six rechecks passed SDK result validation and produced
the same whole-directory export: 100,002 ordinary-attribute entries, 42,712,438
canonical bytes, POSIX checksum `2143929969`, compared byte for byte.
[SDK timings](evidence/performance-20260923-round2/sdk-timings.json),
[export validation](evidence/performance-20260923-round2/sdk-validation.tsv),
[short-operation recheck](evidence/performance-20260923-round2/short-operations-recheck.json)
and [recheck exports](evidence/performance-20260923-round2/short-operations-validation.tsv)
are retained.

Executable SHA-256 values:

```text
before  e820c72e5f62a764f01162c52503ab2088e930127a3459d93bca99412bac0695
current 9d9cb2772395878b14074986797e571bded73f816de48955fb3816a043069bd0
```

## Remaining costs

The same diagnostic prefix workload now allocates about 505 MiB versus 832 MiB
previously, roughly 39% less. The harness forces GC at profile boundaries, so
this is allocation evidence, not RSS. Almost all remaining sampled allocation
is now in owned DN/identity strings in the read-only iterator. CPU time also
remains in DN validation, scope decoding and map lookup. These ownership and
validation contracts must be preserved in subsequent changes.
[CPU](evidence/performance-20260923-round2/substring-cpu.txt) and
[allocation](evidence/performance-20260923-round2/substring-alloc.txt) summaries
record the next profiling targets. Per-write naming-context scans and hierarchy
traversal remain unresolved architectural costs.

## Validation

Full package tests, vet and the 15-group native OpenLDAP differential suite
passed (194 including subtests, no skips or failures). Tests compare new name
lookup against the original folding rules, check schema invalidation and clone
isolation, exercise bounded-cache eviction and concurrent preparation, and
retain the existing substring reference/fuzz tests. A frontend nestgroup test
checks filtering and member projection with ordinary, paged and ManageDsaIT
requests. All accepted runs keep cgo disabled; no race-detector run is claimed.

The [SDK probe](../internal/cmd/ldapbench/README.md) and the previous round's
read-only replay workload are reused for the 100k comparison. Full local
artifacts are retained at `/var/tmp/ldap-go-perf-round6-20260923` on the
qualification host. This remains an optimization checkpoint, not a claim that
all LDAP workloads match OpenLDAP performance.
