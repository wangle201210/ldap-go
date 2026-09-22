# Common-operation and scan overhead

Baseline: `929683d`. All Go builds, tests and benchmarks use `CGO_ENABLED=0`.
This round examines Bind, Compare, indexed and concurrent queries, pagination,
full exports and scan queries. Write-path investigation is reported separately
from the measured read binary.

## Changes

- Common short-form Simple Bind and Compare requests without controls are
  decoded directly after validating the complete bounded BER shape. Other
  encodings, controls, SASL and malformed shapes use the original decoder.
  Packet/depth limits, dynamic provider calls, consumed bytes, error behavior,
  and independent ownership of strings and bytes are retained. Authentication,
  password work factors and authorization are unchanged.
- Checking whether the schema contains collective attributes iterates its
  existing map under the same read lock. It no longer constructs, deduplicates
  and sorts a copy of every attribute type for an existence check. Registration,
  replacement and cloning continue to be observed without an extra cache.
- Eligible substring scans classify object classes and collect matching
  attribute positions in one descriptor pass. Special-entry and visibility
  decisions still precede substring-value evaluation. More than 64 attributes,
  different registries or different schema generations use the separate paths.
  Prepared plans retain no entries and share the existing bounded name cache.

An isolated 20,000-operation Compare profile identified the collective schema
inspection as roughly 7.7% of sampled CPU before that change. It also found
repeated DN normalization and substantial socket/scheduler costs. These are
diagnostic observations, not projected end-to-end speedups. DN/ACL/referral
normalization is not skipped by this patch.

## Component Measurements

Three 300ms samples in the same binary against the previous implementation;
medians below cover components, not whole LDAP operations.

| Component | Reference | Current | Allocations, reference / current |
| --- | ---: | ---: | ---: |
| Simple Bind decode | 1,887 ns | 132 ns | 69 / 5 |
| Compare decode | 2,071 ns | 154 ns | 82 / 6 |
| Collective presence, builtin schema | 190,548 ns | 304 ns | 28 / 0 |
| Classify + substring, 11 attributes, hit | 219.5 ns | 196.1 ns | 0 / 0 |

Collective presence also decreases allocated memory from approximately 250,835
bytes per check to zero. Controlled Bind remains on the packet path, with
medians of 3,450 versus 3,543 ns (+2.7%) and unchanged 129 allocations. This
small fallback-path timing difference is retained rather than represented as
an improvement. The 65-attribute query-plan fallback retains zero allocations.

Raw [schema](evidence/performance-20260923-round5/schema-bench.txt) and
[wire](evidence/performance-20260923-round5/wire-bench.txt) samples include all
measured cases and outliers.

## Method

The disposable 100k fixture and native OpenLDAP 2.6.13 configuration match the
[preceding round](performance-optimization-20260923-round4.md). Three fresh
processes per implementation run in rotating before/current/OpenLDAP order.
Each process performs three SDK batches of 20 operations after a two-operation
warmup, and three unpaged traversals returning all 100k people.

The expanded replay also measures 10,000 indexed searches, eight connections
with 1,000 indexed searches each, two full paged traversals, and ten absent
unindexed equality queries per process. Each workload checks result counts;
pagination also checks uniqueness. Complete canonical ordinary-attribute
exports are compared byte for byte across all nine processes. No forced GC or
OS-cache eviction is used in the replay. Batches within one process are not
independent samples, and small differences on this shared host are noisy.

## 100k Results

SDK medians over nine batches. Time change is `(current / before - 1) * 100%`;
negative is faster. Relative performance is `OpenLDAP / current * 100%`, where
larger is better. These results do not establish performance parity.

| Stage, 20 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 7.77 ms | 7.93 ms | 2.30 ms | +2.0% | 29.1% |
| Base search | 3.58 ms | 3.39 ms | 2.62 ms | -5.5% | 77.3% |
| Indexed equality | 3.41 ms | 3.35 ms | 2.83 ms | -1.6% | 84.4% |
| Compare true | 9.96 ms | 4.27 ms | 2.34 ms | -57.1% | 54.7% |
| Compare false | 9.13 ms | 3.97 ms | 2.22 ms | -56.5% | 56.0% |
| Substring prefix | 1,356.79 ms | 1,169.53 ms | 632.69 ms | -13.8% | 54.1% |
| Substring negative | 1,350.86 ms | 1,167.38 ms | 640.53 ms | -13.6% | 54.9% |

The additional command-line workloads have one batch per process (three
samples), except full prefix, which has three per process (nine samples).
These timings include client execution and output to a file.

| Workload | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full prefix, 100k returned | 733 ms | 737 ms | 649 ms | +0.5% | 88.1% |
| Indexed equality, 10,000 | 764 ms | 785 ms | 665 ms | +2.7% | 84.7% |
| Concurrent indexed, 8 x 1,000 | 215 ms | 212 ms | 241 ms | -1.4% | 113.7% |
| Paged traversal, 2 x 100k | 1,420 ms | 1,406 ms | 1,366 ms | -1.0% | 97.2% |
| Unindexed negative equality, 10 | 200 ms | 194 ms | 356 ms | -3.0% | 183.5% |

Small timing changes in these workloads are not stable improvement/regression
claims. In particular, full-prefix traversal does not show the selective
substring improvement because returning and encoding 100k matches dominates.
The indexed workload includes a 998 ms current sample; no outlier was removed.

Post-workload RSS medians were **332.5 MiB before, 369.8 MiB current and
94.1 MiB OpenLDAP**, an observed **11.2% increase** over baseline. Before/current
ranges overlap (323.2-394.9 versus 357.7-416.6 MiB). RSS is sampled without
forced GC and is not retained-heap size; this run does not demonstrate a memory
improvement or prove the increase is harmless. The expanded workload also
differs from the preceding report's RSS sampling point.

All nine runs returned 100,000 unique people in full-prefix and paged output,
and produced identical ordinary-attribute exports: 100,002 entries, 42,712,438
canonical bytes and POSIX checksum `2143929969`.
[SDK samples](evidence/performance-20260923-round5/sdk-timings.json),
[expanded workload samples](evidence/performance-20260923-round5/online-timings.tsv),
and [exports/RSS](evidence/performance-20260923-round5/sdk-validation.tsv)
retain the complete measurements.

Executable SHA-256 values for this read replay:

```text
before  8599e2070fc37c0f6fa2f579f122b7b36033df57b6a92d5fbfcfdc18cb2d7cd4
current 86fe571735f7b927ec4cb6591753ef6299e6014058b493aa8b34e4f6af62cfcc
```

Local disposable artifacts and the replay script are under
`/var/tmp/ldap-go-perf-round9-20260923`. Naming-context and hierarchy scans on
writes remain a separate bottleneck; these read results make no write-speed
claim.

## Validation

The full Go test suite, vet and native OpenLDAP differential tests passed for
the measured read changes. The direct decoder differential fuzz test passed
357,910 executions in 15 seconds. Tests also exercise schema mutation, clone
isolation, cache eviction, concurrent immutable plans, attribute aliases and
subtypes, bitmap boundaries, special-entry ordering and borrowed-value
ownership. No race-detector result is claimed with cgo disabled.

[Full suite](evidence/performance-20260923-round5/go-test.txt),
[vet](evidence/performance-20260923-round5/go-vet.txt),
[native differential checks](evidence/performance-20260923-round5/openldap-differential.txt)
(194 including subtests, no skips), and
[decoder fuzz](evidence/performance-20260923-round5/decode-fuzz.txt) are retained.
