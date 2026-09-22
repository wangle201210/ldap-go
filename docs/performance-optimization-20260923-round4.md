# Decoder slots, DN parts and Compare responses

Baseline: `f0e1243`. This round follows the
[metadata-view optimization](performance-optimization-20260923-round3.md).
All Go builds and accepted checks use `CGO_ENABLED=0`.

## Changes

- The bounded read-only decoder reuses the owned attribute-name string from the
  previous row's same slot when exact bytes match. An inexpensive first-byte
  rejection handles changing capitalization. Reordered, different, empty and
  otherwise unmatched descriptions retain the original interning path. No
  cache capacity, entry format, flags or output ownership rule is changed.
- Single-AVA identity validation reads each inner count/length once. It keeps
  the outer RDN validation, nonempty type requirement, exact value/tail lengths,
  overflow/truncation handling, accepted nonminimal varints, canonical Base64
  checks and the original fallback/error order. Complex DNs retain their path.
- Empty-field Compare true/false responses use the existing direct result
  encoding mechanism. The gate is restricted to CompareResponse and valid
  nonnegative 32-bit message IDs; matched DN, diagnostics, referrals or controls
  retain the packet encoder. Existing success responses retain their behavior.
  Full output bytes are compared against the previous BER packet construction.

## Component evidence

Identical decoder fixtures were compiled on the baseline and current source.
The final first-byte-gated recheck used five 500ms samples in current/before
order. Medians:

| Decoder layout | Before | Current | Allocations before / current |
| --- | ---: | ---: | ---: |
| Stable names/order | 161.8 ns | 118.0 ns | 0 / 0 |
| Alternating capitalization | 175.4 ns | 176.6 ns | 0 / 0 |
| Stable 1KiB description | 300.6 ns | 160.4 ns | 1 / 0 |

An initial implementation showed a larger capitalization-alternation penalty;
the first-byte rejection was added before the final recheck. The remaining
small timing difference is not a regression-free guarantee for arbitrary
layouts. Initial and recheck samples are retained.

Typical byte-based DN identity validation/scope evaluation decreased from
240.2 ns to 197.1 ns, with zero allocations in both versions (three 300ms
samples). Multi-AVA and escaped fallbacks retained their allocation counts and
roughly the same timings.

Compare result encoding, measured in the same binary against the old packet
encoder, decreased from approximately 0.91 us, 1,740 bytes and 41 allocations to
23 ns, 16 bytes and one allocation. This is response encoding only, not the
complete Compare request or its authorization/matching work.

Raw logs: [decoder baseline](evidence/performance-20260923-round4/decoder-before.txt),
[initial decoder change](evidence/performance-20260923-round4/decoder-current.txt),
[final recheck baseline](evidence/performance-20260923-round4/first-byte-before.txt),
[final recheck current](evidence/performance-20260923-round4/first-byte-current.txt),
[DN baseline](evidence/performance-20260923-round4/dn-before.txt),
[DN current](evidence/performance-20260923-round4/dn-current.txt),
[Compare encoding](evidence/performance-20260923-round4/compare-bench.txt).

## 100k SDK results

Nine-batch medians from three fresh processes per implementation, with two
warmup operations per read/Bind/Compare stage and three measured batches per
process. Each stage has 20 operations. Process order was before/current/OpenLDAP,
current/OpenLDAP/before, then OpenLDAP/before/current. Batches inside one process
are not independent process samples. No forced GC or OS-cache eviction was used.

| Stage, 20 operations | Before | Current | OpenLDAP | Time change | OpenLDAP / current |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 8.16 ms | 8.31 ms | 2.93 ms | +1.8% | 35.3% |
| Base search | 3.33 ms | 3.41 ms | 2.85 ms | +2.5% | 83.4% |
| Indexed equality | 3.51 ms | 3.66 ms | 2.82 ms | +4.1% | 77.0% |
| Compare true | 9.58 ms | 9.34 ms | 2.43 ms | -2.4% | 26.0% |
| Compare false | 9.34 ms | 8.90 ms | 2.11 ms | -4.7% | 23.7% |
| Substring prefix | 1,504.16 ms | 1,353.16 ms | 617.62 ms | -10.0% | 45.6% |
| Substring negative | 1,491.80 ms | 1,345.61 ms | 616.24 ms | -9.8% | 45.8% |

Time change is `(current / before - 1) * 100%`; negative is faster. The last
column is `OpenLDAP / current * 100%`, where larger is better. Small differences
in short-operation batches are not stable performance claims on this shared
host. The data includes outliers such as a 1,568 ms current prefix batch and a
1,663 ms baseline negative batch; no samples are removed.

An unpaged `(uid=scale-*)` traversal returned all 100k users. Three traversals per
process gave nine-sample medians of **740 ms before, 705 ms current, and 612 ms
OpenLDAP** (-4.7% time, 86.8% relative performance). These are same-run values;
do not substitute the preceding run's lower absolute times.

All nine runs passed per-request SDK validation, returned 100,000 unique people
in the full-prefix traversal, and produced byte-for-byte identical ordinary
attribute exports: 100,002 entries, 42,712,438 canonical bytes, POSIX checksum
`2143929969`.
[SDK samples](evidence/performance-20260923-round4/sdk-timings.json),
[full-prefix samples](evidence/performance-20260923-round4/full-prefix-timings.tsv),
and [export validation](evidence/performance-20260923-round4/sdk-validation.tsv)
are retained.

Executable SHA-256 values:

```text
before  4aee4eb132e400121b8174d524be8fb5e653b3ec52e59594930cd12d332c576d
current c20e199118c65a4bbb795f7f646cc975797f29ead16ac1223c1907e1a78f4b3b
```

The diagnostic profile continues to show remaining work in DN validation,
Base64 decoding, descriptor parsing and name-map lookup. Sampled allocation is
dominated by profiling setup/compression, not per-row temporary DN strings.
This profile forces GC at its boundaries and is not an RSS measurement.
[CPU](evidence/performance-20260923-round4/substring-cpu.txt) and
[allocation](evidence/performance-20260923-round4/substring-alloc.txt) summaries
record those limits. Substring scans still take about 2.2 times OpenLDAP's time.

## Validation

Tests cover changing order/count/case, repeated long names, V1/V2/V3/JSON rows,
partial failed decodes, flags and string ownership after source mutation. DN
tests compare the reduced inner validator against the frozen generic decoder,
including all combinations of short and ten-byte nonminimal varints,
truncations, overflowing/maximal lengths, empty types/values and extra tails.
Compare tests check complete BER byte equivalence over message-ID, tag,
result-code and length boundaries, all optional fields and independent outputs.

The full Go suite, vet and native OpenLDAP differential checks passed. An early
short fuzz invocation ended with an executor deadline error without a failing
input; it was not accepted as a pass. A separate 30-second, single-worker run
passed. No race-detector run is claimed because cgo remains disabled.
[Full tests](evidence/performance-20260923-round4/go-test.txt),
[native tests](evidence/performance-20260923-round4/openldap-differential.txt)
(15 groups, 194 including subtests, no skips/failures), and the
[isolated fuzz run](evidence/performance-20260923-round4/rdn-fuzz-isolated.txt)
are retained.

The 100k replay retains the previous workload: three processes per
implementation, two-operation warmup per read/Bind/Compare stage, three SDK
batches of 20 operations, and three full unpaged prefix traversals returning
100k users. Full local artifacts are under
`/var/tmp/ldap-go-perf-round8-20260923` on the qualification host.

This is a measured checkpoint in the continuing optimization work. It does not
eliminate naming-context or hierarchy scans on writes.
