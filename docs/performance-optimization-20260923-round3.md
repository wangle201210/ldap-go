# DN scope decoding and lazy string ownership

Baseline: `a279a00`. This round targets the DN validation/scope work and string
allocations identified by the [previous profile](performance-optimization-20260923-round2.md).
All Go builds and checks use `CGO_ENABLED=0`. No unsafe string conversion or
stored-format change is introduced.

## Implementation

`ValidateDNIdentityInScope` shares one v2 identity decode between DN validation
and scope evaluation. It returns validation and scope errors separately:
validation failures still stop before a candidate callback; scope failures stay
deferred so the server retains its deadline/error order. Legacy keys and
cardinality exceptions retain the original parser. CR/LF rejection remains in
place, using direct byte searches.

The bytes variant avoids string copies for simple ASCII DNs and identity keys
that fit the existing 1KiB scratch buffer. It still checks canonical Base64,
RDN/AVA structure and cardinalities. Complex DNs, large keys, and unsuccessful
fast-path checks use the original string path, including its error details.
Inputs are neither modified nor retained.

A new callback-scoped `EntryMetadataView` retains borrowed DN/key bytes alongside
read-only attributes. `ReadOnlyEntry` explicitly copies its DN and identity
strings while keeping attributes borrowed during the callback. `Materialize`
additionally deep-copies attributes and values. Existing iterators retain their
owned-string contract. Codec fallback is per row and preserves the authoritative
decoder's errors; it does not restart a partially visited scan.

Eligible root substring searches can check metadata without materializing
ordinary nonmatching rows. Every validated row still reaches the callback,
including out-of-scope rows, and deadline checks remain in place. Alias,
referral and subentry records use the original visitor, including references
whose entry does not match the filter. Ordinary matches also use that visitor's
selection, limits and output path, reusing the already evaluated class/filter
result and single deadline check. No extra full-attribute copy is required for
these rows, which keeps the high-hit case comparable to the previous path.

## Component evidence

The same-binary 100k physical-scan benchmark compares the scoped read-only
iterator with metadata scanning. Both use the combined DN validation/scope
implementation; these values isolate lazy string ownership. Medians of three
300ms samples:

| Hits | Read-only entries | Metadata view | Allocated bytes, entries / metadata |
| --- | ---: | ---: | ---: |
| None | 56.46 ms | 51.40 ms | 16,009,392 / 9,336 |
| 1,000 | 57.26 ms | 52.05 ms | 16,307,277 / 467,256 |
| 100,000 | 101.63 ms | 102.31 ms | about 45.61 MB / 45.61 MB |

The high-hit difference is small and overlapping, not an improvement claim.
The metadata path does not remove the required copy of selected output.
These component times do not include the complete LDAP visitor or transport.
The [raw component log](evidence/performance-20260923-round3/metadata-bench.txt)
retains all samples.

## 100k SDK results

The table shows nine-batch medians from three processes per implementation,
using the same 100k fixture, Go SDK and warmup as the preceding round. Each SDK
stage has 20 operations. Process order was before/current/OpenLDAP,
current/OpenLDAP/before, then OpenLDAP/before/current. No forced GC or OS-cache
eviction was used. Repetitions inside one process are not independent process
samples.

| Stage, 20 operations | Before | Current | OpenLDAP | Time change | OpenLDAP / current |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 8.73 ms | 8.31 ms | 2.49 ms | -4.8% | 29.9% |
| Base search | 3.27 ms | 3.52 ms | 2.82 ms | +7.9% | 80.0% |
| Indexed equality | 3.35 ms | 3.19 ms | 3.00 ms | -5.0% | 94.2% |
| Compare true | 9.40 ms | 9.78 ms | 2.21 ms | +4.0% | 22.6% |
| Compare false | 8.80 ms | 9.13 ms | 2.38 ms | +3.7% | 26.0% |
| Substring prefix | 2,624.46 ms | 1,505.48 ms | 625.89 ms | -42.6% | 41.6% |
| Substring negative | 2,614.63 ms | 1,503.00 ms | 622.05 ms | -42.5% | 41.4% |

Time change is `(current / before - 1) * 100%`; negative is faster. The last
column is `OpenLDAP / current * 100%`, where larger is better. The shared host
had visible timing outliers, including a 13.34 ms indexed batch and a 20.28 ms
Compare-false batch on current. Small changes in unrelated operation medians
are retained, without claiming stable gains or regressions from these samples.

For the added high-hit workload, one unpaged `(uid=scale-*)` traversal returned
all 100,000 users. Each process ran three traversals, writing LDIF to files.
Nine-sample medians were **637 ms before, 599 ms current, and 535 ms OpenLDAP**
(-6.0% time, 89.3% relative performance). One current traversal took 861 ms;
the raw result is retained. No regression-free guarantee across all high-hit
queries is inferred from this one workload.

All nine runs returned 100,000 unique people in that traversal and produced the
same 100,002-entry ordinary-attribute export: 42,712,438 canonical bytes, POSIX
checksum `2143929969`, compared byte for byte.

Evidence: [SDK timings](evidence/performance-20260923-round3/sdk-timings.json),
[full-prefix traversals](evidence/performance-20260923-round3/full-prefix-timings.tsv),
[whole-data validation](evidence/performance-20260923-round3/sdk-validation.tsv).

Executable SHA-256 values:

```text
before  41edc34067d8a7b940f48abbb766880f89bdc4ff96362f10baf309510c042dbe
current 5cf89565e32c9d27757a4704999ed6d3e2c8c14dac4b067da848a1b9f58e4dc7
```

The repeated-prefix diagnostic profile no longer records the prior roughly
505 MiB of DN/key allocation. Its approximately 4.1 MiB sampled allocation is
dominated by profile setup and compression. This is not zero application
allocation or a process RSS measurement; the selected rows still own output,
and heap-profile sampling does not account precisely for every small allocation.
The harness forces GC at profile boundaries. Remaining sampled CPU work is in
DN/codec validation, decoding and map lookup.
[CPU](evidence/performance-20260923-round3/substring-cpu.txt) and
[allocation](evidence/performance-20260923-round3/substring-alloc.txt) summaries
are retained for the next optimization step.

## Validation

Directory tests compare the combined string/bytes operations against both the
two-call sequence and frozen parser/scope references. Coverage includes unknown
scopes, legacy bases, malformed keys, CR/LF, unused Base64 bits, RDN/AVA counts,
oversized buffers, escaped/non-ASCII DNs, input lifetime and error ownership.

Storage tests check V1/V2/V3/JSON/mixed rows, dense-row fallback, exact callback
order, deferred scope errors, out-of-scope corruption, cancellation checkpoints,
callback stops, writable/unsupported readers, and output after Bolt unmap.
Materialized entries, cloned/selected attributes and directly retained owned
DN/key strings are tested independently.

Server differential tests compare optimized leaf filters with equivalent
general AND filters across scopes, limits, types-only, wildcard/default
selection, root/non-root clients, alias dereferencing, referrals, and subentry
controls. The full Go suite, vet and the native OpenLDAP differential suite
passed (15 native groups, 194 including subtests, no skips/failures).
One earlier whole-suite run hit the existing one-nanosecond Web Admin
bulk-deadline test; its code was untouched, ten focused reruns and the final
whole-suite run passed. That earlier failure is not treated as a successful run.
[Full tests](evidence/performance-20260923-round3/go-test.txt) and
[native tests](evidence/performance-20260923-round3/openldap-differential.txt)
record the accepted runs.

The 100k replay uses three fresh processes per implementation and three SDK
batches of 20 operations per stage after warmup. It also measures three unpaged
`(uid=scale-*)` traversals per process, each returning all 100k people, to check
high-hit behavior. Workload, data checks and reference tools otherwise match the
previous replay. Complete local artifacts are under
`/var/tmp/ldap-go-perf-round7-20260923` on the qualification host.

Optimization remains ongoing. This work does not eliminate naming-context or
hierarchy scans on writes and does not claim all LDAP operations match OpenLDAP.
