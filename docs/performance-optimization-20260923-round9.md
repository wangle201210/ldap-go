# Common authentication and read operations

Baseline: `42bb528`. This round follows the
[write-path optimization](performance-optimization-20260923-round8.md) and
targets ordinary user authentication, repeated DN normalization and substring
scan overhead. Accepted builds and validation use `CGO_ENABLED=0`.

## Changes

Ordinary local Simple Bind now uses a read transaction when the retained
configuration has no password-policy overlay, password last-success tracking,
lastbind overlay, OTP/TOTP, rewrite, remote-auth, proxy-bind or translucent
handling. The external-password preverification phase remains in its original
position. Final entry lookup, anonymous ACL authorization per password value,
and full verification of every allowed password value use the final snapshot.
The operation checks cancellation after the read completes. Stateful cases
retain their existing write transaction, timestamp/counter updates and policy
controls. No passwords or authentication results are cached, and hash work
factors are unchanged. This removes an empty commit, its revision increment and
commit-only failures for eligible authentication; configured audit/response
effects remain outside this optimization.

Runtime DN normalization opts into a bounded schema cache: at most 128 exact
input keys, input length at most 1,024 bytes, depth at most 32 and an estimated
1 MiB retained-data budget. Only successful results are retained. Attribute
registration/replacement invalidates results through the registry generation;
clones start empty. The existing `NormalizeDN` API remains uncached so callers
that directly mutate externally shared schema-definition slices retain its
behavior. The new opt-in API requires definitions to change through registry
mutation methods. Server runtime schemas meet this condition. Custom normalizer
callbacks retain their original path, calls and errors. Returned DNs remain
immutable through their public API and valid after eviction.

Compare avoids allocating a dynamic-list projection cache when neither dynlist
nor dyngroup is configured. Its controls, ACL collision protection, schema
matching and response codes remain unchanged.

The byte-based substring scan validates outer RDN framing and compares scope
in one traversal instead of rereading the lengths. Scope rejection does not
skip validation of later RDNs. Unsupported forms and malformed data use the
original decoder so detailed errors and their precedence are retained. The
ASCII gate, bounded stack buffer, strict Base64 handling and input ownership
are unchanged. No new query index is enabled for these measurements.

## Validation

Tests cover successful/failed authentication without writes on memory and Bolt,
SSHA/SM3/PBKDF2-SM3, per-value ACL checks, verification after a prior match,
errors before/after read callbacks, cancellation, final-snapshot password
changes and stateful fallbacks. DN tests exercise aliases/OIDs, case-exact and
multi-AVA names, schema replacement, uncached external-slice mutation behavior,
recursive DN matching, owned results, clone isolation, capacity limits and
concurrent access. Scope tests compare all supported relationships and malformed
framing against the original implementation, including corruption after an
out-of-scope result.

An initial test run overlapped unfinished test-file edits and failed compilation;
it is not an accepted run. A delegated task also mistakenly ran a race check;
that result is excluded because the project requires cgo-disabled validation.
Final acceptance uses explicit `CGO_ENABLED=0`, with no race result claimed.

The [full Go suite](evidence/performance-20260923-round9/go-test.txt),
[vet](evidence/performance-20260923-round9/go-vet.txt), and
[focused regressions](evidence/performance-20260923-round9/focused-final.txt)
passed. [Native OpenLDAP checks](evidence/performance-20260923-round9/openldap-differential.txt)
passed 200 checks including subtests, with no skips. These include password
policy, controls, DN/ACL, transaction-Bind and SASL credential regressions.
The [scope differential fuzz run](evidence/performance-20260923-round9/scope-fuzz.txt)
passed 11,011 executions in a 20-second invocation.

## Component Measurement

Three 300ms samples comparing the original byte-scope implementation through
a Go overlay with the new implementation, using unchanged benchmark fixtures:

| Scope validation | Before | Current | Allocations before / current |
| --- | ---: | ---: | ---: |
| Typical four-RDN DN | 211.4 ns | 182.7 ns | 0 / 0 |
| Outside scope | 146.6 ns | 140.4 ns | 0 / 0 |
| Multi-AVA fallback | 1,135 ns | 1,144 ns | 27 / 27 |
| Escaped fallback | 1,024 ns | 1,027 ns | 24 / 24 |

These are component medians, not complete searches. Small fallback differences
are retained and not presented as speedups. Raw
[baseline](evidence/performance-20260923-round9/scope-before.txt) and
[current](evidence/performance-20260923-round9/scope-current.txt) samples include
all results.

## Replay Method

The 100k fixture, indexes, server limits and native OpenLDAP 2.6.13 build match
the preceding reports. Three fresh processes per implementation run in rotating
before/current/OpenLDAP order. Each executes the existing three read batches
of 20 operations, full-prefix/paged traversals, 10,000 indexed queries and eight
concurrent clients with 1,000 indexed queries each.

This round adds three 1,000-operation batches for each short SDK operation and
for successful/failed ordinary-user Bind. The authentication probe creates one
temporary SSHA user with a random salt under the people OU, warms up with 20
successful Binds, checks every Bind result and WhoAmI identity after each batch,
and removes the user afterward. No ppolicy/lastbind/OTP overlay is enabled in
that fixture. Hash work factors, per-value ACL behavior and stateful fallbacks
are validated separately; these timings do not represent expensive KDFs or
stateful authentication configurations.

Every stage validates results. At the end of each process, a complete canonical
ordinary-attribute export is compared with the baseline. Batches in one process
are not independent process samples. Timings are measured without concurrent
builds/tests or forced GC. The final RSS sampling point includes the temporary
user's Add/Delete and therefore is not comparable to earlier read-only RSS
samples without considering that workload change.

## 100k Results

Nine-batch medians from three fresh processes per implementation, three batches
per process. Time change is `(current / before - 1) * 100%`; negative is faster.
Relative performance is `OpenLDAP / current * 100%`, where larger is better.

| Stage, 1,000 operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 375.72 ms | 177.45 ms | 87.51 ms | -52.8% | 49.3% |
| User Bind, wrong password | 370.13 ms | 176.85 ms | 79.18 ms | -52.2% | 44.8% |
| Root Bind | 160.51 ms | 108.26 ms | 73.57 ms | -32.6% | 68.0% |
| Base search | 106.39 ms | 107.17 ms | 90.39 ms | +0.7% | 84.3% |
| Indexed equality | 114.32 ms | 121.64 ms | 102.25 ms | +6.4% | 84.1% |
| Compare true | 145.30 ms | 117.46 ms | 72.93 ms | -19.2% | 62.1% |
| Compare false | 150.88 ms | 115.83 ms | 74.12 ms | -23.2% | 64.0% |

The original 20-operation SDK stages are retained separately. Their prefix
substring medians were 1,193.03 / 1,157.95 / 625.05 ms before/current/native
(-2.9% current/before), and negative-substring medians were
1,211.18 / 1,155.00 / 627.59 ms (-4.6%). These scans remain about 1.8 times
native latency; the new traversal does not replace a substring index.

| Additional workload | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| Full-prefix traversal, 100k returned | 805 ms | 780 ms | 704 ms | -3.1% |
| Command-line indexed searches, 10,000 | 932 ms | 835 ms | 738 ms | -10.4% |
| Concurrent indexed, 8 x 1,000 | 211 ms | 211 ms | 302 ms | 0.0% |
| Paged traversal, 2 x 100k | 1,644 ms | 1,602 ms | 1,564 ms | -2.6% |
| Unindexed negative equality, 10 | 219 ms | 214 ms | 374 ms | -2.3% |

The additional workloads have one batch per process, except full-prefix
traversal, which has three. They include native client execution and writing
output to a file. Small differences and cross-workload ratios on this shared
host are not reliable universal improvement claims.

Because the short-query results were mixed, an isolated recheck used three
fresh processes per version in current/before, before/current, current/before
order, with three batches of 10,000 Base and equality searches per process.
No native implementation was measured in this recheck:

| Isolated SDK search, 10,000 operations | Before | Current | Time change |
| --- | ---: | ---: | ---: |
| Base search | 1,208.72 ms | 1,269.79 ms | +5.1% |
| Indexed equality | 1,285.37 ms | 1,340.42 ms | +4.3% |

These increases are not omitted. Both versions had large overlapping ranges,
including 3,633/3,119 ms Base batches and 3,888/3,110 ms equality batches. A
separate benchmark isolates the actual indexed search handler without sockets,
using an overlay that restores the old parser routing while keeping the fixture
and other code unchanged. Three 500ms samples gave 15.98 us before and 15.70 us
current, with unchanged 10,920 bytes and 266 allocations. This does not prove
the endpoint regressions are harmless, but it did not identify increased
handler work from the parser integration. **No consistent Base/equality
endpoint speedup is claimed in this round.**

Post-workload RSS medians were **481.0 / 473.4 / 95.2 MiB** before/current/native
(-1.6% current/before). All nine primary runs produced identical ordinary
attribute exports after removing the temporary user: 100,002 entries,
42,712,438 canonical bytes and POSIX checksum `2143929969`. Full-prefix and
paged output contained 100,000 unique people. The separate long search recheck
passed its per-request SDK assertions.

Evidence: [1,000-operation samples](evidence/performance-20260923-round9/long-timings.json),
[per-process authentication reports](evidence/performance-20260923-round9/),
[20-operation samples](evidence/performance-20260923-round9/sdk-timings.json),
[additional workloads](evidence/performance-20260923-round9/online-timings.tsv),
[isolated recheck](evidence/performance-20260923-round9/search-recheck.json),
[handler baseline](evidence/performance-20260923-round9/search-component-before.txt),
[handler current](evidence/performance-20260923-round9/search-component-current.txt),
and [export/RSS checks](evidence/performance-20260923-round9/sdk-validation.tsv).

An isolated 20,000-operation Compare diagnostic, subtracting each warm heap
profile from its post-query allocation profile, sampled 653.38 MiB before and
356.83 MiB current. This is cumulative allocation, not RSS or retained heap.
The profiler forces GC at boundaries, so its timings are not used in the replay
tables. [Before](evidence/performance-20260923-round9/compare-alloc-before.txt)
and [current](evidence/performance-20260923-round9/compare-alloc-current.txt)
summaries retain the diagnostic evidence.

## Write Regression

Parser integration also touches writes, so the same 100k fixture was replayed
with 20 operations per write stage, three fresh processes per implementation,
rotating order and separate postcondition verification. The warm leaf-write
results do not replace the cold initialization costs documented in round 8.

| Twenty operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 19.43 ms | 19.29 ms | 115.50 ms | -0.7% | 598.8% |
| Modify, unindexed description | 12.20 ms | 10.26 ms | 116.25 ms | -15.9% | 1,133.2% |
| ModifyDN | 34.02 ms | 28.85 ms | 129.76 ms | -15.2% | 449.8% |
| Delete | 23.37 ms | 20.85 ms | 133.65 ms | -10.8% | 640.9% |

All nine write runs passed SDK assertions and produced the same complete
canonical export as the read replay. Setup, cleanup, verification and every
sample are recorded in [write timings](evidence/performance-20260923-round9/write-timings.json)
and [export checks](evidence/performance-20260923-round9/write-validation.tsv).
These small, sequential operations use the existing backend durability settings;
they do not establish equivalent ratios for every overlay or concurrent workload.

The accepted binary hashes are:

```text
before  7ce8d959f8bfba138c25868c9d0444a957cd2f8a87fe9518daba5c1ff22faeba
current 994e2fd2daefa8c529d84a2bfe9d12bb3b4610ee008b360ca9f52e015b0095f2
```

Replay scripts, diagnostic profiles and raw per-process files remain under
`/var/tmp/ldap-go-perf-round12-20260923`. This checkpoint improves common
authentication and Compare but does not establish OpenLDAP-wide performance
parity. Stateful authentication, costly KDFs, cold DN cache churn and concurrent
mixed production workloads require their own qualification.
