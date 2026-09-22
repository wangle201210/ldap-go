# Query performance optimization, 2026-09-22

This change reduces repeated DN work, paging-state copies, cache lock duration,
and BER allocations without changing filters, result ordering, authorization,
storage formats, or protocol output. The baseline is `d681fe6`, which includes
the [September 20 audit](performance-audit-20260920.md).
The optimized production sources were subsequently committed as `b323d80`;
the timed executable was built from that working tree before the commit.

## Implementation

- A local schema-aware search candidate already has a validated DN identity.
  Build its existing deterministic order key from that identity instead of
  parsing and schema-normalizing the same DN again. Other reader types retain
  their existing order-key path.
- Paged continuations keep independent offsets while sharing immutable items.
  The first continuation still performs the original copy, retaining the same
  slice capacity and memory-budget admission boundary. Later continuations
  avoid repeated copies of the full snapshot. Cache publication/read copies,
  revision invalidation, per-context reservations, and release behavior remain.
- Canonical DN identity validation uses strict base64 decoding with explicit
  CR/LF rejection, removing the encode-back allocation. Differential tests
  compare acceptance with the previous decode/encode rule, including unused
  tail bits, padding, newlines, invalid bytes, and structural errors.
- Search result caches reject oversized results before cloning and move owned
  entry/slice copying outside mutexes. Cache eligibility, revision keys, and
  ownership isolation remain unchanged.
- Search entries with response controls use direct BER encoding instead of
  building an intermediate BER object tree. Byte-for-byte tests cover absent
  and empty values, binary data, length boundaries, opaque control contents,
  and negative message IDs, which retain their previous fallback.

An attempted storage value-descriptor arena was rejected: it reduced allocations
but regressed a 64-value fixture. Storage codec production code is unchanged;
additional compatibility tests and workload-shaped benchmarks remain to catch
such tradeoffs in future work. Eager index candidate materialization also remains:
changing it to streaming would require preserving errors from late corrupt
candidates even when a callback stops early.

## 100k online comparison

Apple M1 Pro, 8 CPUs, 16 GiB RAM, Darwin 24.6.0 arm64, Go 1.26.4. Both ldap-go
binaries used `CGO_ENABLED=0`. The OpenLDAP reference was 2.6.13 at
`d172686d3d270bc961b78f3ff00d7019c8dfb094`; all clients were native OpenLDAP
clients on loopback TCP. Both sides had `uid` and `objectClass` equality indexes.
Other applications were running; measured host load was about 13 during this
session. Tests and builds did not overlap the timed online comparisons.

The same retained 100k database snapshots and workload from the September 20
audit were copied into disposable directories. Order was:

```text
before-1 current-1 openldap-1
current-2 openldap-2 before-2
openldap-3 before-3 current-3
```

Each process ran one first indexed/negative/paged batch, then three repeated
indexed/negative/paged/concurrent batches. Work per repeated batch:

- 10,000 indexed queries, requesting `uid`;
- ten negative description queries, eligible for the same-revision cache;
- two complete `(objectClass=inetOrgPerson)` traversals, page size 10,000;
- eight concurrent connections with 1,000 indexed queries each.

All clients wrote LDIF to files. Both revisions used the same scaled search
budgets: 100,100 entries/candidates, 819,200,000 candidate bytes per request,
and 1,638,400,000 retained Search bytes across the process. No TLS, additional
ACLs, overlays, forced GC, or OS-cache eviction were used in this online test.
"First" denotes a new server process, not a cold filesystem cache. RSS was
sampled after the complete mixed workload, before final full-data validation;
it is neither peak RSS nor an idle/retained-heap measurement.

The table gives medians of three first-batch samples, nine repeated samples,
and three RSS samples. Repeated samples within a process are correlated.
Latency/resource change is `(current / before - 1) * 100%`: negative is better.
Relative performance is `OpenLDAP / current * 100%`: above 100% favors ldap-go.

| Metric | Before | Optimized | Change | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| First indexed batch | 1,235 ms | 1,279 ms | +3.6% | 641 ms | 50% |
| Repeated indexed batch | 804 ms | 797 ms | -0.9% | 617 ms | 77% |
| First negative batch | 343 ms | 319 ms | -7.0% | 346 ms | 108% |
| Repeated negative batch | 30 ms | 32 ms | +6.7% | 338 ms | 1,056% |
| First full objectClass traversal | 2,874 ms | 1,819 ms | **-36.7%** | 530 ms | 29% |
| Two repeated objectClass traversals | 1,061 ms | 965 ms | **-9.0%** | 1,060 ms | 110% |
| Concurrent indexed, 8 x 1,000 | 248 ms | 242 ms | -2.4% | 204 ms | 84% |
| Post-workload RSS | 650.1 MiB | 634.1 MiB | -2.5% | 144.4 MiB | 23% |

First paging improved in all three process samples: baseline 2,874/2,911/2,635
ms, optimized 2,169/1,819/1,811 ms. Other small timing
differences, especially a two-millisecond repeated-negative change, should not
be treated as established improvements or regressions on this shared host.
RSS remains high; reducing cumulative allocations is not equivalent to reducing
resident memory by the same percentage.

All nine processes returned 100,000 unique people and the same 100,002-entry
ordinary-attribute subtree, checked byte for byte: 42,712,504 bytes, POSIX
checksum `648440320`. Indexed, negative, paged, and concurrent result counts
were validated as well. Operational timestamps/UUIDs are excluded by `*`.

This is an online snapshot workload, not a fresh-import 100k run. It does not
replace the historical [complete 100k table](openldap-100k-evidence.md), whose
paging filter and output handling differ.

## Fresh 10k databases

Four full fresh-data runs used the unchanged comparison script in order
`before-1 current-1 current-2 before-2`. Each generated 10,000 users, imported
and explicitly indexed both databases, then measured 10,000 indexed queries,
20 negative queries, five complete paged traversals (page size 1,000), eight
connections with 1,000 queries each, and 1,000 modifications. Paging here uses
the script's `(uid=scale-*)` filter, unlike the 100k snapshot profile above.

Each repeated-query report averages its two oppositely ordered batches. Values
below are midpoints of the two reports for each revision, not 100k results:

| Metric | Before | Optimized | Change |
| --- | ---: | ---: | ---: |
| Import plus index | 2,325 ms | 2,306.5 ms | -0.8% |
| Startup ready | 136.5 ms | 131 ms | -4.0% |
| Repeated indexed batch | 777.5 ms | 789 ms | +1.5% |
| First indexed batch | 1,102.5 ms | 1,086 ms | -1.5% |
| Repeated negative batch | 33 ms | 33 ms | 0.0% |
| First negative batch | 65.5 ms | 62.5 ms | -4.6% |
| Five repeated traversals | 413.5 ms | 404.5 ms | -2.2% |
| First traversal | 89.5 ms | 84 ms | -6.1% |
| Concurrent indexed, 8 x 1,000 | 233 ms | 233.5 ms | +0.2% |
| 1,000 Modify operations | 620 ms | 618.5 ms | -0.2% |
| Post-workload RSS | 53,501,952 B | 52,707,328 B | -1.5% |
| RSS after ten seconds idle | 51,380,224 B | 52,707,328 B | +2.6% |
| Database file size | 14,843,904 B | 14,843,904 B | 0.0% |

All four runs passed all 15 canonical-data/result-code checks, returned 10,000
unique people, exposed all 1,000 modifications, and ended with matching
10,002-entry canonical subtrees. Small changes in this table are consistent
with the measured workstation variation; they are not promises of a speedup.

## Focused encoding and cache benchmarks

The Search-entry encoding benchmark uses the same fixture and test code for
both revisions, with three 200 ms samples and `-cpu=1`. Median times below
measure encoding alone, not end-to-end replication or query throughput.

| Entry encoding | Before | Optimized | Allocations before / after | Bytes before / after |
| --- | ---: | ---: | ---: | ---: |
| Without controls | 290.8 ns | 288.8 ns | 1 / 1 | 1,280 / 1,280 |
| With sync control | 9,661 ns | 310.5 ns | 293 / 1 | 30,080 / 1,408 |
| With two controls | 11,639 ns | 361.5 ns | 334 / 1 | 33,664 / 1,792 |

Separate three-sample cache/DN microbenchmarks used `-cpu=4`. Typical identity
scope lookup dropped from four allocations (320 B) to two (160 B). Oversized
cache rejection dropped from four allocations (65,688 B) to zero. Cache-hit
and base-cache insertion critical sections improved in the focused parallel
benchmark, but ordinary 10k/100k indexed timings above remain the relevant
end-to-end evidence. Raw microbenchmarks retain all samples, including noisy
or slightly slower accepted-cache insertion measurements.

## Validation

- `CGO_ENABLED=0 go test -p=1 ./... -count=1 -timeout=10m`: all 21 packages passed.
- `CGO_ENABLED=0 go vet ./...`: passed.
- `CGO_ENABLED=0 go build ./...`: passed for linux/amd64, linux/arm64,
  darwin/amd64, darwin/arm64, windows/amd64, and freebsd/amd64 using the existing
  build cache. These are compilation checks, not runtime tests on those systems.
- Native OpenLDAP differentials: eight top-level tests, 58 passes including
  subtests, zero failures/skips. These cover the shared-SDK state machine,
  paging limits, domain scope, Search parameter errors, sync/sort/VLV
  combinations, native syncrepl consuming the Go provider, and value sorting.
- Added regressions cover independent cached-paging cursors, cancellation,
  capacity/memory accounting across multiple continuations, schema-aware DN
  ordering, cache ownership/concurrency/budgets, exact BER output, and exact
  canonical identity acceptance/errors. Existing paging mutation and memory
  lease lifecycle tests also passed.

This verifies the affected workloads and regression suite, not universal
identity with every OpenLDAP feature or timing guarantee. Race detection was
not run because the required build mode here is `CGO_ENABLED=0`.

## Evidence

Raw results are retained under
`/var/tmp/ldap-go-perf-opt-20260922` on the qualification host. The snapshot
driver uses the same commands as the previous audit. Fresh-data comparisons
use the repository's `scripts/qualification/compare-openldap.sh`; see
[production qualification](production-qualification.md#openldap-performance-comparison)
for its parameters.

Compact raw results are committed in
[`evidence/performance-20260922`](evidence/performance-20260922/). The source
100k snapshot files retain the same hashes recorded in the September 20 audit.
The tested binary SHA-256 values are:

```text
before  c49f89ee963222e1422d7e48ccf8b6c921b47572dbef0ad49c4ec25c1f8720bf
current f06cb9e830d4295d18fccf6e69a8617822823e9f6dfa03b2dc2e67293a98da65
```

The first broad objectClass traversal is still slower than OpenLDAP, and
post-workload RSS is still substantially larger. Indexed lookup and concurrent
query throughput remain further optimization targets. These measurements do
not establish uniform gains for every backend, overlay, authentication scheme,
or production deployment.
