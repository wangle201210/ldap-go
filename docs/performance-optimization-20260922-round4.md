# Broader LDAP operation optimization

This round starts at `995247e` and examines startup, authentication, base-object
searches, Compare, substring searches, Add, Modify, ModifyDN, Delete, and common
BER encoding. It is separate from the preceding cached-query/paging benchmark.
Every Go build, test, and benchmark uses `CGO_ENABLED=0`.

## Implementation

- Startup's scan for legacy unpartitioned entries seeks past complete
  NUL-delimited partition groups instead of stepping over every modern record.
  Single-record groups use the next cursor position without an extra seek.
  Legacy entries keep their order, decoding, callbacks, and cancellation/error
  checkpoints.
- Local-only password Bind skips the redundant local hash verification in the
  external-authentication preflight. Candidate reads, ACL checks, and errors are
  retained. The final password-policy transaction still performs full password
  verification. Mixed local/RADIUS ordering, lockout, TOTP, and audit processing
  remain on their existing paths; no credential cache or lower work factor is
  introduced.
- A local base-object `(objectClass=*)` search reads its one candidate directly,
  then runs the existing authorization, projection, filter, and limit handling.
  Paging, sort, sync, translucent and delegated-backend paths retain the general
  iterator. Candidate DN hints are reconstructed using the physical-identity
  parser, so a stale memory-store hint after ModifyDN cannot hide the entry.
- Ordinary Modify avoids a complete entry clone per individual modification.
  Configuration and SQL modifications retain that snapshot where it is used.
  Transaction-level before images, rollback, indexes, accesslog, and replication
  event before/after images remain intact.
- Delete and ModifyDN reuse valid normalized DN hints from schema-aware
  iterators, with the original parser/normalizer fallback. Stale display hints
  and readers without schema normalization do not use the shortcut.
- Naming-context inference keeps the complete scan and validation. A dedicated
  metadata reader avoids copying attributes that inference never examines;
  unsupported shapes/codecs retain the original decoder. Only explicitly known
  transparent server decorators are unwrapped; unknown wrappers retain their
  original iteration and errors. Inference retains DN keys and parent keys
  instead of every parsed DN graph. Orphans, configuration entries, partitions,
  duplicate identities, ordering, and errors retain the original rules.
- The shared BER octet-string builder writes directly into its owned buffer,
  avoiding a redundant preliminary clone. Input ownership and encoded bytes
  remain unchanged.

The broader probe exposed both the base-search scan and unconditional global
naming-context inference during Add/Delete/ModifyDN. Naming-context inference
and descendant traversal are still O(N); this round reduces their allocation
and repeated computation costs without changing directory validation rules.

## SDK methodology

The reusable [LDAP SDK probe](../internal/cmd/ldapbench/README.md) uses the
repository's go-ldap dependency against an explicitly supplied disposable
server. It checks exact search results, Compare booleans, and write
postconditions. Write verification time is reported separately from the write
operation itself. Random temporary OUs are cleaned up before whole-directory
ordinary-attribute exports are compared byte for byte.

The 100k diagnostic uses one process per implementation, 20 operations in each
read/Bind/Compare stage, and 20 entries per write stage. Startup readiness is a
successful authenticated LDAP operation, measured from process launch, excluding
database copying. It is a sequential before/current/OpenLDAP sample, not a
multi-process median or a capacity benchmark. Do not infer stable improvements
from small differences on this shared workstation.

All databases are copied from the prior round's complete 100k run. Before
probing, the temporary copies undo its parity rename of user 2, remove its
replacement user, and recreate user 3, restoring the probe's contiguous UID
range. User 1's earlier attribute edits are retained identically on both sides.
The source databases remain unchanged. Intermediate failed/aborted probes and
an intermediate implementation's live CPU sample are excluded from the final
comparison.

## 100k SDK results

Times below are totals for 20 operations, excluding separate write-verification
queries. Relative performance is `OpenLDAP / current * 100%`; larger is better.
Before-to-current change is `(current / before - 1) * 100%`; negative is faster.
Small totals and small percentage differences are especially sensitive to noise.

| Operation | Before | Current | OpenLDAP | Change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root Bind | 12.20 ms | 9.41 ms | 3.04 ms | -22.9% | 32.3% |
| User Bind, SSHA | 14.19 ms | 12.45 ms | 2.00 ms | -12.3% | 16.1% |
| Base-object search | 5,705.66 ms | 3.85 ms | 4.64 ms | -99.93% | 120.6% |
| Indexed equality | 4.89 ms | 3.19 ms | 4.95 ms | -34.9% | 155.3% |
| Compare true | 8.98 ms | 7.63 ms | 4.14 ms | -15.0% | 54.3% |
| Compare false | 7.97 ms | 7.44 ms | 2.56 ms | -6.6% | 34.4% |
| Substring prefix | 9,308.69 ms | 9,599.10 ms | 633.20 ms | +3.1% | 6.6% |
| Substring negative | 9,369.77 ms | 9,492.91 ms | 637.26 ms | +1.3% | 6.7% |
| Add | 27,838.98 ms | 23,720.86 ms | 95.56 ms | -14.8% | 0.40% |
| Modify | 22.07 ms | 12.13 ms | 92.63 ms | -45.0% | 763.5% |
| ModifyDN | 50,483.29 ms | 32,147.46 ms | 92.09 ms | -36.3% | 0.29% |
| Delete | 50,868.06 ms | 32,325.16 ms | 93.48 ms | -36.5% | 0.29% |

Authenticated startup was 151 / 142 / 115 ms for before/current/OpenLDAP.
RSS after this mixed read/write workload was 637.6 / 478.8 / 135.7 MiB.
These are individual samples, not startup or RSS medians. They must not replace
the preceding round's repeated-query/paging measurements.

**Add, ModifyDN, Delete and unindexed substring searches remain substantially
slower than OpenLDAP.** The `uid` index in this fixture is equality-only; prefix
and negative-substring requests perform scans. No optimization of that scan is
claimed here, and its small timing increases are retained in the table. Bind,
Compare and first-process behavior also need further workload-specific study.

All three final exports contained 100,002 ordinary-attribute entries and
42,712,438 canonical bytes, POSIX checksum `2143929969`, with byte-for-byte
equality. The SDK also checked each operation and its stated postconditions.

Raw reports: [before](evidence/performance-20260922-round4/sdk-before.json),
[current](evidence/performance-20260922-round4/sdk-current.json),
[OpenLDAP](evidence/performance-20260922-round4/sdk-openldap.json),
[startup](evidence/performance-20260922-round4/sdk-startup.tsv),
[whole-data validation](evidence/performance-20260922-round4/sdk-validation.tsv).

Executable SHA-256 values:

```text
before   066852801a0c8f13e8360163582fce2bfea44a214c8b11b1bea2dda729b11703
current  70e19505a9a855aa3b0352c191c969431877a127240d8351fd41c77f0d9ea95f
SDK tool fae263b244c29060a0c9e08b9f360f1a6657948325b61f7d41c279f939115308
```

## Focused measurements

The before/after server benchmarks use identical newly added benchmark fixtures
on `995247e` and this round's implementation. Each has three 300ms samples.
The Bind benchmark includes the complete password-policy authentication path,
but excludes sockets, and uses one PBKDF2-SM3 password at 100,000 iterations.

| Operation | Before | Current | Time change |
| --- | ---: | ---: | ---: |
| Local Bind, correct password | 93.48 ms | 45.86 ms | -50.9% |
| Local Bind, wrong password | 92.74 ms | 47.39 ms | -48.9% |
| Memory Modify, 64KiB value and eight changes | 361.99 us | 306.83 us | -15.2% |

The same eight-change Modify allocates 1,549,109 versus 1,016,061 bytes on the
memory backend (-34.4%), and 1,849,276 versus 1,314,926 bytes on Bolt (-28.9%).
Initial Bolt timings were 8.4-11.6% slower in some shapes despite fewer
allocations. They include durable commits and are retained in the raw results;
they must not be presented as a durable-write throughput improvement.
An alternating current/before/current/before recheck of the 64KiB/eight-change
case produced six-sample medians of 8.11 ms before and 8.23 ms current (+1.6%),
with overlapping ranges of 7.74-8.96 ms and 7.79-8.65 ms. It did not reproduce
the initial 11.6% difference. These microbenchmarks use the ordinary `OpenBolt`
configuration, whereas the server opens its store through `OpenBoltForServer`;
their durable-write timings are not interchangeable with the SDK table.

Other same-binary component comparisons (three 300ms samples):

| Operation | Reference | Optimized | Allocated bytes, reference / optimized |
| --- | ---: | ---: | ---: |
| Skip 105k partitioned keys in a legacy scan | 1.49 ms | 5.17 us | 2,376 / 2,888 |
| Naming inference, 1k users with 16KiB values | 10.99 ms | 8.12 ms | 26,573,178 / 6,216,777 |
| BER octet string, 4KiB payload | 1.33 us | 0.82 us | 8,368 / 4,272 |

The metadata comparison retains the same compact key-map algorithm on both
sides and isolates payload-copy avoidance. The separate 10k key-map benchmark
has similar total allocated bytes (36.24 / 36.29 MB); that change shortens the
lifetime of parsed DN graphs rather than guaranteeing fewer allocated bytes.
The legacy-scan fixture includes a long partition name requiring one extra
buffer allocation. Its large scan speedup is not an end-to-end startup claim.

Raw component evidence: [server before](evidence/performance-20260922-round4/server-bench-before.txt),
[server current](evidence/performance-20260922-round4/server-bench-current.txt),
[storage](evidence/performance-20260922-round4/storage-bench.txt),
[wire encoding](evidence/performance-20260922-round4/wire-bench.txt).
The four `bolt-recheck-*` logs in the artifact directory preserve the recheck.

These are workload-specific measurements, not a claim that every operation or
backend is faster. In particular, the SDK SSHA Bind results and the PBKDF2-SM3
component benchmark use different password schemes and must not be combined.

## Validation and reproduction

Full package tests and vet passed. The native OpenLDAP differential suite
passed 15 top-level tests, 194 including subtests, with no skips or failures.
Additional coverage includes local/mixed external Bind, ACL-protected password
values, lockout/TOTP tests, modify rollback/indexes/event snapshots, base search
versus the general path across aliases and anonymous/root clients, and naming
inference/decoder comparisons with the former implementations.

The full regression suite caught stale DN hints in an intermediate base-search
shortcut. That implementation is excluded from measurements; the final path
reconstructs and validates the hint, and the previously failing CLI, subtree
rename, collection, and replication cases pass.

```sh
CGO_ENABLED=0 go test -p=1 ./... -count=1 -timeout=10m
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go build -o /tmp/ldapbench ./internal/cmd/ldapbench
CGO_ENABLED=0 go test ./internal/server -run '^$' -bench '^Benchmark(LocalPasswordBind|ModifyEntrySnapshots)$' -benchmem
CGO_ENABLED=0 go test ./internal/storage -run '^$' -bench '^Benchmark(NamingContextKeys|NamingContextMetadataInference|BoltLegacyPartitionScan)$' -benchmem
CGO_ENABLED=0 go test ./internal/ldapwire -run '^$' -bench '^BenchmarkOctetString$' -benchmem
```

For SDK arguments, fixture requirements, and cleanup behavior, see the
[probe documentation](../internal/cmd/ldapbench/README.md). Evidence is retained
under [round-four artifacts](evidence/performance-20260922-round4/); complete
local databases, binaries, profiles, and replay drivers are under
`/var/tmp/ldap-go-perf-round4-20260922` on the qualification host.
