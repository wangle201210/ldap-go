# Indexed hierarchy and incremental naming contexts

Baseline: `6f97cf6`. This round targets the largest measured gaps: Add,
ModifyDN and Delete on 100k entries. It follows the
[DN and Bind report](performance-optimization-20260923-round7.md). All Go
builds, tests and benchmarks use `CGO_ENABLED=0`.

## Removing Full Scans

Previously, every Add/Delete/ModifyDN recomputed naming contexts from all rows.
Delete also scanned every entry to determine whether it had descendants;
ModifyDN loaded the entire partition before selecting its subtree.

Naming contexts now use a bounded, in-memory index on managed Bolt write
transactions. The first inference fully validates and normalizes the directory.
Later transactions track changed physical keys and update global DN membership,
duplicate ownership and immediate-parent relationships. Duplicate identities
across partitions still use the last physical row's raw DN, and parents in
another partition still affect membership. Empty DNs and config exceptions
retain their original rules. Stored naming-context metadata is still written
only at the existing refresh callsites.

The cache is protected by the store's write lock. Failure, panic, Clear,
migration, changed schema fingerprints and untracked transaction revisions
invalidate affected state. Mutations after a refresh are accounted for before
commit without introducing new write errors; invalid derived updates discard
the cache. Normalizers must explicitly provide immutable semantics. Unknown
normalizers and readers retain the ordered full scan. The retained-data budget
is an estimated 256 MiB, not a process RSS limit; exceeding it falls back to
scanning. Restart and invalidation require a new cold scan.

A separate persistent Bolt hierarchy index stores length-framed normalized
RDNs in root-to-leaf order, mapping each path to its authoritative entry. An
ancestor path is a prefix of descendant paths even when an intermediate entry
is missing. Leaf checks use a seek; rename collects and validates only its
affected subtree, preserving entry ownership and the original ordering within
that set. Ordinary mutations, identity migration and Clear maintain or
invalidate the index in the same transaction as the entries and counts.

Existing databases build the missing hierarchy index on writable startup.
Persisted mappings are fully checked on startup before use. A read-only store
without a usable optional index retains the general path. Malformed manifests
or inconsistent mappings produce errors, not false leaf results. Full offline
reindex now repairs derived hierarchy data after DN identity migration and
authoritative-entry validation; attribute-selective reindex retains its scope.
The normal database checker validates both directions of the mapping. SQL,
RWM, unknown decorators and unsupported identity forms retain their applicable
general paths.

For an offline full hierarchy repair, use `ldap-go slapindex -db PATH` without
an attribute list (select a database with `-n` or `-database` when needed).
The `reindex`/`rebuild` aliases perform physical compaction and are not the
logical hierarchy-repair command. Authoritative-entry corruption must be
resolved before rebuilding derived indexes.

Indexed queries in write transactions now read live postings and revalidate
index configuration without using transaction-ID snapshot caches. This removes
the full collective scan that made deletion of an already absent DN expensive.
The collective index is used to prove that no sources exist; when sources do
exist, all administrative boundaries are scanned. This also fixes incorrect
inheritance into a nested administrative area without a local source.

After warmup, ordinary leaf naming-context maintenance depends on the changes,
not total row count. Subtree work remains proportional to affected entries.
Startup validation, cold cache construction, large subtree changes, cache
fallbacks and enabled collective sources can still require full scans.

## Component Evidence

Each benchmark iteration adds a leaf, refreshes contexts, deletes the leaf and
refreshes again in one writable transaction. Fixture construction, the initial
cache build and durable commit are excluded. Three 100ms samples, medians:

| Directory size | Full scan pair | Incremental pair | Allocated bytes, scan / incremental |
| --- | ---: | ---: | ---: |
| 1k | 7.256 ms | 15.14 us | 6,228,822 / 11,327 |
| 100k | 811.873 ms | 15.44 us | 605,406,872 / 12,186 |

The 100k scan takes longer than the requested benchmark duration and therefore
has one iteration per sample. These results isolate naming-context work and
are not complete LDAP request timings.
[All component samples](evidence/performance-20260923-round8/naming-bench.txt).

## 100k Write Comparison

The normalized fixture and OpenLDAP 2.6.13 configuration match the preceding
reports. Each implementation runs in three fresh processes, rotating
before/current/OpenLDAP, current/OpenLDAP/before, then OpenLDAP/before/current.
Each SDK write stage has three entries. Setup, cleanup and postcondition checks
are recorded separately. The measured Add/Delete/ModifyDN stages follow setup,
so the naming-context cache is warm; the first-write cost is not hidden in their
totals. Negative time change is faster. Relative performance is
`OpenLDAP / current * 100%`, where larger is better.

| Three operations | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 1,899.84 ms | 2.82 ms | 14.78 ms | -99.85% | 524.7% |
| Modify, unindexed description | 2.53 ms | 1.69 ms | 15.72 ms | -33.0% | 929.8% |
| ModifyDN | 3,130.48 ms | 4.61 ms | 16.43 ms | -99.85% | 356.2% |
| Delete | 2,952.65 ms | 3.05 ms | 15.24 ms | -99.90% | 498.8% |

The cleanup stage, including repeated deletion attempts for already absent
temporary DNs, decreases from 19,719.21 to 13.47 ms; native is 52.70 ms. An
intermediate implementation still took about nine seconds here because of the
collective scan on missing-target writes. Final results include the live-index
fix and the administrative-boundary correction.

Post-write RSS medians are **615.7 MiB before, 356.4 MiB current and 133.6 MiB
native**, a 42.1% current/before reduction. This is sampled RSS without forced
GC, not retained-heap size; ldap-go still uses more memory than native.
[All SDK samples](evidence/performance-20260923-round8/sdk-timings.json),
[per-process reports](evidence/performance-20260923-round8/), and
[export/RSS checks](evidence/performance-20260923-round8/sdk-validation.tsv)
are retained.

## Longer Native Comparison

Because the optimized operations are short, an additional run compares current
and native with 20 entries per write stage and three fresh processes each,
alternating their order. No baseline version was measured in this longer run.
The table gives three-process medians, excluding separate verification queries.

| Twenty operations | ldap-go | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: |
| Add | 31.10 ms | 115.31 ms | 370.8% |
| Modify, unindexed description | 17.38 ms | 122.69 ms | 706.1% |
| ModifyDN | 35.51 ms | 121.37 ms | 341.8% |
| Delete | 28.04 ms | 135.41 ms | 482.9% |

The same processes ran the existing read/Bind stages before writes. Root Bind
was 4.77 / 2.84 ms, indexed equality 3.41 / 2.95 ms, and prefix substring
1,240.35 / 644.73 ms for ldap-go/native (20 operations each). These remain
slower than native; this round does not establish overall performance parity.
Post-workload RSS was 389.7 / 135.4 MiB.
[Long-run timings](evidence/performance-20260923-round8/long-timings.json) and
[export/RSS validation](evidence/performance-20260923-round8/long-validation.tsv)
retain every process sample.

## Costs and Limits

Authenticated startup for the three-version run was **152 / 1,446 / 133 ms**
before/current/native. Each copied database initially lacks the hierarchy
index, so current includes its first build. Startup also validates persisted
indexes on later opens; it is not a constant-time readiness check. The setup
stage's eleven Add operations, including cold naming-context inference, took
**7,082.83 / 706.80 / 66.90 ms**. The optimization moves work to initialization
and keeps derived metadata in memory; it does not make first initialization as
fast as native. [Startup samples](evidence/performance-20260923-round8/startup-timings.tsv).

The sequential fixture has small entries, indexed `uid`/`objectClass`, no
collective sources, and ordinary leaf writes. Results do not guarantee the
same ratios for large subtree moves, large attributes, many naming-context
roots, enabled overlays, concurrent writes or different durability settings.
The existing store-opening, password, ACL and durability configurations are
unchanged. No timing outliers were discarded.

All fifteen final main/long runs passed SDK postconditions and returned
byte-for-byte identical ordinary-attribute exports after cleanup: 100,002
entries, 42,712,438 canonical bytes, POSIX checksum `2143929969`.
Executable SHA-256 values for the accepted runs:

```text
before  0e770a645149df125b622d7ab66af953b77ee9120f9e44c89be6b871c1d6634e
current bde04b49af4eacf7cffb56aede7da5202ded2458f2bb433191c39ad1cc2e2f9c
```

Exact local replay scripts and raw artifacts are under
`/var/tmp/ldap-go-perf-round11-20260923`; accepted runs are `writes-final` and
`writes-long`. Disposable database copies are removed after validation and
process exit. Source snapshots, exports, scripts and reports are retained.

## Validation

Tests cover duplicate winners and cross-partition parents, orphan descendants,
config exceptions, same-count replacement, mutations after refresh, rollback
and panic, cancelled empty scans, malformed and zero-length rows, schema changes,
cache capacity/pruning, randomized mutation sequences and writer lifetime.
Hierarchy tests cover transactional changes, legacy migration, restart,
read-only startup, corruption, offline repair and exact subtree ownership/order.
Writer-index tests check same-transaction changes, index invalidation and
rebuild, poisoned snapshot validation caches, callbacks and rollback. Collective
tests compare indexed results with a live full scan, including nested boundaries.

Implementation testing caught and fixed panic rollback, zero-length row error
ordering, legacy offline-reindex ordering and the collective-boundary issue
before the accepted final runs. The [full Go suite](evidence/performance-20260923-round8/go-test.txt)
and [vet](evidence/performance-20260923-round8/go-vet.txt) passed.
[General native differential checks](evidence/performance-20260923-round8/openldap-differential.txt)
passed 194 checks including subtests; additional
[write/overlay checks](evidence/performance-20260923-round8/openldap-write-overlays.txt)
passed 27, covering collective areas, memberof/refint, unique/constraint,
transactions, core operations and tree deletion. No skips were reported in
these selected native checks. No race-detector result is claimed with cgo disabled.

The validation model for indexed operations is complete initialization plus
transactional maintenance and relevant-row validation, rather than decoding
every unrelated row on every write. Direct private-bucket/file corruption that
bypasses normal mutation hooks requires startup or full integrity checking.
The original full-scan helpers remain available as fallbacks.
