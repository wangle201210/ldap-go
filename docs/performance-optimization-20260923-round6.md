# Write-path allocation reduction

Baseline: `1119f2a`. This round is separate from the
[read replay](performance-optimization-20260923-round5.md). All Go commands
use `CGO_ENABLED=0`.

## Delete Preflight

The nonleaf check previously copied every entry's attributes while collecting
and sorting DN metadata. A narrowly gated Bolt helper now retains only the DN
and validated identity/order hints needed by that check. It still validates
every row before the first callback, sorts in the same order, examines orphan
descendants, and retains normalization and cancellation behavior. Unsupported
writers, unmigrated partitions, memory stores and outer wrappers keep the
original iterator. SQL and tree-delete paths are unchanged.

This remains O(N). Global naming-context refresh still scans the directory;
no parent index, relaxed validation or new persisted format is introduced.

Three 300ms component samples, medians below. Fixture construction and commit
are outside the timed loop; this is the preflight scan, not complete Delete.

| 10k-entry fixture | Original iterator | DN metadata | Allocated bytes, before / current |
| --- | ---: | ---: | ---: |
| 256-byte attribute | 27.75 ms | 26.10 ms | 27,307,820 / 22,907,797 |
| 16KiB attribute | 43.14 ms | 28.45 ms | 208,107,789 / 22,907,793 |

Tests compare both iterators across V1/V2/V3/JSON data, row ordering, owned
output after unmapping, malformed rows, physical identities, cancellation,
unsupported wrappers and schema-normalizer errors. LDAP tests cover nonleaf
and orphan-grandchild protection, case-exact siblings, alias/OID DN lookup and
no-op rollback. The standard server write decorators are exercised explicitly
to verify that the optimized path is reachable.

## Indexed Modification

When replacing one existing physical row and its index terms change, Bolt
previously decoded and validated the same old entry twice. It now reuses that
owned entry only when the index-value provider explicitly guarantees read-only
input. The server opts in only for its concrete schema registry; custom
registries and unknown providers retain the second decode. Unchanged index
terms keep their existing path. Index normalization calls, their order and
errors, entry counters, persisted values, rollback and revision behavior remain
unchanged. This does not introduce index-term caching.

Tests cover changed and unchanged terms, old/new index lookups, retained
before/after snapshots, provider errors at each normalization stage, cancellation,
corrupt records, rollback, entry counts and storage revisions. Mutating custom
providers exercise the original fresh-decode fallback.

Identical fixtures were compiled with the baseline `index_bolt.go` through a
Go overlay and with the current implementation. Three 500ms samples, medians:

| Indexed replacement payload | Before | Current | Allocated bytes, before / current |
| --- | ---: | ---: | ---: |
| 1KiB photo | 18.11 us | 16.17 us | 23,810 / 21,145 |
| 64KiB photo | 54.93 us | 44.15 us | 312,821 / 237,543 |

Allocation counts decrease from 366 to 318. Each iteration starts a writable
transaction, changes the indexed `cn` value and rolls back; it excludes durable
commit latency. The current 64KiB samples range from 41.41 to 68.58 us, so these
component medians must not be interpreted as a guarantee for durable Modify.
[Baseline samples](evidence/performance-20260923-round6/modify-before.txt),
[current samples](evidence/performance-20260923-round6/modify-current.txt) and
[Delete samples](evidence/performance-20260923-round6/delete-bench.txt) are retained.

## 100k SDK Method

The existing disposable 100k fixture is copied separately for three fresh
processes per implementation. Order rotates before/current/OpenLDAP,
current/OpenLDAP/before, then OpenLDAP/before/current. The reusable
[SDK probe](../internal/cmd/ldapbench/README.md) runs three operations per
read/Bind stage and three entries per write stage. Setup, cleanup and post-write
verification are reported separately from each measured operation.

Each run creates its own temporary OU and users, checks writes through LDAP,
removes the temporary entries, and exports all ordinary attributes for canonical
comparison. This is a small sequential regression workload, not a concurrent
write-capacity measurement. The probe's Modify replaces unindexed `description`,
so its latency is not evidence for the changed-index decode optimization above.
That branch is exercised by the indexed `cn` component benchmark and index
postcondition tests.

## 100k SDK Results

Three-process medians, each total covers three operations. Time change is
`(current / before - 1) * 100%`; relative performance is
`OpenLDAP / current * 100%`, where larger is better.

| Operation | Before | Current | OpenLDAP | Time change | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Add | 2,365.83 ms | 2,368.79 ms | 12.29 ms | +0.1% | 0.52% |
| Modify, unindexed description | 2.51 ms | 2.40 ms | 12.60 ms | -4.3% | 524.0% |
| ModifyDN | 3,593.93 ms | 3,584.23 ms | 14.36 ms | -0.3% | 0.40% |
| Delete | 3,602.92 ms | 3,461.79 ms | 14.36 ms | -3.9% | 0.41% |

Delete improves modestly on this small-attribute fixture. Add and ModifyDN
remain essentially unchanged; their full-directory scans still dominate and
remain much slower than native OpenLDAP. Small Modify totals are noisy and,
as noted above, do not exercise changed index terms. The storage opening and
durability configurations are inherited unchanged from the earlier SDK replay;
this table does not generalize to all backends or commit configurations.

RSS after setup, writes and cleanup has medians of 626.2 MiB before,
594.8 MiB current and 133.8 MiB native (-5.0% current/before). Samples have wide
overlap; this does not negate the increased RSS in the separate read replay or
establish a general memory improvement. No forced GC was used.

All nine runs passed SDK postcondition checks and produced identical ordinary
attribute exports after cleanup: 100,002 entries, 42,712,438 canonical bytes,
POSIX checksum `2143929969`.
[All timing samples](evidence/performance-20260923-round6/sdk-timings.json),
[export/RSS checks](evidence/performance-20260923-round6/sdk-validation.tsv) and
[per-process SDK reports](evidence/performance-20260923-round6/) are retained.

Executable SHA-256:

```text
before  86fe571735f7b927ec4cb6591753ef6299e6014058b493aa8b34e4f6af62cfcc
current da5c7a756473c61ba999ab3303582147981fc22eb3617ccba5e0f9e3c467855e
```

The exact local replay and disposable databases are under
`/var/tmp/ldap-go-perf-round9-20260923/write-replay.sh` and its `writes` directory.

## Validation

The final write implementation passed the
[full Go suite](evidence/performance-20260923-round6/go-test.txt),
[vet](evidence/performance-20260923-round6/go-vet.txt), and
[native OpenLDAP differential checks](evidence/performance-20260923-round6/openldap-differential.txt)
(194 including subtests, no skips). No race-detector run is claimed with cgo
disabled.
