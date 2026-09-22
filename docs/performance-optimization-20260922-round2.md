# Indexed search and paging optimization

This round follows `989ae79` and the [first September 22 optimization](performance-optimization-20260922.md).
It targets the remaining first-query, broad-paging, and allocation costs without
changing stored formats, filter semantics, authorization, or normal result order.
The implementation is recorded in `33b76b5`, `376fc0a`, `69c372d`, `e50b524`,
`e28e1e2`, and `1cf4a6b`.

## Implementation

- Common short-form BER equality/presence searches without controls decode
  directly into the existing request types. Other shapes and encodings use the
  original BER decoder. Differential tests check accepted values, exact errors,
  decoding limits, ownership, and bytes consumed.
- Stored DN reconstruction uses validated views instead of repeatedly copying
  identity parts. Scope checks use a bounded stack buffer. A validation-only
  helper preserves errors when paging needs to validate a DN but will retain
  only its selected output attributes.
- Equality evaluation uses the original comparison rules under one schema read
  lock, without copying attribute values. Missing-value assertion validation and
  three-valued AND/OR/NOT behavior remain intact. A prepared objectClass matcher
  additionally resolves inheritance once for a compatible root paging request.
- Cache hits avoid allocating the full search's candidate state. A guarded
  small-result path handles at most four raw indexed candidates; the fifth
  forces the general path before entries are decoded or responses are written.
  Frontend projections, special entries, unsupported requests, and limits retain
  the complete handling path. No UID uniqueness assumption is made.
- Inactive RWM relay/retcode and SQL-specific preparation are skipped when the
  corresponding runtime feature is absent. Ordinary operations reuse their ACL
  subject context; proxy authorization still replaces it. Only read-barrier
  operations allocate completion channels.
- Broad Bolt equality candidates are prevalidated before callbacks. Physical
  reads are ordered for locality, while callbacks retain the original posting
  order. Sparse gaps use a bounded number of cursor steps before seeking.
  Unsupported shapes and failures retain the original validation/error path.
- An explicit read-only iterator reuses bounded attribute/value descriptors and
  borrows payload bytes only during callbacks. The server uses it for a guarded
  immutable root projection and copies selected output before retaining it.
  The existing owned iterator keeps its ownership contract.
- Paging retains independent cursors over immutable items, caches their
  memory-accounting totals, and avoids temporarily retaining unused parsed DNs.
  Large snapshots use chunked construction and one final compaction; small
  snapshots retain their original slice growth. Byte limits still apply to the
  retained data and its resulting owned slice capacities, which can now be
  smaller for large snapshots. Lease release remains covered by tests.
- The small-result path now waits for index initialization before attempting
  collective-plan work. Failed and size-truncated snapshots are not cached;
  repeating such a query must not turn partial data into a successful result.

bbolt was upgraded from 1.4.3 to 1.5.0. Its page checks construct assertion
messages only on failure; the checks remain enabled. The file format version
is still 2. Internal bbolt statistics are disabled because LDAP monitoring uses
the server's own operation and persisted-entry counters.
See the [upstream page checks](https://raw.githubusercontent.com/etcd-io/bbolt/v1.5.0/internal/common/page.go)
and [release](https://github.com/etcd-io/bbolt/releases/tag/v1.5.0).

A proposed descriptor arena for the existing owned decoder was rejected after
mixed-shape benchmarks showed regressions for some multivalued entries. Its
production changes are not included. Workload-shaped benchmarks and ownership
tests remain for future optimization work.

## Validation

Accepted validation explicitly uses `CGO_ENABLED=0`. All 21 Go packages and vet
passed, as did 15 top-level native OpenLDAP tests (194 passes including subtests,
no skips/failures), six platform builds, and qualification-script checks. Logs
are retained with the performance evidence. The native cases include SDK state transitions,
attribute options, ACLs, missing-attribute assertions, filter depth, DN identity,
paging limits, sync/sort/VLV combinations, and replication interoperability.

Focused regressions also compare optimized and general paths for small indexed
queries, including negative results, quota counters, frontend overlays, source
flags, revision invalidation, and fallback without partial responses. Storage
tests cover late corruption before callbacks, cancellation checkpoints, sparse
and duplicate references, old codecs, borrowed-value lifetimes, and retained
projections after the database is unmapped.

For upgrade compatibility, the new binary modified a copy of the retained 100k
database. Both the new binary and the pre-optimization binary then exported the
same file: all 100,002 entries matched byte for byte. The source snapshot was
not modified.

Both exports contained 27,372,660 bytes with POSIX checksum `1223827884`.

One supplemental agent race command omitted `CGO_ENABLED=0`; that run is not
part of the accepted no-cgo evidence. The affected storage and directory suites
were rerun explicitly with `CGO_ENABLED=0` and passed. Production code introduces
no cgo dependency.

## Performance evidence

The [100k report](openldap-100k-evidence.md) separates the complete fresh-data run
from the final implementation's online replay. It records fresh import,
indexing, startup, indexed/negative queries, both UID and objectClass paging,
concurrency, writes, memory, and data parity. The
[September 1 report](openldap-100k-evidence-20260901.md) remains historical evidence.
The new objectClass measurements are also in the repository's reproducible
comparison script; its resource samples now follow both paging workloads.

Full local artifacts for this round are under
`/var/tmp/ldap-go-perf-round2-20260922`. Earlier intermediate profiles and snapshot
runs in that directory are diagnostic evidence, not measurements of the final
committed implementation. The complete-run executable was built from the working
tree that became `e28e1e2`, before that commit was created. Later online measurements
include the cold-path and snapshot fixes described above; the report identifies
both binary hashes and keeps the two sets of measurements separate.

The final online replay includes `1cf4a6b`. Its first-query and memory results
have not all reached OpenLDAP; the report keeps those gaps visible.

Timing on a shared workstation cannot establish universal superiority over
OpenLDAP across hardware, backends, overlays, authentication schemes, and query
distributions. Use the individual measurements and their stated workloads.
