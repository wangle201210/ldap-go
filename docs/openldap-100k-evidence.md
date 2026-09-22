# OpenLDAP 100k comparison evidence

The latest measurements were collected on 2026-09-22 (Asia/Shanghai), Apple M1
Pro, 8 CPUs, 16 GiB RAM, Darwin 24.6.0 arm64, Go 1.26.4. Every accepted Go build
used `CGO_ENABLED=0`. Both servers used the same OpenLDAP 2.6.13 clients on
loopback. The native source was pinned to
`d172686d3d270bc961b78f3ff00d7019c8dfb094`.

**Not every metric has reached OpenLDAP performance.** Repeated queries, paging,
negative queries, and concurrent queries reach or exceed the reference in these
runs. First indexed queries, first broad objectClass paging, startup, memory,
and file size still show gaps. This is a shared workstation, not a dedicated
capacity benchmark.

Relative performance is `OpenLDAP / ldap-go * 100%`. Larger is better; 100%
means equal. Timing and resource values themselves are lower-is-better.

## Final online replay

The final query implementation includes the index-readiness guard, simple-DN
validation, chunked snapshot construction, and exclusion of failed/truncated
snapshots from the cache. Its executable SHA-256 is
`c11845cbe570ae1439e00056d7ad7c8bb86f5a930b7b5daa04bcfe4767000029`.

Each server ran three fresh processes from copies of the databases produced by
the complete run below, after its balanced parity operations. Process order was:

```text
before-1 current-1 openldap-1
current-2 openldap-2 before-2
openldap-3 before-3 current-3
```

Here `before` means the immediately preceding cold-path fixes, before chunked
snapshot construction; it is not the original September 1 implementation.
The primary comparison below uses only `current` and `openldap`.

Work per batch:

- 10,000 indexed queries for `scale-001001` through `scale-011000`;
- ten negative description queries;
- one first, then two repeated full `(objectClass=inetOrgPerson)` traversals,
  page size 10,000;
- eight concurrent connections with 1,000 queries each.

Each process ran three repeated batches. Medians use three first-batch samples,
nine repeated-batch samples, and three RSS samples. Repetitions within one
process are not independent process samples. Clients wrote LDIF to files.
There was no forced GC or filesystem-cache eviction. "First" means the first
batch in a new server process, not a cold OS page cache.

| Metric | ldap-go | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: |
| Indexed, first 10,000 queries | 1,069 ms | 725 ms | 68% |
| Indexed, repeated 10,000 queries | 677 ms | 682 ms | 101% |
| Negative, first ten queries | 312 ms | 354 ms | 113% |
| Negative, repeated ten queries | 30 ms | 348 ms | 1,160% |
| First full objectClass traversal | 1,009 ms | 760 ms | 75% |
| Two repeated objectClass traversals | 1,214 ms | 1,411 ms | 116% |
| Concurrent indexed, 8 x 1,000 | 243 ms | 254 ms | 105% |
| RSS after mixed workload | 333.2 MiB | 94.3 MiB | 28% |

All nine runs returned 100,000 unique people and the same 100,002-entry subtree:
42,712,504 canonical ordinary-attribute bytes, POSIX checksum `648440320`.
Request counts, negative result counts, page uniqueness, and concurrent result
counts were checked. Full ordinary-attribute data matched byte for byte.

Repeated negative queries may use the same-revision result cache. RSS is a
post-workload sample, not peak memory or an idle/retained-heap measurement.
These query results are not a replacement measurement for import or writes.

Raw evidence:
[online timings](evidence/performance-20260922-round2/final-online-timings.tsv),
[online validation](evidence/performance-20260922-round2/final-online-validation.tsv).
The replay driver and full artifacts are retained under
`/var/tmp/ldap-go-perf-round2-20260922/online-builder` on the qualification host.

## Complete fresh-data run

This uninterrupted run used the implementation committed as `e28e1e2`, before
the final cold-path fixes. Binary SHA-256:
`f1dab40d5034e2d4359aac55517da51388dfad72062077ee2ef0083a8b9f2bff`.

Both databases were generated and imported afresh with 100,000 inetOrgPerson
entries, then explicitly indexed on `uid` and `objectClass`. Each repeated
batch used 10,000 indexed queries, ten negative queries, two full paged
traversals (page size 10,000), and eight connections with 1,000 queries each.
There were 1,000 timed Modify operations. Paging covered both `(uid=scale-*)`
and `(objectClass=inetOrgPerson)`. Repeated query timings are the integer mean
of two batches in opposite server orders.

| Metric | ldap-go | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: |
| Import plus index | 98,121 ms | 933,093 ms | 951% |
| Startup ready | 656 ms | 159 ms | 24% |
| Indexed search, repeated | 585 ms | 595 ms | 102% |
| Indexed search, first batch | 4,710 ms | 499 ms | 11% |
| Negative search, repeated | 33 ms | 344 ms | 1,042% |
| Negative search, first batch | 305 ms | 522 ms | 171% |
| UID paging, repeated | 1,129 ms | 1,367 ms | 121% |
| UID paging, first | 560 ms | 568 ms | 101% |
| ObjectClass paging, repeated | 573 ms | 1,228 ms | 214% |
| ObjectClass paging, first | 1,153 ms | 709 ms | 61% |
| Concurrent indexed search | 207 ms | 241 ms | 116% |
| Modify | 548 ms | 5,478 ms | 1,000% |
| RSS after workload | 261,308,416 B | 99,565,568 B | 38% |
| RSS after ten seconds idle | 122,060,800 B | 94,371,840 B | 77% |
| Database file size | 140,738,560 B | 85,254,144 B | 61% |

The first indexed batch exposed speculative collective-plan work before index
initialization. The final implementation defers that fast path until readiness
is established; the new regression checks that it performs no speculative View
or collective scan before initialization. The 4,710 ms value above remains the
actual recorded result, not a substituted later measurement. OS cache warmth
also differs between the long import run and the online replays, so differences
between those tables cannot be attributed solely to code changes.

This run passed all 15 canonical-data and result-code checks. Both paging
filters returned exactly 100,000 unique people, every timed modification was
visible, and the final 100,002-entry ordinary-attribute subtree matched byte for
byte with the same checksum and byte count as the replay. Generated operational
timestamps, CSNs, and UUIDs were excluded by requesting `*`.

Raw evidence:
[complete JSON report](evidence/performance-20260922-round2/fresh-100k.json),
[complete TSV](evidence/performance-20260922-round2/fresh-100k.tsv).
Full artifacts are under
`/var/tmp/ldap-go-perf-round2-20260922/fresh-100k`.

## Reproduction and limits

```sh
CGO_ENABLED=0 OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
  make qualification-compare-openldap-100k
```

See [production qualification](production-qualification.md#openldap-performance-comparison)
for parameters and [implementation/validation notes](performance-optimization-20260922-round2.md)
for the changes. The [September 1 complete run](openldap-100k-evidence-20260901.md)
is retained separately. Its paging workload did not include the additional
objectClass measurements, so its RSS is not directly comparable with the new
complete run.

The validated data parity covers these workloads, not every LDAP backend or
overlay. The outstanding first-request, memory, and file-size differences remain
explicit; these results do not establish universal performance superiority.
