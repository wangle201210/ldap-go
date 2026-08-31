# OpenLDAP 100k comparison evidence

This evidence was produced on 2026-08-31 (Asia/Shanghai) on an Apple M1 Pro,
Darwin 24.6.0 arm64 host. Both servers used the same OpenLDAP 2.6.13 client
binaries over loopback. OpenLDAP and ldap-go explicitly rebuilt `uid` and
`objectClass` equality indexes before startup.

Run profile:

- 100,000 generated `inetOrgPerson` entries
- 10,000 sequential indexed searches per round
- 10 unindexed negative searches per round
- two complete paged traversals per round, page size 10,000
- eight concurrent connections, 1,000 indexed searches each
- 1,000 Modify operations
- canonical full-data and operation-result parity enabled

| Metric | ldap-go | OpenLDAP | ldap-go / OpenLDAP |
| --- | ---: | ---: | ---: |
| Import plus index | 165,692 ms | 961,340 ms | 0.17 |
| Startup ready | 319 ms | 93 ms | 3.43 |
| Indexed search, repeated | 810 ms | 605 ms | 1.34 |
| Indexed search, first batch | 4,280 ms | 550 ms | 7.78 |
| Unindexed negative, repeated | 42 ms | 351 ms | 0.12 |
| Unindexed negative, first batch | 1,047 ms | 472 ms | 2.22 |
| Paged traversal, repeated | 750 ms | 1,402 ms | 0.53 |
| Paged traversal, first | 4,152 ms | 726 ms | 5.72 |
| Concurrent indexed search | 255 ms | 237 ms | 1.08 |
| Modify | 1,032 ms | 4,299 ms | 0.24 |
| RSS after workload | 425,967,616 B | 96,911,360 B | 4.40 |
| RSS after 10 seconds idle | 279,379,968 B | 96,894,976 B | 2.88 |
| Database file | 123,813,888 B | 85,254,144 B | 1.45 |

Correctness evidence:

- 100,000 unique people returned by both servers
- all 1,000 timed modifications visible on both servers
- 100,002 final subtree entries after the balanced Add/Delete sequence
- 15 canonical data, query, Bind, Compare, and error-result checks passed
- canonical ordinary-attribute output matched byte for byte: 42,712,504 bytes,
  POSIX checksum `648440320`
- duplicate Add, missing Modify, and non-leaf Delete matched LDAP result codes
  68, 32, and 66; Compare TRUE/FALSE matched 6 and 5

The canonical comparison requests `*`: it covers every ordinary LDAP
attribute and excludes generated operational values such as timestamps, CSNs,
and random UUIDs that are intentionally server-specific. Raw and canonical
LDIF, operation status tables, logs, databases, `results.tsv`, and
`report.json` were retained in the run artifact directory.

Compared with the preceding run of this same 100k profile on the same host,
streaming unsorted scans and coalescing binary-entry ownership reduced
ldap-go's post-workload RSS from 811,089,920 B to 425,967,616 B (47%) and its
ten-second-idle RSS from 734,314,496 B to 279,379,968 B (62%). Database size
remained 123,813,888 B. The comparison does not force a GC or otherwise alter
one side. Cold indexed and cold paged latency remain materially slower than
OpenLDAP and are explicit follow-up targets rather than resolved regressions.
A focused representative binary-entry decode benchmark moved from 23 to 15
allocations per operation and from roughly 571-635 ns/op to 402-465 ns/op. The
single owned encoded block increased retained bytes in that microbenchmark from
816 to 880 B/op; the 100k database size did not change.

Reproduce with:

```sh
make qualification-compare-openldap-100k
```

The results establish exact ordinary-data parity for this bounded workload,
not full behavioral identity with every OpenLDAP backend or overlay. They also
make the remaining cold-path latency, RSS, and database-size differences
explicit rather than treating repeated-cache performance as the only result.
