# OpenLDAP 100k comparison evidence

This evidence was produced on 2026-09-01 (Asia/Shanghai) from ldap-go commit
`38f3fb2` on an Apple M1 Pro,
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

For timing and resource rows, relative performance is `OpenLDAP / ldap-go`,
expressed as a percentage: 100% means equal performance, values above 100%
favor ldap-go, and larger is better.

| Metric | ldap-go | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: |
| Import plus index | 129,952 ms | 1,021,672 ms | 786% |
| Startup ready | 265 ms | 106 ms | 40% |
| Indexed search, repeated | 726 ms | 644 ms | 89% |
| Indexed search, first batch | 1,225 ms | 592 ms | 48% |
| Unindexed negative, repeated | 30 ms | 347 ms | 1,157% |
| Unindexed negative, first batch | 331 ms | 391 ms | 118% |
| Paged traversal, repeated | 1,113 ms | 1,029 ms | 92% |
| Paged traversal, first | 568 ms | 576 ms | 101% |
| Concurrent indexed search | 336 ms | 267 ms | 79% |
| Modify | 748 ms | 5,478 ms | 732% |
| RSS after workload | 147,013,632 B | 97,910,784 B | 67% |
| RSS after 10 seconds idle | 112,869,376 B | 93,257,728 B | 83% |
| Database file | 140,738,560 B | 85,254,144 B | 61% |

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

Compared with the previous complete 100k run on the same host, ldap-go's first
indexed batch fell from 1,953 ms to 1,225 ms (37%), the first unindexed negative
batch from 1,016 ms to 331 ms (67%), and the first paged traversal from 2,012 ms
to 568 ms (72%). Post-workload RSS fell from 485,179,392 B to 147,013,632 B
(70%), and ten-second-idle RSS fell from 217,268,224 B to 112,869,376 B (48%).
The physical-key index references increased the database file from 123,813,888
B to 140,738,560 B (14%), while keyset paging made repeated traversal 55%
slower than the previous retained snapshot path. In the paired result, first
paging and first unindexed negative search now favor ldap-go; repeated indexed
and paged searches are within 11% and 8% of OpenLDAP. Cold indexed search,
concurrent indexed search, startup, idle RSS, and database size remain explicit
follow-up targets.

Every offline, online, resource, and correctness value in the table comes from
this one uninterrupted run. The comparison does not force a GC, drop filesystem
caches, or otherwise alter one side between paired measurements. Raw LDIF,
canonical output, status tables, logs, databases, `results.tsv`, and
`report.json` are retained under `/var/tmp/ldap-go-perf-round10-100k` on the
qualification host.

Reproduce with:

```sh
make qualification-compare-openldap-100k
```

The results establish exact ordinary-data parity for this bounded workload,
not full behavioral identity with every OpenLDAP backend or overlay. They also
make the remaining cold-path latency, RSS, and database-size differences
explicit rather than treating repeated-cache performance as the only result.
