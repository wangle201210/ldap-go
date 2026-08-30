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
| Import plus index | 101,085 ms | 876,070 ms | 0.12 |
| Startup ready | 261 ms | 89 ms | 2.93 |
| Indexed search, repeated | 680 ms | 554 ms | 1.23 |
| Indexed search, first batch | 4,073 ms | 642 ms | 6.34 |
| Unindexed negative, repeated | 32 ms | 336 ms | 0.10 |
| Unindexed negative, first batch | 1,036 ms | 350 ms | 2.96 |
| Paged traversal, repeated | 741 ms | 900 ms | 0.82 |
| Paged traversal, first | 3,876 ms | 450 ms | 8.61 |
| Concurrent indexed search | 202 ms | 201 ms | 1.00 |
| Modify | 572 ms | 5,420 ms | 0.11 |
| RSS after workload | 811,089,920 B | 98,189,312 B | 8.26 |
| RSS after 10 seconds idle | 734,314,496 B | 97,255,424 B | 7.55 |
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

The retained-cache budgets are bounded, but Go did not return most transient
scan heap pages to the operating system during this run's ten-second idle
window. The table records that observed RSS without forcing a GC or otherwise
altering one side of the comparison.

Reproduce with:

```sh
make qualification-compare-openldap-100k
```

The results establish exact ordinary-data parity for this bounded workload,
not full behavioral identity with every OpenLDAP backend or overlay. They also
make the remaining cold-path latency, RSS, and database-size differences
explicit rather than treating repeated-cache performance as the only result.
