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

For timing and resource rows, the ratio is `OpenLDAP / ldap-go`: a value above
1 favors ldap-go, and larger is better.

| Metric | ldap-go | OpenLDAP | OpenLDAP / ldap-go |
| --- | ---: | ---: | ---: |
| Import plus index | 105,727 ms | 832,618 ms | 7.88 |
| Startup ready | 272 ms | 96 ms | 0.35 |
| Indexed search, repeated | 720 ms | 608 ms | 0.84 |
| Indexed search, first batch | 1,953 ms | 617 ms | 0.32 |
| Unindexed negative, repeated | 30 ms | 338 ms | 11.27 |
| Unindexed negative, first batch | 1,016 ms | 390 ms | 0.38 |
| Paged traversal, repeated | 718 ms | 1,543 ms | 2.15 |
| Paged traversal, first | 2,012 ms | 715 ms | 0.36 |
| Concurrent indexed search | 258 ms | 275 ms | 1.07 |
| Modify | 565 ms | 3,780 ms | 6.69 |
| RSS after workload | 485,179,392 B | 98,140,160 B | 0.20 |
| RSS after 10 seconds idle | 217,268,224 B | 94,093,312 B | 0.43 |
| Database file | 123,813,888 B | 85,254,144 B | 0.69 |

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

Compared with the original pre-optimization run of this same 100k profile on
the same host, streaming unsorted scans and coalescing binary-entry ownership
reduced ldap-go's post-workload RSS from 811,089,920 B to 485,179,392 B (40%)
and its ten-second-idle RSS from 734,314,496 B to 217,268,224 B (70%). Database
size remained 123,813,888 B. Indexed collective-plan discovery, revision-bound
index validation, and no-op valsort/sync projection fast paths reduced the cold
indexed batch from 4,280 ms to 1,953 ms and cold paging from 4,152 ms to
2,012 ms relative to the immediately preceding complete run. The comparison
does not force a GC or otherwise alter one side. Cold indexed and cold paged
latency remain slower than OpenLDAP and are explicit follow-up targets rather
than resolved regressions.
A focused representative binary-entry decode benchmark moved from 23 to 15
allocations per operation and from roughly 571-635 ns/op to 402-465 ns/op. The
single owned encoded block increased retained bytes in that microbenchmark from
816 to 880 B/op; the 100k database size did not change.

The full comparison run encountered a host suspension during ldap-go's offline
phase. The `105,727 ms` ldap-go import-plus-index row is an immediate rerun with
the same generated seed, comparison binary, database options, and commands;
the `832,618 ms` OpenLDAP value is from the completed full run. All online,
resource, correctness, and OpenLDAP measurements are from that full run. Its
raw anomalous offline value remains available in the retained `report.json`.

After the retained full run, additional no-op overlay and attribute-only scan
fast paths were tested against the same 100k database with a new ldap-go process
for every trial. Three-run ranges were 1,660-1,868 ms for the first 10,000
indexed searches, 1,865-1,909 ms for the first paged traversal, and 554-570 ms
for the first ten unindexed negative searches. These targeted measurements are
not substituted into the paired table above; the next complete paired run will
replace that table atomically.

Reproduce with:

```sh
make qualification-compare-openldap-100k
```

The results establish exact ordinary-data parity for this bounded workload,
not full behavioral identity with every OpenLDAP backend or overlay. They also
make the remaining cold-path latency, RSS, and database-size differences
explicit rather than treating repeated-cache performance as the only result.
