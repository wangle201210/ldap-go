# Performance audit after compatibility fixes

Measured on 2026-09-20 (Asia/Shanghai), comparing `4fcb185` with `a101bad`.
The baseline already includes the preceding compatibility audit; this measures
the seven subsequent commits, not all changes since the September 1 benchmark.

Correctness checks passed. The measurements do **not establish a stable general
performance regression** from this revision range. Separate-process runs showed
roughly 11% slower repeated indexed queries, but adjacent paired requests and a
port-swapped repetition did not reproduce a consistent difference. Small
regressions cannot be excluded on this busy workstation.

Two separate limitations remain in the 100k workload: the first full paged
traversal using `(objectClass=inetOrgPerson)` is substantially slower than
OpenLDAP, and RSS measured after the entire mixed workload is much higher.
Both ldap-go revisions exhibit these differences; this sampling does not
attribute the RSS difference to any one operation.

## Environment and scope

- Apple M1 Pro, 8 CPUs, 16 GiB RAM, Darwin 24.6.0 arm64.
- Go 1.26.4, both ldap-go executables built with `CGO_ENABLED=0`.
- OpenLDAP 2.6.13, source commit
  `d172686d3d270bc961b78f3ff00d7019c8dfb094`.
- Same native OpenLDAP clients, loopback TCP, simple root Bind, and `uid` and
  `objectClass` equality indexes. No TLS, additional ACLs, or overlays.
- Tests ran sequentially. In paired tests both servers stayed alive, but only
  one received a timed batch at a time.
- Other applications remained running. Observed one-minute host load ranged
  from 10.65 to 17.14; this was not a dedicated benchmark machine.
- No filesystem-cache drop or forced GC. "First" means the first batch in a
  new server process, not a cold operating-system page cache.

For tables comparing servers, relative performance is `OpenLDAP / current
ldap-go`, expressed as a percentage; larger is better. For revision comparisons,
**latency change** is `(current / before - 1) * 100%`; positive means slower.

## Fresh 10k databases

The unchanged `scripts/qualification/compare-openldap.sh` ran in order
`before-1`, `current-1`, `current-2`, `before-2`. Each run generated new
databases, imported 10,000 people, rebuilt indexes, and ran:

- 10,000 sequential indexed queries per batch;
- 20 unindexed negative queries per batch;
- five complete traversals per repeated batch, page size 1,000;
- eight concurrent connections, 1,000 indexed queries each;
- 1,000 Modify operations, followed by all 15 data/result-code parity checks.

Each report already averages two repeated query batches. The following values
are the midpoint of the two reports for each revision, in milliseconds.
OpenLDAP values use the two `current` reports.

| Metric | Before | Current | Latency change | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| Import plus index | 2,368.5 | 2,460.5 | +3.9% | 98,591 | 4,007% |
| Indexed, repeated | 940 | 1,042 | +10.9% | 757 | 73% |
| Indexed, first batch | 1,680 | 1,390 | -17.3% | 1,167 | 84% |
| Unindexed negative, repeated | 40.5 | 35.5 | -12.3% | 84 | 237% |
| Unindexed negative, first batch | 65 | 64.5 | -0.8% | 85.5 | 133% |
| Paged traversal, repeated | 450.5 | 500.5 | +11.1% | 475.5 | 95% |
| Concurrent indexed | 340.5 | 361 | +6.0% | 368.5 | 102% |
| Modify | 786 | 746.5 | -5.0% | 4,590 | 615% |

All four runs returned 10,000 unique people, exposed all 1,000 modifications,
and passed 15 parity checks. Each final canonical subtree had 10,002 entries.
These small sample counts and large native-server timing swings prompted the
additional controls below; the positive percentages alone are not evidence
that the compatibility fixes caused a slowdown.

## Shared 100k snapshots

This online-only test copied the retained September 1 databases before each
server start. It did not repeat the 100k import or measure writes. Each copy
already contained the balanced parity Add/Delete/Rename operations. The original
database files were unchanged, verified by SHA-256 before and after testing.

Three fresh processes per server used this order:

```text
before-1 current-1 openldap-1
current-2 openldap-2 before-2
openldap-3 before-3 current-3
```

Each process ran a first indexed batch, first negative batch, and first paged
traversal, followed by three repetitions of indexed, negative, paged, and
concurrent batches. Indexed batches requested 10,000 users (`scale-001001`
through `scale-011000`); negative batches contained ten descriptions. Repeated
paging performed two full traversals, with page size 10,000. Concurrency was
eight connections with 1,000 queries each. Clients wrote LDIF to local files on
all sides, and the workload validated indexed, negative, paged, and concurrent
result counts.

The ldap-go Search limits were 100,100 entries/candidates, 819,200,000 candidate
bytes per Search, and 1,638,400,000 retained Search bytes across the process,
matching the scaled budgets in the fresh 100k benchmark. These are not the
default limits for an unconfigured server.

Paging used `(objectClass=inetOrgPerson)`, including the parity-added user.
This differs from the `(uid=scale-*)` filter and output handling in the historical
[complete 100k comparison](openldap-100k-evidence.md). The two tables must not be
treated as measurements of the same workload.

Values below are medians: three first-batch samples, nine repeated-batch samples,
and three post-workload RSS samples per server. Repetitions within a process
are not independent process samples.

| Metric | Before | Current | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: | ---: |
| Indexed, first 10,000 queries | 1,175 ms | 1,161 ms | 772 ms | 66% |
| Indexed, repeated 10,000 queries | 834 ms | 922 ms | 649 ms | 70% |
| Negative, first ten queries | 321 ms | 319 ms | 360 ms | 113% |
| Negative, repeated ten queries | 31 ms | 32 ms | 348 ms | 1,088% |
| First full objectClass traversal | 2,702 ms | 2,856 ms | 607 ms | 21% |
| Two repeated objectClass traversals | 1,054 ms | 1,096 ms | 1,153 ms | 105% |
| Concurrent indexed, 8 x 1,000 | 246 ms | 249 ms | 210 ms | 84% |
| RSS immediately after workload | 661.3 MiB | 681.5 MiB | 95.3 MiB | 14% |

Repeated negative queries are eligible for ldap-go's result cache; they do not
represent ten fresh full scans on each repetition. RSS is one resident-memory
sample after the workload, not peak RSS, retained heap, a leak measurement, or
an idle-memory measurement. No 10-second-idle RSS was collected in this profile.

All nine runs returned 100,000 unique people and exactly the same 100,002-entry
canonical subtree: 42,712,504 bytes, POSIX checksum `648440320`. Full ordinary
attributes were compared byte for byte across both revisions and OpenLDAP.
Generated operational attributes were excluded by requesting `*`.

## Adjacent indexed-query controls

To investigate the roughly 11% repeated-indexed difference, both ldap-go
revisions were started together from identical 100k snapshot copies. Each
process pair received one untimed-for-summary warm-up batch and eight timed
10,000-query batches per side. The order alternated on every batch; all result
counts were checked and LDIF output matched byte for byte.

There were three process pairs for each of these experiments:

| Experiment | Warm paired batches | Median paired latency change |
| --- | ---: | ---: |
| Before on port 29481, current on 29482 | 24 | +3.7% |
| Same before binary on both ports (A/A control) | 24 | +1.3% |
| Current on 29481, before on 29482 | 24 | -4.6% |
| Both A/B experiments combined | 48 | -0.3% |

The last column is the median of the **individual paired** percentage changes,
not the percentage change between two separately pooled medians. The combined
A/B samples have separate latency medians of 922.5 ms before and 938.5 ms
current. The 48 paired batches come from six process pairs, not 48 independent
process pairs.

A/A paired differences ranged from -22.5% to +20.7%. The sign reversal after
swapping ports does not establish a port-related cause: background load and
process scheduling also changed between experiments. It does prevent treating
the original 11% estimate as a confirmed code regression. Likewise, -0.3% is
not evidence of a real optimization. A quiet dedicated host is needed to
resolve small differences.

## Evidence and reproduction

Compact raw reports are committed under
[`evidence/performance-20260920`](evidence/performance-20260920/): four complete
fresh-run JSON reports, 100k timings/validation, and all paired-control timings.
Full databases, LDIF, logs, binaries, and temporary snapshot/paired drivers are
retained at `/var/tmp/ldap-go-perf-audit-20260920` on the qualification host.
Each completed snapshot/control experiment retains its driver as `driver.sh`.

The temporary snapshot drivers require these retained fixture databases; they
are audit artifacts, not a new general-purpose benchmark entry point. For a
portable fresh-data run, build both revisions with the same Go toolchain and
run the repository script separately for each binary and fresh artifact path:

```sh
CGO_ENABLED=0 \
OPENLDAP_ENV_FILE=/path/to/openldap-reference.env \
QUALIFICATION_COMPARE_BINARY=/path/to/revision-binary \
QUALIFICATION_COMPARE_ARTIFACT_DIR=/path/to/new-run-directory \
QUALIFICATION_COMPARE_ENTRIES=10000 \
QUALIFICATION_COMPARE_PAGE_SIZE=1000 \
QUALIFICATION_COMPARE_INDEXED_SEARCHES=10000 \
QUALIFICATION_COMPARE_UNINDEXED_SEARCHES=20 \
QUALIFICATION_COMPARE_PAGED_TRAVERSALS=5 \
QUALIFICATION_COMPARE_MODIFICATIONS=1000 \
QUALIFICATION_COMPARE_CONCURRENCY=8 \
QUALIFICATION_COMPARE_SEARCHES_PER_CONNECTION=1000 \
  sh scripts/qualification/compare-openldap.sh
```

Binary SHA-256 values:

```text
4fcb185 b8190c13e5bbb161d7b714e3dc5c3a9443d006bdeded08c19121bae303eead24
a101bad 75af05466a61da5e1b958114bc8abcdb99f8517b69c5ebcb8062aa2cae90e37f
```

Source snapshot SHA-256 values:

```text
ldap-go.db bb5471b2388dc99e427b5498544e6da1b1725e0b5e656d94a38270832fb23d1b
data.mdb   b1ee4b3abbebbee46fb91e23b8b1ab257a82d8f69db34a65a9202816e1944d58
```

No production-code optimization was made based on these noisy measurements.
The clearest follow-up targets are the first broad objectClass traversal and
post-workload resident memory, while preserving the verified data results. This
audit does not qualify PBKDF2 Bind, Darwin RWM capture rewriting, TLS/TLCP, replication, complex
ACLs, or every implemented feature's performance. In particular, recent Darwin
RWM capture work adds processing when that feature is enabled; its cost is not
covered by this plain-directory workload.
