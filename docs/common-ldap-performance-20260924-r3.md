# Common LDAP performance qualification

September 24, 2026, third run: baseline `a7c2941`, OpenLDAP 2.6.13,
100,000 users, Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`.

Against the baseline in this run, direct group discovery takes **35.1%-42.3%
less time**, client-side nested membership 17.1%-19.7% less, and SSHA Bind
5.6%-7.1% less. Ordinary user Base/equality queries change little.
**The OpenLDAP parity goal remains unmet.**

The [second run](common-ldap-performance-20260924-r2.md) and
[first run](common-ldap-performance-20260924-r1.md) retain previous evidence.
Compare implementations within a run; shared-host timing varies across runs.

## Changes

- An opt-in equality evaluator reuses bounded DN normalization for
  `distinguishedNameMatch`. Runtime schemas meet its immutability contract;
  public uncached evaluation remains available. The cache retains at most
  128 successful inputs, 1 KiB input strings, depth 32 and an estimated 1 MiB.
  Registry mutations invalidate it. Invalid values and three-valued filter
  semantics, ordered values and other matching rules retain their prior behavior.
- Qualified unpaged local searches borrow candidate data until their callback
  completes, then copy selected output. ACL checks still run. Controls, sorting,
  sync, collective sources, unsafe overlays and custom callbacks retain the
  general path. No authorization or search result is cached for non-root users.
- Read-only candidate decoding supports small candidate sets and a lazily grown,
  bounded arena of up to 4,096 value descriptors. Larger shapes, legacy paths,
  corruption and unsupported encodings retain owned decoding. A single encoded
  row below 8 KiB uses owned decoding to avoid the arena overhead.
- Idle simple LDAPv3 Bind runs on the reader goroutine after an atomic queue
  claim. It shares the full operation lifecycle with workers, preserving
  admission, audit, monitor, identity changes, transaction handling, response
  failures and shutdown. Busy queues and SASL Bind remain queued.
- ACL evaluation reuses a sole database/global rule slice instead of allocating
  a concatenation. Combined rule sets retain their original order and copy.

Password algorithms, work factors and authentication snapshot checks are unchanged.

## Measurement

The [SDK runner](../internal/cmd/ldapcommonbench/README.md) rotates endpoints per
request and validates exact responses, identities and fixture cleanup. Only SDK
Bind/Search calls are timed. Tables are medians of three batches on one warmed
process per implementation, with no measured outliers discarded.

Both endpoints have uid/member/objectClass equality indexes. Source data contains
100,000 users and two containers. Temporary groups contain 10 or 1,000 real user
DNs. Distributed queries sample 1,000 users across the 100k range. Nested membership
uses the same client BFS, including a cycle, on every endpoint.

Transport is plaintext loopback LDAP; headline Bind uses SSHA. Plaintext password
storage is a separate diagnostic in the raw reports. TLS and stronger password
schemes require separate equivalent measurement.

Relative performance is `OpenLDAP / current * 100%`: higher is better, 100% is
parity. Time reduction is `(1 - current / before) * 100%`; negative means a slower
observed median. Usage frequency is qualitative for authentication/company
directories, not measured traffic; caching and connection pooling change it.

## Explicit ACL

Both servers use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 105.00 ms | 97.52 ms | 71.73 ms | 73.6% | 7.1% |
| Wrong password, SSHA | Low | 1,000 | 102.53 ms | 94.87 ms | 70.15 ms | 73.9% | 7.5% |
| Non-root Base, hot | High | 1,000 | 123.49 ms | 121.47 ms | 79.07 ms | 65.1% | 1.6% |
| Non-root equality, hot | Very high | 1,000 | 122.42 ms | 121.90 ms | 80.97 ms | 66.4% | 0.4% |
| Non-root Base, distributed | High | 1,000 | 141.70 ms | 138.36 ms | 81.77 ms | 59.1% | 2.4% |
| Non-root equality, distributed | Very high | 1,000 | 138.82 ms | 137.50 ms | 88.54 ms | 64.4% | 0.9% |
| Direct group discovery | High | 100 | 34.22 ms | 22.20 ms | 11.79 ms | 53.1% | 35.1% |
| Group Base, 10 members | Medium | 100 | 15.81 ms | 15.51 ms | 9.46 ms | 61.0% | 1.9% |
| Group Base, 1,000 members | Medium | 100 | 97.55 ms | 106.38 ms | 89.57 ms | 84.2% | -9.1% |
| Nested membership, client BFS | Medium-high | 100 traversals | 84.22 ms | 67.61 ms | 41.00 ms | 60.6% | 19.7% |

[Hot samples](evidence/common-performance-20260924-r3/explicit-hot.json),
[distributed samples](evidence/common-performance-20260924-r3/explicit-distributed.json),
[group samples](evidence/common-performance-20260924-r3/explicit-groups.json).

The first three-batch 1,000-member Base result was 9.1% slower. A dedicated
five-batch recheck with 500 calls per batch did not reproduce that slowdown:

| Group size | Calls | Before | Current | OpenLDAP | Relative |
| --- | ---: | ---: | ---: | ---: | ---: |
| 10 | 500 | 77.93 ms | 76.56 ms | 47.99 ms | 62.7% |
| 1,000 | 500 | 489.80 ms | 488.88 ms | 424.74 ms | 86.9% |

All first-run samples remain above; the recheck does not replace them selectively.
No speedup is claimed for large-group Base reads.
[Recheck samples](evidence/common-performance-20260924-r3/explicit-group-recheck.json),
[replay](evidence/common-performance-20260924-r3/explicit-group-recheck.sh.txt).

## Default access

No explicit ACL rules; the earlier default-projection shortcut remains in use.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 102.78 ms | 97.00 ms | 73.34 ms | 75.6% | 5.6% |
| Wrong password, SSHA | Low | 1,000 | 99.33 ms | 93.20 ms | 69.75 ms | 74.8% | 6.2% |
| Non-root Base, hot | High | 1,000 | 109.85 ms | 109.04 ms | 77.97 ms | 71.5% | 0.7% |
| Non-root equality, hot | Very high | 1,000 | 113.33 ms | 113.73 ms | 82.29 ms | 72.4% | -0.4% |
| Non-root Base, distributed | High | 1,000 | 130.98 ms | 131.08 ms | 80.97 ms | 61.8% | -0.1% |
| Non-root equality, distributed | Very high | 1,000 | 150.34 ms | 148.61 ms | 96.95 ms | 65.2% | 1.1% |
| Direct group discovery | High | 100 | 32.50 ms | 18.76 ms | 10.94 ms | 58.3% | 42.3% |
| Group Base, 10 members | Medium | 100 | 13.76 ms | 13.73 ms | 9.53 ms | 69.4% | 0.2% |
| Group Base, 1,000 members | Medium | 100 | 95.74 ms | 95.20 ms | 85.52 ms | 89.8% | 0.6% |
| Nested membership, client BFS | Medium-high | 100 traversals | 74.28 ms | 61.55 ms | 39.45 ms | 64.1% | 17.1% |

[Hot samples](evidence/common-performance-20260924-r3/default-hot.json),
[distributed samples](evidence/common-performance-20260924-r3/default-distributed.json),
[group samples](evidence/common-performance-20260924-r3/default-groups.json).

The very small changes in ordinary user queries do not establish a general
speedup or regression. Direct group discovery remains the largest relative gap.

## Concurrent check

Eight independent root-bound clients each issue 1,000 indexed uid searches.
This separate CLI wall-clock test includes startup/Bind, one excluded warmup
batch and three measured batches with rotated endpoint order. Every returned UID
and result count is checked. It does not establish non-root concurrent throughput.

| Access configuration | Before | Current | OpenLDAP | Relative |
| --- | ---: | ---: | ---: | ---: |
| Default | 190 ms | 188 ms | 213 ms | 113.3% |
| Explicit ACL | 194 ms | 193 ms | 211 ms | 109.3% |

No concurrent speedup is claimed from these small baseline/current differences.
[Default batches](evidence/common-performance-20260924-r3/default-concurrent.tsv),
[explicit batches](evidence/common-performance-20260924-r3/explicit-concurrent.tsv).

## Validation

- [Full Go tests](evidence/common-performance-20260924-r3/go-test-accepted.txt) and [vet](evidence/common-performance-20260924-r3/go-vet-accepted.txt)
  pass with `CGO_ENABLED=0`; no race detector was used.
- [355 native PASS records, including subtests](evidence/common-performance-20260924-r3/openldap-differential.txt)
  pass. The selection includes ACL, DN identity, paging, sync, transactions,
  controls, password policies and the 144-case value-batching matrix.
- New equality tests compare the original evaluator and composed filters,
  invalid/missing values, aliases/options/subtypes, schema updates, bounds,
  ownership and concurrent use.
- New storage/server tests compare owned and borrowed results, error order,
  cancellation, custom callbacks, 1,000 -> 105 -> 1,003 -> 106 member layouts,
  raw storage bytes, output after update/unmap, and memory/candidate/size limits.
  The adaptive decoder's [focused checks](evidence/common-performance-20260924-r3/adaptive-decoder-tests-final.txt)
  and [server checks](evidence/common-performance-20260924-r3/readonly-search-tests.txt) also pass.
- New Bind tests cover idle claims, busy/fenced queues, global/per-connection
  admission, pipelined rebinds, failed/anonymous identity changes, audit/monitor
  accounting, prior-operation abandonment, transactions, write failure and shutdown.
- All nine full ordinary-attribute exports after cleanup match the source:
  100,002 entries, 42,712,438 canonical bytes, POSIX checksum `2143929969`.
  [Default](evidence/common-performance-20260924-r3/default-validation.tsv),
  [explicit](evidence/common-performance-20260924-r3/explicit-validation.tsv),
  [recheck](evidence/common-performance-20260924-r3/explicit-recheck-validation.tsv).

Component evidence:
[DN equality](evidence/common-performance-20260924-r3/dn-equality-bench.txt),
[group candidate projection](evidence/common-performance-20260924-r3/group-candidates-bench.txt),
[tiny candidates before adaptation](evidence/common-performance-20260924-r3/tiny-candidates-bench.txt),
[tiny candidates after adaptation](evidence/common-performance-20260924-r3/tiny-candidates-bench-final.txt),
[ACL rule selection](evidence/common-performance-20260924-r3/acl-rules-bench.txt).
Three 1,000-member groups projected to cn allocate about 207 KB through owned
decoding versus 42 KB through read-only decoding. Single tiny candidates initially
regressed from about 6.0 to 7.2 microseconds and allocated 9,981 rather than 4,306
bytes; adaptation brings them to about 6.1 microseconds and 4,170 bytes.
These are component timings, not end-to-end speedup multipliers.

### Existing operational-attribute gap

This round does not implement missing synthesized `entryDN` or
`hasSubordinates` in the ordinary memory-store fixture. The
[previous expanded differential](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
records the same 40 failures before and after that round's optimization.
Those cases are not included in the passing native matrix or a full compatibility claim.

## Replay

Local root: `/var/tmp/ldap-go-common-perf-20260924-r3`.
[Default replay](evidence/common-performance-20260924-r3/default-replay.sh.txt) and
[explicit replay](evidence/common-performance-20260924-r3/explicit-replay.sh.txt) retain setup, assertions, exports
and cleanup. Paths refer to disposable copies of the existing 100k fixture and
the pinned native installation; adjust them before running elsewhere.
Tests/builds did not run concurrently with timed benchmarks. Temporary servers
were stopped and source snapshots were unchanged.

Executable SHA-256:

```text
before  12e88eae35f7ed42e478e0f758c93f48721a47754e10a5fc983d05a35838a214
current c73d07d1e70afc60030999f9fe001b1b420cfd88dc9fa92dcb4e4dd6a8fec258
```

Non-root concurrent throughput, additional policies, TLS and larger group
populations remain qualification work. Older write/paging/memory measurements
remain in the [full-operation report](performance-optimization-20260923-round13.md);
they were not remeasured in this round.
