# Common LDAP performance qualification

September 29-30, 2026, R6; baseline `45c8e5d`, frozen `current`, 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** Direct group discovery improves 2.7%
with explicit ACLs and 6.4% with default access, but several operations remain
slower than both the baseline and OpenLDAP. Faster writes do not offset slower
reads. The optimization goal remains active.

The [R4 archive](common-ldap-performance-20260929-r4.md) preserves the previous
report verbatim. [R6 evidence index](evidence/performance-20260929-r6/README.md).

## Change and method

Simple Search requests with a leaf equality/presence filter and no controls
now use the existing definite-length parser for minimally encoded long BER
lengths. Other shapes retain the packet decoder. Frame limits, filter-depth
provider calls, error behavior and owned request fields are preserved.
Group Base, direct membership and nested BFS requests exercise this change;
scale-pool Base/equality requests already used the short fast path.

Common rows are medians of three `total_ms` batches with per-request endpoint
rotation. Only SDK calls are timed; setup, connections, verification and cleanup
are excluded. Frequency is qualitative. Relative = `OpenLDAP/current * 100%`;
100% is parity. Time reduction = `(1-current/before) * 100%`; negative means
slower than `45c8e5d`. Ratios use unrounded medians. Methods, access modes,
member counts, hot/distributed reads and independent rechecks are never pooled.

## Common operations

The [complete comparison table](evidence/performance-20260929-r6/common-tables.md)
contains all 24 operation rows: SSHA/plaintext Bind, wrong-password requests,
hot/distributed Base and equality, 10/1,000-member groups and nested membership,
under both access modes. [All 72 endpoint medians](evidence/performance-20260929-r6/medians.tsv)
and complete per-request samples remain available.

This snapshot uses default access. Times are whole-batch milliseconds.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 111.62 | 112.53 | 92.17 | 81.9% | -0.8% |
| Non-root Base, hot | High | 1,000 | 116.31 | 116.65 | 94.02 | 80.6% | -0.3% |
| Non-root equality, hot | Very high | 1,000 | 120.76 | 121.35 | 94.36 | 77.8% | -0.5% |
| Non-root Base, distributed | High | 1,000 | 134.16 | 143.99 | 97.43 | 67.7% | -7.3% |
| Non-root equality, distributed | Very high | 1,000 | 151.36 | 168.85 | 110.86 | 65.7% | -11.6% |
| Direct group discovery | High | 100 | 20.24 | 18.93 | 16.05 | 84.8% | 6.4% |
| Group Base, 10 members | Medium | 100 | 17.61 | 16.02 | 12.56 | 78.4% | 9.0% |
| Group Base, 1,000 members | Medium | 100 | 105.10 | 108.42 | 100.62 | 92.8% | -3.2% |
| Nested membership, client BFS | Medium-high | 100 traversals | 57.55 | 57.20 | 44.32 | 77.5% | 0.6% |

Explicit ACL rules remain:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

Under explicit ACLs, direct group discovery improves 2.7%, 10-member group Base
4.9%, and nested membership 5.3%; 1,000-member group Base is 7.5% slower.
All explicit rows, including every negative result, are in the complete table.

## Independent rechecks

Negative rows prompted fresh-process, seven-repeat rechecks with the same
initial data. They do not replace the original three-repeat results.

| Workload | Calls per batch | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL, 1,000-member group | 100 | 102.18 ms | 101.56 ms | 93.85 ms | 0.6% |
| Default, 1,000-member group | 100 | 102.26 ms | 104.21 ms | 92.91 ms | -1.9% |
| Default, distributed Base | 1,000 | 132.39 ms | 129.22 ms | 96.36 ms | 2.4% |
| Default, distributed equality | 1,000 | 134.31 ms | 133.91 ms | 100.76 ms | 0.3% |

The larger distributed regressions and explicit-ACL group regression did not
recur; default group Base remains slower in its recheck median. This does not
establish that every regression is noise or that every operation improves.
[Group rechecks](evidence/performance-20260929-r6/groups-recheck-tables.md),
[distributed rechecks](evidence/performance-20260929-r6/distributed-recheck-tables.md).

[Paired root results](evidence/performance-20260929-r6/root-paired-tables.md)
retain seven repeats for literal and uppercase root DNs. Compare remains
60.5%-68.4% of OpenLDAP in this run. Concurrent CLI results remain separate in
[their medians](evidence/performance-20260929-r6/concurrent-medians.tsv).

## Validation and limits

The existing long-request component changes from **7,019 to 392.4 ns/op**,
14,968 to 968 B/op and 214 to 12 allocations. Already-fast short equality and
presence medians are 4.2% and 4.9% slower; all cases remain in the
[component tables](evidence/performance-20260929-r6/decode-tables.md).
Both runs use five repetitions, but baseline benchtime is 1s and current 500ms.
New group fixtures compare against the packet reference, not the old binary.
Component gains do not prove whole-request parity.

Full Go tests and vet passed; native differential validation has 355 PASS
records, no failures/skips. Differential fuzzing completed 1,721,970 executions.
All five performance scripts passed. **All 15 exports match** 100,002 entries,
checksum 2143929969 and 42,712,438 canonical bytes. An initial test-fixture
expectation error and its correction are retained in the evidence archive.
No race-detector result is claimed; Go builds and checks use `CGO_ENABLED=0`.

Broad scans, fixed writes, extended fixtures and RSS were last measured in
[R4](common-ldap-performance-20260929-r4.md); they were not rerun or pooled into
R6. The [existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host results do not establish
causality or deployment performance.

Frozen executable SHA-256:

```text
before (45c8e5d)  8551a06409eba3aeff3225748836fc5483c6ec778a207517b025a0df27b279ce
current           4e517908e44d2eeb73635b17322d2be79afa065b112f0d31196ebea34a74d268
```
