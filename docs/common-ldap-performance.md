# Common LDAP performance qualification

September 30, 2026, R7; baseline `fa4d51a`, frozen `current`, 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Common operations have not individually reached parity.** Compare SDK batch
times improve 2.3%-6.4% across true/false results and literal/uppercase root
DNs, but remain 68.0%-70.7% of OpenLDAP performance. Several unrelated rows
are slower, including Modify and ModifyDN in the independent write recheck.
Faster writes do not offset slower reads. The optimization goal stays active.

[R7 evidence](evidence/performance-20260930-r7/README.md) contains the raw
samples and replay scripts. The [R6 report](common-ldap-performance-20260929-r6.md)
is archived verbatim.

## Change and method

Core write DN parsing and Compare entry/self-ACL preparation now reuse the
existing runtime syntax cache. It retains at most 128 entries and 1 MiB, with
1,024-byte input and 32-level depth limits. Only successful syntax parses are
shared. Routing, schema and reader normalization callbacks, entry reads,
error order, matching, and authorization checks still execute as before.
There is no new password, authorization or result cache.

Common tables use three SDK batches; paired root tables use seven. Endpoint
order rotates per request. Only SDK calls are timed; setup, connections,
verification and cleanup are excluded. Medians describe total batch time,
not the median individual request. Relative = `OpenLDAP/current * 100%`, with
100% meaning parity. Time reduction = `(1-current/before) * 100%`, versus
`fa4d51a`; negative means slower. All ratios use unrounded medians. Frequency
is qualitative. Access modes, methods, member counts, variants and independent
rechecks are never pooled.

## Compare

Each row is the median of seven batches of 1,000 SDK operations.

| Root DN spelling | Result | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Literal | True | 126.29 ms | 121.11 ms | 85.64 ms | 70.7% | 4.1% |
| Literal | False | 119.84 ms | 117.14 ms | 81.19 ms | 69.3% | 2.3% |
| Uppercase | True | 130.10 ms | 126.96 ms | 86.39 ms | 68.0% | 2.4% |
| Uppercase | False | 129.17 ms | 120.84 ms | 83.82 ms | 69.4% | 6.4% |

The [complete root table](evidence/performance-20260930-r7/root-tables.md)
also retains root Bind/Base/equality and all negative rows. Root Base is a
fixed container, whereas equality/Compare use distributed users. Untimed
WhoAmI checks make this protocol different from historical serial probes.

## Common operations

The [complete common table](evidence/performance-20260930-r7/common-tables.md)
contains all SSHA/plaintext Bind, wrong-password, hot/distributed reads and
group workloads for default access and explicit ACLs. Default-access snapshot:

| Workload | Typical use | Calls | Current | OpenLDAP | Relative |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 149.18 ms | 119.84 ms | 80.3% |
| Non-root Base, hot | High | 1,000 | 124.55 ms | 101.22 ms | 81.3% |
| Non-root equality, hot | Very high | 1,000 | 129.56 ms | 102.93 ms | 79.4% |
| Direct group discovery | High | 100 | 16.56 ms | 12.34 ms | 74.5% |
| Group Base, 1,000 members | Medium | 100 | 105.72 ms | 96.22 ms | 91.0% |
| Nested membership, client BFS | Medium-high | 100 traversals | 50.05 ms | 39.97 ms | 79.9% |

Default SSHA Bind is 6.8% slower and distributed equality 8.4% slower than
baseline in the original three-repeat run. Independent fresh-process,
seven-repeat rechecks did not reproduce those large regressions:

| Default recheck, 1,000 calls | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| SSHA Bind | 99.63 ms | 98.29 ms | 78.18 ms | 1.3% |
| Plaintext Bind diagnostic | 97.62 ms | 97.38 ms | 79.12 ms | 0.2% |
| Distributed Base | 130.72 ms | 131.32 ms | 98.02 ms | -0.5% |
| Distributed equality | 133.85 ms | 131.94 ms | 99.36 ms | 1.4% |

Rechecks neither replace the original rows nor establish that every regression
is noise. Explicit ACL rules remain:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

## Writes

The original fixed-DN write test uses three fresh processes per endpoint,
20 operations per batch, with verification and cleanup outside SDK timing.

| Operation | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| Add | 16.96 ms | 23.85 ms | 99.91 ms | -40.6% |
| Modify | 8.67 ms | 9.75 ms | 88.64 ms | -12.5% |
| ModifyDN | 29.97 ms | 32.13 ms | 85.67 ms | -7.2% |
| Delete | 20.12 ms | 23.33 ms | 104.74 ms | -15.9% |

These regressions prompted seven alternating before/current process pairs,
100 writes per batch, identical fixture DNs, and no native endpoint:

| Independent write recheck | Before | Current | Time reduction |
| --- | ---: | ---: | ---: |
| Add | 91.79 ms | 89.79 ms | 2.2% |
| Modify | 42.38 ms | 43.60 ms | -2.9% |
| ModifyDN | 134.04 ms | 136.66 ms | -2.0% |
| Delete | 105.24 ms | 102.85 ms | 2.3% |

The larger original regressions are not stable across protocols, but Modify
and ModifyDN remain slower in the recheck medians. No universal speedup or
causal explanation is claimed. Both datasets remain in the evidence archive.

## Component and validation

Compare handler benchmarks use one repeated target or 1,024 rotating targets,
three repetitions and 1s benchtime in both versions, with CPU/memory profiling
enabled equally. No network calls are timed in this component.

| Targets | Before ns/op | Current ns/op | Before B/op | Current B/op | Before allocations | Current allocations |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 21,087 | 14,206 | 15,472 | 12,272 | 357 | 165 |
| 1,024 | 24,909 | 21,283 | 14,566 | 12,926 | 464 | 325 |

Profiles also include fixture setup; their total samples are not query-only.
Component savings do not establish SDK parity. The benchmark verifies
CompareTrue responses outside the timed loop.

Full Go tests passed (server 137.338s), followed by final focused oracle/DN
tests (1.633s), vet and 355 native differential PASS records with no skips or
failures (11.436s). Oracle tests cover cold/warm results, live callbacks and
changing errors, stored spelling, configuration/monitor boundaries, aliases,
multi-AVA DNs and schema changes affecting self-ACL identity. No new fuzz or
race-detector run is claimed in R7.

All six performance scripts passed. **35 exports match** 100,002 entries,
checksum 2143929969 and 42,712,438 canonical bytes: nine common/root, nine
original write, three default recheck and fourteen write recheck exports.
Broad scans and extended fixtures were last measured in
[R4](common-ldap-performance-20260929-r4.md), not rerun here. The
[existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host timings do not establish
deployment performance.

Frozen executable SHA-256:

```text
before (fa4d51a)  4e517908e44d2eeb73635b17322d2be79afa065b112f0d31196ebea34a74d268
current           f3e2c1a6e3f8dcfac6fb20113e97bf3ba3cc07b078a91f8ac3bfbd6b7e16f177
```
