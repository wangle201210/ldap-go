# Common LDAP performance qualification

September 30, 2026, R8b; baseline `2645eba`, frozen `current`, 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** Internal object-class checks and Compare
components allocate less, but common SDK latency remains mixed. Faster writes
or warmed paging do not offset slower login/read operations. Negative rows and
independent rechecks are retained; the optimization goal stays active.

[R8b evidence](evidence/performance-20260930-r8b/README.md) contains all raw
samples, grouped medians and scripts. The [R7 report](common-ldap-performance-20260930-r7.md)
is archived verbatim. [R8](evidence/performance-20260930-r8/README.md) is a
separate, superseded candidate investigation, not final-version evidence.

## Change and method

Object-class checks read entry values directly instead of cloning a list for
read-only comparison. They reuse an already-prepared attribute-name table when
available; a miss does not build a table or attempt an empty-table lookup.
Schema locking, invalidation, inheritance, aliases and option behavior remain.
Identical attribute descriptions also avoid redundant parsing and lookups.
No new cache, authorization shortcut or storage-format change is introduced.

Common SDK rows use medians of three batches with per-request endpoint rotation.
Paired root rows use seven batches for literal and uppercase root DNs. Only SDK
calls are timed; setup, connections, verification and cleanup are excluded.
CLI batches include process startup and output. Medians describe whole-batch
time, not the median individual request. Frequency is qualitative.

Relative = `OpenLDAP/current * 100%`, with 100% meaning parity. Time reduction =
`(1-current/before) * 100%`, versus `2645eba`; negative means slower. Ratios use
unrounded medians. Different methods, access modes, member counts, variants,
rounds and independent rechecks are never pooled.

## Common operations

Default-access snapshot; all explicit/default rows remain in the evidence.

| Workload | Typical use | Calls | Current | OpenLDAP | Relative |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 91.42 ms | 73.11 ms | 80.0% |
| Non-root Base, hot | High | 1,000 | 114.02 ms | 92.36 ms | 81.0% |
| Non-root equality, hot | Very high | 1,000 | 119.22 ms | 93.10 ms | 78.1% |
| Direct group discovery | High | 100 | 14.87 ms | 11.90 ms | 80.0% |
| Group Base, 1,000 members | Medium | 100 | 97.25 ms | 89.19 ms | 91.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 49.14 ms | 40.02 ms | 81.4% |

Default SSHA Bind and direct group discovery improve 2.4%/2.9%, while hot
equality is 2.4% slower and nested membership 1.9% slower. Explicit 10-member
group Base improves 4.7%; explicit nested membership is 1.3% slower. Paired
root Compare remains essentially unchanged (-0.2% to +0.1% time reduction),
at 70.7%-73.4% of native performance. Component gains do not establish SDK gains.

Explicit ACL rules remain:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

## Broader reads

Original CLI results use three fresh processes per endpoint. Full-prefix scans
have three batches per process; the other rows have one. RSS, serial SDK probes,
uppercase-root, long-DN and long-password probes remain separately grouped in
the evidence. No earlier-round samples are reused.

| CLI workload | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| Full prefix, 100k entries | 750 ms | 820 ms | 723 ms | -9.3% |
| Indexed equality, 10k requests | 973 ms | 876 ms | 822 ms | 10.0% |
| Concurrent, 8 x 1k requests | 408 ms | 313 ms | 376 ms | 23.3% |
| Paging, 2 x 100k entries | 1664 ms | 1677 ms | 1411 ms | -0.8% |
| Unindexed negative, 10 requests | 257 ms | 247 ms | 391 ms | 3.9% |

Independent paging/prefix rechecks use fresh processes, rotating endpoint order,
one warmup batch and seven measured batches. They exclude the original extended
fixture history and do not replace original results. Warmup records remain raw.

| Independent CLI recheck | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| Paging, 2 x 100k | 1235 ms | 1187 ms | 1475 ms | 3.9% |
| Full prefix, 100k | 747 ms | 722 ms | 645 ms | 3.3% |

The original prefix slowdown did not recur in this warmed protocol. Paging's
initial warmup batch is 1928/1769/1497 ms (before/current/native), separate from
measured medians. These data do not prove that all variability is unrelated to
code or that every cold/warm workload improves.

## Writes

Original fixed-DN writes use three fresh processes per endpoint and 20
operations per batch. Verification and cleanup remain outside SDK timing.

| Operation | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| Add | 16.80 ms | 18.14 ms | 95.48 ms | -8.0% |
| Modify | 7.90 ms | 8.89 ms | 93.97 ms | -12.5% |
| ModifyDN | 24.56 ms | 26.25 ms | 92.45 ms | -6.9% |
| Delete | 23.66 ms | 19.90 ms | 94.09 ms | 15.9% |

The negative rows prompted seven alternating before/current process pairs,
100 writes per batch, identical fixture DNs, and no native endpoint:

| Independent write recheck | Before | Current | Time reduction |
| --- | ---: | ---: | ---: |
| Add | 95.00 ms | 96.57 ms | -1.7% |
| Modify | 45.33 ms | 41.28 ms | 8.9% |
| ModifyDN | 135.15 ms | 137.65 ms | -1.9% |
| Delete | 109.67 ms | 109.92 ms | -0.2% |

Larger original regressions are not stable across protocols, but Add, ModifyDN
and Delete remain slower in the recheck medians. No universal speedup is claimed.

## Component and validation

Compare handler benchmarks use one repeated target or 1,024 rotating targets,
three repetitions and 1s benchtime, without profiling or network traffic.
Current ran before the fresh immutable baseline test binary in this round.

| Targets | Before ns/op | Current ns/op | Before B/op | Current B/op | Before allocations | Current allocations |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 14,590 | 12,710 | 12,272 | 11,768 | 165 | 149 |
| 1,024 | 22,005 | 19,988 | 12,926 | 12,422 | 325 | 309 |

Object-class component benchmarks separately retain original, cloning-only,
prepared and cold-fallback modes (300ms x 3). Direct-class match changes from
1521 ns/488 B/25 allocations to 230.4 ns/0 B/0 with preparation, or
777.4 ns/160 B/10 without it. Unknown-target medians remain approximately
19 ns, including slightly slower results. The component is not an SDK estimate.

Final full Go tests passed (server 133.720s), as did schema tests (1.540s), vet
and native differential validation (355 PASS records, no failures/skips,
10.219s). Tests cover original-implementation equivalence, inheritance cycles,
aliases, options, Unicode, nil/empty values, schema mutation, cold/prepared
paths and unchanged input data. No new fuzz or race-detector run is claimed.

All eight performance scripts passed. **47 final-version exports match**
100,002 entries, cksum 2143929969 and 42,712,438 canonical bytes: 27 original,
three paging recheck, three prefix recheck and fourteen write recheck exports.
R8's 50 diagnostic exports are not included. The
[existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host timings do not establish
causality or deployment performance.

Frozen executable SHA-256:

```text
before (2645eba)  f3e2c1a6e3f8dcfac6fb20113e97bf3ba3cc07b078a91f8ac3bfbd6b7e16f177
current           abaeae2a3ebbe3695e70897c52495b00a1f5594a9d34df4be4570df81fda54df
```
