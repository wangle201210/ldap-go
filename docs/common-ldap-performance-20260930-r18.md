# Common LDAP performance qualification

September 30, 2026, R18; production baseline `15f428a` (R17), 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** R18 removes two allocations in the
measured local Simple Bind cases. Network latency observations are mixed;
a universal or reproducible network speedup is not established. Fast writes do not offset
slower common reads.

[R18 evidence](evidence/performance-20260930-r18/README.md) retains all samples,
scripts, counters, source reconstruction material and hashes.
The [R17 report](common-ldap-performance-20260930-r17.md) is archived verbatim.

## Implementation and scope

Ordinary local Simple Bind can reuse the DN and database already selected by
the handler. Qualification happens before the first parse, checks all routing
candidates, and requires the same published schema and known local storage.
Custom normalizers, stores, overlays, controls, SASL and other unsupported
configurations retain the string entry point. Configuration-DN classification
is preserved, including aliases that render as cn=config.

Both entry points join before root authentication. Security checks, ACL and
password-policy behavior, two independent storage Views, final password
verification, error ordering and connection identity updates remain in place.
No password, authentication result or directory entry is cached across Views.
There is no data-format change.

## Method

Hot Bind/Base/equality SDK rows use seven batches of 1,000 operations.
Distributed searches use three batches of 1,000; group searches three batches
of 100. Root operations and group Compare use seven batches of 1,000.
Endpoints rotate per request with identical assertions and verified identities.
There is no root fallback. Setup, connections, verification and cleanup are
outside timing; fixture databases are independent writable APFS COW clones.

Medians describe whole batches, not individual-request median latency.
Relative = `OpenLDAP/current * 100%`; 100% is parity.
Time reduction = `(1-current/before) * 100%`; negatives mean slower.
Unrounded medians determine ratios. Frequency is qualitative.
Use paired versions within the same run when evaluating a code change;
ratios across rounds are not controlled version comparisons.

## Bind results

Each row is seven 1,000-call batches. Plaintext is a diagnostic workload,
not a password-storage recommendation.

| Access | Password | Result | Before | Current | OpenLDAP | Time reduction | Relative |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Default | SSHA | Correct | 89.14 ms | 87.86 ms | 71.44 ms | 1.4% | 81.3% |
| Default | Plaintext | Correct | 93.13 ms | 92.49 ms | 76.26 ms | 0.7% | 82.4% |
| Default | SSHA | Wrong | 88.42 ms | 87.14 ms | 70.23 ms | 1.4% | 80.6% |
| Default | Plaintext | Wrong | 85.13 ms | 83.78 ms | 68.34 ms | 1.6% | 81.6% |
| Explicit ACL | SSHA | Correct | 95.14 ms | 95.27 ms | 76.99 ms | -0.1% | 80.8% |
| Explicit ACL | Plaintext | Correct | 93.68 ms | 94.12 ms | 76.66 ms | -0.5% | 81.4% |
| Explicit ACL | SSHA | Wrong | 93.19 ms | 91.86 ms | 74.23 ms | 1.4% | 80.8% |
| Explicit ACL | Plaintext | Wrong | 91.20 ms | 91.74 ms | 73.26 ms | -0.6% | 79.9% |

The default primary improvements do not reproduce uniformly in the independent
startup-order/port swap. All negative observations remain in the evidence.

## Common operations

All rows were rerun for R18; the table keeps access modes separate.

| Workload | Typical use | Calls | Current, default | OpenLDAP, default | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 87.86 ms | 71.44 ms | 81.3% | 80.8% |
| Non-root Base, hot | High | 1,000 | 106.55 ms | 87.26 ms | 81.9% | 79.6% |
| Non-root equality, hot | Very high | 1,000 | 109.48 ms | 88.75 ms | 81.1% | 78.0% |
| Direct group discovery | High | 100 | 14.91 ms | 11.50 ms | 77.1% | 74.6% |
| Group Base, 1,000 members | Medium | 100 | 97.10 ms | 88.62 ms | 91.3% | 94.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 45.57 ms | 37.91 ms | 83.2% | 80.1% |

Default large-group Base is 3.6% slower than the paired baseline. Direct group
discovery and nested membership are each 0.4% slower. Explicit hot Base is
0.4% slower. These observations are retained without a causal explanation.
Full group Compare, distributed, root and concurrent results are in evidence.
ACL configuration is unchanged:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

## Calibration

The default-access A/A and startup-order/port-swap runs were fixed in advance
at seven 1,000-call batches for the four Bind workloads.

A/A uses the exact same candidate executable for both Go endpoint labels.
The label current is 0.6%, 0.6% and 1.3% slower for correct SSHA, correct
plaintext and wrong SSHA, while wrong plaintext is 0.6% faster.

In the real A/B swap, current starts first on port 29481 and before second on
29482. Correct SSHA/plaintext are 1.3%/0.7% slower; wrong SSHA/plaintext are
0.6%/0.8% faster. This limits any claim of a general network latency benefit.
Changing both order and port does not isolate either cause.

These runs remain separate from primary statistics and do not replace or
correct any original result. No statistical-significance claim is made.

## Component results

The same portable BenchmarkHandleSimpleBind source runs against frozen R17
and candidate test executables. It calls the actual handler with fixed SSHA
fixtures, checks every warmup response/identity, and checks the final result.
Setup and checks are outside b.Loop. The rotating set contains 256 users.

Primary components use three unprofiled 500ms repetitions:

| Targets | Password | Before ns/op | Current ns/op | Before B/op | Current B/op | Before/current allocations |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Hot user | Correct | 12,197 | 11,613 | 10,392 | 10,320 | 144 / 142 |
| Hot user | Wrong | 11,721 | 11,732 | 10,296 | 10,224 | 141 / 139 |
| 256 users | Correct | 18,740 | 18,611 | 11,396 | 11,325 | 275 / 273 |
| 256 users | Wrong | 17,946 | 18,477 | 11,300 | 11,228 | 272 / 270 |

The independently rounded B/op medians differ by 71 bytes for rotating correct
Bind; other rows show 72 bytes. All four cases remove two allocations.
Wrong-password medians are slower in the primary pair and remain in the table.

A separate fixed five-round calibration alternates executable order, using
500ms per case. Before/current ns/op medians are 12,136/12,027,
12,091/12,011, 18,593/18,542 and 18,470/18,354 in table order:
reductions of 0.9%, 0.7%, 0.3% and 0.6%. Raw outliers remain.
These medians are not pooled with or substituted for the primary components.
The earlier same-candidate reuse/string diagnostics and isolated prototype
observations are also separate; they are not frozen old-version comparisons.

## Validation and limits

Full tests passed (server 139.182s, webadmin 0.272s), as did vet and
native differential validation (355 PASS records, 10.074s).
Real 100k default/explicit fixture tests prove eligibility without altering
runtime guards, DN/database equivalence, successful/wrong/repeated login
response and identity parity, and unchanged storage revisions. They modify
only temporary database copies. No fresh fuzz or race-detector run is claimed.

All five primary and both network calibration scripts passed.
**21 exports match**: 15 primary and six calibration exports, each with
100,002 entries, cksum 2143929969 and 42,712,438 canonical bytes.
Historical R8b broad scans/writes were not rerun. The
[existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. No complete OpenLDAP compatibility,
universal speedup or deployment-performance guarantee is claimed.
The optimization goal remains active.

Frozen production executable SHA-256:

```text
before  7dd5d031ee6b9ffbdacfc9e302f1fd9626de90fe9d1359486808ff97d5699ab3
current 5546307a886f3b507e8f418eebeab0e020d074a1a49cea476fc66f657c3c6370
```

Evidence preserves actual embedded build metadata, source hashes and the
baseline-relative source reconstruction. Reused binaries are not presented
as clean builds of subsequently committed source revisions.
