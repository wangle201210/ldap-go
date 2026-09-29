# Common LDAP performance qualification

September 30, 2026, R13; baseline `eced1dc` (R12), 100,000 users, Apple M1 Pro,
Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** All measured non-root group Compare
cells improve 9.0%-20.3%. First-member Compare on 1,000-member groups reaches
79.1%-80.1% of native performance; last/missing cases reach 50.2%-56.4%.
Ordinary-operation negatives remain and are not offset by these gains.

[R13 evidence](evidence/performance-20260930-r13/README.md) retains all samples,
counters, scripts and checks. [R12](common-ldap-performance-20260930-r12.md) is
archived verbatim. Historical R8b broad scans/writes were not rerun.

## Implementation

The server opts into the existing bounded DN normalization cache when validating
Compare assertions and comparing entry DN values. Assertion syntax and length
are still checked on every request. ACL, assertion controls, referral handling,
attribute presence and first-error ordering remain in place. No authorization
or Compare result is cached.

`CompareEntryAttribute` retains its uncached behavior; the new explicit
`CompareEntryAttributeCachedDN` shares `NormalizeDNCached`'s immutable-schema
contract and bounds: at most 128 entries and 1 MiB, 1,024-byte inputs and depth
32. Registry mutation APIs invalidate normalization. Failed normalizations are
not cached. Published runtime schemas use this contract; callers that directly
edit shared schema slices must retain the uncached API. Other comparison rules
and ordered values preserve their existing paths.

## Method

Common SDK rows use three batches; paired root rows use seven. Non-root group
Compare uses five batches of 20 calls with per-request endpoint rotation and
the same group/assertion DN on every endpoint. Bind/WhoAmI verification, setup,
connection and cleanup remain outside timed SDK calls. First/last means fixture
order, not an assumption about native storage order. There is no root fallback.

Medians describe whole-batch time. Frequency is qualitative. Relative =
`OpenLDAP/current * 100%`, with 100% parity. Time reduction =
`(1-current/before) * 100%`; negative means slower. Ratios use unrounded medians.
Methods, access modes, sizes, variants and independent rechecks remain separate.

## Group Compare

Default access, 20 calls per batch; typical use is medium and application-dependent.

| Members | Assertion | Before | Current | OpenLDAP | Relative | Time reduction |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10 | First fixture member | 2.40 ms | 1.91 ms | 1.52 ms | 79.7% | 20.3% |
| 10 | Last fixture member | 2.17 ms | 1.82 ms | 1.53 ms | 84.1% | 15.9% |
| 10 | Missing member | 2.23 ms | 1.89 ms | 1.52 ms | 80.1% | 15.0% |
| 1,000 | First fixture member | 2.50 ms | 2.28 ms | 1.80 ms | 79.1% | 9.0% |
| 1,000 | Last fixture member | 3.49 ms | 3.15 ms | 1.58 ms | 50.2% | 9.6% |
| 1,000 | Missing member | 3.53 ms | 3.04 ms | 1.55 ms | 51.0% | 13.9% |

Explicit ACL 1,000-member first/last/missing cases change from
2.605/4.320/3.854 ms to 2.127/3.829/3.301 ms, versus native
1.704/2.161/1.850 ms. Time reductions are 18.3%/11.4%/14.3%; relative performance
is 80.1%/56.4%/56.0%. The remaining native gap is still material.

## Common operations

Default-access snapshot; complete explicit/default/root rows remain in evidence.

| Workload | Typical use | Calls | Current | OpenLDAP | Relative |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 101.95 ms | 87.45 ms | 85.8% |
| Non-root Base, hot | High | 1,000 | 108.59 ms | 86.53 ms | 79.7% |
| Non-root equality, hot | Very high | 1,000 | 126.23 ms | 101.04 ms | 80.0% |
| Direct group discovery | High | 100 | 15.40 ms | 11.52 ms | 74.8% |
| Group Base, 1,000 members | Medium | 100 | 97.24 ms | 91.08 ms | 93.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 49.81 ms | 40.51 ms | 81.3% |

Default SSHA Bind is 5.6% slower in the original run. Explicit large-group Base
is 4.1% slower, direct group discovery 2.6% slower and distributed equality 2.0%
slower. All negative rows remain; these variations are not assigned a causal
explanation. Explicit ACL rules are unchanged:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

The independent default Bind recheck uses fresh endpoints and seven batches of
1,000 calls, without replacing the original samples:

| Recheck | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: |
| SSHA Bind | 101.59 ms | 102.92 ms | 81.63 ms | -1.3% |
| Plaintext Bind diagnostic | 98.46 ms | 97.37 ms | 79.27 ms | 1.1% |

The larger SSHA slowdown did not recur, but its recheck remains slower. No
universal gain or aggregate parity is claimed.

## Component and validation

The realistic root group handler fixture includes stored operational attributes.
Three unprofiled 500ms repetitions, before/current medians:

| 1,000-member case | ns/op | B/op | Allocations/op |
| --- | ---: | ---: | ---: |
| First | 41,685 / 24,602 | 89,568 / 82,456 | 423 / 102 |
| Last | 107,416 / 85,546 | 89,648 / 82,536 | 427 / 106 |
| Missing | 94,094 / 75,189 | 89,608 / 82,624 | 428 / 111 |

The exploratory first-member CPU/memory profile includes fixture setup and GC;
it is not a timing pair or a whole-process memory claim. The component fixture
is repeated, so the cache is warm during its measured loop. Live SDK tables
provide separate behavior and latency evidence.

Full Go tests passed (server 138.392s, webadmin 0.338s), vet and native
differential validation (355 PASS records, no failures/skips, 10.247s). Final
cache-specific checks passed (schema 0.076s, server 0.055s) after tests were
frozen. They cover cold/warm oracle parity, input reuse, failures, schema
mutation, limits, unchanged default behavior and validation after cache warmup.
No new fuzz or race-detector run is claimed in R13.

All six performance scripts passed. **18 exports match** 100,002 entries,
cksum 2143929969 and 42,712,438 canonical bytes: 15 original plus three Bind
recheck exports. The [existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host results do not establish
deployment performance. The optimization goal remains active.

Frozen executable SHA-256:

```text
before (eced1dc)  6d0b5a6cdfe26121ab9a3785beccb517264b35aa7b0ef3baa84d4a09eb7d1184
current           96937b2ddf7bce78eccf7ee728880e5eb68fa560d41df0dcbf2517afa13ad751
```
