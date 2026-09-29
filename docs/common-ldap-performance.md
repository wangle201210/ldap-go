# Common LDAP performance qualification

September 30, 2026, R12; baseline `31f3c08` (R10), 100,000 users, Apple M1 Pro,
Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** Late/missing member Compare on the
measured 1,000-member groups improves 34%-39%, reaching about 45%-49% of native
performance. First-member comparisons have negative results that remain visible.
No aggregate score offsets slower operations.

[R12 evidence](evidence/performance-20260930-r12/README.md) contains the raw
results, counters and replay scripts. [R10](common-ldap-performance-20260930-r10.md)
is archived verbatim. [R11](evidence/performance-20260930-r11/README.md) is a
withdrawn diagnostic candidate, not a shipped optimization or R12 evidence.

## Change and scope

After a simple DN has been fully validated and compared, the request-local plan
can retain its raw suffix after the first comma in an owned 512-byte buffer.
An exact suffix hit validates and compares the first RDN, reusing the already
established suffix result. Changed, oversized or unsupported suffixes use the
full R10 path. The suffix is copied only after all types and syntax are checked;
an earlier mismatch cannot hide a later invalid attribute.

The plan never survives the request. Schema locking, ACL checks, errors,
attribute presence and input ownership remain unchanged. R10's eligibility
limits remain: up to eight single-AVA RDNs, simple ASCII values and supported
case-ignore/exact rules. This does not accelerate every DN shape and introduces
no persistent cache, storage format or authorization shortcut.

The rejected R11 proposal compacted a clone in `withSubschemaReference`.
Normal LDAP Add already stores `subschemaSubentry`, so ordinary SDK fixtures
bypass that branch. Its component improvement did not justify attributing
ordinary-request gains to it. The candidate was withdrawn. The realistic group
handler benchmark now includes operational attributes to avoid that mismatch.

## Method

Common SDK rows use three batches; paired root rows use seven. Non-root group
Compare uses five batches of 20 calls, rotating endpoints per request. All
endpoints receive the same fixture/assertion DN; WhoAmI checks, setup, connections,
verification and cleanup stay outside timing. First/last denotes fixture order,
not native storage order. There is no root fallback.

Medians describe whole-batch duration. Frequency is qualitative. Relative =
`OpenLDAP/current * 100%`, with 100% meaning parity. Time reduction =
`(1-current/before) * 100%`; negative means slower. Ratios use unrounded medians.
Access modes, methods, group sizes, retries and component rechecks remain separate.

## Group Compare

Default access, 20 calls per batch; typical use is medium and application-dependent.

| Members | Assertion | Before | Current | OpenLDAP | Relative | Time reduction |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10 | First fixture member | 2.33 ms | 2.48 ms | 1.62 ms | 65.4% | -6.3% |
| 10 | Last fixture member | 2.30 ms | 2.26 ms | 1.52 ms | 67.0% | 1.5% |
| 10 | Missing member | 2.92 ms | 3.01 ms | 1.94 ms | 64.4% | -3.1% |
| 1,000 | First fixture member | 2.60 ms | 2.74 ms | 1.73 ms | 63.2% | -5.7% |
| 1,000 | Last fixture member | 6.10 ms | 3.73 ms | 1.77 ms | 47.4% | 38.8% |
| 1,000 | Missing member | 6.34 ms | 4.17 ms | 2.03 ms | 48.7% | 34.3% |

Explicit ACL 1,000-member last/missing cases change from 6.07/5.71 ms to
3.73/3.61 ms, versus native 1.69/1.66 ms: 38.5%/36.8% time reduction and
45.3%/46.0% relative performance. Explicit first-member 1,000-member Compare
is 3.6% slower. All smaller-group and negative rows remain in the evidence.

## Common operations

Default-access snapshot; full explicit/default/root results remain available.

| Workload | Typical use | Calls | Current | OpenLDAP | Relative |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 86.60 ms | 70.41 ms | 81.3% |
| Non-root Base, hot | High | 1,000 | 106.54 ms | 85.84 ms | 80.6% |
| Non-root equality, hot | Very high | 1,000 | 110.37 ms | 87.50 ms | 79.3% |
| Direct group discovery | High | 100 | 17.89 ms | 13.55 ms | 75.8% |
| Group Base, 1,000 members | Medium | 100 | 93.19 ms | 88.26 ms | 94.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 45.47 ms | 37.32 ms | 82.1% |

Default hot Base is 0.7% slower and distributed equality 0.6% slower; explicit
direct group discovery is 1.7% slower. Unchanged-path fluctuations do not prove
causality. Explicit ACL rules remain:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

## Component and validation

The realistic root handler benchmark includes `subschemaSubentry` and other
operational attributes. Three unprofiled 500ms repetitions before/current:

| 1,000-member assertion | Before ns/op | Current ns/op | Before/current allocations |
| --- | ---: | ---: | ---: |
| First | 39,558 | 41,101 | 423 / 423 |
| Last | 198,513 | 103,786 | 427 / 427 |
| Missing | 188,560 | 90,839 | 428 / 428 |

A separate first-member recheck alternates six fresh test processes, three
per implementation, with 1s batches. Its medians are 40,150/40,979 ns, **2.1%
slower**, with unchanged 89,568 B and 423 allocations. It does not replace the
original component or SDK results. No universal improvement is claimed.

Full Go tests passed (server 138.638s, webadmin 0.449s), schema tests (1.589s),
vet and native differential checks (355 PASS records, no failures/skips,
10.230s). Three-value differential fuzzing completed 995,633 executions.
Tests cover source mutation, suffix changes, invalid leaves/tails, 512-byte
boundaries, plan isolation, error ordering and unchanged inputs.

The initial default-group run completed SDK calls but failed canonical export
because temporary disk space was exhausted. Its samples and failure log are
diagnostic-only. After freeing previously verified scratch exports, the complete
suite was rerun on fresh processes; only that successful retry supplies the
official default-group table. **15 qualified exports match** 100,002 entries,
cksum 2143929969 and 42,712,438 canonical bytes. No failed-run samples are pooled.

Broad read/write measurements remain historical R8b. The [existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host results do not establish
deployment performance. No race-detector result is claimed. The goal stays active.

Frozen executable SHA-256:

```text
before (31f3c08)  e6898cab705cb5b7f2ccd521961e25e1f9e4dd48ecf260e7acb2134cc00c18bf
current           6d0b5a6cdfe26121ab9a3785beccb517264b35aa7b0ef3baa84d4a09eb7d1184
```
