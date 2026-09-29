# Common LDAP performance qualification

September 30, 2026, R9; baseline `6840e54`, 100,000 users, Apple M1 Pro,
Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** Comparing a late or absent member of
a 1,000-member group is about 48%-54% faster than baseline, but still reaches
only 3.6%-4.5% of OpenLDAP performance. The new measurements expose a remaining
linear-scan bottleneck. Faster operations do not offset slower ones.

[R9 evidence](evidence/performance-20260930-r9/README.md) retains all samples,
checks and scripts. [R8b](common-ldap-performance-20260930-r8b.md) is archived
verbatim; its broad scan/write results are historical, not rerun in R9.

## Implementation

Compare now selects and compares entry attributes in one read-only scan under
one schema snapshot. It avoids cloning selected values, distinguishes absent
attributes from empty attributes, and stops at the first match or comparison
error. Nonordered distinguishedNameMatch comparisons normalize the fixed
assertion once per request, retaining sequential normalization of stored values.
Ordered attributes and other rules use their existing comparison logic.

ACL, assertion controls, referrals, dynamic-group handling, and error-code
mapping remain in their original order. No authorization/result cache or
storage-format change is introduced. Tests preserve schema-description error
types, unknown-identifier handling, aliases/options, malformed values, input
ownership and schema changes between calls.

## Method

Common SDK rows use three batches; paired root rows use seven. New non-root
group Compare rows use five batches of 20 calls, per-request endpoint rotation,
and WhoAmI verification outside timed SDK calls. First/last refer to shared
fixture insertion order, not an assumption about each server's storage order.
All endpoints receive the same group/assertion DN; there is no root fallback.

Only SDK calls are timed; setup, connections, verification and cleanup are
excluded. Medians describe total batch time, not individual-request medians.
Frequency is qualitative. Relative = `OpenLDAP/current * 100%`; 100% is parity.
Time reduction = `(1-current/before) * 100%`; negative means slower than baseline.
Ratios use unrounded medians. Methods, access modes, group sizes and variants
remain separate, with all negative rows retained.

## Group Compare

Default access, 20 calls per batch. Typical usage: medium, depending on whether
an application checks membership by Compare or searches for matching groups.

| Group members | Assertion | Before | Current | OpenLDAP | Relative | Time reduction |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10 | First fixture member | 3.26 ms | 2.91 ms | 1.90 ms | 65.3% | 10.5% |
| 10 | Last fixture member | 4.61 ms | 3.36 ms | 1.74 ms | 51.7% | 27.0% |
| 10 | Missing member | 4.70 ms | 3.76 ms | 1.74 ms | 46.3% | 20.0% |
| 1,000 | First fixture member | 3.09 ms | 2.64 ms | 1.68 ms | 63.6% | 14.7% |
| 1,000 | Last fixture member | 213.63 ms | 110.83 ms | 4.58 ms | 4.1% | 48.1% |
| 1,000 | Missing member | 220.39 ms | 102.04 ms | 3.69 ms | 3.6% | 53.7% |

With explicit ACLs, the 1,000-member last/missing cases change from
201.43/222.03 ms to 103.92/103.80 ms, versus native 4.72/4.02 ms: 48.4%/53.2%
time reduction, but only 4.5%/3.9% relative performance. These are newly measured
existing operations, not newly introduced LDAP functionality.

The runner adds opt-in stages; defaults and `-stages=all` remain unchanged:

```text
-stages=groupCompareTrueFirst,groupCompareTrueLast,groupCompareFalse
-group-sizes=10,1000 -n=20 -repeats=5
```

## Common operations

Default-access snapshot; full default/explicit and paired-root tables remain
in the evidence. Explicit ACL rules are unchanged:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Current | OpenLDAP | Relative |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 105.42 ms | 85.51 ms | 81.1% |
| Non-root Base, hot | High | 1,000 | 122.17 ms | 98.85 ms | 80.9% |
| Non-root equality, hot | Very high | 1,000 | 121.52 ms | 94.31 ms | 77.6% |
| Direct group discovery | High | 100 | 15.71 ms | 11.49 ms | 73.1% |
| Group Base, 1,000 members | Medium | 100 | 105.35 ms | 97.27 ms | 92.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 62.71 ms | 47.92 ms | 76.4% |

Default direct-group/nested searches are both 4.1% slower, distributed equality
3.4% slower, and hot Base 1.9% slower in this run. Explicit large-group Base is
3.3% slower. Paired root UID Compare ranges from 2.1% slower to 0.4% faster.
These mixed rows remain; large-group Compare gains do not imply universal gains.

## Component and validation

Handler benchmarks use three unprofiled 1s repetitions, one repeated target or
1,024 rotating targets, no network. Medians before/current:

| Targets | ns/op | B/op | Allocations/op |
| ---: | ---: | ---: | ---: |
| 1 | 12,724 / 11,794 | 11,768 / 11,232 | 149 / 138 |
| 1,024 | 20,253 / 19,597 | 12,422 / 12,037 | 309 / 301 |

Schema-level 1,000-member comparisons (300ms x 3) change from 43.37 to 7.74 us
for the first value, 7.90 to 4.02 ms for the last, and 8.11 to 4.04 ms for an
absent value. Last/absent allocations fall from 171,010 to 84,086. The original
public-method sequence is retained as an oracle; superseded single-scan-only
measurements are excluded from final component comparisons.

Final full Go tests passed (server 128.953s, webadmin 0.288s), schema tests
(1.585s), runner tests (0.070s), vet, and native differential validation
(355 PASS records, no failures/skips, 10.175s). Final differential fuzzing
completed 679,744 executions. No race-detector result is claimed.

An initial full-suite failure exposed a pre-existing LDIF deadline-test race:
the unchanged baseline reproduced 125 failures in 10,000 repetitions. The
test-only fix `0a29f60` forces an already-expired timeout after setup, avoiding
dependence on a 1 ns timer. The fixed test passed 10,000 repetitions; production
import behavior is unchanged. Initial failure and reproduction logs remain.

All five performance scripts passed. **15 exports match** 100,002 entries,
cksum 2143929969 and 42,712,438 canonical bytes. Broad reads/writes were last
measured in R8b. The [existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host timings do not establish
causality or deployment performance. The goal remains active.

Frozen executable SHA-256:

```text
before (6840e54)  abaeae2a3ebbe3695e70897c52495b00a1f5594a9d34df4be4570df81fda54df
current           b07182c739defbebafa7d769b11e56c7f1d2b8c47ad7ee4ba79781483aa501b9
```
