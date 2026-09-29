# Common LDAP performance qualification

September 30, 2026, R17; production baseline `747e5bd` (R13), 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** In the primary network runs,
1,000-member last/missing Compare improves 8.2%-9.9%; the independent
startup-order/port swap observes 7.4%/12.2%. Small-group and ordinary-operation
negative observations remain. These gains do not offset slower common reads.

[R17 evidence](evidence/performance-20260930-r17/README.md) preserves samples,
scripts, counters, hashes and checks. [R13](common-ldap-performance-20260930-r13.md)
is archived verbatim. The [R16 borrowing experiment](evidence/performance-20260930-r16/README.md)
was rejected and withdrawn after reproducing extra small-entry overhead.
R17 does not contain that storage change.

## Implementation

The simple DN comparator parses a leaf RDN once when its already-validated
suffix matches. The new byte helper retains the strict existing ASCII grammar,
attribute-type validation and full-parser fallback for complex inputs.
The ASCII letter predicate folds the case bit before checking one range;
all 256 byte inputs are tested against the previous predicate.

No entry ownership, data format, authorization, password handling, normalization
cache bounds or comparison-result caching changes. Attribute aliases, OIDs,
case-exact matching, multivalued RDN fallback and first-error ordering retain
their previous behavior. The changes remove repeated parsing work.

## Method

Common SDK rows use three batches; root rows use seven. Group Compare uses
seven batches of 1,000 calls with per-request endpoint rotation, identical
assertions, non-root identities and no root fallback. First/last refers to
fixture insertion order, not assumed native storage order. Setup, connections,
identity verification and cleanup are outside SDK timing.

Medians are whole-batch times. Frequency is qualitative, not measured traffic.
Relative = `OpenLDAP/current * 100%`; 100% means parity.
Time reduction = `(1-current/before) * 100%`; negative means slower.
Ratios use unrounded medians. Compare code changes using the paired before/current
results within a run; do not interpret changes in ratios across rounds as
version regressions.

Final fixture copies use APFS copy-on-write clones for all three endpoints.
Each database remains independently writable; the same warmup is retained.
An earlier attempt exhausted disk space while copying the second database,
before any timed samples. Its setup logs and original script are archived
separately and excluded from statistics.

## Group Compare

Default access, 1,000 calls per batch; typical use is medium and application-dependent.

| Members | Assertion | Before | Current | OpenLDAP | Relative | Time reduction |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10 | First fixture member | 89.72 ms | 91.25 ms | 75.80 ms | 83.1% | -1.7% |
| 10 | Last fixture member | 90.68 ms | 91.08 ms | 75.33 ms | 82.7% | -0.4% |
| 10 | Missing member | 94.62 ms | 95.85 ms | 77.07 ms | 80.4% | -1.3% |
| 1,000 | First fixture member | 101.36 ms | 101.09 ms | 79.33 ms | 78.5% | 0.3% |
| 1,000 | Last fixture member | 160.16 ms | 146.98 ms | 83.87 ms | 57.1% | 8.2% |
| 1,000 | Missing member | 154.29 ms | 139.02 ms | 80.83 ms | 58.1% | 9.9% |

Explicit ACL 1,000-member first/last/missing changes from
102.902/158.219/154.555 ms to 100.952/145.285/141.177 ms, versus native
78.953/81.038/81.497 ms. Time reductions are 1.9%/8.2%/8.7%.
Explicit small-group rows are 0.2%-0.6% slower in the primary run.

## Common operations

Primary runs; all explicit/default/root rows remain in evidence.

| Workload | Typical use | Calls | Current, default | OpenLDAP, default | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 90.97 ms | 71.57 ms | 78.7% | 80.6% |
| Non-root Base, hot | High | 1,000 | 100.57 ms | 80.67 ms | 80.2% | 78.7% |
| Non-root equality, hot | Very high | 1,000 | 116.00 ms | 91.84 ms | 79.2% | 76.4% |
| Direct group discovery | High | 100 | 13.82 ms | 10.61 ms | 76.7% | 71.9% |
| Group Base, 1,000 members | Medium | 100 | 96.15 ms | 90.06 ms | 93.7% | 100.3% |
| Nested membership, client BFS | Medium-high | 100 traversals | 47.19 ms | 38.59 ms | 81.8% | 79.0% |

Default SSHA Bind and hot Base are 2.2% and 1.5% slower than the paired baseline.
Explicit hot equality, direct group discovery and nested membership are
1.9%, 2.2% and 2.3% slower. No universal speedup or absence of regression is
claimed. ACL configuration is unchanged:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

## Calibration

Two additional default-access group runs were fixed in advance at 1,000 calls
and seven repeats. They remain separate from the primary tables.

The A/A run uses the exact same R17 executable for both Go endpoint labels.
The label named current is 0.4%-3.2% slower for small groups; the large last-member
case is 7.6% faster despite identical code. This demonstrates measurement
variation, not a code effect. Small differences in the primary runs therefore
cannot establish a causal regression or its absence.

The independent A/B swap starts current first on port 29481 and before second
on 29482. Large first/last/missing time reductions are 3.1%/7.4%/12.2%.
Small first/last/missing changes are -1.6%/+0.9%/-0.7%.
Neither calibration replaces, pools with, or removes any primary sample.
No statistical-significance claim is made.

## Component and validation

Matched root-handler fixtures differ only in member count. Before/current
medians use three unprofiled 500ms repetitions; allocation counts are unchanged.

| Members | Case | Before ns/op | Current ns/op | B/op, both | Allocations/op, both |
| ---: | --- | ---: | ---: | ---: | ---: |
| 10 | First | 10,057 | 10,359 | 9,688 | 101 |
| 10 | Last | 11,373 | 11,351 | 9,768 | 105 |
| 10 | Missing | 11,939 | 11,868 | 9,856 | 110 |
| 1,000 | First | 26,367 | 25,946 | 82,456 | 102 |
| 1,000 | Last | 83,280 | 67,966 | 82,536 | 106 |
| 1,000 | Missing | 74,671 | 61,521 | 82,624 | 111 |

The final full Go test run passed (server 155.966s, storage 29.912s,
webadmin 0.395s), as did vet and native differential checks
(355 PASS records, 11.408s). Final parser fuzzing passed 454,926 executions
in approximately 16 seconds. Logs identify cached packages. The earlier
isolated component/fuzz observations remain separate. No race-detector run
or complete OpenLDAP compatibility is claimed.

All five primary scripts and both calibration scripts passed.
**21 exports match**: 15 primary plus six calibration exports, each with
100,002 entries, cksum 2143929969 and 42,712,438 canonical bytes.
Historical R8b broad scans/writes were not rerun. The
[existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. Shared-host results do not establish
deployment performance. The optimization goal remains active.

Frozen executable SHA-256:

```text
before  96937b2ddf7bce78eccf7ee728880e5eb68fa560d41df0dcbf2517afa13ad751
current 7dd5d031ee6b9ffbdacfc9e302f1fd9626de90fe9d1359486808ff97d5699ab3
```

The baseline reuses the R13 final executable; its embedded VCS metadata records
an earlier dirty build. Evidence preserves actual metadata and source hashes
rather than claiming a clean build of the subsequently committed baseline.
