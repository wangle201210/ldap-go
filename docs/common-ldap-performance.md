# Common LDAP performance qualification

Latest focused comparison: [R22 Base search](common-ldap-performance-20260930-r22.md).
Verified TLS results and a rejected input-buffer experiment:
[R23](common-ldap-performance-20260930-r23.md).
Unshipped direct-Get lease qualification and calibration:
[R25](common-ldap-performance-20260930-r25.md).
The R19 results below are retained as historical evidence, including workloads
not rerun in R22.

September 30, 2026, R19; production baseline `8918569` (R18), 100,000 users,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** Primary 1,000-member last/missing
Compare observations improve 3.7%-7.6%; the independent startup/port swap
observes 6.6%/4.2%. Other rows include negative observations.
Neither these gains nor fast writes offset slower common reads.

[R19 evidence](evidence/performance-20260930-r19/README.md) preserves all samples,
checks, scripts, hashes and source reconstruction. The
[R18 report](common-ldap-performance-20260930-r18.md) is archived verbatim.

## Implementation and scope

A 256-byte table recognizes the same strict ASCII RDN value subset as before.
When a prevalidated suffix matches and the leaf name exactly matches the
prepared canonical name, one scan validates and compares the leaf value.
A value mismatch does not stop validation of its remaining bytes.
Uppercase folding preserves underscores and case-exact behavior.

Aliases, other names, complex RDNs, UTF-8, escapes and invalid inputs retain the
original parser/normalizer fallback and first-error ordering. Tests check all
256 byte values and the helper's normalized-assertion preconditions.
No storage, ACL, Bind, queue, audit, data-format or cache change is included.
The separately explored input buffer was not implemented because deadline,
Close, custom-reader error boundaries and upgrade-byte ownership need more proof.

## Method

Hot Bind/Base/equality SDK rows use seven 1,000-operation batches.
Distributed lookups use three batches of 1,000; group searches three of 100.
Root operations and group Compare use seven batches of 1,000.
Endpoints rotate per request; identities, assertions and response checks are
shared, without root fallback. Setup, connections, checks and cleanup are
outside timing. APFS COW fixture copies remain independently writable.

Medians are whole-batch times. Frequency is qualitative.
Relative = `OpenLDAP/current * 100%`; 100% means parity.
Time reduction = `(1-current/before) * 100%`; negatives mean slower.
Use paired versions within one run, not ratios across rounds, to assess changes.
Unrounded values determine percentages.

## Group Compare

1,000-member groups, 1,000 calls per batch; typical use is medium and
application-dependent. First/last denotes fixture insertion order, not assumed
native storage order.

| Access | Assertion | Before | Current | OpenLDAP | Time reduction | Relative |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Default | First | 106.04 ms | 105.36 ms | 84.05 ms | 0.6% | 79.8% |
| Default | Last | 146.51 ms | 140.29 ms | 82.91 ms | 4.2% | 59.1% |
| Default | Missing | 148.93 ms | 140.11 ms | 87.06 ms | 5.9% | 62.1% |
| Explicit ACL | First | 102.48 ms | 101.05 ms | 79.00 ms | 1.4% | 78.2% |
| Explicit ACL | Last | 151.93 ms | 140.45 ms | 83.96 ms | 7.6% | 59.8% |
| Explicit ACL | Missing | 149.95 ms | 144.35 ms | 87.25 ms | 3.7% | 60.4% |

For 10-member groups, default first/last improve 0.1%/0.2%, while missing
is 1.0% slower. Explicit first/last are 1.0%/0.9% slower; missing improves 0.1%.
Every small-group value remains in the evidence.

## Common operations

All rows were rerun; seven batches for the first three rows, three for the rest.

| Workload | Typical use | Calls | Current, default | OpenLDAP, default | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 89.60 ms | 71.22 ms | 79.5% | 78.3% |
| Non-root Base, hot | High | 1,000 | 100.88 ms | 80.16 ms | 79.5% | 80.1% |
| Non-root equality, hot | Very high | 1,000 | 101.94 ms | 82.99 ms | 81.4% | 77.4% |
| Direct group discovery | High | 100 | 15.16 ms | 11.63 ms | 76.7% | 72.3% |
| Group Base, 1,000 members | Medium | 100 | 92.46 ms | 86.51 ms | 93.6% | 91.7% |
| Nested membership, client BFS | Medium-high | 100 traversals | 53.96 ms | 44.78 ms | 83.0% | 78.2% |

Default SSHA Bind and hot Base are 1.8%/2.9% slower than the paired baseline.
Explicit SSHA Bind, large-group Base and nested membership are 5.9%, 3.9%
and 4.3% slower. These observations are retained without assigning causality.
There is no claim of a universal speedup or regression-free behavior.
Explicit ACL rules are unchanged:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

## Calibration

Two predetermined default group runs use seven 1,000-call batches and remain
separate from primary statistics.

A/A runs the same candidate binary under both Go endpoint labels. Small-group
current labels are 0.8%-3.1% slower. Large first/last/missing time reductions
are -0.4%/+2.0%/-3.0%, despite identical code.

The real A/B swap starts current first on port 29481 and before second on
29482. Large first/last/missing changes are -1.4%/+6.6%/+4.2%;
small cases are +0.9%/-0.8%/+2.6%. Changing both startup order and port does not
isolate either cause. These calibrations do not correct or replace core results,
establish statistical significance, or prove that all negative values are noise.

## Components and validation

Formal components use frozen R18 and final R19 implementations with identical
root-bound Group1000/Small10 fixtures, three unprofiled 500ms repeats.

| Members | Case | Before ns/op | Current ns/op | B/op, both | Allocations/op, both |
| ---: | --- | ---: | ---: | ---: | ---: |
| 10 | First | 9,908 | 9,669 | 9,688 | 101 |
| 10 | Last | 11,234 | 11,182 | 9,768 | 105 |
| 10 | Missing | 12,122 | 11,890 | 9,856 | 110 |
| 1,000 | First | 23,055 | 24,278 | 82,456 | 102 |
| 1,000 | Last | 65,022 | 59,477 | 82,536 | 106 |
| 1,000 | Missing | 57,239 | 52,035 | 82,624 | 111 |

Large first is 5.3% slower, while last/missing improve 8.5%/9.1%.
All allocations are unchanged. Earlier table-only, single-pass and alternating
prototype observations used a different source baseline and are archived
separately, including their negative results. They are not pooled here.

Focused directory/schema tests, full Go tests (server 156.914s, storage
31.977s, webadmin 0.372s), vet and 355 native differential checks passed
(native 11.211s). Final parse and matching fuzz runs passed 558,456 and
621,669 executions respectively. An independent static review found no
provable change in matching/fallback/error order; that is not a safety proof.

All seven network scripts passed. **21 exports match**: 15 core and six
calibration exports, each with 100,002 entries, cksum 2143929969 and
42,712,438 canonical bytes. Shared-host conditions, COW and caches remain
limitations. No race-detector, controlled cold-cache, universal performance
or complete OpenLDAP compatibility claim is made.

R18 same-process SDK/server profiles are separate exploratory evidence;
their timings and setup-inclusive CPU samples do not enter R19 tables.
Historical R8b broad reads/writes were not rerun. The
[known operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. The optimization goal remains active.

Frozen production SHA-256:

```text
before  5546307a886f3b507e8f418eebeab0e020d074a1a49cea476fc66f657c3c6370
current 8337870fb7ccd7c6a2849d2bcd21b05f5df11d022c658e401fcd4054fccadf98
```

Actual embedded build metadata and baseline-relative source reconstruction are
retained; reused binaries are not described as clean builds of later commits.

## Subsequent rejected experiment

[R20 request-allocation evidence](evidence/performance-20260930-r20/README.md)
records an unshipped queue/audit-snapshot candidate. It removed three allocations
in the same-process network benchmark but did not establish stable latency gains;
that benchmark regressed and the separate startup-order check remained slower.
Both production changes were withdrawn. The R19 figures above remain the last
shipped qualification, and all R20 observations stay separate.

R20 also documents recovery of the removed reference environment and fixtures:
the same pinned OpenLDAP source was rebuilt, and all 21 final exports matched
the original canonical contents. Physical MDB layout and generated operational
attributes were not claimed identical to the removed database.
