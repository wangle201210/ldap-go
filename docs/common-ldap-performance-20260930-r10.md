# Common LDAP performance qualification

September 30, 2026, R10; baseline `19b05f6`, 100,000 users, Apple M1 Pro,
Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

**Per-operation parity remains unmet.** For the measured simple-DN fixtures,
late/missing membership Compare on 1,000-member groups is 91.6%-93.1% faster
than R9, but still reaches only 31.0%-38.6% of native performance. Ordinary
login/read results remain mixed. No aggregate score offsets slower operations.

[R10 evidence](evidence/performance-20260930-r10/README.md) retains all samples,
checks and scripts. [R9](common-ldap-performance-20260930-r9.md) is archived
verbatim. Broad read/write results remain historical R8b evidence.

## Implementation and scope

The pinned OpenLDAP source uses normalized `a_nvals` in `attr_valfind`, with
binary search only when the sorted-values flag is set, otherwise linear search.
This change does not assume that the benchmark's native member values are sorted.

Go Compare now prepares a request-local simple-DN comparison after its first
fully normalized, nonmatching value. Subsequent eligible values are compared
directly without constructing full DN objects. It reuses the existing strict
syntax recognizer and resolves attribute identity and matching rules under the
current schema read lock. No persistent cache, index shortcut, data-format
change or authorization shortcut is introduced.

Eligibility is deliberately explicit: at most eight single-AVA RDNs; values
containing only ASCII letters, digits, `.`, `_`, `-`; corresponding attribute
identities; caseIgnoreMatch/caseExactMatch or their IA5 variants. The normalized
assertion must fit that subset; raw escaped assertions can qualify after full
normalization. Complex stored DNs, different shapes/types/rules, Unicode and
invalid tails use the original normalization path. Even an early unequal value
must not hide an unsupported or invalid later attribute. Unsupported DN shapes
are not claimed to gain the same performance.

## Method

Common SDK rows use three batches; paired root rows use seven. Non-root group
Compare uses five batches of 20 calls, per-request endpoint rotation, shared
fixture/assertion DNs and WhoAmI checks outside timing. First/last mean fixture
insertion order, not each server's internal ordering. No root fallback occurs.

Only SDK calls are timed. Setup, connection, verification and cleanup are
excluded. Medians describe total batch time, not individual-request medians.
Frequency is qualitative. Relative = `OpenLDAP/current * 100%`, with 100% parity.
Time reduction = `(1-current/before) * 100%`; negative means slower. Ratios use
unrounded medians. Access modes, sizes, methods and independent rechecks remain
separate; all negative rows are retained.

## Group Compare

Default access, 20 calls per batch; typical usage is medium and application-dependent.

| Members | Assertion | Before | Current | OpenLDAP | Relative | Time reduction |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 10 | First fixture member | 2.23 ms | 2.22 ms | 1.52 ms | 68.2% | 0.2% |
| 10 | Last fixture member | 3.22 ms | 2.13 ms | 1.39 ms | 65.3% | 33.8% |
| 10 | Missing member | 3.35 ms | 2.40 ms | 1.50 ms | 62.5% | 28.5% |
| 1,000 | First fixture member | 2.39 ms | 2.30 ms | 1.52 ms | 66.2% | 3.6% |
| 1,000 | Last fixture member | 95.36 ms | 6.62 ms | 2.06 ms | 31.0% | 93.1% |
| 1,000 | Missing member | 96.12 ms | 8.10 ms | 2.89 ms | 35.7% | 91.6% |

Explicit ACL last/missing cases at 1,000 members change from 96.93/96.72 ms to
7.15/7.17 ms, versus native 2.54/2.77 ms. Both improve about 92.6%, but remain
at 35.5%/38.6% relative performance. The remaining gap is material.

## Common operations

Default-access snapshot; full explicit/default and root results remain in the evidence.

| Workload | Typical use | Calls | Current | OpenLDAP | Relative |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 91.95 ms | 74.83 ms | 81.4% |
| Non-root Base, hot | High | 1,000 | 107.42 ms | 81.92 ms | 76.3% |
| Non-root equality, hot | Very high | 1,000 | 117.75 ms | 87.73 ms | 74.5% |
| Direct group discovery | High | 100 | 18.22 ms | 13.68 ms | 75.1% |
| Group Base, 1,000 members | Medium | 100 | 129.55 ms | 129.31 ms | 99.8% |
| Nested membership, client BFS | Medium-high | 100 traversals | 54.01 ms | 42.31 ms | 78.3% |

Default direct group discovery is 9.2% slower, hot equality 3.9% slower and
nested membership 4.2% slower. Explicit wrong-password plaintext Bind is 7.7%
slower. Paired root UID Compare ranges from 2.4% slower to 0.7% faster. These
rows are not hidden by the group Compare gains. Explicit ACL rules remain:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

Independent fresh-process, seven-repeat rechecks of the larger negative rows:

| Recheck | Calls | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default direct group discovery | 100 | 14.94 ms | 15.02 ms | 11.56 ms | -0.6% |
| Explicit wrong Bind, SSHA | 1,000 | 99.91 ms | 99.16 ms | 80.80 ms | 0.7% |
| Explicit wrong Bind, plaintext | 1,000 | 87.31 ms | 88.09 ms | 70.42 ms | -0.9% |

The larger slowdowns did not recur, but the original samples remain. Rechecks
are neither pooled with nor substituted for them. Shared-host results do not
establish causal explanations or universal gains.

## Component and validation

Handler benchmarks use three unprofiled 1s repetitions with one repeated target
or 1,024 rotating targets. Before/current medians are 11,538/11,322 ns and
19,219/19,188 ns; allocations stay at 138 and 301 respectively. These UID
comparisons do not exercise the new multi-value DN path.

The schema group component compares the preserved pre-R9 public-method oracle
against current code (300ms x 3), **not against R9 as a separate executable**.
Last/missing 1,000-member cases take approximately 112.96/110.06 us with 173
allocations, versus oracle 7.42/7.34 ms with 171,010 allocations. This is not an
SDK or whole-process memory claim; R9-to-R10 gains use the live SDK table above.

Full Go tests passed (server 138.878s, webadmin 0.269s), focused directory/schema
tests (3.039s/1.853s), vet and native differential validation (355 PASS records,
no failures/skips, 11.371s). Differential fuzzing completed 1,086,188 executions.
Tests cover aliases/OIDs, case-sensitive rules, invalid tails, schema changes,
depth boundaries, first-error ordering and input ownership. No race-detector
result is claimed.

All seven performance scripts passed. **21 exports match** 100,002 entries,
cksum 2143929969 and 42,712,438 canonical bytes: 15 original and six recheck
exports. Broad reads/writes were not rerun. The [existing operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside the passing matrix. The optimization goal remains active.

Frozen executable SHA-256:

```text
before (19b05f6)  b07182c739defbebafa7d769b11e56c7f1d2b8c47ad7ee4ba79781483aa501b9
current           e6898cab705cb5b7f2ccd521961e25e1f9e4dd48ecf260e7acb2134cc00c18bf
```
