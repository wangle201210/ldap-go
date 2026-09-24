# Common LDAP performance qualification

September 24, 2026, R7: baseline `ac7182c`, executable `current`,
100,000 users, Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`,
OpenLDAP 2.6.13.

R7 removes repeated DN text construction, but paired SDK results remain mixed.
SSHA Bind is **7.3% slower with explicit ACLs and 0.7% slower with default
access**. Direct group discovery takes 4.2% less time with explicit ACLs and
0.4% less with default access. **The OpenLDAP parity goal remains unachieved;
there is no uniform gain.** Shared-host measurements do not establish that
the code change caused each timing difference.

The [R6 archive](common-ldap-performance-20260924-r6.md) preserves the previous
report verbatim. This report uses only the completed R7 `explicit-final`
and `default-final` runs; the failed initial attempt is diagnostic only.

## Change and method

Runtime root/suffix display comparisons avoid constructing joined DN strings.
The existing bounded schema cache retains normalized text alongside the parsed
DN for its two cached consumers. `directory.DN` representation and the public
`NormalizeDNCached` result remain unchanged. Limits remain 128 entries, 1 MiB
of estimated retained data, 1,024 input bytes and depth 32, with owned data and
schema-generation invalidation. No authorization, authentication-result or
entry-result cache was added; syntax/length validation, password checks,
snapshot semantics and error behavior remain.

The [SDK runner](../internal/cmd/ldapcommonbench/README.md) rotates endpoints per
request and verifies responses and cleanup. Tables show medians of three
`total_ms` batches, grouped by run, batch, stage, method, member count and
endpoint. Only SDK Bind/Search calls are timed; setup, verification, connection
setup and cleanup are excluded. No measured outlier is discarded. SSHA and
plaintext, hot and distributed reads, and group sizes remain separate.

All endpoints use uid/member/objectClass equality indexes, 100,000 users plus
two containers, plaintext loopback LDAP and the same fixtures. Hot reads use
`scale-001001`; distributed reads sample 1,000 users across the 100k range.
User Base/equality requests retain size limit 2; nested discovery retains limit
6. Each nested batch is 100 client BFS traversals and 417 timed SDK searches.
Other rows have one timed SDK call per operation.

Relative performance is `OpenLDAP / current * 100%`; 100% means parity.
Time reduction is `(1 - current / before) * 100%`; negative means slower.
Ratios use unrounded medians. Usage frequency is qualitative, not traffic data.
[All 72 endpoint medians](evidence/common-performance-20260924-r7/medians.tsv)
and the [calculation helper](evidence/common-performance-20260924-r7/calculate.py.txt)
retain the R6 grouping.

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 102.56 ms | 110.05 ms | 80.59 ms | 73.2% | -7.3% |
| Wrong password, SSHA | Low | 1,000 | 104.50 ms | 107.31 ms | 79.55 ms | 74.1% | -2.7% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 151.97 ms | 158.19 ms | 124.23 ms | 78.5% | -4.1% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 94.76 ms | 95.76 ms | 73.29 ms | 76.5% | -1.1% |
| Non-root Base, hot | High | 1,000 | 127.44 ms | 131.09 ms | 96.36 ms | 73.5% | -2.9% |
| Non-root equality, hot | Very high | 1,000 | 122.74 ms | 121.90 ms | 93.89 ms | 77.0% | 0.7% |
| Non-root Base, distributed | High | 1,000 | 142.01 ms | 140.64 ms | 95.44 ms | 67.9% | 1.0% |
| Non-root equality, distributed | Very high | 1,000 | 148.21 ms | 151.21 ms | 104.12 ms | 68.9% | -2.0% |
| Direct group discovery | High | 100 | 17.74 ms | 16.99 ms | 11.45 ms | 67.4% | 4.2% |
| Group Base, 10 members | Medium | 100 | 17.11 ms | 16.17 ms | 11.84 ms | 73.2% | 5.5% |
| Group Base, 1,000 members | Medium | 100 | 102.52 ms | 103.09 ms | 91.37 ms | 88.6% | -0.6% |
| Nested membership, client BFS | Medium-high | 100 traversals | 59.26 ms | 59.06 ms | 43.88 ms | 74.3% | 0.3% |

Explicit SSHA Bind paired before/current batches are 109.570877/110.048453,
102.561186/102.825934 and 99.401219/111.577467 ms: **0.44%, 0.26% and 12.25%
slower**, respectively. The 7.3% comparison is between the endpoint medians,
not the median paired percentage. The third batch is retained. Neither host
variability nor a component advantage justifies dismissing the regression.

[Hot samples](evidence/common-performance-20260924-r7/explicit-final/hot.json),
[distributed samples](evidence/common-performance-20260924-r7/explicit-final/distributed.json),
[group samples](evidence/common-performance-20260924-r7/explicit-final/groups.json).

## Default access

No explicit ACL rules; methods, executables and fixture size otherwise match.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 91.84 ms | 92.48 ms | 73.45 ms | 79.4% | -0.7% |
| Wrong password, SSHA | Low | 1,000 | 86.14 ms | 86.93 ms | 69.67 ms | 80.1% | -0.9% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 87.99 ms | 89.22 ms | 68.83 ms | 77.2% | -1.4% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 96.83 ms | 94.57 ms | 74.04 ms | 78.3% | 2.3% |
| Non-root Base, hot | High | 1,000 | 121.60 ms | 121.80 ms | 94.79 ms | 77.8% | -0.2% |
| Non-root equality, hot | Very high | 1,000 | 118.11 ms | 118.53 ms | 89.80 ms | 75.8% | -0.4% |
| Non-root Base, distributed | High | 1,000 | 132.14 ms | 132.77 ms | 91.16 ms | 68.7% | -0.5% |
| Non-root equality, distributed | Very high | 1,000 | 127.56 ms | 129.19 ms | 91.11 ms | 70.5% | -1.3% |
| Direct group discovery | High | 100 | 17.18 ms | 17.11 ms | 11.76 ms | 68.8% | 0.4% |
| Group Base, 10 members | Medium | 100 | 13.92 ms | 14.14 ms | 10.25 ms | 72.5% | -1.6% |
| Group Base, 1,000 members | Medium | 100 | 96.85 ms | 97.61 ms | 88.71 ms | 90.9% | -0.8% |
| Nested membership, client BFS | Medium-high | 100 traversals | 51.90 ms | 51.66 ms | 36.84 ms | 71.3% | 0.5% |

Default SSHA Bind, both hot/distributed user-read pairs and both group Base
sizes have slower current medians. Small reductions in direct/nested membership
do not establish a general latency improvement.

[Hot samples](evidence/common-performance-20260924-r7/default-final/hot.json),
[distributed samples](evidence/common-performance-20260924-r7/default-final/distributed.json),
[group samples](evidence/common-performance-20260924-r7/default-final/groups.json).

## Concurrent check

Eight root-bound CLI clients each issue 1,000 indexed UID searches. These
wall-clock batches include startup/Bind; repeat 0 is warmup, and repeats 1-3
supply the medians. This is separate from non-root SDK timing.

| Access configuration | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL | 212 ms | 208 ms | 225 ms | 108.2% | 1.9% |
| Default | 197 ms | 198 ms | 207 ms | 104.5% | -0.5% |

[Explicit batches](evidence/common-performance-20260924-r7/explicit-final/concurrent.tsv)
and [default batches](evidence/common-performance-20260924-r7/default-final/concurrent.tsv)
retain every sample. Ratios above 100% in this check do not establish general parity.

## Component evidence

The following are medians of two existing component repetitions comparing
**warm cached DN lookup plus rerendering** with **warm retained-text lookup**.
They isolate text reuse; they do not compare against uncached normalization.

| Warm workload | DN lookup + rerender | Retained text | Bytes/op, rerender to retained | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Suffix | 81.59 ns/op | 46.12 ns/op | 24 to 0 | 1 to 0 |
| Multi-AVA DN | 103.25 ns/op | 45.81 ns/op | 48 to 0 | 1 to 0 |

Empty-root lookup already allocates zero bytes. Cold and oversized cases are
retained in the [text-cache log](evidence/common-performance-20260924-r7/text-cache-bench.txt);
no general cold-path speedup is claimed. Its separate assertion benchmarks
compare composite cached/uncached normalization and are not evidence for the
incremental R7 text benefit. The [display log](evidence/common-performance-20260924-r7/display-bench.txt)
also records zero allocations for direct root/suffix comparisons, versus one
or two allocations for the corresponding joined-string cases. Component
results do not establish an SDK latency improvement.

## Validation and limits

- Coordinator-confirmed final [Go tests](evidence/common-performance-20260924-r7/go-test.txt)
  passed with `CGO_ENABLED=0` (server 142.798 s; some packages cached).
  [Vet](evidence/common-performance-20260924-r7/go-vet.txt) exited successfully
  with an empty log. [Native differential](evidence/common-performance-20260924-r7/openldap-differential.txt)
  records 355 PASS results, no failures/skips and terminal PASS.
- Both accepted runs exited 0. Smoke and measured JSONs have empty errors,
  complete repeat sequences, completed operation counts and cleanup for all
  endpoints. All six exports match **100,002 entries, checksum 2143929969 and
  42,712,438 canonical bytes**:
  [explicit](evidence/common-performance-20260924-r7/explicit-final/validation.tsv),
  [default](evidence/common-performance-20260924-r7/default-final/validation.tsv).
- The [initial explicit attempt](evidence/common-performance-20260924-r7/diagnostics/explicit-initial/status.txt)
  failed at the existing 10-second client timeout while setting up current's
  1,000-member group, after 24 setup adds and before any measured group sample.
  Its JSON records before/current cleanup and the error; earlier hot/distributed
  samples remain diagnostic only. Both accepted runs used fresh fixtures and
  a 30-second client timeout. SDK timing boundaries were unchanged.
- The [existing R2 operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
  remains: synthesized `entryDN` and `hasSubordinates` are missing in ordinary
  memory-store entry scenarios, including root reads and `+` with types-only.
  These cases are outside the passing native matrix.
- No race detector was used. This shared-host, three-repeat loopback matrix
  does not establish causal certainty, full compatibility, non-root concurrent
  capacity or deployment performance. No further benchmark/recheck is planned
  at this checkpoint.

## Evidence and identity

[Evidence index](evidence/common-performance-20260924-r7/README.md),
[explicit replay](evidence/common-performance-20260924-r7/common-explicit.sh.txt),
[default replay](evidence/common-performance-20260924-r7/common-default.sh.txt),
[explicit completion](evidence/common-performance-20260924-r7/common-explicit.log.txt),
[default completion](evidence/common-performance-20260924-r7/common-default.log.txt).
Replay copies retain the final 30-second timeout and require the existing
disposable fixture password through the environment. No passwords, binaries,
databases or large exports are archived.

Source: `/var/tmp/ldap-go-common-perf-20260924-r7`.
Executable SHA-256 supplied by the coordinator:

```text
before (ac7182c)  f65475df23fa7fa127f688dd6ee475263fdf978af437efecb9a5f009509a46e2
current           9d77bb8edafc272b239a40af57fa8ce5518ee4c758f45ab75dd50e7d15850981
```

Documentation preparation ran no tests, builds or benchmarks. Earlier
write/paging/memory measurements remain in the
[full-operation report](performance-optimization-20260923-round13.md).
