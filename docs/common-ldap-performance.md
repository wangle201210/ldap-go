# Common LDAP performance qualification

September 24, 2026, sixth run: baseline `49af259`, final executable `current`,
OpenLDAP 2.6.13, 100,000 users, Apple M1 Pro, Go 1.26.4 with
`CGO_ENABLED=0`.

R6 reduces sampled allocation beneath the small non-root search path by
**57.4%** in the separate 10,000-query member-equality profile. The paired SDK
measurements remain mixed: direct group discovery takes **4.8% less time with
explicit ACLs and 12.7% less with default access**, while several other rows
regress. Original default SSHA Bind is **6.6% slower**, and explicit group Base
with 1,000 members is **7.1% slower**. Separate seven-repeat rechecks do not
reproduce those two regressions; they do not replace the original observations.
The explicit 10-member group recheck remains **4.0% slower**.
**The OpenLDAP parity goal remains unachieved; there is no uniform latency gain.**

The [fifth run](common-ldap-performance-20260924-r5.md),
[fourth run](common-ldap-performance-20260924-r4.md),
[third run](common-ldap-performance-20260924-r3.md),
[second run](common-ldap-performance-20260924-r2.md), and
[first run](common-ldap-performance-20260924-r1.md) retain previous evidence.
Compare implementations within each run; shared-host timing varies across runs.
Main tables use only `explicit-final` and `default-final`. Rechecks and
profiles are separate evidence.

## Accepted changes

- Eligible read-only candidate iterators lazily borrow an exclusive decoder from
  a fixed pool of at most **16 idle decoders**. This is an idle-retention bound,
  not a limit on active iterators. The existing borrowing bounds remain
  **64 attributes and 4,096 total value descriptors per row**. A single small
  encoded row still uses the owned decoder. Unsupported shapes and errors
  retain the authoritative owned fallback.
- Release clears the complete attribute/value descriptor arrays, the entire
  overflow capacity and the name map before recycling. Idle decoders retain no
  entry or payload references. Bolt payload bytes are not cleared or changed.
  Final selected output still owns its descriptors and bytes before the
  candidate callback ends; snapshots, cancellation and error ordering remain.
- `NormalizeEqualityAssertionCachedDN` reuses the existing bounded,
  generation-invalidated DN cache only for `distinguishedNameMatch`. Attribute
  resolution and **syntax validation, including length, execute on every call
  before cache lookup**. It returns fresh bytes of the existing
  `NormalizedString()` representation, not a DN identity key. The original
  `NormalizeEqualityAssertion` API remains uncached.
- The database index normalizer opts in only for a concrete `*schema.Registry`
  under the runtime/offline immutable-schema contract. Custom registry callbacks,
  non-DN matching rules, ordered-assertion behavior and exact errors retain their
  prior semantics. The shared DN cache remains bounded to 128 entries and 1 MiB,
  with input/depth admission limits and invalidation on registry mutation.

Root/entry/filter/attribute authorization, password verification and work factors,
both authentication storage Views, snapshot freshness and result budgets remain.
No authorization, authentication-result, entry-result or attribute-read cache was
added. The R5 projection and Bind-pointer changes are baseline behavior, not new
R6 changes. The rejected R5 TCP read-buffer prototype remains absent.

## Measurement

The [SDK runner](../internal/cmd/ldapcommonbench/README.md) rotates endpoints per
request and checks exact responses, identities and fixture cleanup. Only SDK
Bind/Search calls are timed. Main rows are medians of three `total_ms` batch
samples, grouped by run, batch, stage, method, member count and endpoint.
Rechecks use seven repeats and are calculated separately. No measured outliers
are discarded. [Calculated medians](evidence/common-performance-20260924-r6/medians.tsv)
retain all 90 endpoint groups, including plaintext Bind diagnostics.

All three endpoints use uid/member/objectClass equality indexes and 100,000 users
plus two containers. Hot user reads use `scale-001001`; distributed reads sample
1,000 users across the 100k range. Temporary groups contain 10 or 1,000 real user
DNs, reported separately. Nested membership uses the same client BFS with cycle
detection: 100 traversals issue 417 timed SDK searches per batch. Other main rows
have one timed SDK call per operation.

Ordinary Base/UID reads retain `SizeLimit=len(want)+1=2`; nested group discovery
retains `SizeLimit=len(groups)+1=6`. SSHA and plaintext methods are never pooled.
Verification, connection setup and fixture cleanup are outside the SDK timer.
Transport is plaintext loopback LDAP.

Relative performance is `OpenLDAP / current * 100%`; 100% means parity.
Time reduction is `(1 - current / before) * 100%`; negative means a slower
observed median. Ratios use unrounded medians; tables show milliseconds to two
decimals and percentages to one. Usage frequency is qualitative, not measured
traffic. Neither an individual ratio above 100% nor a lower allocation count
establishes general parity.

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 95.18 ms | 94.33 ms | 75.49 ms | 80.0% | 0.9% |
| Wrong password, SSHA | Low | 1,000 | 90.19 ms | 91.73 ms | 70.38 ms | 76.7% | -1.7% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 98.36 ms | 102.15 ms | 79.09 ms | 77.4% | -3.9% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 88.95 ms | 89.02 ms | 70.10 ms | 78.7% | -0.1% |
| Non-root Base, hot | High | 1,000 | 133.98 ms | 135.44 ms | 99.32 ms | 73.3% | -1.1% |
| Non-root equality, hot | Very high | 1,000 | 129.54 ms | 125.76 ms | 94.25 ms | 74.9% | 2.9% |
| Non-root Base, distributed | High | 1,000 | 132.58 ms | 131.65 ms | 86.33 ms | 65.6% | 0.7% |
| Non-root equality, distributed | Very high | 1,000 | 265.46 ms | 173.14 ms | 122.06 ms | 70.5% | 34.8% |
| Direct group discovery | High | 100 | 23.98 ms | 22.83 ms | 13.82 ms | 60.5% | 4.8% |
| Group Base, 10 members | Medium | 100 | 16.50 ms | 17.04 ms | 11.81 ms | 69.3% | -3.3% |
| Group Base, 1,000 members | Medium | 100 | 112.73 ms | 120.69 ms | 103.01 ms | 85.4% | -7.1% |
| Nested membership, client BFS | Medium-high | 100 traversals | 90.64 ms | 82.61 ms | 61.81 ms | 74.8% | 8.9% |

[Hot samples](evidence/common-performance-20260924-r6/explicit-final/hot.json),
[distributed samples](evidence/common-performance-20260924-r6/explicit-final/distributed.json),
[group samples](evidence/common-performance-20260924-r6/explicit-final/groups.json).

The 34.8% lower distributed-equality median is an observation from these three
batches, not a stable speedup claim. Hot Base, wrong-password SSHA Bind, plaintext
Bind and both group Base sizes have slower current medians. All remain visible.

## Default access

No explicit ACL rules. Methods, fixture and executables match the explicit run;
access modes are summarized independently.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 123.72 ms | 131.94 ms | 106.12 ms | 80.4% | -6.6% |
| Wrong password, SSHA | Low | 1,000 | 112.70 ms | 105.98 ms | 84.07 ms | 79.3% | 6.0% |
| User Bind, plaintext diagnostic | Very high | 1,000 | 115.31 ms | 110.75 ms | 87.04 ms | 78.6% | 4.0% |
| Wrong password, plaintext diagnostic | Low | 1,000 | 110.17 ms | 112.21 ms | 86.78 ms | 77.3% | -1.9% |
| Non-root Base, hot | High | 1,000 | 126.43 ms | 125.86 ms | 97.06 ms | 77.1% | 0.5% |
| Non-root equality, hot | Very high | 1,000 | 113.91 ms | 113.02 ms | 89.06 ms | 78.8% | 0.8% |
| Non-root Base, distributed | High | 1,000 | 138.65 ms | 145.15 ms | 94.70 ms | 65.2% | -4.7% |
| Non-root equality, distributed | Very high | 1,000 | 141.36 ms | 143.03 ms | 100.82 ms | 70.5% | -1.2% |
| Direct group discovery | High | 100 | 18.64 ms | 16.27 ms | 10.67 ms | 65.6% | 12.7% |
| Group Base, 10 members | Medium | 100 | 20.13 ms | 18.45 ms | 12.74 ms | 69.0% | 8.4% |
| Group Base, 1,000 members | Medium | 100 | 94.16 ms | 96.79 ms | 85.25 ms | 88.1% | -2.8% |
| Nested membership, client BFS | Medium-high | 100 traversals | 57.31 ms | 55.11 ms | 39.83 ms | 72.3% | 3.8% |

[Hot samples](evidence/common-performance-20260924-r6/default-final/hot.json),
[distributed samples](evidence/common-performance-20260924-r6/default-final/distributed.json),
[group samples](evidence/common-performance-20260924-r6/default-final/groups.json).

Default hot user-query medians change by less than 1%. The original SSHA Bind,
both distributed user-query rows, plaintext wrong-password Bind and 1,000-member
group Base are slower. The direct-group and nested-membership reductions do not
erase these observations.

## Seven-repeat rechecks

Both rechecks completed successfully with the same final executables, fresh
disposable fixtures, endpoint rotation and unchanged per-batch operation counts.
They are not pooled into or substituted for the main tables.

### Default Bind

| Workload | Repeats | Calls per batch | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 7 | 1,000 | 91.22 ms | 90.35 ms | 71.21 ms | 78.8% | 1.0% |
| Wrong password, SSHA | 7 | 1,000 | 104.21 ms | 95.21 ms | 76.71 ms | 80.6% | 8.6% |
| User Bind, plaintext diagnostic | 7 | 1,000 | 88.50 ms | 87.46 ms | 68.81 ms | 78.7% | 1.2% |
| Wrong password, plaintext diagnostic | 7 | 1,000 | 89.76 ms | 90.31 ms | 72.28 ms | 80.0% | -0.6% |

The original SSHA Bind result remains **123.72 / 131.94 / 106.12 ms**
(before/current/OpenLDAP), or **6.6% slower** current time. The separate recheck is
**91.22 / 90.35 / 71.21 ms**, a 1.0% reduction. Original regression was not
reproduced; neither run establishes a stable Bind gain. Recheck SSHA Bind ranges
are 87.16-94.20 / 87.69-94.28 / 69.20-73.87 ms. Wrong-password SSHA samples
also vary substantially, including a baseline range of 89.26-141.66 ms.

[Samples](evidence/common-performance-20260924-r6/default-recheck/recheck.json),
[replay](evidence/common-performance-20260924-r6/recheck-default.sh.txt),
[completion log](evidence/common-performance-20260924-r6/recheck-default.log.txt),
[exports](evidence/common-performance-20260924-r6/default-recheck/validation.tsv).

### Explicit group Base

| Workload | Repeats | Calls per batch | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Group Base, 10 members | 7 | 100 | 13.52 ms | 14.06 ms | 9.96 ms | 70.9% | -4.0% |
| Group Base, 1,000 members | 7 | 100 | 97.46 ms | 96.94 ms | 90.40 ms | 93.3% | 0.5% |

The original 1,000-member result remains **112.73 / 120.69 / 103.01 ms**, or
**7.1% slower** current time. The recheck is **97.46 / 96.94 / 90.40 ms**:
the original regression is not reproduced, but a 0.5% median reduction is small.
Ranges are 93.98-121.23 / 91.80-116.93 / 86.13-97.32 ms. The 10-member group
remains slower: 3.3% in the original run and 4.0% in this recheck, with mixed
signs in the paired before/current batches.
No stable group-Base speedup is claimed.

[Samples](evidence/common-performance-20260924-r6/explicit-recheck/recheck.json),
[replay](evidence/common-performance-20260924-r6/recheck-explicit.sh.txt),
[completion log](evidence/common-performance-20260924-r6/recheck-explicit.log.txt),
[exports](evidence/common-performance-20260924-r6/explicit-recheck/validation.tsv).

## Concurrent check

Eight independent root-bound clients each issue 1,000 indexed UID searches.
This separate CLI wall-clock measurement includes startup/Bind and excludes
warmup repeat 0. Medians use repeats 1, 2 and 3 with rotated endpoint order;
every UID/count is checked. It does not measure non-root concurrent throughput.

| Access configuration | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default | 197 ms | 228 ms | 221 ms | 96.9% | -15.7% |
| Explicit ACL | 267 ms | 229 ms | 256 ms | 111.8% | 14.2% |

All measured batches are retained. Default before/current/native samples are
197/197/195, 209/228/251 and 221/223/212 ms. Explicit samples are 286/267/222,
287/229/226 and 281/254/256 ms. Opposite directions across access modes and
three-batch variability do not support a uniform concurrent improvement.
[Default batches](evidence/common-performance-20260924-r6/default-final/concurrent.tsv),
[explicit batches](evidence/common-performance-20260924-r6/explicit-final/concurrent.tsv).

## Focused allocation profile

Separate before/current runs use the same SDK `memberEquality` workload:
10 warmup queries followed by 10,000 measured queries, with both reports showing
10,000 completed requests and successful cleanup. The heap comparison subtracts
each run's warm profile from its measured `alloc_space` profile and focuses
stacks containing `trySmallNonRootSearch`.

| Focused cumulative allocation | Before | Current | Reduction |
| --- | ---: | ---: | ---: |
| `trySmallNonRootSearch`, 10,000 member queries | 626.84 MiB | 267.03 MiB | 57.4% |

This is sampled cumulative allocation, not retained heap, RSS, per-operation
benchmark output or an SDK latency gain. The full harness includes Add and WhoAmI
setup/verification work; whole-process totals and percentages are not query-only
measurements. Only the focused allocation reduction is claimed.
The text reports label binary-megabyte units as `MB`; the table uses MiB.
No new component benchmark was run for R6.

[Before focused report](evidence/common-performance-20260924-r6/profile/query-alloc-before.txt),
[current focused report](evidence/common-performance-20260924-r6/profile/query-alloc-current.txt),
[before SDK report](evidence/common-performance-20260924-r6/profile/member-before-measured.json),
[current SDK report](evidence/common-performance-20260924-r6/profile/member-current-measured.json),
[profile helper](evidence/common-performance-20260924-r6/profile/profile_test.go.txt).
Raw CPU/heap profiles, warmup reports, overlay and completion logs are retained
in the [profile directory](evidence/common-performance-20260924-r6/profile/).

## Validation

The coordinator confirmed final full Go tests, vet and native differential
validation completed successfully after source/test freeze:

- [Accepted Go suite](evidence/common-performance-20260924-r6/go-test-accepted.txt)
  passes with `CGO_ENABLED=0`; some package results are reused from the Go test
  cache. The accepted schema package reports 1.861 seconds.
- [Accepted vet](evidence/common-performance-20260924-r6/go-vet-accepted.txt)
  completed successfully with no output; its empty log is expected.
- [Accepted native differential](evidence/common-performance-20260924-r6/openldap-differential-accepted.txt)
  records **355 PASS results**, no failures/skips, terminal PASS and a 9.540-second
  server-package result.
- Decoder tests cover full-capacity clearing, idle capacity/exclusive ownership,
  lazy acquisition, release on every exit, planning cancellation and concurrent
  stores/clones. Existing candidate/search ownership and fallback regressions
  remain passing.
- Assertion tests compare old/new normalized bytes and exact error types/text,
  length and syntax validation before cache reuse, aliases, schema mutation,
  output ownership, cache bounds, ordered assertions and custom callbacks.
- Earlier full-suite attempts caught in-progress pool-test fixtures and an
  incorrect invalid-UTF-8 rejection expectation. The old and cached assertion
  APIs both accept that tested input; the expectation was corrected. Those
  failed runs remain [diagnostics](evidence/common-performance-20260924-r6/diagnostics/),
  not successful final validation.
- Both main smoke reports and every main/recheck measured report have empty
  errors, complete repeat sequences, `completed == operations` and cleanup for
  all three endpoints.
- All **12 exports** match **100,002 entries, 42,712,438 canonical bytes and
  POSIX checksum `2143929969`**:
  [explicit](evidence/common-performance-20260924-r6/explicit-final/validation.tsv),
  [default](evidence/common-performance-20260924-r6/default-final/validation.tsv),
  [default recheck](evidence/common-performance-20260924-r6/default-recheck/validation.tsv),
  [explicit recheck](evidence/common-performance-20260924-r6/explicit-recheck/validation.tsv).

No race detector was used. This matrix does not establish full compatibility or
deployment capacity.

### Existing operational-attribute gap

The [R2 expanded differential](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
still records missing synthesized `entryDN` and `hasSubordinates` for ordinary
entries in the memory-store fixture, including root reads and `+` with types-only.
The same 40 leaf scenarios failed before and after that earlier optimization.
Those cases are outside the passing native matrix. R6 does not close this gap.

## Replay and identity

Local source: `/var/tmp/ldap-go-common-perf-20260924-r6`.
[Explicit replay](evidence/common-performance-20260924-r6/common-explicit.sh.txt),
[default replay](evidence/common-performance-20260924-r6/common-default.sh.txt),
[explicit completion](evidence/common-performance-20260924-r6/common-explicit.log.txt)
and [default completion](evidence/common-performance-20260924-r6/common-default.log.txt)
preserve setup, assertions, exports and cleanup. Both recheck completion logs
also report success. Paths refer to disposable fixture copies and the pinned
native installation; adjust them before replaying elsewhere.

The coordinator kept final endpoint timing separate from tests/builds and
profiling. Preparing these docs ran no tests, builds or benchmarks; the archived
focused text reports were copied from the coordinator's completed analysis.

Executable SHA-256, verified against the supplied local files:

```text
before (49af259)  dacceacf149cd9e8789790ee631bca362f6f6d1d8011f4b4e1e0f4c27b5735df
current           f65475df23fa7fa127f688dd6ee475263fdf978af437efecb9a5f009509a46e2
```

The JSON endpoint `current` means the R6 executable named `current`. Baseline
`before` is the R5 final executable, now associated with source `49af259`.
The [evidence index](evidence/common-performance-20260924-r6/README.md) records
provenance, calculation rules and diagnostic boundaries. Non-root concurrent
throughput, additional policies, TLS and larger group populations remain
qualification work. Older write/paging/memory results remain in the
[full-operation report](performance-optimization-20260923-round13.md).
