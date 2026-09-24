# Common LDAP performance qualification

September 24, 2026, fifth run: baseline `b7e6cc1`, final executable `final`,
OpenLDAP 2.6.13, 100,000 users, Apple M1 Pro, Go 1.26.4 with
`CGO_ENABLED=0`.

The final paired measurements show explicit-ACL hot Base/equality reductions of
**5.4%/8.7%** and direct-group discovery reductions of **38.6% with explicit ACLs
and 3.0% with default access**. Default hot user queries and SSHA Bind are largely
flat. The initial explicit distributed-equality median is **10.8% slower**;
a separate seven-repeat recheck does not reproduce that regression. The explicit
root-bound concurrent check is **16.8% slower**; a dedicated seven-batch recheck
reverses that median difference, with wide ranges and no stable speedup claim.
All original samples are retained.
**These results do not establish OpenLDAP parity or a uniform speedup.**

The [fourth run](common-ldap-performance-20260924-r4.md),
[third run](common-ldap-performance-20260924-r3.md),
[second run](common-ldap-performance-20260924-r2.md), and
[first run](common-ldap-performance-20260924-r1.md) retain previous evidence.
Compare implementations within each run; shared-host timing varies across runs.
The headline tables use only `explicit-final` and `default-final`.
The recheck and rejected buffer experiment are reported separately.

## Accepted changes

- The existing small non-root executor borrows value-slice descriptors in the
  proven pure default/batch ACL projection branches. Final selection still owns
  the returned descriptors and payload bytes before the storage callback ends.
- A prepared explicit selection skips unrequested attribute ACL evaluations in
  the pure batch branch and unrequested descriptor copying in the pure default
  branch. The full entry remains the ACL target. Alias/OID/subtype and stored
  option membership use the same prepared map as final selection. Nil selection
  preserves the old projection; unsafe policies, context callbacks, normalizers
  and remote mappings retain the full fallback and its callback ordering.
- Read-only password Bind helpers reuse a database pointer only when it is the
  published runtime database, the store is concrete local Bolt with known
  wrappers/normalization, and the read-only policy guards hold. RADIUS and
  unsupported configurations retain the former shallow database snapshot.
  **Both authentication storage Views and live verification remain unchanged.**
- The only Web Admin change is a deterministic test fixture: an already-expired
  parent request context replaces a nanosecond timeout racing an immediate fake
  write. Deadline/error-code and no-LDAP-write assertions remain. No Web Admin
  production behavior changed.

The R4 small-search admission, positive-size-limit ordering and bounded DN syntax
cache are baseline behavior, not new R5 changes. Password algorithms/work factors,
entry/filter authorization, selected-result accounting and unsafe fallbacks remain.
No attribute-read, authentication-result or ACL-decision cache was added.
The raw TCP read-buffer prototype was **rejected and removed from production and
active tests**; only diagnostic snapshots remain in the evidence archive.

## Measurement

The [SDK runner](../internal/cmd/ldapcommonbench/README.md) rotates endpoints per
request and checks exact responses, identities and fixture cleanup. Only SDK
Bind/Search calls are timed. Each main row is the median of three `total_ms`
batch samples grouped by access mode, batch, stage, method, member count and
endpoint. The separate distributed recheck uses seven repeats. No measured
outliers are discarded. [Calculated medians](evidence/common-performance-20260924-r5/medians.tsv)
retain all final, recheck and experiment groups, including plaintext Bind
diagnostics.

All three final endpoints use uid/member/objectClass equality indexes and the
same fixture: 100,000 users plus two containers. Hot user reads use
`scale-001001`; distributed reads sample 1,000 users across the 100k range.
Temporary groups contain exactly 10 or 1,000 real user DNs. Group Base rows are
separate `base_member_values` measurements for each member count. Nested
membership uses the same client BFS with cycle detection on every endpoint;
100 traversals issue 417 timed SDK searches. Other main rows have one timed SDK
call per operation.

The workload and request limits are unchanged: ordinary Base/UID reads use
`SizeLimit=len(want)+1=2`; nested group discovery uses
`SizeLimit=len(groups)+1=6`. SSHA and plaintext storage methods are never pooled.
Verification, connection setup and fixture cleanup are outside the SDK timer.
Transport is plaintext loopback LDAP. TLS and stronger password schemes need
separate equivalent measurements.

Relative performance is `OpenLDAP / current * 100%`: higher is better, 100% is
parity. Time reduction is `(1 - current / before) * 100%`; negative means a slower
observed median. Ratios use unrounded medians; tables show milliseconds to two
decimals and percentages to one. Changes rounding to zero are shown as 0.0%.
Usage frequency is qualitative for authentication/company directories, not
measured traffic; caching and connection pooling affect it.

## Explicit ACL

All endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 100.77 ms | 100.73 ms | 79.34 ms | 78.8% | 0.0% |
| Wrong password, SSHA | Low | 1,000 | 90.77 ms | 91.45 ms | 70.93 ms | 77.6% | -0.8% |
| Non-root Base, hot | High | 1,000 | 116.05 ms | 109.79 ms | 83.55 ms | 76.1% | 5.4% |
| Non-root equality, hot | Very high | 1,000 | 132.48 ms | 120.95 ms | 97.46 ms | 80.6% | 8.7% |
| Non-root Base, distributed | High | 1,000 | 147.35 ms | 141.36 ms | 91.23 ms | 64.5% | 4.1% |
| Non-root equality, distributed | Very high | 1,000 | 197.20 ms | 218.43 ms | 129.65 ms | 59.4% | -10.8% |
| Direct group discovery | High | 100 | 32.09 ms | 19.72 ms | 11.84 ms | 60.0% | 38.6% |
| Group Base, 10 members | Medium | 100 | 18.94 ms | 14.57 ms | 10.91 ms | 74.9% | 23.0% |
| Group Base, 1,000 members | Medium | 100 | 135.87 ms | 116.37 ms | 97.73 ms | 84.0% | 14.4% |
| Nested membership, client BFS | Medium-high | 100 traversals | 67.30 ms | 61.55 ms | 40.70 ms | 66.1% | 8.6% |

[Hot samples](evidence/common-performance-20260924-r5/explicit-final/hot.json),
[distributed samples](evidence/common-performance-20260924-r5/explicit-final/distributed.json),
[group samples](evidence/common-performance-20260924-r5/explicit-final/groups.json).

### Distributed recheck

The original equality result above remains **197.20 / 218.43 / 129.65 ms**
(before/current/OpenLDAP). It is not replaced by the following seven-repeat run,
which uses the same final binary, explicit ACL, methods, user distribution,
1,000 operations per batch and validation. Its medians are calculated separately.

| Workload | Repeats | Calls per batch | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Non-root Base, distributed | 7 | 1,000 | 131.86 ms | 124.44 ms | 81.53 ms | 65.5% | 5.6% |
| Non-root equality, distributed | 7 | 1,000 | 128.53 ms | 120.79 ms | 83.05 ms | 68.8% | 6.0% |

The initial equality regression was not reproduced; the recheck shows 5.6%/6.0%
less time for Base/equality. This does not erase the first observation or establish
stable performance across hosts. All three recheck exports match the source.
[Seven-repeat samples](evidence/common-performance-20260924-r5/explicit-distributed-recheck/queries.json),
[replay](evidence/common-performance-20260924-r5/recheck-distributed.sh.txt),
[validation](evidence/common-performance-20260924-r5/explicit-distributed-recheck/validation.tsv).

## Default access

No explicit ACL rules. The final executable, methods, counts and fixture match
the explicit-ACL run; access modes are summarized independently.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 118.12 ms | 115.10 ms | 91.92 ms | 79.9% | 2.6% |
| Wrong password, SSHA | Low | 1,000 | 88.65 ms | 90.61 ms | 72.62 ms | 80.1% | -2.2% |
| Non-root Base, hot | High | 1,000 | 106.00 ms | 106.38 ms | 81.51 ms | 76.6% | -0.4% |
| Non-root equality, hot | Very high | 1,000 | 110.48 ms | 110.49 ms | 82.17 ms | 74.4% | 0.0% |
| Non-root Base, distributed | High | 1,000 | 126.85 ms | 122.47 ms | 85.58 ms | 69.9% | 3.5% |
| Non-root equality, distributed | Very high | 1,000 | 262.68 ms | 255.48 ms | 142.88 ms | 55.9% | 2.7% |
| Direct group discovery | High | 100 | 21.56 ms | 20.92 ms | 13.23 ms | 63.2% | 3.0% |
| Group Base, 10 members | Medium | 100 | 15.92 ms | 14.92 ms | 11.74 ms | 78.7% | 6.3% |
| Group Base, 1,000 members | Medium | 100 | 108.79 ms | 107.18 ms | 98.62 ms | 92.0% | 1.5% |
| Nested membership, client BFS | Medium-high | 100 traversals | 71.97 ms | 69.23 ms | 46.36 ms | 67.0% | 3.8% |

[Hot samples](evidence/common-performance-20260924-r5/default-final/hot.json),
[distributed samples](evidence/common-performance-20260924-r5/default-final/distributed.json),
[group samples](evidence/common-performance-20260924-r5/default-final/groups.json).

SSHA wrong-password Bind is 0.8%-2.2% slower in the two main runs. Default hot
Base/equality do not show an improvement. The 1,000-member Base medians reach
84.0%-92.0% of native performance; that is not a parity claim.

## Concurrent check

Eight independent root-bound clients each issue 1,000 indexed UID searches.
This separate CLI wall-clock measurement includes startup/Bind, excludes the
`repeat=0` warmup, and takes medians of repeats 1, 2 and 3 with rotated endpoint
order. Every returned UID and count is checked. It does not measure non-root
concurrent throughput.

| Access configuration | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default | 220 ms | 218 ms | 234 ms | 107.3% | 0.9% |
| Explicit ACL | 191 ms | 223 ms | 214 ms | 96.0% | -16.8% |

The explicit samples are before 282/186/191 ms, current 256/204/223 ms, and
OpenLDAP 259/206/214 ms. The slower current median is retained without a speedup
claim. The default difference is small.
[Default batches](evidence/common-performance-20260924-r5/default-final/concurrent.tsv),
[explicit batches](evidence/common-performance-20260924-r5/explicit-final/concurrent.tsv).

### Dedicated concurrent recheck

A separate explicit-ACL run used fresh instances of the same three servers,
normal warmup and seven measured batches of the same eight clients and 1,000 UID
queries per client. Endpoint order rotated and every UID/count was checked.
No group fixture preceded this run, avoiding possible carryover from its cleanup.
Warmup repeat 0 is excluded; the original table above is unchanged.

| Access configuration | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Explicit ACL, seven-batch recheck | 292 ms | 276 ms | 259 ms | 93.8% | 5.5% |

Measured ranges are **195-419 / 196-568 / 203-355 ms** for
before/current/OpenLDAP. The original 16.8% median regression did not persist in
this recheck, but the wide ranges do not support a stable concurrent speedup.
The two runs remain separate and all three recheck exports match the source.
[Raw batches](evidence/common-performance-20260924-r5/concurrent-recheck/concurrent.tsv),
[export validation](evidence/common-performance-20260924-r5/concurrent-recheck/validation.tsv),
[replay](evidence/common-performance-20260924-r5/recheck-concurrent.sh.txt),
[completion log](evidence/common-performance-20260924-r5/recheck-concurrent.log.txt).

## Rejected buffer experiment

The earlier four-endpoint runs compared baseline `before`, the buffer-bearing
prototype named `current`, an earlier `projection` build without that listener
buffer, and `openldap`. These are **diagnostic measurements**, not final R5
results. In particular, the experiment's `current` is a different executable
from the final tables' `current`, which maps to `final`.

The buffer was rejected. Its production file, CLI integration and active tests
were removed; it contributes nothing to the final implementation. The archive
retains both access-mode experiments, smoke checks, concurrent/export results,
replay scripts/logs, the projection overlay and
[discarded source snapshots](evidence/common-performance-20260924-r5/diagnostics/discarded-buffer/).
Former buffer correctness/read-count results are diagnostics only.

[Explicit experiment](evidence/common-performance-20260924-r5/diagnostics/explicit-experiment/hot.json),
[default experiment](evidence/common-performance-20260924-r5/diagnostics/default-experiment/hot.json),
[diagnostic index](evidence/common-performance-20260924-r5/README.md#diagnostics).
No four-endpoint sample is pooled into a final three-endpoint median.

## Component evidence

The completed [component benchmark](evidence/common-performance-20260924-r5/component-bench.txt)
has two samples per case and a terminal PASS. These observations isolate local
allocation/work differences; they are **not SDK latency or throughput claims**.

- The two-View Bind component uses 10,040 B/op and 145 allocs/op with eligible
  pointer reuse versus 12,088 B/op and 147 allocs/op with the legacy copy.
  Two-sample midpoint times are about 11.1 versus 11.5 microseconds/op.
  Both storage Views are executed in both variants.
- Borrowing with an explicit value-independent ACL and a `cn`-only selection
  uses 2,832 B/op and 69 allocs/op versus 76,776-76,777 B/op and 78 allocs/op.
  The two times are 12.747/12.761 versus 51.167/33.365 microseconds/op.
- The corresponding default-access `cn` case uses 1,632 B/op and 42 allocs/op
  versus 75,576-75,577 B/op and 51 allocs/op; times are 7.395/7.760 versus
  23.303/24.148 microseconds/op.

One projection benchmark operation processes **three 1,000-member group entries**
and performs final owning selection. It passes nil as the optional projection
selection, so it isolates descriptor borrowing rather than the new skipped-ACL
selection. The raw `cn,member` samples are retained too; requested member payloads
still require ownership copies and their timing varies.

## Validation

The coordinating run confirmed final full-suite, vet and native validation
completed with exit status 0:

- [Full Go suite](evidence/common-performance-20260924-r5/go-test-optimized.txt)
  passes with `CGO_ENABLED=0`; the server package reports 144.059 seconds.
- [Vet](evidence/common-performance-20260924-r5/go-vet-optimized.txt) completed
  successfully with no output; the empty log is expected.
- [Native differential](evidence/common-performance-20260924-r5/openldap-differential-optimized.txt)
  records 355 PASS results including subtests, zero failures/skips, and terminal PASS.
- Projection differential tests cover aliases/OIDs/subtypes, stored options,
  `1.1`, denied-only and empty/types-only results, full-entry ACL dependencies,
  unchanged unsafe callback traces, and final payload ownership after source
  overwrite. Existing small-search limit/freshness coverage remains passing.
- Database-pointer checks cover published versus detached configuration,
  unsupported readers/normalizers and callback cases, and live authentication
  behavior across the two existing snapshots.
- The Web Admin nanosecond fixture race failed on the pristine baseline in a
  100-repeat check, then the expired-parent-context fixture passed 100 repeats.
  [Baseline failure](evidence/common-performance-20260924-r5/diagnostics/webadmin-deadline-baseline.txt),
  [fixed check](evidence/common-performance-20260924-r5/diagnostics/webadmin-deadline-fixed.txt).
  The earlier focused recheck failure is preserved too; it was not a passing run.
- Both final [explicit](evidence/common-performance-20260924-r5/explicit-final/smoke.json)
  and [default](evidence/common-performance-20260924-r5/default-final/smoke.json)
  smoke reports and all final/recheck measured reports have empty errors,
  `completed == operations`, and cleanup for all three endpoints.
- All **12 exports** (six main, three distributed recheck and three concurrent
  recheck) match: **100,002 entries,
  42,712,438 canonical bytes, POSIX checksum `2143929969`**.
  [Explicit](evidence/common-performance-20260924-r5/explicit-final/validation.tsv),
  [default](evidence/common-performance-20260924-r5/default-final/validation.tsv),
  [distributed recheck](evidence/common-performance-20260924-r5/explicit-distributed-recheck/validation.tsv),
  [concurrent recheck](evidence/common-performance-20260924-r5/concurrent-recheck/validation.tsv).

No race detector was used. This matrix does not establish full compatibility or
deployment capacity.

### Existing operational-attribute gap

All previously recorded qualification gaps remain reference limitations. This
round does not implement missing synthesized `entryDN` or `hasSubordinates` in
the ordinary memory-store fixture. The
[R2 expanded differential](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
records the same 40 failures before and after that round's optimization.
Those cases are outside the passing native matrix. Neither the R4 admission
guards nor the R5 projection changes close that gap.

## Replay and identity

Local root: `/var/tmp/ldap-go-common-perf-20260924-r5`.
[Explicit replay](evidence/common-performance-20260924-r5/final-explicit.sh.txt)
and [default replay](evidence/common-performance-20260924-r5/final-default.sh.txt)
retain exact setup, assertions, exports and cleanup. Their
[explicit](evidence/common-performance-20260924-r5/final-explicit.log.txt) and
[default](evidence/common-performance-20260924-r5/final-default.log.txt)
logs record successful completion, as does the
[recheck log](evidence/common-performance-20260924-r5/recheck-distributed.log.txt).
Paths refer to disposable fixture copies and the pinned native installation;
adjust them before replaying elsewhere. The coordinator confirmed that tests and
builds did not overlap the final timed endpoint benchmarks, all processes have
finished, and the component benchmark ran separately afterward.

Executable SHA-256, verified against the supplied files:

```text
before (b7e6cc1)  bf22f861ebe6a5e2eebfaea08bf11ed42f3acee4c9cf997760d3747786e322c4
final             dacceacf149cd9e8789790ee631bca362f6f6d1d8011f4b4e1e0f4c27b5735df
```

The JSON endpoint label `current` in the final/recheck scripts means `final`,
not the rejected experimental executable named `current`.
The [evidence index](evidence/common-performance-20260924-r5/README.md) records
provenance, calculations and diagnostic boundaries. Non-root concurrent
throughput, additional policies, TLS and larger group populations remain
qualification work. Older write/paging/memory results stay in the
[full-operation report](performance-optimization-20260923-round13.md); they were
not remeasured here.
