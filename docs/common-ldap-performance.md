# Common LDAP performance qualification

September 24, 2026, fourth run: baseline `aaf8350`, final `current-sized`
binary, OpenLDAP 2.6.13, 100,000 users, Apple M1 Pro, Go 1.26.4 with
`CGO_ENABLED=0`.

Against that baseline in the final same-SDK run, SSHA Bind takes **7.6%-9.9%
less time**, ordinary non-root Base/equality queries 3.3%-9.5% less, direct group
discovery 6.3%-9.2% less, and client-side nested membership 6.3%-7.8% less.
Direct group discovery still reaches only 52.5%-62.7% of native performance.
**The OpenLDAP parity goal remains unmet.**

The [third run](common-ldap-performance-20260924-r3.md),
[second run](common-ldap-performance-20260924-r2.md), and
[first run](common-ldap-performance-20260924-r1.md) retain previous evidence.
Compare implementations within a run; shared-host timing varies across runs.
All current results below come from `explicit-sized` and `default-sized`.
The initial R4 attempt is retained separately as diagnostic evidence.

## Changes

- A small non-root search path handles ordinary local Base
  `(objectClass=*)` reads and indexed equality searches with at most **four raw
  postings**. The bound includes candidates outside scope or denied by ACL.
  It reads a current Bolt snapshot with ready indexes, evaluates live base,
  filter, entry and attribute ACLs, and copies selected output before borrowed
  storage data expires. It publishes no non-root result, base-entry or
  authorization cache.
- Admission requires a bound LDAPv3 session, the concrete local Bolt store and
  known wrappers, one route, and a safe schema/ACL/projection configuration.
  Controls, including an empty controls field, operational/collective filter
  attributes, wildcard or unsupported selections, alias dereferencing,
  configured database limits, time limits, unsafe overlays and custom
  stores/readers retain the general path. Missing/special entries and
  speculative read errors also fall back without output. Explicit
  option-qualified selections retain the general path.
- Positive request size limits are supported. After filtering, ACL evaluation
  and projection, the next surviving entry causes size overflow **before**
  reserving its candidate bytes. Previously selected entries accompany
  `sizeLimitExceeded`. Candidate/process-memory failures return no entries;
  reservations are released and a process rejection is counted only once.
  Negative request size limits remain ineligible.
- Password-policy DN normalization reuses the existing bounded
  `runtimeLegacyDNCache` for syntax parsing only. Its limits remain 128 successful
  inputs, 1 KiB per input, depth 32, and an estimated 1 MiB. Schema and reader DN
  normalization still run. Invalid syntax is not cached; no credentials,
  password results or ACL decisions are cached.

The two authentication snapshot checks, password algorithms and work factors
are unchanged. The search dispatch and bounded borrowing changes support the
small-search path; the Bind change is limited to DN syntax parsing.

## Measurement

The [SDK runner](../internal/cmd/ldapcommonbench/README.md) rotates endpoints per
request and validates exact responses, identities and fixture cleanup. Only SDK
Bind/Search calls are timed. Each table row uses the median of three
`total_ms` batch samples for the same access mode, batch, stage, method,
member count and endpoint. SSHA and plaintext methods are kept separate;
10-member and 1,000-member group rows are never pooled. No measured outliers
are discarded. [Calculated medians](evidence/common-performance-20260924-r4/medians.tsv)
retain the values used for rounding and ratios.

Both endpoints have uid/member/objectClass equality indexes. Source data contains
100,000 users and two containers. Temporary groups contain 10 or 1,000 real user
DNs. Distributed queries sample 1,000 users across the 100k range. Nested membership
uses the same client BFS, including a cycle, on every endpoint; each measured
100-traversal batch performs 417 SDK searches.

The workload is unchanged: ordinary Base/UID searches request
`SizeLimit=len(want)+1=2`; nested group discovery requests
`SizeLimit=len(groups)+1=6`. Fixing fast-path admission did not change the SDK
runner, request limits, expected results, indexes, ACLs or measured call counts.

Transport is plaintext loopback LDAP; headline Bind uses SSHA. Plaintext password
storage is a separate diagnostic in the raw reports and median data. TLS and
stronger password schemes require separate equivalent measurement.

Relative performance is `OpenLDAP / current * 100%`: higher is better, 100% is
parity. Time reduction is `(1 - current / before) * 100%`; negative means a slower
observed median. Ratios use unrounded medians. Usage frequency is qualitative for
authentication/company directories, not measured traffic; caching and connection
pooling change it.

## Explicit ACL

Both servers use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 94.82 ms | 87.61 ms | 67.96 ms | 77.6% | 7.6% |
| Wrong password, SSHA | Low | 1,000 | 92.28 ms | 84.79 ms | 67.83 ms | 80.0% | 8.1% |
| Non-root Base, hot | High | 1,000 | 117.10 ms | 107.34 ms | 77.11 ms | 71.8% | 8.3% |
| Non-root equality, hot | Very high | 1,000 | 118.15 ms | 112.29 ms | 78.84 ms | 70.2% | 5.0% |
| Non-root Base, distributed | High | 1,000 | 133.73 ms | 124.88 ms | 77.52 ms | 62.1% | 6.6% |
| Non-root equality, distributed | Very high | 1,000 | 131.33 ms | 126.95 ms | 80.18 ms | 63.2% | 3.3% |
| Direct group discovery | High | 100 | 23.51 ms | 21.34 ms | 11.21 ms | 52.5% | 9.2% |
| Group Base, 10 members | Medium | 100 | 15.57 ms | 14.51 ms | 9.71 ms | 66.9% | 6.8% |
| Group Base, 1,000 members | Medium | 100 | 90.14 ms | 86.31 ms | 80.13 ms | 92.8% | 4.2% |
| Nested membership, client BFS | Medium-high | 100 traversals | 62.45 ms | 58.52 ms | 38.11 ms | 65.1% | 6.3% |

[Hot samples](evidence/common-performance-20260924-r4/explicit-sized/hot.json),
[distributed samples](evidence/common-performance-20260924-r4/explicit-sized/distributed.json),
[group samples](evidence/common-performance-20260924-r4/explicit-sized/groups.json).

## Default access

No explicit ACL rules. The same final implementation and SDK workload are used.

| Workload | Typical use | Calls | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 95.65 ms | 86.14 ms | 68.59 ms | 79.6% | 9.9% |
| Wrong password, SSHA | Low | 1,000 | 91.70 ms | 84.35 ms | 67.82 ms | 80.4% | 8.0% |
| Non-root Base, hot | High | 1,000 | 124.24 ms | 112.90 ms | 84.84 ms | 75.1% | 9.1% |
| Non-root equality, hot | Very high | 1,000 | 126.18 ms | 114.47 ms | 87.58 ms | 76.5% | 9.3% |
| Non-root Base, distributed | High | 1,000 | 130.14 ms | 117.78 ms | 78.32 ms | 66.5% | 9.5% |
| Non-root equality, distributed | Very high | 1,000 | 120.28 ms | 114.34 ms | 80.88 ms | 70.7% | 4.9% |
| Direct group discovery | High | 100 | 18.16 ms | 17.02 ms | 10.66 ms | 62.7% | 6.3% |
| Group Base, 10 members | Medium | 100 | 13.05 ms | 11.83 ms | 8.77 ms | 74.1% | 9.3% |
| Group Base, 1,000 members | Medium | 100 | 88.95 ms | 84.49 ms | 80.66 ms | 95.5% | 5.0% |
| Nested membership, client BFS | Medium-high | 100 traversals | 57.54 ms | 53.03 ms | 36.51 ms | 68.8% | 7.8% |

[Hot samples](evidence/common-performance-20260924-r4/default-sized/hot.json),
[distributed samples](evidence/common-performance-20260924-r4/default-sized/distributed.json),
[group samples](evidence/common-performance-20260924-r4/default-sized/groups.json).

The 1,000-member Base medians improve by 4.2%-5.0% in this run, reaching
92.8%-95.5% of native performance. This is a three-batch observation, not a parity
claim. The earlier large-group recheck remains in the archived R3 report.

## Concurrent check

Eight independent root-bound clients each issue 1,000 indexed uid searches.
This separate CLI wall-clock test includes startup/Bind, one excluded warmup
batch (`repeat=0`) and three measured batches with rotated endpoint order.
Every returned UID and result count is checked. It does not establish non-root
concurrent throughput.

| Access configuration | Before | Current | OpenLDAP | Relative | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default | 188 ms | 187 ms | 208 ms | 111.2% | 0.5% |
| Explicit ACL | 190 ms | 186 ms | 208 ms | 111.8% | 2.1% |

No material concurrent speedup is claimed from these small baseline/current
differences. The explicit native samples include 330, 208 and 205 ms; the 330 ms
sample remains in the evidence and the median is 208 ms.
[Default batches](evidence/common-performance-20260924-r4/default-sized/concurrent.tsv),
[explicit batches](evidence/common-performance-20260924-r4/explicit-sized/concurrent.tsv).

## Initial R4 diagnostic

The first `current` prototype rejected every measured search because it required
`request.SizeLimit == 0`. The real SDK supplied positive limits, so direct unit
tests proving `handled=true` with zero limits did not prove admission for this
workload. The initial timings do not measure the accepted small-search path.

The production fix accepts positive limits and implements the general visitor's
partial-result and memory-error ordering. Only the implementation changed;
the final replay scripts differ from the first attempt in output directory and
current executable path. Positive-limit SDK differential tests now prove that
eligible Base/UID/member requests are actually handled.

The initial explicit-ACL results are retained in
[diagnostic hot](evidence/common-performance-20260924-r4/diagnostics/explicit-final/hot.json),
[distributed](evidence/common-performance-20260924-r4/diagnostics/explicit-final/distributed.json),
[group](evidence/common-performance-20260924-r4/diagnostics/explicit-final/groups.json)
and [median data](evidence/common-performance-20260924-r4/medians.tsv), with smoke,
concurrent, export and replay evidence alongside them. They are **not accepted
current measurements**. Their ordinary search changes ranged from -0.8% to 2.5%;
direct group discovery was 1.2% slower.

Both initial replay scripts are archived:
[explicit](evidence/common-performance-20260924-r4/diagnostics/common-explicit-final.sh.txt),
[default](evidence/common-performance-20260924-r4/diagnostics/common-default-final.sh.txt).
No `default-final` result directory or raw measurements were present in the
supplied R4 source tree; no initial default-ACL numbers are inferred or substituted.

## Validation

Final validation commands completed with exit status 0, confirmed by the
coordinating run:

- [Full Go tests](evidence/common-performance-20260924-r4/go-test-sized.txt)
  pass with `CGO_ENABLED=0`; the server package reports 136.749 seconds.
- [Vet](evidence/common-performance-20260924-r4/go-vet-sized.txt) exits 0 with no
  output. The empty log is expected; completion was confirmed separately.
- [Native differential](evidence/common-performance-20260924-r4/openldap-differential-sized.txt)
  records 355 PASS results including subtests, no skips, and a terminal PASS.
- New search tests compare complete wire/SDK responses with the old general
  handler using the same prelude and assert fast-path handling. They cover
  positive limits, 0/1/4/5 raw postings, scope and ACL denials, disclose semantics,
  synthesized filters and aliases, controls, custom callbacks, missing/special
  entries, exact memory boundaries and rejection counts, write failures, live
  writes/rebinds, existing paging/transaction state and cancellation inside a
  concrete Bolt view.
- DN syntax-cache checks retain malformed/oversized-input behavior, schema/reader
  normalization and live authentication checks.
- Both [explicit](evidence/common-performance-20260924-r4/explicit-sized/smoke.json)
  and [default](evidence/common-performance-20260924-r4/default-sized/smoke.json)
  SDK smoke runs complete with cleanup and no reported errors. All timed JSON
  samples complete their requested operations.
- All six final ordinary-attribute exports after cleanup match the source:
  100,002 entries, 42,712,438 canonical bytes, POSIX checksum `2143929969`.
  [Default exports](evidence/common-performance-20260924-r4/default-sized/validation.tsv),
  [explicit exports](evidence/common-performance-20260924-r4/explicit-sized/validation.tsv).

No race detector was used. Full compatibility or deployment capacity is not
established by this matrix.

### Existing operational-attribute gap

This round does not implement missing synthesized `entryDN` or
`hasSubordinates` in the ordinary memory-store fixture. The
[R2 expanded differential](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
records the same 40 failures before and after that round's optimization.
Those cases are not included in the passing native matrix or a full compatibility
claim. Rejecting synthesized filters from the new shortcut does not close that gap.

## Replay

Local root: `/var/tmp/ldap-go-common-perf-20260924-r4`.
[Default replay](evidence/common-performance-20260924-r4/common-default-sized.sh.txt)
and [explicit replay](evidence/common-performance-20260924-r4/common-explicit-sized.sh.txt)
retain setup, assertions, exports and cleanup. Their
[default](evidence/common-performance-20260924-r4/common-default-sized.log.txt) and
[explicit](evidence/common-performance-20260924-r4/common-explicit-sized.log.txt)
terminal logs record successful completion. Paths refer to disposable copies of
the existing 100k fixture and the pinned native installation; adjust them before
running elsewhere. Tests/builds did not run concurrently with timed benchmarks.
Temporary servers were stopped and source snapshots were unchanged.

Executable SHA-256, verified against the supplied files:

```text
before (aaf8350)  c73d07d1e70afc60030999f9fe001b1b420cfd88dc9fa92dcb4e4dd6a8fec258
current-sized    bf22f861ebe6a5e2eebfaea08bf11ed42f3acee4c9cf997760d3747786e322c4
```

The [evidence index](evidence/common-performance-20260924-r4/README.md) records
source locations, calculations and the missing initial default-ACL output.
Non-root concurrent throughput, additional policies, TLS and larger group
populations remain qualification work. Older write/paging/memory measurements
remain in the [full-operation report](performance-optimization-20260923-round13.md);
they were not remeasured in this round.
