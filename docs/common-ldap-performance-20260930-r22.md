# R22: Base search DN validation

September 30, 2026; baseline `984ada3` (R21), 100,000 users, Apple M1 Pro,
Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13.

Implementation commit: `baf3811`, source-identical to the validated isolated
commit `4566990`.

**Common-operation parity remains unmet.** This round reduces allocations in
non-root Base presence search. Its paired network time decreases 2.0% with
default access, 1.2% with explicit ACL and 1.5% in a separate startup/port swap.
Other rows include slowdowns; no universal improvement is claimed.

## Current common operations

Seven batches of 1,000 calls per endpoint. Times are medians of summed timed
SDK requests; setup, identity checks and cleanup are outside timing. Frequency
is qualitative. Relative = `OpenLDAP/current * 100%`, with 100% meaning parity.

| Operation | Typical use | ldap-go, default | OpenLDAP, default | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 89.50 ms | 71.80 ms | 80.2% | 79.3% |
| Non-root Base, hot | High | 109.46 ms | 91.16 ms | 83.3% | 79.8% |
| Non-root equality, hot | Very high | 119.83 ms | 95.19 ms | 79.4% | 77.0% |
| Group1000 Compare, first | Medium | 114.86 ms | 88.82 ms | 77.3% | 78.1% |
| Group1000 Compare, last | Medium | 127.20 ms | 90.77 ms | 71.4% | 68.3% |
| Group1000 Compare, missing | Medium | 113.88 ms | 82.65 ms | 72.6% | 71.3% |

First/last is fixture insertion order, not assumed native storage order.
Group discovery, nested traversal, distributed reads and broad writes were not
rerun; older measurements in [R21](common-ldap-performance-20260930-r21.md),
[R19](common-ldap-performance.md) and their references remain historical.

## Paired change

Time reduction = `(1-current/before)*100%`, from unrounded values.

| Base search access/run | Before | Current | OpenLDAP | Time reduction | Relative |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default | 111.72 ms | 109.46 ms | 91.16 ms | 2.0% | 83.3% |
| Explicit ACL | 114.29 ms | 112.90 ms | 90.08 ms | 1.2% | 79.8% |
| Startup/port swap | 107.37 ms | 105.80 ms | 88.27 ms | 1.5% | 83.4% |

The swap is independent and is not pooled with primary statistics. Unchanged
paths include negative observations: SSHA Bind is 1.1% slower in both primary
runs; default equality is 0.8% slower; swap Group1000 missing Compare is 5.6%
slower. These are retained without assigning causality or dismissing them as
noise. Compare versions within a run, not ratios across rounds.

## Implementation and components

Only the guarded non-root Base `objectClass` presence path changes. It validates
the stored display DN against the already selected physical identity key using
the existing `ValidateDNWithIdentityKey`, then carries that key into scope
checking without constructing a parsed DN. The existing validator preserves
the full parser's errors and complex-input fallbacks. Reads, schema/normalizer
eligibility, snapshot checks, filter, ACL, projection and response order remain.

The production caller supplies a schema-normalized base. Neither old nor new
code recomputes matching-rule equality between the stored display spelling and
physical key; structurally valid stale hints retain the old behavior. Custom
stores/normalizers and ineligible requests continue through the general path.
No entry/result cache or on-disk representation changes.

Three alternating 500ms handler repeats use one local Bolt entry, no sockets,
and the same request/response validation. Allocation values below are from
the median-time sample; all repeats remain in the evidence.

| ACL / request spelling | Before ns/op | Current ns/op | Before B/op | Current B/op | Before allocs/op | Current allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Default / same | 25,033 | 22,456 | 15,992 | 14,560 | 322 | 273 |
| Default / alias and case | 24,948 | 22,524 | 16,376 | 14,944 | 352 | 303 |
| Explicit / same | 32,441 | 30,247 | 18,712 | 17,280 | 403 | 354 |
| Explicit / alias and case | 33,808 | 31,437 | 19,096 | 17,664 | 433 | 384 |

The separate same-process SDK/server Base benchmark removes 50 allocations
(496 to 446) and about 1.5 KB per call. Its median time is approximately flat
(95,328 to 95,169 ns/op), with wide individual observations. Allocation savings
and handler improvements are not substituted for end-to-end latency results.

## Validation and evidence

The new regression cases pass on both old and new implementations. They compare
complete SDK/wire results against the unchanged general handler, covering
stored/request spelling, OIDs/escapes, aliases, types-only projection, binary
and DN-valued attributes, ACL stages, parent rename, stale metadata, damaged
storage and custom callback/error ordering. Initial fixture assumptions were
corrected to match existing storage normalization and ACL behavior; production
semantics were not changed to satisfy those assertions.

Full Go tests passed (schema 98.100s, server 170.682s, storage 23.524s,
webadmin 0.289s), as did `go vet ./...` and 355 native differential checks
(11.072s). Static review found no change in downstream hint consumers or
error/ACL order under the production caller's normalized-base contract.

[Evidence](evidence/performance-20260930-r22/README.md) retains raw compressed
samples, source reconstruction, scripts and hashes. The final summary verifies
756 completed batches and nine exports, each matching 100,002 canonical
user-data entries. A preliminary default run had brief profile-report processing
during timing and is preserved separately, excluded from primary statistics.
Its three canonical exports also match. No race detector or CGO was used.

The pinned native reference and recovered data are unchanged from R20. No
physical MDB-layout, generated-operational-attribute or complete OpenLDAP
compatibility claim is made. Faster writes do not offset slower reads for the
per-operation acceptance goal.

```text
before  d337fbcdf8d6e8956332fe802fbc85abe966908aa52c0b34cf47fd27ff89c6d9
current e0a505e944ed1d598dc4aafbfb44a17ba13949a696dc23ebbeccf247f19b2d6f
```
