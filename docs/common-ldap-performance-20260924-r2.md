<!-- Historical second run; current results are in common-ldap-performance.md. -->
# Common LDAP performance qualification

Measured September 24, 2026 (second run), against baseline `e07231f` and
OpenLDAP 2.6.13 on Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`.

Explicit-ACL group discovery takes **88.8% less time**, a 1,000-member group read
77.5% less, and client-side nested membership 74.0% less than the baseline in
this run. Common explicit-ACL Base/equality queries improve by 15.4%-16.8%.
SSHA Bind improves by 3.4%-4.8% across the two access configurations.
**The four-operation OpenLDAP parity goal remains unmet.** These measurements
do not establish a speedup for every workload.

The [first run](common-ldap-performance-20260924-r1.md) is retained with its
original baseline and evidence. Compare before/current within one run; absolute
times vary on the shared host.

## Changes and boundaries

Attribute projection now evaluates a proven value-independent ACL once per
attribute, using the existing evaluator and full entry. This also avoids repeated
root/context checks after establishing a stable non-root identity. Authorization
is never retained across attributes, entries, requests or policy reloads.

The proof scans all global and database rules on each call. Value selectors,
target filters, self-value grants, group/dnattr/set/ACI matchers and unknown matcher
kinds retain the old path. Remote ACL mappings, custom context callbacks, custom
normalizers and relay/rwm configurations also retain the old path. Root-DSE
exceptions, rule ordering, stop/continue/break, SSF, real identities, types-only
responses and borrowed value-byte ownership are preserved. OpenLDAP's own
`servers/slapd/acl.c` also reuses per-attribute access results when the ACL state
has no value dependency; this implementation uses a narrower applicability proof.

The request queue no longer broadcasts to all idle workers after completing or
discarding an operation when the queue is open and empty. Enqueue signaling,
pending-work broadcasts, close/drain wakeups, fences, limits and retained-byte
accounting are preserved. Password algorithms, work factors, authentication
snapshots and verification are unchanged.

## Method

The [repository SDK runner](../internal/cmd/ldapcommonbench/README.md) rotates
endpoints after each request, checks exact responses and identities, and removes
only its owned temporary fixture. Only SDK Bind/Search calls are timed.
Tables show medians of three batches on one warmed process per implementation;
no measured outliers are discarded.

The source fixture has 100,000 users and two containers. Both servers have
uid/objectClass/member equality indexes. Hot queries target one user; distributed
queries span 1,000 users across the 100k range. Groups contain 10 or 1,000 distinct
real user DNs. Nested membership uses the same client BFS, including a cycle,
on both endpoints; it is not a native transitive LDAP operation.

Transport is plaintext loopback LDAP. Headline Bind rows use SSHA; plaintext
password storage is a separate diagnostic in the raw files. TLS and stronger
password schemes need equivalent separate qualification.

Relative performance is `OpenLDAP / current * 100%`: higher is better, 100% is
parity. Time reduction is `(1 - current / before) * 100%`; negative means a slower
observed median.

## Explicit ACL

Both endpoints use:

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

| Workload | Calls | Before | Current | OpenLDAP | Relative performance | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 1,000 | 110.12 ms | 106.37 ms | 73.96 ms | 69.5% | 3.4% |
| Wrong password, SSHA | 1,000 | 108.63 ms | 102.35 ms | 74.11 ms | 72.4% | 5.8% |
| Non-root Base, hot | 1,000 | 169.10 ms | 141.96 ms | 90.54 ms | 63.8% | 16.0% |
| Non-root equality, hot | 1,000 | 152.91 ms | 127.21 ms | 83.26 ms | 65.5% | 16.8% |
| Non-root Base, distributed | 1,000 | 169.51 ms | 143.26 ms | 84.81 ms | 59.2% | 15.5% |
| Non-root equality, distributed | 1,000 | 165.25 ms | 139.81 ms | 89.47 ms | 64.0% | 15.4% |
| Direct group discovery | 100 | 386.48 ms | 43.30 ms | 16.72 ms | 38.6% | 88.8% |
| Group Base, 10 members | 100 | 21.32 ms | 15.33 ms | 9.25 ms | 60.4% | 28.1% |
| Group Base, 1,000 members | 100 | 462.86 ms | 103.96 ms | 88.03 ms | 84.7% | 77.5% |
| Nested membership, client BFS | 100 traversals | 458.41 ms | 119.30 ms | 59.96 ms | 50.3% | 74.0% |

[Hot samples](evidence/common-performance-20260924-r2/explicit-hot.json),
[distributed samples](evidence/common-performance-20260924-r2/explicit-distributed.json),
[group samples](evidence/common-performance-20260924-r2/explicit-groups.json).

The largest remaining measured gap is direct group discovery. Batching ACLs
removes repeated member authorization, but does not eliminate the other entry
read, filter and response costs. Results for this policy do not imply the same
gain for value-dependent or dynamic policies.

## Default access

No explicit ACL rules. The previous default-policy projection optimization
already applies, so the new value batching does not replace this path.

| Workload | Calls | Before | Current | OpenLDAP | Relative performance | Time reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 1,000 | 109.57 ms | 104.34 ms | 73.18 ms | 70.1% | 4.8% |
| Wrong password, SSHA | 1,000 | 109.21 ms | 102.95 ms | 71.45 ms | 69.4% | 5.7% |
| Non-root Base, hot | 1,000 | 130.16 ms | 121.49 ms | 85.70 ms | 70.5% | 6.7% |
| Non-root equality, hot | 1,000 | 122.08 ms | 120.42 ms | 87.55 ms | 72.7% | 1.4% |
| Non-root Base, distributed | 1,000 | 146.28 ms | 146.61 ms | 94.26 ms | 64.3% | -0.2% |
| Non-root equality, distributed | 1,000 | 139.95 ms | 141.02 ms | 96.66 ms | 68.5% | -0.8% |
| Direct group discovery | 100 | 35.20 ms | 31.17 ms | 11.53 ms | 37.0% | 11.5% |
| Group Base, 10 members | 100 | 13.66 ms | 14.01 ms | 9.52 ms | 68.0% | -2.6% |
| Group Base, 1,000 members | 100 | 101.04 ms | 100.23 ms | 88.19 ms | 88.0% | 0.8% |
| Nested membership, client BFS | 100 traversals | 77.19 ms | 76.30 ms | 40.21 ms | 52.7% | 1.2% |

[Hot samples](evidence/common-performance-20260924-r2/default-hot.json),
[distributed samples](evidence/common-performance-20260924-r2/default-distributed.json),
[group samples](evidence/common-performance-20260924-r2/default-groups.json).

Default distributed reads and the 10-member group read have medians 0.2%-2.6%
higher in this run. These small differences do not demonstrate a regression or a
universal improvement; shared-host variation is visible in the retained samples.

## Concurrent regression check

Eight independent root-bound clients each issue 1,000 indexed uid searches.
This is a separate wall-clock CLI test, including client startup/Bind. One
explicit warmup batch is followed by three measured batches, with endpoint order
rotated. Every client must return all 1,000 exact UIDs in request order.
It is not evidence of non-root concurrent throughput.

| Access configuration | Before | Current | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: | ---: |
| Default | 194 ms | 191 ms | 212 ms | 111.0% |
| Explicit ACL | 188 ms | 190 ms | 203 ms | 106.8% |

The baseline/current differences here are small; no concurrent speedup is claimed.
[Default batches](evidence/common-performance-20260924-r2/default-concurrent.tsv),
[explicit batches](evidence/common-performance-20260924-r2/explicit-concurrent.tsv).

## Validation

- [Full Go tests](evidence/common-performance-20260924-r2/go-test.txt) and [vet](evidence/common-performance-20260924-r2/go-vet.txt) pass.
  All builds/tests use `CGO_ENABLED=0`; no race detector was used.
- [204 existing native checks, including subtests](evidence/common-performance-20260924-r2/openldap-differential.txt)
  pass, including ACL selectors, connection rules, ACI, groups and proxy ACL
  attribute dependencies.
- [144 new native leaf scenarios](evidence/common-performance-20260924-r2/openldap-value-batch.txt) pass
  (151 PASS records including containers). They cover value-independent explicit
  ACLs, identity rebinding, multivalued entries/groups, password/attribute denies,
  types-only, named operational attributes and `1.1`.
- Old/new projection oracle tests preserve output shape, ownership, callbacks,
  dynamic/value-dependent fallbacks and policy changes. Queue tests cover idle
  wakeups, parallel admission, fences, close/drain and byte accounting.
- All six full ordinary-attribute exports after fixture cleanup equal the source:
  100,002 entries, 42,712,438 canonical bytes, POSIX checksum `2143929969`.
  [Default checks](evidence/common-performance-20260924-r2/default-validation.tsv),
  [explicit checks](evidence/common-performance-20260924-r2/explicit-validation.tsv).

The [component benchmark](evidence/common-performance-20260924-r2/projection-bench.txt) compares the old per-value
projection with the new implementation in one process. For the simple explicit
policy and 1,000-member group, median projection time is 2,622,370 ns versus
8,779 ns; allocations are 13,068 versus 26. This component-only difference is
not an end-to-end throughput multiplier.

### Existing operational-attribute gap

An expanded native matrix found missing synthesized `entryDN` and
`hasSubordinates` for ordinary entries in the memory-store fixture, including
root reads and `+` with types-only. This is a real attribute-presence mismatch.

Replaying the same expanded test with baseline `e07231f` production files and
with the optimized files fails the **same 40 leaf scenarios**. Those failures
are not included in the passing 144-case claim. The performance change preserves
this pre-existing behavior; full operational-attribute parity remains open.
[Baseline failure log](evidence/common-performance-20260924-r2/operational-gap-before.txt),
[current failure log](evidence/common-performance-20260924-r2/operational-gap-current.txt),
[expanded test source](evidence/common-performance-20260924-r2/operational-gap_test.go.txt).
The baseline overlay restores both modified server production files; the new
policy proof helper is present only to check test eligibility.

## Reproduction

Local replay root: `/var/tmp/ldap-go-common-perf-20260924-r2`.
[Default replay](evidence/common-performance-20260924-r2/default-replay.sh.txt) and
[explicit replay](evidence/common-performance-20260924-r2/explicit-replay.sh.txt) retain exact setup, timed commands,
concurrent assertions, exports and cleanup. Paths refer to disposable local
copies of the existing 100k fixture and the pinned native environment. Adjust
those paths before rerunning elsewhere; use the repository SDK runner for new
fixtures. Tests and builds did not run concurrently with timed benchmarks. Temporary servers
were stopped and source snapshots were not modified.

Accepted executable SHA-256:

```text
before  0e14fa9d6f77f4581740a4d153c8864f93b9d65482708d2c46a1c2795c151f65
current 12e88eae35f7ed42e478e0f758c93f48721a47754e10a5fc983d05a35838a214
```

Additional policies, non-root concurrent throughput, TLS and larger group
populations remain qualification work. The
[older full-operation report](performance-optimization-20260923-round13.md)
retains write, paging and memory data; those are not new measurements in this run.
