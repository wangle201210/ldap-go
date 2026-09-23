# Reuse normalized DNs during ACL evaluation

Baseline: `03991cc`. All Go builds, tests and benchmarks use `CGO_ENABLED=0`.
This follows the [substring scan work](performance-optimization-20260923-round12.md)
and targets ordinary local authentication and non-root reads.

## Change and Boundaries

ACL evaluation has an explicit optional `DNIdentityParser` interface, matching
the existing storage parser convention. Opted-in providers must return the same
DN identities, display forms and errors as their attribute normalizer. Nil and
unopted normalizers retain their original parsing and callback behavior. Parser
errors are returned directly, without retries or additional normalization calls.

The server supplies a private wrapper around its published runtime registry for
both local and remapped remote ACL views. That wrapper uses the existing bounded
`NormalizeDNCached` implementation. The registry itself does not implement the
new interface, so other ACL callers and custom normalizers do not silently opt
in. The cache remains limited to 128 successful DNs, 1 KiB input, depth 32 and
an estimated 1 MiB retained data; registry mutation APIs invalidate it. Runtime
schema definitions must retain the existing immutability contract, including
using registry APIs rather than editing shared definition slices directly.

This caches only DN parsing. Rule order, per-value permission checks, group/ACI
reads, authorization decisions, password verification and work factors remain
unchanged. Both authentication snapshots and the final-snapshot verification
remain in place. No password, authentication-result or directory-entry cache is
introduced, and the stored format is unchanged.

## Validation

The [full suite](evidence/performance-20260923-round13/go-test.txt),
[vet](evidence/performance-20260923-round13/go-vet.txt),
[focused authentication checks](evidence/performance-20260923-round13/auth-focused.txt),
and [200 native OpenLDAP checks, including subtests](evidence/performance-20260923-round13/openldap-differential.txt)
passed. The native selection had no skips; no race-detector result is claimed.

New ACL tests compare cached and uncached outcomes across target/suffix/self,
group, DN-valued attributes, expansions, sets and ACI. They check callback order
for unopted providers, exact delegation/error identity, alias/OID/multi-AVA and
Unicode DNs, ownership, schema mutation and changed group/ACI data. Server tests
verify case-exact schema updates and policy replacement after warming both local
and remapped remote access paths. Existing password-policy tests check every
permitted value and changes between the two snapshots.

## Component and Allocation Evidence

Three 300ms samples, medians, with the working DN set warmed. These are complete
ACL checks, not LDAP request latency. Directory lookups and decisions remain live.

| ACL check | Uncached | Cached | Bytes before / current | Allocations before / current |
| --- | ---: | ---: | ---: | ---: |
| Anonymous authentication | 7,368 ns | 725.6 ns | 4,088 / 696 | 167 / 6 |
| Self read | 15,435 ns | 1,212 ns | 8,152 / 856 | 355 / 11 |
| Group read | 30,507 ns | 2,721 ns | 15,360 / 1,456 | 685 / 31 |
| Nonmember denied | 30,258 ns | 2,744 ns | 15,312 / 1,456 | 685 / 31 |

The parallel anonymous-auth check, with eight Go workers and three 500ms samples,
gives 3,373 / 892.9 ns per operation, 3,800 / 408 bytes and 167 / 6 allocations.
It uses one rule rather than the serial fixture's two rules; those byte counts
are not directly interchangeable. Setup and warmup are excluded from timing.
[Serial samples](evidence/performance-20260923-round13/acl-bench.txt),
[parallel samples](evidence/performance-20260923-round13/acl-parallel-bench.txt).

The diagnostic 60k-Bind workload has sampled cumulative server allocation of
2,325.61 MiB before and 1,714.59 MiB current, subtracting each warmed heap profile:
about 26.3% lower. This includes temporary-user creation/cleanup and related
metadata initialization. It is neither a per-Bind allocation measurement nor an
RSS or retained-heap reduction. Passwords in this fixture use SSHA; no work
factor is reduced, and the latency result does not describe stronger password
schemes or external authentication providers.
[Allocation before](evidence/performance-20260923-round13/alloc-before.txt),
[allocation current](evidence/performance-20260923-round13/alloc-current.txt),
[CPU before](evidence/performance-20260923-round13/user-before-cpu.txt),
[CPU current](evidence/performance-20260923-round13/user-current-cpu.txt).

## Per-Request Comparison

One warmed process per implementation uses the same disposable 100k snapshot.
The client rotates the endpoint after every request, also rotating which endpoint
goes first. Every row is the median of three batches of 3,000 calls per endpoint,
summing only that endpoint's calls. Every response and the identity after each
batch is checked. Setup, warmup, cleanup and WhoAmI checks are outside timing.

The short fixture has a 74-byte DN; the long-DN fixture has a 202-byte DN; the
long-password fixture keeps a short DN and uses a 256-byte password. Wrong Bind
passwords are short and all nonmatching Compare assertions have 256 bytes.
Non-root queries bind as the temporary user and retrieve the other fixture user
`uid=scale-001001`, checking the exact DN and uid. Base and equality queries return
one entry and request only uid. This is a repeated hot-key read workload.

| Short-DN fixture, 3,000 calls | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 419.83 ms | 356.48 ms | 235.93 ms | -15.1% |
| User Bind, wrong password | 384.25 ms | 331.59 ms | 216.82 ms | -13.7% |
| Root Bind | 257.95 ms | 258.88 ms | 203.96 ms | +0.4% |
| Compare true | 312.06 ms | 310.39 ms | 213.31 ms | -0.5% |
| Compare false | 320.16 ms | 323.04 ms | 228.70 ms | +0.9% |
| Non-root base search | 965.21 ms | 701.26 ms | 316.92 ms | -27.3% |
| Non-root indexed equality | 962.09 ms | 696.55 ms | 322.22 ms | -27.6% |

| Extended fixture, 3,000 calls | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| Long DN, successful Bind | 430.29 ms | 364.11 ms | 227.17 ms | -15.4% |
| Long DN, wrong password | 440.58 ms | 375.87 ms | 235.51 ms | -14.7% |
| Long DN, matching Compare | 333.43 ms | 334.06 ms | 222.05 ms | +0.2% |
| Long DN, nonmatching Compare | 332.42 ms | 337.44 ms | 222.70 ms | +1.5% |
| Long DN, non-root base | 1,045.86 ms | 781.48 ms | 337.20 ms | -25.3% |
| Long DN, non-root equality | 1,072.28 ms | 815.05 ms | 360.56 ms | -24.0% |
| Long password, successful Bind | 382.36 ms | 336.49 ms | 218.42 ms | -12.0% |
| Long-password fixture, short wrong password | 374.83 ms | 325.22 ms | 214.47 ms | -13.2% |
| Long-password fixture, matching Compare | 309.22 ms | 308.94 ms | 212.17 ms | -0.1% |
| Long-password fixture, nonmatching Compare | 338.80 ms | 336.76 ms | 234.90 ms | -0.6% |
| Long-password fixture, non-root base | 958.70 ms | 686.58 ms | 298.87 ms | -28.4% |
| Long-password fixture, non-root equality | 957.43 ms | 700.34 ms | 334.15 ms | -26.9% |

Root Bind and Compare are administrator operations here and do not exercise the
new ACL parser. Their small mixed changes are not claimed as improvements.
Authentication and non-root reads improve in the measured fixtures, but still
trail OpenLDAP substantially. All three final ordinary-attribute exports match
the original fixture: 100,002 entries, 42,712,438 canonical bytes, POSIX checksum
`2143929969`.
[All samples](evidence/performance-20260923-round13/request-paired-samples.json),
[export checks](evidence/performance-20260923-round13/request-paired-validation.tsv).

## Full Replay

Three fresh processes per implementation ran in rotating order with the same
100k data, indexes and limits. There were three batches of 1,000 short operations
and authentication calls per process, three batches of 20 scans, full-prefix
output checks, 10k indexed calls, eight concurrent clients, paging and negative
equality probes. Every sample is retained. Medians:

| Stage, 1,000 calls | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 127.29 ms | 110.06 ms | 67.12 ms | -13.5% |
| User Bind, wrong password | 122.80 ms | 106.04 ms | 67.30 ms | -13.6% |
| Root Bind | 85.69 ms | 88.06 ms | 63.54 ms | +2.8% |
| Base search, root | 96.73 ms | 99.08 ms | 80.76 ms | +2.4% |
| Indexed equality, root | 102.37 ms | 109.66 ms | 85.20 ms | +7.1% |
| Compare true, root | 101.62 ms | 106.22 ms | 68.68 ms | +4.5% |
| Compare false, root | 101.76 ms | 108.05 ms | 68.74 ms | +6.2% |

| Workload | Before | Current | OpenLDAP |
| --- | ---: | ---: | ---: |
| Prefix substring, 20 | 905.80 ms | 910.67 ms | 612.17 ms |
| Negative substring, 20 | 891.16 ms | 911.04 ms | 610.64 ms |
| Full prefix, 100k returned | 568 ms | 549 ms | 498 ms |
| Indexed CLI queries, 10,000 | 782 ms | 803 ms | 647 ms |
| Concurrent indexed, 8 x 1,000 | 193 ms | 251 ms | 216 ms |
| Paged traversal, 2 x 100k | 1,145 ms | 1,207 ms | 1,042 ms |
| Unindexed negative equality, 10 | 205 ms | 211 ms | 339 ms |

Authentication improvement reproduces the per-request probe. Administrator
queries bypass the changed ACL parser and retain mixed shared-host timings;
neither the larger regressions nor gains in these rows are attributed to the
parser without further evidence. The per-request administrator Bind/Compare
measurements above are near baseline. Read/auth RSS medians were
413.7 / 431.4 / 115.5 MiB before/current/native: reduced cumulative allocation
did not yield a measured RSS reduction in this replay.

The apparent 30% concurrent-query increase prompted a focused recheck. Three
fresh processes per Go version ran in alternating pair order, with a two-query
SDK warmup, one concurrent warmup batch (repeat 0), and three measured batches
of eight clients x 1,000 queries. All clients' returned uid sequences were
compared with the exact expected list. Medians of the nine post-warmup samples
were **198 ms before / 197 ms current**. The original increase did not reproduce.
This recheck omits the earlier authentication workload and measures no new
native sample, so it is retained separately rather than replacing the original
full-workload measurements. Warmup values and all outliers remain in the file.
[Concurrent recheck](evidence/performance-20260923-round13/concurrent-recheck.tsv).

All nine read processes passed SDK assertions and full canonical ordinary-
attribute export comparison. Full-prefix and paged results contained 100,000
unique people.
[Short samples](evidence/performance-20260923-round13/long-timings.json),
[extended samples](evidence/performance-20260923-round13/extended-timings.json),
[scan samples](evidence/performance-20260923-round13/sdk-timings.json),
[traversal samples](evidence/performance-20260923-round13/online-timings.tsv),
[export/RSS checks](evidence/performance-20260923-round13/sdk-validation.tsv).

## Write Regression

Twenty leaf entries per stage, three fresh processes per implementation in
rotating order. Setup, SDK postcondition checks and cleanup are excluded from
each timed stage. Existing durability settings are unchanged.

| Twenty operations | Before | Current | OpenLDAP | Time change |
| --- | ---: | ---: | ---: | ---: |
| Add | 19.60 ms | 18.47 ms | 99.57 ms | -5.7% |
| Modify, unindexed description | 7.97 ms | 8.73 ms | 92.89 ms | +9.5% |
| ModifyDN | 23.05 ms | 25.98 ms | 104.78 ms | +12.7% |
| Delete | 19.49 ms | 18.36 ms | 96.58 ms | -5.8% |

These administrator operations do not use the changed ACL parser. Mixed
small-batch results are retained; no write-path improvement is claimed and the
results do not describe all production workloads. All nine write runs passed
SDK postconditions and the same complete ordinary-attribute export comparison.
Together with the read and per-request replays, 21 full exports matched.
[Write samples](evidence/performance-20260923-round13/write-timings.json),
[export checks](evidence/performance-20260923-round13/write-validation.tsv).

## Reproduction and Remaining Gaps

Both executables use Go 1.26.4, darwin/arm64 and `CGO_ENABLED=0`. The baseline
reuses the previous round's accepted binary whose source became `03991cc`.
SHA-256:

```text
before  2c99009916ddd3dcb00091be38d3004a151ba819ec1d86bfc8047ac93bd163b4
current 599bde3b88256b8bf0d1eaa40b8654bb32f21260d8bf5262ce7b4ff7d2472eb7
```

Local artifacts are under `/var/tmp/ldap-go-perf-round16-20260923`. Builds/tests
did not run concurrently with benchmarks. Temporary servers were stopped and
source snapshots were unchanged. The local [read replay](evidence/performance-20260923-round13/replay.sh.txt),
[write replay](evidence/performance-20260923-round13/write-replay.sh.txt),
[per-request replay](evidence/performance-20260923-round13/request-paired.sh.txt),
[SDK probe](evidence/performance-20260923-round13/paired-probe.go.txt), and
[concurrent recheck](evidence/performance-20260923-round13/concurrent-recheck.sh.txt)
record their fixture/probe dependencies. For fresh environments use the
[comparison runner](../scripts/qualification/compare-openldap.sh) and
[100k instructions](openldap-100k-evidence.md#reproduction-and-limits).

Authentication and non-root reads improve without caching their outcomes.
Non-root base/equality queries still reach only about 45-46% of native performance
in the short-DN per-request fixture (`OpenLDAP / current * 100%`). Stronger password
schemes, cold/changing DN working sets and more complex ACL workloads need their
own measurements. The broader goal of matching OpenLDAP performance is not complete.
