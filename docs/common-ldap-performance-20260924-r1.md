# Common LDAP performance qualification

Historical first September 24 run. See the [latest report](common-ldap-performance.md)
for the second run and current implementation.

Measured September 23-24, 2026, against baseline `fac6a5f` and pinned OpenLDAP
2.6.13 on Apple M1 Pro. Go builds use `CGO_ENABLED=0`. The goal is parity or
better for user Bind, non-root Base/equality searches and group queries.
**That goal is not achieved.** The explicit-ACL group workload remains the
largest measured gap.

## Changes

The runtime now has a bounded cache for the initial, schema-independent DN
syntax parse. It retains at most 128 successful inputs, 1 KiB input strings,
depth 32 and an estimated 1 MiB. Inputs are owned and results are immutable;
syntax errors are not cached. Database routing and schema normalization still
run on every call, preserving custom callbacks, changing errors and configuration
changes. Runtime copies may share this pure syntax cache without sharing routing
or authorization decisions.

Attribute projection can evaluate the default DN privilege once when the whole
policy contains no rules. It preserves the existing root shortcut, output shape,
value ownership and root-DSE exceptions. Any explicit ACL, remote ACL mapping,
unknown context callback, custom DN normalizer or rewrite configuration keeps
the original per-value path. Known partition wrappers are inspected only to
identify their context forwarding; data operations keep their partition scope.
No decision is cached across entries or requests.

## Reproducible SDK runner

[ldapcommonbench](../internal/cmd/ldapcommonbench/README.md) is now a repository
command with configurable named endpoints, stage selection, isolated fixture
ownership/cleanup, exact response checks and per-request endpoint rotation.
Only SDK Bind/Search calls are timed; construction, DN parsing, sorting and result
assertions are outside timing. All responses and bound identities are checked.
Raw reports include every request latency, request counts and cleanup status.

The 100k source fixture has 100,000 people plus two containers. Both servers use
uid, objectClass and member equality indexes. Temporary groups contain 10 or
1,000 real, distinct user DNs; the large group references existing scale users
as well as temporary users. Hot reads target one existing user; distributed reads
span 1,000 users across the declared 100k UID range. Group discovery returns the
exact expected group set. Nested membership uses the same portable client BFS
on both endpoints, including a three-group cycle; it is not a native transitive
LDAP matching-rule operation.

There are two separately measured access configurations:

- Default access, with no explicit ACL rules.
- The same explicit database ACL on both servers: password values allow self
  write/anonymous authentication, while other attributes allow users read and
  deny anonymous access.

```text
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none
```

These results use plaintext LDAP transport and SSHA for the headline Bind row.
The runner also reports plaintext password storage as a separate diagnostic;
it must not substitute for the SSHA comparison. Stronger password schemes and
TLS require separate equivalent measurements.

## Default access

Three batches per operation, one warmed process per implementation, endpoints
rotated after each request. Values are batch-time medians, with no discarded
outliers. Relative performance is `OpenLDAP / current * 100%`; larger is better.

| Workload | Calls | Before | Current | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 1,000 | 109.19 ms | 104.47 ms | 71.46 ms | 68.4% |
| Wrong password, SSHA | 1,000 | 107.08 ms | 101.81 ms | 67.64 ms | 66.4% |
| Non-root Base, hot | 1,000 | 200.76 ms | 110.81 ms | 77.32 ms | 69.8% |
| Non-root equality, hot | 1,000 | 201.12 ms | 110.49 ms | 78.98 ms | 71.5% |
| Non-root Base, distributed | 1,000 | 218.20 ms | 129.27 ms | 78.86 ms | 61.0% |
| Non-root equality, distributed | 1,000 | 210.97 ms | 122.64 ms | 80.61 ms | 65.7% |
| Direct group discovery | 100 | 876.72 ms | 43.54 ms | 16.99 ms | 39.0% |
| Group Base, 10 members | 100 | 38.22 ms | 17.34 ms | 12.61 ms | 72.7% |
| Group Base, 1,000 members | 100 | 909.28 ms | 86.44 ms | 79.73 ms | 92.2% |
| Nested membership, client BFS | 100 traversals | 945.04 ms | 97.21 ms | 55.30 ms | 56.9% |

[Hot samples](evidence/common-performance-20260924/default-hot.json),
[distributed samples](evidence/common-performance-20260924/default-distributed.json),
[group samples](evidence/common-performance-20260924/default-groups.json).

## Explicit ACL

Same data/indexes and measurement procedure; the projection shortcut is excluded.
The syntax cache remains applicable, and all original ACL decisions still run.

| Workload | Calls | Before | Current | OpenLDAP | Relative performance |
| --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | 1,000 | 111.90 ms | 107.14 ms | 71.09 ms | 66.4% |
| Wrong password, SSHA | 1,000 | 109.77 ms | 104.53 ms | 69.81 ms | 66.8% |
| Non-root Base, hot | 1,000 | 214.28 ms | 147.68 ms | 80.23 ms | 54.3% |
| Non-root equality, hot | 1,000 | 214.65 ms | 148.67 ms | 80.82 ms | 54.4% |
| Non-root Base, distributed | 1,000 | 225.89 ms | 165.16 ms | 79.36 ms | 48.1% |
| Non-root equality, distributed | 1,000 | 373.11 ms | 251.28 ms | 110.01 ms | 43.8% |
| Direct group discovery | 100 | 945.44 ms | 380.99 ms | 17.27 ms | 4.5% |
| Group Base, 10 members | 100 | 41.57 ms | 26.67 ms | 13.18 ms | 49.4% |
| Group Base, 1,000 members | 100 | 978.36 ms | 444.67 ms | 82.30 ms | 18.5% |
| Nested membership, client BFS | 100 traversals | 1,026.12 ms | 457.73 ms | 57.73 ms | 12.6% |

[Hot samples](evidence/common-performance-20260924/explicit-hot.json),
[distributed samples](evidence/common-performance-20260924/explicit-distributed.json),
[group samples](evidence/common-performance-20260924/explicit-groups.json).

Direct group discovery currently evaluates permissions for many member values
even when only cn is returned. This explains an optimization target, not a reason
to omit or weaken ACL checks. Results for default access cannot stand in for
explicit policies. Shared-host timing variation remains visible in the samples.

## Validation and limits

The [full Go suite](evidence/common-performance-20260924/go-test-final.txt),
[vet](evidence/common-performance-20260924/go-vet-final.txt), and
[200 native differential checks, including subtests](evidence/common-performance-20260924/openldap-differential-final.txt)
passed. New syntax-cache tests compare the old parser, callback order/errors,
changing routes/schema, ownership, capacity and concurrent use. Projection tests
compare the old implementation for output shape, nil/empty values, RawNormalized
flags, root/config DNs, changing groups, explicit per-value denials, remote
mappings and custom callbacks. Additional tests isolate the explicit-rule and
remote guards, and exercise real partition/context wrapper chains.

Both access configurations passed SDK assertions and cleanup. All six full
ordinary-attribute exports after cleanup equal the source fixture: 100,002 entries,
42,712,438 canonical bytes, POSIX checksum `2143929969`.
[Default export checks](evidence/common-performance-20260924/default-validation.tsv),
[explicit export checks](evidence/common-performance-20260924/explicit-validation.tsv).

Component benchmarks retain both hot and cold syntax-cache costs. A warmed
database-user parse changes from 1,936 ns / 704 bytes / 41 allocations to
542.2 ns / 56 bytes / 2 allocations. Creating a cold syntax cache for every
invocation costs 2,434 ns / 2,120 bytes / 46 allocations; this is not a universal
speedup claim. Default-projection benchmarks include the actual partition
wrapper chain. [Syntax samples](evidence/common-performance-20260924/legacy-bench.txt),
[projection samples](evidence/common-performance-20260924/default-projection-final-bench.txt).

The new runner's timing boundaries, group indexes, fixture DNs and working sets
differ from earlier [round-13 measurements](performance-optimization-20260923-round13.md).
Compare before/current within this report instead of treating historical absolute
times as the same workload. Concurrent throughput, TLS, stronger password schemes,
larger group populations and additional ACL policies remain qualification work.

Local replay artifacts are under `/var/tmp/ldap-go-common-perf-20260923`.
Accepted executable SHA-256 values:

```text
before  599bde3b88256b8bf0d1eaa40b8654bb32f21260d8bf5262ce7b4ff7d2472eb7
current 0e14fa9d6f77f4581740a4d153c8864f93b9d65482708d2c46a1c2795c151f65
```
