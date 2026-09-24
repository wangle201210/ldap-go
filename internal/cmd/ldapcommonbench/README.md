# Common LDAP SDK benchmark

A sequential `github.com/go-ldap/ldap/v3` runner for ordinary-user Bind,
nonroot Base/UID equality, direct-group discovery, group member reads, and
portable client-side nested membership. Supply named ldap-go/OpenLDAP endpoints
running on **disposable task copies**. One endpoint is supported for profiling.
This tool never starts servers, changes server configuration/indexes, or touches
database files. No CGO, external LDAP executable, or server package is used.

## Build and focused tests

```sh
CGO_ENABLED=0 GOFLAGS= go test ./internal/cmd/ldapcommonbench
CGO_ENABLED=0 GOFLAGS= go build -o /var/tmp/ldapcommonbench ./internal/cmd/ldapcommonbench
/var/tmp/ldapcommonbench -help
```

The tests use in-memory SDK responses, with no LDAP connections, benchmarks or
race detector. Implementation validation does not establish performance numbers.

## Run on disposable copies

Start each server separately with matching data, ACLs, schema, limits, indexes,
transport and cache conditions. Set `LDAPCOMMON_ROOT_PASSWORD` through your
normal secret-entry mechanism. There are no default addresses or root credentials.
The root DN/password must work on every endpoint; temporary passwords are random
and identical across the paired fixtures. Passwords and hashes are omitted from
JSON. Keep each endpoint on a separate copy, including endpoints with different
names that resolve to the same machine.

```sh
/var/tmp/ldapcommonbench \
  -endpoint current=ldap://127.0.0.1:29482 \
  -endpoint openldap=ldap://127.0.0.1:29483 \
  -base dc=scale,dc=qualification \
  -root-bind-dn cn=admin,dc=scale,dc=qualification \
  -root-password-env LDAPCOMMON_ROOT_PASSWORD \
  -setup-disposable -n 100 -repeats 3 > common.json
```

`-setup-disposable` is required before any connection; omission is an error.
All addresses above are examples, not discovered or started by the runner.
For a single-server Base/equality profile:

```sh
/var/tmp/ldapcommonbench \
  -endpoint current=ldap://127.0.0.1:29482 \
  -base dc=scale,dc=qualification \
  -root-bind-dn cn=admin,dc=scale,dc=qualification \
  -root-password-env LDAPCOMMON_ROOT_PASSWORD \
  -setup-disposable -stages base,equality -n 3000 -repeats 1 > profile.json
```

This selection creates only an OU and eight users. It performs exact Base reads
and `(uid=...)` equality searches, without group creation, pool discovery, prefix
searches, or paged scans. Server CPU profiling remains a separate caller task;
setup, Bind/WhoAmI verification and cleanup still generate server work.

To query a specific existing scale user, add
`-people ou=people,dc=scale,dc=qualification -uid scale-001001`.
Without `-uid`, `-people` samples the declared contiguous
`scale-000001` through `scale-100000` range (override with `-entries`).
Expected data is the exact DN and matching single UID; locally created users
also assert exact `cn` and `sn`. UID filter values and RDNs are escaped separately.
An equality filter alone cannot certify that the server used an index. Configure
and verify equivalent indexes outside this runner.

## Fixtures and stages

Each invocation creates `ou=ldapcommonbench-<random token>,<base>` on each
endpoint, with the same ownership marker, unique UIDs and generated credentials.
The first ordinary user is the SSHA service account used for all nonroot queries;
the second stores its password as plaintext for an explicitly separate Bind
baseline. Both use LDAP Simple Bind, which sends the supplied password on the
wire: storage labels do not imply transport encryption. LDAPS uses normal
certificate verification; there is no insecure TLS option.

The default group fixture creates **1,000 real users inside the isolated OU**,
two `groupOfNames` groups containing exactly 10 and 1,000 distinct user DNs,
and three nested groups. All references resolve to fixture entries. Each direct
group includes the first eight users. The nested graph is
`user-1 -> nested-1 -> nested-2 -> nested-3 -> nested-1`; users 2 and 3 also join
nested-2 and nested-3 respectively. Remaining sampled users belong only to the
direct groups. `-group-sizes` accepts distinct sizes from 8 through 10,000.

An optional `-people` pool replaces extra local member entries after the first
eight with existing `scale-%06d` references. Every referenced pool entry is
verified by a nonroot exact Base read before timing. Existing entries are never
written or deleted. The default requires no scale fixture conventions. Plain
`groupOfNames` DN references permit adding the small cycle before all its entries
exist; no native transitive-membership extension or overlay is required.

`-stages` defaults to `all`, or accepts a comma-separated subset in execution
order. `base` and `equality` are aliases for `nonrootBase` and `nonrootEquality`.

| Stage | Measured operation and assertion |
| --- | --- |
| `userBind` | Successful ordinary-user Simple Bind; separate `simple_bind_ssha` and `simple_bind_plaintext` methods. |
| `userBindWrong` | Wrong password must return `invalidCredentials` and leave the connection anonymous, for both storage formats. |
| `nonrootBase` | Base-object user read; exactly one expected DN and exact attribute values. |
| `nonrootEquality` | Subtree UID equality under `-base` (or `-people`); same exact result assertion. |
| `memberEquality` | `(member=<user DN>)` discovery within the isolated OU; exact direct parent group DNs and CNs, including an immediate nested-group parent where applicable. |
| `groupBase` | One method instance per direct-group size; Base read requesting only `member`, asserting the complete distinct member set. |
| `nestedMembership` | `client_bfs_member_equality`: breadth-first parent discovery using repeated standard member equality searches, with a visited set and exact transitive result assertion. |

Nested membership uses the **same portable SDK algorithm on every server**.
It is a client traversal, not a native transitive LDAP operation. Returned DNs
drive traversal after assertion, normalized and sorted for consistent request
order. Every discovered group is searched once; the cycle terminates. With
default group sizes, the first three sampled users require six LDAP searches per
traversal, and the other five require three. No scan or native matching-rule OID
is used. LDAP servers may still internally scan if their indexes are absent.

## Timing and JSON

Each method runs `-n` operations per endpoint for each of `-repeats` repetitions.
The first endpoint rotates by iteration and repetition; nested traversals also
rotate between **individual LDAP requests**, not only between full traversals.
Connections are reused. There is no concurrency or implicit warmup. Wrong-Bind
samples first successfully rebind the same account so each tests an authenticated
to anonymous transition. Every timed request checks its outcome and is followed
by an untimed WhoAmI assertion. All searches run as the SSHA service user.

Each `samples` row identifies endpoint, stage, method, 1-based repeat, and group
member count where applicable. `operations` counts attempted logical operations;
`completed` counts fully verified ones; `requests` counts attempted timed SDK
Bind/Search calls. `latency_ms` contains one sample per completed logical
operation. `total_ms` sums only time inside SDK `Bind`/`Search` calls, including
calls returning errors. Request construction, DN parsing, member-set validation,
sorting and traversal bookkeeping are outside the timer. Full assertions still
run before results are accepted or discovered groups are enqueued. Nested sample
latency sums each SDK Search duration for that endpoint, excluding time spent on
other endpoints or verification. These are SDK round-trip timings (including SDK
encoding/decoding), not isolated server CPU times. Reports from the earlier
assertion-inclusive timer are not directly comparable and should be rerun.

`verification_requests` and `verification_ms` separately count preparation Bind,
WhoAmI and wrong-Bind reset requests. Setup, seed validation, connection time and
cleanup are excluded from timed samples. The top-level report records options,
start time, timeout, run DN, successful setup Add count, endpoint names whose
cleanup completed, partial samples and any error. On success each endpoint has
`n * repeats` operations per selected method (and each requested group size).

Exit statuses: 0 success/help; 1 request, assertion, cleanup, cancellation or JSON
output failure; 2 invalid arguments. Runtime/argument failures produce JSON on
stdout; flag diagnostics go to stderr. Do not treat partial reports as successful
measurements. `-n` is 1..100000, `-repeats` 1..100, and `-timeout` is (0,5m].
Values outside these bounds fail instead of being silently clamped.

## Cleanup and scope

After ownership is established by a successful OU Add, cleanup runs on success,
failure, SIGINT or SIGTERM, using a fresh root connection per endpoint. It verifies
the OU marker, deletes only recorded child DNs in reverse order, deletes the OU,
and requires `noSuchObject` on an exact final Base read. Failed child Add attempts
are recorded too because a lost reply can still mean a committed write. Cleanup
continues after individual errors and reports failures across all endpoints.

An unsuccessful initial OU Add never adopts an existing subtree. A lost initial
OU reply, unreachable server, SIGKILL or process crash may leave an orphan;
`run_dn` identifies it for inspection. Cleanup never discovers or recursively
deletes unknown entries. Existing server policies can reject writes, restrict
nonroot visibility or lock accounts after repeated wrong passwords; such results
are reported as failures without changing those policies. Use matching plain
disposable fixtures for a comparable baseline.

References: [existing SDK probe](../ldapbench/README.md) and the
[round-13 paired probe](../../../docs/evidence/performance-20260923-round13/paired-probe.go.txt).
