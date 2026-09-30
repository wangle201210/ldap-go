# Common LDAP SDK benchmark

A sequential `github.com/go-ldap/ldap/v3` runner for ordinary-user Bind,
nonroot Base/UID equality, direct-group discovery, group member reads, and
portable client-side nested membership. Supply named ldap-go/OpenLDAP endpoints
running on **disposable task copies**. One endpoint is supported for profiling.
Optional root Bind, Base, UID equality and true/false Compare stages use a
separate root connection per endpoint; default stages are unchanged.
This tool never starts servers, changes server configuration/indexes, or touches
database files. No CGO, external LDAP executable, or server package is used.

## Build and focused tests

```sh
CGO_ENABLED=0 GOFLAGS= go test ./internal/cmd/ldapcommonbench
CGO_ENABLED=0 GOFLAGS= go build -o /var/tmp/ldapcommonbench ./internal/cmd/ldapcommonbench
/var/tmp/ldapcommonbench -help
```

The tests use in-memory SDK responses and disposable loopback LDAP/TLS peers,
without external servers, benchmarks or a race detector. TLS tests cover trust,
hostname verification, StartTLS ordering, failure cleanup and upgrade timeouts.
Implementation validation does not establish performance numbers.

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

## Verified TLS

Keep the required fixture/credential flags above. For LDAPS, replace the endpoint
flags with the servers' TLS listeners and add a PEM CA bundle, for example:

```sh
-endpoint current=ldaps://localhost:29636 -endpoint native=ldaps://localhost:29637 -tls-ca /path/to/bench-ca.pem
```

For StartTLS, use the ordinary LDAP listeners and add
`-start-tls -tls-ca /path/to/bench-ca.pem`. Every endpoint must use `ldap://` with
`-start-tls`; mixing in `ldaps://` is rejected before any connection. All setup,
root, measured and cleanup connections upgrade before their first Bind.

Without `-tls-ca`, TLS uses system roots. A supplied bundle replaces those roots
for this invocation and must contain at least one valid PEM certificate. Chain
and endpoint hostname/IP verification remain enabled; there is no insecure flag.
An unreadable or unusable bundle is an argument error. `-tls-ca` alone does not
upgrade a plaintext `ldap://` connection; defaults keep the original dial path.

CA parsing and trust-pool construction happen once before connections. Dialing
and TLS negotiation stay outside samples. `-timeout` bounds the TCP dial and the
StartTLS exchange/handshake; the upgrade deadline is cleared before normal LDAP
requests use the existing request timeout. JSON records `tls_ca` when supplied
and `start_tls` when true, never the parsed TLS config. Compare server variants
and native servers with the same SDK, transport and verification settings; these
reused-connection samples do not measure handshake performance.

## In-process network diagnostic

An opt-in server benchmark copies a quiescent 100k qualification seed into a
temporary directory, starts a private loopback server, adds a temporary reader,
and uses the same SDK hot Base/equality requests. The supplied seed is never
opened for writing. Its naming context must be `dc=scale,dc=qualification`, with
`uid=scale-001001,ou=people,dc=scale,dc=qualification` present.

```sh
CGO_ENABLED=0 LDAP_GO_NETWORK_BENCH_FIXTURE=/path/to/member-index.db \
  go test ./internal/server -run '^$' -bench '^BenchmarkNetworkCommon$' \
  -benchtime=5s -count=3 -benchmem
```

Timing excludes setup and response/identity checks. Allocation counts include
both the SDK and server in one process; these results are not the separate
endpoint OpenLDAP comparison. A CPU profile also includes setup and background
work; filtering `runConnectionOperation` stacks does not change its total-sample
denominator. Compare historical and current code with identical benchmark source
and fixed interleaved order, retaining all samples and negative results.

## Optional root SDK stages

Select root stages explicitly; `all` still means only the original nonroot
stages. `rootEquality`, `rootCompareTrue` and `rootCompareFalse` require `-people`
and sample the existing scale pool (100,000 entries by default). They always use
`count = min(n, entries)` and
`1 + (iteration % count) * (entries - 1) / max(1, count - 1)` with zero-based
iteration, matching `fast-probe.go` from round 6. `-uid` applies only to nonroot
Base/equality and does not override root sampling. Use the same `n` as the
reference probe; this harness retains its documented bounds rather than the
reference probe's 10,000-operation clamp.

Build the same harness for before/R1 `b55f670`, current/R2 and native comparisons.
The following is an example pairwise invocation; run the same command for each
pair of caller-managed disposable endpoints:

```sh
/var/tmp/ldapcommonbench \
  -endpoint beforeR1=ldap://127.0.0.1:29481 \
  -endpoint currentR2=ldap://127.0.0.1:29482 \
  -base dc=scale,dc=qualification \
  -people ou=people,dc=scale,dc=qualification -entries 100000 \
  -root-bind-dn cn=admin,dc=scale,dc=qualification \
  -root-password-env LDAPCOMMON_ROOT_PASSWORD -setup-disposable \
  -stages rootBind,rootBase,rootEquality,rootCompareTrue,rootCompareFalse \
  -n 100 -repeats 3 > beforeR1-currentR2-rootliteral-sdk.json
```

For the separate `rootnormalized` client-path run, repeat with
`-root-bind-dn CN=ADMIN,DC=SCALE,DC=QUALIFICATION` and write to
`beforeR1-currentR2-rootnormalized-sdk.json`. Keep server startup root DNs
configured lowercase for both runs. The client sends the supplied DN unchanged;
WhoAmI is verified semantically with parsed, case-folded DN equality, including
after every measured root Bind. Keep the exact `root_bind_dn` in sample grouping:
never pool these two client-DN variants or root and nonroot measurements.
Retain endpoint, stage, method, repeat and group member count where applicable.
Whole-process `rootIndex` results and these SDK-only samples are separate methods.

Root-only runs still require `-setup-disposable`, create the existing isolated
OU/eight-user fixture, and perform its existing service Bind and cleanup flow.
No new fixture ownership or role configuration is introduced. These untimed
operations and WhoAmI requests still generate server work.

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

`-stages` defaults to `all` (the seven original stages below), or accepts a
comma-separated subset in execution order, including optional root stages.
`base` and `equality` are aliases for `nonrootBase` and `nonrootEquality`.

| Stage | Measured operation and assertion |
| --- | --- |
| `userBind` | Successful ordinary-user Simple Bind; separate `simple_bind_ssha` and `simple_bind_plaintext` methods. |
| `userBindWrong` | Wrong password must return `invalidCredentials` and leave the connection anonymous, for both storage formats. |
| `nonrootBase` | Base-object user read; exactly one expected DN and exact attribute values. |
| `nonrootEquality` | Subtree UID equality under `-base` (or `-people`); same exact result assertion. |
| `memberEquality` | `(member=<user DN>)` discovery within the isolated OU; exact direct parent group DNs and CNs, including an immediate nested-group parent where applicable. |
| `groupBase` | One method instance per direct-group size; Base read requesting only `member`, asserting the complete distinct member set. |
| `nestedMembership` | `client_bfs_member_equality`: breadth-first parent discovery using repeated standard member equality searches, with a visited set and exact transitive result assertion. |
| `rootBind` (opt-in) | `simple_bind_root`: Simple Bind with the exact client root DN/password, followed by an untimed WhoAmI check. |
| `rootBase` (opt-in) | `base_objectclass_root`: Search at `-base`, base scope, `(objectClass=*)`, size limit 2, requesting only `objectClass`; exactly the base DN with nonempty objectClass values. |
| `rootEquality` (opt-in) | `subtree_uid_equality_root`: Search under `-people`, subtree scope, sampled `(uid=scale-NNNNNN)`, size limit 2, requesting only `uid`; exactly the expected DN and single UID. |
| `rootCompareTrue` (opt-in) | `compare_uid_true_root`: Compare the sampled entry's `uid` against its sampled UID; require true. |
| `rootCompareFalse` (opt-in) | `compare_uid_false_root`: Compare the sampled entry's `uid` against `ldapbench-absent`; require false. |

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
by an untimed WhoAmI assertion. Nonroot searches run as the SSHA service user;
root stages use the endpoint's dedicated, reused root connection with the same
per-request endpoint rotation. Root searches use no alias dereferencing,
time limit, types-only projection or controls, matching the reference SDK calls.

Each `samples` row identifies endpoint, stage, method, 1-based repeat, and group
member count where applicable. Root rows additionally preserve the exact client
`root_bind_dn` for separate case-variant sample groups. `operations` counts attempted logical operations;
`completed` counts fully verified ones; `requests` counts attempted timed SDK
Bind/Search/Compare calls. `latency_ms` contains one sample per completed logical
operation. `total_ms` sums only time inside SDK `Bind`/`Search`/`Compare` calls, including
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
