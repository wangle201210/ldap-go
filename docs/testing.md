# Compatibility testing

Compatibility claims require four layers of evidence.

## Unit and property tests

Pure components use table, fuzz, and property tests. BER, DN, filter, LDIF, and
schema parsers must include malformed-input and resource-limit tests.

## Protocol conformance

Tests derive expected behavior from the applicable RFC. They cover result codes,
response ordering, connection state, controls, limits, cancellation, and
security-sensitive edge cases.

## OpenLDAP differential tests

The same operation sequence runs against a locally built, pinned OpenLDAP 2.6.x
reference `slapd` and `ldap-go`. Results are normalized only where values are
intentionally server-generated, then compared for:

- result code, matched DN, diagnostics, referrals, and controls;
- returned DNs, attributes, values, and ordering where specified;
- resulting directory content and operational metadata;
- connection closure and unsolicited notifications.

Any intentional difference requires a documented compatibility exception.

## Migration tests

Fixtures are generated with `slapadd` and `slapcat`, imported unchanged into
`ldap-go`, exported again, and compared semantically. Fixtures cover custom
schema, binary and base64 values, folded lines, attribute options, referrals,
subentries, UUID/CSN metadata, and `cn=config`.

## Required checks

The repository exposes two supported entry points:

```sh
make compat
make full
```

`make compat` runs formatting, vet, all Go tests, the selected OpenLDAP
reference suite, and a bounded fuzz smoke pass. `make full` additionally runs
the complete suite with the race detector, builds the fixed OpenLDAP 2.6.13
source locally with the required backends, overlays, and `lloadd` enabled,
rejects every top-level skip, and fuzzes every parser target for five seconds.
Set `LDAP_GO_FUZZ_TIME` to extend the fuzz duration before a compatibility row
is promoted. Corpus minimization is bounded to keep short runs deterministic;
`LDAP_GO_FUZZ_MINIMIZE_TIME` can extend that budget.

The OpenLDAP runner requires 2.6.13 reference tools and schema. The strict
evidence path uses the locally built pinned release described below. It runs
the entire `internal/server` and `internal/lloadd` packages with the reference
gate enabled, so a new differential cannot be omitted from a manually
maintained `-run` regular expression:

```sh
make openldap
```

Missing `slapd`, `slapadd`, `lloadd`, or schema files and unexpected top-level
skips fail the run. Two SCRAM-SHA-256
cases may be reported as optional skips when the local Cyrus SASL installation
does not provide that plugin. Feature-gated differentials are optional when the
selected `slapd -VVV` omits their required backend or overlay: `ldap`, `meta`,
`null`, `relay`/rwm/sssvlv, deref, homedir, pbind, and remoteauth. The strict
runner builds all of those features and converts every optional skip into a
failure.
`OPENLDAP_EXPECTED_VERSION` can
deliberately select another reference version, and `OPENLDAP_SCHEMA_DIR`
selects a non-standard schema installation. The reference suite runs package
tests serially for repeatability; set `LDAP_GO_OPENLDAP_PARALLEL` explicitly
for a separate concurrency stress pass.

Reference fixtures must signal `slapd` to shut down and wait for it before
using a forced kill as a timeout fallback. On macOS, LMDB uses named POSIX
semaphores; repeatedly killing a fixture process skips `sem_unlink`, eventually
exhausts the kernel semaphore quota, and surfaces as a misleading MDB
`ENOSPC` error even when the filesystem has free space.

### Strict OpenLDAP validation in Linux Docker

Use the Docker entry point to run the pinned strict suite in a disposable Linux
container. This isolates fixture LMDB state from the macOS POSIX semaphore
namespace while retaining the OpenLDAP source and build in a named volume:

```sh
./scripts/test-openldap-docker.sh
```

The image is based on `golang:1.25-bookworm`. The wrapper builds it, mounts the
current repository read-only at `/workspace`, starts the container with
`--rm --init --ulimit nofile=4096:4096`, and invokes
`scripts/test-openldap-full.sh` with
`LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1`. Repository paths containing spaces are
supported. The image and wrapper explicitly prepend `/usr/local/go/bin` and
`/go/bin` to `PATH`, including for login-shell execution. Docker is the only
external runtime required; Oracle Database and Oracle client software are not
required.

The explicit `nofile` limit is intentional. Docker Desktop may otherwise
advertise a limit such as 1,048,576; `slapd` sizes its connection table from
that value, so every short-lived fixture can allocate hundreds of MiB and time
out during startup. A 4,096 descriptor limit is ample for this serial test
suite and keeps fixture memory bounded.

The defaults can be overridden without changing the scripts:

```sh
LDAP_GO_OPENLDAP_DOCKER_IMAGE=registry.example/ldap-go-openldap-test:bookworm \
LDAP_GO_OPENLDAP_DOCKER_CACHE_VOLUME=ldap-go-openldap-cache-ci \
  ./scripts/test-openldap-docker.sh
```

The image defaults `GOPROXY` to `https://goproxy.cn,direct` so the first module
download does not depend on `proxy.golang.org`. A host-provided `GOPROXY`
overrides that default.

`LDAP_GO_OPENLDAP_DOCKER_CACHE_VOLUME` must name a Docker volume. It stores the
pinned OpenLDAP source under `source/` and its incremental build under `build/`;
test fixture databases remain inside the disposable container.

For reproducible full-feature evidence, `make openldap-full` uses the pinned
OpenLDAP 2.6.13 release commit
`d172686d3d270bc961b78f3ff00d7019c8dfb094`, enables the `ldap`, `meta`,
`null`, `relay`, and `mdb` backends plus every overlay used by the strict suite
and the standalone balancer. It builds the libraries, slapd/slap tools,
`lloadd`, and client tools, emits a sourceable runtime environment, and then
rejects all optional skips. When `OPENLDAP_SOURCE` is
not set, the tagged source is shallow-cloned once into
`${TMPDIR:-/tmp}/ldap-go-openldap-source-2.6.13`; set
`OPENLDAP_SOURCE_CACHE` to move that managed cache:

```sh
BUILD=/tmp/ldap-go-openldap-reference-2.6 \
CYRUS_SASL_PREFIX=/path/to/cyrus-sasl \
LIBEVENT_PREFIX=/path/to/libevent \
  make openldap-full
```

An existing clean checkout at that exact commit can instead be selected with
`OPENLDAP_SOURCE`. A development branch such as `OPENLDAP_REL_ENG_2_6` is
rejected as compatibility evidence; `OPENLDAP_ALLOW_UNVERIFIED_REFERENCE=1`
is reserved for upstream diagnostics and emits a warning. `OPENSSL_PREFIX`,
`CYRUS_SASL_PREFIX`, `LIBEVENT_PREFIX`, `PREFIX`, `JOBS`, and
`OPENLDAP_ENV_FILE` are optional. On Homebrew systems the script detects
installed `openssl@3`, `cyrus-sasl`, and `libevent` prefixes. The configuration
signature permits deterministic incremental rebuilds while recording the exact
OpenLDAP commit and runtime library paths.

This separation is intentional. The 2026-08-03 diagnostic run of branch
commit `04a19039e8d13dc06316e2d90994d6ff2812eb3d` closed the LDAP connection
with EOF during the reference-only Sync plus Sort/VLV matrix, while the same
matrix passed at the pinned 2.6.13 release commit. A development-head failure
is tracked as an upstream diagnostic and is not allowed to change ldap-go's
compatibility oracle.

The core protocol differential drives the same Bind, Search, filter, Add,
Compare, Modify, Delete, and subtree ModifyDN sequence against slapd and
ldap-go. It compares result codes, matched DNs, diagnostics, referrals, and
normalized entry data. Overlay, control, SASL, transaction, CLI, migration,
and replication differentials remain separate tests and are included by the
same runner.

The `lloadd` evidence group first pins source hashes and behavioral anchors for
message-ID forwarding, tier fallback, Bind pinning, and restriction actions.
Always-on tests cover standalone configuration parsing, bounded BER frames,
message-ID and Abandon rewriting, scheduling and limits, pool recovery,
Simple service/client Bind, ProxyAuthz, auth-only SASL pinning, strict client
request envelopes, single-winner final responses, connection/Bind shutdown,
escaped and three-slash LDAPI addresses, unsupported-operation rejection,
explicit/disconnect/re-Bind Abandon, restriction rejection, and concurrent
client multiplexing. Gated live tests run equivalent no-backend/restriction and
Bind plus Search sequences against the built OpenLDAP 2.6.13 `lloadd` and the
Go proxy. These tests establish the documented subset, not complete daemon,
TLS, SASL, dynamic-config, or monitor compatibility.

The built-in client-tool suite uses raw LDAP wire fixtures to verify generic
control criticality and absent/empty/string/Base64/file values across Search,
writes, Who Am I?, and Extended operations. Multi-server fixtures cover
opt-in referral chasing, anonymous rebind, DN/scope rewriting, control
preservation, loops, and the five-hop limit. A pinned source contract anchors
the corresponding `clients/tools`, libldap request/error, and default-hop
behavior; `ldapcompare` rejects generic controls explicitly because its current
go-ldap API cannot attach them.

The ACL differential suite compares filter/value/object-class targets, DN and
attribute-value capture expansion, static and dynamic groups, connection and
relative-level selectors, and `OpenLDAPaci` behavior against OpenLDAP 2.6.13.
The ACI case uses a reference build with experimental `dynacl/aci` support; the
comparison is not used to promote the overall ACL row beyond `partial`.

The write-control differential compares permissive add/delete behavior,
private No-Op result code `0x410e`, rollback state, and pre/post-read response
control suppression against MDB. The null-backend differential additionally
compares synthetic Search output, Bind policy, discarded writes, Compare,
Assertion, paging, typesOnly, read controls, and No-Op. Source the environment
emitted by `make openldap-full` to use the pinned local build:

```sh
set -a
. /tmp/ldap-go-openldap-reference-2.6/openldap-reference.env
set +a
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run TestOpenLDAPReferenceNullBackend \
    -count=1
```

The relay differential additionally requires a slapd built with
`--enable-relay=yes --enable-rwm=yes --enable-sssvlv=yes`. It compares virtual
and target-root Bind, Search, Compare, Add, Modify, ModifyDN, Delete, direct
target visibility, suffix/attribute/objectClass/DN-value mapping, and inherited
server-side sorting:

```sh
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run TestOpenLDAPReferenceRelayBackend \
    -count=1
```

The strict back-meta group is selected with
`-run '^TestOpenLDAPReferenceMeta'`. It covers routing and Search union plus
the following fixed-reference behaviors:

- Cancel and Abandon forwarding and response ordering;
- Bind polling;
- RWM attribute/object-class wildcard allowlists and drop mappings;
- privileged `olcDbConnectionPoolMax` cross-frontend reuse and the concurrent
  LDAP message-ID multiplex subset;
- `olcDbProtocolVersion` 2 and 3; and
- the stable online single-target lifecycle.

The lifecycle fixture verifies that a zero-target parent accepts its first
target, an online URI replacement succeeds but leaves the in-process target
unavailable until restart, deletion of the sole `olcMetaTargetConfig` or
`olcMetaSub` returns 53, and adding that same target DN again returns 68. It
deliberately does not add a second target while a target connection is active:
the pinned OpenLDAP 2.6.13 process reaches an upstream assertion in that
scenario, so it cannot serve as a stable oracle.

```sh
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test -race ./internal/server \
    -run '^TestOpenLDAPReferenceMeta' \
    -count=1
```

Separate local protocol topologies cover the OpenLDAP default five-hop
referral boundary for final referrals and SearchResultReference, back-ldap and
back-meta preferred-URI failure/recovery/reload behavior, and single-URI
reconnects. Pinned source-contract tests anchor OpenLDAP's back-ldap URL-list
callback registration and reordering, the referral constant/result mapping,
privileged SASL auth-check identity selection, and auxprop failure mapping at
the verified 2.6.13 commit. Proxy SASL integration tests exercise PLAIN,
CRAM-MD5, DIGEST-MD5, and SCRAM-SHA-256 credentials, `authzTo`/`authzFrom`,
group and LDAP-URL rules, suffix mapping, ACL-bind/IDAssert selection, and
backend failure recovery on the same frontend connection.

These tests establish only the named subset. They do not cover complete
multi-target connection categories or dynamic topology, GSSAPI server Bind,
SASL security layers, complete referral rebind behavior, or the full
librewrite language.

The optional pbind differential requires a slapd built with `back_ldap`; its
`slapd -VVV` output must list `ldap`. It starts a ldap-go credential provider,
then runs equivalent OpenLDAP and ldap-go pbind front ends against it. Correct
and incorrect credentials, post-Bind Who Am I? identity, and provider
unavailability are compared:

```sh
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run TestOpenLDAPReferencePBindOverlay \
    -count=1
```

The always-on pbind tests parse multi-endpoint URI, StartTLS/TLS, timeout, and
quarantine configuration; reject duplicate/global overlays and malformed
settings; preserve response controls; and run a local provider/front-end
topology with an unreachable first endpoint. Retrylist tests verify delayed
quarantine, finite/permanent stages, recovery, and one concurrent probe. Live
StartTLS cases cover trusted critical TLS, untrusted peers, and noncritical
cleartext fallback. These tests do not claim connection reuse.

The always-on remoteauth tests parse mappings, DN/domain attributes, defaults,
retry/store policy, TLS settings, and SHA/SM3 public-key pins. Unit cases cover
domain truncation and line-oriented `file://` multi-provider realms. Local
provider/front-end topologies verify no-`userPassword` delegation, invalid
credentials, provider unavailability, local-password priority, successful
password storage, and local authentication after the provider stops. Live
StartTLS cases verify SHA-256 and SM3 peer pins plus wrong/missing pins. The
optional OpenLDAP 2.6 remoteauth differential compares delegation, local
priority, writeback, invalid credentials, and provider loss; it skips when the
selected slapd omits the overlay.

The always-on homedir tests run account Add, Modify, ModifyDN, Delete, and
configuration rollback against temporary POSIX directories. They verify
skeleton files and links, rename and ownership transitions, DELETE and ARCHIVE
policy, post-commit ordering, non-rollback on filesystem failure, and rejection
of traversal, symlink-parent, recursive skeleton, root, and archive-inside-home
paths. Repeated and race runs cover concurrent storage transitions. These tests
do not claim Windows behavior, FIFO skeleton copying, byte-identical tar
archives, or libc-specific regular-expression edge cases. A gated OpenLDAP 2.6
differential compares DELETE and ARCHIVE lifecycles and normalized filesystem
trees. Its recursive ownership assertion runs only when the test process has
permission to change UID/GID. Non-POSIX targets still compile the server but
reject a configured homedir overlay during runtime validation.

The monitor differential compares Root DSE discovery, the standard monitor
subtree hierarchy, stable entry attributes, dynamic operation/connection
counter invariants, Search/Compare, ACL and matched-DN behavior, anonymous
write failures, Log updates, database read-only changes, and runtime operation
restrictions against OpenLDAP 2.6.13.

Storage maintenance tests create a multi-partition bbolt database with binary
entry values and metadata, then check backup snapshot independence, restore
and rebuild round trips, private file modes, atomic overwrite protection,
invalid-backup isolation, cancellation, malformed logical records, and missing
bucket detection. CLI tests exercise `backup`, `restore`, `check`, `rebuild`,
and the `reindex` alias. These commands are intentionally offline because a
separate process cannot safely bypass bbolt's database lock.

Shutdown tests gate a storage update while canceling `Serve`, then verify that
the accepted write receives a successful response and is durable before the
server returns. A second case holds the gate past the configured deadline and
checks forced cancellation, rollback, and `ErrShutdownTimeout`; a persistent
Sync case verifies long-lived searches do not consume the grace period. The
same cases run under the race detector.

The PLAIN case invokes OpenLDAP `ldapwhoami` against ldap-go with
`olcSaslSecProps: none`. The other server-side cases invoke
`ldapwhoami -Y CRAM-MD5`, `ldapwhoami -Y DIGEST-MD5`, and
`ldapwhoami -Y SCRAM-SHA-256`. Each case skips when its local Cyrus SASL
plugin is unavailable.

The transaction cases run OpenLDAP `ldapmodify -E txn=commit/abort` against
ldap-go, then send the same duplicate-Add raw BER sequence to the reference
slapd to verify the failed message ID and atomic rollback semantics. Focused
wire tests cover generated-password commit and rollback, operation/encoded-byte
queue limits, the exact message-ID/OID/value shape of Aborted Transaction
Notice, and Bind/Unbind no-notice aborts. Pinned OpenLDAP 2.6.13 source and live
slapd tests record its transaction-control applicability and Bind behavior.
The accesslog differentials run Add, multi-operation Modify, Password Modify,
ModDN, Delete, failed Add/Modify, Search, Compare, Bind, Unbind, and an active
operation Abandon against slapd and ldap-go. They compare audit classes,
request/result metadata, Search parameters and counts, Compare assertions, Bind
methods, Abandon IDs, `reqMod`, selected `reqOld` values, rename fields, and
generated UUID/CSN shape. Local integration tests additionally cover
transaction rollback, No-Op exclusion, online configuration rollback,
restart-safe request timestamps, branch-scoped operations, purge/minCSN
movement, stale Sync-cookie rejection, frontend Extended exclusion, and a
complete ldap-go accesslog provider to delta-syncrepl consumer topology.

The DSEE retro changelog suite is different from the gated OpenLDAP accesslog
fixture. `TestSyncConsumerChangelogProtocolSnapshotReplayRestartAndPersist`
runs automatically as part of ordinary `go test ./...`, `make test`,
`make compat`, and `make full`. Its in-process protocol-level fake DSEE provider
serves Root DSE `firstChangeNumber`/`lastChangeNumber`, ordinary snapshot data,
one-level LDIF changelog records, and Netscape Persistent Search responses.
Together with focused tests, it covers initial snapshot fallback, stale-entry
cleanup, gap detection and rollback, atomic Add/Modify/ModDN/Delete replay and
`lastChangeNumber`, restart/resume, and persistent streaming.

No default project test requires Oracle software or `dsadm`. The commercial
DSEE fixtures in the upstream OpenLDAP source tree (`test072-dsee-sync` and
`test075-dsee-persist`) are optional and skip when `dsadm` is absent. They are
not part of ldap-go's default runner, and they have not been executed as
evidence here. Passing the fake-provider topology therefore does not establish
interoperability with a real Oracle DSEE deployment.

The auditlog differentials compare semantic LDIF records for proxied Modify,
Add, multi-operation Modify, Password Modify, both `deleteOldRDN` forms,
cross-superior ModDN, Delete, delete-all, Increment, binary/non-ASCII/long
values, failed and No-Op writes, and external file rotation. Separate cases
compare frontend-global scope and OpenLDAP's RFC 5805 behavior: no output
before commit or after explicit abort, but an earlier successful operation
remains in the flat file when a later operation causes database rollback.
Local integration adds online add/modify/delete rollback and restart, duplicate
overlay rejection, non-fatal unavailable paths, and concurrent race coverage.
A migration case converts a real slapd configuration, exports its
`olcAuditlogConfig` entry with `slapcat -n 0`, imports the folded LDIF
unchanged, and verifies that the configured file receives runtime writes.
The Don't Use Copy cases run `ldapsearch -E '!dontUseCopy'` against a ldap-go
shadow database and compare the same critical, non-critical, malformed,
alias, referral, and Compare requests with the reference slapd.
The global-disallow case compares anonymous and authenticated simple Bind plus
critical and non-critical Don't Use Copy results and diagnostics against the
same slapd configuration.
The proxy-authorization cases compare absent, duplicate, malformed, critical,
non-critical, anonymous-target, anonymous-authentication, database-root, and
`authz-policy to` behavior and diagnostics with the reference slapd.
The constraint case configures the same six rule types and restrictions on
slapd and ldap-go, then compares Add, Modify, ModifyDN, Relax, and failure
result codes.
The collect case pins the exact OpenLDAP 2.6.13 release commit and hard-asserts
static grammar, normalized duplicate/unknown/whitespace failures, overlapping
database-plus-frontend response order, normalization and duplicate retention,
requested attributes, `typesOnly`, filter and Compare invisibility, Paging,
Sort, ManageDsaIT, and source/target ACL behavior. Its write section first
asserts OpenLDAP's multi-modification and optioned-attribute bypasses, then
asserts ldap-go returns `unwillingToPerform` and rolls back both attempts. Run
that fixture alone with `-run '^TestOpenLDAPReferenceCollectOverlay$'` after
sourcing the environment emitted by `make openldap-full`.
The unique cases compare normalized duplicate values, independent URI domains,
`strict`, `ignore`, `serialize`, Add, Modify, ModifyDN, and managed Relax with
slapd. A second case converts a real slapd configuration, exports its
`olcUniqueConfig` entry with `slapcat -n 0`, imports the LDIF unchanged, and
verifies that uniqueness is enforced after ldap-go starts.
The valsort cases compare alpha, numeric, weighted secondary, raw-control,
single-value, Add, and Modify behavior with slapd. A second case converts a
real configuration, exports its `olcValSortConfig` entry with `slapcat -n 0`,
imports the LDIF unchanged, and verifies response sorting after ldap-go starts.
The retcode cases compare static and stored `errObject` behavior across all
applicable LDAP operations, result metadata, referrals, ManageDsaIT, synthetic
Search ACLs, successful Bind identity, C base-zero stored codes, unsolicited
responses, and disconnects. A separate case imports a real
`olcRetcodeConfig` entry emitted by `slapcat -n 0`. The OpenLDAP 2.6.13
in-directory Extended duplicate-response bug is asserted separately from
ldap-go's intentional single valid response.
The memberof/refint cases compare group and member Add/Modify/Delete/ModifyDN,
dangling errors, Relax, AddCheck, exact reference repair, subtree rename, and
Nothing placeholders with slapd. A separate `groupOfUniqueNames` case compares
Name And Optional UID equality, no-UID reverse membership and AddCheck, and the
OpenLDAP behavior that UID-bearing values do not follow member ModifyDN. A
third case exports real
`olcMemberOfConfig` and `olcRefintConfig` entries with `slapcat -n 0`, imports
them unchanged, and verifies both overlays after ldap-go starts.
The nestgroup suite first runs an always-on ldap-go integration covering all
four flags, requested attributes, `typesOnly`, positive and negated filters,
Compare isolation, cycles, dangling references, ACLs, ManageDsaIT, paging,
sorting, size limits, disabled-state rollback, delete/re-add, and restart. The
pinned OpenLDAP 2.6.13 fixture then covers defaults, custom attributes, reverse
overlay order, frontend/database placement, multiple instances, online
lifecycle, and the upstream configuration-conversion loss. The differential
compares the complete core outcome. The ldap-go fixture explicitly creates the
same alice, bob, and carol entries as the reference fixture before adding
groups, so dangling test data cannot masquerade as a filter difference.

Run the focused local and fixed-reference checks with:

```sh
go test ./internal/server \
  -run '^TestNestGroup|^TestLoadRuntimeDatabasesNestGroup' \
  -count=1

set -a
. /tmp/ldap-go-openldap-2.6.13-full/openldap-reference.env
set +a
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run '^TestOpenLDAPReferenceNestGroup(Fixture|Differential)$' \
    -count=1

go test -race ./internal/server \
  -run '^TestNestGroup|^TestLoadRuntimeDatabasesNestGroup' \
  -count=3
```

Focused size-limit unit cases cover exact-DN parsing, soft defaults, a smaller
client request, hard clamping, root bypass, and malformed values. Nestgroup's
explicit graph limits are hardening bounds; tests exercise their typed
`adminLimitExceeded` mapping without allocating production-sized fixtures.
The seqmod fixture separately pins startup and `cn=config` shape, singleton
placement, disabled/delete/re-add/restart behavior, basic write operations, and
cross-connection/race serialization against OpenLDAP 2.6.13.
The translucent suite covers whole-attribute merge, stale-local suppression,
remote-only visibility, complete-filter recheck, Compare shadow/fallback,
ManageDsaIT bypass, disabled reload, and invalid child-target rollback. Its core
Phase 2 cases add recursive local/remote split filters, remote-first Bind with
`bindLocal` fallback, `pwmodLocal`, strict deletion, noGlue parent handling, and
local-shadow Add/Modify/Delete/ModifyDN semantics including the partial-entry
ModifyDN failure observed in OpenLDAP. The optional reference tests pin the
OpenLDAP 2.6.13 commit and exact hashes of `translucent.c`,
`test034-translucent`, and `slapo-translucent.5`, then compare the same operation
sequence against reference slapd. Advanced controls, OpenLDAP's non-root
Modify-through-local-ACL edge, frontend/multiple instances, and arbitrary
cross-overlay effects are not claimed. Run the focused checks with:

```sh
go test -race ./internal/server -run 'Translucent' -count=3

LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 LDAP_GO_FAIL_ON_OPTIONAL_SKIP=1 \
  go test ./internal/server \
    -run '^TestOpenLDAPReferenceTranslucent(PhaseOne|PhaseTwoSourceContract|PhaseTwoDifferential|NoGlueDifferential)$' \
    -count=1 -parallel=1
```
The pcache suite has always-on two-server integration and pinned OpenLDAP
2.6.13 Phase 1/2 fixtures. It covers positive and negative misses/hits,
provider loss, `typesOnly` reprojection, exact and over-entry-limit results,
TTL plus consistency-check expiration, TTR positive-to-negative refresh,
offline pause/resume, query LRU, `olcPcacheMaxQueries`, deliberately stale
proxy writes, restart no-restore behavior, and critical/noncritical RFC 2696
handling. Configuration and state tests cover canonical and legacy names,
template/attrset selection, normalized keys, concurrent lookup/commit,
single-flight refresh, deep-cloned remote context, and reload state reuse. Run
the focused checks with:

```sh
go test -race ./internal/server -run 'Pcache' -count=3

set -a
. /tmp/ldap-go-openldap-2.6.13-full/openldap-reference.env
set +a
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run '^TestOpenLDAPReferencePcache(PhaseOne|PhaseTwo)$' \
    -count=1
```

These tests do not claim durable query restoration, Bind caching,
private-database controls, query deletion, arbitrary filter containment, or
cross-overlay parity.
The OTP suite verifies the complete OpenLDAP 2.6.13 embedded OATH schema,
normal LDAP schema validation, HOTP/TOTP candidate order, invalid parameter
convergence to `invalidCredentials`, static-password failure after token
consumption, sequential replay rejection, Password Modify state preservation,
online add/disable/delete/re-add/restart rollback, and runtime overlay counts.
Its race test launches simultaneous redemption of one HOTP value and requires
exactly one success, an intentional hardening over OpenLDAP's source-level
TOCTOU. `TestOpenLDAPReferenceOTPPhaseOne` pins the source hashes and runs the
same HOTP and TOTP flows against reference slapd and ldap-go. Focused commands:

```sh
go test -race ./internal/server -run 'OTP|Otp' -count=3
go test -race ./internal/schema -run OTP -count=3

set -a
. /tmp/ldap-go-openldap-2.6.13-full/openldap-reference.env
set +a
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run '^TestOpenLDAPReferenceOTPPhaseOne$' \
    -count=1
```

The suite does not claim contrib `userPassword` TOTP schemes, replication-wide
linearizable replay protection, HMAC-SM3, encrypted seed envelopes, or broad
cross-overlay parity. It also documents the OpenLDAP 2.6.13 TOTP drift bug:
runtime reads drift from params although schema permits it on the token, then
writes the successful value to the token.

The AutoCA unit and integration suite checks configuration rollback, startup
CA creation, restart reuse, strict attribute ordering, RSA and SM2/SM3 user and
server certificates, PKCS#8 public-key matching, email/IP SANs, concurrent
single-pair persistence, and response ACL filtering. The fixed
`TestOpenLDAPReferenceAutoCADifferential` fixture first self-asserts OpenLDAP
2.6.13, then compares normalized CA/leaf semantics and persisted behavior with
ldap-go:

```sh
go test -race ./internal/server -run 'AutoCA' -count=3
go test -race ./internal/schema -run AutoCA -count=3

set -a
. /tmp/ldap-go-openldap-2.6.13-full/openldap-reference.env
set +a
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run '^TestOpenLDAPReferenceAutoCADifferential$' \
    -count=1
```

The OpenLDAP comparison covers its RSA profile. The SM2/SM3 profile is an
ldap-go extension and is verified against the SM2 X.509 implementation rather
than claimed as upstream OpenLDAP behavior.
The DDS cases run Add, live-TTL Search, Refresh, Modify, ModifyDN, object-count,
disabled-overlay, and expiration-hierarchy checks against reference slapd.
They also run OpenLDAP `ldapexop refresh` against ldap-go and verify the
persisted TTL selected by the server.
The dynlist cases compare default and ordered multiple attribute sets,
arbitrary and mapped values, URI restrictions and local schemes, request-aware
nesting, static groups, reverse memberOf and negated filters, paging behavior,
ManageDsaIT, malformed URLs, missing values, ACL visibility,
`dgIdentity`/`dgAuthz`, and legacy dyngroup Compare behavior. A separate case
imports real `olcDynListConfig` and `olcDynGroupConfig` entries emitted by
`slapcat -n 0` and verifies both runtimes after startup.
The DIT content-rule cases execute the same auxiliary-class and
`MUST`/`MAY`/`NOT` Add/Modify sequence against slapd and ldap-go, comparing
result codes and diagnostics. A second case generates `slapd.d` with
`slaptest`, exports the matching schema entry with `slapcat -n 0`, imports that
LDIF directly, and boots ldap-go from it.
Name Form and DIT Structure Rule tests cover OpenLDAP-style `{n}` prefixes,
RFC description round trips, dependency and cycle rejection, registry cloning,
subschema publication and first-component filters, RDN and superior-rule
selection, forged governing IDs, transactional Add/Modify/ModifyDN rollback,
operational-attribute maintenance, and Relax bypass. OpenLDAP 2.6 has no slapd
registration or enforcement path for these schema elements, so this additive
RFC 4512 behavior has no reference-server differential; the migratable
`olcDitContentRules` portion retains its separate slapd differential suite.

The SCRAM-SHA-256 syncrepl case discovers the mechanism through the provider
Root DSE and skips when the OpenLDAP Cyrus SASL installation has no SCRAM
plugin. When plugins are installed outside the platform default directory,
point Cyrus SASL at them for the gated run:

```sh
SASL_PATH=/path/to/cyrus-sasl/plugins \
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run TestLDAPGoSyncreplConsumesOpenLDAPProviderWithSCRAMSHA256 \
    -count=1
```
