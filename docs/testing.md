# Compatibility testing

Compatibility claims require four layers of evidence.

## Platform build matrix

`make platform-builds` runs `CGO_ENABLED=0 go build ./...` for Linux amd64 and
arm64, macOS amd64 and arm64, Windows amd64, and FreeBSD amd64 using isolated
build caches. Windows excludes Unix-only HUP/USR1 lloadd management signals.
FreeBSD retains SQL backends for registered `database/sql` drivers but reports
the bundled pure-Go ODBC connector as unavailable because its upstream loader
does not compile there without cgo-generated symbols.

This matrix proves source-level portability for the listed targets. It does
not claim runtime execution across every kernel, filesystem, TLS provider,
ODBC driver, architecture revision, or external authentication service.

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

Schema-aware DN migration is exercised independently of LDIF parsing.
`TestLegacyV1SchemaAwareUpgrade` seeds physical v1 folded keys in Memory and
bbolt, reads them through the legacy path, then verifies lazy conversion to v2
keys for caseExact, caseIgnore, alias/OID, and multi-AVA identities.
`TestLegacyV1SchemaAwareAmbiguityIsFailClosed` requires mixed legacy/v2
duplicates to reject lookup, replacement, and deletion rather than select an
arbitrary entry. `TestLegacyV1BoltMaintenancePreservesSchemaIdentity` covers
check, backup/restore, compact, and rebuild behavior. The content-DN runtime
matrix is exercised by the `TestDNIdentity*` tests, while
`TestDNMultiAVARuntimeOpenLDAPSemantics` and the gated
`TestOpenLDAPReferenceDNMultiAVADifferential` compare canonical multi-AVA
behavior with the pinned server. These tests deliberately retain the separate
legacy identity rules for `cn=config`.

Pinned OpenLDAP 2.6.13 `slapadd` differentials import configuration emitted by
`slaptest` and `slapcat -n 0`, then compare the tested acceptance boundary for
unknown attributes, MUST and SINGLE-VALUE rules, default and explicit value
checks, child-before-parent input, final orphans, suffix ownership, obsolete
schema, and schema-disabled `objectClass` handling. The default-value-check
matrix specifically covers malformed integer acceptance, explicit rejection of
noncanonical integers, arbitrary-precision INTEGER acceptance, GeneralizedTime
hour and timezone forms, authzMatch normalization, DN and UUID
equality-normalizer rejection, default `lang-` options, unknown options, and
required/forbidden `;binary` transfer options. Unit and direct slapd tests also
verify that imported `olcAttributeOptions` replace `lang-` with configured
exact, trailing-`-`, and `range=` prefix definitions; range Search selection;
range rejection on Modify; binary shallow validators; idempotent import of
built-in `olcLdapSyntaxes`; and ordered `X-SUBST` validator inheritance. An
ordinary custom syntax without a validator is rejected only when full value
checking is requested.

Separate differentials compare preservation and generation of LastMod
attributes, `-S` CSN server IDs, `-w` suffix-root and config-database
`contextCSN`, config-backend metadata generation, glue-superior root-DN policy,
and `olcSyncUseSubentry` creation/update of `cn=ldapsync,<suffix>`. A real
`slapcat -n 0` fixture passes hierarchy, supported schema, and runnable-config
validation through the same import transaction; an invalid runtime setting has
a rollback regression test. Generated UUIDs, CSNs, and timestamps are compared
structurally rather than byte-for-byte.

Database-routing regressions cover the default first primary database,
most-specific automatic ownership, rejection of an overlapping ordinary
database, and routing from a selected glue superior into a more-specific
`olcSubordinate` partition. A pinned direct OpenLDAP topology also covers
configuration-order defaults, most-specific `-b`, hidden/disabled fallback,
glued `slapcat`, physical `-g` import/export, and duplicate subordinate-suffix
rejection. A direct back-ldif round trip and back-ldap rejection differential
plus fixed-source/unit coverage for the unavailable `wt` reference backend pin
the offline callback matrix. Arbitrary custom syntax/matching-rule modules, exact
partial-write/dry-run behavior, and large-import memory/write-lock bounds remain
outside the proved surface. This bounded matrix is not evidence of complete
`slapadd` or `slapcat` compatibility.

## Required checks

The repository exposes two supported entry points:

```sh
make compat
make full
```

`make compat` runs formatting, vet, all Go tests, the selected OpenLDAP
reference suite, and a bounded fuzz smoke pass. `make full` additionally runs
the complete suite with the race detector, builds the fixed OpenLDAP 2.6.13
source locally with the required backends, overlays, dynamic modules, and
`lloadd` enabled,
rejects every unexpected top-level skip, and fuzzes every parser target for
five seconds. Platform-only tests such as Linux `TCP_USER_TIMEOUT` are allowed
to skip on other operating systems through an explicit runner allowlist.
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

Missing `slapd`, `slapadd`, `slapcat`, `slaptest`, `lloadd`, or schema files
and unexpected top-level skips fail the run. Two SCRAM-SHA-256
cases may be reported as optional skips when the local Cyrus SASL installation
does not provide that plugin. Feature-gated differentials are optional when the
selected `slapd -VVV` omits their required backend or overlay: `ldap`, `meta`,
`null`, `relay`/rwm/sssvlv, `sql`, deref, homedir, pbind, and remoteauth. The strict
runner builds all of those features and converts every optional skip into a
failure.
`OPENLDAP_EXPECTED_VERSION` can
deliberately select another reference version, and `OPENLDAP_SCHEMA_DIR`
selects a non-standard schema installation. The reference suite runs package
tests serially for repeatability; set `LDAP_GO_OPENLDAP_PARALLEL` explicitly
for a separate concurrency stress pass.

The latest pinned local strict run passed 1,929 top-level tests against
OpenLDAP 2.6.13 commit `d172686d3d270bc961b78f3ff00d7019c8dfb094`, including
SQLite ODBC plus statically enabled passwd, dnssrv, asyncmeta, and `{CRYPT}`.
Its only allowed skip was the Linux-only TCP user-timeout test on macOS;
mandatory OpenLDAP differentials, source contracts, TLS, SASL, pcache, and
replication coverage all passed.

`scripts/test-openldap.sh` enables the real-KDC GSSAPI differential when it
finds MIT `krb5kdc`, `kdb5_util`, `kadmin.local`, and `kinit` plus the Cyrus
GSSAPI plugin. Homebrew `/opt/homebrew/opt/krb5` and
`/usr/local/opt/krb5` installations and standard Linux paths are discovered
without changing the user's Kerberos database. The test creates a temporary
realm, database, keytabs, ccache, and random KDC port, then runs the pinned
OpenLDAP `ldapwhoami` client against ldap-go with RFC 4752 no-layer,
integrity, and confidentiality. It also runs ldap-go's pure-Go password, FILE
keytab, and FILE ccache initiators. The ccache case runs first, forcing live
service-ticket acquisition before exercising all three protected connection
modes and Who Am I. Once dependencies are detected the test is mandatory; set
`LDAP_GO_OPENLDAP_GSSAPI_AUTO=0` to disable discovery on hosts that
intentionally prohibit local KDC processes.

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
`null`, `relay`, `sql`, and `mdb` backends plus every overlay used by the strict suite
and the standalone balancer. It builds the libraries, slapd/slap tools,
`lloadd`, and client tools, emits a sourceable runtime environment, and then
rejects all optional skips. Dynamic-module builds require `libltdl` headers and
the `libltdl` library. Homebrew `libtool` is detected automatically; elsewhere
set `LIBTOOL_PREFIX` to its installation prefix. The emitted slap-tool wrappers
are direct links to the built `.libs/slapd`, preserving the
`slapadd`/`slapcat`/`slaptest` argv[0] name that selects tool behavior. Libtool
launchers lose that name, while explicit `slapd -T` mode is not equivalent for
every operation such as configuration conversion. When `OPENLDAP_SOURCE` is
not set, the tagged source is shallow-cloned once into
`${TMPDIR:-/tmp}/ldap-go-openldap-source-2.6.13`; set
`OPENLDAP_SOURCE_CACHE` to move that managed cache:

```sh
BUILD=/tmp/ldap-go-openldap-reference-2.6 \
CYRUS_SASL_PREFIX=/path/to/cyrus-sasl \
LIBEVENT_PREFIX=/path/to/libevent \
  make openldap-full
```

The `/tmp/ldap-go-openldap-reference-2.6/openldap-reference.env` commands below
assume that explicit `BUILD` value. If `BUILD`, `TMPDIR`, or
`OPENLDAP_ENV_FILE` is changed, source the environment file emitted by the
build instead of that example path.

An existing clean checkout at that exact commit can instead be selected with
`OPENLDAP_SOURCE`. A development branch such as `OPENLDAP_REL_ENG_2_6` is
rejected as compatibility evidence; `OPENLDAP_ALLOW_UNVERIFIED_REFERENCE=1`
is reserved for upstream diagnostics and emits a warning. `OPENSSL_PREFIX`,
`LIBTOOL_PREFIX`, `CYRUS_SASL_PREFIX`, `LIBEVENT_PREFIX`, `ODBC_PREFIX`,
`PREFIX`, `JOBS`, and `OPENLDAP_ENV_FILE` are optional. On Homebrew systems the
script detects installed `openssl@3`, `libtool`, `cyrus-sasl`, `libevent`, and
`unixodbc` prefixes. When `ODBC_PREFIX` is found, the OpenLDAP 2.6.13 build is
configured with explicit unixODBC include and library paths for `back-sql`. The
configuration signature permits deterministic incremental rebuilds while
recording the exact OpenLDAP commit and runtime library paths.

The pw-totp differential builds the official contrib module from the pinned
source against the module-enabled reference tree. It compares SHA-1, SHA-256,
SHA-512, all three `ANDPW` variants, current/future/previous windows, malformed
credentials, replay rejection, root and ordinary password Bind, database and
frontend placement, duplicate instances, and Relax-managed `authTimestamp`
behavior against ldap-go. A separate local concurrency test asserts ldap-go's
intentional one-winner hardening for simultaneous first use; this is not claimed
as bug-for-bug parity with OpenLDAP's separate check/update sequence.

The pw-sha2 differential builds the official contrib module from the same
pinned source and covers all salted and unsalted SHA-256, SHA-384, and SHA-512
schemes. For each scheme, ldap-go generates a value through Password Modify
that is exercised by an OpenLDAP Simple Bind; OpenLDAP then generates a new
value through Password Modify, which is imported and exercised by a ldap-go
Simple Bind. Known upstream vectors, eight-byte generated salts, zero-salt
rejection, whitespace, and nonzero Base64 padding-bit behavior are also
covered.

The pw-pbkdf2 differential builds the official contrib module and covers its
`{PBKDF2}` SHA-1 alias plus the explicit SHA-1, SHA-256, and SHA-512 names.
Each scheme runs ldap-go Password Modify followed by OpenLDAP Bind, then
OpenLDAP Password Modify followed by ldap-go import and Bind. The module's man
page vectors, 10,000-iteration generation, 16-byte salt, adapted Base64 forms,
20/32/64-byte derived keys, malformed fields, exact whitespace/padding behavior,
and the 1,000,000-iteration verification bound have coverage. The suite records
the selected stricter parser rules, bounded work, and constant-time compare as
security hardening rather than bug-for-bug parity with the contrib C
implementation.

The pw-apr1 differential dynamically builds the pinned contrib module and
covers both `{APR1}` and `{BSDMD5}`. For each scheme, a ldap-go Password Modify
value is imported into OpenLDAP and exercised by Simple Bind; OpenLDAP then
generates a value through Password Modify that is imported and exercised by a
ldap-go Simple Bind. Local tests additionally cover the eight-character salt
mapping, noncanonical imported salts, malformed Base64, missing or oversized
salts, wrong passwords, and random-source failures.
The reference server accepts valid records for a 4,097-byte credential and a
65-byte salt, while ldap-go tests verify the documented hardening boundaries:
credentials above 4 KiB fail closed before PHK-MD5 processing, and imported
salts above 64 bytes are rejected.
The same differential imports a valid generated hash with 4,097 embedded
Base64 whitespace bytes into OpenLDAP, while the local verifier rejects it at
the documented stored-encoding work bound.

The pw-netscape differential dynamically builds the pinned verify-only module.
A binary-compatible `{NS-MTA-MD5}` value authenticates on OpenLDAP and after
import into ldap-go, while wrong credentials fail on both. A Base64 LDIF case
exercises a 32-byte binary salt and a credential containing NUL and `0xff` on
both servers. The source contract
and live test also preserve the upstream no-hash-function behavior: OpenLDAP
accepts the scheme as `password-hash` but Password Modify returns `other(80)`,
and ldap-go preserves the same configuration and operation result. Both
`slappasswd` implementations reject generation because no hash function exists.
Local ppolicy tests cover the same `other(80)` result for cleartext-hashing Add
and Modify paths.

The pw-radius differential dynamically builds the official pinned
`pw-radius` source against a deterministic radlib fixture. It verifies valid
and invalid Simple Bind, the module's canonical NAS-Identifier input, imported
`{RADIUS}<username>` values, and the no-hash-function `other(80)` result when
the scheme is selected for Password Modify. Independent raw-UDP tests decode
the Access-Request without using the client package's attribute decoder. They
cover full shared secrets, PAP truncation at 128 bytes, exact retry-wire and
source-port reuse, per-secret failover re-encryption, Identifier and Response
Authenticator behavior (including libradius acceptance of an authenticated
nonmatching Identifier), valid and invalid Message-Authenticator attributes,
declared-length authentication with ignored trailing bytes,
invalid-authenticator rejection, timeout failover, dead-time reprobes, and
immediate termination on a valid reject. Parser tests include quoted secrets and
malformed input while the implementation clears temporary byte-backed fields.
Server integration adds SASL PLAIN, Password Modify old-password checks,
LDIF migration, process-wide module serialization across server instances,
configuration reload, deterministic ppolicy rejection before network I/O,
concurrent external password-history key rejection, and LDAP Transaction
verification at commit rather than queue time. Transaction coverage also proves
that a blocked RADIUS server does not hold the directory write transaction,
an earlier unrelated entry update remains valid, an earlier policy update is
used for history verification, a wrong old password does not expose history or
later-operation credentials, and an earlier LDAP failure retains its message ID
without contacting a later deterministic ppolicy operation. A multi-valued
regression requires the first RADIUS value to reject and the second to accept,
then verifies that the accepted value drives the next operation and that no
verification is repeated under the writer. A private-clock regression verifies
that rollback preflight CSNs and accesslog timestamps do not advance global
server clocks. Admission tests reject RADIUS write transactions combined with
`translucent` or `chain` remote effects.
Seqmod concurrency tests cover deterministic transaction lock ordering.

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

`TestOpenLDAPReferenceMatchedValuesControl` sends the same RFC 3876 control
to the pinned slapd and ldap-go. It compares value-level union filtering,
unknown attributes, numeric attribute OIDs, language options, OpenLDAP's inert
approx item, empty filter sequences, and `typesOnly`. Local tests additionally
cover ordering and extensible rules, ACL-hidden values, paging, malformed BER
disconnects, Root DSE publication, pCache cache-fill stripping, and the
built-in `ldapsearch -E mv=` encoder.

`TestOpenLDAPReferenceObjectClassAttributeSelection` compares RFC 4529 Search
projection with pinned OpenLDAP 2.6.13 for inherited classes, numeric OIDs,
`extensibleObject`, unknown classes/options, mixed selectors, `1.1`, and
`typesOnly`. It also pins the read-control difference: OpenLDAP rejects a
known `@objectClass` in pre/post-read, while ldap-go implements the RFC 4529
AttributeSelection requirement. Local tests cover ACL filtering and critical
unknown-class rollback, strict selector syntax, SQL on-demand attribute
loading, and fail-closed pCache attrset coverage.

`TestOpenLDAPReferenceDomainScopeAndSearchOptions` compares both hidden
Microsoft/OpenLDAP controls against pinned slapd. The 30-case matrix covers
Domain Scope absent/empty/nonempty values, Search Options flags 0/1/2/3/-1,
criticality, permissive tags and trailing bytes, malformed values, duplicate
and mixed ordering, continuation references, and final referral conversion.
Local tests additionally cover frontend control stripping, LDAP proxying,
complete-response pCache hits, streaming sock responses, response controls,
Root DSE hiding, and `ldapsearch -E domainScope`.

`TestOpenLDAPReferenceSessionTrackingControl` pins the hidden Session Tracking
control against OpenLDAP 2.6.13. It covers required/empty fields, permissive
inner tags and the single trailing-tag edge, IP/name/OID limits, duplicate
controls, criticality, non-printable fields, and OpenLDAP's invalid-format-OID
success/ignore defect. Its operation matrix covers Bind, Search, Add, Modify,
ModifyDN, Delete, and Who Am I. Local tests additionally verify operation-local
audit isolation, trusted identity separation, LDAP proxy preservation plus
generated-control ordering, pCache refresh stripping, sock overlay handling,
and Root DSE hiding.

`TestOpenLDAPReferenceTreeDeleteMDBProtocol` pins hidden-control parsing,
criticality, leaf/non-leaf behavior, operation scope, and Root DSE hiding for
MDB. `TestOpenLDAPReferenceTreeDeleteBackSQL` runs the same SQLite data through
OpenLDAP ODBC back-sql and ldap-go for critical/noncritical success, No-Op, and
ACL failure. Successful and No-Op database snapshots match exactly. The ACL
case records a hardened divergence: OpenLDAP commits a partial prefix and
returns success, while ldap-go's preflight returns `insufficientAccessRights`
without changing any SQL row. Local tests add three-level deletion, child ACL,
base-only Pre-Read, procedure execution, forced transactions under
`olcSqlAutocommit`, and atomic rollback coverage.

`TestOpenLDAPReferenceLDAPv2ControlsDisconnect` drives identical raw LDAPv2
Bind, Search, Modify, Abandon, and Unbind sequences against slapd and ldap-go.
It covers critical and noncritical controls, empty wrappers, malformed Control
elements, failed authentication retaining v2 state, control-free Abandon, and
v2-to-v3 rebind. `TestOpenLDAPReferenceHiddenControlDiscovery` verifies that
Relax and Transaction Specification remain usable but hidden from Root DSE.

`TestOpenLDAPReferenceLazyCommitControl` compares critical/noncritical
acceptance, absent/value/duplicate validation, unsupported Bind/Extended
operations, write lifecycle, and Root DSE hiding. The paired pinned source
contract proves why no durability fault test is claimed: OpenLDAP 2.6.13's
bundled LMDB masks out the operation flag before transaction creation and its
commit path only observes global environment flags. Local tests verify normal
write and No-Op results without weakening Memory or bbolt durability.

Focused DN identity checks can be repeated without an external server:

```sh
go test -race ./internal/storage \
  -run '^TestLegacyV1SchemaAware(Upgrade|AmbiguityIsFailClosed)$|^TestLegacyV1BoltMaintenancePreservesSchemaIdentity$' \
  -count=1
go test -race ./internal/server \
  -run '^(TestDNMultiAVA(SchemaAwareIdentity|NormalizedString|RuntimeOpenLDAPSemantics)|TestDNIdentity.*)$' \
  -count=1
```

The local index suite runs the same candidate-versus-scan assertions against
Memory and bbolt for equality, presence, substring initial/any/final, ordering,
mixed boolean filters, long-value overflow, replace/delete/rename, rollback,
raw-write invalidation, reopen, backup/restore, check, and compact. Server tests
also validate `olcDbIndex` aliases/OIDs, matching-rule admission, LDAP INTEGER
ordering, generalizedTime whole/fractional-second ordering against the schema
comparator, ordered `default` inheritance, `nolang`/`notags`, supported
`approx`, duplicate definitions, initial build, and configuration reload.
Approximate matching tests compare OpenLDAP's UTF-8 normalization, word order,
and Metaphone result, including `Alice Smith ~= Alice Smyth`, on Memory and
bbolt. Associated phonetic approximate queries are also checked to use a full
scan because phonetic postings are not implemented. These tests prove that an
accepted index does not omit a matching candidate; they do not qualify index
selectivity or throughput at production scale. Run them with:

```sh
go test -race ./internal/storage \
  -run '^(TestEqualityIndex|TestSubstringAndOrderingIndex)' -count=1
go test -race ./internal/server \
  -run '^(TestSortableLDAPInteger|TestLoadDatabaseEqualityIndexes|TestEnsureSearchEqualityIndexes|TestDatabaseIndexDefaultNoLangApproximateMemoryAndBolt|TestOpenLDAPReferenceApproximateMatching)' \
  -count=1
```

The back-sock differential starts one Unix socket fixture and drives the same
Bind, Search, Add, Modify, Compare, ModifyDN, Delete, Password Modify, and
Unbind session through the pinned OpenLDAP 2.6.13 slapd and ldap-go. It compares
LDAP result codes and normalized Search entries, then compares the command,
message ID, suffix, connection metadata, filter, LDIF fields, and extended
request value observed by the fixture. Always-on protocol tests separately
cover Base64/folding, limits, malformed RESULT/LDIF input, and parser fuzzing.
A second live differential verifies that invalid Add/Modify/Compare/ModifyDN
requests and anonymous Password Modify are rejected before any socket request,
while a first-component Compare assertion and OpenLDAP's empty Modify are
delegated. It compares response tags, result codes, matched DNs, diagnostics,
network behavior, and whether the fixture was contacted.
Always-on Unix-socket tests additionally prove that a sock-targeted RFC 5805
update returns `unwillingToPerform` while queueing and does not dial the socket,
and that the commit guard reports the first affected message ID before any
external or storage work. Critical chaining and critical Bind password-policy
controls reject before dialing; the noncritical chaining ignore path is checked
separately. The socket-overlay work is protocol-only: tests cover a
sole `CONTINUE` response and one-way `ENTRY`/`RESULT` encoding, not imported
overlay configuration or an operation callback chain.

The back-sql differential starts a pinned OpenLDAP 2.6.13 `slapd` linked to
unixODBC and a ldap-go server over two identically seeded SQLite databases. It
compares successful and failed Bind, base/one/subtree Search, equality and
substring filters, missing bases, Compare result codes, inherited object
classes, binary values, `structuralObjectClass`, `entryUUID`, and
`hasSubordinates`. It also compares mapped Add, Modify, leaf ModifyDN, and
Delete, including No-Op execution and rollback, injected procedure failures,
SQL rollback state, LDAP-visible state, and a successful add-through-delete
lifecycle. `TestOpenLDAPReferenceSQLBackend` passes this live matrix.
Server-generated `entryCSN` is deliberately excluded. The strict Docker image
installs unixODBC and the SQLite ODBC driver; no Oracle database or client is
required. The fixture does not prove behavior on PostgreSQL, MySQL, Oracle, or
DB2 drivers.
Separate pure-Go SQLite tests record generated SQL and verify parameterized
object-class equality and mapped presence candidates, partial `AND`,
all-or-fallback `OR`, assertion injection resistance, and safe full-ID fallback
for mapped equality. The fallback cases cover case-ignore whitespace/list
normalization and SQLite TEXT values compared with byte-identical BLOB
parameters. They also force an unrequested mapping query to
fail to prove requested/filter attribute pruning, retain binary values,
exercise `olcSqlFetchAttrs` and
synthesize and de-duplicate `olcSqlBaseObject: TRUE`, and reject file base
objects, native layers, custom scope templates, subtree shortcuts, and
schema-check directives. `olcSqlFetchAllAttrs` is present in the implementation
but does not yet have a focused assertion in this planner test. These new
planner/directive cases are not all part of the live OpenLDAP ODBC differential.

The `lloadd` evidence group first pins source hashes and behavioral anchors for
message-ID forwarding, tier fallback, Bind pinning, and restriction actions.
Always-on tests cover standalone configuration parsing, bounded BER frames,
message-ID and Abandon rewriting, scheduling and limits, pool recovery,
Simple service/client Bind, ProxyAuthz, auth-only SASL pinning, strict client
request envelopes, single-winner final responses, connection/Bind shutdown,
escaped and three-slash LDAPI addresses, unsupported-operation rejection,
explicit/disconnect/re-Bind Abandon, RFC 3909 Cancel outer/inner ID rewriting,
same-upstream and same-association enforcement, pending-limit signaling leases,
ProxyAuthz preservation, malformed/duplicate/retry handling, restriction
rejection, and concurrent client multiplexing. TLS topologies cover
client-facing StartTLS and LDAPS, post-upgrade Bind/Search, outstanding-request
rejection, handshake failure, upstream LDAPS and optional/critical StartTLS,
service Bind ordering, CA/SAN and CRL failure, and mutual TLS. Service SASL
tests cover PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-SHA-1/256/512, invalid server
proofs, strict challenge bounds, credential clearing, and StartTLS-before-Bind.
Socket-option tests cover TCP keepalive before and after TLS wrapping, Linux
`TCP_USER_TIMEOUT`, fail-closed option errors, and LDAPI exclusion. Gated live
tests run equivalent no-backend/restriction and Bind plus Search sequences
against the built OpenLDAP 2.6.13 `lloadd` and the Go proxy. Cancel is verified
locally against RFC 3909 because the pinned OpenLDAP lloadd forwards an
unmodified inner ID; that known defect is not the compatibility oracle. These
tests establish the named service-authentication subset. Separate local tests
cover DIGEST-MD5 integrity/privacy, GSSAPI protocol layers, hot reload, Monitor
ACL/sort/VLV/paging, and hardening; a repeatable real-KDC lloadd topology and
complete daemon compatibility remain. Local
listener topologies cover PROXY v2 TCP4/TCP6 logical addresses and copied TLVs,
logical versus transport metadata, malformed/truncated/timeout recovery,
bounded option bytes/TLV metadata count, `pldaps` header-before-TLS ordering,
Bind/authz/TLS snapshots, and rejection on ordinary LDAP/LDAPS. LOCAL cases
verify that family is ignored; both commands consume payloads through 520 bytes
as opaque options. PROXY still validates its family/address block, while valid
TLVs are extracted best-effort and malformed option encoding is accepted. The
implementation also caps concurrent header parsers, but the
focused suite does not yet saturate that cap. There is no claim for PROXY v1,
UDP/UNIX families for the PROXY command, or complete OpenLDAP lloadd behavior.

The built-in client-tool suite uses raw LDAP wire fixtures to verify generic
control criticality and absent/empty/string/Base64/file values across Search,
writes, Who Am I?, and Extended operations. Multi-server fixtures cover
opt-in referral chasing, anonymous rebind, DN/scope rewriting, control
preservation, loops, and the five-hop limit. A pinned source contract anchors
the corresponding `clients/tools`, libldap request/error, and default-hop
behavior. The raw Compare fixture verifies generic `-e`, noncritical `-M`,
critical `-MM`, duplicate rejection, unavailable-critical result propagation,
referral control preservation, SASL PLAIN, and verbose TRUE/FALSE/UNDEFINED,
matched-DN, diagnostic, referral, and response-control output. Source and binary
differentials verify that every `ldapcompare -E` spelling is rejected before a
connection because OpenLDAP 2.6.13 does not register its otherwise present
handler. `ldapexop passwd` tests cover
target/current identities, old/new/generated passwords, password sources,
controls, response decoding, and dry-run validation. `ldapmodify` fixtures
cover `-a` Add records and default no-`changetype` Modify records with
add/delete/replace/increment blocks and an omitted final separator. Client-side
Search tests
cover stable ASCII case-insensitive multi-value/missing-value sorting, empty
`-S` UFN-component sorting, per-page rather than global paged sorting, trailing
`dc` domain folding, uppercase hexadecimal escapes, preserved hexadecimal BER
AVAs, escaped multi-AVA formatting, end-to-end `-S/-u` LDIF, and unsafe
sort-attribute rejection. A pinned OpenLDAP 2.6.13 client differential compares
the covered page order and UFN output. Additional byte-for-byte differentials
cover default extended LDIF, `-L/-LL/-LLL`, arbitrary repeated `L`,
SearchReference output, result diagnostics/counts, and per-query `-c` behavior
for malformed filters and LDAP operation errors. RFC 4516 referral tests cover
all URL fields, percent decoding, scope aliases, result 89/92 mapping, and the
intentional empty-DN base-preservation rule. Language-option projection is
compared with OpenLDAP for bare/exact/range descriptions, subtypes, `*`, and
`typesOnly`. Locale-dependent ordering outside the fixture remains unclaimed.
`TestLDAPClientSASL*` drives raw-wire
and project-server exchanges for PLAIN, CRAM-MD5, DIGEST-MD5,
SCRAM-SHA-1/256/512 with all three `-PLUS` variants, and mutual-TLS EXTERNAL.
It validates GS2/authzid, server proofs, RFC 5929 certificate hash selection,
malformed challenges, binding mismatch, downgrade/replay rejection,
secret-free diagnostics, StartTLS ordering, and option conflicts. GSSAPI client
tests cover password, FILE keytab, and FILE ccache credentials plus RFC 4121
no-layer, integrity, and confidentiality negotiation. Repeatable native
real-KDC automation and platform-specific credential stores remain external.

Global server TLS configuration has separate transaction and live-handshake
coverage. `TestGlobalTLSConfiguration*` validates supported inline/file
material and rejects unsupported or inexact OpenSSL directives. Extended cases
cover semicolon-separated OpenSSL hash directories, ignored non-hash files,
DER de-duplication, internal and escaping symlinks, descriptor-consistent size
checks, directory/file/byte/certificate budgets, traditional encrypted PEM,
password-file path/permission/size rules, supported single-curve aliases, and
explicit rejection of PKCS#8 encryption or inexact multi-curve selectors.
`TestGlobalTLSOnlineCertificateReload` rotates a live LDAPS/StartTLS
certificate, checks that new connections see the candidate only after commit,
and verifies invalid replacement rollback; `TestGlobalTLSVerifyClientDemand`
tests required client certificates. Run the focused transport checks with:

```sh
go test -race ./internal/server \
  -run '^(TestGlobalTLS.*|TestOnlineConfigurationRejectsUnsupportedGlobalTLSDirectiveAndRollsBack)$' \
  -count=1
go test -race ./internal/lloadd \
  -run '^(Test(ClientStartTLS|BackendTLS|BackendLDAPS|BackendStartTLS|ConfigRuntimeBackendTLS|ServiceSASL|RuntimeServiceSASL|RuntimeConfigMapsServiceSASL|BackendKeepAlive|BackendSocket|BackendTCPUserTimeout|NewProxyClonesAndValidatesClientTLS).*)$' \
  -count=1
go test -race ./cmd/ldap-go \
  -run '^(TestLDAPClientSASL.*|TestLloaddCommandServesStartTLSAndLDAPSListeners|TestRunLloadd.*SocketOptions|TestRunLloaddTCPUserTimeout.*)$' \
  -count=1
```

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
password storage, verify-only-scheme cleartext fallback, and local authentication
after the provider stops. Live
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

The `slapadd` continuation tests import parent/child records out of order,
isolate one invalid record, retain successful records, verify line/DN
diagnostics and nonzero partial-failure exit status, and confirm `-c -u` leaves
the destination byte-for-byte unchanged. Configuration-database continuation
is rejected. Quick-mode tests prove that `-q` disables value checks while
schema checks remain independently controlled by `-s` / `schema-check=no` and
the normal `objectClass` requirement remains active. They also verify the
warning that explicit `value-check=yes` is disabled and that the parser,
routing, hierarchy, and storage paths still run. A gated pinned OpenLDAP 2.6.13
test compares `-c` partial retention and the `-q` schema/value-check warning and
exit behavior. The direct `ImportLDIF` API remains covered by atomic rollback
tests.

Shutdown tests gate a storage update while canceling `Serve`, then verify that
the accepted write receives a successful response and is durable before the
server returns. A second case holds the gate past the configured deadline and
checks forced cancellation, rollback, and `ErrShutdownTimeout`; a persistent
Sync case verifies long-lived searches do not consume the grace period. The
same cases run under the race detector.

The PLAIN case invokes OpenLDAP `ldapwhoami` against ldap-go with
`olcSaslSecProps: none`. The other server-side cases invoke
`ldapwhoami -Y CRAM-MD5`, `ldapwhoami -Y DIGEST-MD5`, and
`ldapwhoami -Y SCRAM-SHA-256`. Gated channel-binding cases run SHA-1/256/512
over verified StartTLS with `sasl_cbinding=tls-endpoint`; Cyrus 2.1.28 exposes
these as base SCRAM mechanism names carrying a `p=tls-server-end-point` GS2
header. Each case explicitly skips when its local Cyrus SASL plugin or
channel-binding feature is unavailable.

The full strict wrapper also caches and SHA-256 verifies the pinned HAProxy
PROXY protocol specification used by the v1 and v2 UNIX source contracts.
`HAPROXY_SOURCE` can select a pre-populated snapshot; otherwise
`HAPROXY_SOURCE_CACHE` defaults to a temporary managed cache.

The transaction cases run OpenLDAP `ldapmodify -E txn=commit/abort` against
ldap-go, then send the same duplicate-Add raw BER sequence to the reference
slapd to verify the failed message ID and atomic rollback semantics. Focused
wire tests cover generated-password commit and rollback, operation/encoded-byte
queue limits, the exact message-ID/OID/value shape of Aborted Transaction
Notice, and Bind/Unbind no-notice aborts. Pinned OpenLDAP 2.6.13 source and live
slapd tests record its transaction-control applicability and Bind behavior.
Compatibility-control cases run against Memory and bbolt and verify that
critical ProxyAuthz on Start returns `unavailableCriticalExtension`, while
pre-read or post-read on a transaction update returns `unwillingToPerform`
without response controls and leaves the transaction available for abort.
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

RFC 4533 DN routing has an independent schema matrix.
`TestDNIdentitySyncSearchRFC4533` covers base-change detection plus base,
one-level, subtree, present, and delete routes. `TestDNIdentitySyncProviderState`
covers context entries, checkpoint suffixes, tombstones, and session-log
records. `TestDNIdentitySyncreplPaths` covers consumer configuration and
application paths. Each uses caseExact/caseIgnore attributes, aliases/OIDs,
multi-AVA DNs, and Memory/bbolt where storage is involved. Overlay-specific
`TestDNIdentity*` cases apply the same matrix to implemented overlays; this is
not evidence for arbitrary cross-overlay order or replication topology.

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
. /tmp/ldap-go-openldap-reference-2.6/openldap-reference.env
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
single-flight refresh, deep-cloned remote context, and reload state reuse.
`TestPcacheSchemaAwareTemplateContainment`,
`TestPcacheSubstringContainmentDirection`, and
`TestPcacheExtensibleTemplateSemantics` cover schema-aware equality,
OpenLDAP-direction substring containment, unordered AND/OR matching,
attribute/OID and matching-rule aliases, and extensible filters.
`TestPcacheBindRealLDAPBackendProvider` exercises successful provider Bind,
verifier-only storage, provider loss, offline TTL, and connection identity;
the other `TestPcacheBind*` cases cover limits, concurrent verification,
schema-aware DN keys, reload clearing, and pinned source anchors. Run the
focused checks with:

```sh
go test -race ./internal/server -run 'Pcache' -count=3

set -a
. /tmp/ldap-go-openldap-reference-2.6/openldap-reference.env
set +a
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run '^TestOpenLDAPReferencePcache(PhaseOne|PhaseTwo)$' \
    -count=1
```

These tests do not claim durable query restoration, private-database controls,
query deletion, every advanced control, a live OpenLDAP Bind-cache
differential, or arbitrary cross-overlay parity.
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
. /tmp/ldap-go-openldap-reference-2.6/openldap-reference.env
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
. /tmp/ldap-go-openldap-reference-2.6/openldap-reference.env
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
