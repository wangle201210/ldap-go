# Common OpenLDAP production scope

This audit separates common deployment capability from exhaustive OpenLDAP
source-module parity. The detailed, test-bounded claims remain authoritative in
[compatibility.md](compatibility.md).

The practical acceptance target is a school or company directory: account
authentication, users and groups, access control, password policies, encrypted
connections, directory administration, migration, backups, and a single writer
with replicas. This does not require complete OpenLDAP source-module parity.

## Common deployment paths

The following paths are implemented, with local tests and focused pinned
OpenLDAP 2.6.13 differentials. Coverage varies by feature; the compatibility
matrix records the individual boundaries:

- Local authoritative directories using Memory or bbolt storage: Bind, Search,
  Compare, Add, Modify, Delete, ModifyDN, aliases, referrals, common controls,
  Password Modify, transactions, schema, ACLs, limits, indexes, and `cn=config`.
- TLS, LDAPS, LDAPI, Simple Bind, PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM, GSSAPI,
  EXTERNAL, and the documented TLCP deployment mode.
- OpenLDAP password hashes plus the documented SM3 and contributed schemes,
  password policy for Simple Bind and password writes, account usability,
  password history, expiry, and lockout. SASL authentication is a separate
  path; it does not inherit Simple Bind policy enforcement.
- Standard single-writer syncrepl, single-provider delta-syncrepl, syncprov,
  restart/cookie recovery, A-to-B-to-C delta cascading, common fractional
  replication, and non-delta multi-provider/mirror topologies within the tested
  matrix.
- LDIF import/export, schema validation, backup/restore, rebuild/check, online
  backup, retention, OpenLDAP-style offline/client tools, and the bilingual Web
  administration process. Native config imports build and validate the runnable
  candidate before publication; uncertain Web writes retire their LDAP session.
- Common overlays and proxy paths listed in
  [openldap-module-coverage.md](openldap-module-coverage.md). Direct back-ldap
  Search enforces local database/global ACLs and explicit access policies,
  direct back-ldap RWM maps both directions, and meta/asyncmeta fetch hidden ACL
  dependencies before restoring the requested projection.
- `ldapsearch` named controls, Sort/VLV/deref, and a true streaming
  `sync=rp[/cookie][/<slimit>]` path with bounded cancellation.

An earlier pinned full strict run passed **2,188 top-level tests** against
OpenLDAP 2.6.13 commit
`d172686d3d270bc961b78f3ff00d7019c8dfb094`. That historical gate also included
race, staticcheck, and fuzz checks; it is not a claim that those checks were
rerun at every subsequent revision. Current validation uses `CGO_ENABLED=0`;
the race detector is not part of this cgo-disabled acceptance run.

## Practical acceptance on 2026-09-20

Revision `99c8326` was exercised on Darwin/arm64 with Go 1.26.4 and
`CGO_ENABLED=0`. All services and databases for these checks were disposable;
no existing directory was modified.

| Check | Result and evidence |
| --- | --- |
| 10,000-user lifecycle | Import, offline reindex, indexed and unindexed Search, all 10,000 users paged at 1,000 per page, Modify, Delete, restart, durable-change verification, and offline database check passed. There were 9,999 users after Delete. |
| Concurrent operations and crash recovery | Eight client streams ran Search, Compare, Modify, Bind, and Add/Delete for 60 seconds. One SIGKILL was injected; recovery took 3 seconds. The runner counted 25,262 successful and 62 failed operations out of 25,324 attempts. All failed batches ended during the injected outage. Final online and offline content validation passed. |
| Same-SDK OpenLDAP differential | `TestOpenLDAPReferenceGoLDAPSDKStateMachineDifferential` passed against the pinned native reference: Bind, Search, paging, limits, Add, Compare, Modify, Password Modify, subtree move, Delete, and final snapshots. |
| Password policy | Native differentials `TestOpenLDAPReferencePasswordPolicy`, `TestOpenLDAPReferencePasswordPolicyExpiration`, and `TestOpenLDAPReferencePasswordPolicyControlsAndTiming` passed for the Simple Bind policy path. Local authentication, ACL, and group lifecycle regressions also passed. |
| SASL PLAIN policy boundary | `TestOpenLDAP2613SASLPlainPasswordPolicyBoundary` passed eight endpoint/scenario cases. Both servers reject locked/expired accounts with Simple Bind, but accept the correct password through mapped directory-auxprop PLAIN. Wrong PLAIN passwords do not update `ppolicy` failure counts. This is a tested deployment boundary, not account-policy enforcement through SASL. |
| Replication recovery | `TestRealProcessHAQualification` passed with `LDAP_GO_HA_QUALIFICATION_HEAVY=1`: independent provider/consumer processes, hard crashes, 128 gap writes, expired replay history, reconnect, convergence, and durable consumer cookies. |
| Backup and restore | Validated restore publication/rejection, online backup creation and authorization, and restoration of the snapshot passed. |
| Web administration integration | Real HTTP-to-LDAP login, queries, create/modify, password change and subsequent Bind, and ACL rejection tests passed. Browser visual tests were not rerun in this acceptance round. |

The implementation immediately preceding this acceptance also passed the full
Go suite, `go vet`, and six cgo-disabled platform builds. The focused
[configuration-schema differential](configuration-schema.md) passed 1,023 leaf
cases, including two explicitly expected unsupported-thread-setting differences.
Platform builds establish compilation, not runtime qualification on every OS.

The scale and crash runners produced the same executable SHA-256:
`58b53d1bd7e3d031bdd28f39118ade6ad12817b1c9dad816238e6101c28396a3`.
Artifact directory names were
`ldap-go-scale-qualification-20260920T021825Z-45971` and
`ldap-go-qualification-20260920T021705Z-11919`, respectively. Each contains
`report.json`, effective configuration, logs, and validation output.

These are correctness and bounded recovery checks, not a one-hour soak or a
new OpenLDAP performance comparison. Scale timing/resource ceilings were left
at their record-only defaults. Crash workload counts follow the runner's batch
accounting; they are not a count of every LDAP protocol message. SDK comparisons
normalize entry/value order and DN identity, ignore password hash bytes and
diagnostic text, and treat paging cookies as opaque. They do not establish
byte-for-byte responses for every LDAP operation or configuration.

### Deployment conditions

- Configure TLS certificates, ACLs, password policy, indexes, and service limits
  for the actual applications; the example root password is not a deployment
  credential. See [operations.md](operations.md).
- Use Simple Bind over verified TLS for directory-password authentication that
  relies on `ppolicy`. Do not map those users into password-based SASL mechanisms
  and assume the same account lockout, expiry, or reset restrictions apply.
- Qualify application login/search filters and restore procedures against the
  intended schema and data. MDB files require LDIF migration, and further
  third-party module reimplementation remains outside project scope.
- The common replication target is one writer with replicas. The checks above
  do not provide automatic primary election or qualify arbitrary writable
  multi-provider topologies.
- Online physical backup requires LDAPI and database-administrator access;
  restore requires an offline target database.
- Each Web Admin process targets one LDAP endpoint. Its default per-request
  import/export limits are 1,000/5,000 entries; use offline tools for large
  migrations. See [Web Admin coverage](webadmin-feature-matrix.md).

## Explicit advanced boundaries

These are not silently presented as supported common paths:

- Writable delta multi-provider/mirror mode supports attribute-level Modify
  merging with complete local accesslog history and full-suffix replication.
  Delete/rename, increment, ordered values, request controls, and history gaps
  fail closed. This remains a limited compatibility path, not a general
  replacement for the standard multi-provider topology.
- Syncrepl DIGEST-MD5 and GSSAPI support integrity/confidentiality layers
  without TLS, including protected reconnect and cookie persistence tests.
  The unmodified local Cyrus 3DES provider cannot initialize safely. A pinned,
  isolated parity-only repair now provides native self-checks and bidirectional
  3DES interoperability evidence on Linux and Darwin; this is explicitly not an
  unmodified-Cyrus result. See [the behavior audit](openldap-behavior-audit.md).
- Relay, back-ldap RWM, and back-meta share the common librewrite DSL:
  engine/context/rule directives, aliases, captures, ordered actions, bounded
  recursion, operation variables, parameters, and subcontext calls. POSIX basic
  regex (`R`), external/legacy rewrite maps, session variables, and non-POSIX
  regex extensions fail configuration. This is not the full librewrite language.
- `olcSaslCBinding`, the four logfile settings, per-database `olcMonitoring`,
  and `olcDbMaxEntrySize` have startup, online rollback, restart, and focused
  OpenLDAP evidence. Behavior-bearing settings that remain unsupported,
  including non-default thread controls and LMDB-specific durability/resource
  settings, fail validation instead of becoming silent no-ops.
- Native OpenLDAP C backend/overlay/password ABI modules, `back-perl`, SLAPI,
  and arbitrary third-party modules are outside a pure-Go server boundary and
  fail closed.
- OpenLDAP MDB/LMDB files are not a migration format. Use canonical `slapcat`
  LDIF; ldap-go rebuilds its own indexes in Memory or bbolt. Imported
  `olcDbDirectory` and `olcDbMaxSize` are source metadata, not the bbolt path or
  an enforced quota.
- Every backend/overlay order, operating-system runtime, ODBC driver, Kerberos
  provider, and fault schedule still requires deployment-specific qualification.

Configure ldap-go process concurrency through its command flags. The supported
OpenLDAP logfile routing/rotation settings are documented in [logging.md](logging.md);
service-manager output routing remains another deployment option.
Exact historical client options and interactive VLV iteration remain
compatibility conveniences rather than blockers for the common server paths
above.

## Reproduce the evidence

```sh
CGO_ENABLED=0 go test -p=1 ./... -count=1 -timeout=10m
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 make platform-builds
CGO_ENABLED=0 OPENLDAP_ENV_FILE=/path/to/openldap-reference.env make openldap-sdk

CGO_ENABLED=0 QUALIFICATION_MODE=smoke \
  QUALIFICATION_DURATION_SECONDS=60 QUALIFICATION_CONNECTIONS=8 \
  QUALIFICATION_RESTARTS=1 ./scripts/qualification/run.sh
CGO_ENABLED=0 QUALIFICATION_SCALE_ENTRIES=10000 \
  QUALIFICATION_SCALE_PAGE_SIZE=1000 ./scripts/qualification/scale.sh
CGO_ENABLED=0 LDAP_GO_HA_QUALIFICATION_HEAVY=1 \
  go test -count=1 -timeout=5m ./cmd/ldap-go \
  -run '^TestRealProcessHAQualification$'
```

Use [testing.md](testing.md) to build the pinned reference environment and
[production-qualification.md](production-qualification.md) for workload,
restart, fault, and OpenLDAP performance comparison gates.
