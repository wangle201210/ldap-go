# Common OpenLDAP production scope

This audit separates common deployment capability from exhaustive OpenLDAP
source-module parity. The detailed, test-bounded claims remain authoritative in
[compatibility.md](compatibility.md).

## Common deployment paths

The following paths are implemented and covered by local, race, and pinned
OpenLDAP 2.6.13 tests:

- Local authoritative directories using Memory or bbolt storage: Bind, Search,
  Compare, Add, Modify, Delete, ModifyDN, aliases, referrals, common controls,
  Password Modify, transactions, schema, ACLs, limits, indexes, and `cn=config`.
- TLS, LDAPS, LDAPI, Simple Bind, PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM, GSSAPI,
  EXTERNAL, and the documented TLCP deployment mode.
- OpenLDAP password hashes plus the documented SM3 and contributed schemes,
  password policy, account usability, password history, expiry, and lockout.
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

The latest pinned full strict run passed **2,188 top-level tests** against
OpenLDAP 2.6.13 commit
`d172686d3d270bc961b78f3ff00d7019c8dfb094`. The SDK differential passed the
same Bind, Search, paging, limits, write, Compare, Password Modify, ModifyDN,
and final-state sequence against both servers. Full Go tests, full race tests,
staticcheck, fuzz smoke, and six cgo-disabled platform builds also passed.

## Explicit advanced boundaries

These are not silently presented as supported common paths:

- Delta-syncrepl plus writable multi-provider/mirror mode is rejected because
  OpenLDAP-compatible attribute-history conflict merging is not implemented.
  Use standard syncrepl, single-provider delta, or non-delta multi-provider.
- Syncrepl SASL integrity/confidentiality layers without TLS are not
  implemented. Use TLS, TLCP, or LDAPI when replication transport SSF is
  required.
- General librewrite contexts/rules are not implemented. Supported suffix/map
  forms work; unsupported RWM directives fail configuration instead of being
  ignored.
- Behavior-bearing `cn=config` values that ldap-go cannot honor, including SASL
  channel-binding policy, logfile routing, and non-default thread, monitor, or
  LMDB durability/resource settings, fail validation instead of becoming silent
  no-ops. OpenLDAP-generated defaults remain importable.
- Native OpenLDAP C backend/overlay/password ABI modules, `back-perl`, SLAPI,
  and arbitrary third-party modules are outside a pure-Go server boundary and
  fail closed.
- OpenLDAP MDB/LMDB files are not a migration format. Use canonical `slapcat`
  LDIF; ldap-go rebuilds its own indexes in Memory or bbolt. Imported
  `olcDbDirectory` and `olcDbMaxSize` are source metadata, not the bbolt path or
  an enforced quota.
- Every backend/overlay order, operating-system runtime, ODBC driver, Kerberos
  provider, and fault schedule still requires deployment-specific qualification.

OpenLDAP-specific process tuning and logfile rotation directives are not a
portable LDAP behavior contract; configure ldap-go process concurrency through
its command flags and route or rotate process output through the service
manager. Exact historical client options and interactive VLV iteration remain
compatibility conveniences rather than blockers for the common server paths
above.

## Reproduce the evidence

```sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
staticcheck ./...
make platform-builds
make fuzz-smoke
OPENLDAP_ENV_FILE=/path/to/openldap-reference.env make openldap-full
OPENLDAP_ENV_FILE=/path/to/openldap-reference.env make openldap-sdk
```

Use [testing.md](testing.md) to build the pinned reference environment and
[production-qualification.md](production-qualification.md) for workload,
restart, fault, and OpenLDAP performance comparison gates.
