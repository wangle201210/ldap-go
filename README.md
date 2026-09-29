# ldap-go

[English](README.md) | [简体中文](README.zh-CN.md)

`ldap-go` is a Go implementation of an LDAPv3 directory server targeting
behavioral and LDIF data compatibility with OpenLDAP 2.6.x. It includes a
persistent directory server, OpenLDAP-style client and offline tools, an LDAP
load balancer, and a bilingual Web administration console.

The project is under active development and is not a complete OpenLDAP drop-in
replacement. Treat the [compatibility matrix](docs/compatibility.md) as the
authoritative support boundary.

Common school/company directory workflows have passed the
[practical acceptance checks](docs/common-production-scope.md#practical-acceptance-on-2026-09-20):
10,000-user import/query/paging/persistence, crash recovery, single-writer
replication recovery, backup/restore, Web administration, and a same-SDK
OpenLDAP differential. This is a bounded functional acceptance, not complete
OpenLDAP parity or a capacity guarantee for every deployment.

## Explicit non-goals

- **OpenLDAP MDB/LMDB:** reimplementing its storage engine, native database files,
  and index format is outside the project scope. ldap-go uses bbolt; migrate
  directory data through `slapcat` LDIF rather than copying MDB files.
- **Third-party modules:** further reimplementation of third-party modules and
  compatibility with their native module-loading ABIs are outside the project
  scope. Existing pure-Go implementations remain available within the
  [documented module coverage](docs/openldap-module-coverage.md).

These are deliberate scope exclusions, not pending features or gaps to count
against completion of the in-scope OpenLDAP functionality.

## Highlights

- LDAPv3 Bind, Search, Compare, Add, Modify, Delete, ModifyDN, StartTLS,
  Password Modify, common controls, aliases, referrals, and transactions.
- bbolt persistence with atomic LDIF import/export, backup, restore, rebuild,
  integrity checking, online backup, and retention tooling.
- OpenLDAP `cn=config`, schema, ACL, overlay, replication, Monitor, proxy, and
  offline-tool compatibility for the explicitly tested subset.
- Simple Bind, SASL PLAIN/CRAM-MD5/DIGEST-MD5/SCRAM/GSSAPI/EXTERNAL, TLS,
  LDAPS, LDAPI, and GB/T 38636 TLCP transports.
- OpenLDAP password schemes plus SM3, salted SM3, PBKDF2-SM3, and supported
  contributed password modules.
- ACL-preserving Web administration with English and Simplified Chinese UI.
- Differential tests against a pinned OpenLDAP 2.6.13 reference build.

Detailed implementation claims and boundaries are recorded in the
[implementation status](docs/implementation-status.md), not duplicated here.

## Performance snapshot

Latest comparison: September 30, 2026, R7, 100,000 users, baseline `fa4d51a`,
Apple M1 Pro, Go 1.26.4 with `CGO_ENABLED=0`, OpenLDAP 2.6.13. Rows are
medians of three SDK batches with per-request endpoint rotation. Relative
performance is `OpenLDAP/current * 100%`; 100% means parity. Frequency is
qualitative, not measured traffic.

| Common operation | Typical use | Calls | ldap-go, default access | OpenLDAP, default access | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 149.18 ms | 119.84 ms | 80.3% | 81.1% |
| Non-root Base, hot | High | 1,000 | 124.55 ms | 101.22 ms | 81.3% | 80.2% |
| Non-root equality, hot | Very high | 1,000 | 129.56 ms | 102.93 ms | 79.4% | 80.2% |
| Direct group discovery | High | 100 | 16.56 ms | 12.34 ms | 74.5% | 77.4% |
| Group Base, 1,000 members | Medium | 100 | 105.72 ms | 96.22 ms | 91.0% | 89.6% |
| Nested membership, client BFS | Medium-high | 100 traversals | 50.05 ms | 39.97 ms | 79.9% | 79.9% |

Versus baseline `fa4d51a`, seven-repeat Compare SDK batches improve 2.3%-6.4%
across true/false results and literal/uppercase root DNs, but remain at
68.0%-70.7% of OpenLDAP. Initial default SSHA Bind/distributed equality are
6.8%/8.4% slower; those large regressions do not recur in independent rechecks.
Initial write regressions and seven-pair rechecks remain documented; recheck
Modify/ModifyDN are still 2.9%/2.0% slower. **Per-operation parity is not achieved;
fast writes do not offset slow reads.** Shared-host results do not establish causality.

R7 reuses bounded syntax parsing in core-write and Compare preparation;
schema/reader callbacks and authorization remain live. Compare component
allocations drop from 357 to 165 for one target, and 464 to 325 for rotating
targets. Full tests, focused oracles, vet and 355 native checks without skips
passed; all 35 exports match. Broad scans were last measured in R4.
The operational-attribute gap remains.

See the [R7 report](docs/common-ldap-performance.md),
[evidence index](docs/evidence/performance-20260930-r7/README.md) and
[verbatim R6 archive](docs/common-ldap-performance-20260929-r6.md).

The separate [R5 audit report](docs/audit-performance-20260929-r5.md) records a
conditional audit-observer component allocation reduction. It establishes no
ordinary-request speedup or production-latency gain and is separate from R7.

## Requirements

- Go 1.26 or newer.
- Production binaries build with `CGO_ENABLED=0`; a C compiler is not required.
- OpenLDAP client tools are optional for manual interoperability checks.
- Node.js and Chromium are needed only for Web administration browser tests.
- Building the pinned OpenLDAP differential environment requires the native
  dependencies documented in [testing](docs/testing.md).

## Quick start

Build the binary, import the example directory, and start an LDAP listener:

```sh
mkdir -p ./bin ./data
CGO_ENABLED=0 go build -o ./bin/ldap-go ./cmd/ldap-go

./bin/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./examples/base.ldif \
  -replace

LDAP_GO_ROOT_PASSWORD='change-me' \
  ./bin/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -root-dn cn=admin,dc=example,dc=com
```

Query it with an OpenLDAP client in another terminal:

```sh
ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D cn=admin,dc=example,dc=com -W \
  -b dc=example,dc=com '(objectClass=*)'
```

Start the Web administration console against the same LDAP listener:

```sh
./bin/ldap-go web-admin \
  -listen 127.0.0.1:8080 \
  -ldap-url ldap://127.0.0.1:1389
```

Open `http://127.0.0.1:8080/` and sign in with an LDAP Bind DN. See
[operations](docs/operations.md) for LDAPI, OpenLDAP connections, TLS/TLCP,
backups, auditing, health checks, and production deployment.

## OpenLDAP migration

OpenLDAP backend files are implementation-specific and cannot be copied into
ldap-go. Export from a stopped or application-read-only source so separately
captured databases form a consistent migration set, then use `slapcat` LDIF as
the migration contract:

```sh
slapcat -n 0 -l config.ldif
slapcat -n 1 -l data-1.ldif

./bin/ldap-go import -db ./data/ldap-go.db \
  -ldif ./config.ldif -replace
./bin/ldap-go import -db ./data/ldap-go.db \
  -ldif ./data-1.ldif -database 1 -replace
```

The supported multi-database flow, offline aliases, validation behavior, and
password hash policy are documented in
[migration and passwords](docs/migration-and-passwords.md).

For a legacy `slapd.conf`, convert and validate the configuration in pure Go
before importing directory data:

```sh
CGO_ENABLED=0 go run ./cmd/slapdconf-convert \
  -f /path/to/slapd.conf -out ./config.ldif
```

See [slapd.conf conversion](docs/slapdconf-conversion.md) for supported
directives, strict failure behavior, and direct database output.

## Development

Run the normal local checks:

```sh
go test ./...
make compat
```

Run the complete pinned OpenLDAP, race, fuzz, and Web administration gate:

```sh
make full
```

See [testing](docs/testing.md) before running `make full`; it builds a pinned
OpenLDAP 2.6.13 reference and requires native build dependencies. Release and
upgrade checks are documented in [release](docs/release.md).

## Documentation

| Topic | Document |
| --- | --- |
| Running and production operations | [Operations](docs/operations.md) |
| OpenLDAP migration and passwords | [Migration and passwords](docs/migration-and-passwords.md) |
| Legacy `slapd.conf` conversion | [slapd.conf conversion](docs/slapdconf-conversion.md) |
| Pure-Go builds and platform audit | [Pure-Go builds](docs/pure-go-builds.md) |
| Current implementation details | [Implementation status](docs/implementation-status.md) |
| Supported and unsupported behavior | [Compatibility matrix](docs/compatibility.md) |
| Common production scope | [Common OpenLDAP production features](docs/common-production-scope.md) |
| Package and runtime design | [Architecture](docs/architecture.md) |
| Test suites and OpenLDAP differential setup | [Testing](docs/testing.md) |
| OpenLDAP 100k performance evidence | [100k comparison](docs/openldap-100k-evidence.md) |
| Production scale and crash qualification | [Production qualification](docs/production-qualification.md) |
| Backend, overlay, and module boundary | [OpenLDAP module coverage](docs/openldap-module-coverage.md) |
| Web administration feature boundary | [Web Admin feature matrix](docs/webadmin-feature-matrix.md) |
| Release archives and upgrade gate | [Release](docs/release.md) |

## License

See [LICENSE](LICENSE).
