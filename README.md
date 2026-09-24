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

Latest common-operation comparison: September 24, 2026, fifth run, 100,000 users,
baseline `b7e6cc1` versus the final `final` executable, Apple M1 Pro, Go 1.26.4
with cgo disabled, OpenLDAP 2.6.13. Main rows are batch-time medians of three
repeats with endpoints rotated per request. Only SDK calls are timed; validation
is outside timing. All endpoints use uid/member/objectClass equality indexes.
Relative performance is `OpenLDAP / ldap-go * 100%`; 100% means parity.
Usage frequency is qualitative for authentication/directory workloads, not
measured traffic. SSHA/plaintext methods and different member counts are separate.

| Common operation | Typical use | Calls | ldap-go, default access | OpenLDAP, default access | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 1,000 | 115.10 ms | 91.92 ms | 79.9% | 78.8% |
| Non-root Base, hot | High | 1,000 | 106.38 ms | 81.51 ms | 76.6% | 76.1% |
| Non-root equality, hot | Very high | 1,000 | 110.49 ms | 82.17 ms | 74.4% | 80.6% |
| Direct group discovery | High | 100 | 20.92 ms | 13.23 ms | 63.2% | 60.0% |
| Group Base, 1,000 members | Medium | 100 | 107.18 ms | 98.62 ms | 92.0% | 84.0% |
| Nested membership, client BFS | Medium-high | 100 traversals | 69.23 ms | 46.36 ms | 67.0% | 66.1% |

The [R5 report](docs/common-ldap-performance.md) includes baseline/current/native
tables, exact ACLs, all samples and validation. Explicit-ACL hot Base/equality
take 5.4%/8.7% less time; direct group discovery takes 38.6% less with explicit
ACLs and 3.0% less with default access. Default hot queries and SSHA Bind are
largely flat. **OpenLDAP parity and a uniform speedup are not established.**

The initial explicit distributed-equality row was 10.8% slower
(197.20/218.43/129.65 ms before/current/native). A separate seven-repeat recheck
gave 128.53/120.79/83.05 ms, a 6.0% reduction; both runs are retained, not pooled.
The original explicit root-bound concurrent check was 16.8% slower and is retained.
A dedicated seven-batch recheck gave 292/276/259 ms before/current/native, with
wide ranges of 195-419/196-568/203-355 ms. The original regression did not persist;
these separate observations do not support a stable concurrent speedup claim.

Accepted changes borrow projection descriptors, skip unrequested attributes only
in pure ACL projection, and reuse a published runtime database pointer under
read-only guards. Final selected payloads remain owned, the full entry remains
the ACL target, and both authentication storage Views remain. The TCP read-buffer
experiment was rejected and removed. Full Go tests, vet and 355 native PASS
records passed; a baseline-confirmed Web Admin timer race was fixed only in its
test fixture. The pre-existing R2 operational-attribute gaps remain documented.

The [SDK runner](internal/cmd/ldapcommonbench/README.md) supports disposable
replays. The [archived R4 report](docs/common-ldap-performance-20260924-r4.md)
retains the previous run. Timing boundaries and group fixtures differ from the
[earlier full-operation comparison](docs/performance-optimization-20260923-round13.md),
which retains write, paging, concurrency and memory measurements.

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
