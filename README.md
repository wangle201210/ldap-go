# ldap-go

`ldap-go` is a Go implementation of an LDAPv3 directory server targeting
behavioral and data compatibility with OpenLDAP 2.6.x.

The project is under active development. Compatibility is tracked explicitly in
[docs/compatibility.md](docs/compatibility.md); an item is not supported until
its conformance and differential tests pass.

## Compatibility target

- LDAPv3 wire protocol and data model defined by the RFC 4510 family.
- OpenLDAP 2.6.x `slapd` behavior, controls, extended operations, schema,
  access control, overlays, replication, and operational attributes.
- Lossless import of canonical `slapcat` LDIF, including UUID/CSN metadata and
  `cn=config`.
- Interoperability with OpenLDAP command-line clients and common LDAP SDKs.
- TLS, StartTLS, SASL, and an extensible transport layer for national
  cryptography support.

Binary OpenLDAP database files are implementation-specific and are not the
portable migration contract. `slapcat` LDIF is the authoritative data exchange
format supplied by OpenLDAP itself.

## Development

```sh
go test ./...
```

## Current runnable milestone

The current server milestone supports atomic content-LDIF import/export,
anonymous and simple Bind, Root DSE discovery, base/one/subtree Search, common
LDAP filters, binary attributes, size/time limits, Add, Modify, leaf Delete,
subtree ModifyDN, Compare, and Unbind. It loads OpenLDAP schema, ordered ACLs,
database roots, and selected operation settings from `cn=config`; supported
online changes are validated transactionally and published as one runtime
snapshot. The compatibility matrix marks these as partial until the remaining
schema, ACL, control, alias, configuration, and differential cases pass.

```sh
go run ./cmd/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./examples/base.ldif \
  -replace

go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389

ldapsearch -x -H ldap://127.0.0.1:1389 \
  -b dc=example,dc=com '(objectClass=*)'

go run ./cmd/ldap-go export \
  -db ./data/ldap-go.db \
  -ldif ./data/export.ldif
```

Imported `olcRootDN` and `olcRootPW` values are loaded from `cn=config`
automatically and apply only to their database. To provide an explicit
bootstrap override without exposing its password in the process arguments:

```sh
LDAP_GO_ROOT_PASSWORD='change-me' \
  go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -root-dn cn=admin,dc=example,dc=com
```

See [docs/architecture.md](docs/architecture.md) for the implementation model
and [docs/testing.md](docs/testing.md) for compatibility gates.
