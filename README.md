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
subtree ModifyDN, Compare, Unbind, StartTLS, and RFC 3062 Password Modify. It
also supports RFC 4528 Assertion, RFC 4527 pre-read/post-read, and RFC 2696
simple paged-results controls on their applicable operations. RFC 4511
Abandon and RFC 3909 Cancel can interrupt active Search operations on the same
LDAP connection. RFC 3296 named referrals and ManageDsaIT support base
referrals, subordinate SearchResultReference responses, LDAP URL DN/scope
rewriting, and managed referral updates. RFC 4511/4512 aliases support all four
`derefAliases` modes, recursive base and search-scope dereferencing, loop and
broken-target handling, and OpenLDAP's database-level `olcMaxDerefDepth`.
RFC 3672 subentries include the built-in schema, base/one/subtree visibility,
the Subentries control, paging, and OpenLDAP-compatible write and Bind rules.
RFC 3671 collective attributes include the standard `c-*` schema, strict
subtree-specification scopes, in-memory value propagation and merging,
collective exclusions, source references, and logical-entry behavior across
Search, Compare, assertions, read controls, paging, sorting/VLV, and ACL
evaluation.
RFC 4533 LDAP Sync provider support is enabled by an imported
`olcOverlay=syncprov`. It supports `refreshOnly`, `refreshAndPersist`,
OpenLDAP-compatible multi-SID cookies, present UUID sets, committed
add/modify/modDN/delete notifications, durable delete progress across restart,
dynamic suffix `contextCSN` Search/Compare/read-control semantics,
`olcSpCheckpoint`, bounded `olcSpSessionlog` delete replay,
`olcSpNoPresent`, `olcSpReloadHint`, Abandon/Cancel, server-side Sort/VLV
composition, and OpenLDAP-style syncprov coverage of glued subordinate
databases. OpenLDAP 2.6.13 `ldapsearch` interoperability also passes.
An OpenLDAP 2.6.13 syncrepl consumer also converges through initial,
refresh-and-persist, and stopped-consumer restart scenarios. The ldap-go
syncrepl consumer now loads ordered `olcSyncrepl` values, runs refresh-only or
refresh-and-persist workers under the server lifecycle, commits RFC 4533 entry
changes and cookies atomically, applies Present/Delete UUID sets, and resumes
from its durable cookie after restart. A ldap-go provider-to-consumer topology
covers initial, persistent, and offline catch-up paths. OpenLDAP-provider
differentials and delta-syncrepl remain pending milestones.
RFC 2891 server-side sorting is available on databases
configured with OpenLDAP's `sssvlv` overlay, including paged-search interaction
and virtual list views with offset, proportional, assertion-value, and opaque
context requests. It loads OpenLDAP schema, ordered ACLs, database roots,
hidden/disabled databases, and selected operation settings from `cn=config`;
supported online changes are validated transactionally and published as one
runtime snapshot. Database entry partitions allow different OpenLDAP backends
to hold the same DN without crossing authorization or search boundaries, while
`olcSubordinate` databases participate in OpenLDAP-style glue searches. The
compatibility matrix marks these as partial until the remaining schema, ACL,
control, configuration, and differential cases pass.

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

ldapsearch -x -H ldap://127.0.0.1:1389 \
  -E '!sync=ro' -b dc=example,dc=com '(objectClass=*)'

go run ./cmd/ldap-go export \
  -db ./data/ldap-go.db \
  -ldif ./data/export.ldif
```

Supplying a PEM certificate and key enables StartTLS:

```sh
go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -tls-cert ./server.crt \
  -tls-key ./server.key

ldapsearch -x -ZZ -H ldap://127.0.0.1:1389 \
  -b dc=example,dc=com '(objectClass=*)'
```

Add `-ldaps` to negotiate TLS immediately and advertise an `ldaps://` endpoint
instead. TLS 1.2 is the minimum accepted version. `-tls-client-ca` enables
verification of optional client certificates; `-tls-require-client-cert`
makes a verified certificate mandatory. For example, append:

```sh
-tls-client-ca ./client-ca.crt -tls-require-client-cert
```

GB/T 38636 TLCP uses separate SM2 signing and encryption certificates:

```sh
go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1636 \
  -tlcp-sign-cert ./server-sign.crt \
  -tlcp-sign-key ./server-sign.key \
  -tlcp-enc-cert ./server-enc.crt \
  -tlcp-enc-key ./server-enc.key \
  -tlcp-implicit
```

The TLCP endpoint is reported as `ldap+tlcp://`. Omitting `-tlcp-implicit`
enables a StartTLS-OID upgrade followed by a TLCP handshake for clients that
support that profile. TLCP and RFC 8998 TLS 1.3 cipher suites are distinct;
this milestone implements TLCP only. The corresponding optional client
authentication flags are `-tlcp-client-ca` and
`-tlcp-require-client-cert`.

After a standard TLS or TLCP client certificate chain is verified, the
certificate Subject is normalized as an LDAP DN and the connection advertises
the SASL `EXTERNAL` mechanism. A client can then bind without an LDAP password:

```sh
LDAPTLS_CERT=./client.crt \
LDAPTLS_KEY=./client.key \
LDAPTLS_CACERT=./server-ca.crt \
  ldapwhoami -Y EXTERNAL -ZZ -H ldap://127.0.0.1:1389
```

An unverified certificate never produces an EXTERNAL identity. The current
implementation accepts an empty SASL authorization identity only; proxy
authorization through EXTERNAL remains pending. TLCP requires a client that
implements GB/T 38636 rather than a stock TLS-only OpenLDAP client.

For a complete multi-database OpenLDAP migration, import `cn=config` first and
then select each database using the same numeric index accepted by `slapcat`:

```sh
slapcat -n 0 -l config.ldif
slapcat -n 1 -l data-1.ldif

go run ./cmd/ldap-go import \
  -db ./data/ldap-go.db -ldif ./config.ldif -replace
go run ./cmd/ldap-go import \
  -db ./data/ldap-go.db -ldif ./data-1.ldif -database 1 -replace

go run ./cmd/ldap-go export \
  -db ./data/ldap-go.db -ldif ./data-1-export.ldif -database 1
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

Generate a salted national-cryptography password value for `userPassword` or
`olcRootPW` without passing the cleartext password as a command argument:

```sh
LDAP_GO_PASSWORD='change-me' \
  go run ./cmd/ldap-go passwd
```

The output uses `{PBKDF2-SM3}` with a random 16-byte salt and 100,000
iterations by default. `ldap-go` also verifies imported `{SM3}` and `{SSM3}`
values, but those fast digest schemes should only be retained for migration.
`{PBKDF2-SM3}` is an `ldap-go` extension modeled on OpenLDAP's contributed
PBKDF2 format; an upstream OpenLDAP server needs a matching module or patch to
authenticate against it.

RFC 3062 Password Modify follows OpenLDAP's `olcPasswordHash` setting. Its
default remains `{SSHA}` for OpenLDAP compatibility. To make server-side
password changes use national cryptography, set the frontend database entry:

```ldif
dn: olcDatabase={-1}frontend,cn=config
changetype: modify
replace: olcPasswordHash
olcPasswordHash: {PBKDF2-SM3}
```

The setting is validated and reloaded atomically. Users can then change their
own passwords with an RFC 3062 client without putting either password in
command arguments:

```sh
ldappasswd -x -H ldap://127.0.0.1:1389 \
  -D uid=alice,ou=people,dc=example,dc=com -W -A -S
```

See [docs/architecture.md](docs/architecture.md) for the implementation model
and [docs/testing.md](docs/testing.md) for compatibility gates.
