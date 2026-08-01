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
An imported OpenLDAP `chain` overlay chases named and continuation referrals
for Search, Compare, Add, Modify, Delete, ModifyDN, Password Modify, and Dynamic
Refresh. Child `olcDatabase=ldap` entries provide URI-specific StartTLS,
LDAPS/TLCP, timeout, identity-assertion, pass-through, schema/filter, session
tracking, and nested-referral policies. The experimental Chaining Behavior
control is advertised and enforces referral-preferred/required and
chaining-required outcomes, including OpenLDAP's `cannotChain` result.
RFC 3672 subentries include the built-in schema, base/one/subtree visibility,
the Subentries control, paging, and OpenLDAP-compatible write and Bind rules.
RFC 3671 collective attributes include the standard `c-*` schema, strict
subtree-specification scopes, in-memory value propagation and merging,
collective exclusions, source references, and logical-entry behavior across
Search, Compare, assertions, read controls, paging, sorting/VLV, and ACL
evaluation.
OpenLDAP `olcDitContentRules` schema is loaded from `cn=config`, published
through `cn=Subschema`, and enforced on Add and Modify. Auxiliary-class
allowlists plus `MUST`, `MAY`, `NOT`, and obsolete-rule behavior match slapd
diagnostics. Online updates, restart, and direct import of a real
`slapcat -n 0` schema entry pass.
RFC 5805 transactions use the OpenLDAP 2.6 wire profile and queue Add, Modify,
Delete, ModifyDN, and explicit-value Password Modify operations on one LDAP
connection. Commit replays the queue in one memory or bbolt write transaction;
any failed operation rolls back the full queue and identifies its original
message ID. Abort, Bind-triggered abort, one-database enforcement, Root DSE
discovery, OpenLDAP `ldapmodify -E txn=commit/abort`, and a direct slapd
rollback differential pass.
RFC 6171 Don't Use Copy is available on Search and Compare. Authoritative
databases answer normally; a single-provider shadow Search returns its
OpenLDAP-rewritten `olcUpdateRef` or `unwillingToPerform`, while shadow Compare
returns `unwillingToPerform` without consulting copied entry data. OpenLDAP
`ldapsearch -E '!dontUseCopy'` and raw slapd differential cases pass. Imported
global `olcDisallows` policies enforce `bind_anon`, `bind_simple`,
`tls_2_anon`, `tls_authc`, and `dontusecopy_non_critical`; the related
`olcAllows` LDAPv2, anonymous-DN, and anonymous-credential Bind exceptions
follow OpenLDAP's precedence. Online changes, invalid-value rollback, restart,
and slapd differential cases pass.
RFC 2589 dynamic directory services are enabled by an imported
`olcOverlay=dds`. Dynamic Add generates `entryTtl` and the OpenLDAP
`entryExpireTimestamp`, Refresh enforces configured min/max TTL and `manage`
ACLs, searches project remaining TTL, and a lifecycle worker removes expired
leaf-first hierarchies with syncprov delete publication. Root DSE publishes
`dynamicSubtrees`; matching OpenLDAP, the hidden Refresh extended operation is
not listed in `supportedExtension`. DDS state, limits, online configuration,
restart persistence, slapd differentials, and OpenLDAP `ldapexop refresh`
interoperability pass.
OpenLDAP's `ppolicy` overlay is loaded from `cn=config` and supports default or
per-entry policies across Bind, Add, Modify, and Password Modify. It enforces
validity windows, lockout and exponential delay, expiry warnings and grace
logins, reset-only sessions, password age/length/history rules, safe modify,
cleartext hashing, and `olcLastBind`/`pwdMaxIdle`. The Behera password-policy,
SunDS account-usability, and optional Netscape controls match OpenLDAP 2.6.13
in differential tests. Policy configuration and all operational state survive
`slapcat` LDIF round trips. On shadow databases, chain-backed
`olcPPolicyForwardUpdates` sends policy state changes to the provider without
mutating the consumer copy. Native C `check_password()` modules remain pending;
configured native checker paths fail closed.
RFC 4533 LDAP Sync provider support is enabled by an imported
`olcOverlay=syncprov`. It supports `refreshOnly`, `refreshAndPersist`,
OpenLDAP-compatible multi-SID cookies, present UUID sets, committed
add/modify/modDN/delete notifications, durable delete progress across restart,
dynamic suffix `contextCSN` Search/Compare/read-control semantics,
`olcSpCheckpoint`, bounded `olcSpSessionlog` delete replay with exact `delcsn`,
`olcSpNoPresent`, `olcSpReloadHint`, Abandon/Cancel, server-side Sort/VLV
composition, and OpenLDAP-style syncprov coverage of glued subordinate
databases. OpenLDAP 2.6.13 `ldapsearch` interoperability also passes.
OpenLDAP `olcServerID` drives local CSN SIDs, and writable
`olcMultiProvider`/`olcMirrorMode` databases relay remote changes with
whole-entry/delete CSN conflict protection and durable UUID tombstones. A
three-node topology passes bidirectional writes, concurrent convergence,
middle-node restart catch-up, offline writes, and delete-versus-stale-modify
convergence; bidirectional OpenLDAP 2.6 multi-provider interoperability also
passes.
An OpenLDAP 2.6.13 syncrepl consumer also converges through initial,
refresh-and-persist, and stopped-consumer restart scenarios. The ldap-go
syncrepl consumer now loads ordered `olcSyncrepl` values, runs refresh-only or
refresh-and-persist workers under the server lifecycle, commits RFC 4533 entry
changes and cookies atomically, applies Present/Delete UUID sets, and resumes
from its durable cookie after restart. A ldap-go provider-to-consumer topology
covers initial, persistent, and offline catch-up paths, and the same reverse
topology passes against an OpenLDAP 2.6.13 provider. Broader provider variants
remain pending milestones. The consumer also supports OpenLDAP accesslog
delta-syncrepl, including atomic `reqMod` replay, initial full-refresh
fallback, durable restart, and automatic full recovery when the retained log
cannot be replayed safely. The obsolete DSEE changelog mode and a provider-side
accesslog overlay remain pending. Consumer databases enforce OpenLDAP
shadow/update-referral rules, support online worker replacement, fractional
and filtered result sets, refresh-only polling, and suffix massage for entry
DNs and DN-valued attribute values. Consumer transports support OpenLDAP
StartTLS/LDAPS certificate policies, CA and CRL loading, socket keepalive,
Linux TCP user timeouts, and implicit `ldap+tlcp://` replication with mutual
SM2 authentication. For refresh-and-persist, `timeout=` bounds the initial
refresh without imposing a lifetime on the persistent stream. Legal RFC 4533
Sync Info variants are normalized by ASN.1 tag before `go-ldap` decoding.
Syncrepl authentication supports simple bind,
SASL EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5, GSSAPI, and
SCRAM-SHA-1/256/512; a real OpenLDAP SCRAM-SHA-256 provider topology is
exercised when its Cyrus SASL plugin is available.
Server-side SASL supports EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5, and
SCRAM-SHA-1/256/512. PLAIN verifies the mapped LDAP entry's existing
`userPassword` values. CRAM-MD5 performs the Cyrus-compatible server-first
challenge exchange with an ACL-visible cleartext password. DIGEST-MD5
supports the `qop=auth` exchange, mutual `rspauth`, and imported
`cmusaslsecretDIGEST-MD5` values. SCRAM runs a connection-bound multi-round
exchange and reads either cleartext `userPassword` or Cyrus-compatible
`authPassword` verifiers imported from OpenLDAP. OpenLDAP 2.6.13
`ldapwhoami` PLAIN, CRAM-MD5, DIGEST-MD5, and SCRAM-SHA-256 interoperability
cases pass. Imported `olcSaslHost`, `olcSaslRealm`, `olcSaslSecProps`, and
ordered `olcAuthzRegexp` values are loaded from `cn=config`; direct DN
replacements and local LDAP URL mappings with exactly one ACL-visible result
are supported. RFC 4370 proxied authorization is advertised for Search,
Compare, Add, Modify, Delete, ModifyDN, Password Modify, Who Am I?, and
Dynamic Refresh. It implements `olcAuthzPolicy` values `none`, `from`, `to`,
`any`/`both`, and `all`; hidden ordered `authzTo`/`authzFrom` attributes; DN,
user, group, wildcard, and local LDAP URL rules; database-root and anonymous
targets; and OpenLDAP's `proxy_authz_anon` and
`proxy_authz_non_critical` switches.
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

An imported `olcSyncrepl` can use the same implicit TLCP scheme. `tls_cert` and
`tls_key` identify the client signing pair. ECDHE suites additionally require
the ldap-go extension fields `tlcp_enc_cert` and `tlcp_enc_key` for the client
encryption pair:

```text
olcSyncrepl: {0}rid=001 provider=ldap+tlcp://provider.example:1636 bindmethod=sasl saslmech=EXTERNAL searchbase="dc=example,dc=com" tls_reqcert=demand tls_reqsan=demand tls_cacert=/etc/ldap/tlcp-ca.crt tls_cert=/etc/ldap/client-sign.crt tls_key=/etc/ldap/client-sign.key tlcp_enc_cert=/etc/ldap/client-enc.crt tlcp_enc_key=/etc/ldap/client-enc.key tls_cipher_suite=ECDHE_SM4_GCM_SM3 type=refreshAndPersist
```

After a standard TLS or TLCP client certificate chain is verified, the
certificate Subject is normalized as an LDAP DN and the connection advertises
the SASL `EXTERNAL` mechanism. A client can then bind without an LDAP password:

```sh
LDAPTLS_CERT=./client.crt \
LDAPTLS_KEY=./client.key \
LDAPTLS_CACERT=./server-ca.crt \
  ldapwhoami -Y EXTERNAL -ZZ -H ldap://127.0.0.1:1389
```

An unverified certificate never produces an EXTERNAL identity. EXTERNAL
authorization identities use the same self, database-root,
`olcAuthzPolicy`, `authzTo`, and `authzFrom` checks as the other SASL
mechanisms. TLCP requires a client that implements GB/T 38636 rather than a
stock TLS-only OpenLDAP client.

SASL PLAIN follows OpenLDAP/Cyrus security properties. The default
`noplain,noanonymous` policy suppresses PLAIN on an unprotected TCP
connection, while TLS, TLCP, and local Unix sockets provide an external
security-strength factor. For an intentionally unprotected development
endpoint, `olcSaslSecProps: none` enables PLAIN. Authentication identity
mapping uses the first matching `olcAuthzRegexp`; LDAP URL replacement
searches run as the anonymous authentication identity and require `auth`
access to the search base, candidate entries, and filter attributes. PLAIN
authorization identities use self and database-root authorization plus
OpenLDAP `olcAuthzPolicy`, `authzTo`, and `authzFrom` rules.
SCRAM-SHA-1/256/512 use the same identity mapping and ACL rules.
They accept raw or `{CLEARTEXT}` `userPassword` values, or Cyrus SCRAM
verifiers in the OpenLDAP `authPassword` form
`SCRAM-SHA-*$iterations:salt$StoredKey:ServerKey`. One-way `userPassword`
hashes such as `{SSHA}` cannot be converted into SCRAM verifier keys; migrate
an existing `authPassword` value or reset the password to enable SCRAM.
CRAM-MD5 uses the same identity mapping, `auth` ACL check, and proxy
authorization policy, and forms its challenge with `olcSaslHost` (or the local
hostname). It requires a raw or `{CLEARTEXT}` `userPassword`;
one-way OpenLDAP or national-cryptography password hashes cannot supply the
original HMAC-MD5 key.
DIGEST-MD5 shares that mapping and ACL path, emits a Cyrus-compatible
nonce/realm challenge, verifies both historical Latin-1 and UTF-8 digest
forms, and returns the required `rspauth`. It accepts raw or `{CLEARTEXT}`
`userPassword`, or the legacy 16-byte `cmusaslsecretDIGEST-MD5` value.
`qop=auth-int` and `qop=auth-conf` remain unavailable until the connection
layer can apply negotiated SASL integrity and privacy framing.

For `olcSyncrepl` with `saslmech=GSSAPI`, an explicitly configured
`credentials` value is used as the Kerberos password. Without that field,
ldap-go checks `KRB5_CLIENT_KTNAME`, then `KRB5_KTNAME`, and finally
`KRB5CCNAME`; keytabs require `authcid`, while a credential cache supplies its
own principal. `FILE:` keytabs and caches are supported, and the Unix default
cache is `/tmp/krb5cc_<uid>`. KCM, KEYRING, DIR, and macOS API caches are not
read by the pure-Go Kerberos client. `KRB5_CONFIG` selects the Kerberos
configuration file. The current GSSAPI implementation negotiates no SASL
integrity or privacy layer, so TLS, TLCP, or another protected transport is
required when replication traffic itself must be encrypted.

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
