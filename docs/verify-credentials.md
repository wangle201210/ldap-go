# Verify Credentials and authorization identity

ldap-go implements the simple-authentication portion of OpenLDAP's optional
Verify Credentials (`vc`) extension. It authenticates a supplied DN/password
without changing the caller's connection identity. This supports the built-in
`ldapvc` client and lloadd's `feature vc` service-pool workflow.

## Enable the module

Declare `vc.la` in an `olcModuleList` entry. The declaration enables Go code;
no shared library is loaded. An example for a configuration without an existing
module entry is:

```ldif
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModuleLoad: vc.la
```

If that entry already exists, add `vc.la` to its `olcModuleLoad` values instead
of adding the entry again. VC is disabled by default and remains absent from
Root DSE `supportedExtension`, matching native `SLAP_EXOP_HIDE` behavior.

To request the verified user's authorization identity with `ldapvc -a`, also
configure the global `authzid` overlay. Its only supported location, matching
OpenLDAP, is the frontend database:

```ldif
dn: olcOverlay={0}authzid,olcDatabase={-1}frontend,cn=config
objectClass: olcOverlayConfig
olcOverlay: {0}authzid
```

Use an unused overlay index and an existing frontend entry. `authzid.la` is an
accepted built-in module declaration; the overlay entry activates its behavior.
The `slapdconf-convert` command also accepts `moduleload vc.la`,
`moduleload authzid.la`, and frontend `overlay authzid`.

```sh
./bin/ldap-go ldapvc -x -H ldaps://directory.example.com:636 \
  -tls-ca /etc/ldap/ca.pem -a -b 'uid=alice,ou=people,dc=example,dc=com'
```

The final password is prompted. Connection credentials (`-D/-W/-y` or SASL
options) are independent of the DN/password being verified. `-b` requests the
existing password-policy response control when a ppolicy overlay is configured.

## Authentication behavior

VC creates a separate internal Bind state and reuses the normal authentication
dispatch. The caller's identity, saved bind credentials, transaction, search
sessions, and transport state are not replaced. Password-policy failures,
lockout, expiry/reset responses, and configured lastbind updates remain real
authentication effects. The request body is excluded from accesslog `reqData`.

Like native `connection_fake_init2`, the internal connection does not inherit
the outer TLS/SASL strength or peer identity. Consequently, `simple_bind` SSF
requirements can reject VC even over a verified TLS outer connection. This is
not equivalent to opening a separate TLS connection and binding the user.

The inner response uses an INTEGER result code and optional nested controls;
no response name is emitted. Ordinary credential failures carry the Bind code
both outside and inside the extension response. Invalid VC encoding, DN syntax,
and control decoding/registration fail with outer `protocolError` and no inner
value. Critical ManageDsaIT is rejected at that control-validation stage.
Repeated valueless ppolicy requests produce one response control, matching the
native VC path; duplicate authzid requests remain errors.

The `authzid` overlay also supports normal simple and SASL Bind controls. It
returns an empty identity for anonymous Bind or `dn:<authorized DN>` on success.
It validates absent control values and duplicates and applies the native
authorization-identity disclosure restrictions. Failed Bind does not disclose
an identity. Native callback ordering and less common overlay combinations
remain bounded by the tests, rather than a claim of full overlay parity.

## Limits and remaining work

Request/response values are limited to 1 MiB, individual DN/authentication/cookie
fields to 64 KiB, and control lists to 64. BER decoding uses bounded fixed
structure traversal; credential bytes are not interpreted as text. Valid
nonminimal definite BER lengths are accepted, while indefinite lengths and
extra or malformed fields fail.

VC-specific SASL negotiation and continuation cookies are not implemented.
They fail explicitly; ordinary connection SASL remains supported. The Go client
also intentionally returns nonzero for an inner verification failure even when
an external server returns outer success, and sends an explicit empty simple
credential for anonymous verification. These differ from native 2.6.13 client
quirks and are asserted by the client differential.

See [testing](testing.md) for local, native, and platform evidence. Native
OpenLDAP modules are external test processes only; production and Go tests
continue to build with `CGO_ENABLED=0`.
