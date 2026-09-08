# lloadd upstream SASL EXTERNAL

This supplements the [load-balancer compatibility row](compatibility.md) with
upstream service-account SASL EXTERNAL. Previously,
`bindconf bindmethod=sasl saslmech=EXTERNAL` failed runtime validation.
The supported scope is certificate authentication over LDAPS or
StartTLS, and Unix peer-credential authentication over LDAPI. Other mechanisms,
client-side Bind handling, and pool routing retain their existing behavior.

## Configuration

For a certificate-authenticated service connection:

```conf
feature proxyauthz
bindconf bindmethod=sasl saslmech=EXTERNAL secprops=none timeout=5 \
 tls_cert=/etc/ldap/lloadd-client.pem tls_key=/etc/ldap/lloadd-client.key \
 tls_cacert=/etc/ldap/ca.pem tls_reqcert=demand
tier roundrobin
backend-server uri=ldaps://directory.example.com numconns=4 bindconns=2 retry=5000
```

For StartTLS, use an `ldap://` URI and add `starttls=critical` to the backend.
For a local directory, use an encoded Unix socket path:

```conf
feature proxyauthz
bindconf bindmethod=sasl saslmech=EXTERNAL secprops=none timeout=5
tier roundrobin
backend-server uri=ldapi://%2Frun%2Fslapd%2Fldapi numconns=4 bindconns=2 retry=5000
```

Configure the upstream directory to request and validate the client certificate,
map its certificate subject (or the lloadd process's Unix UID/GID) to the intended
service DN, and authorize that service DN to proxy the permitted client identities
using its normal `authz-policy`/`authzTo` rules. Ordinary client Bind and Search
still use the existing bind and regular pools respectively.

Omitting `authzid` requests the transport's authenticated identity. An explicit
`authzid=dn:...` requests an authorization identity that the upstream must permit.
EXTERNAL does not send a password or a caller-specified authentication identity;
nonempty `credentials`, `authcid`, or `realm` fail configuration instead of being
silently ignored. The existing auth-only configuration boundary accepts empty
`secprops` or `secprops=none`; other security-property expressions remain rejected.
EXTERNAL adds no SASL security layer to the transport.

## Behavior and evidence

The oracle is OpenLDAP 2.6.13 commit
`d172686d3d270bc961b78f3ff00d7019c8dfb094`. Its
`servers/lloadd/upstream.c` supplies the TLS certificate DN or local UID/GID as
`SASL_AUTH_EXTERNAL`, passes the configured authorization ID to Cyrus SASL, and
only publishes regular connections after a successful service Bind. The new
implementation uses the existing pure-Go LDAP exchange and pool lifecycle.

- Bind uses LDAPv3, an empty Bind DN, mechanism `EXTERNAL`, and a present initial
  response containing the authorization ID (including a present empty value).
- The established connection must be TLS or a Unix stream. Cleartext and failed
  optional StartTLS cannot proceed to EXTERNAL, even when a configured URI or a
  custom dialer suggests a secure transport. Certificate and authorization checks
  remain authoritative at the upstream server.
- Failed authentication/authorization closes the connection before regular-pool
  admission. Every replacement connection authenticates again. The bind pool
  remains available for ordinary client Binds.
- OpenLDAP's one-step EXTERNAL exchange has no server proof. Well-formed terminal
  server credentials are ignored; a challenge, malformed response, or mismatched
  message ID fails the connection.

Focused tests cover configuration, wire framing, real LDAPS/StartTLS/LDAPI,
authorization identity and denial, repeated connections, proxied Bind/Search,
missing certificates, and optional-StartTLS downgrade prevention. The process
differential runs both native lloadd and ldap-go against a disposable pinned
slapd, with generated certificates and an isolated MDB directory. It checks nine
transport/authorization cases and verifies service identities on fresh physical
connections. LDAPI execution requires Unix peer credentials.

```sh
CGO_ENABLED=0 go test ./internal/lloadd -run '^TestServiceSASLExternal' -count=1

. /path/to/openldap-reference.env
CGO_ENABLED=0 LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/lloadd -run '^TestOpenLDAPReferenceLloaddServiceExternal$' -count=1
```

OpenLDAP and Cyrus SASL are external test processes only. Production code and all
Go tests build with `CGO_ENABLED=0`. This bounded addition does not upgrade the
entire load-balancer compatibility row or claim complete SASL/provider parity.
