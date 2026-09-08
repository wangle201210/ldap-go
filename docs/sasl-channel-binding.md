# Server SASL channel binding

`olcSaslCBinding` on `cn=config` implements the OpenLDAP 2.6.13 server
policy in pure Go. No cgo or native SASL library is used by ldap-go.

| Value | Behavior when TLS completes |
| --- | --- |
| Absent or `none` | Supply no SASL channel binding. |
| `tls-unique` | Supply the first TLS Finished message, subject to the Go limits below. |
| `tls-endpoint` | Supply the RFC 5929 server certificate digest. |

Values are case insensitive, but their spelling is preserved on read/export,
as OpenLDAP's `ARG_STRING` configuration does. The default is absent, not a
materialized `none`. The attribute is single valued, has `caseIgnoreMatch`,
and uses OID `1.3.6.1.4.1.4203.1.12.2.3.0.100`. Online writes by name or OID
emit the canonical attribute name. Deletion or an empty replacement restores
the absent default. An empty string is invalid Directory String syntax.

Unknown values, whitespace, quoting, ordered prefixes, attribute options,
multiple values, and placement outside the global entry are rejected. In
particular, `tls-server-end-point` is a wire binding name, **not** an accepted
configuration value; `required`, `auto`, and `tls-exporter` are not policies.
OpenLDAP actually stores arbitrary nonempty strings and silently ignores
unrecognized ones at handshake time. Rejecting those strings here is an
intentional fail-closed difference.

Startup and offline validation use the same parser as online changes.
Online modifications validate each intermediate entry and build the candidate
runtime inside the storage transaction. A later invalid change, runtime
validation failure, or commit failure retains both the old stored entry and
the active runtime. Successful changes survive a database restart.

## Connection and Authentication Behavior

The binding is captured when the TLS handshake completes, for StartTLS and
LDAPS. Changes affect subsequently completed handshakes, including StartTLS
on an already open cleartext connection. Existing SASL contexts and exchanges
in progress retain their captured binding. Replacing the policy cannot change
the certificate digest or Finished data of an existing context.

OpenLDAP 2.6.13 has a further context-lifetime detail: after a successful SASL
bind, the next SASL bind reopens the Cyrus context without restoring
`SASL_CHANNEL_BINDING`. ldap-go follows this behavior. The old context still
advertises PLUS until that next bind starts; afterward PLUS is unavailable.
A simple bind alone does not initialize or refresh channel binding.

SCRAM-SHA-1/256/512-PLUS is advertised only when the context has usable binding
data and the existing SASL security properties permit it. Ordinary SCRAM and
other authentication mechanisms retain their existing policies. This setting
selects binding data; it does not require all authentication to use binding.
Ordinary SCRAM with `n` remains usable, while a `y` downgrade attempt is
rejected if the context has binding. PLUS requires binding and rejects `n`,
`y`, unsupported binding names, wrong data, and invalid proofs.

OpenLDAP/Cyrus SCRAM uses `p=ldap` with application data consisting of
`tls-unique:` plus Finished bytes, or `tls-server-end-point:` plus the digest.
That exact format is supported. Existing standard SCRAM wire forms remain
supported with the same selected TLS policy and raw data. They cannot select
a different binding type from the configured policy. The pinned local copy
of xdg-go/scram v1.2.0 adds only `ldap` to its parser's accepted names; proof
validation and downgrade detection remain upstream code.

Cyrus SASL 2.1.28 GSSAPI calls `gss_accept_sec_context` with
`GSS_C_NO_CHANNEL_BINDINGS`, so `olcSaslCBinding` does not impose a GSSAPI
binding requirement. ldap-go preserves this behavior and GSSAPI advertisement
over cleartext and TLS. The separate process option `GSSAPIChannelBinding`
continues to enforce its explicit endpoint requirement, including rejecting
missing data, mismatches, and cleartext. The existing Go acceptor also rejects
unexpected initiator binding checksums when no binding is configured; this is
stricter than native GSS acceptors that ignore such checksums.

LDAP error timing is deliberately stricter than Cyrus: unavailable PLUS is
rejected immediately with code 7 and SCRAM binding errors use code 49.
The tested OpenLDAP/Cyrus combination can instead reach client-final and
return code 80. Neither path authenticates a mismatched or unbound PLUS
exchange.

## Intentional Go TLS Limits

`tls-unique` is available only for completed, non-resumed standard TLS 1.2
handshakes. Go exposes no `TLSUnique` for TLS 1.3 or resumed connections.
Those connections expose no PLUS binding under this policy; no exporter or
endpoint fallback is substituted. OpenLDAP's OpenSSL implementation calls
its Finished-message APIs directly, including for resumed sessions.

`tls-endpoint` works for TLS 1.2, TLS 1.3, and resumed sessions. The existing
standard TLS transport requires a single static certificate with an
expressible RFC 5929 digest. Multiple certificates, dynamic certificate
callbacks, and unsupported signature hashes do not expose an endpoint
binding, because Go's connection state does not identify the server's own
selected certificate. TLCP is never treated as standard TLS for this policy.

## Pinned Evidence and Tests

OpenLDAP tag `OPENLDAP_REL_ENG_2_6_13`, commit
`d172686d3d270bc961b78f3ff00d7019c8dfb094`:

- [bconfig.c](https://github.com/openldap/openldap/blob/d172686d3d270bc961b78f3ff00d7019c8dfb094/servers/slapd/bconfig.c): attribute syntax, storage, and global placement.
- [sasl.c](https://github.com/openldap/openldap/blob/d172686d3d270bc961b78f3ff00d7019c8dfb094/servers/slapd/sasl.c): parsing at handshake, noncritical binding, and context reopening without rebinding.
- [connection.c](https://github.com/openldap/openldap/blob/d172686d3d270bc961b78f3ff00d7019c8dfb094/servers/slapd/connection.c): attachment after TLS completion.
- [cyrus.c](https://github.com/openldap/openldap/blob/d172686d3d270bc961b78f3ff00d7019c8dfb094/libraries/libldap/cyrus.c): recognized keywords, `ldap` name, and prefixed data.
- [tls_o.c](https://github.com/openldap/openldap/blob/d172686d3d270bc961b78f3ff00d7019c8dfb094/libraries/libldap/tls_o.c): Finished-message selection and server certificate digest.
- Cyrus SASL 2.1.28 [scram.c](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/plugins/scram.c) and [gssapi.c](https://github.com/cyrusimap/cyrus-sasl/blob/cyrus-sasl-2.1.28/plugins/gssapi.c): binding validation and GSSAPI's absence of channel-binding input.

`sasl_cbinding_openldap_test.go` pins SHA-256 hashes of these source files and
requires external slapd version 2.6.13. Its differential tests cover absent
defaults, spelling, add/replace/delete results, unsupported-string divergence,
TLS 1.2 endpoint/unique SCRAM exchanges, data mismatch, online updates, and
context reopening. The GSSAPI differential uses a disposable MIT KDC and
external slapd with a pure-Go Kerberos initiator. The native client test also
exercises OpenLDAP/Cyrus ldapwhoami against the Go server.

Local tests additionally cover TLS 1.3, resumed TLS 1.2, LDAPS, standard and
OpenLDAP SCRAM formats, downgrade and wrong-type attacks, in-flight updates,
configuration rollback, injected commit failure, and bbolt restart.

```sh
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build ./...

# With OpenLDAP 2.6.13, Cyrus plugins, and MIT KDC tools configured:
CGO_ENABLED=0 LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  LDAP_GO_OPENLDAP_GSSAPI_TESTS=1 LDAP_GO_TEST_OPENLDAP_SCRAM_PLUS=1 \
  OPENLDAP_SOURCE=/path/to/openldap-2.6.13 \
  CYRUS_SASL_SOURCE=/path/to/cyrus-sasl-2.1.28 \
  go test ./internal/server -count=1 \
  -run 'TestSASLCBinding|TestOpenLDAP2613SASLCBinding|TestCyrus2128SASLCBinding|TestOpenLDAPCyrusSASLSCRAMTLSChannelBinding'
```

External executable overrides use the repository's existing `OPENLDAP_SLAPD`,
`OPENLDAP_SLAPADD`, `OPENLDAP_SCHEMA_DIR`, `LDAP_GO_KRB5KDC`,
`LDAP_GO_KDB5_UTIL`, `LDAP_GO_KADMIN_LOCAL`, and `LDAP_GO_KINIT` variables.
`SASL_PATH` selects the external Cyrus plugin directory. These processes are
test references only; they are not linked into ldap-go.

## Change Inventory and Validation

New implementation: `internal/server/sasl_cbinding.go`. New tests:
`sasl_cbinding_test.go`, `sasl_cbinding_wire_test.go`,
`sasl_cbinding_openldap_test.go`, and `sasl_cbinding_gssapi_test.go` in the
same directory. This document records the compatibility contract and evidence.

Small integration edits are in `internal/server/configuration_capabilities.go`,
`sasl_config.go`, `sasl.go`, `sasl_scram.go`, `server.go`, `extended.go`, and
`write.go`, plus the attribute declaration in `internal/schema/builtin.go`.
No runtime activation mechanism was replaced. Existing tests were adjusted in
`internal/server/configuration_capabilities_test.go`,
`internal/server/sasl_scram_plus_test.go`, `cmd/ldap-go/client_sasl_test.go`,
and `cmd/ldap-go/main_test.go`. The import test now rejects an unknown policy
and checks its diagnostic; unrelated unsupported-configuration assertions are
unchanged. `go.mod` selects the pinned pure-Go library copy in
`third_party/xdg-go-scram`; see its `LOCAL_CHANGES.md`.

Validation on 2026-09-08 used `CGO_ENABLED=0` throughout:

- Full `cmd/ldap-go` tests passed, including the legacy import atomicity test.
- Full `internal/server` tests passed in the repository-wide test run.
- `go build ./...` passed.
- The explicitly enabled OpenLDAP 2.6.13/Cyrus/MIT KDC test run passed,
  including source hashes and native ldapwhoami; no selected tests skipped.
- The final `go test ./...` had one unrelated failure in shared work:
  `internal/lloadd/TestServiceSASLExternalRotationSessionCache`, which also
  reproduced in isolation. Its newly created proxy resumes a session with
  the retired TLS certificate. Those lloadd files were not edited for this
  feature. All other packages passed.
