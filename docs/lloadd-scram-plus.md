# lloadd upstream SCRAM-PLUS

The pure-Go proxy can authenticate its upstream service connections using
`SCRAM-SHA-1-PLUS`, `SCRAM-SHA-256-PLUS`, or `SCRAM-SHA-512-PLUS`. These
mechanisms bind the authentication transcript to the actual TLS server
certificate. Ordinary client Binds continue to use the separate bind pool.

## Configuration

```conf
feature proxyauthz
bindconf bindmethod=sasl saslmech=SCRAM-SHA-256-PLUS authcid=service credentials=replace-me secprops=none tls_cacert=/etc/ldap/ca.pem tls_reqcert=demand timeout=5
tier roundrobin
backend-server uri=ldaps://directory.example.com numconns=4 bindconns=2 retry=5000
```

Protect the configuration containing the service password. The upstream must
provide the selected mechanism, map the service identity, and authorize the
requested proxy identities. An optional `authzid` selects an identity the
upstream service account is permitted to assume.

For StartTLS, change the URI to `ldap://` and add `starttls=critical` to the
backend. Configure the provider's channel-binding policy to `tls-endpoint`.
The client uses OpenLDAP/Cyrus's `p=ldap` GS2 name and endpoint binding bytes;
it does not implement `tls-unique` or other binding types.

This is an intentional difference from native lloadd 2.6.13. Its
`servers/lloadd/upstream.c` automatically supplies unprefixed `tls-unique`
bytes with the name `ldap` and `critical=0`, and it has no `bindconf
tls_cbinding` option. The Go implementation follows libldap's endpoint
encoding and does not claim equality with that native lloadd default.

## Verification and limits

- Binding bytes come from the leaf certificate of the completed, verified
  standard TLS connection. A configured secure URI alone is insufficient.
  Plaintext, LDAPI, TLCP, failed optional StartTLS, and unverifiable peers fail
  before any SCRAM proof is sent.
- `tls_reqcert=never/allow` is rejected. The configuration loader retains its
  trust, hostname, and revocation verifier. Supplying an arbitrary
  `InsecureSkipVerify` callback through the Go API does not bypass this policy.
- Server nonces must extend the client nonce. Salt, iteration count, challenge
  size, proof encoding, and round count are bounded before expensive work.
  Optional SCRAM extension bytes remain in the authenticated transcript;
  malformed, duplicate, and reserved extension fields are rejected.
- Failed authentication never publishes a regular-pool connection. Replacement
  connections authenticate again. TLS session caches remain isolated between
  configuration generations so certificate rotation uses the current binding.

`TestServiceSASLSCRAMPlus*` covers the three hashes, TLS 1.2/1.3,
LDAPS/StartTLS, project-server interoperability, proof and downgrade failures,
optional-extension transcripts, trust/name/revocation checks, pool identities,
reconnects, and certificate rotation:

```sh
CGO_ENABLED=0 go test ./internal/lloadd -run '^TestServiceSASLSCRAMPlus' -count=1
```

This addition does not claim all native lloadd mechanisms, configuration
defaults, channel-binding providers, or platform combinations. The external
OpenLDAP and Cyrus executables used for differential tests are not production
dependencies, and Go builds continue to use `CGO_ENABLED=0`.

`TestServiceSASLSCRAMPlusOpenLDAP2613SourceContract` checks the pinned
`d172686d3d270bc961b78f3ff00d7019c8dfb094` Git objects.
`TestServiceSASLSCRAMPlusRejectsNativeUniqueBinding` uses a real TLS 1.2
connection and a Go provider to verify rejection of the incompatible native
binding bytes for all three hashes. This fixture is not a native-binary test.

`TestServiceSASLSCRAMPlusOpenLDAP2613NativeProvider` starts a disposable pinned
slapd/Cyrus provider with `sasl-cbinding tls-endpoint`. All six combinations of
LDAPS/StartTLS and the three PLUS hashes pass service authentication, server
proof verification, Who Am I, and authenticated Search on macOS arm64 with
OpenLDAP 2.6.13, Cyrus SASL 2.1.28, and Go 1.26.4:

```sh
. /path/to/openldap-reference.env
CGO_ENABLED=0 LDAP_GO_LLOADD_SCRAM_PLUS_NATIVE_TESTS=1 \
  go test ./internal/lloadd \
  -run '^TestServiceSASLSCRAMPlusOpenLDAP2613NativeProvider$' -count=1
```

The source checkout and verified build environment must identify the exact
pin. The strict reference runner enables this test and requires it to pass.
This demonstrates Go lloadd interoperability with the native provider, not
equality with native lloadd's default channel-binding policy.
