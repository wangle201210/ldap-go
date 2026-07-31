# Compatibility testing

Compatibility claims require four layers of evidence.

## Unit and property tests

Pure components use table, fuzz, and property tests. BER, DN, filter, LDIF, and
schema parsers must include malformed-input and resource-limit tests.

## Protocol conformance

Tests derive expected behavior from the applicable RFC. They cover result codes,
response ordering, connection state, controls, limits, cancellation, and
security-sensitive edge cases.

## OpenLDAP differential tests

The same operation sequence runs against a pinned OpenLDAP 2.6.x container and
`ldap-go`. Results are normalized only where values are intentionally
server-generated, then compared for:

- result code, matched DN, diagnostics, referrals, and controls;
- returned DNs, attributes, values, and ordering where specified;
- resulting directory content and operational metadata;
- connection closure and unsolicited notifications.

Any intentional difference requires a documented compatibility exception.

## Migration tests

Fixtures are generated with `slapadd` and `slapcat`, imported unchanged into
`ldap-go`, exported again, and compared semantically. Fixtures cover custom
schema, binary and base64 values, folded lines, attribute options, referrals,
subentries, UUID/CSN metadata, and `cn=config`.

## Required checks

Each milestone must pass:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Network interoperability milestones additionally run OpenLDAP CLI and
differential tests. Fuzz targets run for a bounded period in CI and for an
extended period before a compatibility row is promoted.

The optional local OpenLDAP 2.6 reference fixture for Sync plus Sort/VLV is
enabled explicitly:

```sh
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run 'TestOpenLDAPReferenceSyncSortAndVLV|TestOpenLDAPSyncreplConsumesLDAPGoProvider|TestLDAPGoSyncreplConsumesOpenLDAPProvider|TestLDAPGoDeltaSyncreplConsumesOpenLDAPAccesslog' \
    -count=1
```

The SCRAM-SHA-256 syncrepl case discovers the mechanism through the provider
Root DSE and skips when the OpenLDAP Cyrus SASL installation has no SCRAM
plugin. When plugins are installed outside the platform default directory,
point Cyrus SASL at them for the gated run:

```sh
SASL_PATH=/path/to/cyrus-sasl/plugins \
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run TestLDAPGoSyncreplConsumesOpenLDAPProviderWithSCRAMSHA256 \
    -count=1
```
