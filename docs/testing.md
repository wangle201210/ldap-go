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

The optional local OpenLDAP 2.6 reference fixture for protocol, SASL,
transaction, and replication differentials is enabled explicitly:

```sh
LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 \
  go test ./internal/server \
    -run 'TestOpenLDAPClientSASLPlainBind|TestOpenLDAPClientSASLCRAMMD5Bind|TestOpenLDAPClientSASLDigestMD5Bind|TestOpenLDAPClientSASLSCRAMSHA256Bind|TestOpenLDAPReferenceTransactionRollback|TestOpenLDAPLDAPModifyTransactionInteroperability|TestOpenLDAPLDAPSearchDontUseCopyInteroperability|TestOpenLDAPReferenceDontUseCopy|TestOpenLDAPReferenceGlobalDisallows|TestOpenLDAPReferenceDynamicDirectoryServices|TestOpenLDAPReferenceDisabledDDS|TestOpenLDAPReferenceDDSExpirationHierarchy|TestOpenLDAPLDAPExopDynamicRefreshInterop|TestOpenLDAPReferenceDITContentRules|TestOpenLDAPSlapcatDITContentRuleImport|TestOpenLDAPReferenceSyncSortAndVLV|TestOpenLDAPSyncreplConsumesLDAPGoProvider|TestLDAPGoSyncreplConsumesOpenLDAPProvider|TestLDAPGoDeltaSyncreplConsumesOpenLDAPAccesslog' \
    -count=1
```

The PLAIN case invokes OpenLDAP `ldapwhoami` against ldap-go with
`olcSaslSecProps: none`. The other server-side cases invoke
`ldapwhoami -Y CRAM-MD5`, `ldapwhoami -Y DIGEST-MD5`, and
`ldapwhoami -Y SCRAM-SHA-256`. Each case skips when its local Cyrus SASL
plugin is unavailable.

The transaction cases run OpenLDAP `ldapmodify -E txn=commit/abort` against
ldap-go, then send the same duplicate-Add raw BER sequence to the reference
slapd to verify the failed message ID and atomic rollback semantics.
The Don't Use Copy cases run `ldapsearch -E '!dontUseCopy'` against a ldap-go
shadow database and compare the same critical, non-critical, malformed,
alias, referral, and Compare requests with the reference slapd.
The global-disallow case compares anonymous and authenticated simple Bind plus
critical and non-critical Don't Use Copy results and diagnostics against the
same slapd configuration.
The DDS cases run Add, live-TTL Search, Refresh, Modify, ModifyDN, object-count,
disabled-overlay, and expiration-hierarchy checks against reference slapd.
They also run OpenLDAP `ldapexop refresh` against ldap-go and verify the
persisted TTL selected by the server.
The DIT content-rule cases execute the same auxiliary-class and
`MUST`/`MAY`/`NOT` Add/Modify sequence against slapd and ldap-go, comparing
result codes and diagnostics. A second case generates `slapd.d` with
`slaptest`, exports the matching schema entry with `slapcat -n 0`, imports that
LDIF directly, and boots ldap-go from it.

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
