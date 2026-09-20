# Core configuration schema

The built-in registry includes the 111 core configuration attribute definitions
and nine foundation object classes from OpenLDAP 2.6.13 `bconfig.c`, pinned to
commit `d172686d3d270bc961b78f3ff00d7019c8dfb094`:

`olcConfig`, `olcGlobal`, `olcSchemaConfig`, `olcBackendConfig`,
`olcDatabaseConfig`, `olcOverlayConfig`, `olcIncludeFile`,
`olcFrontendConfig`, and `olcModuleList`.

These definitions provide canonical names/OIDs, inheritance, MUST/MAY
attributes, syntaxes, matching-rule references, single-value constraints, and
ordered-value metadata. They are visible in `cn=Subschema`, as in the native
reference. Entry ACLs still control access to actual configuration values,
including passwords and keys. A published definition does not enable an
unsupported directive, matching-rule implementation, backend, or module.

```sh
./bin/ldap-go ldapsearch -x -H ldap://127.0.0.1:1389 \
  -b cn=Subschema -s base '(objectClasses=olcDatabaseConfig)' objectClasses

./bin/ldap-go ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D cn=config -W -b cn=config -s base '(objectClass=*)' '@olcGlobal'
```

Subschema Compare and equality filters accept definition names and numeric
OIDs, including aliases. Configuration reads and supported online Add/Modify
operations resolve attribute OIDs to the same fields as their canonical names.
Unsupported settings cannot bypass validation by using an OID. Unknown or
inappropriate attribute options are rejected. As in the pinned native backend,
language-tagged size-limit values can be stored and retrieved but do not change
the effective untagged limit.

The runtime uses a canonical read view for imported configuration attributes;
startup does not rewrite their stored names or values. Online writes use
canonical names. Mixed name/OID spellings are combined for validation, so
multiple values of a single-valued setting cannot hide behind aliases.
Configuration handlers retain their existing value parsing; classic accepted
hexadecimal/octal settings are not rejected merely because the published LDAP
attribute syntax is Integer.

Registration is atomic, validates references, and preserves semantically
equivalent imported definitions. Conflicting identifiers, matching semantics,
cardinality, or ordered-value metadata fail without partial registration.
`olcLimits` now carries the native `X-ORDERED 'VALUES'` definition: an online
replacement such as `users size=unlimited` is read back with `{0}`. Failed
updates leave both stored configuration and active runtime unchanged.

Adding schema definitions changes the directory naming-schema fingerprint.
An existing bbolt database may therefore rebuild identity/index metadata once
on upgrade. Regression tests verify that entry DNs, values, partitions, and
indexed query results survive the upgrade and a subsequent reopen.

The existing PKI content classes also now resolve their standard
`authorityRevocationList`, `certificateRevocationList`, and
`crossCertificatePair` dependencies. These use the existing certificate-list
or certificate-pair validators and require `;binary` transfer.

This completes the documented core schema catalog, not every OpenLDAP runtime
configuration option or backend-specific schema. Native MDB/LMDB internals
and further third-party module replication remain outside project scope.
See [compatibility](compatibility.md) and [testing](testing.md) for the actual
runtime and differential boundaries.
