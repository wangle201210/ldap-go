# Allowed attributes overlay

The optional `allowed` overlay exposes schema and ACL information as generated
operational attributes. Directory clients can use it to inspect which attributes
an entry's object classes permit and which the searching identity may write.

| Attribute | Meaning in OpenLDAP |
| --- | --- |
| `allowedAttributes` | Canonical inherited MUST/MAY attribute names for readable object classes on the entry |
| `allowedAttributesEffective` | The above subset for which an attribute-level write ACL check succeeds |
| `allowedChildClasses` | Registered auxiliary object classes that may be added to an entry's objectClass values |
| `allowedChildClassesEffective` | Auxiliary classes for which objectClass-value write and all inherited MUST-attribute write checks succeed |

Despite their names, the child-class attributes describe auxiliary classes,
not permitted types of child directory entries. Effective values are an ACL
summary, not a promise that a later modification will pass every value-specific
rule, constraint, structural rule, or concurrent configuration change.

There is an intentional ACL difference from native 2.6.13. Its allowed-module
and response ACL caches can reuse an attribute-level result for later values,
so some `val.*` denials do not hide class-derived names or generated values.
ldap-go checks each value against the ACL. The differential explicitly asserts
both the native cached result and the stricter Go result for those cases;
they are not reported as equal. Attribute-level denial behaves consistently.

## Configure

For a data database:

```ldif
dn: olcOverlay={0}allowed,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
olcOverlay: {0}allowed
```

Use the actual database DN and an unused overlay index. To include Root DSE
and subschema queries, place the overlay under an existing
`olcDatabase={-1}frontend,cn=config` entry instead. Duplicate instances on the
same database are rejected. The converter accepts `moduleload allowed.la`
and `overlay allowed`; `olcModuleLoad: allowed.la` registers schema, while the
overlay entry activates generated values. No C module is loaded.

```sh
./bin/ldap-go ldapsearch -x -H ldaps://directory.example.com:636 \
  -tls-ca /etc/ldap/ca.pem -D 'uid=alice,ou=people,dc=example,dc=com' -W \
  -b 'uid=alice,ou=people,dc=example,dc=com' -s base '(objectClass=*)' \
  allowedAttributes allowedAttributesEffective allowedChildClasses allowedChildClassesEffective
```

Request the names, their numeric OIDs (`1.2.840.113556.1.4.911` through `.914`),
or `+`. They are absent from default and `*` selection. `typesOnly` returns
attribute names without values. Their schema uses `objectIdentifierMatch`,
NO-USER-MODIFICATION, and `dSAOperation`.

## Semantics and limits

Generation happens after filter matching. The values are not available to
LDAP filters or Compare, are not persisted, and are excluded from Sync output.
LDAP Add/Modify cannot write them. Read ACLs on objectClass, individual class
values, and each generated output attribute/value remain authoritative.
Write checks use a nil attribute value except for the candidate objectClass
value, matching the native overlay's documented limitations.

Schema relationships are immutable per runtime configuration. Permission
results are calculated for the current entry and identity; schema and ACL
updates publish together through the existing configuration transaction.
Module registration validates imported definitions and rejects conflicting
OIDs, names, or semantics without partial publication.

The plan is limited to 8,192 classes, inheritance depth 128, and 1,048,576
inherited attribute references. Ordinary requests do no projection work when
the overlay is disabled or none of these operational attributes is selected.
The default-selection microbenchmark reports zero allocations with or without
the overlay; it is not an end-to-end LDAP throughput comparison.

Some optional built-in `cn=config` classes still lack complete base schema
definitions. Such classes are omitted as a whole rather than inventing MUST
sets or effective permissions. Complete native `cn=config` schema projection
therefore remains unclaimed. Delegated LDAP/meta/socket/passwd/DNS and relay
backend combinations are currently rejected when this overlay would apply;
they need their own operational response integration. General cross-overlay,
SQL-provider, replication-topology, and platform parity remain bounded by the
tests described in [testing.md](testing.md).
