# LDAP syntax discovery

`cn=Subschema` now publishes `ldapSyntaxes` (`1.3.6.1.4.1.1466.101.120.16`).
No module configuration is required. Request the attribute explicitly or with
`+`; it is absent from default and `*` selection.

```sh
./bin/ldap-go ldapsearch -x -H ldap://127.0.0.1:1389 \
  -b cn=Subschema -s base '(objectClass=*)' ldapSyntaxes
```

The publication follows OpenLDAP 2.6.13: a syntax must have an available
validator and must not be hidden. Names, descriptions, and schema extensions
come from the pinned native definitions. Internal binary flags alone do not
invent an `X-BINARY-TRANSFER-REQUIRED` extension; PKCS#8 is one such native
case. Native parser-only syntax descriptions remain absent even when Go has
a parser for reading them.

Custom `olcLdapSyntaxes` definitions with `X-SUBST` retain their own metadata
and inherit the substitute's validation behavior. Hidden and validatorless
substitutes stay unpublished. The native distinction between a concrete
Directory String syntax and an `X-SUBST` copy is preserved: an empty custom
copy value is accepted, while an empty ordinary Directory String is rejected.
UTF-8 validation still applies to nonempty values.

Descriptions are prepared with each immutable runtime configuration, with a
16 MiB/8,192-definition bound. Failed configuration updates preserve the
previous publication. Search, typesOnly, attribute/value ACLs, numeric-OID
Compare and three-valued filters use the normal LDAP paths. Syntax assertions
are numeric OIDs, not the human-readable DESC strings.

## Additional value support

The server now accepts the implemented Audio, Binary, Bit String, Delivery
Method, JPEG, Other Mailbox, RDN, NIS Netgroup Triple, and Boot Parameter
syntaxes. Audio, Binary, and JPEG use the native blob-validation behavior;
that does not validate an image header or require well-formed BER. Other
Mailbox uses native IA5 validation. Delivery Method and the RFC2307 syntax
grammars follow the pinned implementation, including its empty-field behavior.

Bit String values use the quoted bit representation, for example `'001'B` or
`''B`. The `bitStringMatch` rule (`2.5.13.16`) preserves significant leading
bits and supports equality indexes. Invalid bit assertions are undefined in
filters and return invalid attribute syntax for Compare.

Online local Add/Modify of RDN-valued attributes performs native-style pretty
formatting before storage, including canonical attribute names, old quoted
forms, hexadecimal escaping, and selection of the first RDN. Unknown naming
attributes fail rather than being stored. Attribute inheritance and `X-SUBST`
chains use the same formatter. Input is bounded to 8,192 bytes and recursive
RDN-valued naming attributes to 32 levels. Failed modifications remain atomic.
The sparse runtime attribute map keeps ordinary writes outside the formatter
when no RDN-valued attributes are configured.

This is the documented syntax subset. Full DN pretty/normalization behavior,
every offline/delegated-backend combination, third-party executable validators,
and the remaining native syntaxes still require separate evidence. See
[testing](testing.md) for the reproducible native comparison.
