# Matching-rule discovery

`cn=Subschema` publishes `matchingRules` and `matchingRuleUse` for the native
matching rules currently implemented in Go. No module or extra configuration
is required. Both attributes are operational: request them explicitly, by OID
(`2.5.21.4` and `2.5.21.8`), or with `+`.

```sh
./bin/ldap-go ldapsearch -x -H ldap://127.0.0.1:1389 \
  -b cn=Subschema -s base '(objectClass=*)' matchingRules matchingRuleUse
```

`matchingRules` describes the OID, canonical name, and assertion syntax of each
published rule. The current catalog contains 32 public rules covering the
implemented string, numeric, Boolean, DN, unique-member, time, UUID,
first-component, and substring matching families. Hidden OpenLDAP rules remain
hidden, and unsupported certificate/bit-string/custom-module rules are not
advertised. Internal compatibility names without a native OID are not assigned
invented identifiers.

`matchingRuleUse` lists the canonical attribute names a rule can apply to.
Following OpenLDAP 2.6.13 `mr_usable_with_at`, this uses the assertion syntax,
native compatible/superior syntaxes, and the attribute's inherited equality
rule. It is not just a grouping of configured EQUALITY, ORDERING, or SUBSTR
fields. Hidden attributes are excluded. A rule with no applicable attributes
has no use description. Some substring rules have compatible-syntax use
entries; others, including the IA5 and octet-string substring rules, do not.
Sharing a validator with `X-SUBST` does not create native syntax inheritance.

The server builds the descriptions with each immutable runtime configuration,
so successful schema updates refresh APPLIES and failed updates preserve the
previous snapshot. Searches do not rebuild the relation graph. Compilation
is limited to 16 MiB of descriptions and 1,048,576 applicability relationships;
invalid inheritance or excess size fails the candidate configuration atomically.
Normal attribute and value ACLs still filter schema responses.

Compare and equality filters accept both rule names and numeric OIDs in these
two attributes. Unknown numeric rules compare false. A valid but unknown
descriptor compares false while remaining undefined during filter evaluation,
so NOT does not turn it into a match. Malformed OID assertions return invalid
attribute syntax for Compare. The native differential checks these distinctions.

The description parser and formatter support Matching Rule Description and
Matching Rule Use Description syntaxes, including escaped text and bounded
field lists. Parsing a description does not register executable code.
Country String values use the native two-Printable-character validation.
Numeric substring-rule OIDs use the same ordinary, prepared, index, and cache
normalizers as their names; octet-string substrings preserve every byte,
including NUL and non-UTF-8 values.

This publication describes the implemented catalog, not every rule in an
OpenLDAP build or third-party module. Tests compare shared published descriptors
and fixture APPLIES sets; different built-in attribute inventories are not
claimed to be identical. See [test commands and scope](testing.md).
