Source: github.com/xdg-go/scram v1.2.0 (Apache-2.0; see LICENSE).
Upstream module checksum: `h1:bYKF2AEwG5rqd1BumT4gAnvwU/M9nBp2pTSxeZw7Wvs=`.

The only code change is allowing the channel-binding type `ldap` in
`parseGS2Flag`. OpenLDAP 2.6.13 libraries/libldap/cyrus.c uses that name and
prefixes its binding data with `tls-unique:` or `tls-server-end-point:`.
The original conversation, proof validation, downgrade detection, and binding
data comparison remain unchanged. Parent-module SASLCBinding tests exercise
both standard and OpenLDAP binding names, including mismatch and downgrade.

Upstream production files, documentation, and module metadata are retained;
upstream test files are not copied. Revisit this replacement when upstream
supports application-defined channel-binding names.
