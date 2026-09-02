# OpenLDAP migration and password policy

[Back to README](../README.md)

## Migration contract

OpenLDAP MDB and other backend files are implementation-specific. ldap-go does
not read them directly. The portable contract is `slapcat` LDIF, including the
tested `cn=config`, entry UUID, CSN, and operational metadata subset.

Compatibility at the LDIF boundary does not imply support for every OpenLDAP
backend, overlay, module, schema extension, or configuration value. Check the
[compatibility matrix](compatibility.md) before migration.

## Multi-database migration

Export `cn=config` first, followed by each content database:

```sh
slapcat -n 0 -l config.ldif
slapcat -n 1 -l data-1.ldif
```

Import configuration before content and select the same numeric database:

```sh
./bin/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./config.ldif \
  -replace

./bin/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./data-1.ldif \
  -database 1 \
  -replace
```

Export the selected database for canonical comparison or a return migration:

```sh
./bin/ldap-go export \
  -db ./data/ldap-go.db \
  -ldif ./data-1-export.ldif \
  -database 1
```

Run imports against a copy first. Validate configuration and data before
starting a production listener:

```sh
./bin/ldap-go slaptest -db ./data/ldap-go.db
./bin/ldap-go slapschema -db ./data/ldap-go.db -v
./bin/ldap-go check -db ./data/ldap-go.db
```

## OpenLDAP-style offline tools

The following aliases preserve the implemented OpenLDAP option and exit-code
surface while using ldap-go's bbolt storage:

```sh
./bin/ldap-go slaptest -db ./data/ldap-go.db
./bin/ldap-go slapdn -db ./data/ldap-go.db \
  'uid=alice,dc=example,dc=com'
./bin/ldap-go slapadd -db ./data/ldap-go.db \
  -l data-1.ldif -n 1 -S 1 -w
./bin/ldap-go slapadd -db ./data/ldap-go.db \
  -l data-1.ldif -n 1 -j 250001
./bin/ldap-go slapcat -db ./data/ldap-go.db \
  -l exported.ldif -n 1
./bin/ldap-go slapcat -db ./data/ldap-go.db -n 1 \
  -s 'ou=People,dc=example,dc=com' -a '(objectClass=inetOrgPerson)'
./bin/ldap-go slapauth -db ./data/ldap-go.db \
  'uid=alice,cn=auth'
./bin/ldap-go slapacl -db ./data/ldap-go.db \
  -D 'uid=alice,dc=example,dc=com' \
  -b 'uid=bob,dc=example,dc=com' 'mail/read'
./bin/ldap-go slapschema -db ./data/ldap-go.db -v
./bin/ldap-go slapmodify -db ./data/ldap-go.db \
  -l changes.ldif -j 1 -w
./bin/ldap-go slapindex -db ./data/ldap-go.db cn uid
```

These commands do not make bbolt files binary-compatible with OpenLDAP MDB
files. Proxy and virtual backends reject unsupported offline operations rather
than silently changing another partition.

## Validation and atomicity

Native `import`, direct `ImportLDIF` callers, and `slapadd` without `-c` validate
and publish in one transaction. Structural schema checks are enabled by
default. `slapadd -o value-check=yes` enables full value-syntax checks;
`-s` or `-o schema-check=no` disables structural checks while retaining the
basic `objectClass` requirement.

The content-database `slapadd -c` path is intentionally non-atomic: it retains
independent valid records, reports each failure, and exits nonzero when any
record fails. It rejects partial `cn=config` publication because a partially
installed schema or database topology is unsafe. See
[implementation status](implementation-status.md#migration-and-offline-tools)
for glue databases, generated LastMod metadata, continuation, indexing, and DN
identity migration details.

## Password hash interoperability

Imported supported password values remain tagged with their existing scheme.
Bind selects the verifier from that tag; migration does not require converting
every password to one global format. The tested set includes OpenLDAP core and
supported contributed SHA, PBKDF2, APR1/BSDMD5, Argon2, `{CRYPT}`, TOTP,
Netscape, and RADIUS boundaries plus ldap-go's national-cryptography formats.
The exact list and generation/verification limitations are maintained in the
[compatibility matrix](compatibility.md#authentication-authorization-and-security).

For new national-cryptography values, prefer the costed `{PBKDF2-SM3}` format.
Read the cleartext from the environment instead of a command argument:

```sh
LDAP_GO_PASSWORD='change-me' ./bin/ldap-go passwd
```

The default uses a random 16-byte salt and 100,000 iterations. `{SM3}` and
`{SSM3}` are accepted for migration, but their fast digest construction is not
recommended for newly assigned passwords. An upstream OpenLDAP server needs a
matching module or patch to verify ldap-go's `{PBKDF2-SM3}` extension.

`slappasswd` can generate supported OpenLDAP-compatible formats explicitly:

```sh
./bin/ldap-go slappasswd -h '{SSHA}'
./bin/ldap-go slappasswd -h '{PBKDF2-SHA256}'
./bin/ldap-go slappasswd -h '{PBKDF2-SM3}'
```

The command prompts when a password is not supplied through its secure input
options. Do not place cleartext credentials in shell history.

## Server password policy

RFC 3062 Password Modify uses the frontend `olcPasswordHash` policy. The
OpenLDAP-compatible default is `{SSHA}`. To make ordinary server-side password
changes use PBKDF2-SM3, modify `cn=config`:

```ldif
dn: olcDatabase={-1}frontend,cn=config
changetype: modify
replace: olcPasswordHash
olcPasswordHash: {PBKDF2-SM3}
```

The setting is validated and reloaded atomically. Users can then change their
own passwords with a standard RFC 3062 client:

```sh
ldappasswd -x -H ldap://127.0.0.1:1389 \
  -D uid=alice,ou=people,dc=example,dc=com -W -A -S
```

## Per-user selection in Web Admin

Password hash policy is normally server-wide, not a persistent property of one
user. Web Admin can request a different hash for one administrator-initiated
Password Modify operation when the connected ldap-go server advertises the
critical control `1.3.6.1.4.1.4203.666.5.20`.

The selector:

- requires `manage` access to the target password attribute;
- applies only to that Password Modify operation;
- runs after old-password, quality, and history checks;
- does not change `olcPasswordHash`; and
- is unavailable against stock OpenLDAP, where Web Admin shows **Server
  policy** only.

Normal self-service password changes continue to use the configured server
policy.
