# Converting slapd.conf

`slapdconf-convert` is a pure-Go, offline converter. It expands the configuration
and schema includes, builds a deterministic `cn=config` LDIF tree, and validates
it with ldap-go's configuration loader before publishing any output. It does not
invoke OpenLDAP, load native modules, use cgo, or start replication or listeners.

Run from the repository root:

```sh
CGO_ENABLED=0 go build -o /tmp/slapdconf-convert ./cmd/slapdconf-convert
/tmp/slapdconf-convert -f /path/to/slapd.conf -check
/tmp/slapdconf-convert -f /path/to/slapd.conf -out /path/to/config.ldif
# Alternatively, create a new ldap-go database containing the configuration:
/tmp/slapdconf-convert -f /path/to/slapd.conf -db /path/to/ldap-go.db
```

Without `-out`, `-db`, or `-check`, LDIF goes to stdout. These three flags are
mutually exclusive. Output files are created with mode `0600`; existing files,
including symlinks, are never replaced. Validation failures produce no LDIF or
destination database. File output is published atomically from temporary files.

Relative includes resolve against the process working directory, matching
OpenLDAP. Use `-include-base /original/working/directory` to select that base
explicitly. Nested includes share it. Other paths, such as certificate and
auditlog paths, retain their configured values. Use absolute paths when changing
the runtime working directory. TLS files must be accessible during validation.

The converter migrates configuration only. `directory` and MDB `maxsize` are
retained as OpenLDAP storage metadata; they do not select the bbolt destination,
import existing LMDB files, or impose an LMDB map-size limit on ldap-go. Import
content from an LDIF export separately, selecting the converted database:

```sh
go run ./cmd/ldap-go import -db /path/to/ldap-go.db -database 1 -ldif /path/to/content.ldif
go run ./cmd/ldap-go config-test -db /path/to/ldap-go.db
```

## Supported Configuration

- Double-quoted and escaped arguments, whitespace and backslash continuations,
  comments, nested includes, custom schema descriptions, and OID macros.
- `backend` declarations and `database frontend`, `config`, `mdb`, `ldif`,
  `ldap`, `null`, `relay`, and `monitor`. Content databases receive indices in
  declaration order; frontend and config keep indices `-1` and `0`.
- Database suffixes, root DNs and password bytes/hashes, ACL ordering, index
  definitions and defaults, limits, read-only settings, per-database
  `monitoring`, and security policy.
- Global `logfile`, `logfile-format`, `logfile-only`, and `logfile-rotate`
  settings map to ldap-go's validated file logger and rotation configuration.
- Global `sasl-cbinding none|tls-unique|tls-endpoint` maps to the single-valued
  `olcSaslCBinding` on `cn=config` (OID `1.3.6.1.4.1.4203.1.12.2.3.0.100`),
  including when written after a backend, database, or overlay declaration.
  Values are ASCII case-insensitive; spelling is preserved after double quotes
  and escapes are decoded. Omission leaves the runtime default of `none`.
  Empty values, surrounding whitespace inside quotes, unknown policies (including
  `tls-server-end-point` and `tls-exporter`), extra arguments, and repeated
  directives fail with source file and line information. Repeated identical
  values also fail, following the converter's single-value contract.
- TLS certificate/key/CA files, protocol minimum, verification, cipher and
  group settings, subject to ldap-go's runtime TLS support. Both certificate
  and key are required: standalone OpenLDAP TLS defaults are rejected because
  ldap-go cannot apply them without server material.
- Syncrepl consumers, including quoted credentials, retry schedules, filters,
  SASL/TLS options supported by ldap-go, and multiple ordered consumers.
- Common overlays including syncprov, memberof, refint, ppolicy, accesslog,
  auditlog, unique, dynlist/dyngroup, constraint, sssvlv, and rwm. Named RWM
  rewrite contexts/rules are accepted only on `ldap` and `relay` databases,
  where ldap-go executes them. Local backends retain suffix massage and direct
  attribute/object-class maps. Each directive is dispatched to its current
  database/overlay and runtime-validated.

Unknown directives, unsupported native modules/module arguments, backend-wide
options without runtime equivalents, and unsupported overlay options fail with
source file and line information. There is no ignore-unknown mode. For example,
LMDB durability flags, checkpoint scheduling, SLAPI plugins, and slurpd settings
are rejected. Duplicate single-valued settings are rejected rather than silently
choosing one. This is a strict conversion path, not a general OpenLDAP emulator.

The SASL channel-binding mapping follows OpenLDAP 2.6.13
(`d172686d3d270bc961b78f3ff00d7019c8dfb094`): `doc/man/man5/slapd.conf.5`
documents the policy names, `servers/slapd/bconfig.c` declares the global
single-valued string attribute, and `libraries/libldap/cyrus.c` compares the
policy names without trimming or tokenizing them. ldap-go deliberately rejects
unsupported policies that OpenLDAP's `servers/slapd/sasl.c` silently ignores.
This setting selects channel-binding metadata; it does not require TLS files
for conversion or initiate TLS, SASL authentication, or network connections
during conversion, validation, or offline import (including import dry-run).

The library lives in `internal/migration/slapdconf`: `ParseFile`, `ConvertFile`,
`ConvertFileContext`, `Document.WriteLDIF`, and transactional `Document.Import`.
Default parser limits are 16 MiB per file, 64 MiB total, 1 MiB per logical line,
32 nested includes, and 256 file expansions. Include cycles (including symlink
cycles), nonregular files, invalid UTF-8, NUL bytes, and malformed quoting fail.
Unix opens are nonblocking and descriptor-validated; path identity is checked
after opening on every platform so a file swapped to a FIFO or another inode is
rejected instead of read.

## Verification

```sh
CGO_ENABLED=0 go test ./internal/migration/... ./cmd/slapdconf-convert
CGO_ENABLED=0 go test ./internal/migration/slapdconf -run '^$' -fuzz FuzzLogicalLinesAndArguments -fuzztime 5s
# Optional external oracle; slaptest/slapadd/slapcat must be on PATH:
CGO_ENABLED=0 LDAP_GO_SLAPDCONF_ORACLE=1 go test ./internal/migration/slapdconf -run TestOpenLDAPConversionOracle -v
```

Set `LDAP_GO_OPENLDAP_SCHEMA_DIR` if the oracle's `core.schema` is outside the
standard Linux/Homebrew schema directories. The oracle uses disposable directories,
compares configuration values, and imports the Go-generated LDIF into OpenLDAP.
All ordinary tests run without OpenLDAP installed.
