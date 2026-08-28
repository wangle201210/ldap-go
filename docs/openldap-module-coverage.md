# OpenLDAP 2.6.13 module coverage

This ledger is pinned to OpenLDAP commit
`d172686d3d270bc961b78f3ff00d7019c8dfb094`. It is a closed inventory for that
source release, not a claim about arbitrary third-party modules. Unknown native
modules are rejected during startup, offline validation, and online changes.

## Backends

| Coverage | Modules |
| --- | --- |
| In-process runtime | `asyncmeta`, `config`, `dnssrv`, `frontend`, `ldap`, `ldif`, `mdb`, `meta`, `monitor`, `null`, `passwd`, `relay`, `sock`, `sql`, `wt` |
| Explicitly unsupported | `perl` (`back-perl` requires an embedded Perl interpreter and native backend ABI) |

`mdb`, `ldif`, and `wt` use ldap-go storage contracts rather than native
OpenLDAP database files. `sql` supports registered `database/sql` drivers; the
bundled ODBC connector is unavailable in FreeBSD pure-Go builds.

## Standard overlays

All 25 overlays selected by OpenLDAP 2.6.13 `configure.ac` have an in-process
runtime implementation:

`accesslog`, `auditlog`, `autoca`, `collect`, `constraint`, `dds`, `deref`,
`dyngroup`, `dynlist`, `homedir`, `memberof`, `nestgroup`, `otp`, `ppolicy`,
`proxycache` (`pcache`), `refint`, `remoteauth`, `retcode`, `rwm`, `seqmod`,
`sssvlv`, `syncprov`, `translucent`, `unique`, and `valsort`.

Additional accepted core configurations are `chain`, `pbind`, `sock`, explicit
`glue`, the contrib `allop` default Root DSE mode, contrib `lastbind`, contrib
`nops`, and the `totp` password overlay. `syncrepl` is represented by the
consumer runtime rather than accepted as a user-created overlay. `distproc`
and experimental `slapi` remain explicitly unsupported.

An accepted overlay name means its documented runtime is implemented and
tested. It does not claim every permutation of overlay order, backend, glue,
replication, proxy topology, and failure timing; those combinations remain
bounded by the evidence in [compatibility.md](compatibility.md).

## Password modules

| Coverage | Modules/schemes |
| --- | --- |
| In-process, generated and verified | core `argon2` (`{ARGON2}` d/i/id import, id generation), `pw-apr1`, `pw-pbkdf2`, `pw-sha2`, `pw-totp` |
| In-process verify/delegation | `pw-netscape`, `pw-radius` |
| Explicitly unsupported | `pw-kerberos`, `smbk5pwd`/`{K5KEY}`, unknown dynamic schemes |

## Contrib modules

The pinned source contains these top-level contrib directories:

`acl`, `addpartial`, `adremap`, `alias`, `allop`, `allowed`, `authzid`,
`autogroup`, `ciboolean`, `cloak`, `comp_match`, `datamorph`, `denyop`,
`dsaschema`, `dupent`, `emptyds`, `kinit`, `lastbind`, `lastmod`, `noopsrch`,
`nops`, `nssov`, `passwd`, `ppm`, `proxyOld`, `rbac`, `samba4`, `smbk5pwd`,
`trace`, `usn`, `variant`, and `vc`.

The password implementations listed above, `allop`, `lastbind`, and `nops` are
data/protocol compatible. The remaining contrib modules execute
OpenLDAP C `Entry`, overlay, SLAPI,
dynamic ACL, matching-rule, PAM/NSS, Kerberos, or extended-operation ABIs and
are rejected. Loading them as `.so`/`.la` would require embedding slapd rather
than reimplementing LDAP behavior in Go.

## Platform boundary

`scripts/test-platform-builds.sh` builds the complete repository with cgo
disabled for Linux amd64/arm64, macOS amd64/arm64, Windows amd64, and FreeBSD
amd64. Runtime differential tests still execute on the host platform. No
finite matrix can prove every kernel, filesystem, external service, TLS
provider, ODBC driver, and third-party module combination.
