# OpenLDAP compatibility matrix

Baseline: OpenLDAP 2.6.x, with OpenLDAP 2.6.13 used by the initial differential
test environment.

Status values:

- `planned`: no passing implementation claim;
- `partial`: a documented subset has conformance tests;
- `compatible`: standards tests and OpenLDAP differential tests pass;
- `n/a`: deliberately inapplicable, with rationale recorded.

No row may become `compatible` based only on unit tests.

## LDAPv3 protocol

| Area | Status | Required evidence |
| --- | --- | --- |
| BER framing and LDAPMessage | partial | RFC malformed-input corpus and client interoperability |
| Bind: anonymous and simple | partial | RFC 4511/4513 plus OpenLDAP differential tests |
| Bind: SASL | planned | mechanism matrix and channel-binding tests |
| Search and SearchResultReference | partial | scope, deref, limits, attributes, typesOnly |
| Filters and matching | partial | RFC 4515 corpus and schema-aware differential tests |
| Modify | partial | atomic modification and error-order differential tests |
| Add | partial | parent/schema/ACL/operational-attribute tests |
| Delete | partial | leaf/subtree/referral behavior tests |
| ModifyDN | partial | rename/move/subtree and RDN-value tests |
| Compare | partial | matching-rule and ACL disclosure tests |
| Abandon and cancellation | planned | concurrent operation tests |
| Unbind and disconnect notices | partial | connection-state tests |
| Referrals, aliases, and ManageDsaIT | planned | topology differential tests |
| LDAP URLs and attribute options | planned | RFC 4516 and binary/language option tests |

## Controls and extended operations

| Area | Status | Required evidence |
| --- | --- | --- |
| StartTLS | planned | RFC 4511/4513 state machine and TLS tests |
| Password Modify | planned | RFC 3062 and password policy integration |
| Who Am I? | planned | RFC 4532 authorization identity tests |
| Cancel | planned | RFC 3909 concurrent operation tests |
| Assertion | planned | RFC 4528 atomic write tests |
| Pre-read and post-read | planned | RFC 4527 write transaction tests |
| Paged results | planned | RFC 2696 cookie and mutation tests |
| Server-side sorting | planned | RFC 2891 matching and error tests |
| VLV | planned | OpenLDAP control differential tests |
| Subentries | planned | RFC 3672 visibility tests |
| Don't Use Copy | planned | RFC 6171 topology tests |
| LDAP Sync | planned | RFC 4533 refresh/persist interoperability |
| OpenLDAP transaction extension | planned | multi-operation atomicity tests |
| Dynamic refresh | planned | OpenLDAP DDS interoperability tests |

## Data model and schema

| Area | Status | Required evidence |
| --- | --- | --- |
| DN/RDN parsing and normalization | partial | RFC 4514 corpus and OpenLDAP normalization |
| Core syntaxes and matching rules | partial | RFC 4517 schema-aware corpus |
| Standard operational attributes | partial | create/modify/rename differential tests |
| Subschema subentry | partial | discovery and schema publication tests |
| Runtime schema through `cn=config` | partial | add/modify/delete and restart tests |
| Collective attributes and subentries | planned | RFC 3671/3672 tests |
| DIT content/name/structure rules | planned | schema enforcement differential tests |

## Authentication, authorization, and security

| Area | Status | Required evidence |
| --- | --- | --- |
| OpenLDAP password schemes | partial | hash/verify vectors and migration tests |
| Password policy overlay | planned | lockout, expiry, grace, history, controls |
| OpenLDAP ACL grammar and evaluation | partial | ordered rule differential suite |
| Security strength factors | planned | transport/SASL/ACL integration tests |
| TLS and mutual TLS | planned | LDAPS, StartTLS, reload, CRL, client cert |
| National cryptography transport | planned | selected GM/T profile and client matrix |
| Audit and security logging | planned | redaction, integrity, and operation coverage |

## Storage, configuration, and migration

| Area | Status | Required evidence |
| --- | --- | --- |
| Transactional durable backend | partial | crash, atomicity, recovery, race tests |
| Multiple suffixes and subordinate DBs | partial | partition, hidden, and glue routing tests |
| `cn=config` online configuration | partial | OpenLDAP LDIF import and online changes |
| `slapcat` content LDIF import/export | partial | lossless fixtures and large-dataset tests |
| `slapcat` `cn=config` import | partial | boot from imported configuration |
| Backup, restore, index rebuild, check | planned | fault-injection and round-trip tests |
| Proxy, relay, monitor, and null backends | planned | OpenLDAP behavior suites |
| SQL, sock, and perl-style adapters | planned | backend-specific compatibility suites |

OpenLDAP MDB binary files are not a stable interchange format. Canonical
`slapcat` LDIF is the direct migration contract; all destination indexes are
rebuilt by `ldap-go`.

## Overlays

| Area | Status | Required evidence |
| --- | --- | --- |
| accesslog and auditlog | planned | LDIF/result differential tests |
| chain | planned | referral chaining tests |
| constraint | planned | rule and error differential tests |
| DDS | planned | TTL lifecycle and refresh tests |
| dynlist and dynid | planned | expansion/update tests |
| homedir | planned | lifecycle hook tests |
| memberof and refint | planned | transactional referential-integrity tests |
| pbind and remoteauth | planned | remote authentication tests |
| pcache | planned | cache correctness and invalidation tests |
| ppolicy | planned | full password policy suite |
| retcode | planned | configured result behavior |
| rwm | planned | DN/attribute rewrite differential tests |
| syncprov | planned | RFC 4533 provider suite |
| translucent | planned | local/remote merge tests |
| unique | planned | concurrent uniqueness tests |
| valsort | planned | value sorting tests |
| autoca and OTP-related contrib modules | planned | module-specific compatibility tests |

## Replication and operations

| Area | Status | Required evidence |
| --- | --- | --- |
| Syncrepl consumer | planned | OpenLDAP provider interoperability |
| Syncprov provider | planned | OpenLDAP consumer interoperability |
| Delta-syncrepl | planned | accesslog replay and recovery tests |
| Multi-provider and mirror mode | planned | conflict/topology/failover tests |
| Fractional and sparse replication | planned | filter/attribute convergence tests |
| Connection and operation monitoring | planned | `cn=Monitor` differential tests |
| Dynamic logging and runtime limits | planned | `cn=config` behavior tests |
| Graceful restart and zero-loss shutdown | planned | in-flight operation and durability tests |
| `lloadd` behavior | planned | routing, health, bind affinity, and controls |

## Command-line compatibility

| Area | Status | Required evidence |
| --- | --- | --- |
| Server daemon and config validation | partial | lifecycle and config diagnostics |
| `slapadd` / `slapcat` equivalents | partial | OpenLDAP LDIF round trips |
| `slapindex` / `slaptest` / `slapdn` | planned | output and exit-code differential tests |
| LDAP client tools | planned | option and protocol interoperability |
| Load balancer tooling | planned | `lloadd` configuration tests |

## Implemented subset evidence

The first runnable subset includes bounded BER framing; LDAPv3 anonymous/simple
Bind; Root DSE; base, one-level, and subtree Search; boolean, equality,
presence, substring, ordering, approximate, and basic extensible filters;
Unbind; Add, Modify (including increment), leaf Delete, subtree ModifyDN,
Compare; a transactional bbolt backend; and atomic content LDIF import/export.
Network Add generates `entryUUID`, `entryCSN`, creator/modifier names, and
create/modify timestamps, `structuralObjectClass`, and `subschemaSubentry`.
Modify and ModifyDN update modification metadata.

The schema registry parses OpenLDAP `{n}`-ordered `olcAttributeTypes` and
`olcObjectClasses`, applies object-class and syntax checks to writes, and uses
registered matching rules for Search and Compare. Root DSE discovery and the
read-only `cn=Subschema` entry publish built-in and imported definitions.
Attribute selection distinguishes user attributes (`*`) from operational
attributes (`+`).

Current password verification covers cleartext, `{CLEARTEXT}`, `{SHA}`,
`{SSHA}`, `{MD5}`, and `{SMD5}`.

The ACL evaluator loads ordered `olcAccess` values from frontend and database
entries. It supports exact/base, one-level, subtree, children, and regular
expression DN targets; attribute targets; anonymous, users, self, DN, DN
attribute, static group, and SSF subjects; access levels and `=`, `+`, `-`
privileges; `stop`, `continue`, and `break`; and OpenLDAP's implicit clauses.
Search/Compare/Bind and all write operations enforce attribute or pseudo-
attribute access. Add/delete privileges (`a`/`z`), Replace semantics,
`olcAddContentAcl`, ModifyDN parent/RDN checks, DN-syntax-only `selfwrite`,
root bypass, default read access, and the `cn=config` default-none exception
follow the slapd implementation.

ACL filter/value targets, object-class attribute sets, dynamic groups, sets,
network/peer selectors, ACI, DN expansion, and transport-derived SSF remain
unimplemented. Configurations using an unsupported selector fail server
startup instead of silently weakening access control.

Runtime database selection loads `olcDatabase`, all `olcSuffix` values,
`olcRootDN`, and `olcRootPW` from imported `cn=config` entries. Longest-suffix
selection scopes root authentication and ACL bypass to one database. Hashed
root passwords use the same supported OpenLDAP password schemes as entry
passwords; an unset root password falls back to normal entry authentication,
while an explicitly empty value disables simple Bind for that root DN.
Configuration-like attributes outside `cn=config` are ignored by schema, ACL,
and runtime database loaders.

Online Add, Modify, Delete, and in-tree ModifyDN operations under `cn=config`
build schema, ACL, and database routing as one immutable snapshot inside the
write transaction. Invalid supported configuration rolls back the directory
change; a successful commit atomically publishes the new snapshot. Tests cover
immediate ACL and root-password changes, schema publication/removal, rollback,
and concurrent searches during repeated ACL reloads. The complete OpenLDAP
configuration schema, backend/module-specific mutation hooks, ordered-entry
renumbering, and full differential error behavior remain pending.

Runtime database settings also load `olcReadOnly` and `olcLastMod`, including
the frontend read-only restriction, while global `olcAllows: update_anon`
controls whether anonymous updates may reach ACL evaluation. Update
restrictions run before ACL checks, and database root DNs do not bypass
read-only mode. With `olcLastMod: FALSE`, Add, Modify, and ModifyDN stop
generating UUID, CSN, creator, and timestamp metadata while schema operational
attributes remain available. Online changes and invalid-value rollback are
covered through TCP client tests. Other `olcAllows` behavior, `olcRestrict`,
`olcRequires`, listener permissions, and SSF-based update requirements remain
pending.

Every configured database now has an isolated storage partition, keyed by its
imported configuration-entry UUID when available. Existing single-namespace
stores are partitioned atomically at startup. Bind, Search, Compare, and write
operations only see the selected partition; ModifyDN rejects cross-database
moves with `affectsMultipleDSAs`. `olcHidden` databases are skipped during
selection and Root DSE publication, while their entries remain isolated and
may use the same DN as a visible database. Online hide/show changes and suffix
conflict rollback are covered by TCP tests. `olcDisabled` databases are also
removed from operation routing but, matching slapd, remain published in Root
DSE and retain their isolated data. Online disable/enable changes and invalid-
value rollback are covered through TCP tests. Root DSE `namingContexts`,
`configContext`, and `monitorContext` values are built from the same runtime
snapshot. Database-selective import/export accepts a slapcat-style numeric
index, an `olcDatabase` value, or a configuration-entry DN; tests import and
export identical DNs from visible and hidden databases independently.
`olcSubordinate: TRUE`, `FALSE`, and `advertise` are loaded and validated with
OpenLDAP's single-suffix restriction. Base searches stay in the selected
backend; one-level and subtree searches fan out across the applicable
subordinate partitions with shared limits. Unadvertised subordinate suffixes
are omitted from Root DSE, while `advertise` publishes them. Bind and writes
still select the most-specific backend, empty subordinate suffix entries can be
created online, and cross-database ModifyDN returns `affectsMultipleDSAs`.
Online setting changes and invalid-value rollback are covered by TCP tests.
Glue interactions with controls and explicitly positioned overlays remain
pending.

Evidence currently consists of package tests, TCP interoperability tests using
`github.com/go-ldap/ldap/v3`, import/export semantic round trips, and manual
process-level operations using OpenLDAP 2.6.13 `ldapsearch`, `ldapadd`,
`ldapmodify`, `ldapcompare`, `ldapmodrdn`, and `ldapdelete`. Rows remain
`partial` because the complete RFC 4517 syntax/matching-rule set,
aliases/referrals, controls, the remaining ACL grammar and differential suite,
SASL, subtree-delete control, and full differential fixtures are still
pending.

Schema bootstrap was also exercised by importing the unmodified Homebrew
OpenLDAP 2.6 `core`, `cosine`, `inetorgperson`, `nis`, and `openldap` schema
LDIF files, starting `ldap-go` from that database, and reading Root DSE and
`cn=Subschema` with OpenLDAP `ldapsearch`.

ACL behavior was aligned against `OPENLDAP_REL_ENG_2_6` revision
`04a19039e8d13dc06316e2d90994d6ff2812eb3d`, primarily
`servers/slapd/acl.c`, `servers/slapd/aclparse.c`, the MDB operation
implementations, and `slapd.access(5)`.
