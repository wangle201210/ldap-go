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
| Modify | planned | atomic modification and error-order differential tests |
| Add | planned | parent/schema/ACL/operational-attribute tests |
| Delete | planned | leaf/subtree/referral behavior tests |
| ModifyDN | planned | rename/move/subtree and RDN-value tests |
| Compare | planned | matching-rule and ACL disclosure tests |
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
| Core syntaxes and matching rules | planned | RFC 4517 schema-aware corpus |
| Standard operational attributes | planned | create/modify/rename differential tests |
| Subschema subentry | planned | discovery and schema publication tests |
| Runtime schema through `cn=config` | planned | add/modify/delete and restart tests |
| Collective attributes and subentries | planned | RFC 3671/3672 tests |
| DIT content/name/structure rules | planned | schema enforcement differential tests |

## Authentication, authorization, and security

| Area | Status | Required evidence |
| --- | --- | --- |
| OpenLDAP password schemes | partial | hash/verify vectors and migration tests |
| Password policy overlay | planned | lockout, expiry, grace, history, controls |
| OpenLDAP ACL grammar and evaluation | planned | ordered rule differential suite |
| Security strength factors | planned | transport/SASL/ACL integration tests |
| TLS and mutual TLS | planned | LDAPS, StartTLS, reload, CRL, client cert |
| National cryptography transport | planned | selected GM/T profile and client matrix |
| Audit and security logging | planned | redaction, integrity, and operation coverage |

## Storage, configuration, and migration

| Area | Status | Required evidence |
| --- | --- | --- |
| Transactional durable backend | partial | crash, atomicity, recovery, race tests |
| Multiple suffixes and subordinate DBs | planned | naming-context routing tests |
| `cn=config` online configuration | planned | OpenLDAP LDIF import and online changes |
| `slapcat` content LDIF import/export | partial | lossless fixtures and large-dataset tests |
| `slapcat` `cn=config` import | planned | boot from imported configuration |
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
| `slapadd` / `slapcat` equivalents | planned | OpenLDAP LDIF round trips |
| `slapindex` / `slaptest` / `slapdn` | planned | output and exit-code differential tests |
| LDAP client tools | planned | option and protocol interoperability |
| Load balancer tooling | planned | `lloadd` configuration tests |

## Implemented subset evidence

The first runnable subset includes bounded BER framing; LDAPv3 anonymous/simple
Bind; Root DSE; base, one-level, and subtree Search; boolean, equality,
presence, substring, ordering, approximate, and basic extensible filters;
Unbind; a transactional bbolt backend; and atomic content LDIF import.

Current password verification covers cleartext, `{CLEARTEXT}`, `{SHA}`,
`{SSHA}`, `{MD5}`, and `{SMD5}`. Until ordered OpenLDAP ACL evaluation is
implemented, non-root search responses always suppress `userPassword`.

Evidence currently consists of package tests, TCP interoperability tests using
`github.com/go-ldap/ldap/v3`, and manual process-level searches using OpenLDAP
2.6.13 `ldapsearch`. Rows remain `partial` because schema-aware matching,
aliases/referrals, controls, ACLs, SASL, writes, and full differential fixtures
are still pending.
