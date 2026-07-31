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
| Bind: SASL | partial | EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5 `qop=auth`, and multi-round SCRAM-SHA-1/256/512 pass; OpenLDAP 2.6.13 PLAIN, CRAM-MD5, DIGEST-MD5, and SCRAM-SHA-256 `ldapwhoami` pass; GSSAPI, security layers, and full proxy authorization remain |
| Search and SearchResultReference | partial | scope, named-referral, all alias deref modes, limits, attributes, typesOnly |
| Filters and matching | partial | RFC 4515 corpus and schema-aware differential tests |
| Modify | partial | atomic modification and error-order differential tests |
| Add | partial | parent/schema/ACL/operational-attribute tests |
| Delete | partial | leaf/subtree/referral behavior tests |
| ModifyDN | partial | rename/move/subtree and RDN-value tests |
| Compare | partial | matching-rule and ACL disclosure tests |
| Abandon and cancellation | partial | active Search, response suppression, same-connection, and state-barrier tests pass |
| Unbind and disconnect notices | partial | connection-state tests |
| Referrals, aliases, and ManageDsaIT | partial | RFC 3296 referrals, RFC 4511/4512 aliases, and OpenLDAP 2.6.13 differentials pass; referral chaining remains |
| LDAP URLs and attribute options | partial | referral DN/scope rewrite passes; full RFC 4516 and language options remain |

## Controls and extended operations

| Area | Status | Required evidence |
| --- | --- | --- |
| StartTLS | partial | RFC 4511/4513 state machine, TLS tests, and OpenLDAP differential |
| Password Modify | partial | RFC 3062 core passes; password policy integration remains |
| Who Am I? | partial | RFC 4532 simple-bind and StartTLS identity tests pass |
| Cancel | partial | RFC 3909 BER, result, ordering, isolation, and OpenLDAP 2.6.13 differential tests pass |
| Assertion | partial | RFC 4528 Add/Modify/Delete/ModifyDN/Search/Compare atomic tests pass |
| Pre-read and post-read | partial | RFC 4527 Add/Modify/Delete/ModifyDN transaction and ACL tests pass |
| Paged results | partial | RFC 2696 Go-client, cookie, ACL, limit, glue, and mutation tests pass |
| Server-side sorting | partial | RFC 2891/OpenLDAP 2.6.13 CLI, Go-client, matching, ACL, paging, and mutation tests pass |
| VLV | partial | OpenLDAP 2.6.13 CLI, Go-client, BER, offset, assertion, multi-context, ACL, limit, and error tests pass |
| ManageDsaIT | partial | RFC 3296 Search/write/Password Modify and OpenLDAP 2.6.13 referral differential tests pass |
| Subentries | partial | RFC 3672 schema/control, visibility, paging, write rules, and OpenLDAP 2.6.13 differential tests pass |
| Don't Use Copy | partial | RFC 6171 Search/Compare, shadow referrals, alias/referral ordering, OpenLDAP `ldapsearch`, and slapd differentials pass; chaining and `olcDisallows` remain |
| LDAP Sync | partial | RFC 4533 BER, refreshOnly, refreshAndPersist, present/session-log refresh, `delcsn`, dynamic contextCSN, cancellation, restart, Sort/VLV, glue, and OpenLDAP 2.6.13 ldapsearch pass |
| LDAP transactions (RFC 5805/OpenLDAP) | partial | strict BER, connection state, Add/Modify/Delete/ModifyDN/Password Modify, memory/bbolt rollback, OpenLDAP `ldapmodify`, and slapd differential tests pass; proxy authorization, generated passwords, server abort notices, and resource limits remain |
| Dynamic refresh | partial | RFC 2589 BER/TTL/ACL behavior, OpenLDAP `ldapexop`, and slapd differentials pass; broader overlay-order and replication topologies remain |

## Data model and schema

| Area | Status | Required evidence |
| --- | --- | --- |
| DN/RDN parsing and normalization | partial | RFC 4514 corpus and OpenLDAP normalization |
| Core syntaxes and matching rules | partial | RFC 4517 schema-aware corpus |
| Standard operational attributes | partial | create/modify/rename differential tests |
| Subschema subentry | partial | discovery and schema publication tests |
| Runtime schema through `cn=config` | partial | add/modify/delete and restart tests |
| Collective attributes | partial | RFC 3671 schema, propagation, merge/exclusions, filtering, Compare, controls, paging, sorting/VLV, and ACL tests pass; X.501 administrative-area boundaries and OpenLDAP differential remain |
| DIT content/name/structure rules | planned | schema enforcement differential tests |

## Authentication, authorization, and security

| Area | Status | Required evidence |
| --- | --- | --- |
| OpenLDAP and SM3 password schemes | partial | hash/verify vectors and migration tests |
| Password policy overlay | planned | lockout, expiry, grace, history, controls |
| OpenLDAP ACL grammar and evaluation | partial | ordered rule differential suite |
| SASL server authentication | partial | EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5 `qop=auth`, SCRAM-SHA-1/256/512, transport SSF policy, `olcSaslHost`, direct/LDAP-URL `olcAuthzRegexp`, Cyrus credential forms, and OpenLDAP CLI interoperability pass; GSSAPI, SCRAM-PLUS, DIGEST security layers, and `olcAuthzPolicy` remain |
| SASL client authentication | partial | syncrepl EXTERNAL/PLAIN/CRAM-MD5/DIGEST-MD5/SCRAM-SHA-1/256/512 pass; GSSAPI password/keytab/FILE-cache paths pass unit coverage; a real KDC topology, SCRAM-PLUS, and SASL security layers remain |
| Security strength factors | partial | TLS cipher, TLCP SM4, Unix-socket, minimum SSF, and PLAIN advertisement policy pass; SASL-layer and ACL SSF integration remain |
| TLS and mutual TLS | partial | LDAPS/StartTLS/client cert pass; syncrepl CA/SAN/CRL policies pass; live server certificate reload remains |
| National cryptography transport | partial | GB/T 38636 TLCP dual-server-cert, mutual-client-cert, and ECDHE syncrepl matrix |
| Audit and security logging | planned | redaction, integrity, and operation coverage |

## Storage, configuration, and migration

| Area | Status | Required evidence |
| --- | --- | --- |
| Transactional durable backend | partial | crash, atomicity, recovery, race tests |
| Multiple suffixes and subordinate DBs | partial | partition, hidden, glue routing, paging, and syncprov inheritance tests pass |
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
| DDS | partial | OpenLDAP config, add/modify/modDN constraints, live TTL, limits, expiry/restart, sync delete publication, disabled state, and slapd differential tests pass |
| dynlist and dynid | planned | expansion/update tests |
| homedir | planned | lifecycle hook tests |
| memberof and refint | planned | transactional referential-integrity tests |
| pbind and remoteauth | planned | remote authentication tests |
| pcache | planned | cache correctness and invalidation tests |
| ppolicy | planned | full password policy suite |
| retcode | planned | configured result behavior |
| rwm | planned | DN/attribute rewrite differential tests |
| sssvlv | partial | RFC 2891 sorting, VLV, RFC 2696 interaction, and global/per-connection limits pass |
| syncprov | partial | cn=config gating, refresh/persist stream, configured SIDs, multi-SID cookies, `delcsn`, contextCSN checkpointing, session-log policies, Sort/VLV, glue providers, and OpenLDAP CLI interoperability pass |
| translucent | planned | local/remote merge tests |
| unique | planned | concurrent uniqueness tests |
| valsort | planned | value sorting tests |
| autoca and OTP-related contrib modules | planned | module-specific compatibility tests |

## Replication and operations

| Area | Status | Required evidence |
| --- | --- | --- |
| Syncrepl consumer | partial | ordered olcSyncrepl loading plus ldap-go, OpenLDAP 2.6.13 standard, and accesslog delta initial/persist/restart/recovery topologies pass; tag-based Sync Info compatibility and initial-refresh timeout semantics pass; advanced modes remain |
| Syncprov provider | partial | OpenLDAP 2.6.13 ldapsearch, overlay-order Sort/VLV, and slapd consumer initial/persist/restart topology pass; broader topology suite remains |
| Delta-syncrepl | partial | OpenLDAP accesslog `reqMod` replay, durable cookies, refresh fallback, and gap recovery pass; DSEE changelog and provider-side accesslog remain |
| Multi-provider and mirror mode | partial | `olcServerID`, writable `olcMultiProvider`/`olcMirrorMode`, durable UUID tombstones, three-node relay/restart/offline conflict convergence, and OpenLDAP 2.6 bidirectional topology pass; delta attribute-level conflicts and broader failure matrices remain |
| Fractional and sparse replication | partial | attrs/exattrs, filter exit/reentry, mandatory UUID/CSN, and suffix-massage convergence pass; broader schema/topology cases remain |
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
StartTLS and implicit LDAPS use a shared pluggable secure-transport interface;
the standard TLS adapter requires TLS 1.2 or newer, publishes the StartTLS OID,
and resets an authenticated connection to anonymous after a successful upgrade.
The GB/T 38636 TLCP adapter requires separate SM2 signing/encryption
certificates and has an end-to-end LDAP Bind/Search test fixed to
`ECC_SM4_GCM_SM3`. It intentionally does not claim RFC 8998 TLS 1.3
compatibility.
Verified standard TLS and TLCP client certificate chains expose their
normalized Subject DN to SASL EXTERNAL. Root DSE publishes EXTERNAL only on a
connection with such an identity. Empty authorization identities bind as the
certificate DN; non-empty proxy authorization identities are currently
rejected. Tests cover EXTERNAL root authorization, Who Am I, simple-Bind state
replacement, and both implicit TLCP and StartTLS-to-TLCP paths.
SASL PLAIN authenticates mapped directory entries through the same
`userPassword` and `auth` ACL path as simple Bind. Root DSE publishes it only
when `olcSaslSecProps` permits it for the connection's TLS, TLCP, or Unix
external SSF, or when `noplain` is disabled. `olcSaslRealm` and ordered
`olcAuthzRegexp` rules support direct DN and local LDAP URL mappings; URL
searches require exactly one result and OpenLDAP-compatible `auth` access.
Self authorization and database-root proxy authorization pass, while
`olcAuthzPolicy`, `authzTo`, and `authzFrom` remain pending.
CRAM-MD5 follows Cyrus SASL's server-first exchange, 1024-byte input bound,
lowercase HMAC-MD5 response, self authorization, and `olcSaslHost` challenge
format. It shares the identity mapping and anonymous `auth` ACL path but
requires a raw or `{CLEARTEXT}` password; one-way hashes cannot provide its
HMAC key. Tests cover configured-host challenges, malformed initial data,
wrong and hashed passwords, ACL denial, and OpenLDAP `ldapwhoami`
interoperability.
DIGEST-MD5 implements the bounded RFC 2831 directive grammar, Cyrus
nonce/realm challenge, nonce-count and LDAP digest-URI validation, historical
Latin-1 fallback, constant-time response verification, and mutual `rspauth`.
Credential lookup accepts ACL-visible raw or `{CLEARTEXT}` passwords and the
legacy binary `cmusaslsecretDIGEST-MD5` attribute. The RFC digest vector,
malformed parser cases, all credential forms, ACL denial, independent
`go-ldap`, and OpenLDAP Cyrus clients pass. Only `qop=auth` is advertised;
`auth-int`, `auth-conf`, and fast reauthentication remain pending.
SCRAM-SHA-1/256/512 use a connection-scoped multi-round Bind state and reject
interleaved operations as OpenLDAP does. Credential lookup accepts ACL-visible
raw or `{CLEARTEXT}` `userPassword` values and Cyrus-compatible
`authPassword` StoredKey/ServerKey records. Imported one-way `userPassword`
hashes cannot supply SCRAM verifier keys. Tests cover absent initial responses,
server proofs, all three hashes, malformed credentials, ACL denial, and
OpenLDAP SCRAM-SHA-256 interoperability. SCRAM-PLUS and negotiated SASL
integrity/privacy layers remain pending.
Network Add generates `entryUUID`, `entryCSN`, creator/modifier names, and
create/modify timestamps, `structuralObjectClass`, and `subschemaSubentry`.
Modify and ModifyDN update modification metadata.

RFC 5805 transactions advertise the Start Transaction and End Transaction
extended operations plus the Transaction Specification control. The wire codec
accepts OpenLDAP's explicitly present zero-length transaction identifier and
strictly validates transaction end request and response values. A connection
queues Add, Modify, Delete, ModifyDN, and Password Modify with an explicit new
password without holding a database lock. End Transaction commit replays the
ordered queue through one storage writer, so later operations observe earlier
ones and any operation failure rolls back entries, metadata, runtime changes,
and Sync publication. The failure result and original update message ID are
returned in `txnEndRes`. Abort discards the queue, and Bind or connection close
aborts outstanding work. A transaction is restricted to one storage partition;
configuration writes and cross-database operations are rejected.

OpenLDAP 2.6.13 `ldapmodify -E txn=commit/abort` interoperates with ldap-go.
A raw BER differential against slapd also verifies duplicate-Add failure
ordering, failed message ID reporting, and full rollback. Like OpenLDAP 2.6.13,
the current transaction path rejects pre-read and post-read controls. Proxied
authorization on Start Transaction, generated Password Modify response values,
server-initiated Aborted Transaction Notice, and explicit queued-resource
limits remain pending.

RFC 6171 Don't Use Copy is advertised in Root DSE and accepted on Search and
Compare only. The control requires an absent value; duplicate or valued
controls return `protocolError`. Matching OpenLDAP's default behavior,
non-critical requests are also honored, while support for rejecting them
through `olcDisallows: dontusecopy_non_critical` remains pending.
Authoritative databases, including writable multi-provider databases, answer
normally. A single-provider shadow Search rejects before alias dereferencing,
filtering, Sync setup, or other copied-data processing and returns a
request-DN/scope-rewritten `olcUpdateRef`; without one it returns
`unwillingToPerform`. Shadow Compare returns `unwillingToPerform` with
`copy not used`, matching slapd MDB. Imported LDAP-form `olcUpdateRef` values
are validated with OpenLDAP's global-referral restriction: DN, attribute,
scope, and filter URL components are forbidden, while non-LDAP URIs remain
valid. OpenLDAP `ldapsearch -E '!dontUseCopy'` interoperability and raw BER
differentials cover criticality, invalid values, broken aliases, named
referrals, URL rewriting, and Compare. Server-side chaining remains pending.

RFC 2589 and OpenLDAP's DDS overlay are enabled per database by
`olcOverlay=dds`. The runtime loads `olcDDSstate`, maximum, minimum, and default
TTL, expiration interval and tolerance, and the dynamic-object count limit.
Dynamic Add rejects aliases and referrals, prevents static children below a
dynamic parent, generates `entryTtl` plus the hidden
`entryExpireTimestamp`, and enforces the count limit in the storage write
transaction. Modify cannot convert between static and dynamic entries, direct
client modification of lifetime attributes is rejected, and ModifyDN cannot
move a static entry below a dynamic new superior.

Refresh uses strict RFC 2589 BER, applies the configured min/max TTL, requires
`manage` access to `entryTtl`, updates LastMod/CSN metadata atomically, and
returns the effective client refresh period. Search projects remaining TTL
without rewriting the stored refresh value. A server-lifecycle worker honors
the configured interval and tolerance, deletes expired entries deepest-first,
defers non-leaf parents, resumes from persisted expiration timestamps after
restart, and publishes syncprov deletes. Canonical slapcat LDIF preserves
`dynamicObject`, `entryTtl`, and OpenLDAP's private
`entryExpireTimestamp`; the private attribute is accepted by schema but omitted
from Subschema publication.

Root DSE publishes enabled suffixes through `dynamicSubtrees`. OpenLDAP loads
Refresh with `SLAP_EXOP_HIDE`, so neither slapd nor ldap-go lists its OID in
`supportedExtension`; clients can issue the operation directly. With
`olcDDSstate: FALSE`, the object class remains accepted but no lifetime is
generated or managed. OpenLDAP 2.6.13 differential tests cover Add, Search,
Refresh, Modify, ModifyDN, limits, disabled state, and parent/child expiration;
the OpenLDAP `ldapexop refresh` client interoperates with ldap-go. Complex
ordering with other overlays and replicated DDS exclusion topologies remain
pending.

The schema registry parses OpenLDAP `{n}`-ordered `olcAttributeTypes` and
`olcObjectClasses`, applies object-class and syntax checks to writes, and uses
registered matching rules for Search and Compare. Root DSE discovery and the
read-only `cn=Subschema` entry publish built-in and imported definitions.
Attribute selection distinguishes user attributes (`*`) from operational
attributes (`+`).

RFC 3296 `ref` and `referral` schema definitions are built in, and
ManageDsaIT is advertised through Root DSE `supportedControl`. Without the
control, a base referral returns result code 10 with matched DN and rewritten
LDAP URLs; one-level and subtree searches emit application tag 19
SearchResultReference responses independently of the search filter. Requests
below a referral replace the local referral suffix with the URL DN, preserve
an explicit URL scope, and otherwise add OpenLDAP-compatible `base`, `one`, or
`sub` scope fields. URI labels are removed before transmission, while non-LDAP
URIs are preserved.

ManageDsaIT makes an exact referral entry visible to Search and manageable by
Modify, Delete, ModifyDN, Compare, and Password Modify. Add, Modify, Delete,
ModifyDN, Compare, base/subtree Search, missing descendants, one-level scope,
duplicate controls, and forbidden control values have TCP or unit coverage.
Adding a child below a referral still returns a referral because the referral
DSE is not a naming context for local descendants. Process-level differential
tests against OpenLDAP 2.6.13 cover result codes, matched DNs, URL DN/scope
rewrites, SearchResultReference behavior, and managed updates.

RFC 4512 `alias` and `aliasedObjectName` schema definitions are also built in.
Search implements `neverDerefAliases`, `derefInSearching`,
`derefFindingBaseObj`, and `derefAlways`, including recursive alias chains,
base DNs below an alias, target-DN SearchResultEntry names, and expansion of
one-level or subtree search scopes outside the original subtree. The base alias
is retained when only searching aliases are dereferenced, matching OpenLDAP.
Broken and circular aliases fail base resolution with alias result codes and
matched DNs but are ignored while expanding search scopes. The per-database
`olcMaxDerefDepth` setting is loaded from `cn=config` and defaults to 15.
Exact target scopes are coalesced while overlapping target subtrees remain
distinct, preserving OpenLDAP MDB's observable duplicate-entry behavior.
Paging, server-side sorting, VLV, Add-parent, ModifyDN-superior, ordinary
Modify/Compare/Delete, and Bind rejection have TCP coverage. Process-level
OpenLDAP 2.6.13 differentials cover all four modes, base descendants, broken
targets, loops, and overlapping scopes. One intentional edge-case difference
is recorded: after a positive `olcMaxDerefDepth` is exceeded, OpenLDAP 2.6.13
MDB can emit success with a matched DN and the diagnostic `maximum deref depth
exceeded` because a successful intermediate lookup overwrites result code 36.
`ldap-go` consistently returns `aliasDereferencingProblem` (36) for that
failure. Referral chasing and the `chain` overlay remain pending.

RFC 3672 `subentry`, `subtreeSpecification`, and `administrativeRole` schema
definitions are built in, and the Subentries control is advertised through
Root DSE. Without the control, one-level and subtree searches omit subentries
while base searches retain them. A TRUE value returns only subentries and a
FALSE value only normal entries for all ordinary database searches. Control
values use OpenLDAP-compatible strict three-octet BER validation; absent,
malformed, and duplicate values return `protocolError`.

Visibility is enforced before the user filter, referral handling, and read
ACLs, and therefore composes with alias routes, RFC 2696 paging, sorting, and
VLV candidate construction. Subentries cannot be used for Bind, and Add
rejects a subentry parent with `objectClassViolation`. Modify, Compare,
ModifyDN, and Delete of the subentry itself remain ordinary operations.
OpenLDAP 2.6.13 MDB also permits ModifyDN to move an existing normal entry
under a subentry even though direct Add at the same DN is rejected; `ldap-go`
preserves that observable edge behavior. The synthetic `cn=Subschema` entry
publishes `subentry` and `structuralObjectClass: subentry`, and, like OpenLDAP's
frontend special entry, remains base-searchable regardless of a FALSE
Subentries control. Process-level differentials cover base, one-level, and
subtree visibility, TRUE/FALSE values, special entries, malformed values,
Bind, and parent rules.

RFC 3671 support builds on a strict RFC 3672 GSER parser for subtree bases,
specific exclusions, minimum/maximum depth, and object-class refinements. The
13 standard `c-*` attribute types and the collective system schema are built
in. A collective-attribute subentry contributes values to normal entries in
its scope; values from multiple sources are merged and deduplicated using
schema equality rules. `collectiveExclusions`, including
`excludeAllCollectiveAttributes`, suppress values without hiding the generated
`collectiveAttributeSubentries` source references.

Derived values exist only on the logical entry assembled inside a read
transaction. They are evaluated before filters, Compare, Assertion, read
controls, paging, sorting, and ACL `dnattr` checks, and are never written back
to member entries. Members cannot add or modify collective values or generated
source references, while a source-subentry update becomes visible
immediately. TCP tests cover these paths as well as multi-source propagation
and optioned attributes. An imported malformed subtree specification remains
readable but cannot define a propagation scope.

OpenLDAP 2.6 keeps its collective schema behind a development build option and
does not provide mainline value propagation suitable for process
differentials. X.501 specific/inner administrative-area boundary nesting and
DIT content-rule interaction also remain pending. The feature therefore
remains `partial`.

RFC 4533 LDAP Sync is advertised only when the target runtime contains an
OpenLDAP `syncprov` overlay. Overlay loading follows the database parent in
`cn=config`, rejects duplicates, and requires `olcLastMod: TRUE`. The request,
state, done, and info values use strict BER codecs, including default Boolean
handling and exact 16-byte wire UUIDs. Sync searches reject
`derefInSearching` and `derefAlways`, paged-results combinations, duplicate or
malformed controls, and unsupported critical target contexts.

`refreshOnly` takes one storage snapshot. A new consumer receives entries with
Sync State `add`; a returning consumer receives changed entries plus chunked
`syncIdSet` present UUIDs, allowing it to infer deletions. Cookies use
OpenLDAP's `rid=...,csn=...` layout, add `delcsn=...` when a delete set needs
its exact change CSN, and preserve one context CSN per server ID.
`olcServerID` accepts OpenLDAP's decimal, `0x` hexadecimal, and
`<ID> <listener-URL>` forms. URI-qualified values select exactly one local
listener; multi-provider databases require a non-zero SID. The selected local
SID context is committed atomically with each successful
Add/Modify/Password Modify/Delete/ModifyDN and survives restart, including
delete-only progress. Legacy stores containing a single SID 000 metadata value
upgrade in place to a durable multi-SID context vector.

`olcSpCheckpoint` writes the current SID-sorted context vector to the first
database suffix after either its committed-operation threshold or elapsed
minute threshold. The counter and timestamp are transactional metadata, and
the internal suffix update does not create another CSN or Sync event.
`olcSpSessionlog` retains the configured number of committed non-Add changes
in a provider-local memory window while retaining each change's actual data
partition. A covered cookie receives entries first, followed by disappearing
UUIDs with `refreshDeletes=TRUE` and progressive cookies carrying each delete
batch's exact `delcsn`, including filter and scope exits. Adds are recovered
from the normal entry scan. An evicted, incomplete, or not-yet-published
window falls back to Present processing.

Without a configured session log, `olcSpNoPresent: TRUE` suppresses Present
processing and marks the refresh as delete-based, matching the upstream
setting's documented log-database-only contract. With
`olcSpReloadHint: TRUE`, a stale cookie that cannot be anchored by any retained
entry CSN receives `syncRefreshRequired` unless the request sets `reloadHint`;
with the hint, the cookie is discarded and a full refresh is returned.

For ordinary operations, the provider dynamically replaces any stored
`contextCSN` copy on the first database suffix with the current, SID-sorted
vector. Search exposes it when explicitly requested or selected by `+`;
Compare and RFC 4527 pre/post-read controls use the same live value. `*` does
not select it, and clients cannot add or modify it. RFC 4533 responses strip
`dSAOperation` attributes, including `contextCSN`, so provider-local state is
not synchronized as entry content. The built-in OpenLDAP CSN syntax validates
both `entryCSN` and `contextCSN`, including normalization of the OpenLDAP 2.3
no-fraction/two-digit-SID form.

For a glued tree, every data route resolves an effective provider within its
own glue hierarchy. A syncprov directly attached to a subordinate database
wins; otherwise the nearest syncprov ancestor, including the primary database,
owns the context, checkpoint, session log, and persistent subscription. This
matches OpenLDAP's common single-primary-provider and per-branch-provider
layouts. Independent naming contexts do not inherit a provider merely because
their suffix is textually below another database. Entry reads and scope checks
continue to use the actual data partition, so a primary provider can refresh
and stream the complete glued tree without merging backend storage.

`refreshAndPersist` subscribes before taking its refresh snapshot, then emits
full add/modify entries, empty delete entries, and new-cookie intermediate
responses for changes outside the filter. Filter-entry and filter-exit
transitions become add and delete respectively. Abandon and RFC 3909 Cancel
stop the operation; a changed search base or an overflowing bounded event
queue terminates it with `syncRefreshRequired` (4096). Collective values are
not synchronized onto member entries. TCP tests cover these paths, and an
installed OpenLDAP 2.6.13 `ldapsearch -E !sync=ro` is run as an optional
process-level interoperability test. A real OpenLDAP 2.6.13 syncrepl consumer
also converges from an empty MDB, applies persistent Add/Modify/Delete events,
and catches up through the same cookie after it is stopped, provider changes
accumulate, and the consumer restarts.

The ldap-go syncrepl consumer parses ordered `olcSyncrepl` values into an
immutable runtime configuration, including search, fractional attribute,
retry, bind, timeout, TLS, suffix-massage, and delta-related fields. Duplicate
RIDs, invalid local bases, malformed filters, and incomplete retry or delta
settings fail `cn=config` validation. Workers start and stop with `Serve`, and
online configuration replacement cancels the previous partition/RID worker
before starting its replacement. Online tests add a consumer to a running
database, reject and roll back an invalid replacement while the old worker
continues, stop it by deleting `olcSyncrepl`, and re-enable it to catch up.

Standard RFC 4533 consumption supports refresh-only and
refresh-and-persist, provider URI failover, simple bind, StartTLS/LDAPS, SASL
EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5, GSSAPI, and SCRAM-SHA-1/256/512,
Present/Delete UUID sets, DN suffix massage, and durable opaque cookies.
The consumer decodes Sync Info optional fields by ASN.1 tag through a bounded
connection adapter, accepting legal OpenLDAP encodings that omit the cookie or
default Boolean. For refresh-and-persist, `timeout=` is enforced through the
initial refresh-done response and does not terminate a healthy persistent
stream.
EXTERNAL and SCRAM carry `authzid`; SASL defaults and numeric `secprops` are
enforced without silently enabling plaintext authentication. Options that
require credential delegation, stronger mechanism classifications, channel
binding, or a SASL security layer fail explicitly. Entry upserts, UUID-based
renames/deletes, cookie updates, and derived context CSNs use storage
transactions. Present completion removes only local entries in the configured
scope and filter that were not reported by the provider. An in-process
provider/consumer topology verifies initial convergence, persistent
Add/Modify/Delete, consumer shutdown, offline provider changes, restart with
the same store, cookie catch-up, and stale-entry removal. Gated reverse process
topologies use real OpenLDAP 2.6.13 syncprov/MDB providers for both simple bind
and SCRAM-SHA-256, with the SCRAM case enabled when its Cyrus SASL plugin is
available.

GSSAPI uses the provider hostname as `ldap/<host>`. An explicitly present
`credentials` field supplies a password, including an intentionally empty
password. Without it, `KRB5_CLIENT_KTNAME`/`KRB5_KTNAME` select a keytab or
`KRB5CCNAME` selects a credential cache; the Unix default is
`/tmp/krb5cc_<uid>`. The pure-Go Kerberos implementation accepts bare or
`FILE:` paths (and `WRFILE:` keytabs), rejects unsupported KCM/API/KEYRING/DIR
cache types explicitly, and obtains Kerberos configuration from `KRB5_CONFIG`
or the platform file default. It currently selects the RFC 4752 no-security
layer, so `minssf` must already be met by TLS, TLCP, or ldapi.

Consumer TCP setup honors `network-timeout`, `keepalive`, and, on Linux,
`tcp-user-timeout`. A failed `starttls=critical` aborts the cycle;
`starttls=yes` continues on the same plaintext connection only when the LDAP
server rejects the extension; network, framing, and TLS handshake failures
still abort the cycle because connection state is no longer trustworthy.
LDAPS and StartTLS support client certificates, CA files/directories, OpenLDAP
`tls_reqcert` and `tls_reqsan` hostname policies, `peer`/`all` CRL checks,
protocol minima, common OpenSSL cipher names and operators, and Go-supported
curve selection. Go cannot configure TLS 1.3 cipher suites or reproduce the
complete OpenSSL cipher-expression grammar.

Implicit `ldap+tlcp://` providers run the same RFC 4533 consumer over GB/T 38636.
Both server signing and encryption certificates are chain-checked, including
hostname and CRL policy. Mutual authentication uses `tls_cert`/`tls_key` as the
client signing pair; the ldap-go extensions `tlcp_enc_cert`/`tlcp_enc_key`
supply the second client pair required by ECDHE SM4/SM3 suites. An end-to-end
topology verifies SASL EXTERNAL, initial refresh, and persistent modification
over mutual ECDHE TLCP.

OpenLDAP accesslog delta-syncrepl uses the configured `logbase` and
`logfilter` after an empty consumer completes a conventional refresh-only
search. Audit add, modify, modrdn, and delete records are parsed from ordered
`reqMod` values and applied with the corresponding cookie in one transaction.
Single-valued add/delete compatibility, DN-valued suffix massage, operation
CSN idempotency, and subtree rename are handled explicitly. A provider
`syncRefreshRequired` result or a local replay conflict clears only that
consumer RID's cookie; the next cycle performs a full standard refresh before
returning to the log stream. A gated OpenLDAP 2.6.13 accesslog fixture verifies
online replay, stopped-consumer catch-up, deliberate local-state loss,
automatic full recovery, and continued modrdn/delete persistence.

Single-provider consumer databases follow OpenLDAP shadow rules. External
updates return rewritten `olcUpdateRef` referrals, or
`shadow context; no update referral` when none is configured. Legacy
`olcUpdateDN` may write a shadow, while `olcMultiProvider` and its
`olcMirrorMode` alias make the database externally writable. Conflicting
shadow mechanisms and update referrals on non-shadow databases fail runtime
validation.

Fractional tests verify `attrs`/`exattrs`, mandatory entry UUID/CSN retrieval,
and persistence of excluded binary/password attributes across provider
modifications. Filter exit emits a delete and re-entry emits an add.
Refresh-only polling converges on its configured interval. Suffix massage maps
remote entry DNs and schema-recognized DN-valued attributes into the local
suffix; update referrals map a local target back to the provider suffix.

Sync composes with RFC 2891 sorting and VLV after candidates from all database
routes have been collected. Refresh-only entries always carry Sync State, and
SearchResultDone carries Sync Done plus Sort/VLV result controls.
Refresh-and-persist places Sort/VLV result controls on the refresh-done
intermediate response. A gated OpenLDAP 2.6.13 fixture records that slapd's
observable response changes with `syncprov`/`sssvlv` overlay order, including
lost or misplaced controls and an incomplete persistent combination.
`ldap-go` deliberately keeps one protocol-coherent response shape independent
of configuration order.

Standard syncrepl multi-provider nodes compare whole-entry and delete CSNs
before applying remote changes, preserve local entries not covered by a
refreshPresent cookie, and republish committed remote data and context-only
advances through syncprov. Equal-CSN delete batches remain distinct events,
and durable UUID tombstones reject a stale remote re-add after the original
entry has disappeared. A newer re-add clears the tombstone. An in-process SID
1/2/3 topology passes bidirectional relay, concurrent-write convergence,
middle-node outage/restart catch-up, writes made at both outer nodes while the
middle node is offline, and delete-versus-stale-modify convergence. A gated
OpenLDAP 2.6 topology passes bidirectional online writes between slapd SID 2
and ldap-go SID 1. `olcMirrorMode` is accepted as OpenLDAP's alias for
`olcMultiProvider`; active/passive writer selection remains the responsibility
of the external load balancer.

This provider does not yet implement an accesslog overlay,
`olcSpSessionlogSource`, the optional sync-provider subentry context, or a full
`slapd` topology differential. The consumer still lacks obsolete DSEE
changelog delta mode, the remaining SASL mechanisms and security layers, full
OpenSSL cipher-expression compatibility, delta-syncrepl's complete
attribute-level conflict history, and broader OpenLDAP provider variants. The
replication rows therefore remain `partial`.

Current password verification covers cleartext, `{CLEARTEXT}`, `{SHA}`,
`{SSHA}`, `{MD5}`, `{SMD5}`, `{SM3}`, `{SSM3}`, and `{PBKDF2-SM3}`. New
national-cryptography password values use `{PBKDF2-SM3}` with a random 16-byte
salt, a 32-byte derived key, and 100,000 iterations by default. The textual
layout follows OpenLDAP's contributed PBKDF2 scheme:
`{PBKDF2-SM3}<iterations>$<salt>$<derived-key>`, using unpadded adapted
base64. Verification rejects iteration counts above 10,000,000 to bound Bind
work from untrusted stored values. `{SM3}` and `{SSM3}` are accepted for
existing deployments but are not recommended for newly stored passwords.
These three SM3 scheme names are not built into upstream OpenLDAP; reverse
migration requires a corresponding OpenLDAP password module or patch.

`ldap-go passwd` generates `{PBKDF2-SM3}` values. It reads the cleartext from
`LDAP_GO_PASSWORD` or bounded standard input and never accepts it as a
positional command argument.

RFC 3062 Password Modify is advertised in Root DSE and supports the bound
identity or an explicit target DN, optional old-password verification,
client-supplied passwords, server-generated passwords, ACL enforcement, and
normal schema/operational-attribute updates in one storage transaction. The
frontend database's `olcPasswordHash` values select one or more output hashes;
the OpenLDAP default is `{SSHA}`, while `{PBKDF2-SM3}` enables the costed SM3
format. Legacy placement on `cn=config` is also accepted. Online changes are
validated as part of the runtime snapshot and unsupported schemes roll back.
Password policy controls, history, quality checks, expiry, and lockout remain
pending with the ppolicy overlay.

RFC 4528 Assertion is published through Root DSE `supportedControl`. The BER
filter is decoded strictly and evaluated inside the same storage transaction
as Add, Modify, Delete, and ModifyDN; failed assertions return result code 122
without side effects. Search evaluates the assertion against its base entry,
and Compare against its target entry. Tests cover duplicate/missing/empty
control values, malformed and trailing BER, noncritical handling, schema-aware
matching, and successful/failed atomic operations.

RFC 4527 pre-read and post-read are also published through Root DSE
`supportedControl`. Pre-read applies to Modify, Delete, and ModifyDN; post-read
applies to Add, Modify, and ModifyDN. Their AttributeSelection values are
decoded strictly, and response values contain the required SearchResultEntry
application payload. Snapshots are generated inside the write transaction,
use normal entry and attribute read ACLs, honor `*`, `+`, `1.1`, explicit
attributes, and the empty default selection, and are only returned after a
successful commit. Tests cover old/new values and DNs, operational attributes,
password-value filtering, malformed and duplicate controls, operation
applicability, and rollback after a critical post-read failure. OpenLDAP
differential fixtures remain pending.

RFC 4511 Abandon and RFC 3909 Cancel use a connection-local operation registry.
The connection reader can accept either request while the serial operation
worker is scanning or transmitting an active Search. Abandon cancels the
Search context, immediately suppresses further entries, and sends no
SearchResultDone. A successful Cancel waits for the target Search to return
`canceled` (118), then sends an ExtendedResponse success with no responseName
or responseValue. Message IDs cannot cross LDAP associations. Bind and
StartTLS remain read barriers, and complete BER PDUs share one write lock.

Request values use strict BER for `SEQUENCE { cancelID MessageID }`; absent,
empty, malformed, unknown, finalizing, pending, and non-cancelable targets map
to the RFC result codes. Deterministic TCP tests pause the storage scan and
cover response ordering, connection reuse, Root DSE discovery, and cross-
connection rejection. Process-level probes against OpenLDAP 2.6.13 match
result codes, diagnostics, and target-before-Cancel response ordering for
normal cases. Two strict RFC differences are intentional: `ldap-go` rejects
trailing bytes after cancelRequestValue and returns `cannotCancel` when a
Cancel targets its own message ID; OpenLDAP 2.6.13 accepts the trailing data
and returns success for self-cancel despite RFC 3909 declaring Cancel
non-cancelable.

Cancel and Abandon currently interrupt Search only. Running update operations
return `cannotCancel`, pending Search follows OpenLDAP's `cannotCancel`
behavior, and ordinary operations on one connection execute serially. Update
cancellation, discretionary update Abandon, and OpenLDAP-style parallel
operation execution remain before these rows can become `compatible`.

RFC 2696 simple paged results are published through Root DSE
`supportedControl`. Request and response values use strict BER decoding and an
opaque, connection-local cookie; only the latest cookie can continue a search,
and it is bound to the authenticated identity, request semantics, control
criticality, and current runtime configuration. Page size may change between
requests. Completion returns an empty cookie, while a size-zero continuation
abandons the sequence. Continuation uses a database-route and normalized-DN
cursor, preserves the total search size limit across pages, applies normal
filter and read ACL processing before page boundaries, and reports a zero size
estimate to avoid disclosing unreadable candidates. Tests cover malformed,
old, and reused cookies, Bind reset, changed requests, empty initial requests,
cross-database glue searches, mutation between pages, and
`github.com/go-ldap/ldap/v3` interoperability. OpenLDAP process-level
differential fixtures remain pending.

RFC 2891 server-side sorting is advertised only when an OpenLDAP `sssvlv`
overlay is loaded. Overlay settings are bound to their parent database, while
a frontend overlay applies globally; `olcSssVlvMaxKeys` is validated and
defaults to five. Request and response values use strict BER. The server sorts
the complete ACL-visible candidate set before size limits or RFC 2696 page
boundaries, supports multiple keys, reverse order, absent and multi-valued
attributes, and resolves default or explicitly named/OID ordering rules through
the active schema. Sorted paging preserves the initial ordered route/DN set,
excludes later additions, skips deletions, and re-evaluates current entry and
attribute ACLs on continuation.

OpenLDAP-compatible request failures return direct LDAP result codes 16, 18,
and 53 for unknown attributes, unavailable ordering rules, and excessive key
counts; duplicate alias keys remain accepted. Process-level differential tests
against OpenLDAP 2.6.13 using `ldapsearch -E sss -E pr` pass for multi-key,
reverse, absent-value, paging, and error cases. `olcSssVlvMaxKeys`,
`olcSssVlvMax`, and `olcSssVlvMaxPerConn` are loaded per overlay with defaults
of five, eight, and five. Eight matches half of OpenLDAP's default 16-worker
pool. Regular sorts hold a transient lease; sorted paging and VLV retain leases
for their cookie/context lifetime. A target and frontend overlay each account
for the same request, and saturation returns OpenLDAP's LDAP `busy` result 51
without sort, paging, or VLV response controls.

One known differential remains for sort plus paging plus a total size limit:
OpenLDAP's overlay can report `sizeLimitExceeded` on an earlier page, while
`ldap-go` reports it when the cumulative limit is reached; both return the same
globally sorted top-N entries. Same-connection request intake and Abandon now
work, but ordinary operations still execute serially instead of using
OpenLDAP's worker-level concurrency, so the `sssvlv` row remains partial.

Virtual list views from `draft-ietf-ldapext-ldapv3-vlv-09` use strict BER and
are advertised with the `sssvlv` overlay. They require an RFC 2891 sort control
and reject RFC 2696 paging on the same search. Offset, proportional offset,
greater-than-or-equal assertion, reverse ordering, absent values, empty result
sets, and OpenLDAP's historical target-position-zero behavior are covered.
OpenLDAP 2.6.13 uses VLV result values 76 and 77 for a missing sort control and
an out-of-range offset; `ldap-go` follows those deployed values.

Each successful initial request creates a random 16-byte, connection-local
context bound to the authenticated identity, search semantics, sort request,
and runtime configuration. Up to `olcSssVlvMaxPerConn` contexts can coexist.
Continuations retain the initially sorted route/DN set, exclude later
additions, skip deletions, re-read current values, reapply entry and attribute
ACLs, and enforce the search size limit for every window. Bind, StartTLS,
connection close, and runtime replacement invalidate all contexts and release
their leases. Process-level tests with OpenLDAP 2.6.13 `ldapsearch` pass
discovery, offset windows, response controls, and missing-sort errors. Unlike
OpenLDAP's pointer-derived context, an `ldap-go` context cannot be reused with
changed query semantics.

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
the frontend read-only restriction, plus database-local `olcMaxDerefDepth`,
while global `olcAllows: update_anon`
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
referral chaining, controls, the remaining ACL grammar and differential suite,
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
