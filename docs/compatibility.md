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
| Bind: SASL | partial | EXTERNAL over verified TLS/TLCP passes; other mechanisms remain |
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
| Collective attributes | partial | RFC 3671 schema, propagation, merge/exclusions, filtering, Compare, controls, paging, sorting/VLV, and ACL tests pass; X.501 administrative-area boundaries and OpenLDAP differential remain |
| DIT content/name/structure rules | planned | schema enforcement differential tests |

## Authentication, authorization, and security

| Area | Status | Required evidence |
| --- | --- | --- |
| OpenLDAP and SM3 password schemes | partial | hash/verify vectors and migration tests |
| Password policy overlay | planned | lockout, expiry, grace, history, controls |
| OpenLDAP ACL grammar and evaluation | partial | ordered rule differential suite |
| Security strength factors | planned | transport/SASL/ACL integration tests |
| TLS and mutual TLS | partial | LDAPS/StartTLS/client cert pass; reload and CRL remain |
| National cryptography transport | partial | GB/T 38636 TLCP dual-server-cert and mutual-client-cert matrix |
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
| sssvlv | partial | RFC 2891 sorting, VLV, RFC 2696 interaction, and global/per-connection limits pass |
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
Network Add generates `entryUUID`, `entryCSN`, creator/modifier names, and
create/modify timestamps, `structuralObjectClass`, and `subschemaSubentry`.
Modify and ModifyDN update modification metadata.

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
