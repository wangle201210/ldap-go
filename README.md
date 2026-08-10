# ldap-go

`ldap-go` is a Go implementation of an LDAPv3 directory server targeting
behavioral and data compatibility with OpenLDAP 2.6.x.

The project is under active development and is not a complete OpenLDAP drop-in
replacement. Compatibility is tracked explicitly in
[docs/compatibility.md](docs/compatibility.md); an item is not supported until
its conformance and differential tests pass.

## Compatibility target

- LDAPv3 wire protocol and data model defined by the RFC 4510 family.
- OpenLDAP 2.6.x `slapd` behavior, controls, extended operations, schema,
  access control, overlays, replication, and operational attributes.
- Import/export compatibility for the documented canonical `slapcat` LDIF
  subset, including tested UUID/CSN metadata and `cn=config` records.
- Interoperability with OpenLDAP command-line clients and common LDAP SDKs.
- TLS, StartTLS, SASL, and an extensible transport layer for national
  cryptography support.

Binary OpenLDAP database files are implementation-specific and are not the
portable migration contract. `slapcat` LDIF is the authoritative data exchange
format supplied by OpenLDAP itself. That format-level migration path does not
imply runtime support for every OpenLDAP backend, overlay, schema extension, or
configuration value.

## Development

```sh
go test ./...
make compat
make full
```

`make full` builds the pinned OpenLDAP 2.6.13 release commit locally with the
`ldap`, `meta`, `null`, `relay`, `sock`, and `mdb` backends, the required overlays,
dynamic-module support, and the reference `lloadd` binary. The suite compiles
OpenLDAP's contrib `pw-sha2`, `pw-pbkdf2`, `pw-apr1`, `pw-netscape`, and
`pw-totp` modules against that build. It rejects reference-test skips, runs the
Go race detector, and executes
the parser fuzz suite. The tagged source is cached outside the repository and an explicit
checkout is never reset or switched. See [docs/testing.md](docs/testing.md) for
the `libltdl` dependency, dependency-prefix, and build-cache options.

## Current runnable milestone

The current server milestone supports atomic content-LDIF import/export,
validated offline bbolt backup/restore/check/rebuild commands,
anonymous and simple Bind, Root DSE discovery, base/one/subtree Search, common
LDAP filters, binary attributes, size/time limits, Add, Modify, leaf Delete,
subtree ModifyDN, Compare, Unbind, StartTLS, and RFC 3062 Password Modify. It
also supports RFC 4528 Assertion, RFC 4527 pre-read/post-read, and RFC 2696
simple paged-results controls on their applicable operations. OpenLDAP's
hidden No-Op control atomically validates and rolls back Add, Modify, Delete,
and ModifyDN, while permissiveModify ignores duplicate additions and missing
deletions. Both controls pass direct MDB differentials. RFC 4511
Abandon and RFC 3909 Cancel can interrupt active Search operations on the same
LDAP connection. RFC 3296 named referrals and ManageDsaIT support base
referrals, subordinate SearchResultReference responses, LDAP URL DN/scope
rewriting, and managed referral updates. RFC 4511/4512 aliases support all four
`derefAliases` modes, recursive base and search-scope dereferencing, loop and
broken-target handling, and OpenLDAP's database-level `olcMaxDerefDepth`.
An imported OpenLDAP `chain` overlay chases named and continuation referrals
for Search, Compare, Add, Modify, Delete, ModifyDN, Password Modify, and Dynamic
Refresh. Child `olcDatabase=ldap` entries provide URI-specific StartTLS,
LDAPS/TLCP, timeout, identity-assertion, pass-through, schema/filter, session
tracking, and nested-referral policies. The experimental Chaining Behavior
control is advertised and enforces referral-preferred/required and
chaining-required outcomes, including OpenLDAP's `cannotChain` result.
An imported naming-context `olcDatabase=ldap` proxies Bind, Search, Compare,
writes, Password Modify, Dynamic Refresh, and Who Am I? to ordered remote
URIs, with Simple identity reuse, root identity assertion, proxy authorization,
transport failover, health-preferred endpoint recovery, Abandon, and Cancel.
Transactions and directly attached local overlays are rejected rather than
silently bypassed. An imported
`olcDatabase=meta` routes and unions multiple LDAP targets, including target
selection/defaults, suffix massage, attribute and object-class maps,
wildcard/drop maps, subtree/filter rules, failover, quarantine, DN-route cache,
connection reuse and expiry, health-preferred URI recovery, bind polling,
controls, Abandon, Cancel, and the OpenLDAP default five-hop referral limit.
PLAIN, CRAM-MD5, DIGEST-MD5, and SCRAM Bind can read proxy-backed auxiliary
credentials and authorization rules through `acl-bind`/IDAssert, including
group and local LDAP-URL rules; native outbound SASL assertion carries the
mapped authorization ID.

An imported `olcDatabase=sock` delegates Bind, Search, Compare, Add, Modify,
ModifyDN, Delete, Password Modify, and Unbind to a Unix-domain socket using
OpenLDAP's line-oriented back-sock protocol. Each operation gets a fresh
socket, optional `binddn`/`peername`/`ssf`/`connid` fields come from the
frontend connection, Search entries pass local read ACLs, and Abandon/Cancel
close a blocked external request. Before delegation, the frontend applies the
same tested Add/Modify schema checks, matching-rule assertion validation for
Compare, ModifyDN validation, manage-only Relax updates, shadow-aware Don't Use
Copy handling, and empty-Modify behavior as OpenLDAP 2.6.13. The
implementation passes pinned operation and frontend-validation differentials.
Socket overlay mode, transactions, and overlay response callbacks remain
outside this milestone.

The separate `ldap-go lloadd` command implements the verified core of
OpenLDAP's LDAP-aware load balancer. It forwards bounded BER frames while
remapping message IDs, maintains regular and Bind connection pools, supports
round-robin, weighted, and best-of backend selection, preserves ordered-tier
busy/unavailable behavior and pending limits, performs guarded Simple Bind and
ProxyAuthz flows, applies operation restrictions and write affinity, rewrites
explicit and disconnect/re-Bind Abandon targets, and implements RFC 3909 Cancel
by pinning it to the target's physical upstream while rewriting both message
IDs. Cancel remains accounted while bypassing a full target connection's
ordinary pending limit. The proxy also supports both OpenLDAP LDAPI URL forms
and recovers backend connections. Its standalone configuration
parser and runtime pass pinned-source and live OpenLDAP 2.6.13 differential
tests. Unsafe unsupported paths fail explicitly: service Bind requires
ProxyAuthz, while client StartTLS and SASL EXTERNAL are rejected.
Client-facing LDAPS/StartTLS/PROXY v2, config-driven upstream TLS, full SASL
identity/security-layer handling, embedded `cn=config`/monitor mode, dynamic
topology, and the historical daemon surface are not yet implemented; see the
compatibility matrix for the exact boundary.

```sh
go run ./cmd/ldap-go lloadd -f ./lloadd.conf -test-config
go run ./cmd/ldap-go lloadd -f ./lloadd.conf
```

Pinned OpenLDAP 2.6.13 differentials additionally cover
`olcDbProtocolVersion` 2/3 and the verified subset of privileged
`olcDbConnectionPoolMax` behavior: cross-frontend reuse and concurrent LDAP
message-ID multiplexing. Online lifecycle behavior is pinned to the same
release: a zero-target meta database can accept its first target; changing an
existing target URI succeeds in `cn=config` but leaves that in-process target
unavailable until restart; deleting the sole `olcMetaTargetConfig` or
`olcMetaSub` entry returns 53; and adding the same target DN again returns 68.
Adding a second target while OpenLDAP has an active target connection is not a
stable oracle because the pinned upstream server triggers an assertion in that
scenario. This remains a partial back-meta implementation: GSSAPI and SASL
security-layer proxy Bind, complete referral rebind behavior, full librewrite,
complete multi-target connection categories and dynamic topology,
frontend-overlay wrapping, and transaction forwarding remain.
The database-local `pbind` overlay forwards non-anonymous Simple Bind requests
to the ordered endpoints in `olcDbURI`, failing over after transport errors.
It loads `olcDbStartTLS` and its TLS parameters, `olcDbNetworkTimeout`, and the
`olcDbQuarantine` schedule; the request controls and remote result code,
matched DN, diagnostic, referrals, and response controls are preserved. A
local provider/front-end topology and an optional OpenLDAP `back_ldap`
differential pass. Connections are still created per attempt, and the parsed
quarantine schedule drives a shared endpoint-health state machine that permits
one probe at each configured retry interval. Connection pooling is not yet
implemented.
The `remoteauth` overlay delegates only local entries that have configured
remote-DN/domain attributes and no `userPassword`. Ordered domain mappings,
default domain/realm fallback, `DOMAIN\user` and `DOMAIN:user` truncation,
file-backed multi-provider realms, retries, TLS policy, and SHA/SM3 peer-key
pins are supported. Existing local passwords take precedence. With
`olcRemoteAuthStore`, a successful remote credential is hashed with the first
effective `olcPasswordHash` scheme, including `{PBKDF2-SM3}`, and stored
locally. Matching OpenLDAP, any hash-generation failure, including selecting a
verify-only scheme such as `{NS-MTA-MD5}`, makes this explicit store-on-success
path fall back to cleartext;
do not combine that setting with verify-only hashes when cleartext persistence
is unacceptable. Local two-server tests pass. A gated OpenLDAP 2.6 differential covers
delegation, local-password
priority, writeback, bad credentials, and provider loss. Live StartTLS tests
cover SHA-256/SM3 public-key pins, mismatches, and missing host pins; connection
pooling and a broader platform TLS failure matrix are not claimed.
The `homedir` overlay applies POSIX account lifecycle changes only after the
LDAP storage transaction commits. It can provision a home from `olcSkeletonPath`,
rename and selectively chown it when `homeDirectory`, `uidNumber`, or
`gidNumber` changes, and apply IGNORE, DELETE, or ARCHIVE removal policy.
Configured regular-expression replacements must stay below an absolute trusted
root; parent traversal, parent symlinks, root deletion, skeleton recursion, and
archives inside the source home are rejected. Filesystem failure is logged
without rolling back the committed LDAP operation, matching OpenLDAP's overlay
callback contract. The implementation targets POSIX filesystems and does not
claim FIFO skeleton copying, byte-identical tar output, or Windows ownership
semantics. A gated OpenLDAP 2.6 filesystem differential passes for DELETE and
ARCHIVE lifecycles; recursive ownership comparison additionally requires root.
RFC 3672 subentries include the built-in schema, base/one/subtree visibility,
the Subentries control, paging, and OpenLDAP-compatible write and Bind rules.
RFC 3671 collective attributes include the standard `c-*` schema, strict
subtree-specification scopes, in-memory value propagation and merging,
collective exclusions, source references, and logical-entry behavior across
Search, Compare, assertions, read controls, paging, sorting/VLV, and ACL
evaluation.
OpenLDAP's separate `collect` overlay loads ordered `olcCollectInfo` rules on
one database and one frontend instance. Matching ancestor values are
equality-normalized and appended, without de-duplication, only while final
Search entries are encoded. Filters, Compare, and server-side Sort therefore
see stored values, while requested attributes, `typesOnly`, paging, VLV, and
ManageDsaIT are applied to the projected response. Template and target
entry/attribute/value ACLs, overlapping rules, online changes, rollback, and
restart are covered by a pinned OpenLDAP 2.6.13 differential. Descendant
Modify returns `unwillingToPerform`; ldap-go additionally checks every
modification and strips attribute options for this protection, closing two
bypasses present in OpenLDAP 2.6.13. Add, ModifyDN, and Delete remain backend
operations and are not intercepted by `collect`.
OpenLDAP `olcDitContentRules` schema is loaded from `cn=config`, published
through `cn=Subschema`, and enforced on Add and Modify. Auxiliary-class
allowlists plus `MUST`, `MAY`, `NOT`, and obsolete-rule behavior match slapd
diagnostics. Online updates, restart, and direct import of a real
`slapcat -n 0` schema entry pass.
The schema registry also implements RFC 4512 Name Forms and DIT Structure
Rules, publishes them through `cn=Subschema`, enforces RDN and superior-rule
relationships on Add, Modify, and ModifyDN, and maintains the protected
`governingStructureRule` attribute. OpenLDAP 2.6 exposes these only as hidden
subschema metadata and client-side parsers, not writable `cn=config` schema, so
ldap-go accepts such additive definitions through its base schema registry and
does not invent incompatible OpenLDAP configuration attributes.
OpenLDAP's `constraint` overlay loads ordered `olcConstraintAttribute` values
from `cn=config` and enforces `regex`, `negregex`, `size`, `count`, local LDAP
URI, and ACL set rules on Add, Modify, and ModifyDN. Optional `restrict=` URLs,
requester-authorized URI searches, normalized set paths, Relax bypass, atomic
online updates, restart persistence, and a direct slapd differential pass.
OpenLDAP's `dynlist` overlay loads ordered `olcDynListAttrSet` values and the
legacy aliases emitted for `dyngroup`. It projects arbitrary and mapped list
attributes, DN members, reverse memberOf values, and nested dynamic/static
groups without persisting generated data. Local LDAP URL schemes, URI
restrictions, request-sensitive expansion, `dgIdentity`/`dgAuthz`, ACLs,
ManageDsaIT, paging quirks, Compare result codes, online changes, restart, and
real `slapcat -n 0` configuration import pass OpenLDAP 2.6.13 differentials.
OpenLDAP's `unique` overlay accepts `olcUniqueURI` domains and legacy unique
configuration, including multiple URIs plus `strict`, `ignore`, and
`serialize`. It enforces schema-aware uniqueness on Add, Modify, and ModifyDN,
requires `manage` access for Relax bypass, validates online changes atomically,
survives restart, and imports real `slapcat -n 0` configuration LDIF. The
storage transaction makes concurrent uniqueness checks atomic.
OpenLDAP's `valsort` overlay loads ordered `olcValSortAttr` rules for
ascending/descending alpha and numeric order plus weighted primary and
secondary order. Add and Modify enforce weight syntax, Search sorts only the
returned values while preserving stored values, the hidden raw-value control
is accepted without being advertised, and Sync responses bypass value sorting.
Paging, server-side Sort, VLV continuation, online changes, restart, real
`slapcat -n 0` import, and a same-sequence OpenLDAP 2.6.13 differential pass.
OpenLDAP's `retcode` overlay supports ordered static result items and stored
`errObject`/`errAuxObject` entries for Add, Bind, Compare, Delete, Modify,
ModifyDN, Search, Password Modify, and Dynamic Refresh. Operation masks,
result metadata, referrals, delays, unsolicited responses, disconnects,
ManageDsaIT behavior, ACL-filtered synthetic searches, online changes,
restart, real `slapcat -n 0` import, and static/in-directory slapd
differentials pass. It remains partial where OpenLDAP itself produces an
invalid in-directory Extended response and for untested default-referral,
glue, and cross-overlay ordering combinations.
OpenLDAP's database-local `memberof` and `refint` overlays load their current
`cn=config` attributes, including multiple instances. Group Add/Modify/Delete,
individual group and member ModifyDN, dangling-reference modes, AddCheck,
member-side referential integrity, exact and subtree refint repair, and
`olcRefintNothing` run in the same storage transaction as the initiating
write. Online changes, rollback, restart, real `slapcat -n 0` import, and
same-sequence OpenLDAP 2.6.13 differentials pass. The built-in Name And
Optional UID syntax, `uniqueMemberMatch`, standard group schema, and
`groupOfUniqueNames` memberof behavior also pass a direct differential.
UID-bearing `uniqueMember` values are stored and matched but, like OpenLDAP's
memberof overlay, do not create reverse links. Global instances,
cross-overlay ordering, and replicated overlay topologies remain pending.
RFC 5805 transactions queue Add, Modify, Delete, ModifyDN, and Password Modify
operations on one LDAP connection. A missing new password is generated once,
returned in the immediate Password Modify response, and fixed into the queued
request. Commit replays the queue in one memory or bbolt write transaction; any
failed operation rolls back the full queue and identifies its original message
ID. Per-transaction operation and encoded-byte limits are bounded by default and
configurable. Exceeding either limit aborts the queue with the RFC 5805
server-initiated notice; Bind and Unbind abort without notice as required by the
RFC. OpenLDAP `ldapmodify -E txn=commit/abort` plus direct slapd rollback and
Bind differentials pass. A separate wire differential records that OpenLDAP
2.6.13 rejects transactional Password Modify, while ldap-go implements the RFC
5805/RFC 3062 composition described above.
RFC 6171 Don't Use Copy is available on Search and Compare. Authoritative
databases answer normally; a single-provider shadow Search returns its
OpenLDAP-rewritten `olcUpdateRef` or `unwillingToPerform`, while shadow Compare
returns `unwillingToPerform` without consulting copied entry data. OpenLDAP
`ldapsearch -E '!dontUseCopy'` and raw slapd differential cases pass. Imported
global `olcDisallows` policies enforce `bind_anon`, `bind_simple`,
`tls_2_anon`, `tls_authc`, and `dontusecopy_non_critical`; the related
`olcAllows` LDAPv2, anonymous-DN, and anonymous-credential Bind exceptions
follow OpenLDAP's precedence. Online changes, invalid-value rollback, restart,
and slapd differential cases pass.
RFC 2589 dynamic directory services are enabled by an imported
`olcOverlay=dds`. Dynamic Add generates `entryTtl` and the OpenLDAP
`entryExpireTimestamp`, Refresh enforces configured min/max TTL and `manage`
ACLs, searches project remaining TTL, and a lifecycle worker removes expired
leaf-first hierarchies with syncprov delete publication. Root DSE publishes
`dynamicSubtrees`; matching OpenLDAP, the hidden Refresh extended operation is
not listed in `supportedExtension`. DDS state, limits, online configuration,
restart persistence, slapd differentials, and OpenLDAP `ldapexop refresh`
interoperability pass.
OpenLDAP's `ppolicy` overlay is loaded from `cn=config` and supports default or
per-entry policies across Bind, Add, Modify, and Password Modify. It enforces
validity windows, lockout and exponential delay, expiry warnings and grace
logins, reset-only sessions, password age/length/history rules, safe modify,
cleartext hashing, and `olcLastBind`/`pwdMaxIdle`. The Behera password-policy,
SunDS account-usability, and optional Netscape controls match OpenLDAP 2.6.13
in differential tests. Policy configuration and all operational state survive
`slapcat` LDIF round trips. On shadow databases, chain-backed
`olcPPolicyForwardUpdates` sends policy state changes to the provider without
mutating the consumer copy. Native C `check_password()` modules remain pending;
configured native checker paths fail closed.
OpenLDAP's contrib `pw-sha2` module is data-compatible for `{SHA256}`,
`{SSHA256}`, `{SHA384}`, `{SSHA384}`, `{SHA512}`, and `{SSHA512}`. Salted
hashes use the module's eight-byte salt, and Password Modify,
`olcPasswordHash`, Simple Bind, imported values, and `slappasswd -h` share the
same implementation. A pinned 2.6.13 dynamic-module differential verifies
both directions: ldap-go hashes bind on OpenLDAP, and OpenLDAP-generated
hashes bind after import into ldap-go.
OpenLDAP's contrib `pw-pbkdf2` module is data-compatible for `{PBKDF2}` and
`{PBKDF2-SHA1}` using HMAC-SHA-1, plus `{PBKDF2-SHA256}` and
`{PBKDF2-SHA512}`. Generation matches the module's 10,000 iterations,
16-byte salt, adapted Base64, and 20/32/64-byte derived keys. Password Modify,
`olcPasswordHash`, Simple Bind, and import pass a pinned bidirectional
dynamic-module differential; `slappasswd -h` has CLI compatibility tests over
all four names. Verification rejects iterations above 1,000,000 and malformed
trailing fields before running PBKDF2, and uses a constant-time derived-key
comparison; these are intentional hardening differences from the contrib
module's unbounded `atoi` and `memcmp` path.
OpenLDAP's contrib `pw-apr1` module is data-compatible for `{APR1}` and
`{BSDMD5}`. ldap-go emits the module's standard-Base64 representation of the
16-byte PHK-MD5 digest followed by its eight-byte salt; this is intentionally
not the textual Apache `$apr1$...` or BSD `$1$...` form. Password Modify,
`olcPasswordHash`, Simple Bind, import, and `slappasswd -h` share the same
implementation and pass a pinned bidirectional module differential. Imported
values may retain noncanonical salts up to 64 bytes, and digest comparison is
constant time. Credentials above 4 KiB fail closed before the 1,000-round loop
to prevent unauthenticated CPU amplification; stored encodings above 4 KiB
also fail closed before Base64 scanning. Both schemes use MD5 and only 1,000
rounds, so they are provided for migration compatibility and should not be
selected for new passwords.
OpenLDAP's contrib `pw-netscape` `{NS-MTA-MD5}` format is supported for
one-way migration and Simple Bind. Its exact 64-byte payload, lowercase digest,
binary salt behavior, and embedded-NUL credentials pass a pinned dynamic-module
import/Bind differential. The upstream module registers no hash function, so ldap-go also
accepts it in imported `olcPasswordHash` configuration but returns `other(80)`
from Password Modify, matching OpenLDAP. `slappasswd -h` reports that the scheme
has no hash function; imported values remain readable without pretending the
format can be generated.
OpenLDAP's contrib `pw-totp` module is implemented separately from the built-in
OATH `otp` overlay. A database or frontend `olcOverlay=totp` activates
`{TOTP1}`, `{TOTP256}`, `{TOTP512}`, and their `ANDPW` variants for Simple
Bind. Pure TOTP credentials are six digits; `ANDPW` credentials concatenate
the static password and the final six-digit code. Every successful Simple Bind
on that database updates the non-replicated `authTimestamp`, and the update is
part of the authentication transaction so one token cannot be redeemed twice
concurrently. The schemes fail closed when the overlay is absent or disabled.
Password Modify and `slappasswd -h` accept a raw seed for pure TOTP schemes and
`seed|static-password` for `ANDPW`, matching the contrib module's Base32 plus
`{SSHA}` storage format. Imported `ANDPW` values can nest any password scheme
implemented by ldap-go, including the contrib SHA-2 schemes; dynamically
registered third-party nested schemes are not yet executable. Pinned OpenLDAP
2.6.13 module differentials cover all six
schemes, root and ordinary passwords, database/frontend and duplicate overlay
placement, current/previous windows, replay, malformed credentials, and
Relax-managed `authTimestamp` updates. On an entry with no prior timestamp,
ldap-go intentionally serializes concurrent redemption to one successful Bind;
OpenLDAP's separate check and update can admit multiple first-use attempts.
RFC 4533 LDAP Sync provider support is enabled by an imported
`olcOverlay=syncprov`. It supports `refreshOnly`, `refreshAndPersist`,
OpenLDAP-compatible multi-SID cookies, present UUID sets, committed
add/modify/modDN/delete notifications, durable delete progress across restart,
dynamic suffix `contextCSN` Search/Compare/read-control semantics,
`olcSpCheckpoint`, bounded `olcSpSessionlog` delete replay with exact `delcsn`,
`olcSpNoPresent`, `olcSpReloadHint`, Abandon/Cancel, server-side Sort/VLV
composition, and OpenLDAP-style syncprov coverage of glued subordinate
databases. OpenLDAP 2.6.13 `ldapsearch` interoperability also passes.
OpenLDAP `olcServerID` drives local CSN SIDs, and writable
`olcMultiProvider`/`olcMirrorMode` databases relay remote changes with
whole-entry/delete CSN conflict protection and durable UUID tombstones. A
three-node topology passes bidirectional writes, concurrent convergence,
middle-node restart catch-up, offline writes, and delete-versus-stale-modify
convergence; bidirectional OpenLDAP 2.6 multi-provider interoperability also
passes.
An OpenLDAP 2.6.13 syncrepl consumer also converges through initial,
refresh-and-persist, and stopped-consumer restart scenarios. The ldap-go
syncrepl consumer now loads ordered `olcSyncrepl` values, runs refresh-only or
refresh-and-persist workers under the server lifecycle, commits RFC 4533 entry
changes and cookies atomically, applies Present/Delete UUID sets, and resumes
from its durable cookie after restart. A ldap-go provider-to-consumer topology
covers initial, persistent, and offline catch-up paths, and the same reverse
topology passes against an OpenLDAP 2.6.13 provider. Broader provider variants
remain pending milestones. The consumer also supports OpenLDAP accesslog
delta-syncrepl, including atomic `reqMod` replay, initial full-refresh
fallback, durable restart, and automatic full recovery when the retained log
cannot be replayed safely. The local accesslog provider supports successful
Add/Delete/Modify/ModDN and Password Modify records, old-value selection,
branch-scoped operation logging, Search/Compare, Bind/Unbind/Abandon,
database-targeted Extended operations, successful and failed results, periodic
purge with `minCSN`, and a tested provider-to-consumer delta topology.
The DSEE retro changelog consumer mode, `syncdata=changelog`, reads
`firstChangeNumber`/`lastChangeNumber` from the provider Root DSE, performs an
ordinary full snapshot on initial synchronization or after an unsafe gap,
replays LDIF Add/Modify/ModDN/Delete changes, and atomically persists the
per-RID `lastChangeNumber`. Refresh-and-persist uses the Netscape Persistent
Search control. An automatically run protocol-level fake DSEE topology covers
snapshot, replay, restart/resume, and persistent streaming; interoperability
with a real Oracle DSEE installation has not been verified.
OpenLDAP's flat-file `auditlog` overlay loads `olcAuditlogFile` on a database
or the global frontend and appends OpenLDAP-shaped LDIF for successful Add,
Modify, Password Modify, ModDN, and Delete operations. It preserves proxied
authorization and real connection identities, reopens the file for external
rotation, ignores file failures at the LDAP result boundary, and matches
OpenLDAP's non-transactional audit record behavior when a later RFC 5805
operation rolls back the database transaction. Arbitrary accesslog
unknown-operation routing remains pending.
Consumer databases enforce OpenLDAP
shadow/update-referral rules, support online worker replacement, fractional
and filtered result sets, refresh-only polling, and suffix massage for entry
DNs and DN-valued attribute values. Consumer transports support OpenLDAP
StartTLS/LDAPS certificate policies, CA and CRL loading, socket keepalive,
Linux TCP user timeouts, and implicit `ldap+tlcp://` replication with mutual
SM2 authentication. For refresh-and-persist, `timeout=` bounds the initial
refresh without imposing a lifetime on the persistent stream. Legal RFC 4533
Sync Info variants are normalized by ASN.1 tag before `go-ldap` decoding.
Syncrepl authentication supports simple bind,
SASL EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5, GSSAPI, and
SCRAM-SHA-1/256/512; a real OpenLDAP SCRAM-SHA-256 provider topology is
exercised when its Cyrus SASL plugin is available. The DIGEST-MD5 consumer
selects from multiple offered realms, validates an explicitly configured
realm, sends `authzid`, derives `digest-uri` from the provider host, and
strictly verifies the server `rspauth`; it still negotiates only `qop=auth`.
Server-side SASL supports EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5, and
SCRAM-SHA-1/256/512. PLAIN verifies the mapped LDAP entry's existing
`userPassword` values. CRAM-MD5 performs the Cyrus-compatible server-first
challenge exchange with an ACL-visible cleartext password. DIGEST-MD5
supports the `qop=auth` exchange, mutual `rspauth`, and imported
`cmusaslsecretDIGEST-MD5` values. SCRAM runs a connection-bound multi-round
exchange and reads either cleartext `userPassword` or Cyrus-compatible
`authPassword` verifiers imported from OpenLDAP. OpenLDAP 2.6.13
`ldapwhoami` PLAIN, CRAM-MD5, DIGEST-MD5, and SCRAM-SHA-256 interoperability
cases pass. Imported `olcSaslHost`, `olcSaslRealm`, `olcSaslSecProps`, and
ordered `olcAuthzRegexp` values are loaded from `cn=config`; direct DN
replacements and local LDAP URL mappings with exactly one ACL-visible result
are supported. RFC 4370 proxied authorization is advertised for Search,
Compare, Add, Modify, Delete, ModifyDN, Password Modify, Who Am I?, and
Dynamic Refresh. It implements `olcAuthzPolicy` values `none`, `from`, `to`,
`any`/`both`, and `all`; hidden ordered `authzTo`/`authzFrom` attributes; DN,
user, group, wildcard, and local LDAP URL rules; database-root and anonymous
targets; and OpenLDAP's `proxy_authz_anon` and
`proxy_authz_non_critical` switches.
Ordered `olcAccess` evaluation includes filter/value/object-class targets;
effective and real DN selectors; static and dynamic groups; set expressions;
DN and attribute regular-expression capture expansion; peer, domain,
`sockname`, listener URL, IPv4/IPv6 network, and path selectors; and overall,
transport, TLS, and SASL SSF predicates. `OpenLDAPaci` and custom attributes
with the same syntax are evaluated through `dynacl/aci`. Direct OpenLDAP
differentials cover target selectors, expansion/groups, connection/level
selectors, and ACI behavior, while the overall ACL row remains partial for
unlisted grammar and dynacl modules.
RFC 2891 server-side sorting is available on databases
configured with OpenLDAP's `sssvlv` overlay, including paged-search interaction
and virtual list views with offset, proportional, assertion-value, and opaque
context requests. It loads OpenLDAP schema, ordered ACLs, database roots,
hidden/disabled databases, and selected operation settings from `cn=config`;
supported online changes are validated transactionally and published as one
runtime snapshot. Database entry partitions allow different OpenLDAP backends
to hold the same DN without crossing authorization or search boundaries, while
`olcSubordinate` databases participate in OpenLDAP-style glue searches. The
OpenLDAP `null` backend loads `olcDbBindAllowed` and `olcDbDoSearch`, supports
root and arbitrary Bind behavior, its synthetic suffix Search entry, discarded
writes, Compare, Assertion, paging, typesOnly, read controls, and backend-
specific No-Op responses. A `back-null`-enabled OpenLDAP build passes the same
operation sequence. Relay databases can expose an existing local database
under another suffix, with explicit or suffix-massage-selected targets. The
implemented `rwm` subset maps suffixes, attribute descriptions, object classes,
DN-valued attributes, and LDAP URL DNs in both directions; Bind, Search,
Compare, writes, transactions, ACLs, and inherited sorting pass an OpenLDAP
differential. Wildcard allowlists and response-side drop mappings are also
supported. General rewrite contexts and rules, remaining map flags, relay
chains, and broader proxy/overlay combinations remain. The compatibility
matrix marks these as partial until the remaining schema, ACL, control,
configuration, and differential cases pass.

An imported `olcDatabase=monitor` publishes `monitorContext` and exposes the
standard OpenLDAP `cn=Monitor` subtree hierarchy. Connection, operation,
statistics, time, listener, database, overlay, TLS, SASL, thread, and waiter
entries are generated from runtime state. Search, Compare, ACLs, paging,
limits, matched-DN behavior, monitor Log changes, database read-only changes,
and operation restrictions are covered by an OpenLDAP 2.6.13 differential.
On SIGINT or SIGTERM, the daemon stops accepting connections, completes
already accepted ordinary operations, abandons persistent Sync searches, and
only force-cancels remaining work after `-shutdown-timeout`. The database and
audit sink close after the connection drain completes.

The built-in LDAP client commands accept generic `-e`/`-E` controls with
critical, absent, empty, string, Base64, and file-backed values on applicable
operations. `-C` enables anonymous referral chasing with DN/scope rewriting,
control preservation, loop detection, and the OpenLDAP default five-hop limit.
SASL client authentication and the complete historical ldap-tools option set
remain outside this subset.

```sh
go run ./cmd/ldap-go import \
  -db ./data/ldap-go.db \
  -ldif ./examples/base.ldif \
  -replace

go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -transaction-max-operations 1000 \
  -transaction-max-queued-bytes 16777216 \
  -shutdown-timeout 30s

ldapsearch -x -H ldap://127.0.0.1:1389 \
  -b dc=example,dc=com '(objectClass=*)'

ldapsearch -x -H ldap://127.0.0.1:1389 \
  -E '!sync=ro' -b dc=example,dc=com '(objectClass=*)'

go run ./cmd/ldap-go export \
  -db ./data/ldap-go.db \
  -ldif ./data/export.ldif

# Stop the server before direct bbolt maintenance.
go run ./cmd/ldap-go check -db ./data/ldap-go.db
go run ./cmd/ldap-go backup \
  -db ./data/ldap-go.db \
  -out ./data/ldap-go.backup.db
go run ./cmd/ldap-go restore \
  -backup ./data/ldap-go.backup.db \
  -db ./data/restored.db
go run ./cmd/ldap-go rebuild -db ./data/restored.db
```

To enable credential-redacted security auditing, create a private HMAC key and
configure an append-only JSON Lines file:

```sh
umask 077
openssl rand -hex 32 > ./data/audit.key

go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -audit-log ./data/audit.jsonl \
  -audit-key-file ./data/audit.key

go run ./cmd/ldap-go audit-verify \
  -audit-log ./data/audit.jsonl \
  -audit-key-file ./data/audit.key
```

Every record includes operation identity, target DN, result code, transport
security state, and duration. Bind passwords, SASL credentials, filter and
Compare assertions, attribute values, and Password Modify values are never
submitted to the audit sink. Records are sequenced and linked with
HMAC-SHA-256; startup verifies the existing chain before appending. The key
file must not grant group or other access. `LDAP_GO_AUDIT_KEY` may supply the
key instead of `-audit-key-file`.

Supplying a PEM certificate and key enables StartTLS:

```sh
go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1389 \
  -tls-cert ./server.crt \
  -tls-key ./server.key

ldapsearch -x -ZZ -H ldap://127.0.0.1:1389 \
  -b dc=example,dc=com '(objectClass=*)'
```

Add `-ldaps` to negotiate TLS immediately and advertise an `ldaps://` endpoint
instead. TLS 1.2 is the minimum accepted version. `-tls-client-ca` enables
verification of optional client certificates; `-tls-require-client-cert`
makes a verified certificate mandatory. For example, append:

```sh
-tls-client-ca ./client-ca.crt -tls-require-client-cert
```

GB/T 38636 TLCP uses separate SM2 signing and encryption certificates:

```sh
go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -listen 127.0.0.1:1636 \
  -tlcp-sign-cert ./server-sign.crt \
  -tlcp-sign-key ./server-sign.key \
  -tlcp-enc-cert ./server-enc.crt \
  -tlcp-enc-key ./server-enc.key \
  -tlcp-implicit
```

The TLCP endpoint is reported as `ldap+tlcp://`. Omitting `-tlcp-implicit`
enables a StartTLS-OID upgrade followed by a TLCP handshake for clients that
support that profile. TLCP and RFC 8998 TLS 1.3 cipher suites are distinct;
this milestone implements TLCP only. The corresponding optional client
authentication flags are `-tlcp-client-ca` and
`-tlcp-require-client-cert`.

An imported `olcSyncrepl` can use the same implicit TLCP scheme. `tls_cert` and
`tls_key` identify the client signing pair. ECDHE suites additionally require
the ldap-go extension fields `tlcp_enc_cert` and `tlcp_enc_key` for the client
encryption pair:

```text
olcSyncrepl: {0}rid=001 provider=ldap+tlcp://provider.example:1636 bindmethod=sasl saslmech=EXTERNAL searchbase="dc=example,dc=com" tls_reqcert=demand tls_reqsan=demand tls_cacert=/etc/ldap/tlcp-ca.crt tls_cert=/etc/ldap/client-sign.crt tls_key=/etc/ldap/client-sign.key tlcp_enc_cert=/etc/ldap/client-enc.crt tlcp_enc_key=/etc/ldap/client-enc.key tls_cipher_suite=ECDHE_SM4_GCM_SM3 type=refreshAndPersist
```

After a standard TLS or TLCP client certificate chain is verified, the
certificate Subject is normalized as an LDAP DN and the connection advertises
the SASL `EXTERNAL` mechanism. A client can then bind without an LDAP password:

```sh
LDAPTLS_CERT=./client.crt \
LDAPTLS_KEY=./client.key \
LDAPTLS_CACERT=./server-ca.crt \
  ldapwhoami -Y EXTERNAL -ZZ -H ldap://127.0.0.1:1389
```

An unverified certificate never produces an EXTERNAL identity. EXTERNAL
authorization identities use the same self, database-root,
`olcAuthzPolicy`, `authzTo`, and `authzFrom` checks as the other SASL
mechanisms. TLCP requires a client that implements GB/T 38636 rather than a
stock TLS-only OpenLDAP client.

SASL PLAIN follows OpenLDAP/Cyrus security properties. The default
`noplain,noanonymous` policy suppresses PLAIN on an unprotected TCP
connection, while TLS, TLCP, and local Unix sockets provide an external
security-strength factor. For an intentionally unprotected development
endpoint, `olcSaslSecProps: none` enables PLAIN. Authentication identity
mapping uses the first matching `olcAuthzRegexp`; LDAP URL replacement
searches run as the anonymous authentication identity and require `auth`
access to the search base, candidate entries, and filter attributes. PLAIN
authorization identities use self and database-root authorization plus
OpenLDAP `olcAuthzPolicy`, `authzTo`, and `authzFrom` rules.
SCRAM-SHA-1/256/512 use the same identity mapping and ACL rules.
They accept raw or `{CLEARTEXT}` `userPassword` values, or Cyrus SCRAM
verifiers in the OpenLDAP `authPassword` form
`SCRAM-SHA-*$iterations:salt$StoredKey:ServerKey`. One-way `userPassword`
hashes such as `{SSHA}` cannot be converted into SCRAM verifier keys; migrate
an existing `authPassword` value or reset the password to enable SCRAM.
CRAM-MD5 uses the same identity mapping, `auth` ACL check, and proxy
authorization policy, and forms its challenge with `olcSaslHost` (or the local
hostname). It requires a raw or `{CLEARTEXT}` `userPassword`;
one-way OpenLDAP or national-cryptography password hashes cannot supply the
original HMAC-MD5 key.
DIGEST-MD5 shares that mapping and ACL path, emits a Cyrus-compatible
nonce/realm challenge, verifies both historical Latin-1 and UTF-8 digest
forms, and returns the required `rspauth`. It accepts raw or `{CLEARTEXT}`
`userPassword`, or the legacy 16-byte `cmusaslsecretDIGEST-MD5` value.
`qop=auth-int` and `qop=auth-conf` remain unavailable until the connection
layer can apply negotiated SASL integrity and privacy framing.

For `olcSyncrepl` with `saslmech=GSSAPI`, an explicitly configured
`credentials` value is used as the Kerberos password. Without that field,
ldap-go checks `KRB5_CLIENT_KTNAME`, then `KRB5_KTNAME`, and finally
`KRB5CCNAME`; keytabs require `authcid`, while a credential cache supplies its
own principal. `FILE:` keytabs and caches are supported, and the Unix default
cache is `/tmp/krb5cc_<uid>`. KCM, KEYRING, DIR, and macOS API caches are not
read by the pure-Go Kerberos client. `KRB5_CONFIG` selects the Kerberos
configuration file. The current GSSAPI implementation negotiates no SASL
integrity or privacy layer, so TLS, TLCP, or another protected transport is
required when replication traffic itself must be encrypted.

For the supported multi-database LDIF migration flow, import `cn=config` first
and then select each database using the same numeric index accepted by
`slapcat`:

```sh
slapcat -n 0 -l config.ldif
slapcat -n 1 -l data-1.ldif

go run ./cmd/ldap-go import \
  -db ./data/ldap-go.db -ldif ./config.ldif -replace
go run ./cmd/ldap-go import \
  -db ./data/ldap-go.db -ldif ./data-1.ldif -database 1 -replace

go run ./cmd/ldap-go export \
  -db ./data/ldap-go.db -ldif ./data-1-export.ldif -database 1
```

OpenLDAP-style offline aliases are also available for migration and operator
scripts:

```sh
go run ./cmd/ldap-go slaptest -db ./data/ldap-go.db
go run ./cmd/ldap-go slapdn -db ./data/ldap-go.db 'uid=alice,dc=example,dc=com'
go run ./cmd/ldap-go slapadd -db ./data/ldap-go.db -l data-1.ldif -n 1 -S 1 -w
go run ./cmd/ldap-go slapcat -db ./data/ldap-go.db -l exported.ldif -n 1
go run ./cmd/ldap-go slapindex -db ./data/ldap-go.db
go run ./cmd/ldap-go slappasswd -h '{PBKDF2-SM3}'
```

These aliases preserve the implemented OpenLDAP option and exit-code surface;
they do not make bbolt files binary-compatible with OpenLDAP MDB files.
Native `ldap-go import` atomically validates value syntax and structural schema
using the built-in registry plus supported schema imported from `cn=config`.
The `slapadd` alias follows the tested OpenLDAP subset: structural checks are on
by default, `-o value-check=yes` enables full value-syntax checks, and `-s` or
`-o schema-check=no` disables schema checks while still requiring
`objectClass`. Even with the default `value-check=no`, AttributeDescription,
configured attribute options, `;binary` transfer requirements, and the tested
DN, Name And Optional UID, UUID, arbitrary-precision INTEGER, generalized-time,
authzMatch, CSN, OpenLDAP ACI, and UTF-8 equality normalizers are checked.
Imported `olcAttributeOptions` replace the default `lang-` option family and
support OpenLDAP-style exact, trailing-`-`, and `range=` prefix definitions,
including range selection on Search and range rejection on Modify. Imported
`olcLdapSyntaxes` preserve ordinary declarations and ordered `X-SUBST` chains;
a substitute inherits the known syntax's validator and binary-transfer flags.
Full value checking covers built-in and supported substituted syntaxes;
ordinary declarations without a validator and unknown module-provided
syntaxes fail closed.

Without `-n`, `-b`, or `-database`, `slapadd` and `slapcat` select the first
configured primary content database in `cn=config` order, skipping config,
frontend, monitor, and subordinate databases. An unsupported first database is
reported rather than silently skipped, and an installation with no selectable
content database fails instead of falling back to an unconfigured partition.
Selected-database imports allow
child-before-parent LDIF but reject final orphans and DNs outside configured
suffixes. When the selected database is a glue superior, `slapadd` routes DNs
under a more-specific `olcSubordinate` suffix into that subordinate partition;
an overlapping ordinary database is rejected. `slapcat` assembles the selected
superior and its directly attached subordinate partitions. For both tools,
`-g` disables glue and operates on only the selected physical partition;
default glue mode rejects a subordinate suffix entry duplicated in its superior.
Replacing a selected glued tree clears the superior and each directly attached
subordinate partition; `-g` limits replacement to the selected physical
partition.

Missing LastMod metadata is generated when `olcLastMod` is enabled, and `-S`
selects the generated CSN SID. A glue import uses the selected superior's
LastMod and root-DN policy before routing records to physical subordinate
partitions. With LastMod enabled, `-w` updates the per-SID
`contextCSN` vector on the first suffix root, or on a created/updated
`cn=ldapsync,<suffix>` subentry when `olcSyncUseSubentry` is true. A
`slapadd -n 0` import generates config-backend metadata under `cn=config`,
supports `-w`, and validates the configuration hierarchy, supported schema,
and the runnable server configuration before the same transaction commits, so
an invalid supported setting rolls back the whole import.

All ldap-go imports remain atomic and stop at the first error. This differs
from OpenLDAP's partial-write and `-c` behavior; `-c` and `-q` remain
unsupported, and `-u` uses a temporary database copy rather than reproducing
every upstream backend-callback detail. The import API itself also forces a
transaction rollback after successful dry-run validation, so direct callers
cannot accidentally commit staged entries. Offline tool behavior is
modeled for `config`, `mdb`, `ldif`, and `wt`, plus `null`
accept-then-discard; proxy and virtual backends reject unsupported tool
operations. This is semantic LDIF compatibility backed by bbolt, not direct
access to OpenLDAP backend files. Custom schema/matching-rule modules are not
executed. Import parsing,
pending-entry validation, and commit
currently occupy one write transaction and retain the pending content set, so
memory use and lock duration grow with a large LDIF. The current bbolt backend
also has no independent attribute indexes, so local Search scans the selected
partition; migration size, lock time, and Search latency must be qualified
before production use. These limits are part of why ldap-go is not yet a
complete OpenLDAP drop-in replacement.

Imported `olcRootDN` and `olcRootPW` values are loaded from `cn=config`
automatically and apply only to their database. To provide an explicit
bootstrap override without exposing its password in the process arguments:

```sh
LDAP_GO_ROOT_PASSWORD='change-me' \
  go run ./cmd/ldap-go serve \
  -db ./data/ldap-go.db \
  -root-dn cn=admin,dc=example,dc=com
```

AutoCA defaults to the OpenLDAP-compatible RSA profile. To issue SM2
certificates signed with SM3, add the explicitly ldap-go-specific profile to a
writable local database overlay:

```ldif
dn: olcOverlay={0}autoca,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcAutoCAConfig
olcOverlay: {0}autoca
olcAutoCAProfile: sm2-sm3
olcAutoCAKeybits: 256
olcAutoCAuserKeybits: 256
olcAutoCAserverKeybits: 256
```

As with OpenLDAP AutoCA, issuance is triggered only by requesting exactly
`userCertificate;binary` followed by `userPrivateKey;binary`. The generated
CA and leaf key pairs are stored in the directory as PKCS#8 material and remain
subject to normal read ACLs. An unmodified OpenLDAP server does not understand
`olcAutoCAProfile`.

Generate a salted national-cryptography password value for `userPassword` or
`olcRootPW` without passing the cleartext password as a command argument:

```sh
LDAP_GO_PASSWORD='change-me' \
  go run ./cmd/ldap-go passwd
```

The output uses `{PBKDF2-SM3}` with a random 16-byte salt and 100,000
iterations by default. `ldap-go` also verifies imported `{SM3}` and `{SSM3}`
values, but those fast digest schemes should only be retained for migration.
`{PBKDF2-SM3}` is an `ldap-go` extension modeled on OpenLDAP's contributed
PBKDF2 format; an upstream OpenLDAP server needs a matching module or patch to
authenticate against it. This is separate from the supported upstream
`{PBKDF2}`, `{PBKDF2-SHA1}`, `{PBKDF2-SHA256}`, and `{PBKDF2-SHA512}`
schemes, which use SHA-family HMACs rather than SM3.

RFC 3062 Password Modify follows OpenLDAP's `olcPasswordHash` setting. Its
default remains `{SSHA}` for OpenLDAP compatibility. To make server-side
password changes use national cryptography, set the frontend database entry:

```ldif
dn: olcDatabase={-1}frontend,cn=config
changetype: modify
replace: olcPasswordHash
olcPasswordHash: {PBKDF2-SM3}
```

The setting is validated and reloaded atomically. Users can then change their
own passwords with an RFC 3062 client without putting either password in
command arguments:

```sh
ldappasswd -x -H ldap://127.0.0.1:1389 \
  -D uid=alice,ou=people,dc=example,dc=com -W -A -S
```

See [docs/architecture.md](docs/architecture.md) for the implementation model
and [docs/testing.md](docs/testing.md) for compatibility gates.
