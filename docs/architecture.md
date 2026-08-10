# Architecture

## Target

The compatibility baseline is OpenLDAP 2.6.x, with the fixed OpenLDAP 2.6.13
release commit as the reproducible differential oracle. LDAP standards define
protocol correctness; differential tests define behavior where the standards
permit multiple outcomes or OpenLDAP adds extensions.

Compatibility is behavioral and data-oriented. The Go implementation does not
copy OpenLDAP's C internals, backend ABI, or binary database layout.

## Layers

```text
TCP / Unix / TLS / StartTLS
              |
         LDAP BER codec
              |
   connection and operation engine
              |
   authn -> ACL -> overlays -> DSA
              |
 schema / DN / matching / controls
              |
 transactional backend interface
              |
 memory | durable local | proxy | monitor | config
```

### Wire

The wire package owns RFC 4511 BER decoding and encoding, message IDs,
protocol-operation types, controls, limits, and malformed-message handling. It
must not contain directory semantics.

### Operation engine

Each connection can have multiple outstanding message IDs. Abandon and Unbind
have no response. Bind and StartTLS enforce the RFC connection-state rules.
Cancellation, time limits, size limits, backpressure, and graceful shutdown are
handled here.

Before paging state is allocated, database-local exact bound-DN size rules are
combined with the server and client limits. The soft value supplies an omitted
client limit, the hard value clamps a larger request, and database-root searches
bypass subject-specific rules. This keeps ordinary, sorted, paged, VLV, and
overlay-expanded candidates under one cumulative Search limit.

One reader accepts and registers requests while one worker serializes ordinary
operations that share authentication, paging, VLV, and runtime state. Abandon
and RFC 3909 Cancel are handled by the reader so they can cancel the active
Search context without waiting behind it. Bind and StartTLS are read barriers,
and a connection-wide writer lock keeps every BER PDU intact when a Cancel
response races with Search output. The registry establishes an atomic
final-response boundary for `tooLate` and limits cancellation to the LDAP
association that created the target operation.

Shutdown closes the listener first and interrupts each connection's read side
so no new request is admitted. Queued and executing ordinary operations retain
their contexts and drain before storage is closed. Refresh-and-persist Sync
operations are marked long-lived and abandoned immediately. A configurable
deadline cancels any remaining operation and closes its transport; timeout is
returned distinctly so supervisors can detect a forced shutdown.

RFC 5805 transaction state is connection-local. Update requests carrying the
Transaction Specification control are cloned into an ordered queue, including
their original message IDs, without opening a storage transaction. End
Transaction settles the state exactly once. The queue has configurable,
non-zero operation-count and encoded-byte limits. Crossing a limit atomically
discards it and writes an Aborted Transaction Notice with message ID zero; Bind,
Unbind, and connection teardown discard it without that notice. Password Modify
generates an omitted new password once while cloning the request, returns it in
that operation's immediate RFC 3062 response, and commits the same value.

### LDAP load balancer

The standalone `internal/lloadd` runtime is separate from the directory
service agent and storage stack. It accepts bounded LDAP BER frames, parses
only the outer message envelope needed for routing, and preserves protocol-op
and control payloads while translating client and upstream message IDs. Search
entries, references, and intermediate responses retain an operation until its
final response; Abandon rewrites its embedded target ID and removes the mapped
operation without forwarding a response. Client disconnect and replacement
Bind paths synthesize the same mapped Abandon for outstanding non-Bind
operations. Attachment and completion share a small operation lock, and only
the goroutine that wins final completion may publish a terminal response.

Each configured backend maintains regular and Bind connection pools. Regular
connections can carry concurrent operations and may first perform a configured
Simple service Bind. Bind connections are reserved for client authentication,
and successful identity state is represented through critical ProxyAuthz on
later regular operations. A non-anonymous service Bind is rejected unless
ProxyAuthz is enabled, preventing anonymous clients from accidentally running
as the service identity. Auth-only client SASL remains on its exclusive bound
upstream and does not receive an empty ProxyAuthz control; EXTERNAL is rejected
until the listener can derive a trustworthy local TLS or Unix peer identity.
A concurrency-safe scheduler implements ordered tiers, round-robin, weighted,
and best-of selection, per-backend and per-connection limits, OpenLDAP's
decaying best-of latency fitness, and the distinction between a busy tier and
one with no available backend. Restrictions and write coherence increase
affinity from a backend to a specific upstream when needed.

RFC 3909 Cancel is registered as a separate operation on the same physical
upstream as its target. The outer Cancel message ID and inner `cancelID` are
both translated, the client association is revalidated before attachment, and
ProxyAuthz identity is retained. Its signaling lease may temporarily exceed a
full client/backend/connection limit so the operation that consumes the last
slot can still be canceled, but remains included in pending accounting. A
target admits at most one in-flight Cancel; Cancel itself cannot be abandoned.

The proxy owns listener-accepted clients and background backend maintainers;
upstream loss completes affected operations with OpenLDAP's `other` result and
the maintainer rebuilds the configured pool. Connection establishment and
service Bind reads are context-cancellable, and service Bind honors its
configured timeout. Client-facing StartTLS is rejected locally until its
stateful implementation exists. Client-facing TLS/PROXY v2,
service-account SASL, exact SASL post-Bind identity restoration and security
layers, embedded slapd-module configuration/monitoring, and dynamic topology
are outside the current runtime contract.

### Directory service agent

The DSA implements Bind, Search, Modify, Add, Delete, ModifyDN, Compare,
Abandon, Unbind, and Extended operations. It owns referrals, aliases,
operational attributes, result codes, and transaction boundaries.
Alias-aware Search resolves the effective base first, then represents
dereferenced targets as stable additional database routes so ordinary ACL,
filter, paging, sorting, and VLV processing remains shared.
Subentry visibility is applied to candidates before user filters, referrals,
and read ACLs. This keeps hidden administrative entries out of filter
evaluation and makes paging, sorting, VLV, and alias-expanded routes share the
same RFC 3672 behavior.
Collective attributes are another logical-entry projection. The DSA discovers
collective-attribute subentries once per partition and read transaction,
evaluates their subtree specifications, merges schema-normalized values, and
applies member exclusions before filters and authorization. Storage and write
validation continue to use the raw entry, so derived values and generated
source references are never persisted.

### Schema and matching

DN parsing, attribute descriptions, syntaxes, matching rules, object classes,
implemented schema rules, and schema validation are centralized. Stored values
retain their original representation while indexes use normalized values.
DIT content rules are loaded only after their attribute-type and object-class
dependencies. The registry indexes each rule by its structural class OID and
names, publishes canonical descriptions through the subschema subentry, and
applies only the rule for the entry's exact structural class. Runtime
replacement makes online schema changes atomic with the `cn=config` write.
RFC 4512 Name Forms and DIT Structure Rules are indexed separately by OID/name
and integer rule ID/name. Registration resolves structural-class and attribute
dependencies before accepting a form, then validates the complete superior-rule
graph before accepting a replacement. Write transactions select a governing
rule from the entry RDN and its direct parent, persist
`governingStructureRule`, and roll back Add, Modify, or ModifyDN when no active
rule applies. Because OpenLDAP 2.6 has no corresponding slapd runtime or
`cn=config` fields, these additional definitions enter through the base schema
registry rather than OpenLDAP configuration import.

### Backends

Backends expose atomic read/write transactions over entries. The target
candidate-selection and indexing architecture must support:

- base, one-level, and subtree candidate selection;
- equality, ordering, approximate, substring, and presence indexes;
- stable entry IDs and entry UUIDs;
- atomic Modify and ModifyDN, including subtree moves;
- snapshot reads and ordered change records for replication;
- offline backup, restore, consistency checking, and atomic database rebuild.

The current bbolt implementation provides DN-keyed transactional entry storage
but no independent attribute indexes; Search walks the selected partition and
applies scope and filter evaluation in the server. Index-backed candidate
selection is therefore a production scalability requirement, not a current
compatibility claim.

OpenLDAP-style databases map to isolated storage partitions selected by the
longest matching naming context. Imported database-entry UUIDs provide stable
partition identities across ordered configuration changes; legacy stores are
partitioned atomically at startup. Hidden databases retain their data partition
but do not participate in operation routing or Root DSE publication. Disabled
databases also retain their partition and leave operation routing, but remain
published in Root DSE to match slapd. Subordinate databases form glue
hierarchies under the nearest non-subordinate naming context. Base searches
stay in the most-specific partition, while one-level and subtree searches build
a deterministic multi-partition plan with one shared size/time budget.

An LDAP transaction may target one partition. Commit opens one backend write
transaction and reuses its writer while replaying every queued operation, so
authorization, assertions, schema checks, operational metadata, and later
operations see a single evolving view. A failed LDAP result aborts that
backend transaction. Runtime activation and Sync change publication are
collected during replay and released only after durable commit.
The flat-file auditlog response observer is intentionally outside that atomic
boundary. It appends after each operation succeeds during replay, so an
explicit abort writes nothing while a later replay failure can leave an audit
record for an operation whose database change was rolled back. This matches
OpenLDAP's observable auditlog behavior.

Naming-context `ldap` and `meta` databases share an outbound transport
executor but keep different routing models. Back-ldap selects an ordered remote
URI list for one naming context. Back-meta first selects one or more target
configurations, applies suffix, attribute, object-class, filter, and result
namespace rewrites, and unions Search results. Its implemented RWM subset
includes attribute/object-class wildcard allowlists and response-side drop
maps; it does not implement the complete librewrite language.

Back-meta pools privileged identity-assertion transports under
`olcDbConnectionPoolMax`. The verified subset shares an eligible transport
across frontend client connections and multiplexes concurrent requests by LDAP
message ID while serializing BER writes. Explicit user-credential transports
remain private, and temporary overflow follows the target's use-temporary
policy. Pool capacity and categories are intentionally described as a subset:
the implementation does not yet reproduce every OpenLDAP multi-target
connection category or rebind transition.

`olcDbProtocolVersion` accepts the OpenLDAP values 0, 2, and 3. Zero inherits
the frontend connection's current Bind version, while an explicit 2 or 3
rewrites outbound Bind requests accordingly. The LDAPv2 path suppresses
unsupported noncritical controls and rejects combinations, such as privileged
proxy authorization, that OpenLDAP does not forward in that mode. Protocol
selection is part of the transport reuse key so differently configured targets
cannot share an incompatible connection.

Online meta target activation follows the stable behavior observed from the
pinned 2.6.13 server. A zero-target parent database may receive its first
`olcMetaTargetConfig` or `olcMetaSub` entry. Replacing an existing target URI
updates `cn=config` successfully but makes that target unavailable in the
running process until restart. Deleting the sole target entry returns
`unwillingToPerform` (53), leaving it present, and a repeated Add of the same
DN returns `entryAlreadyExists` (68). Adding a second target while the
reference server has an active target connection triggers an upstream
OpenLDAP 2.6.13 assertion, so that path is excluded from the stable
differential oracle. Proxy auth-check searches use `acl-bind` with IDAssert
fallback for back-ldap and target IDAssert for back-meta; password-based SASL
mechanisms can therefore authenticate and authorize entries in either proxy
backend without mutating the frontend connection's in-progress Bind state.
Referral chasing uses OpenLDAP's default five-hop limit, while back-meta keeps
a healthy preferred URI and probes a recovered URI after the preferred one
fails. Complete dynamic topology, GSSAPI and SASL security layers, full rebind,
full librewrite, and multi-target pool-category behavior remain outside the
implemented compatibility boundary.

A `sock` naming-context database is a delegated backend with no local storage
partition. Its immutable runtime configuration contains a Unix socket path and
the enabled OpenLDAP connection-extension fields. Dispatch performs the same
frontend restriction and limited pseudo-entry ACL checks as back-sock, encodes
the operation into the line/LDIF protocol, and creates a fresh Unix connection.
The operation context owns that connection, so Abandon, Cancel, shutdown, or a
client disconnect interrupts blocked I/O by closing it. Unbind bypasses normal
target routing and is written to every configured socket backend.

Before encoding, the delegated database frontend validates the operation forms
that slapd handles outside `back-sock`: Add/Modify schema and value rules,
Compare matching-rule assertion validation and normalization, ModifyDN
destination syntax and database ownership, manage-only Relax updates,
shadow-aware Don't Use Copy results, and Password Modify authentication.
An empty Modify change sequence remains a valid delegated request because that
is the observed OpenLDAP 2.6.13 behavior.

The external service is an untrusted process boundary. Request encoding is
completed before dialing and rejects newline/NUL injection. Response parsing
has byte, line, entry, attribute, value, and entry-count limits and requires a
terminal RESULT. Search entries are parsed before LDAP emission, then pass
local entry and attribute/value read ACLs and requested-attribute projection.
This bounded fail-closed design intentionally does not reproduce OpenLDAP's
known early-EOF-as-success bug. RESULT diagnostics preserve the bytes following
the field colon as OpenLDAP does. Socket overlay callbacks are a separate
middleware architecture and are not implemented by the database runtime.

### Overlays

Overlays are typed middleware around operation dispatch and response emission.
They can inspect or transform requests, execute transactional side effects, add
response controls, and observe final outcomes. Ordering is explicit and
configuration-backed.

The database-local DDS runtime treats `entryTtl` as a projected operational
value and persists OpenLDAP's hidden `entryExpireTimestamp` as the durable
expiration authority. Add and Refresh update both values inside the same
storage transaction as LastMod and syncprov state. A context-bound scheduler
keeps one deadline per enabled database, is awakened by runtime replacement,
rechecks active configuration inside each write transaction, and publishes
committed expiration deletes only after storage success.

Dynlist is implemented as a request-scoped logical-entry projection. One
read-transaction cache loads each database partition, expands configured local
LDAP URLs under the effective identity, and keeps separate output and filter
projections so unmapped values remain visible but cannot affect filters.
Membership graphs add reverse and nested values only when the request needs
them. Compare uses the OpenLDAP DN-membership fast path where required, while
ManageDsaIT bypasses all generated values. The legacy dyngroup configuration
shares URL parsing and membership evaluation but remains Compare-only.

Nestgroup is also request-scoped, but maintains a separate graph for every
selected database partition and configured instance. Stored member references
form forward edges; groups inside configured bases form the reverse parent
index. Positive member/memberOf equality assertions are rewritten before
candidate filtering. Internal parent searches retain the requester's Search
ACL, while memberOf child traversal uses direct snapshot entry lookup to match
slapd. Odd-NOT equality assertions are not rewritten. When the corresponding
projected attribute was requested, the final expanded response entry is tested
against the complete rewritten filter a second time.

The Search order is collective logical values, dynlist, nestgroup filter/value
processing, candidate and final-entry ACL checks, sorting/paging/VLV, then late
collect response projection and attribute selection. ManageDsaIT skips every
nestgroup step, and Compare never enters this path. Sorted-page and VLV
continuations re-read the stored entry and reapply nestgroup response projection
from a new request-scoped cache. Each graph has fixed entry, edge, depth, and
expanded-value limits; no graph or mutable cache is shared between requests,
so concurrent searches only share the immutable runtime snapshot and storage
read transaction.

The OpenLDAP `collect` overlay uses a separate, late Search-response
projection. A request cache resolves each normalized template DN once, applies
template entry/attribute/value ACLs, normalizes source values with the schema
equality rule, and appends every configured contribution without de-duplication.
The filter, Compare, and Sort views stay unchanged; target ACL filtering,
attribute selection, paging/VLV response reconstruction, and valsort run on the
final response view. Database rules precede frontend rules. This path does not
reuse the RFC 3671 collective-attribute plan because those values are part of
the logical entry and are deliberately visible to filters and Compare.

The `translucent` runtime is database-local and owns one captive LDAP backend
parsed from the overlay's child `olcDatabase={0}ldap` entry. Remote entries are
the visibility anchor. A same-DN local entry replaces each matching attribute
as a whole and appends local-only attributes before the complete request filter,
ACL, and attribute-selection path runs. Configured local and remote attribute
sets recursively split candidate filters; local candidates are confirmed by a
remote base lookup, stale local entries stay hidden, and the merged entry is
rechecked against the original filter. Compare stays local when the asserted
attribute exists locally and otherwise uses the same back-ldap/chain network
executor for remote fallback.

Simple Bind tries the remote target first and `bindLocal` permits ordinary local
authentication only after remote failure. Add, Modify, Delete, and ModifyDN
write only partial local shadow entries; automatic parent glue is limited by
`noGlue`, while `strict` controls deletion of attributes that are visible only
remotely. Assertion controls on Add evaluate the proposed local entry, while
Modify assertions evaluate the complete remote/local merged view before a
shadow is created or changed. `pwmodLocal` stores Password Modify results in
the local shadow after confirming that the remote DN exists. ManageDsaIT
bypasses the overlay. These
core paths are pinned to OpenLDAP 2.6.13 source and differential fixtures;
advanced controls, OpenLDAP's non-root Modify-through-local-ACL edge,
frontend/multiple instances, and arbitrary cross-overlay ordering or side
effects remain outside the verified contract.

Pbind is a database-local Bind overlay rather than a general proxy backend. For
each non-anonymous Simple Bind it sends the original Bind request and controls
to the ordered `olcDbURI` endpoints. The common outbound transport layer
applies network deadlines, LDAPS or configured StartTLS, certificate/SAN/CRL
policy, and the supported cipher/curve/protocol settings. A completed LDAP
result is authoritative; only transport or framing failure advances to the
next endpoint. The response path preserves result metadata, referrals, and
controls, then installs the original local DN as the connection identity after
success. Local `userPassword` is not consulted by pbind. Each attempt currently
uses a fresh connection. `olcDbQuarantine` maintains shared health state across
connections: it blocks requests until the current interval expires, admits a
single retry probe, advances finite retry blocks, and resets after a responsive
target. There is no outbound connection pool yet.

Remoteauth is also database-local, but delegates selectively. Before ordinary
local password verification, it reads the target entry in the selected
partition and proceeds only when the entry has no `userPassword`, has a valid
remote DN in `olcRemoteAuthDNAttribute`, and has a domain from
`olcRemoteAuthDomainAttribute` or the configured default. Domain mapping and
default-realm selection produce either one LDAP URI or a line-oriented
`file://` provider list; providers are attempted in order across the configured
retry rounds. The same outbound TLS layer is used, with an additional
hostname-to-leaf-public-key pin check supporting SHA and SM3 digests. Invalid
credentials stop failover, while connection failures continue it.

Successful remoteauth can optionally materialize a local credential. The
server hashes the accepted cleartext with the first effective
`olcPasswordHash`, reopens the entry in a write transaction, and stores it only
if no concurrent writer has added `userPassword`. Normal LastMod and Sync
publication paths are reused. A failed writeback is logged and
does not turn successful remote authentication into a failed Bind. Subsequent
Binds use the local hash and bypass remoteauth. The outbound authentication
paths still lack pooled connections; remoteauth has no endpoint-health
scheduler, and broad platform TLS/pin fault topologies remain untested.

Homedir wraps committed Store updates and records entry images before and after
each transaction. Only after a successful commit does it pair ModifyDN
delete/add records by `entryUUID` and apply the effective database or frontend
overlay. This keeps aborted LDAP writes free of filesystem side effects while
preserving OpenLDAP's rule that a later filesystem failure is logged and does
not undo the LDAP write. Each configured replacement is reduced to a bounded
absolute root; `os.Root` operations plus parent-symlink checks constrain copy,
rename, chown, delete, and archive work to that boundary. Filesystem effects are
serialized for deterministic transitions. The design assumes POSIX UID/GID and
`Lchown` semantics and supports one homedir instance per database or frontend.

The auditlog runtime can be attached to a database and once to the frontend.
A successful write is rendered after LastMod and overlay mutations are known;
both applicable instances receive independent records using the selected
backend's first suffix. Each append opens and closes its configured file under
a server mutex, which preserves complete LDIF records across concurrent
connections and supports external rename-based rotation. File I/O errors are
reported to the logger after the directory write and never replace its LDAP
result.

### Configuration

The canonical runtime configuration is represented as LDAP entries under
`cn=config`. A bootstrap file may locate storage and listeners, but all
directory behavior must be readable and writable through the config DIT.

### Replication

When `olcLastMod` is enabled, committed writes receive OpenLDAP-compatible CSN
metadata. A Sync change carries both its actual data partition and its
effective provider partition. Direct subordinate syncprov overlays take
precedence; otherwise the nearest provider in the same glue hierarchy owns the
context, with the primary database commonly covering the whole glued tree.
Independent naming contexts cannot inherit through a different glue root. The
effective provider atomically advances durable `contextCSN` metadata and
publishes an after-commit before/after record to a bounded process-local
stream. RFC 4533 refresh uses a consistent directory snapshot plus present
UUIDs, so reconnects recover deletions without relying on process-local
history; refresh-and-persist subscribes to provider partitions before its
snapshot while reading entries from their data partitions.

The provider projects the current, SID-sorted context vector as a dynamic
`contextCSN` operational attribute on the first database suffix for ordinary
Search, Compare, and read controls. This replaces stale imported checkpoint
values in responses without rewriting them. Sync responses omit
`dSAOperation` attributes so provider-local state is not replicated as entry
content.

`olcSpCheckpoint` transactionally persists that context vector on the suffix
after its operation or elapsed-time threshold. `olcSpSessionlog` retains a
bounded, provider-local window of committed non-Add changes, including the
actual source partition needed for glue scope evaluation. A refresh uses the
window only when the consumer cookie covers its baseline and publication has
reached the storage snapshot; otherwise it falls back to the Present phase.
Delete ID sets carry the exact operation CSN in OpenLDAP's `delcsn` cookie
field, preventing an unrelated newer context CSN from changing conflict
ordering.
Runtime configuration activation preserves a complete existing window and
resets it when a publication gap is detected. Sorting and VLV operate on the
combined ACL-visible candidate set after all glue routes are read, then attach
their result controls to Sync Done or the refresh-done intermediate response.

Consumer workers are keyed by storage partition and replication ID. `Serve`
owns their context; runtime activation publishes a desired immutable
configuration, and the manager fully stops a changed worker before starting
its replacement. RFC 4533 entry changes and opaque cookies commit in one
storage transaction. In multi-provider mode, `olcServerID` selects the local
non-zero CSN SID, durable context metadata stores a vector across all observed
SIDs, and incoming whole entries or deletes are rejected when their CSN is
older than the current entry. Durable UUID tombstones retain deletion CSNs
after entry removal, reject stale re-adds, and are cleared by a newer re-add.
Applied remote changes and context-only cookie advances are republished after
commit, allowing a node to relay changes without creating a new local CSN.
Present completion scans only the configured local scope/filter, while suffix
massage rewrites entry and schema-recognized DN-valued attribute values.
Single-provider databases reject client updates or return their rewritten
update referrals; internal replication bypasses that LDAP-operation
precondition.

RFC 6171 interrogation requests distinguish those single-provider shadow
partitions from authoritative and writable multi-provider partitions. Don't
Use Copy is checked before alias dereferencing, Sync snapshot setup, filtering,
or entry reads. Shadow Search rewrites a configured update referral from the
requested base and scope, while shadow Compare fails without consulting the
copied assertion target. This ordering follows OpenLDAP MDB and prevents a
control intended to reject copied information from first consuming it.

Outbound consumer connections share one RFC 4533 engine across plain LDAP,
LDAPS, StartTLS, and implicit TLCP. TCP keepalive and Linux user-timeout policy
are applied before the secure handshake. TLS and TLCP peer verification share
OpenLDAP-style certificate/SAN requirements and CRL policy, while TLCP verifies
both server certificates and can present separate SM2 signing and encryption
client certificates for ECDHE.

The consumer can replay a remote OpenLDAP accesslog as delta-syncrepl. Each
audit operation and its cookie share a storage transaction; malformed or
non-replayable history clears the consumer cookie and forces a conventional
refresh before log streaming resumes. The local accesslog overlay writes audit
records and source changes in the same storage transaction, republishes those
records through the log database's sync provider, and maintains durable
`contextCSN`/`minCSN` boundaries across restart and purge. A consumer cookie
older than `minCSN` receives `syncRefreshRequired`, forcing a standard refresh
instead of silently skipping deleted history.

`syncdata=changelog` follows the DSEE retro changelog protocol instead of RFC
4533 or OpenLDAP accesslog. The consumer reads `firstChangeNumber` and
`lastChangeNumber` from the Root DSE and uses an ordinary suffix snapshot when
its per-RID position is absent, zero, outside the retained range, or reset by a
replay gap. Snapshot completion removes stale local entries and stores the
provider boundary as both private metadata and the operational
`lastChangeNumber`. A one-level changelog search then parses each `changes`
attribute with an LDIF parser and applies Add, Modify, ModDN, or Delete in the
same transaction as the new position. A discontinuous change number rolls back
and resets replay state for a later full refresh, while transport failures
preserve the last durable position. Refresh-and-persist adds the Netscape
Persistent Search control. This architecture is exercised by an in-process
protocol provider; it is not evidence of real Oracle DSEE interoperability.

### Security

Transport security is abstracted from LDAP semantics. Standard TLS and StartTLS
use the same `SecureTransport` server-handshake contract for explicit and
implicit upgrades. The TLCP provider implements GB/T 38636 with separate SM2
signing and encryption certificates and SM4/SM3 cipher suites without forking
the operation engine. RFC 8998 TLS 1.3 support is a separate provider because
it is not wire-compatible with TLCP. Password schemes are registered modules
and constant-time verification is mandatory. Imported OpenLDAP digest schemes
remain readable. The contrib SHA-2 schemes use Go's SHA-256/384/512 primitives,
strict Base64 decoding, exact unsalted digest lengths, and OpenLDAP's eight-byte
salt for newly generated salted values. New national-cryptography credentials
use salted, costed PBKDF2-SM3 rather than a fast bare SM3 digest. Stored
iteration counts are bounded during verification so a malicious directory
value cannot force unlimited work on a Bind handler. RFC 3062 Password Modify runs old-password
verification, ACL checks, password replacement, schema validation, and
operational-attribute updates in one storage transaction. Hash selection is
loaded from the frontend database's `olcPasswordHash` values in the same
immutable runtime snapshot as ACL and schema configuration.

Secure transports may expose an external identity only after validating the
peer certificate chain. The standard TLS and TLCP adapters both return the
certificate Subject as an LDAP DN through the same connection interface. SASL
EXTERNAL is advertised per connection, never globally, and a successful Bind
copies that DN into the ordinary authorization state used by ACL and root
checks.

The same connection abstraction reports an external security-strength factor:
the effective standard TLS cipher strength, 128 bits for TLCP's SM4 suites,
and OpenLDAP's 71-bit local-socket value. The immutable runtime snapshot loads
global `olcSaslHost`, `olcSaslRealm`, `olcSaslSecProps`, and ordered
`olcAuthzRegexp` configuration. Server-side PLAIN is advertised only when
those properties permit it, maps its authentication identity through direct
or local LDAP URL rules, and verifies the resulting entry through the existing
password and ACL path. CRAM-MD5 creates a Cyrus-compatible hostname challenge
and verifies it with an ACL-visible raw or `{CLEARTEXT}` password.
DIGEST-MD5 uses a bounded directive parser, the same anonymous `auth` ACL
lookup, either cleartext or a legacy precomputed secret, and returns the
mutual-authentication `rspauth`; it currently advertises only `qop=auth`.
SCRAM-SHA-1/256/512 use the same mapping and a connection-scoped conversation
that blocks interleaved operations until Bind succeeds or fails. They derive
ephemeral verifiers from ACL-visible cleartext passwords or parse Cyrus
`authPassword` salt, StoredKey, and ServerKey records without exposing those
values to the client. LDAP URL mappings perform an internal anonymous
auth-check search and require exactly one result, including `auth` access to
the search base, candidate entry, and filter attributes.

ACL evaluation receives both effective and real identities plus normalized
peer, local-socket, domain, listener-URL, and overall/transport/TLS/SASL SSF
connection context. Target DN and value regular expressions retain separate
capture sets for expansion into DN, group, set, and connection selectors.
Group and set traversal use the operation's storage reader, so membership and
attribute chasing observe the same transaction snapshot as the protected
operation. `OpenLDAPaci` is schema-typed and evaluated as a dynamic ACL source,
including inherited scopes and grant/deny masks. Unsupported ACL or dynacl
syntax is rejected while loading the immutable runtime rather than ignored.

RFC 4370 controls are resolved before operation dispatch and removed before
operation-specific control parsing. The connection's authenticated DN is
retained while a request-local effective DN drives ACL, root, operational
attribute, and extended-operation checks; it is restored when dispatch
returns. Queued RFC 5805 updates clone that effective DN with the request so
commit replay cannot regain the connection's root identity. Authorization
uses the same engine as SASL Bind: anonymous target, self, database-local
root, then `olcAuthzPolicy` checks over ACL-visible `authzTo` and `authzFrom`
values. User and LDAP URL rule searches run with the original authentication
DN for RFC 4370 requests and with the anonymous pre-Bind identity during SASL
authentication mapping.

The syncrepl client uses Go TLS for LDAPS and StartTLS and the same TLCP adapter
for `ldap+tlcp://` providers. OpenSSL cipher names and the common
`DEFAULT`/`HIGH`/`ALL` selection and exclusion operators are mapped to Go's
configurable TLS 1.0-1.2 suites; TLS 1.3 suite selection and the complete
OpenSSL cipher-expression language cannot be represented by `crypto/tls`.

Before handing a provider socket to `go-ldap`, the consumer owns a bounded BER
exchange layer for StartTLS and multi-round SASL Bind. This permits EXTERNAL
with an authorization ID, PLAIN, CRAM-MD5, DIGEST-MD5, and
SCRAM-SHA-1/256/512. The DIGEST-MD5 conversation preserves repeated realm
directives, validates or selects a realm, carries `authzid`, derives
`ldap/<host>` from the selected provider, and accepts the Bind only after a
strict `rspauth` check; it selects `qop=auth` and no SASL security layer. SCRAM
derives and verifies both proofs through `xdg-go/scram`; LDAP framing, result
validation, round limits, timeouts, and OpenLDAP `secprops` policy remain
internal. GSSAPI is handed to
`go-ldap` after transport negotiation and uses its pure-Go Kerberos client
with password, keytab, or FILE credential-cache acquisition. That client
selects no RFC 4752 security layer. During RFC 4533 streaming, a bounded
response adapter normalizes Sync Info optional fields by ASN.1 tag before
`go-ldap` decodes them; this preserves legal OpenLDAP encodings with an omitted
cookie or default Boolean. The consumer's operation timeout covers initial
refresh only and is removed after refresh-done for persistent searches. SCRAM
channel-binding variants and negotiated SASL integrity/privacy layers are not
yet implemented.

The proxy cache is a database-local overlay on back-ldap. Its runtime
configuration is immutable; a mutex-protected query store is reused only when
an online reload preserves the complete cache fingerprint. A structured
Filter AST prototype selects a configured template and the selected attrset,
normalized base DN, scope, and concrete filter form the query key. Misses are
fully staged from the remote BER stream and committed only after a successful
SearchResultDone. Hits re-encode cached entries for the current requested
attributes and `typesOnly` flag. Expiration is evaluated at the same
consistency-period boundary used by the checker model, so an expired query can
remain visible only inside that configured window. Phase 1 deliberately has
no private database. Phase 2 adds TTR single-flight refresh, an offline mode
that pauses expiry age, `olcPcacheMaxQueries`, query-level LRU, and OpenLDAP's
observable delayed `>` maximum-entry boundary. Proxy writes deliberately do
not invalidate matching cache entries before TTL. `olcPcachePersist` is part of
the configuration fingerprint, but restart does not restore query state; this
matches the pinned 2.6.13 fixture instead of advertising persistence that was
not observed. Bind caching, query deletion, and full filter containment remain
unsupported.

The built-in OTP overlay is attached only to writable local databases and
intercepts non-anonymous
Simple Bind for entries derived from `oathUser`. It reads the user, token, and
parameter entries through the database partition writer, validates TOTP before
HOTP, and advances the selected token in the same storage transaction. The
committed static-password prefix then enters the existing password and ppolicy
Bind path. This preserves OpenLDAP's observable ordering: a valid OTP is
consumed before a wrong static password is rejected, while Password Modify
continues to operate only on the static password and never resets token state.
Internal token reads deliberately bypass caller read ACLs; normal Search and
Modify still use the ordinary ACL and schema paths. Unlike OpenLDAP 2.6.13's
read/release/Modify sequence, the transactional update allows only one
concurrent redemption of a token. The upstream TOTP drift placement bug is
preserved for compatibility: drift is read from the params entry and written
to the token entry. HMAC-SM3 and encrypted seed storage are not implied by this
implementation.

The contrib `pw-totp` path is a separate database or frontend `totp` overlay;
multiple instances are accepted like OpenLDAP. Its six RFC 2307 schemes decode
the stored Base32 seed and verify the final six credential digits against the
current 30-second window; the `ANDPW` variants first verify the credential
prefix against a nested password scheme implemented by ldap-go. Dynamically
registered third-party nested password schemes are not executable yet. A
previous-window code is considered only when the prior `authTimestamp` is set
and older than that previous window. Every successful Simple Bind, including a
normal password Bind, replaces `authTimestamp` in the same storage transaction
without LastMod or sync publication. A failed timestamp write rolls back the
Bind state and returns invalid credentials, while serialized store updates
permit only one successful concurrent redemption. Password hashing uses
OpenLDAP's padded RFC 4648 Base32 representation and fixed `{SSHA}` nested hash
for `seed|static-password` input. The one-winner first-use behavior is an
intentional hardening difference: OpenLDAP 2.6.13 checks and updates
`authTimestamp` separately and can admit concurrent first-use attempts.

The AutoCA overlay is also database-local. Runtime activation reads or creates
one CA certificate and PKCS#8 private key on the first naming-context suffix.
Only a Search whose requested attributes resolve, in order, to
`userCertificate;binary` and `userPrivateKey;binary` can trigger leaf
issuance. The requester must be the database root or the returned entry itself,
and the original entry must satisfy the Search filter and entry ACLs. A storage
update rechecks the private-key attribute before signing, so concurrent strict
Search requests converge on one persisted DER pair. The subsequent normal
Search projection applies attribute ACLs, allowing self-service issuance while
still hiding `userPrivateKey` when policy denies it. The default
`openldap-rsa` profile follows OpenLDAP's RSA behavior. The explicitly labelled
ldap-go extension `olcAutoCAProfile=sm2-sm3` selects SM2 keys and SM3
signatures; it does not imply that an unmodified OpenLDAP server understands
that configuration attribute. AutoCA currently stores material in LDAP but
does not install `olcAutoCAlocalDN` material into the listener TLS context.

## Data migration contract

For documented features, `ldap-go import` accepts unmodified LDIF emitted by
OpenLDAP `slapcat` for content databases and `cn=config`. This is a semantic
interchange contract, not a claim that every imported OpenLDAP configuration
object has equivalent runtime behavior. Within the supported subset, import
must:

- preserve DNs, attribute options, binary values, entry UUIDs, and CSNs;
- validate schema while supporting an explicit bootstrap order for custom
  schema;
- reconstruct backend-native storage rather than trusting source database files;
- reject partial imports atomically and report the record and line;
- produce an export whose normalized LDAP content is equivalent to the input.

Native `ldap-go import` and the `slapadd` alias share one atomic storage
transaction but use different validation policies. Native import enables
structural and value-syntax validation. `slapadd` enables structural checks by
default while leaving full value checks off unless requested. Both use the
built-in registry plus supported `olcObjectIdentifier`, `olcAttributeTypes`,
`olcObjectClasses`, `olcDitContentRules`, and `olcLdapSyntaxes` definitions
imported through `cn=config`. Ordered `X-SUBST` syntax declarations inherit a
known validator and binary-transfer behavior; ordinary declarations remain
registered without inventing a validator. AttributeDescription parsing always
validates configured exact, trailing-`-`, and `range=` options,
operational-attribute option restrictions, and required or forbidden `;binary`
transfer. With `value-check=no`, only matching rules that OpenLDAP invokes while
materializing stored values are checked in the covered subset: DN, Name And
Optional UID, UUID, arbitrary-precision INTEGER, generalized time, authzMatch,
CSN, OpenLDAP ACI, and case-rule UTF-8.
Full value checking validates implemented built-in and substituted syntaxes,
including OpenLDAP's shallow checks for the covered binary certificate/key
syntaxes, and rejects a declaration with no validator rather than accepting
unvalidated data. These checks do not rewrite the original attribute bytes.

For a selected database, hierarchy validation runs after all records are read,
so child-before-parent LDIF is accepted while final orphans and out-of-suffix
DNs are rejected. With no explicit selector, the OpenLDAP-style aliases select
the first configured primary content database in configuration order, excluding
config, frontend, monitor, and subordinate databases. They do not skip an
unsupported selected backend to find a later one. A selected glue superior
routes records owned by a more-specific `olcSubordinate` suffix into the child
partition; a more-specific ordinary database is a selection error. Automatic
native import routing instead chooses the most-specific active configured
suffix. `slapcat` assembles a selected glue superior with its attached
subordinate partitions. `-g` disables import routing and export aggregation so
the selected physical partition is operated on directly. Default glue mode
also rejects a subordinate suffix entry duplicated in the superior partition,
matching the OpenLDAP tool-open consistency check.
Database-scoped replacement follows the same boundary: a glued selection
clears the superior and directly attached subordinate partitions, while `-g`
clears only the selected physical partition.

The `slapadd` path preserves supplied operational values and, when `olcLastMod`
is enabled, generates missing LastMod metadata. Metadata policy comes from the
database selected by the tool, even when glue routes the physical write to a
subordinate backend. `-S` selects the generated CSN SID. With LastMod enabled,
`-w` derives the maximum imported `entryCSN` per SID
and updates the first suffix root; with `olcSyncUseSubentry: TRUE`, it instead
creates or updates the OpenLDAP-shaped `cn=ldapsync,<suffix>` sync-provider
subentry. The same context update and config-backend LastMod generation apply
to `slapadd -n 0`. A `slapadd` configuration import validates the imported
hierarchy and supported schema,
then builds the runnable server configuration through the transaction reader.
The persisted configuration becomes visible only after that same transaction
commits; the offline validator does not publish a live runtime snapshot.

Configuration LDIF is imported first. Subsequent content imports identify the
OpenLDAP database by numeric index, `olcDatabase` value, or configuration-entry
DN, which permits overlapping backends to contain identical DNs. Default tool
selection fails when no primary content database exists rather than writing to
an unconfigured fallback partition. API dry-run executes all validation against
the staged transaction and then deliberately rolls it back.

This atomic design intentionally differs from OpenLDAP `slapadd`, which can
leave earlier records committed and supports `-c` continuation. It also means
the LDIF parse, pending-entry set, schema/hierarchy checks, and final writes live
inside one write transaction; memory use and write-lock duration grow with a
large import. Offline tool behavior currently covers `config`/`mdb` and
`ldif`/`wt`, plus `null` accept-then-discard; proxy and virtual backends reject
offline operations without the corresponding OpenLDAP callbacks. All supported
content is represented in bbolt rather than native backend files. Arbitrary
custom syntax/matching-rule modules, exact OpenLDAP dry-run diagnostics, and
broader nested glue/backend combinations are not implemented.
MDB indexes are never imported, and the current bbolt backend has no
independent attribute indexes, so local Search scans its selected partition.
These are explicit non-drop-in
boundaries.

## Dependency policy

Small, well-maintained libraries may be used for generic primitives such as BER
and cryptography. LDAP semantics, storage contracts, schema behavior, and
OpenLDAP compatibility remain owned by this repository. Every dependency must
be replaceable behind an internal interface.
