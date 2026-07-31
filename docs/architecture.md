# Architecture

## Target

The compatibility baseline is OpenLDAP 2.6.x. LDAP standards define protocol
correctness; OpenLDAP differential tests define behavior where the standards
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

One reader accepts and registers requests while one worker serializes ordinary
operations that share authentication, paging, VLV, and runtime state. Abandon
and RFC 3909 Cancel are handled by the reader so they can cancel the active
Search context without waiting behind it. Bind and StartTLS are read barriers,
and a connection-wide writer lock keeps every BER PDU intact when a Cancel
response races with Search output. The registry establishes an atomic
final-response boundary for `tooLate` and limits cancellation to the LDAP
association that created the target operation.

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
name forms, content rules, and schema validation are centralized. Stored values
retain their original representation while indexes use normalized values.

### Backends

Backends expose atomic read/write transactions over entries and indexes. The
interface must support:

- base, one-level, and subtree candidate selection;
- equality, ordering, approximate, substring, and presence indexes;
- stable entry IDs and entry UUIDs;
- atomic Modify and ModifyDN, including subtree moves;
- snapshot reads and ordered change records for replication;
- online backup, restore, and consistency checking.

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

### Overlays

Overlays are typed middleware around operation dispatch and response emission.
They can inspect or transform requests, execute transactional side effects, add
response controls, and observe final outcomes. Ordering is explicit and
configuration-backed.

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
Runtime configuration activation preserves a complete existing window and
resets it when a publication gap is detected. Sorting and VLV operate on the
combined ACL-visible candidate set after all glue routes are read, then attach
their result controls to Sync Done or the refresh-done intermediate response.

Consumer workers are keyed by storage partition and replication ID. `Serve`
owns their context; runtime activation publishes a desired immutable
configuration, and the manager fully stops a changed worker before starting
its replacement. RFC 4533 entry changes and opaque cookies commit in one
storage transaction. Present completion scans only the configured local
scope/filter, while suffix massage rewrites entry and schema-recognized
DN-valued attribute values. Single-provider databases reject client updates or
return their rewritten update referrals; internal replication bypasses that
LDAP-operation precondition.

The consumer can replay a remote OpenLDAP accesslog as delta-syncrepl. Each
audit operation and its cookie share a storage transaction; malformed or
non-replayable history clears the consumer cookie and forces a conventional
refresh before log streaming resumes. A local provider-side durable accesslog
overlay remains a future layer and must not treat the current process-local
provider stream as a crash-recovery log.

### Security

Transport security is abstracted from LDAP semantics. Standard TLS and StartTLS
use the same `SecureTransport` server-handshake contract for explicit and
implicit upgrades. The TLCP provider implements GB/T 38636 with separate SM2
signing and encryption certificates and SM4/SM3 cipher suites without forking
the operation engine. RFC 8998 TLS 1.3 support is a separate provider because
it is not wire-compatible with TLCP. Password schemes are registered modules
and constant-time verification is mandatory. Imported OpenLDAP digest schemes
remain readable, while new national-cryptography credentials use salted,
costed PBKDF2-SM3 rather than a fast bare SM3 digest. Stored iteration counts
are bounded during verification so a malicious directory value cannot force
unlimited work on a Bind handler. RFC 3062 Password Modify runs old-password
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

## Data migration contract

`ldap-go import` must accept unmodified LDIF emitted by OpenLDAP `slapcat` for
content databases and `cn=config`. Import must:

- preserve DNs, attribute options, binary values, entry UUIDs, and CSNs;
- validate schema while supporting an explicit bootstrap order for custom
  schema;
- reconstruct all indexes rather than trusting source database files;
- reject partial imports atomically and report the record and line;
- produce an export whose normalized LDAP content is equivalent to the input.

Configuration LDIF is imported first. Subsequent content imports identify the
OpenLDAP database by numeric index, `olcDatabase` value, or configuration-entry
DN, which permits overlapping backends to contain identical DNs. A
database-scoped replacement clears only that partition.

## Dependency policy

Small, well-maintained libraries may be used for generic primitives such as BER
and cryptography. LDAP semantics, storage contracts, schema behavior, and
OpenLDAP compatibility remain owned by this repository. Every dependency must
be replaceable behind an internal interface.
