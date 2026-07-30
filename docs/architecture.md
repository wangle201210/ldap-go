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

### Directory service agent

The DSA implements Bind, Search, Modify, Add, Delete, ModifyDN, Compare,
Abandon, Unbind, and Extended operations. It owns referrals, aliases,
operational attributes, result codes, and transaction boundaries.

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

OpenLDAP-style databases map to backend instances selected by the longest
matching naming context.

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

Every committed write receives OpenLDAP-compatible CSN metadata and is appended
to an ordered change stream. RFC 4533 provider and consumer support is built on
that stream. Delta-syncrepl uses the same durable log through the accesslog
overlay.

### Security

Transport security is abstracted from LDAP semantics. Standard TLS and StartTLS
ship first; a national-cryptography transport can be added without forking the
operation engine. Password schemes are registered modules and constant-time
verification is mandatory.

## Data migration contract

`ldap-go import` must accept unmodified LDIF emitted by OpenLDAP `slapcat` for
content databases and `cn=config`. Import must:

- preserve DNs, attribute options, binary values, entry UUIDs, and CSNs;
- validate schema while supporting an explicit bootstrap order for custom
  schema;
- reconstruct all indexes rather than trusting source database files;
- reject partial imports atomically and report the record and line;
- produce an export whose normalized LDAP content is equivalent to the input.

## Dependency policy

Small, well-maintained libraries may be used for generic primitives such as BER
and cryptography. LDAP semantics, storage contracts, schema behavior, and
OpenLDAP compatibility remain owned by this repository. Every dependency must
be replaceable behind an internal interface.

