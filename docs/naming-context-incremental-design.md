# Incremental Naming Context Inference

Status: design only, NOT IMPLEMENTED. Baseline: 205b61b.

The current change only reuses a parsed legacy DN during metadata inference.
Every entry is still scanned and validated. No incremental index, validation
certificate, mutation journal, or scan-skipping path is implemented.

## Required Semantics

- Infer roots from actual entries across every partition, including unconfigured
  partitions. Configured database suffixes are not a replacement for roots.
- A nonempty DN is a root when its immediate parent identity is absent globally.
  This includes orphans; the parent may be in another partition.
- Use legacy identity for the configuration partition and for the `cn=config`
  subtree in any partition. Otherwise recompute identity with the current schema.
- For duplicate identities, the last entry in physical-key traversal order wins,
  including its raw DN. This is not last-write order. Sort output by identity.
- Validate every physical record, including empty DNs and overwritten duplicates.
  Preserve codec/binding/schema error order, error wrapping, cancellation, and
  custom reader iteration errors.
- Keep refresh and SetNamingContexts at their existing call sites. Configuration
  writes currently refresh using the old runtime before migrating identities.
  Accesslog and other writes can occur after refresh in the same transaction.

## Proposed Storage State

Maintain these records transactionally, rather than in the three LDAP handlers:

1. Physical key to inferred identity, parent identity, and raw DN.
2. Inferred identity to an ordered set of physical contributors. The maximum
   physical key supplies the winning raw DN; a nonempty set proves existence.
3. Parent identity to distinct child identities, including absent parents.
4. Nonempty child groups whose parent identity is absent. Single-RDN entries use
   a permanently active group. Adding a formerly absent parent deactivates one
   group without updating each formerly orphaned child.
5. Inference mode, schema fingerprint, store-instance epoch, validated data
   version, and transaction-local mutation sequence.

After a full validated baseline, process only changed physical records. Emit
active groups and sort their winners by identity. For delta changed records and
R roots, expected B-tree maintenance is O(delta log N), output O(R log R), and
storage O(N). Materializing R roots necessarily costs at least O(R).

## Validation And Lifecycle Prerequisites

- Start with the existing full ordered scan. Reuse that certificate only if all
  subsequent changes are tracked, and fully validate changed final records.
- Track writes at the storage layer, including replacements, plain Store.Update,
  overlays, replication, imports, and writes after refresh. The existing low-level
  putEntry/deleteEntry paths are useful integration points, but identity migration
  directly edits storage and Clear replaces buckets; both need explicit handling.
- Keep state and mutation tracking in the same transaction as entries so rollback
  and no-op writes cannot publish it. Multiple refreshes in one transaction need
  mutation sequences, not just a committed snapshot revision.
- On missing tracking, schema/mode changes, migration, partition layout changes,
  unknown decorators, or uncertain provenance, use the original full scan.
  Incremental validation failures must fall back to the original scan to preserve
  first-error behavior. Do not introduce earlier errors at arbitrary Put calls:
  later operations in the transaction may repair or delete the offending record.
- Restore/reopen must establish a new instance epoch and validate/rebuild the
  derived state; restored marker values or transaction IDs alone are insufficient.
  Extend backup/check/restore validation if new persistent buckets are introduced.
- Arbitrary untracked file modification or corruption cannot be detected from
  existing markers. If every refresh must discover such changes immediately,
  retaining the full read is necessary; no sublinear guarantee is possible.

## Existing Building Blocks And Gaps

- Physical entry keys support partition lookup and deterministic traversal, but
  there is no global contributor set or parent/child index.
- entries:count tracks physical entries per partition, not logical identities.
- storage:dn-identity:v2 marks the identity format. DN binding checks establish
  binding and shape, not equality with the current schema's normalization.
- server:dn-identity-schema:v1 and Registry.DNIdentityFingerprint can identify
  naming rules, but do not certify every record after arbitrary writes.
- storage:partitioned-entry-keys:v1 and equality index configs/refs do not encode
  root topology. MaintenanceMutationObserver is not a complete mutation journal.
- Snapshot revisions support committed immutable caches, not transaction-local
  changes or restore identity. Memory write transactions currently leave their
  revision field at zero.

Eliminating this scan alone does not eliminate Delete/ModifyDN's separate scans
or Memory.Update's full copy. No performance claim is established by this memo.
