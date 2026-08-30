package storage

import (
	"encoding/base64"
	"errors"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const OpenLDAPConfigPartition = "openldap:config"

func OpenLDAPDatabasePartition(name string, entryUUID []byte) string {
	if uuid := strings.TrimSpace(string(entryUUID)); uuid != "" {
		return "openldap:database:uuid:" + encodePartitionComponent(
			strings.ToLower(uuid),
		)
	}
	return "openldap:database:name:" + encodePartitionComponent(
		strings.ToLower(strings.TrimSpace(name)),
	)
}

func OpenLDAPBootstrapPartition(suffix directory.DN) string {
	return "openldap:bootstrap:" + encodePartitionComponent(suffix.Key())
}

func encodePartitionComponent(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func ReaderInPartition(reader Reader, partition string) Reader {
	return partitionReader{
		Reader:    reader,
		partition: partition,
	}
}

func WriterInPartition(writer Writer, partition string) Writer {
	return partitionWriter{
		Writer:    writer,
		partition: partition,
	}
}

// ReaderInPartitionWithNormalizer scopes a reader to one partition and
// normalizes every Get DN with the supplied schema matching rules.
func ReaderInPartitionWithNormalizer(
	reader Reader,
	partition string,
	normalizer directory.DNAttributeNormalizer,
) Reader {
	return schemaAwarePartitionReader{
		partitionReader: partitionReader{Reader: reader, partition: partition},
		normalizer:      normalizer,
	}
}

func ReaderInPartitionWithNormalizerLegacy(
	reader Reader,
	partition string,
	normalizer directory.DNAttributeNormalizer,
) Reader {
	return schemaAwarePartitionReader{
		partitionReader: partitionReader{Reader: reader, partition: partition},
		normalizer:      normalizer,
		allowLegacy:     true,
	}
}

// WriterInPartitionWithNormalizer scopes a writer to one partition and uses
// schema-aware DN identities for Get, Put, and Delete.
func WriterInPartitionWithNormalizer(
	writer Writer,
	partition string,
	normalizer directory.DNAttributeNormalizer,
) Writer {
	return schemaAwarePartitionWriter{
		partitionWriter: partitionWriter{Writer: writer, partition: partition},
		normalizer:      normalizer,
	}
}

func WriterInPartitionWithNormalizerLegacy(
	writer Writer,
	partition string,
	normalizer directory.DNAttributeNormalizer,
) Writer {
	return schemaAwarePartitionWriter{
		partitionWriter: partitionWriter{Writer: writer, partition: partition},
		normalizer:      normalizer,
		allowLegacy:     true,
	}
}

// NormalizeReaderDN applies a reader's DN identity semantics when available.
// Readers without schema-aware identity support retain legacy DN behavior.
func NormalizeReaderDN(reader Reader, dn directory.DN) (directory.DN, error) {
	normalizer, ok := reader.(interface {
		NormalizeDNIdentity(directory.DN) (directory.DN, error)
	})
	if !ok {
		return dn, nil
	}
	return normalizer.NormalizeDNIdentity(dn)
}

// ReaderDNOrderKey returns the key used by a reader's deterministic iteration
// order. Schema-aware readers preserve legacy DN ordering and use the v2
// identity only to distinguish DNs that share a legacy case-folded key.
func ReaderDNOrderKey(reader Reader, dn directory.DN) (string, error) {
	orderer, ok := reader.(interface {
		DNIdentityOrderKey(directory.DN) (string, error)
	})
	if !ok {
		return dn.Key(), nil
	}
	return orderer.DNIdentityOrderKey(dn)
}

// ForEachStablePhysicalEntry streams a schema-aware partition in a backend's
// stable physical order. It is intended for unsorted paged searches, whose LDAP
// result order is unspecified, and avoids materializing the whole partition.
func ForEachStablePhysicalEntry(
	reader Reader,
	fn func(directory.Entry) error,
) (bool, error) {
	scoped, ok := reader.(schemaAwarePartitionReader)
	if !ok {
		return false, nil
	}
	if err := requireSchemaAwareDNIdentities(scoped.Reader, scoped.partition); err != nil {
		return false, err
	}
	backend := maintenanceReader(scoped.Reader)
	iterator, ok := backend.(stableSchemaAwarePhysicalIterator)
	if !ok || !iterator.schemaAwarePhysicalIterationStable() {
		return false, nil
	}
	_, err := iterator.forEachSchemaAwarePhysicalIn(
		scoped.partition,
		func(entry directory.Entry, physicalKey string) error {
			dn, err := directory.ParseDNWithIdentityKey(entry.DN, physicalKey)
			if err != nil {
				return err
			}
			return fn(entry.WithNormalizedDNHint(dn, physicalKey))
		},
	)
	return true, err
}

type partitionReader struct {
	Reader
	partition string
}

func (reader partitionReader) StorageSnapshotRevision() (uint64, bool) {
	return ReaderSnapshotRevision(reader.Reader)
}

func (reader partitionReader) AccessContext() any {
	if provider, ok := reader.Reader.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (reader partitionReader) Get(dn directory.DN) (directory.Entry, error) {
	return reader.Reader.GetIn(reader.partition, dn)
}

func (reader partitionReader) ForEach(fn func(directory.Entry) error) error {
	return reader.Reader.ForEachIn(reader.partition, fn)
}

type partitionWriter struct {
	Writer
	partition string
}

type schemaAwarePartitionReader struct {
	partitionReader
	normalizer  directory.DNAttributeNormalizer
	allowLegacy bool
}

func (reader schemaAwarePartitionReader) NormalizeDNIdentity(
	dn directory.DN,
) (directory.DN, error) {
	return directory.ParseDNWithNormalizer(dn.String(), reader.normalizer)
}

func (reader schemaAwarePartitionReader) DNIdentityOrderKey(
	dn directory.DN,
) (string, error) {
	return schemaAwareDNOrderKey(dn, reader.normalizer)
}

func (reader schemaAwarePartitionReader) Get(
	dn directory.DN,
) (directory.Entry, error) {
	normalized, err := reader.NormalizeDNIdentity(dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry, err := schemaAwareGetIn(
		reader.Reader,
		reader.partition,
		normalized,
	)
	if err != nil && reader.allowLegacy && errors.Is(err, ErrDNIdentityMigrationRequired) {
		return legacySchemaAwareGetIn(
			reader.Reader, reader.partition, normalized, reader.normalizer,
		)
	}
	return entry, err
}

func (reader schemaAwarePartitionReader) ForEach(
	fn func(directory.Entry) error,
) error {
	return schemaAwareForEachIn(
		reader.Reader,
		reader.partition,
		reader.normalizer,
		reader.allowLegacy,
		fn,
	)
}

type schemaAwarePartitionWriter struct {
	partitionWriter
	normalizer  directory.DNAttributeNormalizer
	allowLegacy bool
}

func (writer schemaAwarePartitionWriter) NormalizeDNIdentity(
	dn directory.DN,
) (directory.DN, error) {
	return directory.ParseDNWithNormalizer(dn.String(), writer.normalizer)
}

func (writer schemaAwarePartitionWriter) DNIdentityOrderKey(
	dn directory.DN,
) (string, error) {
	return schemaAwareDNOrderKey(dn, writer.normalizer)
}

func (writer schemaAwarePartitionWriter) Get(
	dn directory.DN,
) (directory.Entry, error) {
	normalized, err := writer.NormalizeDNIdentity(dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry, err := schemaAwareGetIn(
		writer.Writer,
		writer.partition,
		normalized,
	)
	if err != nil && writer.allowLegacy && errors.Is(err, ErrDNIdentityMigrationRequired) {
		return legacySchemaAwareGetIn(
			writer.Writer, writer.partition, normalized, writer.normalizer,
		)
	}
	return entry, err
}

func (writer schemaAwarePartitionWriter) ForEach(
	fn func(directory.Entry) error,
) error {
	return schemaAwareForEachIn(
		writer.Writer,
		writer.partition,
		writer.normalizer,
		writer.allowLegacy,
		fn,
	)
}

func (writer schemaAwarePartitionWriter) Put(
	entry directory.Entry,
	replace bool,
) error {
	dn, err := directory.ParseDNWithNormalizer(entry.DN, writer.normalizer)
	if err != nil {
		return err
	}
	if _, canonical := writer.normalizer.(directory.DNAttributeCanonicalNamer); canonical {
		entry.DN = dn.String()
		dn, err = directory.ParseDNWithNormalizer(entry.DN, writer.normalizer)
		if err != nil {
			return err
		}
	}
	if err := ensureSchemaAwareDNIdentities(
		writer.Writer,
		writer.partition,
		writer.normalizer,
	); err != nil {
		return err
	}
	if handled, err := putPartitionEntryWithEqualityIndexes(
		writer.Writer,
		writer.partition,
		entry,
		dn,
		replace,
		writer.normalizer,
	); handled {
		return err
	}
	return PutInWithDN(writer.Writer, writer.partition, entry, dn, replace)
}

func (writer schemaAwarePartitionWriter) Delete(dn directory.DN) error {
	normalized, err := writer.NormalizeDNIdentity(dn)
	if err != nil {
		return err
	}
	if err := ensureSchemaAwareDNIdentities(
		writer.Writer,
		writer.partition,
		writer.normalizer,
	); err != nil {
		return err
	}
	if handled, err := deletePartitionEntryWithEqualityIndexes(
		writer.Writer,
		writer.partition,
		normalized,
		writer.normalizer,
	); handled {
		return err
	}
	return writer.Writer.DeleteIn(writer.partition, normalized)
}

func (writer schemaAwarePartitionWriter) Clear() error {
	var dns []directory.DN
	if err := writer.Writer.ForEachIn(
		writer.partition,
		func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			normalized, err := writer.NormalizeDNIdentity(dn)
			if err != nil {
				return err
			}
			dns = append(dns, normalized)
			return nil
		},
	); err != nil {
		return err
	}
	for _, dn := range dns {
		if err := writer.Writer.DeleteIn(writer.partition, dn); err != nil {
			return err
		}
	}
	return nil
}

func schemaAwareGetIn(
	reader Reader,
	partition string,
	dn directory.DN,
) (directory.Entry, error) {
	if err := requireSchemaAwareDNIdentities(reader, partition); err != nil {
		return directory.Entry{}, err
	}
	if getter, ok := maintenanceReader(reader).(schemaAwareDirectGetter); ok {
		return getter.getSchemaAwareIn(partition, dn)
	}
	return reader.GetIn(partition, dn)
}

type schemaAwareDirectGetter interface {
	getSchemaAwareIn(partition string, dn directory.DN) (directory.Entry, error)
}

func legacySchemaAwareGetIn(
	reader Reader,
	partition string,
	dn directory.DN,
	normalizer directory.DNAttributeNormalizer,
) (directory.Entry, error) {
	var match directory.Entry
	found := false
	err := reader.ForEachIn(partition, func(candidate directory.Entry) error {
		candidateDN, parseErr := directory.ParseDNWithNormalizer(
			candidate.DN,
			normalizer,
		)
		if parseErr != nil {
			return parseErr
		}
		if !candidateDN.Equal(dn) {
			return nil
		}
		if found {
			return ErrEntryAmbiguous
		}
		match = candidate
		found = true
		return nil
	})
	if err != nil {
		return directory.Entry{}, err
	}
	if !found {
		return directory.Entry{}, ErrEntryNotFound
	}
	return match, nil
}

func schemaAwareForEachIn(
	reader Reader,
	partition string,
	normalizer directory.DNAttributeNormalizer,
	allowLegacy bool,
	fn func(directory.Entry) error,
) error {
	identityErr := requireSchemaAwareDNIdentities(reader, partition)
	if identityErr != nil {
		if !errors.Is(identityErr, ErrDNIdentityMigrationRequired) {
			return identityErr
		}
		if err := validateSchemaAwareDNBindingsIn(reader, partition, normalizer); err != nil {
			return err
		}
	}
	type normalizedEntry struct {
		entry directory.Entry
		key   string
	}

	var entries []normalizedEntry
	appendEntry := func(entry directory.Entry, physicalKey string) error {
		if physicalKey != "" {
			dn, err := directory.ParseDNWithIdentityKey(entry.DN, physicalKey)
			if err != nil {
				return err
			}
			key := dn.LegacyKey() + "\x00" + physicalKey
			entry = entry.WithNormalizedDNHint(dn, key)
			entries = append(entries, normalizedEntry{entry: entry, key: key})
			return nil
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		key, err := schemaAwareDNOrderKey(dn, normalizer)
		if err != nil {
			return err
		}
		entries = append(entries, normalizedEntry{entry: entry, key: key})
		return nil
	}
	var iterationErr error
	iterationOrdered := false
	if identityErr == nil {
		backend := maintenanceReader(reader)
		if iterator, ok := backend.(schemaAwarePhysicalIterator); ok {
			iterationOrdered, iterationErr = iterator.forEachSchemaAwarePhysicalIn(
				partition,
				appendEntry,
			)
		} else {
			iterationErr = reader.ForEachIn(partition, func(entry directory.Entry) error {
				return appendEntry(entry, "")
			})
		}
	} else {
		iterationErr = reader.ForEachIn(partition, func(entry directory.Entry) error {
			return appendEntry(entry, "")
		})
	}
	if iterationErr != nil {
		return iterationErr
	}
	if !iterationOrdered {
		sort.SliceStable(entries, func(left, right int) bool {
			if entries[left].key == entries[right].key {
				return entries[left].entry.DN < entries[right].entry.DN
			}
			return entries[left].key < entries[right].key
		})
	}
	for _, candidate := range entries {
		if err := fn(candidate.entry); err != nil {
			return err
		}
	}
	return nil
}

type schemaAwarePhysicalIterator interface {
	forEachSchemaAwarePhysicalIn(
		partition string,
		visit func(directory.Entry, string) error,
	) (bool, error)
}

type stableSchemaAwarePhysicalIterator interface {
	schemaAwarePhysicalIterator
	schemaAwarePhysicalIterationStable() bool
}

func schemaAwareDNOrderKey(
	dn directory.DN,
	normalizer directory.DNAttributeNormalizer,
) (string, error) {
	legacy, err := directory.ParseDN(dn.String())
	if err != nil {
		return "", err
	}
	normalized, err := directory.ParseDNWithNormalizer(dn.String(), normalizer)
	if err != nil {
		return "", err
	}
	return legacy.Key() + "\x00" + normalized.Key(), nil
}

func (writer partitionWriter) AccessContext() any {
	if provider, ok := writer.Writer.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (writer partitionWriter) Get(dn directory.DN) (directory.Entry, error) {
	return writer.Writer.GetIn(writer.partition, dn)
}

func (writer partitionWriter) ForEach(fn func(directory.Entry) error) error {
	return writer.Writer.ForEachIn(writer.partition, fn)
}

func (writer partitionWriter) Put(entry directory.Entry, replace bool) error {
	return writer.Writer.PutIn(writer.partition, entry, replace)
}

func (writer partitionWriter) Delete(dn directory.DN) error {
	return writer.Writer.DeleteIn(writer.partition, dn)
}

func (writer partitionWriter) Clear() error {
	var dns []directory.DN
	if err := writer.Writer.ForEachIn(
		writer.partition,
		func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			dns = append(dns, dn)
			return nil
		},
	); err != nil {
		return err
	}
	for _, dn := range dns {
		if err := writer.Writer.DeleteIn(writer.partition, dn); err != nil {
			return err
		}
	}
	return nil
}
