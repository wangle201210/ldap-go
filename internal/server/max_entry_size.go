package server

import (
	"context"
	"errors"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/mdbentry"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type databaseEntryLimit struct {
	bytes  uint64
	schema *schema.Registry
}

func loadDatabaseEntryLimit(entry directory.Entry, database *runtimeDatabase, normalizer directory.DNAttributeNormalizer) error {
	limit, err := mdbentry.Configuration(entry)
	if err != nil {
		return err
	}
	database.entryLimit.bytes = limit
	database.entryLimit.schema, _ = normalizer.(*schema.Registry)
	return nil
}

func maxEntrySizeConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *mdbentry.ConfigError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(ldapwire.ResultCode(failure.Code), failure.Error()), true
}

func canonicalizeMaxEntrySize(entry *directory.Entry) error {
	if _, err := mdbentry.Configuration(*entry); err != nil {
		if result, ok := maxEntrySizeConfigurationResult(err); ok {
			return &operationFailure{result: result}
		}
		return err
	}
	for i := range entry.Attributes {
		if mdbentry.IsAttribute(entry.Attributes[i].Description) {
			entry.Attributes[i].Description = mdbentry.Attribute
		}
	}
	return nil
}

func applyMaxEntrySizeModification(entry *directory.Entry, change ldapwire.Modification, permissive bool) (bool, error) {
	if !mdbentry.IsAttribute(change.Attribute.Description) {
		return false, nil
	}
	if strings.Contains(change.Attribute.Description, ";") {
		return true, operationFailed(ldapwire.ResultUndefinedAttributeType, "attribute options are not supported")
	}
	for _, value := range change.Attribute.Values {
		if _, err := mdbentry.ParseValue(string(value)); err != nil {
			result, _ := maxEntrySizeConfigurationResult(err)
			return true, &operationFailure{result: result}
		}
	}
	if len(change.Attribute.Values) > 1 {
		return true, operationFailed(ldapwire.ResultConstraintViolation, "olcDbMaxEntrySize must be single-valued")
	}
	if err := canonicalizeMaxEntrySize(entry); err != nil {
		return true, err
	}
	change.Attribute.Description = mdbentry.Attribute
	if err := applyModificationWithPermissive(entry, change, permissive); err != nil {
		return true, err
	}
	return true, canonicalizeMaxEntrySize(entry)
}

// Install below partition and RWM writers, so accounting uses stored attributes.
func withDatabaseEntryLimit(writer storage.Writer, database runtimeDatabase) storage.Writer {
	if database.entryLimit.bytes == 0 || databaseType(database.name) != "mdb" {
		return writer
	}
	return &entryLimitWriter{Writer: writer, partition: database.partition, limit: database.entryLimit}
}

type entryLimitWriter struct {
	storage.Writer
	partition string
	limit     databaseEntryLimit
}

func (writer *entryLimitWriter) PutIn(partition string, entry directory.Entry, replace bool) error {
	if err := writer.check(partition, &entry); err != nil {
		return err
	}
	return writer.Writer.PutIn(partition, entry, replace)
}

func (writer *entryLimitWriter) check(partition string, entry *directory.Entry) error {
	if partition != writer.partition || entry == nil {
		return nil
	}
	if err := mdbentry.Check(*entry, writer.limit.schema, writer.limit.bytes); err != nil {
		if errors.Is(err, mdbentry.ErrTooLarge) {
			return operationFailed(ldapwire.ResultAdminLimitExceeded, err.Error())
		}
		return err
	}
	return nil
}

func (writer *entryLimitWriter) ValidateStorageEntry(partition string, entry directory.Entry) error {
	return writer.check(partition, &entry)
}

func (writer *entryLimitWriter) MaintenanceStorageReader() storage.Reader { return writer.Writer }
func (writer *entryLimitWriter) MaintenanceStorageWriter() storage.Writer { return writer.Writer }
func (writer *entryLimitWriter) AccessContext() any {
	if provider, ok := writer.Writer.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}
func (writer *entryLimitWriter) StorageContext() context.Context {
	if provider, ok := writer.Writer.(interface{ StorageContext() context.Context }); ok {
		return provider.StorageContext()
	}
	return context.Background()
}

// MDB changes descendants' DN index records without rewriting their attributes.
// Our physical key moves must likewise permit already oversized descendants.
func putRenamedDatabaseEntry(writer, tx storage.Writer, database runtimeDatabase, entry directory.Entry, root bool) error {
	if !root && database.entryLimit.bytes != 0 {
		database.entryLimit.bytes = 0
		tx = writerForDatabase(writer, database)
	}
	return tx.Put(entry, false)
}

func putRenamedSyncConsumerEntry(writer, tx storage.Writer, config syncConsumerConfig, entry directory.Entry, root bool) error {
	if !root && config.entryLimit.bytes != 0 {
		config.entryLimit.bytes = 0
		tx = syncConsumerWriter(writer, nil, config)
	}
	return tx.Put(entry, false)
}
