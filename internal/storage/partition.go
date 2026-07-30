package storage

import (
	"encoding/base64"
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

type partitionReader struct {
	Reader
	partition string
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
