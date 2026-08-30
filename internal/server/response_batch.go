package server

import (
	"net"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	maximumLDAPResponseBatchPDUs  = 64
	maximumLDAPResponseBatchBytes = 64 * 1024
)

type ldapResponseBatchWriter interface {
	writeLDAPResponseBatch(values [][]byte) (int, error)
}

type ldapResponseBatchConnection struct {
	net.Conn
	values [][]byte
	bytes  int
}

func newLDAPResponseBatchConnection(connection net.Conn) *ldapResponseBatchConnection {
	return &ldapResponseBatchConnection{Conn: connection}
}

func (connection *ldapResponseBatchConnection) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	if len(connection.values) != 0 &&
		(connection.bytes+len(value) > maximumLDAPResponseBatchBytes ||
			len(connection.values) >= maximumLDAPResponseBatchPDUs) {
		if err := connection.Flush(); err != nil {
			return 0, err
		}
	}
	connection.values = append(connection.values, value)
	connection.bytes += len(value)
	if connection.bytes >= maximumLDAPResponseBatchBytes ||
		len(connection.values) >= maximumLDAPResponseBatchPDUs {
		if err := connection.Flush(); err != nil {
			return len(value), err
		}
	}
	return len(value), nil
}

func (connection *ldapResponseBatchConnection) Flush() error {
	if len(connection.values) == 0 {
		return nil
	}
	values := connection.values
	connection.values = nil
	connection.bytes = 0
	if writer, ok := connection.Conn.(ldapResponseBatchWriter); ok {
		_, err := writer.writeLDAPResponseBatch(values)
		return err
	}
	for _, value := range values {
		if err := ldapwire.Write(connection.Conn, value); err != nil {
			return err
		}
	}
	return nil
}

func (connection *ldapResponseBatchConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface {
		beginFinalResponse() error
	}); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}
