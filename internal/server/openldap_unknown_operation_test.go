package server

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type unknownOperationObservation struct {
	messageID   int64
	tag         uint64
	resultCode  int64
	diagnostic  string
	responseOID string
	closed      bool
}

func TestUnknownLDAPOperationDisconnects(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	got := observeUnknownLDAPOperation(t, address)
	assertUnknownLDAPOperationObservation(t, got)
}

func TestOpenLDAPReferenceUnknownOperationDisconnect(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServer(t, tools, nil)
	defer stop()
	want := observeUnknownLDAPOperation(t, uri[len("ldap://"):])
	assertUnknownLDAPOperationObservation(t, want)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stopLocal := startServer(t, store, Config{})
	defer stopLocal()
	got := observeUnknownLDAPOperation(t, address)
	if got != want {
		t.Fatalf("unknown operation differs: ldap-go=%#v OpenLDAP=%#v", got, want)
	}
}

func observeUnknownLDAPOperation(t *testing.T, address string) unknownOperationObservation {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(%s): %v", address, err)
	}
	defer connection.Close()
	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 31, nil, "unknown request")
	writeRawLDAPRequest(t, connection, 7, operation)
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	packet, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("ReadPacket(notice): %v", err)
	}
	observation := unknownOperationObservation{}
	if len(packet.Children) != 2 {
		t.Fatalf("notice LDAPMessage = %#v", packet)
	}
	observation.messageID, err = ber.ParseInt64(packet.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse notice message ID: %v", err)
	}
	operationPacket := packet.Children[1]
	observation.tag = uint64(operationPacket.Tag)
	if len(operationPacket.Children) < 3 {
		t.Fatalf("notice ExtendedResponse = %#v", operationPacket)
	}
	observation.resultCode, err = ber.ParseInt64(operationPacket.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse notice result code: %v", err)
	}
	observation.diagnostic = string(operationPacket.Children[2].Data.Bytes())
	for _, child := range operationPacket.Children[3:] {
		if child.ClassType == ber.ClassContext && child.Tag == 10 {
			observation.responseOID = string(child.Data.Bytes())
		}
	}
	_, err = ber.ReadPacket(connection)
	observation.closed = errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
	return observation
}

func assertUnknownLDAPOperationObservation(t *testing.T, got unknownOperationObservation) {
	t.Helper()
	if got.messageID != 0 ||
		got.tag != ldapwire.ApplicationExtendedResponse ||
		got.resultCode != int64(ldapwire.ResultProtocolError) ||
		got.diagnostic != "unknown LDAP request" ||
		got.responseOID != "1.3.6.1.4.1.1466.20036" ||
		!got.closed {
		t.Fatalf("unknown operation observation = %#v", got)
	}
}
