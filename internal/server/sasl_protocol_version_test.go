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

func TestLDAPv2SASLBindRequiresLDAPv3AndDisconnects(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(t, store, "olcAllows", "bind_v2")

	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline(): %v", err)
	}

	response := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSASLBindRequestVersion(2, "PLAIN", nil),
	)
	if len(response.Children) != 2 {
		t.Fatalf("LDAPv2 SASL response envelope = %#v", response)
	}
	messageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse response message ID: %v", err)
	}
	operation := response.Children[1]
	if messageID != 1 ||
		operation.ClassType != ber.ClassApplication ||
		operation.Tag != ldapwire.ApplicationBindResponse {
		t.Fatalf(
			"LDAPv2 SASL response = message ID %d, class %d, tag %d",
			messageID,
			operation.ClassType,
			operation.Tag,
		)
	}
	if code := rawLDAPResultCode(t, operation); code !=
		int64(ldapwire.ResultProtocolError) {
		t.Fatalf("LDAPv2 SASL result code = %d", code)
	}
	if diagnostic := rawLDAPDiagnostic(response); diagnostic !=
		"SASL bind requires LDAPv3" {
		t.Fatalf("LDAPv2 SASL diagnostic = %q", diagnostic)
	}

	buffer := make([]byte, 1)
	read, err := connection.Read(buffer)
	if read != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("post-response read = %d, %v; want EOF", read, err)
	}
}

func rawSASLBindRequestVersion(
	version int64,
	mechanism string,
	credentials []byte,
) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		version,
		"version",
	))
	request.AppendChild(rawOctetString(nil))
	authentication := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		3,
		nil,
		"SASL authentication",
	)
	authentication.AppendChild(rawOctetString([]byte(mechanism)))
	authentication.AppendChild(rawOctetString(credentials))
	request.AppendChild(authentication)
	return request
}
