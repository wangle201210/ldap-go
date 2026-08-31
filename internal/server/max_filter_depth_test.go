package server

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestMaxFilterDepthOnlineSearchAndAssertionDisconnect(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)

	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configuration.Close() })
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcMaxFilterDepth", []string{"not-an-integer"})
	assertLDAPResultCode(
		t,
		configuration.Modify(invalid),
		ldap.LDAPResultInvalidAttributeSyntax,
	)
	replaceMaxFilterDepth := func(value string) {
		t.Helper()
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcMaxFilterDepth", []string{value})
		if err := configuration.Modify(request); err != nil {
			t.Fatalf("replace olcMaxFilterDepth with %q: %v", value, err)
		}
	}

	replaceMaxFilterDepth("2")
	connection := dialRawMaxFilterDepth(t, address)
	writeRawLDAPRequest(
		t,
		connection,
		1,
		rawMaxFilterDepthSearch(rawNestedNotFilter(2)),
	)
	if code := readRawMaxFilterDepthSearchDone(t, connection); code != int64(ldap.LDAPResultNoSuchObject) {
		t.Fatalf("depth 2 boundary result = %d", code)
	}

	replaceMaxFilterDepth("1")
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawMaxFilterDepthSearch(rawNestedNotFilter(2)),
	)
	assertFilterDepthDisconnect(t, connection)
	assertRawConnectionClosed(t, connection)

	assertionConnection := dialRawMaxFilterDepth(t, address)
	assertion := encodeRawLDAPControl(ldapwire.Control{
		OID:      assertionControlOID,
		Critical: true,
		HasValue: true,
		Value:    rawNestedNotFilter(2).Bytes(),
	})
	writeRawLDAPRequest(
		t,
		assertionConnection,
		3,
		rawMaxFilterDepthSearch(rawNestedNotFilter(0)),
		assertion,
	)
	assertFilterDepthDisconnect(t, assertionConnection)
	assertRawConnectionClosed(t, assertionConnection)

	replaceMaxFilterDepth("-1")
	negativeConnection := dialRawMaxFilterDepth(t, address)
	writeRawLDAPRequest(
		t,
		negativeConnection,
		4,
		rawMaxFilterDepthSearch(rawNestedNotFilter(0)),
	)
	assertFilterDepthDisconnect(t, negativeConnection)
	assertRawConnectionClosed(t, negativeConnection)

	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcMaxFilterDepth", nil)
	if err := configuration.Modify(remove); err != nil {
		t.Fatalf("delete olcMaxFilterDepth: %v", err)
	}
	restoredConnection := dialRawMaxFilterDepth(t, address)
	defer restoredConnection.Close()
	writeRawLDAPRequest(
		t,
		restoredConnection,
		5,
		rawMaxFilterDepthSearch(rawNestedNotFilter(2)),
	)
	if code := readRawMaxFilterDepthSearchDone(t, restoredConnection); code != int64(ldap.LDAPResultNoSuchObject) {
		t.Fatalf("restored default result = %d", code)
	}
}

func dialRawMaxFilterDepth(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	return connection
}

func rawNestedNotFilter(depth int) *ber.Packet {
	filter := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		7,
		"notPresentOnRootDSE",
		"present",
	)
	for range depth {
		not := ber.Encode(ber.ClassContext, ber.TypeConstructed, 2, nil, "not")
		not.AppendChild(filter)
		filter = not
	}
	return filter
}

func rawMaxFilterDepthSearch(filter *ber.Packet) *ber.Packet {
	operation := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationSearchRequest,
		nil,
		"SearchRequest",
	)
	operation.AppendChild(rawOctetString([]byte("cn=missing,dc=example,dc=com")))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "scope"))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "sizeLimit"))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "timeLimit"))
	operation.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	operation.AppendChild(filter)
	operation.AppendChild(ber.NewSequence("attributes"))
	return operation
}

func assertFilterDepthDisconnect(t *testing.T, connection net.Conn) {
	t.Helper()
	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read Notice of Disconnection: %v", err)
	}
	if len(response.Children) < 2 {
		t.Fatalf("malformed Notice of Disconnection: %#v", response)
	}
	messageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil || messageID != 0 {
		t.Fatalf("Notice message ID = %d, %v", messageID, err)
	}
	operation := response.Children[1]
	if uint64(operation.Tag) != ldapwire.ApplicationExtendedResponse {
		t.Fatalf("Notice operation tag = %d, children=%d", operation.Tag, len(operation.Children))
	}
	if len(operation.Children) < 4 {
		t.Fatalf("Notice operation children = %d", len(operation.Children))
	}
	code, err := ber.ParseInt64(operation.Children[0].Data.Bytes())
	if err != nil || code != int64(ldap.LDAPResultProtocolError) {
		t.Fatalf("Notice result = %d, %v", code, err)
	}
	if diagnostic := operation.Children[2].Data.String(); diagnostic != "filter nested too deeply" {
		t.Fatalf("Notice diagnostic = %q", diagnostic)
	}
	if operation.Children[3].ClassType != ber.ClassContext ||
		operation.Children[3].Tag != 10 ||
		operation.Children[3].Data.String() != "1.3.6.1.4.1.1466.20036" {
		t.Fatalf("Notice responseName = %#v", operation.Children[3])
	}
}

func readRawMaxFilterDepthSearchDone(t *testing.T, connection net.Conn) int64 {
	t.Helper()
	for {
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read Search response: %v", err)
		}
		if len(response.Children) < 2 ||
			uint64(response.Children[1].Tag) != ldapwire.ApplicationSearchResultDone {
			continue
		}
		if len(response.Children[1].Children) == 0 {
			t.Fatalf("malformed SearchResultDone: %#v", response)
		}
		code, err := ber.ParseInt64(response.Children[1].Children[0].Data.Bytes())
		if err != nil {
			t.Fatalf("decode Search result: %v", err)
		}
		return code
	}
}

func assertRawConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	_, err := ber.ReadPacket(connection)
	if err == nil {
		t.Fatal("connection remained open after Notice of Disconnection")
	}
	if !errors.Is(err, io.EOF) {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatalf("connection was not closed: %v", err)
		}
	}
}
