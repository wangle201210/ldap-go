package ldapwire

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestReadBindRequest(t *testing.T) {
	t.Parallel()

	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "")
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=admin", ""))
	operation.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "secret", ""))

	message := testMessage(7, operation)
	decoded, err := ReadMessage(bytes.NewReader(message.Bytes()), 1024)
	if err != nil {
		t.Fatalf("ReadMessage(): %v", err)
	}
	request, ok := decoded.Request.(BindRequest)
	if !ok {
		t.Fatalf("request type = %T", decoded.Request)
	}
	if decoded.ID != 7 || request.Version != 3 || request.Name != "cn=admin" ||
		string(request.Authentication.Simple) != "secret" {
		t.Fatalf("decoded request = %#v, message ID = %d", request, decoded.ID)
	}
}

func TestReadSearchRequestWithFilter(t *testing.T) {
	t.Parallel()

	filter := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "and")
	equality := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "equality")
	equality.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", ""))
	equality.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "person", ""))
	filter.AppendChild(equality)
	filter.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, "mail", "present"))

	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "")
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=com", ""))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, ""))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 100, ""))
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 5, ""))
	operation.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, ""))
	operation.AppendChild(filter)
	attributes := ber.NewSequence("")
	attributes.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", ""))
	operation.AppendChild(attributes)

	decoded, err := ReadMessage(bytes.NewReader(testMessage(8, operation).Bytes()), 4096)
	if err != nil {
		t.Fatalf("ReadMessage(): %v", err)
	}
	request, ok := decoded.Request.(SearchRequest)
	if !ok {
		t.Fatalf("request type = %T", decoded.Request)
	}
	if request.Scope != directory.ScopeWholeSubtree ||
		request.SizeLimit != 100 ||
		request.TimeLimit != 5 ||
		len(request.Attributes) != 1 ||
		request.Attributes[0] != "cn" {
		t.Fatalf("decoded request = %#v", request)
	}

	entry := directory.Entry{
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("person")}},
			{Description: "mail", Values: [][]byte{[]byte("a@example.com")}},
		},
	}
	matches, err := request.Filter.Match(entry)
	if err != nil {
		t.Fatalf("filter.Match(): %v", err)
	}
	if !matches {
		t.Fatal("decoded filter did not match")
	}
}

func TestReadMessageRejectsOversizedFrame(t *testing.T) {
	t.Parallel()

	_, err := ReadMessage(bytes.NewReader([]byte{0x30, 0x82, 0x01, 0x00}), 32)
	if !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("ReadMessage() error = %v, want ErrMalformedMessage", err)
	}
}

func TestReadExtendedRequest(t *testing.T) {
	t.Parallel()

	operation := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationExtendedRequest,
		nil,
		"",
	)
	operation.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"1.3.6.1.4.1.1466.20037",
		"",
	))
	value := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "")
	_, _ = value.Data.Write([]byte{0x00, 0xff})
	operation.AppendChild(value)

	decoded, err := ReadMessage(
		bytes.NewReader(testMessage(9, operation).Bytes()),
		1024,
	)
	if err != nil {
		t.Fatalf("ReadMessage(): %v", err)
	}
	request, ok := decoded.Request.(ExtendedRequest)
	if !ok {
		t.Fatalf("request type = %T", decoded.Request)
	}
	if request.Name != "1.3.6.1.4.1.1466.20037" ||
		!request.HasValue ||
		!bytes.Equal(request.Value, []byte{0x00, 0xff}) {
		t.Fatalf("decoded request = %#v", request)
	}
}

func TestReadExtendedRequestRejectsInvalidElementOrder(t *testing.T) {
	t.Parallel()

	operation := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationExtendedRequest,
		nil,
		"",
	)
	operation.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		"value-before-name",
		"",
	))
	_, err := ReadMessage(
		bytes.NewReader(testMessage(9, operation).Bytes()),
		1024,
	)
	if !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("ReadMessage() error = %v, want ErrMalformedMessage", err)
	}
}

func TestEncodeSearchResultEntryPreservesBinaryValues(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
		},
	}
	encoded := EncodeSearchResultEntry(3, entry, nil)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	got := packet.Children[1].Children[1].Children[0].Children[1].Children[0].Data.Bytes()
	if !bytes.Equal(got, entry.Attributes[0].Values[0]) {
		t.Fatalf("encoded value = %v, want %v", got, entry.Attributes[0].Values[0])
	}
}

func testMessage(id int64, operation *ber.Packet) *ber.Packet {
	message := ber.NewSequence("")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	message.AppendChild(operation)
	return message
}
