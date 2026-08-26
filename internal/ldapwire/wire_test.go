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

func TestReadSASLBindRequestPreservesCredentialsPresence(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		include     bool
		credentials []byte
	}{
		{name: "absent"},
		{name: "present empty", include: true, credentials: []byte{}},
		{name: "present value", include: true, credentials: []byte("step")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			operation := ber.Encode(
				ber.ClassApplication,
				ber.TypeConstructed,
				ApplicationBindRequest,
				nil,
				"BindRequest",
			)
			operation.AppendChild(ber.NewInteger(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagInteger,
				3,
				"version",
			))
			operation.AppendChild(ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				"",
				"name",
			))
			authentication := ber.Encode(
				ber.ClassContext,
				ber.TypeConstructed,
				3,
				nil,
				"sasl",
			)
			authentication.AppendChild(ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				"SCRAM-SHA-256",
				"mechanism",
			))
			if test.include {
				credentials := ber.Encode(
					ber.ClassUniversal,
					ber.TypePrimitive,
					ber.TagOctetString,
					nil,
					"credentials",
				)
				_, _ = credentials.Data.Write(test.credentials)
				authentication.AppendChild(credentials)
			}
			operation.AppendChild(authentication)

			decoded, err := ReadMessage(
				bytes.NewReader(testMessage(8, operation).Bytes()),
				4096,
			)
			if err != nil {
				t.Fatalf("ReadMessage(): %v", err)
			}
			request, ok := decoded.Request.(BindRequest)
			if !ok ||
				request.Authentication.HasSASLCredentials != test.include ||
				!bytes.Equal(
					request.Authentication.SASLCredentials,
					test.credentials,
				) {
				t.Fatalf("decoded SASL Bind = %#v", decoded.Request)
			}
		})
	}
}

func TestEncodeSASLBindResponsePreservesEmptyCredentials(t *testing.T) {
	t.Parallel()

	encoded := EncodeSASLBindResponse(
		9,
		Result{Code: ResultSASLBindInProgress},
		[]byte{},
		true,
		nil,
	)
	packet, err := ber.ReadPacket(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadPacket(): %v", err)
	}
	if len(packet.Children) != 2 ||
		len(packet.Children[1].Children) != 4 {
		t.Fatalf("encoded BindResponse = %#v", packet)
	}
	credentials := packet.Children[1].Children[3]
	if credentials.ClassType != ber.ClassContext ||
		credentials.TagType != ber.TypePrimitive ||
		credentials.Tag != 7 ||
		credentials.Data.Len() != 0 {
		t.Fatalf("serverSaslCreds = %#v", credentials)
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

func TestReadEmptyModifyRequest(t *testing.T) {
	t.Parallel()

	operation := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationModifyRequest,
		nil,
		"ModifyRequest",
	)
	operation.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"uid=alice,dc=example,dc=com",
		"object",
	))
	operation.AppendChild(ber.NewSequence("changes"))

	decoded, err := ReadMessage(
		bytes.NewReader(testMessage(9, operation).Bytes()),
		4096,
	)
	if err != nil {
		t.Fatalf("ReadMessage(): %v", err)
	}
	request, ok := decoded.Request.(ModifyRequest)
	if !ok || request.DN != "uid=alice,dc=example,dc=com" ||
		len(request.Changes) != 0 {
		t.Fatalf("decoded empty ModifyRequest = %#v", decoded.Request)
	}
}

func TestReadMessageRejectsOversizedFrame(t *testing.T) {
	t.Parallel()

	_, err := ReadMessage(bytes.NewReader([]byte{0x30, 0x82, 0x01, 0x00}), 32)
	if !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("ReadMessage() error = %v, want ErrMalformedMessage", err)
	}
}

func TestDecodeFilterRejectsTrailingPacket(t *testing.T) {
	t.Parallel()

	packet := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		ber.Tag(3),
		nil,
		"equalityMatch",
	)
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"uid",
		"attribute",
	))
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"alice",
		"assertion",
	))
	filter, err := DecodeFilter(packet.Bytes())
	if err != nil {
		t.Fatalf("DecodeFilter(): %v", err)
	}
	if filter.Kind != directory.FilterEquality ||
		filter.Attribute != "uid" ||
		string(filter.Assertion) != "alice" {
		t.Fatalf("filter = %#v", filter)
	}
	if _, err := DecodeFilter(append(bytes.Clone(packet.Bytes()), 0x00)); !errors.Is(
		err,
		ErrMalformedMessage,
	) {
		t.Fatalf("DecodeFilter(trailing) error = %v", err)
	}
}

func TestReadControlPreservesEmptyValuePresence(t *testing.T) {
	t.Parallel()

	unbind := ber.Encode(
		ber.ClassApplication,
		ber.TypePrimitive,
		ApplicationUnbindRequest,
		nil,
		"UnbindRequest",
	)
	message := testMessage(10, unbind)
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	control := ber.NewSequence("Control")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"1.3.6.1.1.12",
		"controlType",
	))
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"",
		"controlValue",
	))
	controls.AppendChild(control)
	message.AppendChild(controls)

	decoded, err := ReadMessage(bytes.NewReader(message.Bytes()), 1024)
	if err != nil {
		t.Fatalf("ReadMessage(): %v", err)
	}
	if len(decoded.Controls) != 1 ||
		!decoded.Controls[0].HasValue ||
		len(decoded.Controls[0].Value) != 0 {
		t.Fatalf("controls = %#v", decoded.Controls)
	}
}

func TestReadUnbindIgnoresMalformedControl(t *testing.T) {
	t.Parallel()
	unbind := ber.Encode(
		ber.ClassApplication,
		ber.TypePrimitive,
		ApplicationUnbindRequest,
		nil,
		"UnbindRequest",
	)
	message := testMessage(11, unbind)
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	wrapper.AppendChild(ber.NewSequence("malformed empty Control"))
	message.AppendChild(wrapper)
	decoded, err := ReadMessage(bytes.NewReader(message.Bytes()), 1024)
	if err != nil {
		t.Fatalf("ReadMessage(Unbind malformed control): %v", err)
	}
	if _, ok := decoded.Request.(UnbindRequest); !ok ||
		!decoded.ControlsPresent || len(decoded.Controls) != 0 {
		t.Fatalf("decoded Unbind = %#v", decoded)
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

func TestEncodeSearchResultReference(t *testing.T) {
	t.Parallel()

	encoded := EncodeSearchResultReference(
		7,
		[]string{
			"ldap://one.example/dc=example,dc=com??sub",
			"ldaps://two.example/dc=example,dc=com??sub",
		},
		nil,
	)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if len(packet.Children) != 2 {
		t.Fatalf("LDAPMessage children = %d, want 2", len(packet.Children))
	}
	response := packet.Children[1]
	if response.ClassType != ber.ClassApplication ||
		response.Tag != ApplicationSearchResultReference ||
		len(response.Children) != 2 {
		t.Fatalf("SearchResultReference = %#v", response)
	}
	if got := response.Children[0].Value; got !=
		"ldap://one.example/dc=example,dc=com??sub" {
		t.Fatalf("first URI = %q", got)
	}
	if got := response.Children[1].Value; got !=
		"ldaps://two.example/dc=example,dc=com??sub" {
		t.Fatalf("second URI = %q", got)
	}
}

func testMessage(id int64, operation *ber.Packet) *ber.Packet {
	message := ber.NewSequence("")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	message.AppendChild(operation)
	return message
}
