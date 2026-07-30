package ldapwire

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestDecodePasswordModifyRequestValue(t *testing.T) {
	t.Parallel()

	if request, err := DecodePasswordModifyRequestValue(nil, false); err != nil ||
		request.HasUserIdentity ||
		request.HasOldPassword ||
		request.HasNewPassword ||
		len(request.UserIdentity) != 0 ||
		len(request.OldPassword) != 0 ||
		len(request.NewPassword) != 0 {
		t.Fatalf("absent request value = %#v, %v", request, err)
	}

	sequence := ber.NewSequence("PasswordModifyRequestValue")
	sequence.AppendChild(contextString(0, []byte("uid=alice,dc=example,dc=com")))
	sequence.AppendChild(contextString(1, []byte("old-secret")))
	sequence.AppendChild(contextString(2, []byte("new-secret")))
	request, err := DecodePasswordModifyRequestValue(sequence.Bytes(), true)
	if err != nil {
		t.Fatalf("DecodePasswordModifyRequestValue(): %v", err)
	}
	if !request.HasUserIdentity ||
		!request.HasOldPassword ||
		!request.HasNewPassword ||
		string(request.UserIdentity) != "uid=alice,dc=example,dc=com" ||
		string(request.OldPassword) != "old-secret" ||
		string(request.NewPassword) != "new-secret" {
		t.Fatalf("request = %#v", request)
	}
}

func TestDecodePasswordModifyRequestValueRejectsMalformedData(t *testing.T) {
	t.Parallel()

	wrongRoot := contextString(0, []byte("value")).Bytes()
	outOfOrder := ber.NewSequence("out of order")
	outOfOrder.AppendChild(contextString(2, []byte("new")))
	outOfOrder.AppendChild(contextString(1, []byte("old")))
	duplicate := ber.NewSequence("duplicate")
	duplicate.AppendChild(contextString(1, []byte("old")))
	duplicate.AppendChild(contextString(1, []byte("old again")))
	unknown := ber.NewSequence("unknown")
	unknown.AppendChild(contextString(3, []byte("value")))
	constructed := ber.NewSequence("constructed child")
	constructed.AppendChild(ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "bad"))
	valid := ber.NewSequence("valid").Bytes()

	for _, value := range [][]byte{
		{},
		wrongRoot,
		outOfOrder.Bytes(),
		duplicate.Bytes(),
		unknown.Bytes(),
		constructed.Bytes(),
		append(bytes.Clone(valid), 0x00),
	} {
		if _, err := DecodePasswordModifyRequestValue(value, true); !errors.Is(
			err,
			ErrMalformedMessage,
		) {
			t.Fatalf("DecodePasswordModifyRequestValue(%x) error = %v", value, err)
		}
	}
}

func TestEncodePasswordModifyResponseValue(t *testing.T) {
	t.Parallel()

	if value := EncodePasswordModifyResponseValue(nil); value != nil {
		t.Fatalf("empty response value = %x", value)
	}
	value := EncodePasswordModifyResponseValue([]byte("generated"))
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 1 ||
		!isPacket(packet.Children[0], ber.ClassContext, ber.TypePrimitive, 0) ||
		string(packet.Children[0].Data.Bytes()) != "generated" {
		t.Fatalf("response packet = %#v", packet)
	}
}

func TestEncodeExtendedResponsePreservesEmptyResponseValue(t *testing.T) {
	t.Parallel()

	encoded := EncodeExtendedResponse(
		1,
		Result{Code: ResultSuccess},
		"",
		[]byte{},
		nil,
	)
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if len(packet.Children) != 2 {
		t.Fatalf("LDAPMessage children = %d", len(packet.Children))
	}
	response := packet.Children[1]
	if len(response.Children) != 4 ||
		!isPacket(response.Children[3], ber.ClassContext, ber.TypePrimitive, 11) ||
		response.Children[3].Data.Len() != 0 {
		t.Fatalf("ExtendedResponse = %#v", response)
	}
}

func contextString(tag ber.Tag, value []byte) *ber.Packet {
	return ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		tag,
		string(value),
		"value",
	)
}
