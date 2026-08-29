package ldapwire

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestReadMessageWithSizePreservesEnvelopeOnControlError(t *testing.T) {
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(7),
		"messageID",
	))
	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(2),
		"version",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"",
		"name",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"",
		"simple",
	))
	message.AppendChild(bind)
	controls := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		0,
		nil,
		"controls",
	)
	controls.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"not-a-control-sequence",
		"malformed control",
	))
	message.AppendChild(controls)
	encoded := message.Bytes()

	decoded, size, err := ReadMessageWithDynamicFilterDepthAndSize(
		bytes.NewReader(encoded),
		DefaultMaxMessageSize,
		0,
		nil,
	)
	if err == nil {
		t.Fatal("malformed controls were accepted")
	}
	if size != len(encoded) {
		t.Fatalf("encoded size = %d, want %d", size, len(encoded))
	}
	request, ok := decoded.Request.(BindRequest)
	if !ok || decoded.ID != 7 || request.Version != 2 || !decoded.ControlsPresent {
		t.Fatalf("partial decoded envelope = %#v", decoded)
	}
}
