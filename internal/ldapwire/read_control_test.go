package ldapwire

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestDecodeAttributeSelection(t *testing.T) {
	t.Parallel()

	selection := ber.NewSequence("AttributeSelection")
	selection.AppendChild(octetString([]byte("cn")))
	selection.AppendChild(octetString([]byte("+")))
	attributes, err := DecodeAttributeSelection(selection.Bytes())
	if err != nil {
		t.Fatalf("DecodeAttributeSelection(): %v", err)
	}
	if len(attributes) != 2 || attributes[0] != "cn" || attributes[1] != "+" {
		t.Fatalf("attributes = %q", attributes)
	}

	empty := ber.NewSequence("empty AttributeSelection")
	attributes, err = DecodeAttributeSelection(empty.Bytes())
	if err != nil || len(attributes) != 0 {
		t.Fatalf("empty attributes = %q, %v", attributes, err)
	}
}

func TestDecodeAttributeSelectionRejectsMalformedValue(t *testing.T) {
	t.Parallel()

	valid := ber.NewSequence("AttributeSelection")
	valid.AppendChild(octetString([]byte("cn")))
	invalidElement := ber.NewSequence("AttributeSelection")
	invalidElement.AppendChild(ber.NewSequence("invalid element"))
	for _, value := range [][]byte{
		nil,
		octetString([]byte("cn")).Bytes(),
		append(bytes.Clone(valid.Bytes()), 0x00),
		invalidElement.Bytes(),
	} {
		if _, err := DecodeAttributeSelection(value); !errors.Is(err, ErrMalformedMessage) {
			t.Fatalf("DecodeAttributeSelection(%x) error = %v", value, err)
		}
	}
}

func TestEncodeReadControlValuePreservesEntry(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "jpegPhoto",
			Values:      [][]byte{{0x00, 0xff, 0x10}},
		}},
	}
	packet, err := ber.DecodePacketErr(EncodeReadControlValue(entry))
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if packet.ClassType != ber.ClassApplication ||
		packet.Tag != ApplicationSearchResultEntry ||
		string(packet.Children[0].Data.Bytes()) != entry.DN ||
		!bytes.Equal(
			packet.Children[1].Children[0].Children[1].Children[0].Data.Bytes(),
			entry.Attributes[0].Values[0],
		) {
		t.Fatalf("read control packet = %#v", packet)
	}
}
