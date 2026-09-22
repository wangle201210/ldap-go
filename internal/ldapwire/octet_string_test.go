package ldapwire

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

// Preserve the original copy-before-write implementation as an oracle.
func octetStringCloneReference(value []byte) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"LDAPString",
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}

func TestOctetStringMatchesCloneReference(t *testing.T) {
	t.Parallel()

	for _, length := range []int{-1, 0, 1, 63, 64, 127, 128, 255, 256, 65535, 65536} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			var value []byte
			if length >= 0 {
				value = bytes.Repeat([]byte{0, 0xff, 0x80}, (length+2)/3)[:length]
			}
			original := bytes.Clone(value)
			got, want := octetString(value), octetStringCloneReference(value)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("packet differs from clone reference")
			}
			encoded := got.Bytes()
			if !bytes.Equal(encoded, want.Bytes()) {
				t.Fatal("encoded bytes differ from clone reference")
			}
			clear(value)
			if !bytes.Equal(got.Bytes(), encoded) {
				t.Fatal("packet aliases the input")
			}
			copy(value, original)
			second := octetString(value)
			clear(encoded)
			if !bytes.Equal(got.Data.Bytes(), original) || !bytes.Equal(value, original) {
				t.Fatal("encoded bytes alias the packet or input")
			}
			clear(got.Data.Bytes())
			if !bytes.Equal(value, original) || !bytes.Equal(second.Data.Bytes(), original) {
				t.Fatal("packet storage aliases the input or another packet")
			}
		})
	}
}

func BenchmarkOctetString(b *testing.B) {
	for _, length := range []int{0, 16, 128, 4096} {
		b.Run(fmt.Sprint(length), func(b *testing.B) {
			value := bytes.Repeat([]byte{0xa5}, length)
			for _, encoder := range []struct {
				name   string
				encode func([]byte) *ber.Packet
			}{
				{name: "Current", encode: octetString},
				{name: "CloneReference", encode: octetStringCloneReference},
			} {
				b.Run(encoder.name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(length))
					for b.Loop() {
						if packet := encoder.encode(value); packet.Data.Len() != length {
							b.Fatal("incorrect content length")
						}
					}
				})
			}
		})
	}
}

func BenchmarkEncodeNonSearchRequest(b *testing.B) {
	const dn = "uid=alice,dc=example,dc=com"
	for _, length := range []int{16, 4096} {
		value := bytes.Repeat([]byte{0, 0xff, 0x80, 0x42}, length/4)
		for _, fixture := range []struct {
			name    string
			request Request
		}{
			{
				name: "BindSimple",
				request: BindRequest{Version: 3, Name: dn, Authentication: Authentication{
					Simple: value,
				}},
			},
			{
				name: "BindSASL",
				request: BindRequest{Version: 3, Name: dn, Authentication: Authentication{
					IsSASL: true, SASLMechanism: "PLAIN", HasSASLCredentials: true,
					SASLCredentials: value,
				}},
			},
			{
				name:    "Compare",
				request: CompareRequest{DN: dn, Attribute: "jpegPhoto", Assertion: value},
			},
			{
				name: "Modify",
				request: ModifyRequest{DN: dn, Changes: []Modification{
					{Operation: ModificationReplace, Attribute: directory.Attribute{
						Description: "jpegPhoto", Values: [][]byte{value},
					}},
					{Operation: ModificationDelete, Attribute: directory.Attribute{
						Description: "description", Values: [][]byte{},
					}},
				}},
			},
		} {
			b.Run(fmt.Sprintf("%s/%d", fixture.name, length), func(b *testing.B) {
				message := Message{ID: 128, Request: fixture.request, Controls: []Control{
					{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 0xff}},
					{OID: "1.2.4", HasValue: true},
				}}
				encoded, err := EncodeRequestMessage(message)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(encoded)))
				for b.Loop() {
					got, err := EncodeRequestMessage(message)
					if err != nil || len(got) != len(encoded) {
						b.Fatalf("encode: length %d, error %v", len(got), err)
					}
				}
			})
		}
	}
}
