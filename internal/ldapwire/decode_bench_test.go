package ldapwire

import (
	"bytes"
	"io"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func searchDecodeFixtures(tb testing.TB) map[string][]byte {
	tb.Helper()
	equality := directory.Filter{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("alice")}
	fixtures := make(map[string][]byte)
	for _, name := range []string{"Equality", "Presence", "Controls", "Nested", "Long"} {
		message := Message{ID: 1234, Request: SearchRequest{
			BaseDN: "dc=example,dc=com", Scope: directory.ScopeWholeSubtree,
			Filter: equality, Attributes: []string{"uid", "cn", "mail"},
		}}
		request := message.Request.(SearchRequest)
		switch name {
		case "Presence":
			request.Filter = directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"}
			request.Attributes = []string{}
		case "Controls":
			message.Controls = []Control{{OID: "1.2.840.113556.1.4.319", HasValue: true,
				Value: []byte{0x30, 0x05, 0x02, 0x01, 0x05, 0x04, 0x00}}}
		case "Nested":
			request.Filter = directory.Filter{Kind: directory.FilterAnd, Children: []directory.Filter{
				equality, {Kind: directory.FilterPresent, Attribute: "objectClass"},
			}}
		case "Long":
			request.Filter.Assertion = bytes.Repeat([]byte("a"), 256)
		}
		message.Request = request
		encoded, err := EncodeRequestMessage(message)
		if err != nil {
			tb.Fatal(err)
		}
		fixtures[name] = encoded
	}
	return fixtures
}

func BenchmarkReadSearchMessage(b *testing.B) {
	benchmarkReadSearchMessage(b, ReadMessageWithDynamicFilterDepthAndSize)
}

func BenchmarkReadSearchMessagePacketReference(b *testing.B) {
	benchmarkReadSearchMessage(b, readSearchMessageReference)
}

func BenchmarkShortSearchFrameFallback(b *testing.B) {
	fixtures := searchDecodeFixtures(b)
	for _, name := range []string{"Controls", "Nested", "Long"} {
		b.Run(name, func(b *testing.B) {
			frame := fixtures[name]
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := decodeShortSearchFrame(frame); ok {
					b.Fatal("unexpected fast path match")
				}
			}
		})
	}
}

func benchmarkReadSearchMessage(b *testing.B, read func(io.Reader, int64, uint64, func() int) (Message, int, error)) {
	fixtures := searchDecodeFixtures(b)
	for _, name := range []string{"Equality", "Presence", "Controls", "Nested", "Long"} {
		b.Run(name, func(b *testing.B) {
			frame := fixtures[name]
			reader := bytes.NewReader(frame)
			depth := func() int { return DefaultMaxFilterDepth }
			b.ReportAllocs()
			b.SetBytes(int64(len(frame)))
			b.ResetTimer()
			for b.Loop() {
				reader.Reset(frame)
				message, size, err := read(reader, DefaultMaxMessageSize, 0, depth)
				if err != nil || message.ID != 1234 || size != len(frame) {
					b.Fatalf("decode: %#v, size %d, error %v", message, size, err)
				}
			}
		})
	}
}

func BenchmarkSearchDecodeStages(b *testing.B) {
	frame := searchDecodeFixtures(b)["Equality"]
	b.Run("Frame", func(b *testing.B) {
		reader := bytes.NewReader(frame)
		b.ReportAllocs()
		for b.Loop() {
			reader.Reset(frame)
			if _, err := readFrame(reader, DefaultMaxMessageSize); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("BER", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ber.DecodePacketErr(frame); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Request", func(b *testing.B) {
		packet, err := ber.DecodePacketErr(frame)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := decodeMessageWithFilterDepth(packet, DefaultMaxFilterDepth); err != nil {
				b.Fatal(err)
			}
		}
	})
}
