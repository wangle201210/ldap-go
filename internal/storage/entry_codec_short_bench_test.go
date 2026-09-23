package storage

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func BenchmarkEntryCodecShortField(b *testing.B) {
	for _, shape := range []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{0, 1, 'x'}},
		{"Tiny", appendEntryBinaryField(nil, []byte("alice@example.com"))},
		{"Boundary127", appendEntryBinaryField(nil, bytes.Repeat([]byte("x"), 127))},
		{"Long128", appendEntryBinaryField(nil, bytes.Repeat([]byte("x"), 128))},
		{"Long4096", appendEntryBinaryField(nil, bytes.Repeat([]byte("x"), 4096))},
		{"Nonminimal", []byte{0x81, 0, 'x', 0}},
		{"TruncatedTiny", []byte{2, 'x'}},
		{"TruncatedLong", []byte{0x80, 1, 'x'}},
		{"TruncatedVarint", []byte{0x80}},
		{"Overflow", bytes.Repeat([]byte{0xff}, 10)},
	} {
		for _, implementation := range []struct {
			name    string
			consume func([]byte) ([]byte, []byte, error)
		}{
			{"Original", entryCodecShortOriginalField},
			{"Current", consumeEntryBinaryField},
		} {
			b.Run(shape.name+"/"+implementation.name, func(b *testing.B) {
				want, wantRest, wantErr := entryCodecShortOriginalField(shape.input)
				var got, rest []byte
				var err error
				b.ReportAllocs()
				for b.Loop() {
					got, rest, err = implementation.consume(shape.input)
				}
				if !bytes.Equal(got, want) || !bytes.Equal(rest, wantRest) || (err == nil) != (wantErr == nil) {
					b.Fatal("unexpected field result")
				}
			})
		}
	}
}

func BenchmarkEntryCodecShortCount(b *testing.B) {
	for _, shape := range []struct {
		name  string
		input []byte
	}{
		{"Zero", []byte{0}},
		{"Tiny", []byte{3, 2, 'c', 'n', 1, 1, 'x'}},
		{"Boundary127", []byte{127, 0}},
		{"Long128", binary.AppendUvarint(nil, 128)},
		{"Long16384", binary.AppendUvarint(nil, 16384)},
		{"Nonminimal", []byte{0x81, 0, 0}},
		{"TruncatedVarint", []byte{0x80}},
		{"OverflowVarint", bytes.Repeat([]byte{0xff}, 10)},
		{"OverflowInt", binary.AppendUvarint(nil, ^uint64(0))},
	} {
		for _, implementation := range []struct {
			name    string
			consume func([]byte) (int, []byte, error)
		}{
			{"Original", entryCodecShortOriginalCount},
			{"Current", consumeEntryBinaryCount},
		} {
			b.Run(shape.name+"/"+implementation.name, func(b *testing.B) {
				want, wantRest, wantErr := entryCodecShortOriginalCount(shape.input)
				var got int
				var rest []byte
				var err error
				b.ReportAllocs()
				for b.Loop() {
					got, rest, err = implementation.consume(shape.input)
				}
				if got != want || !bytes.Equal(rest, wantRest) || (err == nil) != (wantErr == nil) {
					b.Fatal("unexpected count result")
				}
			})
		}
	}
}
