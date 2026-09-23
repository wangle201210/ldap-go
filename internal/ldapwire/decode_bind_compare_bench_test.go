package ldapwire

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkReadBindCompareMessage(b *testing.B) {
	benchmarkReadBindCompareMessage(b, ReadMessageWithDynamicFilterDepthAndSize)
}

func BenchmarkReadBindCompareMessagePacketReference(b *testing.B) {
	benchmarkReadBindCompareMessage(b, readSearchMessageReference)
}

func benchmarkReadBindCompareMessage(b *testing.B, read func(io.Reader, int64, uint64, func() int) (Message, int, error)) {
	fixtures := bindCompareDecodeFixtures(b)
	for _, name := range []string{"Bind", "AnonymousBind", "BinaryBind", "Compare", "EmptyCompare", "BinaryCompare", "BindControls", "CompareControls", "SASL", "LongBind", "LongCompare", "LongDNBind", "LongDNCompare", "LongAttributeCompare", "LongBindControls", "LongCompareControls"} {
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

func BenchmarkBindCompareFrameFallback(b *testing.B) {
	fixtures := bindCompareDecodeFixtures(b)
	for _, name := range []string{"BindControls", "CompareControls", "SASL", "LongBindControls", "LongCompareControls"} {
		b.Run(name, func(b *testing.B) {
			frame := fixtures[name]
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := decodeBindCompareFrame(frame); ok {
					b.Fatal("unexpected fast path match")
				}
			}
		})
	}
}
