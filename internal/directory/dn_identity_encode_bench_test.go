package directory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

func dnIdentityPartsAppendReference(parts ...[]byte) []byte {
	result := make([]byte, 0)
	result = binary.AppendUvarint(result, uint64(len(parts)))
	for _, part := range parts {
		result = binary.AppendUvarint(result, uint64(len(part)))
		result = append(result, part...)
	}
	return result
}

func dnIdentityEncodeReference(parts [][]byte) string {
	return schemaAwareDNKeyPrefix + base64.RawURLEncoding.EncodeToString(dnIdentityPartsAppendReference(parts...))
}

func TestDNIdentityEncodingCapacityAndOwnership(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3, 127, 128, 129} {
		for _, length := range []int{0, 1, 2, 127, 128, 129, 249, 250, 251, 255, 256, 257, 375, 376, 377, 16383, 16384} {
			parts := make([][]byte, count)
			for i := range parts {
				parts[i] = bytes.Repeat([]byte{byte(i), 0, 255}, (length+2)/3)[:length]
			}
			wantParts := dnIdentityPartsAppendReference(parts...)
			wantKey := dnIdentityEncodeReference(parts)
			gotParts, gotKey := encodeDNIdentityParts(parts...), encodeDNIdentity(parts)
			if !bytes.Equal(gotParts, wantParts) || gotKey != wantKey || dnIdentityPartsSize(parts) != len(wantParts) {
				t.Fatalf("count=%d length=%d: encoding differs", count, length)
			}
			for _, part := range parts {
				clear(part)
			}
			if !bytes.Equal(gotParts, wantParts) || gotKey != wantKey {
				t.Fatalf("count=%d length=%d: result aliases input", count, length)
			}
			clear(gotParts)
			if gotKey != wantKey {
				t.Fatal("key aliases another encoding")
			}
		}
	}
}

func BenchmarkDNIdentityEncoding(b *testing.B) {
	for _, count := range []int{1, 4, 16} {
		parts := make([][]byte, count)
		for i := range parts {
			parts[i] = dnIdentityPartsAppendReference(dnIdentityPartsAppendReference([]byte("0.9.2342.19200300.100.1.1"), []byte(fmt.Sprintf("user%06d", i))))
		}
		want := dnIdentityEncodeReference(parts)
		for _, method := range []struct {
			name   string
			encode func([][]byte) string
		}{
			{"reference", dnIdentityEncodeReference}, {"current", encodeDNIdentity},
		} {
			b.Run(fmt.Sprintf("RDNs%d/%s", count, method.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if got := method.encode(parts); got != want {
						b.Fatal("encoding differs")
					}
				}
			})
		}
	}
}
