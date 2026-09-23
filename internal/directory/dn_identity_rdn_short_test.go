package directory

import (
	"bytes"
	"testing"
)

func singleAVARDNReference(encoded []byte) bool {
	rdns, err := decodeDNIdentityParts(encoded)
	if err != nil || len(rdns) != 1 {
		return false
	}
	ava, err := decodeDNIdentityParts(rdns[0])
	return err == nil && len(ava) == 2 && len(ava[0]) != 0
}

func singleAVARDNFixtures() [][]byte {
	fixtures := [][]byte{nil, {}, {1}, {1, 0}, {0}, {1, 4, 2, 1, 'x', 0}}
	for _, attributeLength := range []int{0, 1, 7, 120, 127, 128, 129} {
		for _, valueLength := range []int{0, 1, 7, 120, 127, 128, 129} {
			ava := encodeDNIdentityParts(bytes.Repeat([]byte("a"), attributeLength), bytes.Repeat([]byte("v"), valueLength))
			encoded := encodeDNIdentityParts(ava)
			fixtures = append(fixtures, encoded, append([]byte{0x81, 0}, encoded[1:]...))
		}
	}
	return fixtures
}

func checkSingleAVARDN(t testing.TB, encoded []byte) {
	t.Helper()
	want := singleAVARDNReference(encoded)
	if got := validSingleAVADNIdentityRDN(encoded); got != want {
		t.Fatalf("RDN %x: got %t, want %t", encoded, got, want)
	}
}

func TestSingleAVARDNShortFramingReference(t *testing.T) {
	for _, encoded := range singleAVARDNFixtures() {
		checkSingleAVARDN(t, encoded)
		for end := range len(encoded) {
			checkSingleAVARDN(t, encoded[:end])
		}
		checkSingleAVARDN(t, append(bytes.Clone(encoded), 0))
		mutated := bytes.Clone(encoded)
		for offset := range len(encoded) {
			if offset >= 16 && offset != len(encoded)-1 {
				continue
			}
			for replacement := range 256 {
				mutated[offset] = byte(replacement)
				checkSingleAVARDN(t, mutated)
			}
			mutated[offset] = encoded[offset]
		}
	}
}

func FuzzSingleAVARDNReference(f *testing.F) {
	for _, encoded := range singleAVARDNFixtures() {
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		checkSingleAVARDN(t, encoded)
	})
}
