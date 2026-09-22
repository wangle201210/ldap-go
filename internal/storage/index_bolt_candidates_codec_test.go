package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func encodeCandidateTestEntry(t testing.TB, entry directory.Entry, identity, format string) []byte {
	t.Helper()
	if format == "json" {
		encoded, err := json.Marshal(storedEntry{Entry: entry, DNIdentity: identity, DNSource: entry.DN})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	var encoded []byte
	if format == "v1" {
		encoded = bytes.Clone(entryBinaryV1Prefix)
	} else if format == "v2" {
		encoded = bytes.Clone(entryBinaryPrefix)
	} else {
		encoded = bytes.Clone(entryBinaryV3Prefix)
		flags := make([]byte, (len(entry.Attributes)+7)/8)
		for i, attribute := range entry.Attributes {
			if attribute.RawNormalized {
				flags[i/8] |= 1 << uint(i%8)
			}
		}
		encoded = appendEntryBinaryField(encoded, flags)
	}
	encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
	if format == "v1" {
		encoded = appendEntryBinaryField(encoded, []byte(identity))
		encoded = appendEntryBinaryField(encoded, []byte(entry.DN))
	} else {
		binding := entryDNBinding(identity, entry.DN)
		encoded = appendEntryBinaryField(encoded, binding[:])
	}
	encoded = binary.AppendUvarint(encoded, uint64(len(entry.Attributes)))
	for _, attribute := range entry.Attributes {
		encoded = appendEntryBinaryField(encoded, []byte(attribute.Description))
		encoded = binary.AppendUvarint(encoded, uint64(len(attribute.Values)))
		for _, value := range attribute.Values {
			encoded = appendEntryBinaryField(encoded, value)
		}
	}
	return encoded
}

func candidateCodecSeeds(t testing.TB) [][]byte {
	t.Helper()
	var seeds [][]byte
	for _, format := range []string{"v1", "v2", "v3"} {
		for _, count := range []int{0, 1, 7, 8, 9, 16} {
			entry := directory.Entry{DN: "uid=alice,dc=example"}
			for i := 0; i < count; i++ {
				entry.Attributes = append(entry.Attributes, directory.Attribute{
					Description: "a", RawNormalized: i%2 == 0,
					Values: [][]byte{{}, {0, 0xff}, []byte("second")},
				})
			}
			seeds = append(seeds, encodeCandidateTestEntry(t, entry, "dn:v2:identity", format))
		}
	}
	seeds = append(seeds,
		append(bytes.Clone(entryBinaryPrefix), 0x80, 0, 0x80, 0, 0x81, 0, 0x81, 0, 'a', 0x81, 0, 0x80, 0),
		append(bytes.Clone(entryBinaryPrefix), 0, 0, 0),
		append(bytes.Clone(entryBinaryPrefix), 0, 0, 1, 0, 0),
		append(bytes.Clone(entryBinaryPrefix), 0, 0, 1, 0, 2, 0, 0),
	)
	overflow := binary.AppendUvarint(nil, ^uint64(0))
	for _, payload := range [][]byte{
		overflow, append([]byte{1, 0}, overflow...),
		{1, 0, 1, 0x80}, {2, 0, 0, 0x80}, {2, 0}, {1, 0, 2, 0},
	} {
		seeds = append(seeds, append(append(bytes.Clone(entryBinaryPrefix), 0, 0), payload...))
	}
	return seeds
}

func assertCandidateValidationMatchesDecoder(t testing.TB, value []byte) {
	t.Helper()
	_, err := decodeStoredEntry(value)
	binary := bytes.HasPrefix(value, entryBinaryV1Prefix) ||
		bytes.HasPrefix(value, entryBinaryPrefix) || bytes.HasPrefix(value, entryBinaryV3Prefix)
	if got, want := validBinaryCandidateEntry(value), binary && err == nil; got != want {
		t.Fatalf("validation(%x) = %v; decode error = %v", value, got, err)
	}
}

func TestBinaryCandidateValidationDifferential(t *testing.T) {
	for _, seed := range candidateCodecSeeds(t) {
		assertCandidateValidationMatchesDecoder(t, seed)
		for end := 0; end < len(seed); end++ {
			assertCandidateValidationMatchesDecoder(t, seed[:end])
		}
		for index := range seed {
			for _, mask := range []byte{1, 0x80, 0xff} {
				mutated := bytes.Clone(seed)
				mutated[index] ^= mask
				assertCandidateValidationMatchesDecoder(t, mutated)
			}
		}
		assertCandidateValidationMatchesDecoder(t, append(bytes.Clone(seed), 0))
	}
	for _, format := range []string{"v1", "v2", "v3"} {
		value := encodeCandidateTestEntry(t, benchmarkBinaryEntryCodecEntry(), "dn:v2:identity", format)
		original := bytes.Clone(value)
		if allocs := testing.AllocsPerRun(100, func() {
			if !validBinaryCandidateEntry(value) {
				t.Fatal("valid entry rejected")
			}
		}); allocs != 0 {
			t.Fatalf("%s validation allocs = %v", format, allocs)
		}
		if !bytes.Equal(value, original) {
			t.Fatal("validation changed input")
		}
	}
}

func FuzzBinaryCandidateValidation(f *testing.F) {
	for _, seed := range candidateCodecSeeds(f) {
		f.Add(seed)
	}
	f.Add([]byte(`{"dn":"cn=example","attributes":[]}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, value []byte) {
		assertCandidateValidationMatchesDecoder(t, value)
	})
}
