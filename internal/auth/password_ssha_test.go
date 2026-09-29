package auth

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"strings"
	"testing"
)

func TestVerifySSHABoundariesAndOwnership(t *testing.T) {
	t.Parallel()

	for _, passwordLength := range []int{1, 27, 51, 52, 55, 56, 63, 64, 65, 251, 252, 253, 256, 1024} {
		for _, saltLength := range []int{1, 2, 3, 4, 12, 43, 44, 45, 46, 257} {
			t.Run(fmt.Sprintf("password=%d/salt=%d", passwordLength, saltLength), func(t *testing.T) {
				// Spare capacity and binary bytes expose accidental appends to caller data.
				backing := bytes.Repeat([]byte{0xa5}, passwordLength+saltLength+16)
				password := backing[:passwordLength]
				for index := range password {
					password[index] = byte(index)
				}
				beforePassword := bytes.Clone(backing)
				salt := bytes.Repeat([]byte{0x81}, saltLength)
				stored := sshaTestStored(password, salt)
				beforeStored := bytes.Clone(stored)
				wrong := bytes.Clone(password)
				wrong[0] ^= 1
				for _, supplied := range [][]byte{password, wrong, nil} {
					want := len(supplied) > 0 && bytes.Equal(supplied, password)
					if got := VerifyPassword(stored, supplied); got != want {
						t.Fatalf("VerifyPassword() = %t, want %t", got, want)
					}
					if got := legacyVerifySSHAPassword(stored, supplied); got != want {
						t.Fatalf("legacy verifier = %t, want %t", got, want)
					}
				}
				if !bytes.Equal(backing, beforePassword) || !bytes.Equal(stored, beforeStored) {
					t.Fatal("verification mutated caller-owned bytes")
				}
			})
		}
	}
}

func TestVerifySSHABase64Semantics(t *testing.T) {
	t.Parallel()

	password := []byte("secret")
	stored := sshaTestStored(password, []byte{1, 2, 3, 4})
	payload := string(stored[len(OpenLDAPDefaultHashScheme):])
	var spaced strings.Builder
	for index := range payload {
		spaced.WriteString(" \t\r\n\v\f")
		spaced.WriteByte(payload[index])
	}
	spaced.WriteString(" \t\r\n\v\f")
	// A 22-byte decoded value has two padding bytes and four unused bits.
	padded := sshaTestStored(password, []byte{1, 2})
	nonzeroPadding := bytes.Clone(padded)
	nonzeroPadding[len(nonzeroPadding)-3] = 'h' // Canonical encoding ends in Ag==.
	for _, test := range []struct {
		name   string
		stored []byte
		want   bool
	}{
		{name: "canonical", stored: stored, want: true},
		{name: "mixed case scheme", stored: []byte("{sShA}" + payload), want: true},
		{name: "OpenLDAP whitespace", stored: []byte("{SSHA}" + spaced.String()), want: true},
		{name: "canonical padding", stored: padded, want: true},
		{name: "nonzero padding bits", stored: nonzeroPadding},
		{name: "no salt", stored: sshaTestStored(password, nil)},
		{name: "empty payload", stored: []byte("{SSHA}")},
		{name: "short digest", stored: []byte("{SSHA}AAAA")},
		{name: "truncated quartet", stored: stored[:len(stored)-1]},
		{name: "invalid byte", stored: []byte("{SSHA}!" + payload[1:])},
		{name: "trailing invalid byte", stored: []byte(string(stored) + "!")},
		{name: "data after padding", stored: []byte(string(padded) + "AAAA")},
		{name: "missing padding", stored: padded[:len(padded)-2]},
		{name: "extra padding", stored: []byte(string(stored) + "=")},
		{name: "non ASCII whitespace", stored: []byte("{SSHA}\xc2\xa0" + payload)},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := bytes.Clone(test.stored)
			for _, supplied := range [][]byte{password, []byte("wrong"), nil} {
				want := test.want && bytes.Equal(supplied, password)
				got := VerifyPassword(test.stored, supplied)
				legacy := legacyVerifySSHAPassword(test.stored, supplied)
				if got != want || got != legacy {
					t.Fatalf("VerifyPassword() = %t, legacy = %t, want %t", got, legacy, want)
				}
			}
			if !bytes.Equal(test.stored, before) {
				t.Fatal("verification mutated stored bytes")
			}
		})
	}
}

func FuzzVerifySSHAEquivalence(f *testing.F) {
	for _, saltLength := range []int{1, 4, 12, 43, 44, 257} {
		password := []byte("secret")
		stored := sshaTestStored(password, bytes.Repeat([]byte{1}, saltLength))
		f.Add(stored[len(OpenLDAPDefaultHashScheme):], password)
	}
	f.Add([]byte("AAAA \t\r\n\v\f"), []byte("wrong"))
	f.Fuzz(func(t *testing.T, payload, supplied []byte) {
		stored := append([]byte(OpenLDAPDefaultHashScheme), payload...)
		if got, want := VerifyPassword(stored, supplied), legacyVerifySSHAPassword(stored, supplied); got != want {
			t.Fatalf("VerifyPassword() = %t, legacy = %t", got, want)
		}
	})
}

func sshaTestStored(password, salt []byte) []byte {
	digest := sha1.New()
	digest.Write(password)
	digest.Write(salt)
	return encoded(OpenLDAPDefaultHashScheme, append(digest.Sum(nil), salt...))
}

// Retain the previous SSHA branch for equivalence checks and paired benchmarks.
func legacyVerifySSHAPassword(stored, supplied []byte) bool {
	if len(stored) == 0 || len(supplied) == 0 {
		return false
	}
	_, payload := legacySSHASplitScheme(stored)
	return verifyDigest(payload, supplied, true, sha1.Size, func(value []byte) []byte {
		digest := sha1.Sum(value)
		return digest[:]
	})
}

func legacySSHASplitScheme(stored []byte) (string, []byte) {
	if len(stored) < 3 || stored[0] != '{' {
		return "", stored
	}
	end := strings.IndexByte(string(stored), '}')
	if end <= 1 {
		return "", stored
	}
	return strings.ToUpper(string(stored[1:end])), stored[end+1:]
}

func BenchmarkVerifySSHA(b *testing.B) {
	for _, fixture := range []struct {
		name           string
		passwordLength int
		saltLength     int
		whitespace     bool
	}{
		{name: "default", passwordLength: 27, saltLength: 4},
		{name: "imported salt", passwordLength: 27, saltLength: 12},
		{name: "long password", passwordLength: 1024, saltLength: 4},
		{name: "long salt", passwordLength: 27, saltLength: 257},
		{name: "whitespace", passwordLength: 27, saltLength: 4, whitespace: true},
	} {
		password := bytes.Repeat([]byte{'p'}, fixture.passwordLength)
		stored := sshaTestStored(password, bytes.Repeat([]byte{1}, fixture.saltLength))
		if fixture.whitespace {
			stored = append(stored, ' ', '\t', '\n')
		}
		for _, correct := range []bool{true, false} {
			supplied := bytes.Clone(password)
			if !correct {
				supplied[0] ^= 1
			}
			for _, implementation := range []struct {
				name   string
				verify func([]byte, []byte) bool
			}{
				{name: "legacy", verify: legacyVerifySSHAPassword},
				{name: "current", verify: VerifyPassword},
			} {
				b.Run(fmt.Sprintf("%s/correct=%t/%s", fixture.name, correct, implementation.name), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if got := implementation.verify(stored, supplied); got != correct {
							b.Fatalf("VerifyPassword() = %t, want %t", got, correct)
						}
					}
				})
			}
		}
	}
}
