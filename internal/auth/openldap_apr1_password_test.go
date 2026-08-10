package auth

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"strings"
	"testing"
)

func TestHashPasswordOpenLDAPPHK(t *testing.T) {
	t.Parallel()

	random := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	for _, scheme := range []string{
		OpenLDAPAPR1HashScheme,
		OpenLDAPBSDMD5HashScheme,
	} {
		stored, err := HashPassword(
			[]byte("secret"),
			strings.ToLower(scheme),
			bytes.NewReader(random),
		)
		if err != nil {
			t.Fatalf("HashPassword(%s): %v", scheme, err)
		}
		if !strings.HasPrefix(string(stored), scheme) {
			t.Fatalf("HashPassword(%s) = %q", scheme, stored)
		}
		decoded, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(string(stored), scheme),
		)
		if err != nil {
			t.Fatalf("decode HashPassword(%s): %v", scheme, err)
		}
		if len(decoded) != md5.Size+openLDAPAPR1SaltSize ||
			string(decoded[md5.Size:]) != "./012345" {
			t.Fatalf("HashPassword(%s) payload = %x", scheme, decoded)
		}
		if !VerifyPassword(stored, []byte("secret")) {
			t.Fatalf("VerifyPassword() rejected generated %s value", scheme)
		}
		if VerifyPassword(stored, []byte("wrong")) {
			t.Fatalf("VerifyPassword() accepted an incorrect %s password", scheme)
		}
		spaced := []byte(scheme + strings.Repeat(" ", 128) + strings.TrimPrefix(string(stored), scheme))
		if !VerifyPassword(spaced, []byte("secret")) {
			t.Fatalf("VerifyPassword() rejected whitespace in %s Base64", scheme)
		}
		oversizedStored := []byte(
			scheme + strings.Repeat(" ", maxOpenLDAPPHKStoredSize+1) +
				strings.TrimPrefix(string(stored), scheme),
		)
		if VerifyPassword(oversizedStored, []byte("secret")) {
			t.Fatalf("VerifyPassword() accepted oversized valid %s data", scheme)
		}
	}
}

func TestVerifyOpenLDAPPHKImportedSalt(t *testing.T) {
	t.Parallel()

	password := []byte("secret")
	salt := []byte("nonstandard-imported-salt")
	for _, scheme := range []string{
		OpenLDAPAPR1HashScheme,
		OpenLDAPBSDMD5HashScheme,
	} {
		magic, _ := openLDAPPHKMagic(scheme)
		digest := openLDAPPHKDigest(password, salt, magic)
		payload := append(append([]byte(nil), digest[:]...), salt...)
		stored := []byte(scheme + base64.StdEncoding.EncodeToString(payload))
		if !VerifyPassword(stored, password) {
			t.Fatalf("VerifyPassword() rejected imported %s salt", scheme)
		}
	}
}

func TestVerifyOpenLDAPPHKRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	noSalt := base64.StdEncoding.EncodeToString(make([]byte, md5.Size))
	for _, stored := range []string{
		OpenLDAPAPR1HashScheme,
		OpenLDAPAPR1HashScheme + "AAAA",
		OpenLDAPAPR1HashScheme + noSalt,
		OpenLDAPAPR1HashScheme + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
		OpenLDAPBSDMD5HashScheme + noSalt,
	} {
		if VerifyPassword([]byte(stored), []byte("secret")) {
			t.Fatalf("VerifyPassword(%q) accepted malformed PHK data", stored)
		}
	}
	oversizedSalt := bytes.Repeat([]byte{'s'}, maxOpenLDAPPHKSaltSize+1)
	magic, _ := openLDAPPHKMagic(OpenLDAPAPR1HashScheme)
	digest := openLDAPPHKDigest([]byte("secret"), oversizedSalt, magic)
	payload := append(append([]byte(nil), digest[:]...), oversizedSalt...)
	stored := []byte(OpenLDAPAPR1HashScheme + base64.StdEncoding.EncodeToString(payload))
	if VerifyPassword(stored, []byte("secret")) {
		t.Fatal("VerifyPassword() accepted a valid record with an oversized salt")
	}
}

func TestVerifyOpenLDAPPHKRejectsNonzeroBase64TailBits(t *testing.T) {
	t.Parallel()

	password := []byte("secret")
	salt := []byte{'x'}
	magic, _ := openLDAPPHKMagic(OpenLDAPAPR1HashScheme)
	digest := openLDAPPHKDigest(password, salt, magic)
	payload := append(append([]byte(nil), digest[:]...), salt...)
	encoded := []byte(base64.StdEncoding.EncodeToString(payload))
	if !VerifyPassword(
		append([]byte(OpenLDAPAPR1HashScheme), encoded...),
		password,
	) {
		t.Fatal("VerifyPassword() rejected valid one-byte salt")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := strings.IndexByte(alphabet, encoded[len(encoded)-2])
	if index < 0 || index&0x03 != 0 {
		t.Fatalf("unexpected Base64 tail %q", encoded)
	}
	encoded[len(encoded)-2] = alphabet[index|1]
	if VerifyPassword(
		append([]byte(OpenLDAPAPR1HashScheme), encoded...),
		password,
	) {
		t.Fatal("VerifyPassword() accepted nonzero Base64 tail bits")
	}
}

func TestHashPasswordOpenLDAPPHKRejectsRandomFailure(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{
		OpenLDAPAPR1HashScheme,
		OpenLDAPBSDMD5HashScheme,
	} {
		if _, err := HashPassword([]byte("secret"), scheme, errorReader{}); err == nil {
			t.Fatalf("HashPassword(%s) ignored random source failure", scheme)
		}
	}
}

func TestOpenLDAPPHKRejectsOversizedPassword(t *testing.T) {
	t.Parallel()

	oversized := bytes.Repeat([]byte{'x'}, maxOpenLDAPPHKPasswordSize+1)
	for _, scheme := range []string{
		OpenLDAPAPR1HashScheme,
		OpenLDAPBSDMD5HashScheme,
	} {
		magic, _ := openLDAPPHKMagic(scheme)
		salt := []byte("........")
		digest := openLDAPPHKDigest(oversized, salt, magic)
		payload := append(append([]byte(nil), digest[:]...), salt...)
		stored := []byte(scheme + base64.StdEncoding.EncodeToString(payload))
		if VerifyPassword(stored, oversized) {
			t.Fatalf("VerifyPassword(%s) accepted an oversized password", scheme)
		}
		if _, err := HashPassword(
			oversized,
			scheme,
			bytes.NewReader(make([]byte, openLDAPAPR1SaltSize)),
		); err == nil {
			t.Fatalf("HashPassword(%s) accepted an oversized password", scheme)
		}
	}
}
