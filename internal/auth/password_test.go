package auth

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	password := []byte("correct horse battery staple")
	salt := []byte{0x01, 0x02, 0x03, 0x04}

	sha := sha1.Sum(password)
	sshaInput := append(append([]byte(nil), password...), salt...)
	ssha := sha1.Sum(sshaInput)
	sha256Digest := sha256.Sum256(password)
	ssha256Digest := sha256.Sum256(sshaInput)
	sha384Digest := sha512.Sum384(password)
	ssha384Digest := sha512.Sum384(sshaInput)
	sha512Digest := sha512.Sum512(password)
	ssha512Digest := sha512.Sum512(sshaInput)
	md := md5.Sum(password)
	smdInput := append(append([]byte(nil), password...), salt...)
	smd := md5.Sum(smdInput)
	sm := sm3.Sum(password)
	ssmInput := append(append([]byte(nil), password...), salt...)
	ssm := sm3.Sum(ssmInput)
	pbkdf, err := HashPasswordSMPBKDF2(
		password,
		10,
		bytes.NewReader([]byte{
			0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f,
		}),
	)
	if err != nil {
		t.Fatalf("HashPasswordSMPBKDF2(): %v", err)
	}

	tests := []struct {
		name   string
		stored []byte
		want   bool
	}{
		{name: "plain", stored: password, want: true},
		{name: "cleartext", stored: append([]byte("{CLEARTEXT}"), password...), want: true},
		{name: "sha", stored: encoded("{SHA}", sha[:]), want: true},
		{name: "ssha", stored: encoded("{SSHA}", append(ssha[:], salt...)), want: true},
		{name: "sha256", stored: encoded("{SHA256}", sha256Digest[:]), want: true},
		{name: "ssha256", stored: encoded("{SSHA256}", append(ssha256Digest[:], salt...)), want: true},
		{name: "sha384", stored: encoded("{SHA384}", sha384Digest[:]), want: true},
		{name: "ssha384", stored: encoded("{SSHA384}", append(ssha384Digest[:], salt...)), want: true},
		{name: "sha512", stored: encoded("{SHA512}", sha512Digest[:]), want: true},
		{name: "ssha512", stored: encoded("{SSHA512}", append(ssha512Digest[:], salt...)), want: true},
		{name: "md5", stored: encoded("{MD5}", md[:]), want: true},
		{name: "smd5", stored: encoded("{SMD5}", append(smd[:], salt...)), want: true},
		{name: "sm3", stored: encoded("{SM3}", sm[:]), want: true},
		{name: "ssm3", stored: encoded("{SSM3}", append(ssm[:], salt...)), want: true},
		{name: "pbkdf2 sm3", stored: pbkdf, want: true},
		{name: "unknown scheme", stored: []byte("{ARGON2}value"), want: false},
		{name: "empty", stored: nil, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := VerifyPassword(test.stored, password); got != test.want {
				t.Fatalf("VerifyPassword() = %v, want %v", got, test.want)
			}
			if len(test.stored) > 0 && VerifyPassword(test.stored, []byte("wrong")) {
				t.Fatal("VerifyPassword() accepted an incorrect password")
			}
		})
	}
}

func TestExtractCleartextPassword(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		stored string
		want   string
		ok     bool
	}{
		{stored: "secret", want: "secret", ok: true},
		{stored: "{CLEARTEXT}secret", want: "secret", ok: true},
		{stored: "{cleartext}secret", want: "secret", ok: true},
		{stored: "{CLEARTEXT}"},
		{stored: "{SSHA}not-cleartext"},
		{stored: "{UNKNOWN}secret"},
	} {
		password, ok := ExtractCleartextPassword([]byte(test.stored))
		if ok != test.ok || string(password) != test.want {
			t.Fatalf(
				"ExtractCleartextPassword(%q) = %q, %t",
				test.stored,
				password,
				ok,
			)
		}
	}
}

func TestHashPasswordSMPBKDF2(t *testing.T) {
	t.Parallel()

	password := []byte("correct horse battery staple")
	salt := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}
	stored, err := HashPasswordSMPBKDF2(
		password,
		DefaultSMPBKDF2Iterations,
		bytes.NewReader(salt),
	)
	if err != nil {
		t.Fatalf("HashPasswordSMPBKDF2(): %v", err)
	}
	const want = "{PBKDF2-SM3}100000$AAECAwQFBgcICQoLDA0ODw$" +
		"fUBdjqhPpt3Jslsy6gMRfqrZOD5pSFN65Z53Ef96hkY"
	if string(stored) != want {
		t.Fatalf("stored password = %q, want %q", stored, want)
	}
	if !VerifyPassword(stored, password) {
		t.Fatal("generated PBKDF2-SM3 password did not verify")
	}
	if VerifyPassword(stored, []byte("wrong")) {
		t.Fatal("generated PBKDF2-SM3 password accepted a wrong password")
	}
}

func TestHashPasswordSchemes(t *testing.T) {
	t.Parallel()

	password := []byte("secret")
	tests := []struct {
		scheme string
		prefix string
	}{
		{scheme: "{CLEARTEXT}", prefix: "secret"},
		{scheme: "{SHA}", prefix: "{SHA}"},
		{scheme: "{SSHA}", prefix: "{SSHA}"},
		{scheme: "{SHA256}", prefix: "{SHA256}"},
		{scheme: "{SSHA256}", prefix: "{SSHA256}"},
		{scheme: "{SHA384}", prefix: "{SHA384}"},
		{scheme: "{SSHA384}", prefix: "{SSHA384}"},
		{scheme: "{SHA512}", prefix: "{SHA512}"},
		{scheme: "{SSHA512}", prefix: "{SSHA512}"},
		{scheme: "{MD5}", prefix: "{MD5}"},
		{scheme: "{SMD5}", prefix: "{SMD5}"},
		{scheme: "{SM3}", prefix: "{SM3}"},
		{scheme: "{SSM3}", prefix: "{SSM3}"},
		{scheme: SMPBKDF2HashScheme, prefix: "{PBKDF2-SM3}100000$"},
	}
	for _, test := range tests {
		t.Run(test.scheme, func(t *testing.T) {
			t.Parallel()

			stored, err := HashPassword(
				password,
				strings.ToLower(test.scheme),
				bytes.NewReader(make([]byte, smPasswordSaltSize)),
			)
			if err != nil {
				t.Fatalf("HashPassword(): %v", err)
			}
			if !strings.HasPrefix(string(stored), test.prefix) {
				t.Fatalf("HashPassword() = %q", stored)
			}
			if !VerifyPassword(stored, password) {
				t.Fatal("generated password did not verify")
			}
			if VerifyPassword(stored, []byte("wrong")) {
				t.Fatal("generated password accepted an incorrect value")
			}
		})
	}
}

func TestOpenLDAPSHA2KnownVectors(t *testing.T) {
	t.Parallel()

	for _, stored := range []string{
		"{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
		"{SHA384}WKd1ukESvjAFrkQHznV9iP2nHUBJe7gCbsrFTU4//HIyzo3jq1rLMK45dg/ufFPt",
		"{SHA512}vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==",
	} {
		if !VerifyPassword([]byte(stored), []byte("secret")) {
			t.Fatalf("VerifyPassword(%q) rejected the OpenLDAP vector", stored)
		}
		if VerifyPassword([]byte(stored), []byte("wrong")) {
			t.Fatalf("VerifyPassword(%q) accepted an incorrect password", stored)
		}
	}
}

func TestOpenLDAPDigestBase64Rules(t *testing.T) {
	t.Parallel()

	withWhitespace := []byte(
		"{SHA256}K7gN U3sdo+OL0wNh\tqoVWhr3g6s1x\vYv72ol/pe/Un\fols=\r\n",
	)
	if !VerifyPassword(withWhitespace, []byte("secret")) {
		t.Fatal("VerifyPassword() rejected OpenLDAP Base64 whitespace")
	}
	for _, stored := range []string{
		"{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unolt=",
		"{SHA512}vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/ish==",
	} {
		if VerifyPassword([]byte(stored), []byte("secret")) {
			t.Fatalf("VerifyPassword(%q) accepted nonzero Base64 padding bits", stored)
		}
	}
}

func TestHashOpenLDAPSHA2UsesEightByteSalt(t *testing.T) {
	t.Parallel()

	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, test := range []struct {
		scheme       string
		digestLength int
	}{
		{scheme: "{SSHA256}", digestLength: sha256.Size},
		{scheme: "{SSHA384}", digestLength: sha512.Size384},
		{scheme: "{SSHA512}", digestLength: sha512.Size},
	} {
		stored, err := HashPassword(
			[]byte("secret"),
			test.scheme,
			bytes.NewReader(salt),
		)
		if err != nil {
			t.Fatalf("HashPassword(%s): %v", test.scheme, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(string(stored), test.scheme),
		)
		if err != nil {
			t.Fatalf("decode HashPassword(%s): %v", test.scheme, err)
		}
		if len(decoded) != test.digestLength+len(salt) ||
			!bytes.Equal(decoded[test.digestLength:], salt) {
			t.Fatalf("HashPassword(%s) payload = %x", test.scheme, decoded)
		}
	}
}

func TestVerifyPasswordRejectsMalformedSHA2(t *testing.T) {
	t.Parallel()

	for _, stored := range []string{
		"{SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=",
		"{SHA256}",
		"{SHA256}AAAA",
		"{SHA256}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
		"{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=AAAA",
		"{SSHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
		"{SHA384}AAAA",
		"{SSHA384}WKd1ukESvjAFrkQHznV9iP2nHUBJe7gCbsrFTU4//HIyzo3jq1rLMK45dg/ufFPt",
		"{SHA512}AAAA",
		"{SSHA512}vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==",
	} {
		if VerifyPassword([]byte(stored), []byte("secret")) {
			t.Fatalf("VerifyPassword(%q) accepted malformed SHA-2 data", stored)
		}
	}
}

func TestHashPasswordRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := HashPassword(nil, "{SSHA}", nil); err == nil {
		t.Fatal("empty password was accepted")
	}
	if _, err := HashPassword([]byte("secret"), "{CRYPT}", nil); err == nil {
		t.Fatal("unsupported scheme was accepted")
	}
	if _, err := HashPassword([]byte("secret"), "{SSHA}", errorReader{}); err == nil {
		t.Fatal("salt generation failure was ignored")
	}
	if _, err := HashPassword([]byte("secret"), "{SHA}", errorReader{}); err != nil {
		t.Fatalf("unsalted scheme read random source: %v", err)
	}
}

func TestHashPasswordSMPBKDF2RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := HashPasswordSMPBKDF2(nil, 1, bytes.NewReader(make([]byte, 16))); err == nil {
		t.Fatal("empty password was accepted")
	}
	for _, iterations := range []int{0, -1, MaxSMPBKDF2Iterations + 1} {
		if _, err := HashPasswordSMPBKDF2(
			[]byte("secret"),
			iterations,
			bytes.NewReader(make([]byte, 16)),
		); err == nil {
			t.Fatalf("iterations %d were accepted", iterations)
		}
	}
	if _, err := HashPasswordSMPBKDF2(
		[]byte("secret"),
		1,
		errorReader{},
	); err == nil {
		t.Fatal("salt generation failure was ignored")
	}
}

func TestVerifyPasswordRejectsMalformedSMPBKDF2(t *testing.T) {
	t.Parallel()

	for _, stored := range []string{
		"{PBKDF2-SM3}",
		"{PBKDF2-SM3}0$AAECAwQFBgcICQoLDA0ODw$AAAA",
		"{PBKDF2-SM3}10000001$AAECAwQFBgcICQoLDA0ODw$AAAA",
		"{PBKDF2-SM3}iterations$AAECAwQFBgcICQoLDA0ODw$AAAA",
		"{PBKDF2-SM3}1$invalid*$AAAA",
		"{PBKDF2-SM3}1$AAECAwQFBgcICQoLDA0ODw$AAAA",
		"{PBKDF2-SM3}1$AAECAwQFBgcICQoLDA0ODw$AAAA$extra",
		"{PBKDF2-SM3}1$" + strings.Repeat("A", 1_000_000),
	} {
		if VerifyPassword([]byte(stored), []byte("secret")) {
			t.Fatalf("VerifyPassword(%q) accepted malformed data", stored)
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("random source failed")
}

func encoded(prefix string, value []byte) []byte {
	return []byte(prefix + base64.StdEncoding.EncodeToString(value))
}
