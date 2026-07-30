package auth

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
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
