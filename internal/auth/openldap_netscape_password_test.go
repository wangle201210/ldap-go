package auth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVerifyOpenLDAPNetscapeKnownVectors(t *testing.T) {
	t.Parallel()

	const salt = "0123456789abcdefghijklmnopqrstuv"
	for _, test := range []struct {
		name     string
		password []byte
		digest   string
	}{
		{
			name:     "password",
			password: []byte("password"),
			digest:   "61eeba12f15aaefe2569e77ee5c3d05c",
		},
		{
			name:     "empty password",
			password: nil,
			digest:   "0254eff6c8cb973fd4b38ed7f5654cb4",
		},
		{
			name:     "binary password",
			password: []byte("p\xc3\xa4ss\x00word"),
			digest:   "0bd5b62ed6958cab903e2744c71e9070",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			payload := []byte(test.digest + salt)
			if !verifyOpenLDAPNetscape(payload, test.password) {
				t.Fatal("verifyOpenLDAPNetscape() rejected a known vector")
			}
			if verifyOpenLDAPNetscape(payload, append(bytes.Clone(test.password), 'x')) {
				t.Fatal("verifyOpenLDAPNetscape() accepted an incorrect password")
			}
		})
	}
}

func TestVerifyOpenLDAPNetscapePublicIntegration(t *testing.T) {
	t.Parallel()

	const payload = "61eeba12f15aaefe2569e77ee5c3d05c" +
		"0123456789abcdefghijklmnopqrstuv"
	stored := []byte(strings.ToLower(OpenLDAPNetscapeMTAHashScheme) + payload)
	if !VerifyPassword(stored, []byte("password")) {
		t.Fatal("VerifyPassword() rejected a Netscape password")
	}
	if VerifyPassword(stored, []byte("wrong")) {
		t.Fatal("VerifyPassword() accepted an incorrect Netscape password")
	}
	normalized, err := NormalizePasswordHashScheme(
		strings.ToLower(OpenLDAPNetscapeMTAHashScheme),
	)
	if err != nil || normalized != OpenLDAPNetscapeMTAHashScheme {
		t.Fatalf("NormalizePasswordHashScheme() = %q, %v", normalized, err)
	}
	if !IsKnownPasswordScheme(" \t" + strings.ToLower(OpenLDAPNetscapeMTAHashScheme) + "\n") {
		t.Fatal("IsKnownPasswordScheme() rejected a verify-only scheme")
	}
	if _, err := HashPassword(
		[]byte("password"),
		OpenLDAPNetscapeMTAHashScheme,
		nil,
	); !errors.Is(err, ErrPasswordHashUnavailable) {
		t.Fatalf("HashPassword() error = %v, want unavailable hash", err)
	}
	if _, err := HashPassword(
		nil,
		strings.ToLower(OpenLDAPNetscapeMTAHashScheme),
		nil,
	); !errors.Is(err, ErrPasswordHashUnavailable) {
		t.Fatalf("HashPassword(empty) error = %v, want unavailable hash", err)
	}
	if IsKnownPasswordScheme("{UNKNOWN}") {
		t.Fatal("IsKnownPasswordScheme() accepted an unknown scheme")
	}
}

func TestVerifyOpenLDAPNetscapeBinarySaltAndPassword(t *testing.T) {
	t.Parallel()

	salt := make([]byte, openLDAPNetscapeSaltSize)
	for index := range salt {
		salt[index] = byte(index)
	}
	payload := append([]byte("976dd0289b0ebe5759db514e122c227a"), salt...)
	password := []byte{'p', 0x00, 'w', 0xff}
	if !verifyOpenLDAPNetscape(payload, password) {
		t.Fatal("verifyOpenLDAPNetscape() rejected binary salt or credentials")
	}
}

func TestVerifyOpenLDAPNetscapeRejectsMalformedPayloads(t *testing.T) {
	t.Parallel()

	const salt = "0123456789abcdefghijklmnopqrstuv"
	valid := []byte("61eeba12f15aaefe2569e77ee5c3d05c" + salt)
	for _, payload := range [][]byte{
		nil,
		valid[:openLDAPNetscapePayloadSize-1],
		append(bytes.Clone(valid), 'x'),
		[]byte(strings.ToUpper(string(valid[:openLDAPNetscapeDigestSize])) + salt),
		[]byte(strings.Repeat("g", openLDAPNetscapeDigestSize) + salt),
	} {
		if verifyOpenLDAPNetscape(payload, []byte("password")) {
			t.Fatalf("verifyOpenLDAPNetscape() accepted malformed payload %q", payload)
		}
	}
}

func TestVerifyOpenLDAPNetscapeRejectsTampering(t *testing.T) {
	t.Parallel()

	const value = "61eeba12f15aaefe2569e77ee5c3d05c" +
		"0123456789abcdefghijklmnopqrstuv"
	for _, index := range []int{0, openLDAPNetscapeDigestSize - 1, openLDAPNetscapeDigestSize, len(value) - 1} {
		payload := []byte(value)
		payload[index] ^= 1
		if verifyOpenLDAPNetscape(payload, []byte("password")) {
			t.Fatalf("verifyOpenLDAPNetscape() accepted tampering at byte %d", index)
		}
	}
}
