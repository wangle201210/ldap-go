package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

const (
	openLDAPPBKDF2SHA1Vector = "10000$QJTEclnXgh9Cz3ChCWpdAg$" +
		"9.s98jwFJM.NXJK9ca/oJ5AyoAQ"
	openLDAPPBKDF2SHA256Vector = "10000$jq40ImWtmpTE.aYDYV1GfQ$" +
		"mpiL4ui02ACmYOAnCjp/MI1gQk50xLbZ54RZneU0fCg"
	openLDAPPBKDF2SHA512Vector = "10000$/oQ4xZi382mk7kvCd3ZdkA$" +
		"2wqjpuyV2l0U/a1QwoQPOtlQL.UcJGNACj1O24balruqQb/" +
		"NgPW6OCvvrrJP8.SzA3/5iYvLnwWPzeX8IK/bEQ"
)

func TestOpenLDAPPBKDF2KnownVectors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		scheme  string
		payload string
	}{
		{scheme: OpenLDAPPBKDF2HashScheme, payload: openLDAPPBKDF2SHA1Vector},
		{scheme: OpenLDAPPBKDF2SHA1HashScheme, payload: openLDAPPBKDF2SHA1Vector},
		{scheme: OpenLDAPPBKDF2SHA256HashScheme, payload: openLDAPPBKDF2SHA256Vector},
		{scheme: OpenLDAPPBKDF2SHA512HashScheme, payload: openLDAPPBKDF2SHA512Vector},
	} {
		stored := []byte(test.scheme + test.payload)
		if !VerifyPassword(stored, []byte("secret")) {
			t.Fatalf("VerifyPassword(%s) rejected the OpenLDAP vector", test.scheme)
		}
		if VerifyPassword(stored, []byte("wrong")) {
			t.Fatalf("VerifyPassword(%s) accepted an incorrect password", test.scheme)
		}
	}
}

func TestOpenLDAPPBKDF2PayloadWorkBound(t *testing.T) {
	for _, terminator := range []string{"$", "\x00"} {
		payload := openLDAPPBKDF2SHA1Vector + terminator
		payload += strings.Repeat("x", maxOpenLDAPPBKDF2PayloadSize-len(payload))
		stored := []byte(OpenLDAPPBKDF2SHA1HashScheme + payload)
		if !VerifyPassword(stored, []byte("secret")) {
			t.Fatalf("bounded native suffix %q rejected", terminator)
		}
		if VerifyPassword(append(stored, 'x'), []byte("secret")) {
			t.Fatalf("oversized native suffix %q accepted", terminator)
		}
	}
}

func TestHashOpenLDAPPBKDF2KnownVectors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		scheme  string
		payload string
	}{
		{scheme: OpenLDAPPBKDF2HashScheme, payload: openLDAPPBKDF2SHA1Vector},
		{scheme: OpenLDAPPBKDF2SHA1HashScheme, payload: openLDAPPBKDF2SHA1Vector},
		{scheme: OpenLDAPPBKDF2SHA256HashScheme, payload: openLDAPPBKDF2SHA256Vector},
		{scheme: OpenLDAPPBKDF2SHA512HashScheme, payload: openLDAPPBKDF2SHA512Vector},
	} {
		fields := strings.Split(test.payload, "$")
		salt, err := decodeOpenLDAPPBKDF2Base64(fields[1])
		if err != nil {
			t.Fatalf("decode %s vector salt: %v", test.scheme, err)
		}
		stored, err := HashPasswordOpenLDAPPBKDF2(
			[]byte("secret"),
			strings.ToLower(test.scheme),
			OpenLDAPPBKDF2DefaultIterations,
			bytes.NewReader(salt),
		)
		if err != nil {
			t.Fatalf("HashPasswordOpenLDAPPBKDF2(%s): %v", test.scheme, err)
		}
		if want := test.scheme + test.payload; string(stored) != want {
			t.Fatalf("HashPasswordOpenLDAPPBKDF2(%s) = %q, want %q", test.scheme, stored, want)
		}
	}
}

func TestHashPasswordOpenLDAPPBKDF2Defaults(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		scheme    string
		keyLength int
	}{
		{scheme: OpenLDAPPBKDF2HashScheme, keyLength: 20},
		{scheme: OpenLDAPPBKDF2SHA1HashScheme, keyLength: 20},
		{scheme: OpenLDAPPBKDF2SHA256HashScheme, keyLength: 32},
		{scheme: OpenLDAPPBKDF2SHA512HashScheme, keyLength: 64},
	} {
		stored, err := HashPassword(
			[]byte("secret"),
			test.scheme,
			bytes.NewReader(make([]byte, openLDAPPBKDF2SaltSize)),
		)
		if err != nil {
			t.Fatalf("HashPassword(%s): %v", test.scheme, err)
		}
		fields := strings.Split(strings.TrimPrefix(string(stored), test.scheme), "$")
		if len(fields) != 3 || fields[0] != "10000" {
			t.Fatalf("HashPassword(%s) = %q", test.scheme, stored)
		}
		salt, saltErr := decodeOpenLDAPPBKDF2Base64(fields[1])
		derived, derivedErr := decodeOpenLDAPPBKDF2Base64(fields[2])
		if saltErr != nil || derivedErr != nil ||
			len(salt) != openLDAPPBKDF2SaltSize || len(derived) != test.keyLength {
			t.Fatalf(
				"HashPassword(%s) salt=%d/%v derived=%d/%v",
				test.scheme,
				len(salt),
				saltErr,
				len(derived),
				derivedErr,
			)
		}
		if !VerifyPassword(stored, []byte("secret")) {
			t.Fatalf("VerifyPassword() rejected generated %s value", test.scheme)
		}
	}
}

func TestVerifyOpenLDAPPBKDF2Base64Forms(t *testing.T) {
	t.Parallel()

	fields := strings.Split(openLDAPPBKDF2SHA256Vector, "$")
	paddedSalt := fields[1] + "=="
	paddedDerived := fields[2] + "="
	for _, payload := range []string{
		"010000$" + fields[1] + "$" + fields[2],
		"10000$" + paddedSalt + "$" + paddedDerived,
		"10000$" + strings.ReplaceAll(fields[1], ".", "+") + "$" +
			strings.ReplaceAll(fields[2], ".", "+"),
		"10000$" + fields[1] + "$" + fields[2][:10] + " \t\r\n" + fields[2][10:],
	} {
		if !VerifyPassword(
			[]byte(OpenLDAPPBKDF2SHA256HashScheme+payload),
			[]byte("secret"),
		) {
			t.Fatalf("VerifyPassword() rejected compatible payload %q", payload)
		}
	}
}

func TestVerifyOpenLDAPPBKDF2ImportedFormats(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ scheme, payload string }{
		{OpenLDAPPBKDF2HashScheme, openLDAPPBKDF2SHA1Vector},
		{OpenLDAPPBKDF2SHA1HashScheme, openLDAPPBKDF2SHA1Vector},
		{OpenLDAPPBKDF2SHA256HashScheme, openLDAPPBKDF2SHA256Vector},
		{OpenLDAPPBKDF2SHA512HashScheme, openLDAPPBKDF2SHA512Vector},
	} {
		fields := strings.Split(test.payload, "$")
		suffix := "$" + fields[1] + "$" + fields[2]
		for _, payload := range []string{
			"+10000" + suffix,
			" \t\n\r\v\f+10000" + suffix,
			strings.Repeat("0", 150) + "10000" + suffix,
			"10000junk" + suffix,
			"10000.5" + suffix,
			"10000e2" + suffix,
			"10000 " + suffix,
			"10000" + strings.Repeat("x", 150) + suffix,
			"10000" + suffix + "$ignored",
			"10000" + suffix + "$$",
			"10000" + suffix + "$" + strings.Repeat("x", 1024),
			"10000" + suffix + "\x00ignored",
		} {
			stored := []byte(test.scheme + payload)
			if !VerifyPassword(stored, []byte("secret")) {
				t.Errorf("VerifyPassword(%q) rejected compatible import", stored)
			}
			if VerifyPassword(stored, []byte("wrong")) {
				t.Errorf("VerifyPassword(%q) accepted wrong password", stored)
			}
		}
	}
}

func TestVerifyOpenLDAPPBKDF2RejectsMalformedValues(t *testing.T) {
	t.Parallel()

	fields := strings.Split(openLDAPPBKDF2SHA1Vector, "$")
	for _, payload := range []string{
		"",
		"0$" + fields[1] + "$" + fields[2],
		"-1$" + fields[1] + "$" + fields[2],
		"+ 10000$" + fields[1] + "$" + fields[2],
		"junk10000$" + fields[1] + "$" + fields[2],
		"\u00a010000$" + fields[1] + "$" + fields[2],
		"10000001$" + fields[1] + "$" + fields[2],
		"1000001$" + fields[1] + "$" + fields[2],
		"999999999$" + fields[1] + "$" + fields[2],
		"10000$" + fields[1],
		"10000$$" + fields[2],
		"10000$" + fields[1] + "$",
		"10000$" + fields[1] + "$" + fields[2] + "garbage",
		"10000$QJTEclnXgh9Cz3ChCWpdAh$" + fields[2],
		"10000$" + fields[1] + "$9.s98jwFJM.NXJK9ca/oJ5AyoAR",
		"10000$QJTEclnXgh9Cz3ChCWpdA-$" + fields[2],
		"10000$" + fields[1][:10] + " \t" + fields[1][10:] + "$" + fields[2],
		"10000$" + fields[1] + "$" + strings.Repeat("A", 89),
		"10000\x00$" + fields[1] + "$" + fields[2],
		"10000$" + fields[1] + "\x00$" + fields[2],
		"4294977296$" + fields[1] + "$" + fields[2],
		"-4294957296$" + fields[1] + "$" + fields[2],
	} {
		stored := []byte(OpenLDAPPBKDF2SHA1HashScheme + payload)
		if VerifyPassword(stored, []byte("secret")) {
			t.Fatalf("VerifyPassword(%q) accepted malformed PBKDF2 data", stored)
		}
	}
}

func TestHashPasswordOpenLDAPPBKDF2RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	salt := bytes.NewReader(make([]byte, openLDAPPBKDF2SaltSize))
	if _, err := HashPasswordOpenLDAPPBKDF2(
		nil,
		OpenLDAPPBKDF2HashScheme,
		1,
		salt,
	); err == nil {
		t.Fatal("empty password was accepted")
	}
	for _, iterations := range []int{0, -1, MaxOpenLDAPPBKDF2Iterations + 1} {
		if _, err := HashPasswordOpenLDAPPBKDF2(
			[]byte("secret"),
			OpenLDAPPBKDF2HashScheme,
			iterations,
			bytes.NewReader(make([]byte, openLDAPPBKDF2SaltSize)),
		); err == nil {
			t.Fatalf("iterations %d were accepted", iterations)
		}
	}
	if _, err := HashPasswordOpenLDAPPBKDF2(
		[]byte("secret"),
		SMPBKDF2HashScheme,
		1,
		bytes.NewReader(make([]byte, openLDAPPBKDF2SaltSize)),
	); err == nil {
		t.Fatal("PBKDF2-SM3 was accepted as an OpenLDAP PBKDF2 scheme")
	}
	if _, err := HashPasswordOpenLDAPPBKDF2(
		[]byte("secret"),
		OpenLDAPPBKDF2HashScheme,
		1,
		errorReader{},
	); err == nil {
		t.Fatal("salt generation failure was ignored")
	}
}

func TestParseOpenLDAPPBKDF2IterationLimit(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value string
		want  int
		ok    bool
	}{
		{value: "1", want: 1, ok: true},
		{value: "0001", want: 1, ok: true},
		{value: "10000", want: 10_000, ok: true},
		{value: "1000000", want: MaxOpenLDAPPBKDF2Iterations, ok: true},
		{value: "+1", want: 1, ok: true},
		{value: "1junk", want: 1, ok: true},
		{value: " \t\n\r\v\f+10000rest", want: 10000, ok: true},
		{value: strings.Repeat("0", 150) + "10000", want: 10000, ok: true},
		{value: "  +0001000000.9", want: MaxOpenLDAPPBKDF2Iterations, ok: true},
		{value: "10000e2", want: 10000, ok: true},
		{value: "1000001"},
		{value: "  +0001000001ignored"},
		{value: "10000001"},
		{value: "999999999"},
		{value: "4294977296"},
		{value: "184467440737095516160000"},
		{value: "-1"},
		{value: "-4294957296"},
		{value: "0x2710"},
		{value: "0"},
		{value: "+ 1"},
		{value: "+"},
		{value: ""},
		{value: "\u00a010000"},
	} {
		got, ok := parseOpenLDAPPBKDF2Iterations(test.value)
		if got != test.want || ok != test.ok {
			t.Fatalf(
				"parseOpenLDAPPBKDF2Iterations(%q) = %d, %t, want %d, %t",
				test.value,
				got,
				ok,
				test.want,
				test.ok,
			)
		}
	}
}

func TestVerifyOpenLDAPPBKDF2IterationCostLimit(t *testing.T) {
	t.Parallel()
	salt := make([]byte, 16)
	for _, iterations := range []int{MaxOpenLDAPPBKDF2Iterations, MaxOpenLDAPPBKDF2Iterations + 1} {
		derived := pbkdf2.Key([]byte("secret"), salt, iterations, sha256.Size, sha256.New)
		stored := OpenLDAPPBKDF2SHA256HashScheme + "  +000" + strconv.Itoa(iterations) + "ignored$" +
			base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived)
		if got, want := VerifyPassword([]byte(stored), []byte("secret")), iterations <= MaxOpenLDAPPBKDF2Iterations; got != want {
			t.Errorf("VerifyPassword at %d iterations = %t, want %t", iterations, got, want)
		}
	}
}
