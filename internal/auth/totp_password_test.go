package auth

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTOTPPasswordHashSchemes(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{
		TOTP1HashScheme,
		TOTP256HashScheme,
		TOTP512HashScheme,
		TOTP1AndPWHashScheme,
		TOTP256AndPWHashScheme,
		TOTP512AndPWHashScheme,
	} {
		got, err := NormalizePasswordHashScheme(" \t" + strings.ToLower(scheme) + "\n")
		if err != nil {
			t.Fatalf("NormalizePasswordHashScheme(%q): %v", scheme, err)
		}
		if got != scheme {
			t.Fatalf("NormalizePasswordHashScheme(%q) = %q", scheme, got)
		}
	}
}

func TestHashTOTPPasswordDeterministic(t *testing.T) {
	t.Parallel()

	seed := []byte("12345678901234567890")
	const encodedSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, scheme := range []string{
		TOTP1HashScheme,
		TOTP256HashScheme,
		TOTP512HashScheme,
	} {
		stored, err := HashPassword(seed, strings.ToLower(scheme), errorReader{})
		if err != nil {
			t.Fatalf("HashPassword(%s): %v", scheme, err)
		}
		if want := scheme + encodedSeed; string(stored) != want {
			t.Fatalf("HashPassword(%s) = %q, want %q", scheme, stored, want)
		}
	}

	padded, err := HashPassword([]byte("f"), TOTP1HashScheme, errorReader{})
	if err != nil {
		t.Fatalf("HashPassword(padded seed): %v", err)
	}
	if want := TOTP1HashScheme + "MY======"; string(padded) != want {
		t.Fatalf("HashPassword(padded seed) = %q, want %q", padded, want)
	}

	salt := []byte{0x01, 0x02, 0x03, 0x04}
	staticPassword := []byte("static-secret")
	staticInput := append(append([]byte(nil), staticPassword...), salt...)
	staticDigest := sha1.Sum(staticInput)
	staticHash := encoded("{SSHA}", append(staticDigest[:], salt...))
	input := append(append(append([]byte(nil), seed...), '|'), staticPassword...)
	for _, scheme := range []string{
		TOTP1AndPWHashScheme,
		TOTP256AndPWHashScheme,
		TOTP512AndPWHashScheme,
	} {
		stored, hashErr := HashPassword(input, scheme, bytes.NewReader(salt))
		if hashErr != nil {
			t.Fatalf("HashPassword(%s): %v", scheme, hashErr)
		}
		want := scheme + encodedSeed + "|" + string(staticHash)
		if string(stored) != want {
			t.Fatalf("HashPassword(%s) = %q, want %q", scheme, stored, want)
		}
	}
}

func TestTOTPPasswordRFC6238Vectors(t *testing.T) {
	t.Parallel()

	type algorithm struct {
		scheme string
		seed   string
		codes  []string
	}
	algorithms := []algorithm{
		{
			scheme: TOTP1HashScheme,
			seed:   "12345678901234567890",
			codes:  []string{"287082", "081804", "050471", "005924", "279037", "353130"},
		},
		{
			scheme: TOTP256HashScheme,
			seed:   "12345678901234567890123456789012",
			codes:  []string{"119246", "084774", "062674", "819424", "698825", "737706"},
		},
		{
			scheme: TOTP512HashScheme,
			seed:   "1234567890123456789012345678901234567890123456789012345678901234",
			codes:  []string{"693936", "091201", "943326", "441116", "618901", "863826"},
		},
	}
	timestamps := []int64{59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000}

	for _, algorithm := range algorithms {
		algorithm := algorithm
		t.Run(algorithm.scheme, func(t *testing.T) {
			t.Parallel()

			stored := []byte(algorithm.scheme + base32.StdEncoding.EncodeToString([]byte(algorithm.seed)))
			for index, timestamp := range timestamps {
				if !VerifyTOTPPassword(
					stored,
					[]byte(algorithm.codes[index]),
					time.Unix(timestamp, 0),
					time.Time{},
				) {
					t.Fatalf("timestamp %d rejected code %s", timestamp, algorithm.codes[index])
				}
			}
		})
	}
}

func TestHashTOTPPasswordRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Unix(59, 0)
	tests := []struct {
		scheme string
		seed   string
		code   string
	}{
		{scheme: TOTP1HashScheme, seed: "12345678901234567890", code: "287082"},
		{scheme: TOTP256HashScheme, seed: "12345678901234567890123456789012", code: "119246"},
		{
			scheme: TOTP512HashScheme,
			seed:   "1234567890123456789012345678901234567890123456789012345678901234",
			code:   "693936",
		},
		{scheme: TOTP1AndPWHashScheme, seed: "12345678901234567890", code: "287082"},
		{
			scheme: TOTP256AndPWHashScheme,
			seed:   "12345678901234567890123456789012",
			code:   "119246",
		},
		{
			scheme: TOTP512AndPWHashScheme,
			seed:   "1234567890123456789012345678901234567890123456789012345678901234",
			code:   "693936",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.scheme, func(t *testing.T) {
			t.Parallel()

			seed := []byte(test.seed)
			input := seed
			supplied := []byte(test.code)
			if strings.Contains(test.scheme, "ANDPW") {
				input = append(append(append([]byte(nil), seed...), '|'), "static-secret"...)
				supplied = append([]byte("static-secret"), test.code...)
			}
			stored, err := HashPassword(input, test.scheme, bytes.NewReader([]byte{1, 2, 3, 4}))
			if err != nil {
				t.Fatalf("HashPassword(): %v", err)
			}
			if !IsTOTPPassword(stored) {
				t.Fatalf("IsTOTPPassword(%q) = false", stored)
			}
			if !VerifyTOTPPassword(stored, supplied, now, time.Time{}) {
				t.Fatalf("VerifyTOTPPassword(%q, %q) = false", stored, supplied)
			}
			wrong := append([]byte(nil), supplied...)
			wrong[0] ^= 1
			if VerifyTOTPPassword(stored, wrong, now, time.Time{}) {
				t.Fatalf("VerifyTOTPPassword() accepted %q", wrong)
			}
			wrongOTP := append([]byte(nil), supplied...)
			wrongOTP[len(wrongOTP)-1] ^= 1
			if VerifyTOTPPassword(stored, wrongOTP, now, time.Time{}) {
				t.Fatalf("VerifyTOTPPassword() accepted wrong OTP %q", wrongOTP)
			}
		})
	}
}

func TestVerifyTOTPAndPWUsesCredentialSuffix(t *testing.T) {
	t.Parallel()

	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	stored := []byte(TOTP1AndPWHashScheme + seed + "|{CLEARTEXT}static123456")
	if !VerifyTOTPPassword(
		stored,
		[]byte("static123456287082"),
		time.Unix(59, 0),
		time.Time{},
	) {
		t.Fatal("VerifyTOTPPassword() did not use the final six credential bytes as the OTP")
	}
}

func TestVerifyTOTPPasswordReplayBoundaries(t *testing.T) {
	t.Parallel()

	seed := []byte("12345678901234567890")
	stored := []byte(TOTP1HashScheme + base32.StdEncoding.EncodeToString(seed))
	now := time.Unix(90, 0)
	current := generateTOTP(seed, 3, sha1.New)
	previous := generateTOTP(seed, 2, sha1.New)

	for _, test := range []struct {
		name     string
		code     []byte
		lastAuth time.Time
		want     bool
	}{
		{name: "first use current", code: current, want: true},
		{name: "first use previous", code: previous},
		{name: "step zero previous", code: previous, lastAuth: time.Unix(1, 0)},
		{name: "older step previous", code: previous, lastAuth: time.Unix(30, 0), want: true},
		{name: "previous step boundary", code: previous, lastAuth: time.Unix(60, 0)},
		{name: "end of previous step", code: previous, lastAuth: time.Unix(89, 0)},
		{name: "subsecond unix zero previous", code: previous, lastAuth: time.Unix(0, 1)},
		{name: "old timestamp current", code: current, lastAuth: time.Unix(30, 0), want: true},
		{name: "same step rejects current", code: current, lastAuth: time.Unix(90, 0)},
		{name: "end of same step rejects current", code: current, lastAuth: time.Unix(119, 0)},
		{name: "future step rejects current", code: current, lastAuth: time.Unix(120, 0)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := VerifyTOTPPassword(stored, test.code, now, test.lastAuth); got != test.want {
				t.Fatalf("VerifyTOTPPassword() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestVerifyTOTPPasswordAcceptsOpenLDAPBase32Forms(t *testing.T) {
	t.Parallel()

	now := time.Unix(59, 0)
	for _, test := range []struct {
		name    string
		encoded string
		seed    []byte
	}{
		{name: "padded", encoded: "MY======", seed: []byte("f")},
		{name: "complete unpadded block", encoded: "MZXW6YTB", seed: []byte("fooba")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			code := generateTOTP(test.seed, uint64(now.Unix()/totpTimeStep), sha1.New)
			stored := []byte(TOTP1HashScheme + test.encoded)
			if !VerifyTOTPPassword(stored, code, now, time.Time{}) {
				t.Fatalf("VerifyTOTPPassword(%q) rejected valid Base32", stored)
			}
		})
	}
}

func TestVerifyTOTPPasswordRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	now := time.Unix(59, 0)
	for _, stored := range []string{
		"",
		"{UNKNOWN}MY======",
		TOTP1HashScheme,
		TOTP1HashScheme + "my======",
		TOTP1HashScheme + "M!======",
		TOTP1HashScheme + "MY=====",
		TOTP1HashScheme + "MZ======",
		TOTP1HashScheme + "MY======A",
		TOTP1HashScheme + "MY",
		TOTP1HashScheme + "========",
		TOTP1HashScheme + "MY======\x00",
	} {
		if VerifyTOTPPassword([]byte(stored), []byte("287082"), now, time.Time{}) {
			t.Fatalf("VerifyTOTPPassword(%q) accepted malformed storage", stored)
		}
	}

	valid := []byte(TOTP1HashScheme + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	for _, supplied := range []string{"", "28708", "2870820", "abcdef"} {
		if VerifyTOTPPassword(valid, []byte(supplied), now, time.Time{}) {
			t.Fatalf("VerifyTOTPPassword() accepted credential %q", supplied)
		}
	}
	if VerifyTOTPPassword(valid, []byte("287082"), time.Unix(-1, 0), time.Time{}) {
		t.Fatal("VerifyTOTPPassword() accepted a pre-epoch current time")
	}

	for _, stored := range []string{
		TOTP1AndPWHashScheme + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		TOTP1AndPWHashScheme + "|{SSHA}value",
		TOTP1AndPWHashScheme + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ|",
		TOTP1AndPWHashScheme + "my======|{SSHA}value",
		TOTP1AndPWHashScheme + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ|{SSHA}invalid",
	} {
		if VerifyTOTPPassword([]byte(stored), []byte("static-secret287082"), now, time.Time{}) {
			t.Fatalf("VerifyTOTPPassword(%q) accepted malformed ANDPW storage", stored)
		}
	}
	if VerifyTOTPPassword(
		[]byte(TOTP1AndPWHashScheme+"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ|{CLEARTEXT}static-secret"),
		[]byte("287082"),
		now,
		time.Time{},
	) {
		t.Fatal("VerifyTOTPPassword() accepted ANDPW without a static credential")
	}
}

func TestHashTOTPPasswordRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{
		[]byte("seed-without-delimiter"),
		[]byte("|static-secret"),
		[]byte("seed|"),
	} {
		if _, err := HashPassword(input, TOTP1AndPWHashScheme, bytes.NewReader([]byte{1, 2, 3, 4})); err == nil {
			t.Fatalf("HashPassword(%q) accepted malformed ANDPW input", input)
		}
	}
	if _, err := HashPassword(
		[]byte("seed|static-secret"),
		TOTP1AndPWHashScheme,
		errorReader{},
	); err == nil {
		t.Fatal("HashPassword() ignored the ANDPW SSHA random source failure")
	}
}

func TestIsTOTPPassword(t *testing.T) {
	t.Parallel()

	for _, stored := range []string{
		TOTP1HashScheme + "seed",
		TOTP256HashScheme + "seed",
		TOTP512HashScheme + "seed",
		TOTP1AndPWHashScheme + "seed|password",
		TOTP256AndPWHashScheme + "seed|password",
		TOTP512AndPWHashScheme + "seed|password",
		"{totp1}seed",
	} {
		if !IsTOTPPassword([]byte(stored)) {
			t.Fatalf("IsTOTPPassword(%q) = false", stored)
		}
	}
	for _, stored := range []string{"", "{TOTP}", "{UNKNOWN}value", "TOTP1"} {
		if IsTOTPPassword([]byte(stored)) {
			t.Fatalf("IsTOTPPassword(%q) = true", stored)
		}
	}
}
