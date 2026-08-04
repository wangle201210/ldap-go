package server

import (
	"errors"
	"math"
	"testing"
)

func TestOTPCoreRFC4226HOTP(t *testing.T) {
	t.Parallel()

	secret := []byte("12345678901234567890")
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, expected := range want {
		got, err := generateOTP(secret, uint64(counter), 6, otpHMACSHA1OID)
		if err != nil {
			t.Fatalf("generate counter %d: %v", counter, err)
		}
		if got != expected {
			t.Errorf("counter %d = %q, want %q", counter, got, expected)
		}
	}
}

func TestOTPCoreOpenLDAPAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		oid  string
		want string
	}{
		{otpHMACSHA1OID, "05315093"},
		{otpHMACSHA224OID, "30733759"},
		{otpHMACSHA256OID, "86515696"},
		{otpHMACSHA384OID, "73353807"},
		{otpHMACSHA512OID, "71180035"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.oid, func(t *testing.T) {
			t.Parallel()
			got, err := generateOTP([]byte("algorithm-smoke-secret"), 123456789, 8, test.oid)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("generateOTP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOTPCoreHOTPWindowAndReplay(t *testing.T) {
	t.Parallel()

	secret := []byte("12345678901234567890")
	match, err := matchHOTP(secret, "969429", 0, 2, 6, otpHMACSHA1OID)
	if err != nil {
		t.Fatal(err)
	}
	if !match.Matched || match.Found != 3 {
		t.Fatalf("match = %#v, want counter 3", match)
	}

	replay, err := matchHOTP(secret, "969429", match.Found, 2, 6, otpHMACSHA1OID)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Matched || replay.Found != -1 {
		t.Fatalf("replay = %#v, want no match", replay)
	}

	outside, err := matchHOTP(secret, "338314", 0, 2, 6, otpHMACSHA1OID)
	if err != nil {
		t.Fatal(err)
	}
	if outside.Matched {
		t.Fatalf("outside-window token matched: %#v", outside)
	}
}

func TestOTPCoreHOTPUsesLastCollision(t *testing.T) {
	t.Parallel()

	secret := []byte("collision-search")
	first, second, token := findOTPCoreCollision(t, secret)
	match, err := matchHOTP(secret, token, first-1, second-first, 1, otpHMACSHA1OID)
	if err != nil {
		t.Fatal(err)
	}
	if !match.Matched || match.Found != second {
		t.Fatalf("match = %#v, want last collision at %d", match, second)
	}
}

func TestOTPCoreTOTPOrderReplayAndDrift(t *testing.T) {
	t.Parallel()

	secret := []byte("totp-window-secret")
	const (
		now      = int64(3_000)
		period   = int64(30)
		baseStep = now / period
	)

	pastToken, err := generateOTP(secret, uint64(baseStep-1), 6, otpHMACSHA256OID)
	if err != nil {
		t.Fatal(err)
	}
	past, err := matchTOTP(secret, pastToken, now, -1, 0, period, 2, 6, otpHMACSHA256OID)
	if err != nil {
		t.Fatal(err)
	}
	if !past.Matched || past.FoundStep != baseStep-1 || past.DriftDelta != -1 {
		t.Fatalf("past match = %#v", past)
	}

	futureToken, err := generateOTP(secret, uint64(baseStep+2), 6, otpHMACSHA256OID)
	if err != nil {
		t.Fatal(err)
	}
	future, err := matchTOTP(secret, futureToken, now, past.FoundStep, 0, period, 2, 6, otpHMACSHA256OID)
	if err != nil {
		t.Fatal(err)
	}
	if !future.Matched || future.FoundStep != baseStep+2 || future.DriftDelta != 2 {
		t.Fatalf("future match = %#v", future)
	}

	replay, err := matchTOTP(secret, futureToken, now, future.FoundStep, 0, period, 2, 6, otpHMACSHA256OID)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Matched {
		t.Fatalf("replay matched: %#v", replay)
	}
}

func TestOTPCoreTOTPChecksZeroBeforeNeighbors(t *testing.T) {
	t.Parallel()

	secret := []byte("totp-order")
	const baseStep = int64(500)
	current, err := generateOTP(secret, uint64(baseStep), 8, otpHMACSHA512OID)
	if err != nil {
		t.Fatal(err)
	}
	match, err := matchTOTP(
		secret,
		current,
		baseStep*30,
		baseStep-1,
		0,
		30,
		2,
		8,
		otpHMACSHA512OID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !match.Matched || match.FoundStep != baseStep || match.DriftDelta != 0 {
		t.Fatalf("match = %#v", match)
	}
}

func TestOTPCoreTOTPUsesOpenLDAPCandidateOrder(t *testing.T) {
	t.Parallel()

	secret := []byte("totp-collision-order")
	base, token, wantDelta := findOTPCoreTOTPCollision(t, secret)
	match, err := matchTOTP(
		secret,
		token,
		base*30,
		-1,
		0,
		30,
		2,
		1,
		otpHMACSHA1OID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !match.Matched || match.FoundStep != base+wantDelta || match.DriftDelta != wantDelta {
		t.Fatalf("match = %#v, want final ordered collision delta %d", match, wantDelta)
	}
}

func TestOTPCoreErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func() error
		want error
	}{
		{
			name: "zero digits",
			run: func() error {
				_, err := generateOTP(nil, 0, 0, otpHMACSHA1OID)
				return err
			},
			want: errOTPInvalidDigits,
		},
		{
			name: "nine digits",
			run: func() error {
				_, err := generateOTP(nil, 0, 9, otpHMACSHA1OID)
				return err
			},
			want: errOTPInvalidDigits,
		},
		{
			name: "unknown algorithm",
			run: func() error {
				_, err := generateOTP(nil, 0, 6, "1.2.3")
				return err
			},
			want: errOTPUnsupportedAlgorithm,
		},
		{
			name: "negative look-ahead",
			run: func() error {
				_, err := matchHOTP(nil, "000000", -1, -1, 6, otpHMACSHA1OID)
				return err
			},
			want: errOTPInvalidLookAhead,
		},
		{
			name: "zero period",
			run: func() error {
				_, err := matchTOTP(nil, "000000", 0, -1, 0, 0, 0, 6, otpHMACSHA1OID)
				return err
			},
			want: errOTPInvalidPeriod,
		},
		{
			name: "negative window",
			run: func() error {
				_, err := matchTOTP(nil, "000000", 0, -1, 0, 30, -1, 6, otpHMACSHA1OID)
				return err
			},
			want: errOTPInvalidWindow,
		},
		{
			name: "invalid last step",
			run: func() error {
				_, err := matchHOTP(nil, "000000", -2, 0, 6, otpHMACSHA1OID)
				return err
			},
			want: errOTPInvalidLastStep,
		},
		{
			name: "HOTP step overflow",
			run: func() error {
				_, err := matchHOTP(nil, "000000", math.MaxInt64, 0, 6, otpHMACSHA1OID)
				return err
			},
			want: errOTPStepOverflow,
		},
		{
			name: "TOTP drift overflow",
			run: func() error {
				_, err := matchTOTP(
					nil,
					"000000",
					math.MaxInt64,
					-1,
					1,
					1,
					0,
					6,
					otpHMACSHA1OID,
				)
				return err
			},
			want: errOTPStepOverflow,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.run(); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestOTPCoreRejectsWrongTokenLength(t *testing.T) {
	t.Parallel()

	for _, token := range []string{"75522", "0755224", "abcdef"} {
		match, err := matchHOTP(
			[]byte("12345678901234567890"),
			token,
			-1,
			0,
			6,
			otpHMACSHA1OID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if match.Matched {
			t.Fatalf("invalid token %q matched", token)
		}
	}
}

func findOTPCoreCollision(t *testing.T, secret []byte) (int64, int64, string) {
	t.Helper()

	seen := make(map[string]int64)
	for counter := int64(0); counter < 100; counter++ {
		token, err := generateOTP(secret, uint64(counter), 1, otpHMACSHA1OID)
		if err != nil {
			t.Fatal(err)
		}
		if first, ok := seen[token]; ok {
			return first, counter, token
		}
		seen[token] = counter
	}
	t.Fatal("failed to find a one-digit HOTP collision")
	return 0, 0, ""
}

func findOTPCoreTOTPCollision(t *testing.T, secret []byte) (int64, string, int64) {
	t.Helper()

	order := []int64{0, -1, 1, -2, 2}
	for base := int64(10); base < 1_000; base++ {
		matches := make(map[string][]int64)
		for _, delta := range order {
			token, err := generateOTP(secret, uint64(base+delta), 1, otpHMACSHA1OID)
			if err != nil {
				t.Fatal(err)
			}
			matches[token] = append(matches[token], delta)
		}
		for token, deltas := range matches {
			if len(deltas) > 1 {
				return base, token, deltas[len(deltas)-1]
			}
		}
	}
	t.Fatal("failed to find a one-digit TOTP collision")
	return 0, "", 0
}
