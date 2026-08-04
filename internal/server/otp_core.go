package server

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"strconv"
	"strings"
)

const (
	otpHMACSHA1OID   = "1.2.840.113549.2.7"
	otpHMACSHA224OID = "1.2.840.113549.2.8"
	otpHMACSHA256OID = "1.2.840.113549.2.9"
	otpHMACSHA384OID = "1.2.840.113549.2.10"
	otpHMACSHA512OID = "1.2.840.113549.2.11"
)

var (
	errOTPInvalidDigits        = errors.New("OTP digits must be between 1 and 8")
	errOTPUnsupportedAlgorithm = errors.New("unsupported OTP HMAC algorithm OID")
	errOTPInvalidLookAhead     = errors.New("HOTP look-ahead must not be negative")
	errOTPInvalidWindow        = errors.New("TOTP window must not be negative")
	errOTPInvalidPeriod        = errors.New("TOTP period must be positive")
	errOTPInvalidLastStep      = errors.New("OTP last step must be at least -1")
	errOTPStepOverflow         = errors.New("OTP step calculation overflow")
)

type otpAlgorithmRegistry struct {
	algorithms map[string]func() hash.Hash
}

var openLDAPOTPAlgorithms = otpAlgorithmRegistry{
	algorithms: map[string]func() hash.Hash{
		otpHMACSHA1OID:   sha1.New,
		otpHMACSHA224OID: sha256.New224,
		otpHMACSHA256OID: sha256.New,
		otpHMACSHA384OID: sha512.New384,
		otpHMACSHA512OID: sha512.New,
	},
}

type otpHOTPMatch struct {
	Found   int64
	Matched bool
}

type otpTOTPMatch struct {
	FoundStep  int64
	DriftDelta int64
	Matched    bool
}

func generateOTP(
	secret []byte,
	movingFactor uint64,
	digits int,
	algorithmOID string,
) (string, error) {
	if digits < 1 || digits > 8 {
		return "", errOTPInvalidDigits
	}
	newHash, ok := openLDAPOTPAlgorithms.algorithms[algorithmOID]
	if !ok {
		return "", errOTPUnsupportedAlgorithm
	}

	var message [8]byte
	binary.BigEndian.PutUint64(message[:], movingFactor)
	mac := hmac.New(newHash, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])

	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	token := strconv.FormatUint(uint64(value%modulus), 10)
	return strings.Repeat("0", digits-len(token)) + token, nil
}

func matchHOTP(
	secret []byte,
	token string,
	last int64,
	lookAhead int64,
	digits int,
	algorithmOID string,
) (otpHOTPMatch, error) {
	if err := validateOTPParameters(digits, algorithmOID); err != nil {
		return otpHOTPMatch{}, err
	}
	if last < -1 {
		return otpHOTPMatch{}, errOTPInvalidLastStep
	}
	if lookAhead < 0 {
		return otpHOTPMatch{}, errOTPInvalidLookAhead
	}
	if lookAhead == math.MaxInt64 || last > math.MaxInt64-lookAhead-1 {
		return otpHOTPMatch{}, errOTPStepOverflow
	}

	end := last + lookAhead + 1
	match := otpHOTPMatch{Found: -1}
	for candidate := last + 1; candidate <= end; candidate++ {
		generated, err := generateOTP(secret, uint64(candidate), digits, algorithmOID)
		if err != nil {
			return otpHOTPMatch{}, err
		}
		if otpTokenEqual(generated, token, digits) {
			// OpenLDAP scans the complete window, so the last collision wins.
			match.Found = candidate
			match.Matched = true
		}
		if candidate == end {
			break
		}
	}
	return match, nil
}

func matchTOTP(
	secret []byte,
	token string,
	unixTime int64,
	lastStep int64,
	drift int64,
	period int64,
	window int64,
	digits int,
	algorithmOID string,
) (otpTOTPMatch, error) {
	if err := validateOTPParameters(digits, algorithmOID); err != nil {
		return otpTOTPMatch{}, err
	}
	if period <= 0 {
		return otpTOTPMatch{}, errOTPInvalidPeriod
	}
	if window < 0 {
		return otpTOTPMatch{}, errOTPInvalidWindow
	}
	if lastStep < -1 {
		return otpTOTPMatch{}, errOTPInvalidLastStep
	}

	base, ok := checkedAddInt64(unixTime/period, drift)
	if !ok || base < math.MinInt64+window || base > math.MaxInt64-window {
		return otpTOTPMatch{}, errOTPStepOverflow
	}

	match := otpTOTPMatch{FoundStep: -1}
	check := func(delta int64) error {
		candidate := base + delta
		if candidate <= lastStep {
			return nil
		}
		generated, err := generateOTP(secret, uint64(candidate), digits, algorithmOID)
		if err != nil {
			return err
		}
		if otpTokenEqual(generated, token, digits) {
			match.FoundStep = candidate
			match.DriftDelta = delta
			match.Matched = true
		}
		return nil
	}

	if err := check(0); err != nil {
		return otpTOTPMatch{}, err
	}
	for distance := int64(1); distance <= window; distance++ {
		if err := check(-distance); err != nil {
			return otpTOTPMatch{}, err
		}
		if err := check(distance); err != nil {
			return otpTOTPMatch{}, err
		}
		if distance == window {
			break
		}
	}
	return match, nil
}

func validateOTPParameters(digits int, algorithmOID string) error {
	if digits < 1 || digits > 8 {
		return errOTPInvalidDigits
	}
	if _, ok := openLDAPOTPAlgorithms.algorithms[algorithmOID]; !ok {
		return errOTPUnsupportedAlgorithm
	}
	return nil
}

func otpTokenEqual(generated, supplied string, digits int) bool {
	candidate := make([]byte, digits)
	copy(candidate, supplied)
	equal := subtle.ConstantTimeCompare([]byte(generated), candidate)
	lengthEqual := subtle.ConstantTimeEq(int32(len(supplied)), int32(digits))
	return equal&lengthEqual == 1
}

func checkedAddInt64(left, right int64) (int64, bool) {
	if right > 0 && left > math.MaxInt64-right {
		return 0, false
	}
	if right < 0 && left < math.MinInt64-right {
		return 0, false
	}
	return left + right, true
}
