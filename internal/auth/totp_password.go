package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"
)

const (
	TOTP1HashScheme        = "{TOTP1}"
	TOTP256HashScheme      = "{TOTP256}"
	TOTP512HashScheme      = "{TOTP512}"
	TOTP1AndPWHashScheme   = "{TOTP1ANDPW}"
	TOTP256AndPWHashScheme = "{TOTP256ANDPW}"
	TOTP512AndPWHashScheme = "{TOTP512ANDPW}"

	totpTimeStep       = 30
	totpDigits         = 6
	totpAndPWDelimiter = '|'
)

type totpPasswordScheme struct {
	hash        func() hash.Hash
	andPassword bool
}

// IsTOTPPassword reports whether stored names one of OpenLDAP pw-totp's six
// password schemes. The payload is validated by VerifyTOTPPassword.
func IsTOTPPassword(stored []byte) bool {
	scheme, _ := splitScheme(stored)
	_, ok := lookupTOTPPasswordScheme(scheme)
	return ok
}

// VerifyTOTPPassword verifies OpenLDAP pw-totp credentials using the current
// 30-second time step and its authTimestamp replay rules.
func VerifyTOTPPassword(stored, supplied []byte, now, lastAuth time.Time) bool {
	scheme, payload := splitScheme(stored)
	configuration, ok := lookupTOTPPasswordScheme(scheme)
	if !ok || now.Unix() < 0 {
		return false
	}

	encodedSeed := payload
	otpCredential := supplied
	staticPasswordOK := true
	if configuration.andPassword {
		delimiter := bytes.IndexByte(payload, totpAndPWDelimiter)
		if delimiter <= 0 || delimiter == len(payload)-1 || len(supplied) <= totpDigits {
			return false
		}
		encodedSeed = payload[:delimiter]
		storedStaticPassword := payload[delimiter+1:]
		staticCredential := supplied[:len(supplied)-totpDigits]
		otpCredential = supplied[len(supplied)-totpDigits:]
		staticPasswordOK = VerifyPassword(storedStaticPassword, staticCredential)
	} else if len(supplied) != totpDigits {
		return false
	}

	seed, ok := decodeOpenLDAPBase32(encodedSeed)
	if !ok {
		return false
	}
	defer clear(seed)

	currentStep := now.Unix() / totpTimeStep
	lastStep := lastAuth.Unix() / totpTimeStep
	if !lastAuth.IsZero() && lastStep >= currentStep {
		return false
	}

	currentOK := constantTimeEqual(
		generateTOTP(seed, uint64(currentStep), configuration.hash),
		otpCredential,
	)
	previousOK := false
	if lastStep > 0 && lastStep < currentStep-1 {
		previousOK = constantTimeEqual(
			generateTOTP(seed, uint64(currentStep-1), configuration.hash),
			otpCredential,
		)
	}

	return staticPasswordOK && (currentOK || previousOK)
}

func hashTOTPPassword(
	password []byte,
	scheme string,
	random io.Reader,
) ([]byte, error) {
	configuration, ok := lookupTOTPPasswordScheme(scheme[1 : len(scheme)-1])
	if !ok {
		return nil, errors.New("unsupported TOTP password hash scheme")
	}

	seed := password
	var staticHash []byte
	if configuration.andPassword {
		delimiter := bytes.IndexByte(password, totpAndPWDelimiter)
		if delimiter <= 0 {
			return nil, errors.New("TOTP password must use seed|static format")
		}
		seed = password[:delimiter]
		staticPassword := password[delimiter+1:]
		var err error
		staticHash, err = HashPassword(
			staticPassword,
			OpenLDAPDefaultHashScheme,
			random,
		)
		if err != nil {
			return nil, err
		}
	}

	encodedSeed := base32.StdEncoding.EncodeToString(seed)
	stored := make([]byte, 0, len(scheme)+len(encodedSeed)+1+len(staticHash))
	stored = append(stored, scheme...)
	stored = append(stored, encodedSeed...)
	if configuration.andPassword {
		stored = append(stored, totpAndPWDelimiter)
		stored = append(stored, staticHash...)
	}
	return stored, nil
}

func lookupTOTPPasswordScheme(scheme string) (totpPasswordScheme, bool) {
	switch scheme {
	case "TOTP1":
		return totpPasswordScheme{hash: sha1.New}, true
	case "TOTP256":
		return totpPasswordScheme{hash: sha256.New}, true
	case "TOTP512":
		return totpPasswordScheme{hash: sha512.New}, true
	case "TOTP1ANDPW":
		return totpPasswordScheme{hash: sha1.New, andPassword: true}, true
	case "TOTP256ANDPW":
		return totpPasswordScheme{hash: sha256.New, andPassword: true}, true
	case "TOTP512ANDPW":
		return totpPasswordScheme{hash: sha512.New, andPassword: true}, true
	default:
		return totpPasswordScheme{}, false
	}
}

func decodeOpenLDAPBase32(encoded []byte) ([]byte, bool) {
	decoded, err := base32.StdEncoding.DecodeString(string(encoded))
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	canonical := base32.StdEncoding.EncodeToString(decoded)
	if !constantTimeEqual(encoded, []byte(canonical)) {
		return nil, false
	}
	return decoded, true
}

func generateTOTP(seed []byte, step uint64, newHash func() hash.Hash) []byte {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, step)
	digest := hmac.New(newHash, seed)
	_, _ = digest.Write(message)
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	value %= 1_000_000

	code := make([]byte, totpDigits)
	for index := len(code) - 1; index >= 0; index-- {
		code[index] = byte(value%10) + '0'
		value /= 10
	}
	return code
}
