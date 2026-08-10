package auth

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/pbkdf2"
)

const (
	DefaultSMPBKDF2Iterations = 100_000
	MaxSMPBKDF2Iterations     = 10_000_000
	OpenLDAPDefaultHashScheme = "{SSHA}"
	SMPBKDF2HashScheme        = "{PBKDF2-SM3}"
	openLDAPPasswordSaltSize  = 4
	smPasswordSaltSize        = 16
	maxSMPBKDF2PayloadSize    = 8 + 1 + 22 + 1 + 43
)

// VerifyPassword accepts portable OpenLDAP digest schemes and ldap-go's SM3
// extensions without relying on platform-specific crypt(3).
func VerifyPassword(stored, supplied []byte) bool {
	if len(stored) == 0 || len(supplied) == 0 {
		return false
	}

	scheme, payload := splitScheme(stored)
	switch scheme {
	case "":
		return constantTimeEqual(stored, supplied)
	case "CLEARTEXT":
		return constantTimeEqual(payload, supplied)
	case "SHA":
		return verifyDigest(payload, supplied, false, sha1.Size, func(value []byte) []byte {
			digest := sha1.Sum(value)
			return digest[:]
		})
	case "SSHA":
		return verifyDigest(payload, supplied, true, sha1.Size, func(value []byte) []byte {
			digest := sha1.Sum(value)
			return digest[:]
		})
	case "MD5":
		return verifyDigest(payload, supplied, false, md5.Size, func(value []byte) []byte {
			digest := md5.Sum(value)
			return digest[:]
		})
	case "SMD5":
		return verifyDigest(payload, supplied, true, md5.Size, func(value []byte) []byte {
			digest := md5.Sum(value)
			return digest[:]
		})
	case "SM3":
		return verifyDigest(payload, supplied, false, sm3.Size, func(value []byte) []byte {
			digest := sm3.Sum(value)
			return digest[:]
		})
	case "SSM3":
		return verifyDigest(payload, supplied, true, sm3.Size, func(value []byte) []byte {
			digest := sm3.Sum(value)
			return digest[:]
		})
	case "PBKDF2-SM3":
		return verifySMPBKDF2(payload, supplied)
	default:
		return false
	}
}

// ExtractCleartextPassword returns credentials that can be used by
// challenge-response mechanisms which require the original password.
func ExtractCleartextPassword(stored []byte) ([]byte, bool) {
	if len(stored) == 0 {
		return nil, false
	}
	scheme, payload := splitScheme(stored)
	switch scheme {
	case "":
		return bytes.Clone(stored), true
	case "CLEARTEXT":
		if len(payload) == 0 {
			return nil, false
		}
		return bytes.Clone(payload), true
	default:
		return nil, false
	}
}

func NormalizePasswordHashScheme(value string) (string, error) {
	scheme := strings.ToUpper(strings.TrimSpace(value))
	switch scheme {
	case "{CLEARTEXT}",
		"{SHA}",
		"{SSHA}",
		"{MD5}",
		"{SMD5}",
		"{SM3}",
		"{SSM3}",
		TOTP1HashScheme,
		TOTP256HashScheme,
		TOTP512HashScheme,
		TOTP1AndPWHashScheme,
		TOTP256AndPWHashScheme,
		TOTP512AndPWHashScheme,
		SMPBKDF2HashScheme:
		return scheme, nil
	default:
		return "", fmt.Errorf("unsupported password hash scheme %q", value)
	}
}

func HashPassword(password []byte, scheme string, random io.Reader) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	normalized, err := NormalizePasswordHashScheme(scheme)
	if err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}

	switch normalized {
	case "{CLEARTEXT}":
		return bytes.Clone(password), nil
	case "{SHA}":
		return hashPasswordDigest(password, normalized, 0, random, func(value []byte) []byte {
			digest := sha1.Sum(value)
			return digest[:]
		})
	case "{SSHA}":
		return hashPasswordDigest(
			password,
			normalized,
			openLDAPPasswordSaltSize,
			random,
			func(value []byte) []byte {
				digest := sha1.Sum(value)
				return digest[:]
			},
		)
	case "{MD5}":
		return hashPasswordDigest(password, normalized, 0, random, func(value []byte) []byte {
			digest := md5.Sum(value)
			return digest[:]
		})
	case "{SMD5}":
		return hashPasswordDigest(
			password,
			normalized,
			openLDAPPasswordSaltSize,
			random,
			func(value []byte) []byte {
				digest := md5.Sum(value)
				return digest[:]
			},
		)
	case "{SM3}":
		return hashPasswordDigest(password, normalized, 0, random, func(value []byte) []byte {
			digest := sm3.Sum(value)
			return digest[:]
		})
	case "{SSM3}":
		return hashPasswordDigest(
			password,
			normalized,
			smPasswordSaltSize,
			random,
			func(value []byte) []byte {
				digest := sm3.Sum(value)
				return digest[:]
			},
		)
	case TOTP1HashScheme,
		TOTP256HashScheme,
		TOTP512HashScheme,
		TOTP1AndPWHashScheme,
		TOTP256AndPWHashScheme,
		TOTP512AndPWHashScheme:
		return hashTOTPPassword(password, normalized, random)
	case SMPBKDF2HashScheme:
		return HashPasswordSMPBKDF2(password, DefaultSMPBKDF2Iterations, random)
	default:
		panic("validated password hash scheme was not handled")
	}
}

func HashPasswordSMPBKDF2(
	password []byte,
	iterations int,
	random io.Reader,
) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if iterations < 1 || iterations > MaxSMPBKDF2Iterations {
		return nil, fmt.Errorf(
			"PBKDF2-SM3 iterations must be between 1 and %d",
			MaxSMPBKDF2Iterations,
		)
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, smPasswordSaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	derived := pbkdf2.Key(password, salt, iterations, sm3.Size, sm3.New)
	return []byte(fmt.Sprintf(
		"{PBKDF2-SM3}%d$%s$%s",
		iterations,
		adaptedBase64(salt),
		adaptedBase64(derived),
	)), nil
}

func hashPasswordDigest(
	password []byte,
	scheme string,
	saltSize int,
	random io.Reader,
	sum func([]byte) []byte,
) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	input := make([]byte, 0, len(password)+len(salt))
	input = append(input, password...)
	input = append(input, salt...)
	digest := sum(input)
	encoded := make([]byte, 0, len(digest)+len(salt))
	encoded = append(encoded, digest...)
	encoded = append(encoded, salt...)
	return []byte(scheme + base64.StdEncoding.EncodeToString(encoded)), nil
}

func splitScheme(stored []byte) (string, []byte) {
	if len(stored) < 3 || stored[0] != '{' {
		return "", stored
	}
	end := strings.IndexByte(string(stored), '}')
	if end <= 1 {
		return "", stored
	}
	return strings.ToUpper(string(stored[1:end])), stored[end+1:]
}

func verifyDigest(
	encoded []byte,
	password []byte,
	salted bool,
	digestLength int,
	sum func([]byte) []byte,
) bool {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		return false
	}
	decoded = decoded[:n]
	if len(decoded) < digestLength || (!salted && len(decoded) != digestLength) {
		return false
	}

	salt := decoded[digestLength:]
	input := make([]byte, 0, len(password)+len(salt))
	input = append(input, password...)
	input = append(input, salt...)
	actual := sum(input)
	return subtle.ConstantTimeCompare(decoded[:digestLength], actual) == 1
}

func verifySMPBKDF2(payload, password []byte) bool {
	if len(payload) > maxSMPBKDF2PayloadSize {
		return false
	}
	fields := strings.Split(string(payload), "$")
	if len(fields) != 3 ||
		len(fields[0]) == 0 ||
		len(fields[0]) > 8 ||
		len(fields[1]) > 24 ||
		len(fields[2]) > 44 {
		return false
	}
	iterations, err := strconv.Atoi(fields[0])
	if err != nil || iterations < 1 || iterations > MaxSMPBKDF2Iterations {
		return false
	}
	salt, err := decodeAdaptedBase64(fields[1])
	if err != nil || len(salt) != smPasswordSaltSize {
		return false
	}
	expected, err := decodeAdaptedBase64(fields[2])
	if err != nil || len(expected) != sm3.Size {
		return false
	}
	actual := pbkdf2.Key(password, salt, iterations, sm3.Size, sm3.New)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func adaptedBase64(value []byte) string {
	return strings.ReplaceAll(
		base64.RawStdEncoding.EncodeToString(value),
		"+",
		".",
	)
}

func decodeAdaptedBase64(value string) ([]byte, error) {
	normalized := strings.ReplaceAll(value, ".", "+")
	switch len(normalized) % 4 {
	case 0:
	case 2:
		normalized += "=="
	case 3:
		normalized += "="
	default:
		return nil, errors.New("invalid adapted base64")
	}
	return base64.StdEncoding.DecodeString(normalized)
}

func constantTimeEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}
