package auth

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	OpenLDAPPBKDF2HashScheme       = "{PBKDF2}"
	OpenLDAPPBKDF2SHA1HashScheme   = "{PBKDF2-SHA1}"
	OpenLDAPPBKDF2SHA256HashScheme = "{PBKDF2-SHA256}"
	OpenLDAPPBKDF2SHA512HashScheme = "{PBKDF2-SHA512}"

	OpenLDAPPBKDF2DefaultIterations = 10_000
	MaxOpenLDAPPBKDF2Iterations     = 1_000_000
	openLDAPPBKDF2SaltSize          = 16
	maxOpenLDAPPBKDF2PayloadSize    = 8 + 1 + 24 + 1 + 88
)

type openLDAPPBKDF2Parameters struct {
	newHash   func() hash.Hash
	keyLength int
}

func HashPasswordOpenLDAPPBKDF2(
	password []byte,
	scheme string,
	iterations int,
	random io.Reader,
) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	normalized, err := NormalizePasswordHashScheme(scheme)
	if err != nil {
		return nil, err
	}
	name := normalized[1 : len(normalized)-1]
	parameters, ok := openLDAPPBKDF2SchemeParameters(name)
	if !ok {
		return nil, fmt.Errorf("%s is not an OpenLDAP PBKDF2 scheme", normalized)
	}
	if iterations < 1 || iterations > MaxOpenLDAPPBKDF2Iterations {
		return nil, fmt.Errorf(
			"OpenLDAP PBKDF2 iterations must be between 1 and %d",
			MaxOpenLDAPPBKDF2Iterations,
		)
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, openLDAPPBKDF2SaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	derived := pbkdf2.Key(
		password,
		salt,
		iterations,
		parameters.keyLength,
		parameters.newHash,
	)
	return []byte(fmt.Sprintf(
		"%s%d$%s$%s",
		normalized,
		iterations,
		adaptedBase64(salt),
		adaptedBase64(derived),
	)), nil
}

func verifyOpenLDAPPBKDF2(scheme string, payload, password []byte) bool {
	if len(payload) > maxOpenLDAPPBKDF2PayloadSize {
		return false
	}
	parameters, ok := openLDAPPBKDF2SchemeParameters(scheme)
	if !ok {
		return false
	}
	fields := strings.Split(string(payload), "$")
	if len(fields) != 3 || len(fields[1]) > 24 || len(fields[2]) > 88 {
		return false
	}
	iterations, ok := parseOpenLDAPPBKDF2Iterations(fields[0])
	if !ok {
		return false
	}
	salt, err := decodeOpenLDAPPBKDF2Base64(fields[1])
	if err != nil || len(salt) != openLDAPPBKDF2SaltSize {
		return false
	}
	expected, err := decodeOpenLDAPPBKDF2Base64(fields[2])
	if err != nil || len(expected) != parameters.keyLength {
		return false
	}
	actual := pbkdf2.Key(
		password,
		salt,
		iterations,
		parameters.keyLength,
		parameters.newHash,
	)
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

func openLDAPPBKDF2SchemeParameters(
	scheme string,
) (openLDAPPBKDF2Parameters, bool) {
	switch scheme {
	case "PBKDF2", "PBKDF2-SHA1":
		return openLDAPPBKDF2Parameters{newHash: sha1.New, keyLength: sha1.Size}, true
	case "PBKDF2-SHA256":
		return openLDAPPBKDF2Parameters{newHash: sha256.New, keyLength: sha256.Size}, true
	case "PBKDF2-SHA512":
		return openLDAPPBKDF2Parameters{newHash: sha512.New, keyLength: sha512.Size}, true
	default:
		return openLDAPPBKDF2Parameters{}, false
	}
}

func parseOpenLDAPPBKDF2Iterations(value string) (int, bool) {
	if len(value) == 0 || len(value) > 8 {
		return 0, false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	iterations, err := strconv.Atoi(value)
	if err != nil || iterations < 1 || iterations > MaxOpenLDAPPBKDF2Iterations {
		return 0, false
	}
	return iterations, true
}

func decodeOpenLDAPPBKDF2Base64(value string) ([]byte, error) {
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
	normalized = string(stripOpenLDAPBase64Whitespace([]byte(normalized)))
	return base64.StdEncoding.Strict().DecodeString(normalized)
}
