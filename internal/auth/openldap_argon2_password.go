package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	cryptargon2 "github.com/sergeymakinen/go-crypt/argon2"
)

const (
	OpenLDAPArgon2HashScheme       = "{ARGON2}"
	OpenLDAPArgon2DefaultMemory    = uint32(7168)
	OpenLDAPArgon2DefaultTime      = uint32(5)
	OpenLDAPArgon2DefaultThreads   = uint8(1)
	OpenLDAPArgon2MaxMemory        = uint32(256 * 1024)
	OpenLDAPArgon2MaxTime          = uint32(100)
	OpenLDAPArgon2MaxThreads       = uint8(32)
	openLDAPArgon2SaltLength       = 16
	openLDAPArgon2HashLength       = 32
	openLDAPArgon2MaxEncodedLength = 1024
)

func HashPasswordOpenLDAPArgon2(password []byte, random io.Reader) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, openLDAPArgon2SaltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate ARGON2 salt: %w", err)
	}
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	key, err := cryptargon2.Key(
		password,
		[]byte(encodedSalt),
		OpenLDAPArgon2DefaultMemory,
		OpenLDAPArgon2DefaultTime,
		OpenLDAPArgon2DefaultThreads,
		&cryptargon2.CompatibilityOptions{
			Prefix:  cryptargon2.Prefix2id,
			Version: cryptargon2.Version13,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("derive ARGON2 password: %w", err)
	}
	payload := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		OpenLDAPArgon2DefaultMemory,
		OpenLDAPArgon2DefaultTime,
		OpenLDAPArgon2DefaultThreads,
		encodedSalt,
		base64.RawStdEncoding.EncodeToString(key),
	)
	clear(key)
	return append([]byte(OpenLDAPArgon2HashScheme), payload...), nil
}

func verifyOpenLDAPArgon2(payload, supplied []byte) bool {
	if len(payload) == 0 || len(payload) > openLDAPArgon2MaxEncodedLength ||
		len(supplied) == 0 {
		return false
	}
	hash := string(payload)
	salt, memory, timeCost, threads, options, err := cryptargon2.Params(hash)
	if err != nil || len(salt) == 0 || options == nil ||
		memory > OpenLDAPArgon2MaxMemory || timeCost > OpenLDAPArgon2MaxTime ||
		threads > OpenLDAPArgon2MaxThreads ||
		!strings.HasPrefix(options.Prefix, "$argon2") {
		return false
	}
	if decodedSalt, err := base64.RawStdEncoding.DecodeString(string(salt)); err != nil ||
		len(decodedSalt) < 8 || len(decodedSalt) > 64 {
		return false
	}
	return cryptargon2.Check(hash, string(supplied)) == nil
}
