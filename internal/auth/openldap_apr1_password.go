package auth

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	OpenLDAPAPR1HashScheme   = "{APR1}"
	OpenLDAPBSDMD5HashScheme = "{BSDMD5}"

	openLDAPAPR1SaltSize       = 8
	maxOpenLDAPPHKPasswordSize = 4 << 10
	maxOpenLDAPPHKStoredSize   = 4 << 10
	maxOpenLDAPPHKPayloadSize  = 108
	maxOpenLDAPPHKSaltSize     = 64
	openLDAPAPR1SaltCharacters = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func hashPasswordOpenLDAPPHK(
	password []byte,
	scheme string,
	random io.Reader,
) ([]byte, error) {
	if len(password) == 0 || len(password) > maxOpenLDAPPHKPasswordSize {
		return nil, fmt.Errorf(
			"password length must be between 1 and %d bytes",
			maxOpenLDAPPHKPasswordSize,
		)
	}
	magic, ok := openLDAPPHKMagic(scheme)
	if !ok {
		return nil, fmt.Errorf("unsupported OpenLDAP PHK scheme %q", scheme)
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, openLDAPAPR1SaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	for index := range salt {
		salt[index] = openLDAPAPR1SaltCharacters[int(salt[index])%len(openLDAPAPR1SaltCharacters)]
	}
	digest := openLDAPPHKDigest(password, salt, magic)
	payload := make([]byte, 0, len(digest)+len(salt))
	payload = append(payload, digest[:]...)
	payload = append(payload, salt...)
	return []byte(scheme + base64.StdEncoding.EncodeToString(payload)), nil
}

func verifyOpenLDAPPHK(scheme string, payload, password []byte) bool {
	if len(password) == 0 || len(password) > maxOpenLDAPPHKPasswordSize {
		return false
	}
	payload, ok := boundedOpenLDAPBase64(payload, maxOpenLDAPPHKPayloadSize)
	if !ok {
		return false
	}
	magic, ok := openLDAPPHKMagic("{" + scheme + "}")
	if !ok {
		return false
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(payload)))
	decodedLength, err := base64.StdEncoding.Strict().Decode(decoded, payload)
	if err != nil {
		return false
	}
	decoded = decoded[:decodedLength]
	if len(decoded) <= md5.Size || len(decoded)-md5.Size > maxOpenLDAPPHKSaltSize {
		return false
	}
	salt := decoded[md5.Size:]
	actual := openLDAPPHKDigest(password, salt, magic)
	return subtle.ConstantTimeCompare(decoded[:md5.Size], actual[:]) == 1
}

func boundedOpenLDAPBase64(value []byte, limit int) ([]byte, bool) {
	if len(value) > maxOpenLDAPPHKStoredSize {
		return nil, false
	}
	for _, character := range value {
		if openLDAPBase64Whitespace(character) {
			cleaned := make([]byte, 0, min(len(value), limit))
			for _, remaining := range value {
				if openLDAPBase64Whitespace(remaining) {
					continue
				}
				if len(cleaned) == limit {
					return nil, false
				}
				cleaned = append(cleaned, remaining)
			}
			return cleaned, len(cleaned) > 0
		}
	}
	return value, len(value) > 0 && len(value) <= limit
}

func openLDAPPHKMagic(scheme string) ([]byte, bool) {
	switch scheme {
	case OpenLDAPAPR1HashScheme:
		return []byte("$apr1$"), true
	case OpenLDAPBSDMD5HashScheme:
		return []byte("$1$"), true
	default:
		return nil, false
	}
}

func openLDAPPHKDigest(password, salt, magic []byte) [md5.Size]byte {
	hasher := md5.New()
	_, _ = hasher.Write(password)
	_, _ = hasher.Write(magic)
	_, _ = hasher.Write(salt)

	inner := md5.New()
	_, _ = inner.Write(password)
	_, _ = inner.Write(salt)
	_, _ = inner.Write(password)
	innerDigest := inner.Sum(nil)
	for remaining := len(password); remaining > 0; remaining -= md5.Size {
		length := min(remaining, md5.Size)
		_, _ = hasher.Write(innerDigest[:length])
	}

	zeroDigest := [md5.Size]byte{}
	for remaining := len(password); remaining > 0; remaining >>= 1 {
		if remaining&1 != 0 {
			_, _ = hasher.Write(zeroDigest[:1])
		} else {
			_, _ = hasher.Write(password[:1])
		}
	}
	var digest [md5.Size]byte
	copy(digest[:], hasher.Sum(nil))

	for round := 0; round < 1000; round++ {
		hasher.Reset()
		if round&1 != 0 {
			_, _ = hasher.Write(password)
		} else {
			_, _ = hasher.Write(digest[:])
		}
		if round%3 != 0 {
			_, _ = hasher.Write(salt)
		}
		if round%7 != 0 {
			_, _ = hasher.Write(password)
		}
		if round&1 != 0 {
			_, _ = hasher.Write(digest[:])
		} else {
			_, _ = hasher.Write(password)
		}
		copy(digest[:], hasher.Sum(nil))
	}
	return digest
}
