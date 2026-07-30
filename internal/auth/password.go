package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// VerifyPassword supports the password schemes built into a typical OpenLDAP
// deployment that can be implemented without platform-specific crypt(3).
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
	default:
		return false
	}
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

func constantTimeEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}
