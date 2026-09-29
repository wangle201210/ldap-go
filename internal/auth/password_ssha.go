package auth

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
)

func verifySSHA(encoded, password []byte) bool {
	encoded = stripOpenLDAPBase64Whitespace(encoded)
	// Keep common SSHA inputs local without limiting imported salts or passwords.
	var decodedBuffer [64]byte
	decoded := decodedBuffer[:]
	if size := base64.StdEncoding.DecodedLen(len(encoded)); size > len(decoded) {
		decoded = make([]byte, size)
	}
	n, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil || n <= sha1.Size {
		return false
	}

	salt := decoded[sha1.Size:n]
	var inputBuffer [256]byte
	input := inputBuffer[:0]
	if size := len(password) + len(salt); size > cap(input) {
		input = make([]byte, 0, size)
	}
	input = append(input, password...)
	input = append(input, salt...)
	actual := sha1.Sum(input)
	return subtle.ConstantTimeCompare(decoded[:sha1.Size], actual[:]) == 1
}
