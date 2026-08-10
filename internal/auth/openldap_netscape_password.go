package auth

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
)

const (
	OpenLDAPNetscapeMTAHashScheme = "{NS-MTA-MD5}"

	openLDAPNetscapeDigestSize  = md5.Size * 2
	openLDAPNetscapeSaltSize    = 32
	openLDAPNetscapePayloadSize = openLDAPNetscapeDigestSize +
		openLDAPNetscapeSaltSize
)

// verifyOpenLDAPNetscape implements OpenLDAP's verify-only NS-MTA-MD5 scheme.
func verifyOpenLDAPNetscape(payload, password []byte) bool {
	if len(payload) != openLDAPNetscapePayloadSize {
		return false
	}

	salt := payload[openLDAPNetscapeDigestSize:]
	hasher := md5.New()
	_, _ = hasher.Write(salt)
	_, _ = hasher.Write([]byte{0x59})
	_, _ = hasher.Write(password)
	_, _ = hasher.Write([]byte{0xf7})
	_, _ = hasher.Write(salt)

	var encoded [openLDAPNetscapeDigestSize]byte
	hex.Encode(encoded[:], hasher.Sum(nil))
	return subtle.ConstantTimeCompare(payload[:openLDAPNetscapeDigestSize], encoded[:]) == 1
}
