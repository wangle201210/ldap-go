package directory

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

// ValidateDNIdentityInScopeBytes has the same results and error ordering as
// ValidateDNIdentityInScope. Simple ASCII DNs with matching v2 cardinalities and
// keys fitting the stack buffer avoid string copies and allocations. All other
// inputs use the string implementation to preserve its validation details.
// Neither input is modified or retained.
//
// Handle validationErr first; scopeErr remains deferred until after any callback
// deadline check, including for valid entries outside the requested scope.
func ValidateDNIdentityInScopeBytes(value, key []byte, base DN, scope Scope) (inScope bool, scopeErr error, validationErr error) {
	var scratch [1024]byte
	if base.hasSchemaAwareIdentity() {
		if inScope, ok := validateSimpleDNIdentityInScopeBytes(value, key, base, scope, scratch[:]); ok {
			return inScope, nil, nil
		}
	}
	return ValidateDNIdentityInScope(string(value), string(key), base, scope)
}

func validateSimpleDNIdentityInScopeBytes(value, key []byte, base DN, scope Scope, scratch []byte) (inScope, ok bool) {
	if !bytes.HasPrefix(key, []byte(schemaAwareDNKeyPrefix)) {
		return false, false
	}
	depth, simple := simpleDNDepthBytes(value)
	if !simple {
		return false, false
	}
	encoded := key[len(schemaAwareDNKeyPrefix):]
	if base64.RawURLEncoding.DecodedLen(len(encoded)) > len(scratch) ||
		bytes.IndexByte(encoded, '\r') >= 0 || bytes.IndexByte(encoded, '\n') >= 0 {
		return false, false
	}
	n, err := base64.RawURLEncoding.Strict().Decode(scratch, encoded)
	if err != nil {
		return false, false
	}
	payload := scratch[:n]
	count, n := binary.Uvarint(payload)
	if n <= 0 {
		return false, false
	}
	payload = payload[n:]
	if count > uint64(len(payload))+1 || count != uint64(depth) {
		return false, false
	}
	baseDepth := len(base.identityRDNs)
	equal, ancestor := baseDepth == depth, baseDepth < depth
	offset := depth - baseDepth
	// Fuse framing, AVA validation and suffix comparison. A scope mismatch must
	// not skip later validation; any failure defers error precedence to fallback.
	for index := range depth {
		length, n := binary.Uvarint(payload)
		if n <= 0 {
			return false, false
		}
		payload = payload[n:]
		if length > uint64(len(payload)) {
			return false, false
		}
		rdn := payload[:int(length):int(length)]
		payload = payload[int(length):]
		if !validSingleAVADNIdentityRDN(rdn) {
			return false, false
		}
		if (equal || ancestor) && index >= offset && !bytes.Equal(base.identityRDNs[index-offset], rdn) {
			equal, ancestor = false, false
		}
	}
	if len(payload) != 0 {
		return false, false
	}
	switch scope {
	case ScopeBase:
		return equal, true
	case ScopeSingleLevel:
		return ancestor && depth == baseDepth+1, true
	case ScopeWholeSubtree:
		return equal || ancestor, true
	case ScopeChildren:
		return ancestor, true
	default:
		return false, true
	}
}

// Validate one complete single-AVA RDN without re-reading its nested lengths.
// Exact final lengths reject trailing bytes at both levels; Uvarint preserves
// acceptance of non-minimal encodings. Failures use the caller's full fallback.
func validSingleAVADNIdentityRDN(encoded []byte) bool {
	// Common RDNs use one-byte lengths at every level. Check all framing before
	// accepting; larger or nonminimal varints retain the general validator.
	if len(encoded) >= 6 && encoded[0] == 1 && encoded[1] < 128 &&
		int(encoded[1]) == len(encoded)-2 && encoded[2] == 2 &&
		encoded[3] > 0 && encoded[3] < 128 {
		valueOffset := 4 + int(encoded[3])
		if valueOffset < len(encoded) && encoded[valueOffset] < 128 &&
			int(encoded[valueOffset]) == len(encoded)-valueOffset-1 {
			return true
		}
	}
	count, n := binary.Uvarint(encoded)
	if n <= 0 || count != 1 {
		return false
	}
	encoded = encoded[n:]
	length, n := binary.Uvarint(encoded)
	if n <= 0 || length != uint64(len(encoded)-n) {
		return false
	}
	encoded = encoded[n:]
	count, n = binary.Uvarint(encoded)
	if n <= 0 || count != 2 {
		return false
	}
	encoded = encoded[n:]
	length, n = binary.Uvarint(encoded)
	if n <= 0 || length == 0 || length > uint64(len(encoded)-n) {
		return false
	}
	encoded = encoded[n+int(length):]
	length, n = binary.Uvarint(encoded)
	return n > 0 && length == uint64(len(encoded)-n)
}

// Recognize the same strict ASCII subset as simpleDNDepth without string copies.
func simpleDNDepthBytes(value []byte) (int, bool) {
	depth := 0
	for len(value) > 0 {
		rdn, rest, more := bytes.Cut(value, []byte(","))
		attribute, assertion, found := bytes.Cut(rdn, []byte("="))
		if !found || !validDNAttributeTypeBytes(attribute) || len(assertion) == 0 {
			return 0, false
		}
		for _, c := range assertion {
			if !asciiDNAttributeLetter(c) && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
				return 0, false
			}
		}
		depth++
		if !more {
			return depth, true
		}
		value = rest
	}
	return 0, false
}

func validDNAttributeTypeBytes(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		for {
			arc, rest, more := bytes.Cut(value, []byte("."))
			if len(arc) == 0 || len(arc) > 1 && arc[0] == '0' {
				return false
			}
			for _, c := range arc {
				if c < '0' || c > '9' {
					return false
				}
			}
			if !more {
				return true
			}
			value = rest
		}
	}
	if !asciiDNAttributeLetter(value[0]) {
		return false
	}
	for _, c := range value[1:] {
		if !asciiDNAttributeLetter(c) && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
