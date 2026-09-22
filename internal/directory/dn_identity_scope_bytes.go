package directory

import (
	"bytes"
	"encoding/base64"
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
		if rdns, ok := validatedSimpleDNIdentityRDNsBytes(value, key, scratch[:]); ok {
			return dnIdentityRDNsInScope(base, rdns, scope), nil, nil
		}
	}
	return ValidateDNIdentityInScope(string(value), string(key), base, scope)
}

func validatedSimpleDNIdentityRDNsBytes(value, key, scratch []byte) (dnIdentityParts, bool) {
	if !bytes.HasPrefix(key, []byte(schemaAwareDNKeyPrefix)) {
		return dnIdentityParts{}, false
	}
	depth, simple := simpleDNDepthBytes(value)
	if !simple {
		return dnIdentityParts{}, false
	}
	encoded := key[len(schemaAwareDNKeyPrefix):]
	if base64.RawURLEncoding.DecodedLen(len(encoded)) > len(scratch) ||
		bytes.IndexByte(encoded, '\r') >= 0 || bytes.IndexByte(encoded, '\n') >= 0 {
		return dnIdentityParts{}, false
	}
	n, err := base64.RawURLEncoding.Strict().Decode(scratch, encoded)
	if err != nil {
		return dnIdentityParts{}, false
	}
	rdns, err := viewDNIdentityParts(scratch[:n])
	if err != nil || rdns.count != depth {
		return dnIdentityParts{}, false
	}
	remaining := rdns
	for range rdns.count {
		avas, err := viewDNIdentityParts(remaining.next())
		if err != nil || avas.count != 1 {
			return dnIdentityParts{}, false
		}
		parts, err := viewDNIdentityParts(avas.next())
		if err != nil || parts.count != 2 || len(parts.next()) == 0 {
			return dnIdentityParts{}, false
		}
	}
	return rdns, true
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
