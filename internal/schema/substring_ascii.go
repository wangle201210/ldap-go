package schema

const maxSubstringASCIIIdentityBytes = 128

// substringASCIIIdentity proves byte-for-byte identity under normalizeSpace
// (caseIgnore=false) or normalizeCaseIgnore (caseIgnore=true). It deliberately
// rejects long values, whitespace and non-ASCII bytes. The length bound avoids
// an extra full scan when a large value requires normalization near its end.
func substringASCIIIdentity(value []byte, caseIgnore bool) bool {
	if len(value) > maxSubstringASCIIIdentityBytes {
		return false
	}
	for _, c := range value {
		if c >= 0x80 || c == ' ' || (c >= '\t' && c <= '\r') {
			return false
		}
		if caseIgnore && c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

// normalizeSubstringASCIIValue may borrow value, including nil/empty slices.
// The result is read-only and valid only during matching; callers must not
// retain it or use this wrapper to normalize owned assertion parts. Ordered
// values must have their prefix validated and removed by the caller first.
func normalizeSubstringASCIIValue(value []byte, caseIgnore bool) []byte {
	if substringASCIIIdentity(value, caseIgnore) {
		return value
	}
	if caseIgnore {
		return normalizeCaseIgnore(value)
	}
	return normalizeSpace(value)
}
