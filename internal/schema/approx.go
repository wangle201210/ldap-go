package schema

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const openLDAPApproximatePhonemeLength = 4

// AssociatedApproximateMatchingRule returns the OpenLDAP 2.6.13 approximate
// rule associated with a built-in equality matching rule.
func AssociatedApproximateMatchingRule(equality string) (string, bool) {
	switch canonicalMatchingRule(equality) {
	case "caseignorematch", "caseexactmatch":
		return "directorystringapproxmatch", true
	case "caseignoreia5match", "caseexactia5match":
		return "ia5stringapproxmatch", true
	default:
		return "", false
	}
}

// ApproximateIndexKeys returns the OpenLDAP approximate index keys for one
// value. Each non-empty normalized word contributes one Metaphone key. The
// boolean reports whether every word produced an indexable key; callers must
// scan for assertions containing an empty Metaphone key to avoid false
// negatives.
func ApproximateIndexKeys(rule string, value []byte) ([][]byte, bool) {
	switch canonicalMatchingRule(rule) {
	case "directorystringapproxmatch", "ia5stringapproxmatch":
	default:
		return nil, false
	}
	normalized, ok := normalizeOpenLDAPApproximate(value)
	if !ok {
		return nil, false
	}
	words := splitOpenLDAPApproximateWords(normalized)
	keys := make([][]byte, 0, len(words))
	complete := true
	for _, word := range words {
		key := openLDAPMetaphone(word)
		if key != "" {
			keys = append(keys, []byte(key))
		} else {
			complete = false
		}
	}
	return keys, complete
}

// MatchApproximate applies an attribute's associated approximate rule. When
// no rule is associated, OpenLDAP falls back to the equality matching rule.
func (registry *Registry) MatchApproximate(
	attributeName string,
	value, assertion []byte,
) (bool, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return false, err
	}
	if rule, associated := AssociatedApproximateMatchingRule(effective.Equality); associated {
		return matchOpenLDAPApproximate(rule, value, assertion), nil
	}
	if effective.Equality == "" {
		return false, fmt.Errorf("attribute %q has no equality matching rule", attributeName)
	}
	comparison, err := registry.compareWithRuleLocked(effective.Equality, value, assertion)
	return comparison == 0, err
}

func matchOpenLDAPApproximate(rule string, value, assertion []byte) bool {
	switch canonicalMatchingRule(rule) {
	case "directorystringapproxmatch", "ia5stringapproxmatch":
	default:
		return false
	}
	normalizedValue, ok := normalizeOpenLDAPApproximate(value)
	if !ok {
		return false
	}
	normalizedAssertion, ok := normalizeOpenLDAPApproximate(assertion)
	if !ok {
		return false
	}

	valueWords := splitOpenLDAPApproximateWords(normalizedValue)
	assertionWords := splitOpenLDAPApproximateWords(normalizedAssertion)
	if len(assertionWords) == 0 {
		return false
	}
	phoneticValues := make([]string, len(valueWords))
	for index, word := range valueWords {
		phoneticValues[index] = openLDAPMetaphone(word)
	}

	next := 0
	for _, word := range assertionWords {
		phonetic := openLDAPMetaphone(word)
		matched := false
		for next < len(phoneticValues) {
			candidate := phoneticValues[next]
			next++
			if candidate == phonetic {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return next > 0
}

// LDAP_UTF8_APPROX uses compatibility decomposition and discards every
// decomposed non-ASCII code point. ASCII input is retained verbatim.
func normalizeOpenLDAPApproximate(value []byte) ([]byte, bool) {
	if !utf8.Valid(value) {
		return nil, false
	}
	decomposed := norm.NFKD.Bytes(value)
	normalized := make([]byte, 0, len(decomposed))
	for len(decomposed) > 0 {
		r, size := utf8.DecodeRune(decomposed)
		if r < utf8.RuneSelf {
			normalized = append(normalized, byte(r))
		}
		decomposed = decomposed[size:]
	}
	return normalized, true
}

func splitOpenLDAPApproximateWords(value []byte) [][]byte {
	parts := bytes.Split(value, []byte{' '})
	words := make([][]byte, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			words = append(words, part)
		}
	}
	return words
}

func openLDAPMetaphone(word []byte) string {
	letters := make([]byte, 0, 31)
	for _, character := range word {
		if openLDAPWordBreak(character) || len(letters) == 31 {
			break
		}
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		if character >= 'A' && character <= 'Z' {
			letters = append(letters, character)
		}
	}
	if len(letters) == 0 {
		return ""
	}

	// Four leading and four trailing NUL bytes reproduce phonetic.c's
	// pointer look-behind/look-ahead without boundary special cases.
	padded := make([]byte, len(letters)+8)
	copy(padded[4:], letters)
	start := 4
	end := 4 + len(letters)
	switch padded[start] {
	case 'P', 'K', 'G':
		if padded[start+1] == 'N' {
			padded[start] = 0
			start++
		}
	case 'A':
		if padded[start+1] == 'E' {
			padded[start] = 0
			start++
		}
	case 'W':
		if padded[start+1] == 'R' {
			padded[start] = 0
			start++
		} else if padded[start+1] == 'H' {
			padded[start+1] = padded[start]
			padded[start] = 0
			start++
		}
	case 'X':
		padded[start] = 'S'
	}

	metaphone := make([]byte, 0, openLDAPApproximatePhonemeLength)
	ksPending := false
	for position := start; position <= end && len(metaphone) < cap(metaphone); position++ {
		if ksPending {
			ksPending = false
			metaphone = append(metaphone, 'S')
			continue
		}
		character := padded[position]
		if padded[position-1] == character && character != 'C' {
			continue
		}
		if openLDAPSame(character) || position == start && openLDAPVowel(character) {
			metaphone = append(metaphone, character)
			continue
		}
		switch character {
		case 'B':
			if position == end-1 && padded[position-1] != 'M' {
				metaphone = append(metaphone, character)
			}
		case 'C':
			if padded[position-1] != 'S' || !openLDAPFrontVowel(padded[position+1]) {
				switch {
				case padded[position+1] == 'I' && padded[position+2] == 'A':
					metaphone = append(metaphone, 'X')
				case openLDAPFrontVowel(padded[position+1]):
					metaphone = append(metaphone, 'S')
				case padded[position+1] == 'H':
					if position == start && !openLDAPVowel(padded[position+2]) || padded[position-1] == 'S' {
						metaphone = append(metaphone, 'K')
					} else {
						metaphone = append(metaphone, 'X')
					}
				default:
					metaphone = append(metaphone, 'K')
				}
			}
		case 'D':
			if padded[position+1] == 'G' && openLDAPFrontVowel(padded[position+2]) {
				metaphone = append(metaphone, 'J')
			} else {
				metaphone = append(metaphone, 'T')
			}
		case 'G':
			if (padded[position+1] != 'J' || openLDAPVowel(padded[position+2])) &&
				(padded[position+1] != 'N' || position+1 < end &&
					(padded[position+2] != 'E' || padded[position+3] != 'D')) &&
				(padded[position-1] != 'D' || !openLDAPFrontVowel(padded[position+1])) {
				if openLDAPFrontVowel(padded[position+1]) && padded[position+2] != 'G' {
					metaphone = append(metaphone, 'G')
				} else {
					metaphone = append(metaphone, 'K')
				}
			} else if padded[position+1] == 'H' &&
				!openLDAPNoGHF(padded[position-3]) && padded[position-4] != 'H' {
				metaphone = append(metaphone, 'F')
			}
		case 'H':
			if !openLDAPVariableConsonant(padded[position-1]) &&
				(!openLDAPVowel(padded[position-1]) || openLDAPVowel(padded[position+1])) {
				metaphone = append(metaphone, 'H')
			}
		case 'K':
			if padded[position-1] != 'C' {
				metaphone = append(metaphone, 'K')
			}
		case 'P':
			if padded[position+1] == 'H' {
				metaphone = append(metaphone, 'F')
			} else {
				metaphone = append(metaphone, 'P')
			}
		case 'Q':
			metaphone = append(metaphone, 'K')
		case 'S':
			if padded[position+1] == 'H' || padded[position+1] == 'I' &&
				(padded[position+2] == 'O' || padded[position+2] == 'A') {
				metaphone = append(metaphone, 'X')
			} else {
				metaphone = append(metaphone, 'S')
			}
		case 'T':
			switch {
			case padded[position+1] == 'I' &&
				(padded[position+2] == 'O' || padded[position+2] == 'A'):
				metaphone = append(metaphone, 'X')
			case padded[position+1] == 'H':
				metaphone = append(metaphone, '0')
			case padded[position+1] != 'C' || padded[position+2] != 'H':
				metaphone = append(metaphone, 'T')
			}
		case 'V':
			metaphone = append(metaphone, 'F')
		case 'W', 'Y':
			if openLDAPVowel(padded[position+1]) {
				metaphone = append(metaphone, character)
			}
		case 'X':
			if position == start {
				metaphone = append(metaphone, 'S')
			} else {
				metaphone = append(metaphone, 'K')
				ksPending = true
			}
		case 'Z':
			metaphone = append(metaphone, 'S')
		}
	}
	if len(metaphone) > openLDAPApproximatePhonemeLength {
		metaphone = metaphone[:openLDAPApproximatePhonemeLength]
	}
	return string(metaphone)
}

func openLDAPWordBreak(character byte) bool {
	return character == 0 || character >= utf8.RuneSelf ||
		character >= '0' && character <= '9' ||
		character == ' ' || character >= '\t' && character <= '\r' ||
		character >= '!' && character <= '/' ||
		character >= ':' && character <= '@' ||
		character >= '[' && character <= '`' ||
		character >= '{' && character <= '~'
}

func openLDAPVowel(character byte) bool {
	return character == 'A' || character == 'E' || character == 'I' ||
		character == 'O' || character == 'U'
}

func openLDAPSame(character byte) bool {
	return bytes.IndexByte([]byte("FJLMNR"), character) >= 0
}

func openLDAPVariableConsonant(character byte) bool {
	return bytes.IndexByte([]byte("CGPST"), character) >= 0
}

func openLDAPFrontVowel(character byte) bool {
	return character == 'E' || character == 'I' || character == 'Y'
}

func openLDAPNoGHF(character byte) bool {
	return character == 'B' || character == 'D' || character == 'H'
}
