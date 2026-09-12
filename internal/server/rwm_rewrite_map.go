package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	rwmRewriteMaximumMaps          = 64
	rwmRewriteMaximumMapOperations = 16
	rwmRewriteMaximumMapSteps      = 4 << 20
)

// OpenLDAP 2.6.13 d172686d3d270bc961b78f3ff00d7019c8dfb094 registers
// only ldap and escape in libraries/librewrite/map.c. escapemap.c defines
// these four operations; dynamically registered and LDAP maps stay unsupported.
type rwmRewriteMap struct {
	operations []string
}

func (engine *rwmRewriteEngine) parseMap(words []string) error {
	if len(words) < 3 {
		return errors.New("rewriteMap expects a type, name, and mapper arguments")
	}
	if !strings.EqualFold(words[1], "escape") {
		return fmt.Errorf("rewriteMap is not implemented for type %q", words[1])
	}
	name, err := validateRWMRewriteMapName(words[2])
	if err != nil {
		return err
	}
	key := strings.ToLower(name)
	if engine.maps[key] != nil {
		return fmt.Errorf("rewrite map %q is already defined", name)
	}
	if len(engine.maps) >= rwmRewriteMaximumMaps {
		return fmt.Errorf("rewrite map count exceeds %d", rwmRewriteMaximumMaps)
	}
	// Native rm_config returns NULL for empty/unknown operation lists;
	// reject them before publishing a map that cannot be applied safely.
	if len(words) < 4 || len(words)-3 > rwmRewriteMaximumMapOperations {
		return fmt.Errorf("rewriteMap escape expects 1 to %d operations", rwmRewriteMaximumMapOperations)
	}
	mapper := &rwmRewriteMap{}
	for _, word := range words[3:] {
		if len(word) > len("unescapefilter") {
			return errors.New("rewriteMap escape has an unknown operation")
		}
		switch operation := strings.ToLower(word); operation {
		case "escape2dn", "escape2filter", "unescapedn", "unescapefilter":
			mapper.operations = append(mapper.operations, operation)
		default:
			return fmt.Errorf("rewriteMap escape has unknown operation %q", word)
		}
	}
	engine.maps[key] = mapper
	engine.configured = true
	return nil
}

func rwmRewriteCString(value string) string {
	if end := strings.IndexByte(value, 0); end >= 0 {
		return value[:end]
	}
	return value
}

func (mapper *rwmRewriteMap) apply(input string, operation *rwmRewriteOperation) (string, error) {
	if len(input) > rwmRewriteMaximumInputBytes {
		return "", errors.New("rewrite map input limit exceeded")
	}
	// rm_apply receives a C string, but operations within one escape map
	// exchange bervals and can preserve decoded NUL bytes between stages.
	value := rwmRewriteCString(input)
	for _, stage := range mapper.operations {
		operation.mapSteps += len(value) + 1
		operation.expansionSteps++
		if operation.mapSteps > rwmRewriteMaximumMapSteps || operation.expansionSteps > rwmRewriteMaximumExpansionSteps {
			return "", errors.New("rewrite map work limit exceeded")
		}
		var err error
		switch stage {
		case "escape2dn", "escape2filter":
			value, err = rwmRewriteEscape(value, stage == "escape2dn")
		case "unescapedn":
			value, err = rwmRewriteUnescapeDN(value)
		case "unescapefilter":
			value, err = rwmRewriteUnescapeFilter(rwmRewriteCString(value))
		}
		if err != nil {
			return "", err
		}
	}
	return value, nil
}

func rwmRewriteEscape(input string, dn bool) (string, error) {
	if dn && !rwmRewriteDNUtf8(input) {
		return "", errors.New("escape2dn received invalid UTF-8")
	}
	var output strings.Builder
	const digits = "0123456789ABCDEF"
	for index := 0; index < len(input); index++ {
		c := input[index]
		escape := c < ' ' || c >= 0x7f || strings.ContainsRune("()*\\", rune(c))
		if dn {
			escape = c == 0 || c >= 0x80 || strings.ContainsRune(",+\"\\<>;=", rune(c)) ||
				index == 0 && (c == '#' || rwmRewriteDNSpace(c)) ||
				index == len(input)-1 && rwmRewriteDNSpace(c)
		}
		size := 1
		if escape {
			size = 3
		}
		if output.Len()+size > rwmRewriteMaximumOutputBytes {
			return "", errors.New("rewrite map output limit exceeded")
		}
		if escape {
			output.WriteByte('\\')
			output.WriteByte(digits[c>>4])
			output.WriteByte(digits[c&15])
		} else {
			output.WriteByte(c)
		}
	}
	return output.String(), nil
}

// libldap/getdn.c uses the historical RFC 2279 validator in utf-8.c:
// shortest encodings of two through six bytes, including surrogate values.
func rwmRewriteDNUtf8(value string) bool {
	for index := 0; index < len(value); {
		c := value[index]
		if c < 0x80 {
			index++
			continue
		}
		length, minimum := 0, byte(0x80)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			length = 2
		case c >= 0xe0 && c <= 0xef:
			length = 3
			if c == 0xe0 {
				minimum = 0x20
			}
		case c >= 0xf0 && c <= 0xf7:
			length = 4
			if c == 0xf0 {
				minimum = 0x30
			}
		case c >= 0xf8 && c <= 0xfb:
			length = 5
			if c == 0xf8 {
				minimum = 0x38
			}
		case c >= 0xfc && c <= 0xfd:
			length = 6
			if c == 0xfc {
				minimum = 0x3c
			}
		default:
			return false
		}
		if length > len(value)-index || value[index+1]&minimum == 0 {
			return false
		}
		for offset := 1; offset < length; offset++ {
			if value[index+offset]&0xc0 != 0x80 {
				return false
			}
		}
		index += length
	}
	return true
}

func rwmRewriteUnescapeFilter(input string) (string, error) {
	var output strings.Builder
	for index := 0; index < len(input); index++ {
		c := input[index]
		switch c {
		case '(', ')', '*':
			return "", errors.New("unescapefilter received an unescaped metacharacter")
		case '\\':
			index++
			if index >= len(input) {
				return "", errors.New("unescapefilter received an incomplete escape")
			}
			c = input[index]
			if !strings.ContainsRune("()*\\", rune(c)) {
				var decoded [1]byte
				if index+1 >= len(input) {
					return "", errors.New("unescapefilter received an incomplete hex escape")
				}
				if _, err := hex.Decode(decoded[:], []byte(input[index:index+2])); err != nil {
					return "", errors.New("unescapefilter received an invalid escape")
				}
				c = decoded[0]
				index++
			}
		}
		output.WriteByte(c)
	}
	return output.String(), nil
}

func rwmRewriteDNSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func rwmRewriteDNSeparator(c byte) bool {
	return c == ',' || c == '+'
}

func rwmRewriteDNLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// escapemap.c parses "uid=" + input as a complete LDAPv3 DN and returns
// the first AVA's raw bytes. In particular, #hex stays BER bytes, and all
// subsequent AVAs must parse even though their values are discarded.
func rwmRewriteUnescapeDN(input string) (string, error) {
	if strings.IndexByte(input, 0) >= 0 {
		return "", errors.New("unescapedn received a NUL byte")
	}
	var first string
	for offset := 0; ; {
		value, consumed, err := rwmRewriteDNValue(input[offset:])
		if err != nil {
			return "", err
		}
		if offset == 0 {
			first = value
		}
		offset += consumed
		if offset == len(input) {
			return first, nil
		}
		offset++
		for offset < len(input) && rwmRewriteDNSpace(input[offset]) {
			offset++
		}
		start := offset
		if offset < len(input) && rwmRewriteDNLetter(input[offset]) {
			for offset++; offset < len(input); offset++ {
				c := input[offset]
				if !rwmRewriteDNLetter(c) && (c < '0' || c > '9') && c != '-' && c != ';' {
					break
				}
			}
		} else {
			for offset < len(input) && input[offset] >= '0' && input[offset] <= '9' {
				offset++
				if offset < len(input) && input[offset] == '.' {
					offset++
					if offset == len(input) || input[offset] < '0' || input[offset] > '9' {
						return "", errors.New("unescapedn received an invalid attribute OID")
					}
				}
			}
		}
		if offset == start {
			return "", errors.New("unescapedn received an invalid attribute type")
		}
		for offset < len(input) && rwmRewriteDNSpace(input[offset]) {
			offset++
		}
		if offset == len(input) || input[offset] != '=' {
			return "", errors.New("unescapedn expected an attribute value")
		}
		offset++
	}
}

func rwmRewriteDNValue(input string) (string, int, error) {
	start := 0
	for start < len(input) && rwmRewriteDNSpace(input[start]) {
		start++
	}
	end := start
	if start < len(input) && input[start] == '#' {
		start++
		end = start
		if start == len(input) {
			return "", 0, errors.New("unescapedn received an incomplete binary value")
		}
		for end < len(input) && !rwmRewriteDNSeparator(input[end]) && !rwmRewriteDNSpace(input[end]) {
			end++
		}
		decoded, err := hex.DecodeString(input[start:end])
		if err != nil {
			return "", 0, errors.New("unescapedn received invalid hex")
		}
		// getdn.c's non-pedantic binary parser ignores everything after
		// whitespace until the next AVA/RDN separator.
		for end < len(input) && !rwmRewriteDNSeparator(input[end]) {
			end++
		}
		return string(decoded), end, nil
	}
	for end < len(input) && !rwmRewriteDNSeparator(input[end]) {
		c := input[end]
		if c == '\\' {
			end++
			if end == len(input) {
				return "", 0, errors.New("unescapedn received an incomplete escape")
			}
			if !strings.ContainsRune("\\,+=<>;\"# \t\n\r", rune(input[end])) {
				var decoded [1]byte
				if end+1 >= len(input) {
					return "", 0, errors.New("unescapedn received an incomplete hex escape")
				}
				if _, err := hex.Decode(decoded[:], []byte(input[end:end+2])); err != nil {
					return "", 0, errors.New("unescapedn received an invalid escape")
				}
				end++
			}
		} else if strings.ContainsRune("\";<>", rune(c)) {
			return "", 0, errors.New("unescapedn received an unescaped metacharacter")
		}
		end++
	}
	trimmed := end
	for trimmed > start+1 && rwmRewriteDNSpace(input[trimmed-1]) && input[trimmed-2] != '\\' {
		trimmed--
	}
	var output strings.Builder
	for index := start; index < trimmed; index++ {
		c := input[index]
		if c == '\\' {
			index++
			c = input[index]
			if !strings.ContainsRune("\\,+=<>;\"# \t\n\r", rune(c)) {
				var decoded [1]byte
				_, _ = hex.Decode(decoded[:], []byte(input[index:index+2]))
				c = decoded[0]
				index++
			}
		}
		output.WriteByte(c)
	}
	return output.String(), end, nil
}
