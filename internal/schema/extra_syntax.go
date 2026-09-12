package schema

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func validateDeliveryMethod(value []byte) error {
	for {
		end := bytes.IndexAny(value, " $")
		if end < 0 {
			end = len(value)
		}
		if end < 3 || end > len("telephone") {
			return errors.New("value is not a delivery method")
		}
		for _, character := range value[:end] {
			if character > 0x7f {
				return errors.New("value is not a delivery method")
			}
		}
		switch strings.ToLower(string(value[:end])) {
		case "any", "mhs", "physical", "telex", "teletex", "g3fax", "g4fax", "ia5", "videotex", "telephone":
		default:
			return errors.New("value is not a delivery method")
		}
		value = value[end:]
		if len(value) == 0 {
			return nil
		}
		// Native accepts only ASCII spaces around '$', with no trailing space
		// after the final method and no leading space before the first method.
		value = bytes.TrimLeft(value, " ")
		if len(value) == 0 || value[0] != '$' {
			return errors.New("value is not a delivery method")
		}
		value = bytes.TrimLeft(value[1:], " ")
	}
}

func validateNISNetgroupTriple(value []byte) error {
	if len(value) < 4 || value[0] != '(' || value[len(value)-1] != ')' {
		return errors.New("value is not a NIS netgroup triple")
	}
	commas := 0
	for _, character := range value[1 : len(value)-1] {
		if character == ',' {
			commas++
			if commas > 2 {
				return errors.New("value is not a NIS netgroup triple")
			}
		} else if !extraSyntaxADChar(character) {
			return errors.New("value is not a NIS netgroup triple")
		}
	}
	if commas != 2 {
		return errors.New("value is not a NIS netgroup triple")
	}
	return nil
}

func validateBootParameter(value []byte) error {
	keyEnd := bytes.IndexByte(value, '=')
	if keyEnd < 0 {
		return errors.New("value is not a boot parameter")
	}
	serverEnd := bytes.IndexByte(value[keyEnd+1:], ':')
	if serverEnd < 0 {
		return errors.New("value is not a boot parameter")
	}
	serverEnd += keyEnd + 1
	for _, part := range [][]byte{value[:keyEnd], value[keyEnd+1 : serverEnd]} {
		for _, character := range part {
			if !extraSyntaxADChar(character) {
				return errors.New("value is not a boot parameter")
			}
		}
	}
	// Native loops over path characters without requiring a nonempty path.
	path := value[serverEnd+1:]
	if len(path) != 0 && !validPrintableString(path) {
		return errors.New("value is not a boot parameter")
	}
	return nil
}

// AD_CHAR in OpenLDAP's slap.h, also used for both RFC2307 syntaxes.
func extraSyntaxADChar(character byte) bool {
	return character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' ||
		character == '-' || character == '.' || character == ';'
}

const maxRDNSyntaxLength = 8192 // SLAP_LDAPDN_MAXLEN in the pinned slap.h.

func validateRDN(value []byte) error {
	_, err := parseRDNSyntax(value)
	return err
}

// PrettyRDNValue returns OpenLDAP's schema-aware LDAP_DN_PRETTY form of the
// first RDN. It preserves naming-value case rather than applying equality
// normalization, and does not modify the supplied value.
func (registry *Registry) PrettyRDNValue(value []byte) ([]byte, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.prettyRDNValueLocked(value, 0)
}

func (registry *Registry) prettyRDNValueLocked(value []byte, depth int) ([]byte, error) {
	if depth >= 32 {
		return nil, errors.New("RDN syntax nesting exceeds 32 levels")
	}
	dn, err := parseRDNSyntaxMode(value, true)
	if err != nil {
		return nil, err
	}
	avas := dn.RDNValues()
	seen := make(map[string]struct{}, len(avas))
	for index := range avas {
		ava := &avas[index]
		attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(ava.Type))]
		if !ok {
			return nil, fmt.Errorf("undefined RDN attribute type %q", ava.Type)
		}
		effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
		if err != nil {
			return nil, err
		}
		if attributeHasOrderedValues(*attribute) || attributeHasOrderedValues(effective) {
			return nil, errors.New("ordered values cannot be RDN naming attributes")
		}
		if strings.Contains(ava.Type, ";") {
			if err := registry.validateAttributeDescription(ava.Type, effective); err != nil {
				return nil, err
			}
		}
		key := schemaKey(attribute.OID)
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("RDN contains a duplicate canonical attribute type")
		}
		seen[key] = struct{}{}
		if len(ava.Value) == 0 || !utf8.Valid(ava.Value) {
			return nil, errors.New("RDN naming value must be nonempty UTF-8")
		}
		syntax := registry.syntaxes[schemaKey(effective.Syntax)]
		if syntax != nil && syntax.validatorIdentity == SyntaxRDN {
			ava.Value, err = registry.prettyRDNValueLocked(ava.Value, depth+1)
		} else {
			// LDAPRDN_rewrite validates the syntax, without requiring an
			// equality rule or enforcing AttributeType's advisory size.
			err = registry.validateSyntax(effective.Syntax, 0, ava.Value)
		}
		if err != nil {
			return nil, fmt.Errorf("RDN attribute %q: %w", ava.Type, err)
		}
		if len(ava.Value) == 0 {
			return nil, errors.New("RDN naming value must be nonempty")
		}
		ava.Type, err = registry.canonicalDNAttributeNameLocked(ava.Type)
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(avas, func(left, right int) bool { return avas[left].Type < avas[right].Type })
	var pretty strings.Builder
	for index, ava := range avas {
		if index != 0 {
			pretty.WriteByte('+')
		}
		pretty.WriteString(ava.Type)
		pretty.WriteByte('=')
		for offset, character := range ava.Value {
			escape := character == 0 || strings.ContainsRune(`\",;+<>=`, rune(character)) ||
				(offset == 0 && (character == '#' || isRDNSpace(character))) ||
				(offset == len(ava.Value)-1 && isRDNSpace(character))
			if escape {
				pretty.WriteByte('\\')
				pretty.WriteByte("0123456789ABCDEF"[character>>4])
				pretty.WriteByte("0123456789ABCDEF"[character&15])
			} else {
				pretty.WriteByte(character)
			}
		}
	}
	return []byte(pretty.String()), nil
}

// parseRDNSyntax preserves rdnValidate's first-RDN behavior: the remaining
// DN is not parsed, but the length and raw-NUL checks cover the whole input.
func parseRDNSyntax(value []byte) (directory.DN, error) {
	return parseRDNSyntaxMode(value, false)
}

func parseRDNSyntaxMode(value []byte, pretty bool) (directory.DN, error) {
	if len(value) > maxRDNSyntaxLength || bytes.IndexByte(value, 0) >= 0 {
		return directory.DN{}, errors.New("value is not an RDN")
	}
	if len(value) == 0 {
		return directory.ParseDN("")
	}
	var input strings.Builder
	writeDecodedValue := func(decoded []byte) {
		// Hex escapes preserve binary bytes; SDK EscapeDN iterates runes and
		// would replace invalid UTF-8 in a decoded BER or quoted value.
		for _, character := range decoded {
			input.WriteByte('\\')
			input.WriteByte("0123456789abcdef"[character>>4])
			input.WriteByte("0123456789abcdef"[character&15])
		}
	}
	for {
		equals := bytes.IndexByte(value, '=')
		if equals < 0 {
			return directory.DN{}, errors.New("value is not an RDN")
		}
		attribute := bytes.Trim(value[:equals], " \t\r\n")
		input.WriteString(strings.ReplaceAll(string(attribute), ";", `\;`))
		input.WriteByte('=')
		value = bytes.TrimLeft(value[equals+1:], " \t\r\n")
		if len(value) != 0 && value[0] == '"' {
			// LDAP_DN_FORMAT_LDAP also accepts the old quoted form. In that
			// form a backslash quotes one byte; it does not introduce hex.
			var quoted []byte
			index := 1
			for ; index < len(value) && value[index] != '"'; index++ {
				if value[index] == '\\' {
					index++
					if index == len(value) {
						break
					}
				}
				quoted = append(quoted, value[index])
			}
			if index == len(value) {
				return directory.DN{}, errors.New("value is not an RDN")
			}
			writeDecodedValue(quoted)
			value = bytes.TrimLeft(value[index+1:], " \t\r\n")
		} else {
			index := 0
			for ; index < len(value); index++ {
				if value[index] == '\\' {
					index++
				} else if value[index] == ',' || value[index] == ';' || value[index] == '+' {
					break
				}
			}
			if index > len(value) {
				return directory.DN{}, errors.New("value is not an RDN")
			}
			part := value[:index]
			for len(part) > 1 && isRDNSpace(part[len(part)-1]) && part[len(part)-2] != '\\' {
				part = part[:len(part)-1]
			}
			if len(part) != 0 && part[0] == '#' {
				if pretty {
					return directory.DN{}, errors.New("BER-encoded RDN naming values are not supported")
				}
				// Read only the outer element. Passing arbitrary constructed
				// BER to the SDK DN decoder would recurse into attacker data.
				encoded, err := hex.DecodeString(string(part[1:]))
				if err != nil {
					return directory.DN{}, errors.New("value is not an RDN")
				}
				cursor := berCursor{value: encoded}
				element, err := cursor.readElement()
				if err != nil || !cursor.atEnd() {
					return directory.DN{}, errors.New("value is not an RDN")
				}
				writeDecodedValue(encoded[element.contentStart:])
			} else {
				for offset := 0; offset < len(part); offset++ {
					character := part[offset]
					if character == '\\' && offset+1 < len(part) {
						offset++
						character = part[offset]
						if !isRDNSpace(character) {
							input.WriteByte('\\')
							input.WriteByte(character)
							continue
						}
					} else if character >= 0x20 && character < 0x7f {
						input.WriteByte(character)
						continue
					}
					input.WriteByte('\\')
					input.WriteByte("0123456789abcdef"[character>>4])
					input.WriteByte("0123456789abcdef"[character&15])
				}
			}
			value = value[index:]
		}
		if len(value) == 0 || value[0] != '+' {
			break
		}
		input.WriteByte('+')
		value = value[1:]
	}
	dn, err := directory.ParseDN(input.String())
	if err != nil || dn.Depth() != 1 {
		return directory.DN{}, errors.New("value is not an RDN")
	}
	return dn, nil
}

func isRDNSpace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r' || character == '\n'
}
