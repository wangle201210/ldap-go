package schema

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// MDBRawValueSize uses slapd's pretty syntax form, independently of index keys.
func (registry *Registry) MDBRawValueSize(name string, value []byte) (uint64, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return uint64(len(value)), nil
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return 0, err
	}
	switch effective.Syntax {
	case SyntaxDistinguishedName:
		// OpenLDAP's dnPretty/dnNormalize reject inputs above this bound.
		if len(value) > 8192 {
			return 0, &Violation{Kind: ViolationSyntax, Attribute: name, Message: "DN exceeds OpenLDAP's 8192 byte limit"}
		}
		dn, err := registry.normalizeDNLocked(string(value))
		return uint64(len(dn.String())), err
	case SyntaxOID:
		if attribute.OID == "2.5.4.0" || attribute.OID == "2.5.21.9" {
			if class, ok := registry.objectClasses[schemaKey(strings.TrimSpace(string(value)))]; ok {
				return uint64(len(class.Name())), nil
			}
		}
	}
	return uint64(len(value)), nil
}

// MDBNormalizedValueSize describes OpenLDAP's separate a_nvals storage, which
// differs from our equality index keys (notably UUIDs and postal addresses).
func (registry *Registry) MDBNormalizedValueSize(name string, value []byte) (uint64, bool, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return 0, false, nil
	} // schemachecking=off keeps unknown raw values
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return 0, false, err
	}
	rule := canonicalMatchingRule(effective.Equality)
	var prefix uint64
	if attributeHasOrderedValues(*attribute) {
		_, content, indexed, err := ParseOrderedValue(value)
		if err != nil {
			return 0, false, err
		}
		if indexed {
			prefix = uint64(len(value) - len(content))
			value = content
		}
	}
	var n uint64
	switch rule {
	case "", "objectidentifiermatch", "integermatch", "integerorderingmatch", "booleanmatch", "octetstringmatch", "octetstringorderingmatch", "bitstringmatch":
		return 0, false, nil
	case "uuidmatch", "uuidorderingmatch":
		n = 16
	case "caseignorematch", "caseignoreorderingmatch", "caseexactmatch", "caseexactorderingmatch":
		n, err = mdbTextSize(value, rule == "caseignorematch" || rule == "caseignoreorderingmatch", true)
	case "caseignoreia5match", "caseexactia5match", "caseignoreia5orderingmatch", "caseexactia5orderingmatch":
		n, err = mdbTextSize(value, false, false)
	case "telephonenumbermatch", "numericstringmatch", "numericstringorderingmatch":
		for _, c := range value {
			if !mdbASCIISpace(c) && (rule != "telephonenumbermatch" || c != '-') {
				n++
			}
		}
	case "caseignorelistmatch":
		for {
			line, rest, found := bytes.Cut(value, []byte{'$'})
			var size uint64
			size, err = mdbTextSize(line, true, true)
			n += size
			if err != nil || !found {
				break
			}
			n++
			value = rest
		}
	default:
		// Structured syntaxes use the existing parser, one value at a time;
		// the caller has already bounded their raw size by the entry budget.
		var normalized []byte
		normalized, err = registry.normalizeWithRuleLocked(rule, value)
		n = uint64(len(normalized))
	}
	return n + prefix, true, err
}

func mdbASCIISpace(c byte) bool { return c == ' ' || c >= '\t' && c <= '\r' }

// Stream simple lowercasing then NFKC through fixed buffers. Never marshal an
// entry or build a normalized copy of an arbitrarily large text/binary value.
func mdbTextSize(value []byte, fold, unicodeText bool) (uint64, error) {
	if unicodeText && !utf8.Valid(value) {
		return 0, fmt.Errorf("invalid UTF-8")
	}
	var input io.Reader = bytes.NewReader(value)
	if unicodeText {
		var normalizer transform.Transformer = norm.NFKC
		if fold {
			normalizer = transform.Chain(runes.Map(unicode.ToLower), norm.NFKC)
		}
		input = transform.NewReader(input, normalizer)
	}
	var buffer [4096]byte
	var size uint64
	space := false
	for {
		n, err := input.Read(buffer[:])
		for _, c := range buffer[:n] {
			if mdbASCIISpace(c) {
				space = size != 0
				continue
			}
			if space {
				size++
				space = false
			}
			size++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if unicodeText && size == 0 && len(value) != 0 {
		size = 1
	}
	return size, nil
}
