package schema

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MatchingRule describes a rule's schema, not its executable implementation.
type MatchingRule struct {
	OID         string
	Names       []string
	Description string
	Obsolete    bool
	Syntax      string
	Extensions  map[string][]string
}

type MatchingRuleUse struct {
	OID         string
	Names       []string
	Description string
	Obsolete    bool
	Applies     []string
	Extensions  map[string][]string
}

const (
	maxMatchingRuleDescriptionSize   = 1 << 20
	maxMatchingRuleDescriptionTokens = 1 << 16
)

func ParseMatchingRule(description string) (MatchingRule, error) {
	rule, _, err := parseMatchingRuleDescription(description, false)
	return rule, err
}

func ParseMatchingRuleUse(description string) (MatchingRuleUse, error) {
	rule, applies, err := parseMatchingRuleDescription(description, true)
	if err != nil {
		return MatchingRuleUse{}, err
	}
	return MatchingRuleUse{
		OID: rule.OID, Names: rule.Names, Description: rule.Description,
		Obsolete: rule.Obsolete, Applies: applies, Extensions: rule.Extensions,
	}, nil
}

func parseMatchingRuleDescription(description string, use bool) (MatchingRule, []string, error) {
	parser, err := newMatchingRuleDescriptionParser(description)
	if err != nil {
		return MatchingRule{}, nil, err
	}
	oid, err := parser.readNumericOID("matching rule")
	if err != nil {
		return MatchingRule{}, nil, err
	}
	rule := MatchingRule{OID: oid, Extensions: make(map[string][]string)}
	var applies []string
	seen := make(map[string]bool)
	for !parser.atEnd() {
		keyword := strings.ToUpper(parser.take())
		if seen[keyword] {
			return MatchingRule{}, nil, parser.errorf("duplicate matching rule field %q", keyword)
		}
		seen[keyword] = true
		switch {
		case keyword == "NAME":
			rule.Names, err = readMatchingRuleQuotedList(parser, true)
		case keyword == "DESC":
			var value string
			value, err = parser.readOne()
			if err == nil {
				rule.Description, err = matchingRuleQuotedValue(value, false)
			}
		case keyword == "OBSOLETE":
			rule.Obsolete = true
		case keyword == "SYNTAX" && !use:
			rule.Syntax, err = parser.readNumericOID("matching rule syntax")
		case keyword == "APPLIES" && use:
			applies, err = readMatchingRuleApplies(parser)
		case validMatchingRuleExtension(keyword):
			rule.Extensions[keyword], err = readMatchingRuleQuotedList(parser, false)
		default:
			err = fmt.Errorf("unknown matching rule field %q", keyword)
		}
		if err != nil {
			return MatchingRule{}, nil, parser.wrap(err)
		}
	}
	required := "SYNTAX"
	if use {
		required = "APPLIES"
	}
	if !seen[required] {
		return MatchingRule{}, nil, parser.errorf("matching rule description requires %s", required)
	}
	if err := parser.finish(); err != nil {
		return MatchingRule{}, nil, err
	}
	return rule, applies, nil
}

// Keep quoted tokens intact so a quoted ')' is a value and a quoted OID cannot
// pass readNumericOID. The shared parser still handles fields and flat lists.
func newMatchingRuleDescriptionParser(description string) (*descriptionParser, error) {
	if len(description) > maxMatchingRuleDescriptionSize {
		return nil, errors.New("matching rule description exceeds 1 MiB")
	}
	if !utf8.ValidString(description) {
		return nil, errors.New("matching rule description is not UTF-8")
	}
	description = strings.Trim(description, " \t\r\n\v\f")
	if strings.HasPrefix(description, "{") {
		end := strings.IndexByte(description, '}')
		if end < 2 {
			return nil, errors.New("invalid OpenLDAP schema ordering prefix")
		}
		if _, err := parseRuleID(description[1:end]); err != nil {
			return nil, fmt.Errorf("invalid OpenLDAP schema ordering prefix: %w", err)
		}
		description = strings.Trim(description[end+1:], " \t\r\n\v\f")
	}
	var tokens []string
	for position := 0; position < len(description); {
		if matchingRuleSpace(description[position]) {
			position++
			continue
		}
		if len(tokens) == maxMatchingRuleDescriptionTokens {
			return nil, errors.New("too many matching rule description tokens")
		}
		start := position
		switch description[position] {
		case '(', ')', '$':
			position++
		case '\'':
			value, next, err := readQuoted(description, position+1)
			if err != nil {
				return nil, err
			}
			if !utf8.ValidString(value) {
				return nil, errors.New("quoted schema value is not UTF-8")
			}
			position = next
			if position < len(description) && !matchingRuleSpace(description[position]) && description[position] != ')' {
				return nil, errors.New("missing separator after quoted schema value")
			}
		default:
			for position < len(description) && !matchingRuleSpace(description[position]) &&
				description[position] != '(' && description[position] != ')' && description[position] != '$' {
				if description[position] == '\'' {
					return nil, errors.New("missing separator before quoted schema value")
				}
				if description[position] < 0x21 || description[position] > 0x7e {
					return nil, errors.New("schema identifiers and keywords must be ASCII")
				}
				position++
			}
		}
		tokens = append(tokens, description[start:position])
	}
	if len(tokens) < 3 || tokens[0] != "(" || tokens[len(tokens)-1] != ")" {
		return nil, errors.New("schema description must be enclosed in parentheses")
	}
	return &descriptionParser{input: description, tokens: tokens[1 : len(tokens)-1]}, nil
}

func matchingRuleSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\v' || value == '\f'
}

func readMatchingRuleQuotedList(parser *descriptionParser, descriptors bool) ([]string, error) {
	// RFC 4512 permits an empty qdescrs/qdstrings list, unlike the required oids.
	if parser.index+1 < len(parser.tokens) && parser.tokens[parser.index] == "(" && parser.tokens[parser.index+1] == ")" {
		parser.index += 2
		return nil, nil
	}
	start := parser.index
	values, err := parser.readList()
	if err != nil {
		return nil, err
	}
	for _, token := range parser.tokens[start:parser.index] {
		if token == "$" {
			return nil, errors.New("quoted schema lists do not use dollar separators")
		}
	}
	for index, value := range values {
		values[index], err = matchingRuleQuotedValue(value, descriptors)
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}

func matchingRuleQuotedValue(value string, descriptor bool) (string, error) {
	if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
		return "", errors.New("expected quoted schema value")
	}
	if descriptor {
		name := value[1 : len(value)-1]
		if len(name) == 0 || !isASCIILetter(name[0]) || !validObjectIdentifier(name) {
			return "", fmt.Errorf("invalid matching rule name %q", name)
		}
		return name, nil
	}
	decoded, _, err := readQuoted(value, 1)
	return decoded, err
}

func readMatchingRuleApplies(parser *descriptionParser) ([]string, error) {
	start := parser.index
	values, err := parser.readList()
	if err != nil {
		return nil, err
	}
	if parser.tokens[start] == "(" {
		list := parser.tokens[start+1 : parser.index-1]
		if len(list) != 2*len(values)-1 {
			return nil, errors.New("APPLIES list requires dollar separators between identifiers")
		}
		for index := 1; index < len(list); index += 2 {
			if list[index] != "$" {
				return nil, errors.New("APPLIES list requires dollar separators between identifiers")
			}
		}
	}
	for _, value := range values {
		if !validObjectIdentifier(value) {
			return nil, fmt.Errorf("invalid APPLIES identifier %q", value)
		}
	}
	return values, nil
}

func validMatchingRuleExtension(name string) bool {
	if !strings.HasPrefix(name, "X-") || len(name) == 2 {
		return false
	}
	for index := 2; index < len(name); index++ {
		if !isASCIILetter(name[index]) && name[index] != '-' && name[index] != '_' {
			return false
		}
	}
	return true
}

func FormatMatchingRule(rule MatchingRule) string {
	fields := formatMatchingRuleFields(rule.OID, rule.Names, rule.Description, rule.Obsolete)
	fields = append(fields, "SYNTAX", rule.Syntax)
	fields = appendExtensions(fields, rule.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func FormatMatchingRuleUse(rule MatchingRuleUse) string {
	fields := formatMatchingRuleFields(rule.OID, rule.Names, rule.Description, rule.Obsolete)
	fields = append(fields, "APPLIES", formatOIDList(rule.Applies))
	fields = appendExtensions(fields, rule.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func formatMatchingRuleFields(oid string, names []string, description string, obsolete bool) []string {
	fields := []string{"(", oid}
	if len(names) > 0 {
		fields = append(fields, "NAME", formatQuotedList(names))
	}
	if description != "" {
		fields = append(fields, "DESC", quoteSchemaValue(description))
	}
	if obsolete {
		fields = append(fields, "OBSOLETE")
	}
	return fields
}
