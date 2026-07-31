package schema

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

func ParseAttributeType(description string) (AttributeType, error) {
	parser, err := newDescriptionParser(description)
	if err != nil {
		return AttributeType{}, err
	}
	attribute := AttributeType{
		OID:        parser.take(),
		Usage:      UsageUserApplications,
		Extensions: make(map[string][]string),
	}
	if attribute.OID == "" {
		return AttributeType{}, parser.errorf("missing attribute type OID")
	}

	for !parser.atEnd() {
		keyword := strings.ToUpper(parser.take())
		switch {
		case keyword == "NAME":
			attribute.Names, err = parser.readList()
		case keyword == "DESC":
			attribute.Description, err = parser.readOne()
		case keyword == "OBSOLETE":
			attribute.Obsolete = true
		case keyword == "SUP":
			attribute.Superior, err = parser.readOne()
		case keyword == "EQUALITY":
			attribute.Equality, err = parser.readOne()
		case keyword == "ORDERING":
			attribute.Ordering, err = parser.readOne()
		case keyword == "SUBSTR":
			attribute.Substring, err = parser.readOne()
		case keyword == "SYNTAX":
			var syntax string
			syntax, err = parser.readOne()
			if err == nil {
				attribute.Syntax, attribute.SyntaxLength, err = parseSyntaxOID(syntax)
			}
		case keyword == "SINGLE-VALUE":
			attribute.SingleValue = true
		case keyword == "COLLECTIVE":
			attribute.Collective = true
		case keyword == "NO-USER-MODIFICATION":
			attribute.NoUserModification = true
		case keyword == "USAGE":
			var usage string
			usage, err = parser.readOne()
			attribute.Usage = AttributeUsage(usage)
			if err == nil && !validUsage(attribute.Usage) {
				err = fmt.Errorf("unknown attribute usage %q", usage)
			}
		case strings.HasPrefix(keyword, "X-"):
			attribute.Extensions[keyword], err = parser.readList()
		default:
			err = fmt.Errorf("unknown attribute type field %q", keyword)
		}
		if err != nil {
			return AttributeType{}, parser.wrap(err)
		}
	}
	if err := parser.finish(); err != nil {
		return AttributeType{}, err
	}
	return attribute, nil
}

func ParseObjectClass(description string) (ObjectClass, error) {
	parser, err := newDescriptionParser(description)
	if err != nil {
		return ObjectClass{}, err
	}
	objectClass := ObjectClass{
		OID:        parser.take(),
		Kind:       ObjectClassStructural,
		Extensions: make(map[string][]string),
	}
	if objectClass.OID == "" {
		return ObjectClass{}, parser.errorf("missing object class OID")
	}

	for !parser.atEnd() {
		keyword := strings.ToUpper(parser.take())
		switch {
		case keyword == "NAME":
			objectClass.Names, err = parser.readList()
		case keyword == "DESC":
			objectClass.Description, err = parser.readOne()
		case keyword == "OBSOLETE":
			objectClass.Obsolete = true
		case keyword == "SUP":
			objectClass.Superiors, err = parser.readList()
		case keyword == "ABSTRACT":
			objectClass.Kind = ObjectClassAbstract
		case keyword == "STRUCTURAL":
			objectClass.Kind = ObjectClassStructural
		case keyword == "AUXILIARY":
			objectClass.Kind = ObjectClassAuxiliary
		case keyword == "MUST":
			objectClass.Must, err = parser.readList()
		case keyword == "MAY":
			objectClass.May, err = parser.readList()
		case strings.HasPrefix(keyword, "X-"):
			objectClass.Extensions[keyword], err = parser.readList()
		default:
			err = fmt.Errorf("unknown object class field %q", keyword)
		}
		if err != nil {
			return ObjectClass{}, parser.wrap(err)
		}
	}
	if err := parser.finish(); err != nil {
		return ObjectClass{}, err
	}
	return objectClass, nil
}

func ParseDITContentRule(description string) (DITContentRule, error) {
	parser, err := newDescriptionParser(description)
	if err != nil {
		return DITContentRule{}, err
	}
	contentRule := DITContentRule{
		OID:        parser.take(),
		Extensions: make(map[string][]string),
	}
	if contentRule.OID == "" {
		return DITContentRule{}, parser.errorf("missing DIT content rule OID")
	}

	seen := make(map[string]struct{})
	for !parser.atEnd() {
		keyword := strings.ToUpper(parser.take())
		if _, duplicate := seen[keyword]; duplicate {
			return DITContentRule{}, parser.errorf(
				"duplicate DIT content rule field %q",
				keyword,
			)
		}
		seen[keyword] = struct{}{}
		switch {
		case keyword == "NAME":
			contentRule.Names, err = parser.readList()
		case keyword == "DESC":
			contentRule.Description, err = parser.readOne()
		case keyword == "OBSOLETE":
			contentRule.Obsolete = true
		case keyword == "AUX":
			contentRule.Auxiliary, err = parser.readList()
		case keyword == "MUST":
			contentRule.Must, err = parser.readList()
		case keyword == "MAY":
			contentRule.May, err = parser.readList()
		case keyword == "NOT":
			contentRule.Not, err = parser.readList()
		case strings.HasPrefix(keyword, "X-"):
			contentRule.Extensions[keyword], err = parser.readList()
		default:
			err = fmt.Errorf("unknown DIT content rule field %q", keyword)
		}
		if err != nil {
			return DITContentRule{}, parser.wrap(err)
		}
	}
	if err := parser.finish(); err != nil {
		return DITContentRule{}, err
	}
	return contentRule, nil
}

type descriptionParser struct {
	input  string
	tokens []string
	index  int
}

func newDescriptionParser(description string) (*descriptionParser, error) {
	description = strings.TrimSpace(description)
	if strings.HasPrefix(description, "{") {
		end := strings.IndexByte(description, '}')
		if end < 2 {
			return nil, errors.New("invalid OpenLDAP schema ordering prefix")
		}
		if _, err := strconv.Atoi(description[1:end]); err != nil {
			return nil, fmt.Errorf("invalid OpenLDAP schema ordering prefix: %w", err)
		}
		description = strings.TrimSpace(description[end+1:])
	}
	tokens, err := tokenize(description)
	if err != nil {
		return nil, err
	}
	if len(tokens) < 3 || tokens[0] != "(" || tokens[len(tokens)-1] != ")" {
		return nil, errors.New("schema description must be enclosed in parentheses")
	}
	return &descriptionParser{input: description, tokens: tokens[1 : len(tokens)-1]}, nil
}

func (parser *descriptionParser) atEnd() bool {
	return parser.index >= len(parser.tokens)
}

func (parser *descriptionParser) take() string {
	if parser.atEnd() {
		return ""
	}
	value := parser.tokens[parser.index]
	parser.index++
	return value
}

func (parser *descriptionParser) readOne() (string, error) {
	if parser.atEnd() {
		return "", errors.New("missing field value")
	}
	value := parser.take()
	if value == "(" || value == ")" || value == "$" {
		return "", fmt.Errorf("expected field value, got %q", value)
	}
	return value, nil
}

func (parser *descriptionParser) readList() ([]string, error) {
	if parser.atEnd() {
		return nil, errors.New("missing list value")
	}
	if parser.tokens[parser.index] != "(" {
		value, err := parser.readOne()
		if err != nil {
			return nil, err
		}
		return []string{value}, nil
	}
	parser.index++
	var values []string
	for !parser.atEnd() {
		value := parser.take()
		switch value {
		case ")":
			if len(values) == 0 {
				return nil, errors.New("empty list")
			}
			return values, nil
		case "$":
			continue
		case "(":
			return nil, errors.New("nested schema list")
		default:
			values = append(values, value)
		}
	}
	return nil, errors.New("unterminated list")
}

func (parser *descriptionParser) finish() error {
	if !parser.atEnd() {
		return parser.errorf("unexpected token %q", parser.tokens[parser.index])
	}
	return nil
}

func (parser *descriptionParser) wrap(err error) error {
	return fmt.Errorf("parse schema description near token %d: %w", parser.index, err)
}

func (parser *descriptionParser) errorf(format string, args ...any) error {
	return parser.wrap(fmt.Errorf(format, args...))
}

func tokenize(input string) ([]string, error) {
	var tokens []string
	for position := 0; position < len(input); {
		if unicode.IsSpace(rune(input[position])) {
			position++
			continue
		}
		switch input[position] {
		case '(', ')', '$':
			tokens = append(tokens, input[position:position+1])
			position++
		case '\'':
			value, next, err := readQuoted(input, position+1)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, value)
			position = next
		default:
			start := position
			for position < len(input) &&
				!unicode.IsSpace(rune(input[position])) &&
				input[position] != '(' &&
				input[position] != ')' &&
				input[position] != '$' {
				position++
			}
			tokens = append(tokens, input[start:position])
		}
	}
	return tokens, nil
}

func readQuoted(input string, position int) (string, int, error) {
	var value strings.Builder
	for position < len(input) {
		switch input[position] {
		case '\'':
			return value.String(), position + 1, nil
		case '\\':
			if position+2 >= len(input) {
				return "", 0, errors.New("truncated schema escape")
			}
			decoded, err := strconv.ParseUint(input[position+1:position+3], 16, 8)
			if err != nil {
				return "", 0, fmt.Errorf("invalid schema escape %q", input[position:position+3])
			}
			value.WriteByte(byte(decoded))
			position += 3
		default:
			value.WriteByte(input[position])
			position++
		}
	}
	return "", 0, errors.New("unterminated quoted schema value")
}

func parseSyntaxOID(value string) (string, int, error) {
	open := strings.LastIndexByte(value, '{')
	if open < 0 {
		return value, 0, nil
	}
	if !strings.HasSuffix(value, "}") {
		return "", 0, fmt.Errorf("invalid syntax length %q", value)
	}
	length, err := strconv.Atoi(value[open+1 : len(value)-1])
	if err != nil || length <= 0 {
		return "", 0, fmt.Errorf("invalid syntax length %q", value)
	}
	return value[:open], length, nil
}

func validUsage(usage AttributeUsage) bool {
	switch usage {
	case UsageUserApplications,
		UsageDirectoryOperation,
		UsageDistributedOperation,
		UsageDSAOperation:
		return true
	default:
		return false
	}
}
