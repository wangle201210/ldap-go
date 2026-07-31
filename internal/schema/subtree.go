package schema

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const maxSubtreeRefinementDepth = 128

type SubtreeSpecification struct {
	Base                directory.DN
	SpecificExclusions  []SubtreeSpecificExclusion
	Minimum             uint64
	Maximum             *uint64
	SpecificationFilter *SubtreeRefinement
}

type SubtreeSpecificExclusion struct {
	ChopBefore bool
	LocalName  directory.DN
}

type SubtreeRefinementKind uint8

const (
	SubtreeRefinementItem SubtreeRefinementKind = iota
	SubtreeRefinementAnd
	SubtreeRefinementOr
	SubtreeRefinementNot
)

type SubtreeRefinement struct {
	Kind     SubtreeRefinementKind
	Item     string
	Children []SubtreeRefinement
}

func ParseSubtreeSpecification(value string) (SubtreeSpecification, error) {
	if !utf8.ValidString(value) {
		return SubtreeSpecification{}, errors.New("subtree specification is not valid UTF-8")
	}
	empty, err := directory.ParseDN("")
	if err != nil {
		return SubtreeSpecification{}, fmt.Errorf("parse empty local name: %w", err)
	}
	parser := subtreeSpecificationParser{input: value}
	specification := SubtreeSpecification{Base: empty}
	if err := parser.parse(&specification); err != nil {
		return SubtreeSpecification{}, err
	}
	return specification, nil
}

func (registry *Registry) SubtreeSpecificationMatches(
	specification SubtreeSpecification,
	administrativePoint directory.DN,
	candidateDN directory.DN,
	entry directory.Entry,
) (bool, error) {
	base, err := directory.ComposeLocalName(specification.Base, administrativePoint)
	if err != nil {
		return false, fmt.Errorf("compose subtree base: %w", err)
	}
	if !base.Equal(candidateDN) && !base.AncestorOf(candidateDN) {
		return false, nil
	}

	distance := uint64(candidateDN.Depth() - base.Depth())
	if distance < specification.Minimum ||
		(specification.Maximum != nil && distance > *specification.Maximum) {
		return false, nil
	}
	for _, exclusion := range specification.SpecificExclusions {
		excludedBase, err := directory.ComposeLocalName(exclusion.LocalName, base)
		if err != nil {
			return false, fmt.Errorf("compose subtree exclusion: %w", err)
		}
		if exclusion.ChopBefore {
			if excludedBase.Equal(candidateDN) || excludedBase.AncestorOf(candidateDN) {
				return false, nil
			}
			continue
		}
		if excludedBase.AncestorOf(candidateDN) {
			return false, nil
		}
	}
	if specification.SpecificationFilter == nil {
		return true, nil
	}

	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.matchesSubtreeRefinement(*specification.SpecificationFilter, entry), nil
}

func (registry *Registry) matchesSubtreeRefinement(
	refinement SubtreeRefinement,
	entry directory.Entry,
) bool {
	switch refinement.Kind {
	case SubtreeRefinementItem:
		target, ok := registry.objectClasses[schemaKey(refinement.Item)]
		if !ok {
			return false
		}
		for _, value := range entry.Values("objectClass") {
			candidate, ok := registry.objectClasses[schemaKey(string(value))]
			if ok && registry.isSubclass(candidate, target, make(map[string]bool)) {
				return true
			}
		}
		return false
	case SubtreeRefinementAnd:
		for _, child := range refinement.Children {
			if !registry.matchesSubtreeRefinement(child, entry) {
				return false
			}
		}
		return true
	case SubtreeRefinementOr:
		for _, child := range refinement.Children {
			if registry.matchesSubtreeRefinement(child, entry) {
				return true
			}
		}
		return false
	case SubtreeRefinementNot:
		return len(refinement.Children) == 1 &&
			!registry.matchesSubtreeRefinement(refinement.Children[0], entry)
	default:
		return false
	}
}

type subtreeSpecificationParser struct {
	input string
	index int
}

func (parser *subtreeSpecificationParser) parse(
	specification *SubtreeSpecification,
) error {
	if err := parser.expectByte('{'); err != nil {
		return err
	}
	parser.skipSpaces()
	if parser.consumeByte('}') {
		if parser.index != len(parser.input) {
			return parser.errorf("unexpected trailing data")
		}
		return nil
	}

	lastField := -1
	for {
		field := parser.readIdentifier()
		fieldIndex := subtreeSpecificationFieldIndex(field)
		if fieldIndex < 0 {
			return parser.errorf("unknown field %q", field)
		}
		if fieldIndex <= lastField {
			return parser.errorf("field %q is duplicated or out of order", field)
		}
		if err := parser.requireSpaces(); err != nil {
			return parser.errorf("field %q must be followed by a space", field)
		}
		switch field {
		case "base":
			localName, err := parser.readLocalName()
			if err != nil {
				return err
			}
			specification.Base = localName
		case "specificExclusions":
			exclusions, err := parser.readSpecificExclusions()
			if err != nil {
				return err
			}
			specification.SpecificExclusions = exclusions
		case "minimum":
			minimum, err := parser.readBaseDistance()
			if err != nil {
				return err
			}
			specification.Minimum = minimum
		case "maximum":
			maximum, err := parser.readBaseDistance()
			if err != nil {
				return err
			}
			specification.Maximum = &maximum
		case "specificationFilter":
			refinement, err := parser.readRefinement(0)
			if err != nil {
				return err
			}
			specification.SpecificationFilter = &refinement
		}
		lastField = fieldIndex

		parser.skipSpaces()
		if parser.consumeByte('}') {
			if parser.index != len(parser.input) {
				return parser.errorf("unexpected trailing data")
			}
			return nil
		}
		if err := parser.expectByte(','); err != nil {
			return err
		}
		parser.skipSpaces()
		if parser.peekByte() == '}' {
			return parser.errorf("trailing comma")
		}
	}
}

func subtreeSpecificationFieldIndex(field string) int {
	switch field {
	case "base":
		return 0
	case "specificExclusions":
		return 1
	case "minimum":
		return 2
	case "maximum":
		return 3
	case "specificationFilter":
		return 4
	default:
		return -1
	}
}

func (parser *subtreeSpecificationParser) readSpecificExclusions() (
	[]SubtreeSpecificExclusion,
	error,
) {
	if err := parser.expectByte('{'); err != nil {
		return nil, err
	}
	parser.skipSpaces()
	if parser.consumeByte('}') {
		return nil, nil
	}

	var exclusions []SubtreeSpecificExclusion
	for {
		kind := parser.readIdentifier()
		var chopBefore bool
		switch kind {
		case "chopBefore":
			chopBefore = true
		case "chopAfter":
		default:
			return nil, parser.errorf("unknown specific exclusion %q", kind)
		}
		if err := parser.expectByte(':'); err != nil {
			return nil, err
		}
		localName, err := parser.readLocalName()
		if err != nil {
			return nil, err
		}
		exclusions = append(exclusions, SubtreeSpecificExclusion{
			ChopBefore: chopBefore,
			LocalName:  localName,
		})

		parser.skipSpaces()
		if parser.consumeByte('}') {
			return exclusions, nil
		}
		if err := parser.expectByte(','); err != nil {
			return nil, err
		}
		parser.skipSpaces()
		if parser.peekByte() == '}' {
			return nil, parser.errorf("trailing comma in specific exclusions")
		}
	}
}

func (parser *subtreeSpecificationParser) readRefinement(
	depth int,
) (SubtreeRefinement, error) {
	if depth >= maxSubtreeRefinementDepth {
		return SubtreeRefinement{}, parser.errorf("refinement nesting is too deep")
	}
	kind := parser.readIdentifier()
	if err := parser.expectByte(':'); err != nil {
		return SubtreeRefinement{}, err
	}
	switch kind {
	case "item":
		item := parser.readObjectIdentifier()
		if !validObjectIdentifier(item) {
			return SubtreeRefinement{}, parser.errorf(
				"invalid object identifier %q",
				item,
			)
		}
		return SubtreeRefinement{Kind: SubtreeRefinementItem, Item: item}, nil
	case "and", "or":
		children, err := parser.readRefinements(depth + 1)
		if err != nil {
			return SubtreeRefinement{}, err
		}
		refinementKind := SubtreeRefinementAnd
		if kind == "or" {
			refinementKind = SubtreeRefinementOr
		}
		return SubtreeRefinement{Kind: refinementKind, Children: children}, nil
	case "not":
		child, err := parser.readRefinement(depth + 1)
		if err != nil {
			return SubtreeRefinement{}, err
		}
		return SubtreeRefinement{
			Kind:     SubtreeRefinementNot,
			Children: []SubtreeRefinement{child},
		}, nil
	default:
		return SubtreeRefinement{}, parser.errorf("unknown refinement %q", kind)
	}
}

func (parser *subtreeSpecificationParser) readRefinements(
	depth int,
) ([]SubtreeRefinement, error) {
	if err := parser.expectByte('{'); err != nil {
		return nil, err
	}
	parser.skipSpaces()
	if parser.consumeByte('}') {
		return nil, nil
	}

	var refinements []SubtreeRefinement
	for {
		refinement, err := parser.readRefinement(depth)
		if err != nil {
			return nil, err
		}
		refinements = append(refinements, refinement)
		parser.skipSpaces()
		if parser.consumeByte('}') {
			return refinements, nil
		}
		if err := parser.expectByte(','); err != nil {
			return nil, err
		}
		parser.skipSpaces()
		if parser.peekByte() == '}' {
			return nil, parser.errorf("trailing comma in refinements")
		}
	}
}

func (parser *subtreeSpecificationParser) readLocalName() (directory.DN, error) {
	if err := parser.expectByte('"'); err != nil {
		return directory.DN{}, err
	}
	var value strings.Builder
	for parser.index < len(parser.input) {
		character := parser.input[parser.index]
		if character != '"' {
			value.WriteByte(character)
			parser.index++
			continue
		}
		if parser.index+1 < len(parser.input) && parser.input[parser.index+1] == '"' {
			value.WriteByte('"')
			parser.index += 2
			continue
		}
		parser.index++
		localName, err := directory.ParseDN(value.String())
		if err != nil {
			return directory.DN{}, parser.errorf("invalid local name: %v", err)
		}
		return localName, nil
	}
	return directory.DN{}, parser.errorf("unterminated local name")
}

func (parser *subtreeSpecificationParser) readBaseDistance() (uint64, error) {
	start := parser.index
	for parser.index < len(parser.input) &&
		parser.input[parser.index] >= '0' &&
		parser.input[parser.index] <= '9' {
		parser.index++
	}
	value := parser.input[start:parser.index]
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, parser.errorf("invalid base distance %q", value)
	}
	distance, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, parser.errorf("invalid base distance %q", value)
	}
	return distance, nil
}

func (parser *subtreeSpecificationParser) readObjectIdentifier() string {
	start := parser.index
	for parser.index < len(parser.input) {
		switch parser.input[parser.index] {
		case ' ', ',', '}':
			return parser.input[start:parser.index]
		default:
			parser.index++
		}
	}
	return parser.input[start:parser.index]
}

func validObjectIdentifier(value string) bool {
	if value == "" {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		components := strings.Split(value, ".")
		if len(components) < 2 {
			return false
		}
		for _, component := range components {
			if component == "" || (len(component) > 1 && component[0] == '0') {
				return false
			}
			for _, character := range component {
				if character < '0' || character > '9' {
					return false
				}
			}
		}
		return true
	}
	if !isASCIILetter(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIILetter(character) &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func (parser *subtreeSpecificationParser) readIdentifier() string {
	start := parser.index
	for parser.index < len(parser.input) {
		character := parser.input[parser.index]
		if !isASCIILetter(character) &&
			(character < '0' || character > '9') &&
			character != '-' {
			break
		}
		parser.index++
	}
	return parser.input[start:parser.index]
}

func (parser *subtreeSpecificationParser) requireSpaces() error {
	start := parser.index
	parser.skipSpaces()
	if parser.index == start {
		return parser.errorf("expected one or more spaces")
	}
	return nil
}

func (parser *subtreeSpecificationParser) skipSpaces() {
	for parser.index < len(parser.input) && parser.input[parser.index] == ' ' {
		parser.index++
	}
}

func (parser *subtreeSpecificationParser) expectByte(expected byte) error {
	if !parser.consumeByte(expected) {
		return parser.errorf("expected %q", expected)
	}
	return nil
}

func (parser *subtreeSpecificationParser) consumeByte(expected byte) bool {
	if parser.peekByte() != expected {
		return false
	}
	parser.index++
	return true
}

func (parser *subtreeSpecificationParser) peekByte() byte {
	if parser.index >= len(parser.input) {
		return 0
	}
	return parser.input[parser.index]
}

func (parser *subtreeSpecificationParser) errorf(format string, arguments ...any) error {
	return fmt.Errorf(
		"parse subtree specification at byte %d: %s",
		parser.index,
		fmt.Sprintf(format, arguments...),
	)
}
