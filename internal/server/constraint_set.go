package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type constraintSetNodeKind uint8

const (
	constraintSetLiteral constraintSetNodeKind = iota
	constraintSetThis
	constraintSetUser
	constraintSetChase
	constraintSetParent
	constraintSetParents
	constraintSetUnion
	constraintSetIntersection
	constraintSetConcatenation
)

type constraintSetNode struct {
	kind    constraintSetNodeKind
	value   string
	level   int
	closure bool
	left    *constraintSetNode
	right   *constraintSetNode
}

type constraintSetParser struct {
	input string
	index int
	depth int
}

type constraintValueSet map[string]struct{}

type constraintSetEvaluation struct {
	runtime *runtimeState
	reader  storage.Reader
	target  directory.Entry
	userDN  string
}

func parseConstraintSetExpression(value string) (*constraintSetNode, error) {
	parser := &constraintSetParser{input: value}
	node, err := parser.parseExpression(false)
	if err != nil {
		return nil, err
	}
	parser.skipSpaces()
	if parser.index != len(parser.input) {
		return nil, parser.errorf("unexpected token %q", parser.input[parser.index])
	}
	return node, nil
}

func (parser *constraintSetParser) parseExpression(
	parenthesized bool,
) (*constraintSetNode, error) {
	left, err := parser.parseOperand()
	if err != nil {
		return nil, err
	}
	for {
		parser.skipSpaces()
		if parser.index == len(parser.input) {
			if parenthesized {
				return nil, parser.errorf("unterminated parenthesized expression")
			}
			return left, nil
		}
		if parser.input[parser.index] == ')' {
			if !parenthesized {
				return nil, parser.errorf("unexpected closing parenthesis")
			}
			parser.index++
			return left, nil
		}

		operator := parser.input[parser.index]
		parser.index++
		var kind constraintSetNodeKind
		switch operator {
		case '|':
			kind = constraintSetUnion
		case '&':
			kind = constraintSetIntersection
		case '+':
			kind = constraintSetConcatenation
		default:
			return nil, parser.errorf("unknown set operator %q", operator)
		}
		right, err := parser.parseOperand()
		if err != nil {
			return nil, err
		}
		left = &constraintSetNode{kind: kind, left: left, right: right}
	}
}

func (parser *constraintSetParser) parseOperand() (*constraintSetNode, error) {
	parser.skipSpaces()
	if parser.index == len(parser.input) {
		return nil, parser.errorf("missing set operand")
	}
	var node *constraintSetNode
	switch parser.input[parser.index] {
	case '(':
		parser.index++
		parser.depth++
		if parser.depth > 64 {
			return nil, parser.errorf("set expression nesting exceeds 64")
		}
		var err error
		node, err = parser.parseExpression(true)
		parser.depth--
		if err != nil {
			return nil, err
		}
	case '[':
		parser.index++
		end := strings.IndexByte(parser.input[parser.index:], ']')
		if end < 0 {
			return nil, parser.errorf("unterminated set literal")
		}
		node = &constraintSetNode{
			kind:  constraintSetLiteral,
			value: parser.input[parser.index : parser.index+end],
		}
		parser.index += end + 1
	default:
		identifier := parser.readIdentifier()
		switch identifier {
		case "this":
			node = &constraintSetNode{kind: constraintSetThis}
		case "user":
			node = &constraintSetNode{kind: constraintSetUser}
		case "":
			return nil, parser.errorf("invalid set operand")
		default:
			return nil, parser.errorf("unknown set operand %q", identifier)
		}
	}

	for {
		parser.skipSpaces()
		if parser.index >= len(parser.input) {
			return node, nil
		}
		switch {
		case parser.input[parser.index] == '/':
			parser.index++
		case strings.HasPrefix(parser.input[parser.index:], "->"):
			parser.index += 2
		default:
			return node, nil
		}
		if parser.index >= len(parser.input) {
			return nil, parser.errorf("missing set path component")
		}
		if parser.input[parser.index] == '-' {
			parser.index++
			if parser.index >= len(parser.input) {
				return nil, parser.errorf("missing parent level")
			}
			if parser.input[parser.index] == '*' {
				parser.index++
				node = &constraintSetNode{
					kind: constraintSetParents,
					left: node,
				}
				continue
			}
			start := parser.index
			for parser.index < len(parser.input) &&
				parser.input[parser.index] >= '0' &&
				parser.input[parser.index] <= '9' {
				parser.index++
			}
			if start == parser.index {
				return nil, parser.errorf("invalid parent level")
			}
			level, err := strconv.Atoi(parser.input[start:parser.index])
			if err != nil {
				return nil, parser.errorf("invalid parent level")
			}
			node = &constraintSetNode{
				kind:  constraintSetParent,
				level: level,
				left:  node,
			}
			continue
		}

		attribute := parser.readIdentifier()
		if attribute == "" {
			return nil, parser.errorf("invalid set attribute path")
		}
		closure := false
		if parser.index < len(parser.input) && parser.input[parser.index] == '*' {
			closure = true
			parser.index++
		}
		node = &constraintSetNode{
			kind:    constraintSetChase,
			value:   attribute,
			closure: closure,
			left:    node,
		}
	}
}

func (parser *constraintSetParser) readIdentifier() string {
	if parser.index >= len(parser.input) ||
		!constraintSetIdentifierLead(parser.input[parser.index]) {
		return ""
	}
	start := parser.index
	parser.index++
	for parser.index < len(parser.input) &&
		constraintSetIdentifierCharacter(parser.input[parser.index]) {
		if parser.input[parser.index] == '-' &&
			(parser.index+1 == len(parser.input) ||
				!constraintSetIdentifierCharacter(parser.input[parser.index+1])) {
			break
		}
		parser.index++
	}
	return parser.input[start:parser.index]
}

func constraintSetIdentifierLead(value byte) bool {
	return value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9'
}

func constraintSetIdentifierCharacter(value byte) bool {
	return constraintSetIdentifierLead(value) ||
		value == '-' ||
		value == '.' ||
		value == ';'
}

func (parser *constraintSetParser) skipSpaces() {
	for parser.index < len(parser.input) {
		switch parser.input[parser.index] {
		case ' ', '\t', '\n', '\r':
			parser.index++
		default:
			return
		}
	}
}

func (parser *constraintSetParser) errorf(format string, args ...any) error {
	return fmt.Errorf(
		"parse set expression at byte %d: %s",
		parser.index,
		fmt.Sprintf(format, args...),
	)
}

func validateConstraintSetSchema(
	registry *schema.Registry,
	node *constraintSetNode,
) error {
	if node == nil {
		return nil
	}
	if node.kind == constraintSetChase &&
		!strings.EqualFold(node.value, "entryDN") {
		if err := validateConstraintAttributeDescription(node.value); err != nil {
			return fmt.Errorf("constraint set: %w", err)
		}
		if _, found := registry.AttributeType(node.value); !found {
			return fmt.Errorf(
				"constraint set references undefined attribute type %q",
				node.value,
			)
		}
	}
	if err := validateConstraintSetSchema(registry, node.left); err != nil {
		return err
	}
	return validateConstraintSetSchema(registry, node.right)
}

func (evaluation constraintSetEvaluation) evaluate(
	node *constraintSetNode,
) (constraintValueSet, error) {
	if node == nil {
		return nil, errors.New("constraint set expression is missing")
	}
	switch node.kind {
	case constraintSetLiteral:
		return newConstraintSet(node.value), nil
	case constraintSetThis:
		value, err := evaluation.normalizedDNValue(evaluation.target.DN)
		if err != nil {
			return nil, err
		}
		return newConstraintSet(value), nil
	case constraintSetUser:
		if evaluation.userDN == "" {
			return constraintValueSet{}, nil
		}
		value, err := evaluation.normalizedDNValue(evaluation.userDN)
		if err != nil {
			return nil, err
		}
		return newConstraintSet(value), nil
	case constraintSetChase:
		base, err := evaluation.evaluate(node.left)
		if err != nil {
			return nil, err
		}
		return evaluation.chase(base, node.value, node.closure)
	case constraintSetParent:
		base, err := evaluation.evaluate(node.left)
		if err != nil {
			return nil, err
		}
		return evaluation.parentsAtLevel(base, node.level), nil
	case constraintSetParents:
		base, err := evaluation.evaluate(node.left)
		if err != nil {
			return nil, err
		}
		return evaluation.allParents(base), nil
	case constraintSetUnion,
		constraintSetIntersection,
		constraintSetConcatenation:
		left, err := evaluation.evaluate(node.left)
		if err != nil {
			return nil, err
		}
		right, err := evaluation.evaluate(node.right)
		if err != nil {
			return nil, err
		}
		return joinConstraintSets(left, right, node.kind)
	default:
		return nil, fmt.Errorf("unknown constraint set node %d", node.kind)
	}
}

func (evaluation constraintSetEvaluation) normalizeDN(raw string) (directory.DN, error) {
	if evaluation.runtime != nil && evaluation.runtime.schema != nil {
		return evaluation.runtime.schema.NormalizeDN(raw)
	}
	return directory.ParseDN(raw)
}

func (evaluation constraintSetEvaluation) normalizedDNValue(raw string) (string, error) {
	dn, err := evaluation.normalizeDN(raw)
	if err != nil {
		return "", err
	}
	return dn.NormalizedString(), nil
}

func (evaluation constraintSetEvaluation) chase(
	base constraintValueSet,
	attribute string,
	closure bool,
) (constraintValueSet, error) {
	result := make(constraintValueSet)
	queue := make([]string, 0, len(base))
	for value := range base {
		queue = append(queue, value)
	}
	visited := make(map[string]struct{})
	for len(queue) > 0 {
		value := queue[0]
		queue = queue[1:]
		if _, seen := visited[value]; seen {
			continue
		}
		visited[value] = struct{}{}
		values, err := evaluation.gather(value, attribute)
		if err != nil {
			return nil, err
		}
		for _, candidate := range values {
			if _, exists := result[candidate]; exists {
				continue
			}
			result[candidate] = struct{}{}
			if closure {
				queue = append(queue, candidate)
			}
		}
	}
	return result, nil
}

func (evaluation constraintSetEvaluation) gather(
	rawDN,
	attribute string,
) ([]string, error) {
	if strings.HasPrefix(strings.ToLower(rawDN), "ldap:///") {
		return evaluation.gatherLDAPURL(rawDN, attribute)
	}
	dn, err := evaluation.normalizeDN(rawDN)
	if err != nil {
		return nil, nil
	}
	if strings.EqualFold(attribute, "entryDN") {
		return []string{dn.NormalizedString()}, nil
	}
	targetDN, err := evaluation.normalizeDN(evaluation.target.DN)
	if err != nil {
		return nil, err
	}
	entry := evaluation.target
	if !dn.Equal(targetDN) {
		database := databaseForDN(evaluation.runtime, dn)
		if database == nil {
			return nil, nil
		}
		entry, err = readerForDatabase(evaluation.reader, *database).Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
	values := constraintAttributeValues(
		evaluation.runtime.schema,
		entry,
		attribute,
	)
	result := make([]string, len(values))
	for index := range values {
		normalized, err := evaluation.runtime.schema.NormalizeEqualityValue(
			attribute,
			values[index],
		)
		if err != nil {
			return nil, err
		}
		result[index] = string(normalized)
	}
	return result, nil
}

func (evaluation constraintSetEvaluation) gatherLDAPURL(
	rawURL,
	attribute string,
) ([]string, error) {
	parsed, err := parseConstraintLDAPURLWithNormalizer(
		rawURL,
		evaluation.runtime.schema,
	)
	if err != nil || parsed.extensions != "" || parsed.base == nil {
		return nil, nil
	}
	database := databaseForDN(evaluation.runtime, *parsed.base)
	if database == nil {
		return nil, nil
	}
	filter := directory.Filter{
		Kind:      directory.FilterPresent,
		Attribute: "objectClass",
	}
	if parsed.filter != nil {
		filter = *parsed.filter
	}
	requested := append(append([]string(nil), parsed.attributes...), attribute)
	reader := readerForDatabase(evaluation.reader, *database)
	base, err := storage.NormalizeReaderDN(reader, *parsed.base)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	err = reader.ForEach(func(entry directory.Entry) error {
		if evaluation.runtime.schema.EntryHasObjectClass(entry, "referral") ||
			!subentrySearchVisible(
				evaluation.runtime,
				entry,
				parsed.scope,
				nil,
			) {
			return nil
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		dn, err = storage.NormalizeReaderDN(reader, dn)
		if err != nil {
			return err
		}
		if !directory.InScope(base, dn, parsed.scope) {
			return nil
		}
		matches, err := filter.MatchWith(entry, evaluation.runtime.schema)
		if err != nil || !matches {
			return nil
		}
		for _, description := range requested {
			if strings.EqualFold(description, "entryDN") {
				result = append(result, dn.NormalizedString())
				continue
			}
			if _, found := evaluation.runtime.schema.AttributeType(description); !found {
				continue
			}
			for _, value := range constraintAttributeValues(
				evaluation.runtime.schema,
				entry,
				description,
			) {
				normalized, err := evaluation.runtime.schema.NormalizeEqualityValue(
					description,
					value,
				)
				if err != nil {
					return err
				}
				result = append(result, string(normalized))
			}
		}
		return nil
	})
	return result, err
}

func newConstraintSet(values ...string) constraintValueSet {
	set := make(constraintValueSet, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func joinConstraintSets(
	left,
	right constraintValueSet,
	kind constraintSetNodeKind,
) (constraintValueSet, error) {
	result := make(constraintValueSet)
	switch kind {
	case constraintSetUnion:
		for value := range left {
			result[value] = struct{}{}
		}
		for value := range right {
			result[value] = struct{}{}
		}
	case constraintSetIntersection:
		for value := range left {
			if _, exists := right[value]; exists {
				result[value] = struct{}{}
			}
		}
	case constraintSetConcatenation:
		if uint64(len(left))*uint64(len(right)) > 100000 {
			return nil, errors.New(
				"constraint set concatenation exceeds 100000 combinations",
			)
		}
		for leftValue := range left {
			for rightValue := range right {
				result[leftValue+rightValue] = struct{}{}
			}
		}
	default:
		return nil, fmt.Errorf("invalid constraint set join %d", kind)
	}
	return result, nil
}

func (evaluation constraintSetEvaluation) parentsAtLevel(
	base constraintValueSet,
	level int,
) constraintValueSet {
	result := make(constraintValueSet)
	for rawDN := range base {
		dn, err := evaluation.normalizeDN(rawDN)
		if err != nil {
			continue
		}
		for index := 0; index < level; index++ {
			parent, ok := dn.Parent()
			if !ok {
				break
			}
			dn = parent
		}
		result[dn.NormalizedString()] = struct{}{}
	}
	return result
}

func (evaluation constraintSetEvaluation) allParents(
	base constraintValueSet,
) constraintValueSet {
	result := make(constraintValueSet)
	for rawDN := range base {
		dn, err := evaluation.normalizeDN(rawDN)
		if err != nil {
			continue
		}
		for {
			result[dn.NormalizedString()] = struct{}{}
			parent, ok := dn.Parent()
			if !ok {
				break
			}
			dn = parent
		}
	}
	return result
}
