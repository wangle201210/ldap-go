package acl

import (
	"errors"
	"net/url"
	"strings"
	"unicode"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const maxACLSetValues = 10000

type setExpressionKind uint8

const (
	setLiteral setExpressionKind = iota
	setUser
	setThis
	setUnion
	setIntersection
	setConcat
	setChase
	setParents
)

type setExpression struct {
	kind      setExpressionKind
	value     string
	left      *setExpression
	right     *setExpression
	closure   bool
	allParent bool
	level     int
}

type setParser struct {
	input    string
	position int
	depth    int
}

func matchesSet(
	matcher WhoMatcher,
	subjectDN string,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) bool {
	pattern := matcher.SetPattern
	if matcher.SetExpand {
		expanded, ok := expandACLPattern(pattern, context)
		if !ok {
			return false
		}
		pattern = expanded
	}
	expression, err := parseSetExpression(pattern)
	if err != nil {
		return false
	}
	values, err := evaluateSetExpression(
		expression,
		setEvaluationContext{
			subjectDN: subjectDN,
			target:    target,
			targetDN:  targetDN,
			reader:    reader,
		},
	)
	return err == nil && len(values) > 0
}

func parseSetExpression(input string) (*setExpression, error) {
	parser := setParser{input: input}
	expression, err := parser.parseExpression(0)
	if err != nil {
		return nil, err
	}
	parser.skipSpace()
	if expression == nil || parser.position != len(parser.input) {
		return nil, errors.New("invalid set expression")
	}
	return expression, nil
}

func (parser *setParser) parseExpression(terminator byte) (*setExpression, error) {
	left, err := parser.parseOperand()
	if err != nil {
		return nil, err
	}
	for {
		parser.skipSpace()
		if parser.position >= len(parser.input) ||
			(terminator != 0 && parser.input[parser.position] == terminator) {
			return left, nil
		}
		operator := parser.input[parser.position]
		kind := setUnion
		switch operator {
		case '|':
		case '&':
			kind = setIntersection
		case '+':
			kind = setConcat
		default:
			return nil, errors.New("invalid set binary operator")
		}
		parser.position++
		right, err := parser.parseOperand()
		if err != nil {
			return nil, err
		}
		left = &setExpression{kind: kind, left: left, right: right}
	}
}

func (parser *setParser) parseOperand() (*setExpression, error) {
	parser.skipSpace()
	if parser.position >= len(parser.input) {
		return nil, errors.New("missing set operand")
	}
	var expression *setExpression
	switch parser.input[parser.position] {
	case '(':
		parser.position++
		parser.depth++
		if parser.depth > 64 {
			return nil, errors.New("set expression nesting is too deep")
		}
		var err error
		expression, err = parser.parseExpression(')')
		if err != nil {
			return nil, err
		}
		parser.skipSpace()
		if parser.position >= len(parser.input) || parser.input[parser.position] != ')' {
			return nil, errors.New("unterminated set expression")
		}
		parser.position++
		parser.depth--
	case '[':
		end := strings.IndexByte(parser.input[parser.position+1:], ']')
		if end < 0 {
			return nil, errors.New("unterminated set literal")
		}
		end += parser.position + 1
		expression = &setExpression{
			kind:  setLiteral,
			value: parser.input[parser.position+1 : end],
		}
		parser.position = end + 1
	default:
		identifier := parser.parseIdentifier()
		switch identifier {
		case "user":
			expression = &setExpression{kind: setUser}
		case "this":
			expression = &setExpression{kind: setThis}
		default:
			return nil, errors.New("unknown set operand")
		}
	}
	for {
		parser.skipSpace()
		if parser.position >= len(parser.input) {
			return expression, nil
		}
		if strings.HasPrefix(parser.input[parser.position:], "->") {
			parser.position += 2
		} else if parser.input[parser.position] == '/' {
			parser.position++
		} else {
			return expression, nil
		}
		if parser.position < len(parser.input) && parser.input[parser.position] == '-' {
			parser.position++
			parent := &setExpression{kind: setParents, left: expression}
			if parser.position < len(parser.input) && parser.input[parser.position] == '*' {
				parent.allParent = true
				parser.position++
			} else {
				start := parser.position
				for parser.position < len(parser.input) &&
					parser.input[parser.position] >= '0' && parser.input[parser.position] <= '9' {
					parser.position++
				}
				if start == parser.position {
					return nil, errors.New("invalid set parent level")
				}
				for _, digit := range parser.input[start:parser.position] {
					parent.level = parent.level*10 + int(digit-'0')
					if parent.level > 10000 {
						return nil, errors.New("set parent level is too large")
					}
				}
			}
			expression = parent
			continue
		}
		attribute := parser.parseIdentifier()
		if attribute == "" {
			return nil, errors.New("set chase requires an attribute")
		}
		chase := &setExpression{kind: setChase, value: attribute, left: expression}
		if parser.position < len(parser.input) && parser.input[parser.position] == '*' {
			chase.closure = true
			parser.position++
		}
		expression = chase
	}
}

func (parser *setParser) parseIdentifier() string {
	start := parser.position
	for parser.position < len(parser.input) {
		character := rune(parser.input[parser.position])
		if unicode.IsLetter(character) || unicode.IsDigit(character) ||
			character == '-' || character == '.' || character == ';' {
			parser.position++
			continue
		}
		break
	}
	return parser.input[start:parser.position]
}

func (parser *setParser) skipSpace() {
	for parser.position < len(parser.input) && unicode.IsSpace(rune(parser.input[parser.position])) {
		parser.position++
	}
}

type setEvaluationContext struct {
	subjectDN string
	target    Target
	targetDN  directory.DN
	reader    EntryReader
}

type aclStringSet map[string]struct{}

func evaluateSetExpression(
	expression *setExpression,
	context setEvaluationContext,
) (aclStringSet, error) {
	if expression == nil {
		return nil, errors.New("nil set expression")
	}
	switch expression.kind {
	case setLiteral:
		return aclStringSet{expression.value: {}}, nil
	case setUser:
		return aclStringSet{canonicalSetDN(context.subjectDN): {}}, nil
	case setThis:
		return aclStringSet{context.targetDN.Key(): {}}, nil
	case setUnion, setIntersection, setConcat:
		left, err := evaluateSetExpression(expression.left, context)
		if err != nil {
			return nil, err
		}
		right, err := evaluateSetExpression(expression.right, context)
		if err != nil {
			return nil, err
		}
		return joinACLSets(left, right, expression.kind)
	case setChase:
		values, err := evaluateSetExpression(expression.left, context)
		if err != nil {
			return nil, err
		}
		return chaseACLSet(values, expression.value, expression.closure, context)
	case setParents:
		values, err := evaluateSetExpression(expression.left, context)
		if err != nil {
			return nil, err
		}
		return parentACLSet(values, expression.level, expression.allParent), nil
	default:
		return nil, errors.New("unknown set expression")
	}
}

func joinACLSets(left, right aclStringSet, kind setExpressionKind) (aclStringSet, error) {
	result := make(aclStringSet)
	switch kind {
	case setUnion:
		for value := range left {
			result[value] = struct{}{}
		}
		for value := range right {
			result[value] = struct{}{}
		}
	case setIntersection:
		for value := range left {
			if _, exists := right[value]; exists {
				result[value] = struct{}{}
			}
		}
	case setConcat:
		if len(left) > 0 && len(right) > maxACLSetValues/len(left) {
			return nil, errors.New("set expression result is too large")
		}
		for leftValue := range left {
			for rightValue := range right {
				result[leftValue+rightValue] = struct{}{}
			}
		}
	}
	if len(result) > maxACLSetValues {
		return nil, errors.New("set expression result is too large")
	}
	return result, nil
}

func chaseACLSet(
	values aclStringSet,
	attribute string,
	closure bool,
	context setEvaluationContext,
) (aclStringSet, error) {
	result := make(aclStringSet)
	queue := make([]string, 0, len(values))
	for value := range values {
		queue = append(queue, value)
	}
	for position := 0; position < len(queue); position++ {
		gathered := gatherACLSetValue(queue[position], attribute, context)
		for value := range gathered {
			if _, exists := result[value]; exists {
				continue
			}
			if len(result) >= maxACLSetValues {
				return nil, errors.New("set chase result is too large")
			}
			result[value] = struct{}{}
			if closure {
				queue = append(queue, value)
			}
		}
		if !closure && position+1 == len(values) {
			break
		}
	}
	return result, nil
}

func gatherACLSetValue(
	value,
	attribute string,
	context setEvaluationContext,
) aclStringSet {
	if strings.HasPrefix(strings.ToLower(value), "ldap:///") {
		return gatherACLSetURL(value, attribute, context)
	}
	dn, err := directory.ParseDN(value)
	if err != nil || context.reader == nil {
		return aclStringSet{}
	}
	if strings.EqualFold(attribute, "entryDN") {
		return aclStringSet{dn.Key(): {}}
	}
	entry := context.target.Entry
	if !dn.Equal(context.targetDN) {
		entry, err = context.reader.Get(dn)
		if err != nil {
			return aclStringSet{}
		}
	}
	return aclSetAttributeValues(entry, attribute, context.target.Schema)
}

func aclSetAttributeValues(
	entry directory.Entry,
	attribute string,
	schema TargetSchema,
) aclStringSet {
	values := entry.Values(attribute)
	if schema != nil {
		values = schema.AttributeValues(entry, attribute)
	}
	result := make(aclStringSet)
	for _, value := range values {
		normalized := value
		if schema != nil {
			if candidate, err := schema.NormalizeEqualityValue(attribute, value); err == nil {
				normalized = candidate
			}
		}
		result[string(normalized)] = struct{}{}
	}
	return result
}

func parentACLSet(values aclStringSet, level int, all bool) aclStringSet {
	result := make(aclStringSet)
	for value := range values {
		dn, err := directory.ParseDN(value)
		if err != nil {
			continue
		}
		if all {
			for {
				result[dn.Key()] = struct{}{}
				parent, ok := dn.Parent()
				if !ok {
					break
				}
				dn = parent
			}
			continue
		}
		ancestor, ok := dnAncestorAllowRoot(dn, level)
		if ok {
			result[ancestor.Key()] = struct{}{}
		}
	}
	return result
}

func dnAncestorAllowRoot(dn directory.DN, level int) (directory.DN, bool) {
	for ; level > 0; level-- {
		parent, ok := dn.Parent()
		if !ok {
			return directory.DN{}, false
		}
		dn = parent
	}
	return dn, true
}

func canonicalSetDN(raw string) string {
	dn, err := directory.ParseDN(raw)
	if err != nil {
		return raw
	}
	return dn.Key()
}

func gatherACLSetURL(
	raw,
	chaseAttribute string,
	context setEvaluationContext,
) aclStringSet {
	scanner, ok := context.reader.(interface {
		ForEach(func(directory.Entry) error) error
	})
	if !ok {
		return aclStringSet{}
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "ldap") || parsed.Host != "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return aclStringSet{}
	}
	baseText, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil {
		return aclStringSet{}
	}
	base, err := directory.ParseDN(baseText)
	if err != nil {
		return aclStringSet{}
	}
	components := strings.Split(parsed.RawQuery, "?")
	for len(components) < 4 {
		components = append(components, "")
	}
	if len(components) > 4 || components[3] != "" {
		return aclStringSet{}
	}
	attributesText, err := url.PathUnescape(components[0])
	if err != nil {
		return aclStringSet{}
	}
	attributes := []string{chaseAttribute}
	for _, attribute := range strings.Split(attributesText, ",") {
		if attribute != "" {
			attributes = append(attributes, attribute)
		}
	}
	scope := directory.ScopeBase
	scopeText, err := url.PathUnescape(components[1])
	if err != nil {
		return aclStringSet{}
	}
	switch strings.ToLower(scopeText) {
	case "", "base":
	case "one", "onelevel":
		scope = directory.ScopeSingleLevel
	case "sub", "subtree":
		scope = directory.ScopeWholeSubtree
	case "children", "subord", "subordinate":
		scope = directory.ScopeChildren
	default:
		return aclStringSet{}
	}
	filterText, err := url.PathUnescape(components[2])
	if err != nil {
		return aclStringSet{}
	}
	filter := directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"}
	if filterText != "" {
		filter, err = ldapwire.CompileFilter(filterText)
		if err != nil {
			return aclStringSet{}
		}
	}
	matcher := directory.ValueMatcher(directory.BasicMatcher{})
	if context.target.Schema != nil {
		matcher = context.target.Schema
	}
	result := make(aclStringSet)
	_ = scanner.ForEach(func(entry directory.Entry) error {
		dn, parseErr := directory.ParseDN(entry.DN)
		if parseErr != nil || !directory.InScope(base, dn, scope) {
			return nil
		}
		matches, matchErr := filter.MatchWith(entry, matcher)
		if matchErr != nil || !matches {
			return nil
		}
		for _, attribute := range attributes {
			if strings.EqualFold(attribute, "entryDN") {
				result[dn.Key()] = struct{}{}
				continue
			}
			for value := range aclSetAttributeValues(entry, attribute, context.target.Schema) {
				result[value] = struct{}{}
			}
		}
		return nil
	})
	return result
}
