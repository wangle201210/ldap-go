package server

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	rwmRewriteDefaultMaxPasses         = 100
	rwmRewriteMaximumPasses            = 1000
	rwmRewriteMaximumContexts          = 128
	rwmRewriteMaximumRules             = 1024
	rwmRewriteMaximumPatternBytes      = 64 << 10
	rwmRewriteMaximumSubstitutionBytes = 64 << 10
	rwmRewriteMaximumInputBytes        = 1 << 20
	rwmRewriteMaximumOutputBytes       = 1 << 20
	rwmRewriteMaximumDepth             = 16
	rwmRewriteMaximumVariables         = 64
	rwmRewriteMaximumExpansionSteps    = 1 << 16
)

type rwmRewriteEngine struct {
	enabled          bool
	configured       bool
	maxPasses        int
	maxPassesPerRule int
	contexts         map[string]*rwmRewriteContext
	parameters       map[string]string
	maps             map[string]*rwmRewriteMap
	current          *rwmRewriteContext
	ruleCount        int
}

type rwmRewriteContext struct {
	name  string
	alias *rwmRewriteContext
	rules []*rwmRewriteRule
}

type rwmRewriteRule struct {
	pattern      *regexp.Regexp
	program      *syntax.Prog
	substitution rwmRewriteTemplate
	recurse      bool
	actions      []rwmRewriteAction
	maxPasses    int
}

type rwmRewriteAction struct {
	kind     byte
	argument int
}

type rwmRewriteTemplate []rwmRewriteTemplatePart

type rwmRewriteTemplatePart struct {
	kind    rwmRewriteTemplatePartKind
	value   string
	capture int
	nested  rwmRewriteTemplate
	context *rwmRewriteContext
	mapper  *rwmRewriteMap
}

type rwmRewriteTemplatePartKind uint8

const (
	rwmRewriteLiteral rwmRewriteTemplatePartKind = iota
	rwmRewriteCapture
	rwmRewriteSubcontext
	rwmRewriteSetVariable
	rwmRewriteSetAndGetVariable
	rwmRewriteGetVariable
	rwmRewriteGetParameter
	rwmRewriteBuiltinMap
)

type rwmRewriteOperation struct {
	passes         int
	depth          int
	variables      map[string]string
	expansionSteps int
	regexSteps     int
	mapSteps       int
}

var errRWMRewriteRejected = errors.New("RWM rewrite rejected the value")

func newRWMRewriteEngine() *rwmRewriteEngine {
	engine := &rwmRewriteEngine{
		maxPasses:        rwmRewriteDefaultMaxPasses,
		maxPassesPerRule: rwmRewriteDefaultMaxPasses,
		contexts:         make(map[string]*rwmRewriteContext),
		parameters:       make(map[string]string),
		maps:             make(map[string]*rwmRewriteMap),
	}
	engine.current = engine.addContext("default")
	// OpenLDAP RWM creates searchFilter as an explicit empty context so it does
	// not fall through to the default DN rules.
	engine.addContext("searchFilter")
	return engine
}

func (engine *rwmRewriteEngine) addContext(name string) *rwmRewriteContext {
	key := strings.ToLower(name)
	if context := engine.contexts[key]; context != nil {
		return context
	}
	context := &rwmRewriteContext{name: name}
	engine.contexts[key] = context
	return context
}

func (engine *rwmRewriteEngine) parseDirective(words []string) error {
	if engine == nil || len(words) == 0 {
		return errors.New("empty rewrite directive")
	}
	for _, word := range words {
		if strings.IndexByte(word, 0) >= 0 {
			return errors.New("rewrite directives cannot contain NUL bytes")
		}
	}
	directive := strings.ToLower(strings.TrimSpace(words[0]))
	if strings.HasPrefix(directive, "rwm-") {
		directive = strings.TrimPrefix(directive, "rwm-")
	}
	switch directive {
	case "rewriteengine":
		if len(words) != 2 {
			return errors.New("rewriteEngine expects exactly on or off")
		}
		switch strings.ToLower(words[1]) {
		case "on":
			engine.enabled = true
		case "off":
			engine.enabled = false
		default:
			return fmt.Errorf("rewriteEngine has unknown state %q", words[1])
		}
		engine.configured = true
		return nil

	case "rewritemaxpasses":
		if len(words) != 2 && len(words) != 3 {
			return errors.New("rewriteMaxPasses expects total and optional per-rule limits")
		}
		total, err := parseRWMRewriteLimit(words[1])
		if err != nil {
			return fmt.Errorf("rewriteMaxPasses total: %w", err)
		}
		perRule := total
		if len(words) == 3 {
			perRule, err = parseRWMRewriteLimit(words[2])
			if err != nil {
				return fmt.Errorf("rewriteMaxPasses per rule: %w", err)
			}
		}
		engine.maxPasses = total
		engine.maxPassesPerRule = perRule
		engine.configured = true
		return nil

	case "rewritecontext":
		if len(words) != 2 && len(words) != 4 {
			return errors.New("rewriteContext expects a name and optional alias target")
		}
		name, err := validateRWMRewriteName(words[1], "context")
		if err != nil {
			return err
		}
		if len(engine.contexts) >= rwmRewriteMaximumContexts &&
			engine.contexts[strings.ToLower(name)] == nil {
			return fmt.Errorf("rewrite context count exceeds %d", rwmRewriteMaximumContexts)
		}
		context := engine.contexts[strings.ToLower(name)].resolved()
		if len(words) == 4 {
			if !strings.EqualFold(words[2], "alias") {
				return fmt.Errorf("rewriteContext has unsupported qualifier %q", words[2])
			}
			targetName, nameErr := validateRWMRewriteName(words[3], "alias context")
			if nameErr != nil {
				return nameErr
			}
			target := engine.contexts[strings.ToLower(targetName)]
			if target == nil {
				return fmt.Errorf("rewriteContext alias target %q is not defined", targetName)
			}
			if context == nil {
				context = engine.addContext(name)
			}
			context.alias = target.resolved()
			engine.current = context.alias
		} else {
			if context == nil {
				context = engine.addContext(name)
			}
			engine.current = context
		}
		engine.configured = true
		return nil

	case "rewriterule":
		if len(words) != 3 && len(words) != 4 {
			return errors.New("rewriteRule expects pattern, substitution, and optional flags")
		}
		if engine.ruleCount >= rwmRewriteMaximumRules {
			return fmt.Errorf("rewrite rule count exceeds %d", rwmRewriteMaximumRules)
		}
		flags := ""
		if len(words) == 4 {
			flags = words[3]
		}
		rule, err := compileRWMRewriteRule(
			words[1],
			words[2],
			flags,
			engine.maxPassesPerRule,
		)
		if err != nil {
			return err
		}
		if err := engine.bindTemplateContexts(rule.substitution); err != nil {
			return err
		}
		if engine.current == nil {
			engine.current = engine.contexts["default"]
		}
		engine.current.rules = append(engine.current.rules, rule)
		engine.ruleCount++
		engine.configured = true
		return nil

	case "rewriteparam":
		if len(words) != 3 {
			return errors.New("rewriteParam expects a name and value")
		}
		name, err := validateRWMRewriteName(words[1], "parameter")
		if err != nil {
			return err
		}
		if len(words[2]) > rwmRewriteMaximumOutputBytes {
			return fmt.Errorf("rewrite parameter %q exceeds %d bytes", name, rwmRewriteMaximumOutputBytes)
		}
		if _, exists := engine.parameters[strings.ToLower(name)]; !exists && len(engine.parameters) >= rwmRewriteMaximumVariables {
			return fmt.Errorf("rewrite parameter count exceeds %d", rwmRewriteMaximumVariables)
		}
		engine.parameters[strings.ToLower(name)] = words[2]
		engine.configured = true
		return nil

	case "rewritemap":
		return engine.parseMap(words)
	default:
		return fmt.Errorf("unsupported rewrite directive %q", words[0])
	}
}

func parseRWMRewriteLimit(value string) (int, error) {
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("%q is not a positive decimal integer", value)
	}
	if limit > rwmRewriteMaximumPasses {
		return 0, fmt.Errorf("%d exceeds the implementation limit %d", limit, rwmRewriteMaximumPasses)
	}
	return limit, nil
}

func validateRWMRewriteName(value, kind string) (string, error) {
	if value == "" || len(value) > 128 {
		return "", fmt.Errorf("rewrite %s name %q is invalid", kind, value)
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return "", fmt.Errorf("rewrite %s name %q is invalid", kind, value)
	}
	return value, nil
}

func (context *rwmRewriteContext) resolved() *rwmRewriteContext {
	if context != nil && context.alias != nil {
		return context.alias
	}
	return context
}

func compileRWMRewriteRule(
	pattern,
	substitution,
	flags string,
	defaultMaxPasses int,
) (*rwmRewriteRule, error) {
	if len(pattern) > rwmRewriteMaximumPatternBytes {
		return nil, fmt.Errorf("rewriteRule pattern exceeds %d bytes", rwmRewriteMaximumPatternBytes)
	}
	if len(substitution) > rwmRewriteMaximumSubstitutionBytes {
		return nil, fmt.Errorf("rewriteRule substitution exceeds %d bytes", rwmRewriteMaximumSubstitutionBytes)
	}
	if len(flags) > rwmRewriteMaximumSubstitutionBytes {
		return nil, errors.New("rewriteRule flags exceed the configuration size bound")
	}
	for index := 0; index+1 < len(pattern); index++ {
		if pattern[index] == '\\' {
			index++
			character := pattern[index]
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
				return nil, errors.New("rewriteRule pattern contains an unsupported regex escape")
			}
		}
	}
	rule := &rwmRewriteRule{recurse: true, maxPasses: defaultMaxPasses}
	caseSensitive := false
	for index := 0; index < len(flags); index++ {
		switch flags[index] {
		case 'C':
			caseSensitive = true
		case ':':
			rule.recurse = false
		case '@':
			rule.actions = append(rule.actions, rwmRewriteAction{kind: '@'})
		case '#':
			rule.actions = append(rule.actions, rwmRewriteAction{kind: '#'})
			rule.recurse = false
		case 'I':
			rule.actions = append(rule.actions, rwmRewriteAction{kind: 'I'})
		case 'G', 'U', 'M':
			flag := flags[index]
			value, end, err := parseRWMRewriteFlagArgument(flags, index)
			if err != nil {
				return nil, err
			}
			index = end
			switch flag {
			case 'G':
				rule.actions = append(rule.actions, rwmRewriteAction{kind: flag, argument: value})
			case 'U':
				if value < 1 || value > 4095 {
					return nil, fmt.Errorf("rewriteRule U{%d} is outside 1..4095", value)
				}
				rule.actions = append(rule.actions, rwmRewriteAction{kind: flag, argument: value})
			case 'M':
				if value < 1 {
					value = 1
				}
				if value > rwmRewriteMaximumPasses {
					return nil, fmt.Errorf("rewriteRule M{%d} exceeds %d", value, rwmRewriteMaximumPasses)
				}
				rule.maxPasses = value
			}
		case 'R':
			return nil, errors.New("rewriteRule flag R (POSIX basic regex) is not implemented")
		default:
			return nil, fmt.Errorf("rewriteRule has unsupported flag %q", flags[index])
		}
	}
	// OpenLDAP uses REG_EXTENDED without REG_NEWLINE.
	regexFlags := syntax.POSIX | syntax.DotNL | syntax.ClassNL | syntax.OneLine
	if !caseSensitive {
		regexFlags |= syntax.FoldCase
	}
	parsed, err := syntax.Parse(pattern, regexFlags)
	if err != nil {
		return nil, fmt.Errorf("rewriteRule pattern %q: %w", pattern, err)
	}
	if rwmRewritePatternCost(parsed) > 8192 {
		return nil, errors.New("rewriteRule compiled pattern exceeds 8192 instructions")
	}
	compiled, err := regexp.Compile(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("rewriteRule pattern %q: %w", pattern, err)
	}
	compiled.Longest()
	program, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return nil, fmt.Errorf("rewriteRule pattern %q: %w", pattern, err)
	}
	if len(program.Inst) > 8192 {
		return nil, errors.New("rewriteRule compiled pattern exceeds 8192 instructions")
	}
	template, err := parseRWMRewriteTemplate(substitution)
	if err != nil {
		return nil, fmt.Errorf("rewriteRule substitution %q: %w", substitution, err)
	}
	rule.pattern = compiled
	rule.program = program
	rule.substitution = template
	return rule, nil
}

func parseRWMRewriteFlagArgument(flags string, index int) (int, int, error) {
	if index+2 >= len(flags) || flags[index+1] != '{' {
		return 0, index, fmt.Errorf("rewriteRule flag %q requires {integer}", flags[index])
	}
	end := strings.IndexByte(flags[index+2:], '}')
	if end < 0 {
		return 0, index, fmt.Errorf("rewriteRule flag %q has unterminated argument", flags[index])
	}
	end += index + 2
	value64, err := strconv.ParseInt(flags[index+2:end], 0, 32)
	if err != nil {
		return 0, index, fmt.Errorf("rewriteRule flag %q has invalid integer", flags[index])
	}
	return int(value64), end, nil
}

func parseRWMRewriteTemplate(value string) (rwmRewriteTemplate, error) {
	return parseRWMRewriteTemplateDepth(value, 0)
}

func parseRWMRewriteTemplateDepth(value string, depth int) (rwmRewriteTemplate, error) {
	if depth >= rwmRewriteMaximumDepth {
		return nil, fmt.Errorf("rewrite substitution depth exceeds %d", rwmRewriteMaximumDepth)
	}
	parts := make(rwmRewriteTemplate, 0, 4)
	literalStart := 0
	flushLiteral := func(end int) {
		if end > literalStart {
			parts = append(parts, rwmRewriteTemplatePart{
				kind:  rwmRewriteLiteral,
				value: value[literalStart:end],
			})
		}
	}
	for index := 0; index < len(value); {
		if value[index] != '$' && value[index] != '%' {
			index++
			continue
		}
		escape := value[index]
		if index+1 >= len(value) {
			return nil, fmt.Errorf("dangling substitution escape %q", escape)
		}
		flushLiteral(index)
		next := value[index+1]
		switch {
		case next == '$' || next == '%':
			parts = append(parts, rwmRewriteTemplatePart{kind: rwmRewriteLiteral, value: string(next)})
			index += 2
		case next >= '0' && next <= '9':
			if index+2 < len(value) && value[index+2] == '{' {
				return nil, errors.New("legacy capture maps are not implemented")
			}
			parts = append(parts, rwmRewriteTemplatePart{kind: rwmRewriteCapture, capture: int(next - '0')})
			index += 2
		case next == '{':
			end, err := findRWMRewriteExpressionEnd(value, index+2)
			if err != nil {
				return nil, err
			}
			part, err := parseRWMRewriteExpression(value[index+2:end], depth+1)
			if err != nil {
				return nil, err
			}
			parts = append(parts, part)
			index = end + 1
		default:
			return nil, fmt.Errorf("unsupported substitution escape %q", value[index:index+2])
		}
		literalStart = index
	}
	flushLiteral(len(value))
	return parts, nil
}

func findRWMRewriteExpressionEnd(value string, start int) (int, error) {
	depth := 1
	for index := start; index < len(value); index++ {
		if value[index] == '$' || value[index] == '%' {
			if index+1 < len(value) && value[index+1] == '{' {
				depth++
				index++
				continue
			}
			if index+1 < len(value) {
				index++
			}
			continue
		}
		if value[index] == '}' {
			depth--
			if depth == 0 {
				return index, nil
			}
		}
	}
	return 0, errors.New("unterminated substitution expression")
}

func parseRWMRewriteExpression(expression string, depth int) (rwmRewriteTemplatePart, error) {
	if expression == "" {
		return rwmRewriteTemplatePart{}, errors.New("empty substitution expression")
	}
	switch expression[0] {
	case '>':
		name, argument, err := parseRWMRewriteCall(expression[1:])
		if err != nil {
			return rwmRewriteTemplatePart{}, fmt.Errorf("subcontext: %w", err)
		}
		nested, err := parseRWMRewriteTemplateDepth(argument, depth)
		return rwmRewriteTemplatePart{kind: rwmRewriteSubcontext, value: name, nested: nested}, err
	case '&':
		if len(expression) > 1 && expression[1] == '&' {
			return rwmRewriteTemplatePart{}, errors.New("session variables are not implemented")
		}
		kind := rwmRewriteSetVariable
		start := 1
		if len(expression) > 1 && expression[1] == '*' {
			kind = rwmRewriteSetAndGetVariable
			start++
		}
		name, argument, err := parseRWMRewriteCall(expression[start:])
		if err != nil {
			return rwmRewriteTemplatePart{}, fmt.Errorf("operation variable: %w", err)
		}
		nested, err := parseRWMRewriteTemplateDepth(argument, depth)
		return rwmRewriteTemplatePart{kind: kind, value: name, nested: nested}, err
	case '*':
		if len(expression) > 1 && expression[1] == '*' {
			return rwmRewriteTemplatePart{}, errors.New("session variables are not implemented")
		}
		name, err := validateRWMRewriteMapName(expression[1:])
		return rwmRewriteTemplatePart{kind: rwmRewriteGetVariable, value: name}, err
	case '$':
		name, err := validateRWMRewriteMapName(expression[1:])
		return rwmRewriteTemplatePart{kind: rwmRewriteGetParameter, value: name}, err
	default:
		// librewrite/map.c ignores text following the final closing parenthesis.
		if end := strings.LastIndexByte(expression, ')'); end >= 0 {
			expression = expression[:end+1]
		}
		name, argument, err := parseRWMRewriteCall(expression)
		if err != nil {
			return rwmRewriteTemplatePart{}, fmt.Errorf("rewrite map: %w", err)
		}
		nested, err := parseRWMRewriteTemplateDepth(argument, depth)
		return rwmRewriteTemplatePart{kind: rwmRewriteBuiltinMap, value: name, nested: nested}, err
	}
}

func parseRWMRewriteCall(value string) (string, string, error) {
	open := strings.IndexByte(value, '(')
	if open <= 0 || !strings.HasSuffix(value, ")") {
		return "", "", fmt.Errorf("%q is not name(argument)", value)
	}
	name, err := validateRWMRewriteMapName(value[:open])
	if err != nil {
		return "", "", err
	}
	return name, value[open+1 : len(value)-1], nil
}

func validateRWMRewriteMapName(name string) (string, error) {
	if name == "" || len(name) > 128 {
		return "", fmt.Errorf("invalid rewrite map name %q", name)
	}
	for index, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return "", fmt.Errorf("invalid rewrite map name %q", name)
	}
	return name, nil
}

func (engine *rwmRewriteEngine) bindTemplateContexts(template rwmRewriteTemplate) error {
	for index := range template {
		part := &template[index]
		if part.kind == rwmRewriteSubcontext {
			part.context = engine.contexts[strings.ToLower(part.value)].resolved()
			if part.context == nil {
				return fmt.Errorf("rewrite subcontext %q is not defined", part.value)
			}
		}
		if part.kind == rwmRewriteBuiltinMap {
			part.mapper = engine.maps[strings.ToLower(part.value)]
			if part.mapper == nil {
				return fmt.Errorf("rewrite map %q is not defined", part.value)
			}
		}
		if err := engine.bindTemplateContexts(part.nested); err != nil {
			return err
		}
	}
	return nil
}

func (engine *rwmRewriteEngine) active() bool {
	return engine != nil && engine.configured && engine.enabled
}

func (engine *rwmRewriteEngine) addSuffixMapping(mapping *rwmSuffixMapping, responseContext string) error {
	configured := engine.configured
	defer func() { engine.configured = configured }()
	escape := func(value string) string {
		return strings.NewReplacer("$", "$$", "%", "%%").Replace(value)
	}
	directives := [][]string{
		{"rewriteEngine", "on"},
		{"rewriteContext", "default"},
		{"rewriteRule", "^(.+,)?" + regexp.QuoteMeta(mapping.local.String()) + "$", "$1" + escape(mapping.remote.String()), ":"},
		{"rewriteContext", "searchEntryDN"},
		{"rewriteRule", "^(.+,)?" + regexp.QuoteMeta(mapping.remote.String()) + "$", "$1" + escape(mapping.local.String()), ":"},
	}
	if responseContext == "searchResult" {
		directives = append(directives, []string{"rewriteContext", "searchResult", "alias", "searchEntryDN"})
	}
	directives = append(directives, []string{"rewriteContext", "matchedDN", "alias", "searchEntryDN"})
	if responseContext == "searchResult" {
		directives = append(directives, []string{"rewriteContext", "searchAttrDN", "alias", "searchEntryDN"})
	}
	directives = append(directives, [][]string{
		{"rewriteContext", "referralAttrDN"},
		{"rewriteContext", "referralDN"},
	}...)
	if responseContext != "searchResult" {
		directives = append(directives, []string{"rewriteContext", "searchAttrDN", "alias", "searchEntryDN"})
	}
	for _, directive := range directives {
		if err := engine.parseDirective(directive); err != nil {
			return err
		}
	}
	return nil
}

func (engine *rwmRewriteEngine) rewrite(context, input string) (string, bool, error) {
	if !engine.active() {
		return input, false, nil
	}
	if strings.IndexByte(input, 0) >= 0 {
		return "", false, operationFailed(ldapwire.ResultOther, "RWM rewrite input contains a NUL byte")
	}
	if len(input) > rwmRewriteMaximumInputBytes {
		return "", false, operationFailed(
			ldapwire.ResultOther,
			fmt.Sprintf("RWM rewrite input exceeds %d bytes", rwmRewriteMaximumInputBytes),
		)
	}
	operation := &rwmRewriteOperation{variables: make(map[string]string)}
	output, changed, err := engine.rewriteContext(context, input, operation, true)
	if err != nil {
		return "", false, rwmRewriteOperationError(err)
	}
	return output, changed, nil
}

func (engine *rwmRewriteEngine) rewriteDefinedContext(
	context,
	input string,
) (string, bool, error) {
	if !engine.active() {
		return input, false, nil
	}
	if engine.contexts[strings.ToLower(context)] == nil {
		return input, false, nil
	}
	return engine.rewrite(context, input)
}

func rwmRewriteOperationError(err error) error {
	if errors.Is(err, errRWMRewriteRejected) {
		return operationFailed(ldapwire.ResultUnwillingToPerform, "RWM rewrite rejected the value")
	}
	var result *rwmRewriteResultError
	if errors.As(err, &result) {
		return operationFailed(result.code, "RWM rewrite returned a configured result")
	}
	return operationFailed(ldapwire.ResultOther, "RWM rewrite failed: "+err.Error())
}

type rwmRewriteResultError struct {
	code ldapwire.ResultCode
}

func (failure *rwmRewriteResultError) Error() string {
	return fmt.Sprintf("RWM rewrite result %d", failure.code)
}

func (engine *rwmRewriteEngine) rewriteContext(
	name,
	input string,
	operation *rwmRewriteOperation,
	fallbackToDefault bool,
) (string, bool, error) {
	context := engine.contexts[strings.ToLower(name)]
	if context == nil && fallbackToDefault {
		context = engine.contexts["default"]
	}
	if context == nil {
		return input, false, nil
	}
	output, produced, err := engine.applyContext(context.resolved(), input, operation)
	if !produced && err == nil {
		return input, false, nil
	}
	return output, output != input, err
}

// The boolean preserves librewrite's NULL result, which expands to an empty
// string in a subcontext but means unchanged input at the public entry point.
func (engine *rwmRewriteEngine) applyContext(context *rwmRewriteContext, input string, operation *rwmRewriteOperation) (string, bool, error) {
	if operation.depth >= rwmRewriteMaximumDepth {
		return "", false, fmt.Errorf("rewrite context depth exceeds %d", rwmRewriteMaximumDepth)
	}
	operation.depth++
	defer func() { operation.depth-- }()

	current := rwmRewriteCString(input)
	var result string
	produced := false
	for index := 0; index < len(context.rules) && operation.passes < engine.maxPasses; index, operation.passes = index+1, operation.passes+1 {
		rule := context.rules[index]
		before := current
		matched := false
		var expansionErr error
		produced = false
		for rulePass := 0; rulePass < rule.maxPasses && operation.passes < engine.maxPasses; rulePass++ {
			operation.passes++
			indices, err := rule.match(current, operation)
			if err != nil {
				return "", false, err
			}
			if indices == nil {
				break
			}
			matched = true
			next, err := engine.expandTemplate(rule.substitution, current, indices, operation)
			if err != nil {
				expansionErr = err
				current = before
				break
			}
			// Rule results become C strings in librewrite; nested substitutions
			// retain their berval lengths until this boundary.
			current = rwmRewriteCString(next)
			if !rule.recurse {
				break
			}
		}
		if matched {
			ignored := false
			for _, action := range rule.actions {
				if expansionErr != nil {
					if action.kind == 'I' {
						ignored = true
					}
					if action.kind != 'G' || !ignored {
						continue
					}
				}
				switch action.kind {
				case '@':
					return current, true, nil
				case '#':
					return "", false, errRWMRewriteRejected
				case 'U':
					return "", false, &rwmRewriteResultError{code: ldapwire.ResultCode(action.argument)}
				case 'G':
					// The C action selects the predecessor of the destination;
					// the context loop advances once after all ordered actions.
					index += action.argument - 1
					if index < -1 || index >= len(context.rules) {
						return "", false, errors.New("rewriteRule goto leaves the current context")
					}
				}
			}
			if expansionErr != nil && !ignored {
				return "", false, expansionErr
			}
		}
		produced = matched && expansionErr == nil || index == len(context.rules)-1
		result = current
	}
	return result, produced, nil
}

func (engine *rwmRewriteEngine) expandTemplate(
	template rwmRewriteTemplate,
	input string,
	indices []int,
	operation *rwmRewriteOperation,
) (string, error) {
	var builder strings.Builder
	for _, part := range template {
		operation.expansionSteps++
		if operation.expansionSteps > rwmRewriteMaximumExpansionSteps {
			return "", fmt.Errorf("rewrite expansion steps exceed %d", rwmRewriteMaximumExpansionSteps)
		}
		var value string
		switch part.kind {
		case rwmRewriteLiteral:
			value = part.value
		case rwmRewriteCapture:
			position := part.capture * 2
			if position+1 < len(indices) && indices[position] >= 0 {
				value = input[indices[position]:indices[position+1]]
			}
		case rwmRewriteSubcontext:
			argument, err := engine.expandTemplate(part.nested, input, indices, operation)
			if err != nil {
				return "", err
			}
			var produced bool
			value, produced, err = engine.applyContext(part.context, argument, operation)
			if err != nil {
				// librewrite converts map/subcontext results into expansion
				// errors, allowing the caller's I action to handle them.
				return "", fmt.Errorf("rewrite subcontext %s failed: %v", part.value, err)
			}
			if !produced {
				value = ""
			}
		case rwmRewriteSetVariable, rwmRewriteSetAndGetVariable:
			argument, err := engine.expandTemplate(part.nested, input, indices, operation)
			if err != nil {
				return "", err
			}
			key := strings.ToLower(part.value)
			if _, exists := operation.variables[key]; !exists && len(operation.variables) >= rwmRewriteMaximumVariables {
				return "", fmt.Errorf("rewrite variable count exceeds %d", rwmRewriteMaximumVariables)
			}
			operation.variables[key] = rwmRewriteCString(argument)
			if part.kind == rwmRewriteSetAndGetVariable {
				value = argument
			}
		case rwmRewriteGetVariable:
			var found bool
			value, found = operation.variables[strings.ToLower(part.value)]
			if !found {
				return "", fmt.Errorf("rewrite operation variable %q is not set", part.value)
			}
		case rwmRewriteGetParameter:
			var found bool
			value, found = engine.parameters[strings.ToLower(part.value)]
			if !found {
				return "", fmt.Errorf("rewrite parameter %q is not set", part.value)
			}
		case rwmRewriteBuiltinMap:
			argument, err := engine.expandTemplate(part.nested, input, indices, operation)
			if err != nil {
				return "", err
			}
			value, err = part.mapper.apply(argument, operation)
			if err != nil {
				return "", fmt.Errorf("rewrite map %s failed: %w", part.value, err)
			}
		default:
			return "", errors.New("invalid rewrite substitution part")
		}
		if builder.Len()+len(value) > rwmRewriteMaximumOutputBytes {
			return "", fmt.Errorf("rewrite output exceeds %d bytes", rwmRewriteMaximumOutputBytes)
		}
		builder.WriteString(value)
	}
	return builder.String(), nil
}
