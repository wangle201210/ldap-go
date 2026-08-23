package acl

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

var configSuffix = staticDN("cn=config")

func NewPolicy(global []Rule, databases map[string][]Rule) (*Policy, error) {
	return newPolicy(global, databases, nil)
}

func newPolicy(
	global []Rule,
	databases map[string][]Rule,
	addContentACL map[string]bool,
) (*Policy, error) {
	policy := &Policy{global: append([]Rule(nil), global...)}
	SortRules(policy.global)
	for suffix, rules := range databases {
		dn, err := directory.ParseDN(suffix)
		if err != nil {
			return nil, err
		}
		copy := append([]Rule(nil), rules...)
		SortRules(copy)
		policy.databases = append(policy.databases, databaseRules{
			Suffix:        dn,
			Rules:         copy,
			AddContentACL: addContentACL[suffix],
		})
	}
	sortDatabases(policy.databases)
	return policy, nil
}

func DefaultPolicy() *Policy {
	return &Policy{}
}

func (policy *Policy) Validate(schema TargetSchema) error {
	if schema == nil {
		return nil
	}
	for _, rule := range policy.global {
		if err := validateRuleSchema(rule, schema); err != nil {
			return fmt.Errorf("global ACL %q: %w", rule.Raw, err)
		}
	}
	for _, database := range policy.databases {
		for _, rule := range database.Rules {
			if err := validateRuleSchema(rule, schema); err != nil {
				return fmt.Errorf("ACL for %s %q: %w", database.Suffix.Key(), rule.Raw, err)
			}
		}
	}
	return nil
}

func validateRuleSchema(rule Rule, schema TargetSchema) error {
	for _, selector := range rule.Target.Attributes {
		switch {
		case selector == "*" || selector == "+":
			continue
		case strings.HasPrefix(selector, "@") ||
			strings.HasPrefix(selector, "!") ||
			(strings.HasPrefix(selector, "+") && len(selector) > 1):
			_, known := schema.ObjectClassAllowsAttribute(selector[1:], "objectClass")
			if !known {
				return fmt.Errorf("unknown object class %q", selector[1:])
			}
		case strings.HasPrefix(selector, "-"):
			continue
		default:
			// OpenLDAP can expose dynamically registered and proxied undefined
			// attributes (for example cmusaslsecretDIGEST-MD5). Exact names
			// remain safe to accept even when absent from the static registry.
			continue
		}
	}
	if rule.Target.Value != nil {
		attribute := rule.Target.Attributes[0]
		selector := *rule.Target.Value
		if selector.Style != DNExact && selector.Style != DNRegex &&
			!schema.IsDNValued(attribute) {
			return fmt.Errorf("value style requires DN-syntax attribute %q", attribute)
		}
		if selector.Style == DNExact && schema.IsDNValued(attribute) {
			if _, err := directory.ParseDN(string(selector.Assertion)); err != nil {
				return fmt.Errorf("invalid DN value for attribute %q: %w", attribute, err)
			}
		} else if selector.Style != DNRegex {
			if _, err := schema.Compare(
				attribute,
				selector.MatchingRule,
				selector.Assertion,
				selector.Assertion,
			); err != nil {
				return fmt.Errorf("invalid value selector for attribute %q: %w", attribute, err)
			}
		}
	}
	for _, clause := range rule.By {
		for _, matcher := range clause.Who {
			switch matcher.Kind {
			case WhoDNAttribute:
				if !schema.IsDNReferenceValued(matcher.Attribute) {
					return fmt.Errorf(
						"DN attribute %q does not use DN or NameAndOptionalUID syntax",
						matcher.Attribute,
					)
				}
			case WhoGroup:
				_, known := schema.ObjectClassAllowsAttribute(
					matcher.GroupObjectClass,
					"objectClass",
				)
				if !known {
					return fmt.Errorf("unknown group object class %q", matcher.GroupObjectClass)
				}
				static := schema.IsDNReferenceValued(matcher.GroupAttribute)
				dynamic := schema.AttributeDescriptionSubtype(
					matcher.GroupAttribute,
					"labeledURI",
				)
				if !static && !dynamic {
					return fmt.Errorf(
						"group attribute %q must use DN, NameAndOptionalUID, or labeledURI syntax",
						matcher.GroupAttribute,
					)
				}
				allowed, _ := schema.ObjectClassAllowsAttribute(
					matcher.GroupObjectClass,
					matcher.GroupAttribute,
				)
				if !allowed {
					return fmt.Errorf(
						"group attribute %q is not allowed by object class %q",
						matcher.GroupAttribute,
						matcher.GroupObjectClass,
					)
				}
			case WhoACI:
				if !schema.IsACIValued(matcher.ACIAttribute) {
					return fmt.Errorf(
						"ACI attribute %q does not use OpenLDAP ACI syntax",
						matcher.ACIAttribute,
					)
				}
			}
		}
	}
	return nil
}

func (policy *Policy) Allowed(
	subject Subject,
	target Target,
	required Privilege,
	reader EntryReader,
) bool {
	targetDN, err := parseACLDN(target.Entry.DN, target.DNNormalizer)
	if err != nil {
		return false
	}
	rules := policy.rulesFor(targetDN, target.DNNormalizer)
	if len(rules) == 0 {
		return defaultPrivileges(targetDN)&required == required
	}

	var privileges Privilege
	for _, rule := range rules {
		matched, context := matchTarget(rule.Target, target, targetDN)
		if !matched {
			continue
		}
		breakRule := false
		for _, clause := range rule.By {
			match := matchesWho(
				clause.Who,
				clause.Grant,
				subject,
				target,
				targetDN,
				reader,
				context,
			)
			if !match.matched {
				continue
			}
			if match.dynamic {
				if clause.Grant.Privileges&required != required {
					continue
				}
				grant := match.grant & clause.Grant.Privileges
				switch {
				case match.deny == 0:
					privileges |= grant
				case grant == 0:
					privileges &^= match.deny
				default:
					privileges |= grant &^ match.deny
				}
			} else {
				privileges = applyGrant(privileges, clause.Grant)
			}
			switch clause.Control {
			case ControlStop:
				return privileges&required == required
			case ControlContinue:
				continue
			case ControlBreak:
				breakRule = true
			}
			break
		}
		if breakRule {
			continue
		}
		// Every matching access rule has an implicit "by * none stop".
		return false
	}
	// A non-empty ACL list has an implicit final "to * by * none".
	return false
}

func defaultPrivileges(target directory.DN) Privilege {
	if configSuffix.Equal(target) || configSuffix.AncestorOf(target) {
		return NoneLevel
	}
	return ReadLevel
}

func (policy *Policy) rulesFor(
	target directory.DN,
	normalizer directory.DNAttributeNormalizer,
) []Rule {
	var database []Rule
	for _, candidate := range policy.databases {
		suffix, err := normalizeACLDN(candidate.Suffix, normalizer)
		if err == nil && (suffix.Equal(target) || suffix.AncestorOf(target)) {
			database = candidate.Rules
			break
		}
	}
	result := make([]Rule, 0, len(database)+len(policy.global))
	result = append(result, database...)
	result = append(result, policy.global...)
	return result
}

func (policy *Policy) RequiresAddContentACL(target directory.DN) bool {
	for _, database := range policy.databases {
		if database.Suffix.Equal(target) || database.Suffix.AncestorOf(target) {
			return database.AddContentACL
		}
	}
	return false
}

func matchesTarget(selector TargetSelector, target Target, targetDN directory.DN) bool {
	matched, _ := matchTarget(selector, target, targetDN)
	return matched
}

func matchTarget(
	selector TargetSelector,
	target Target,
	targetDN directory.DN,
) (bool, matchContext) {
	dnMatches, matched := targetDNMatches(selector.DN, targetDN, target.DNNormalizer)
	if !matched {
		return false, matchContext{}
	}
	if len(selector.Attributes) > 0 && !matchesTargetAttribute(selector.Attributes, target) {
		return false, matchContext{}
	}
	var valueMatches []string
	if selector.Value != nil {
		var valueMatched bool
		valueMatched, valueMatches = matchTargetValue(*selector.Value, target)
		if !valueMatched {
			return false, matchContext{}
		}
	}
	if selector.Filter != nil {
		matcher := directory.ValueMatcher(directory.BasicMatcher{})
		if target.Schema != nil {
			matcher = target.Schema
		}
		matches, err := selector.Filter.MatchWith(target.Entry, matcher)
		if err != nil || !matches {
			return false, matchContext{}
		}
	}
	return true, matchContext{dn: dnMatches, value: valueMatches}
}

func targetDNMatches(
	matcher DNMatcher,
	candidate directory.DN,
	normalizer directory.DNAttributeNormalizer,
) ([]string, bool) {
	if matcher.Style == DNRegex {
		if matcher.Pattern == nil {
			return nil, false
		}
		candidateText := candidate.Key()
		if normalizer != nil {
			candidateText = candidate.NormalizedString()
		}
		matches := matcher.Pattern.FindStringSubmatch(candidateText)
		return matches, matches != nil
	}
	var err error
	matcher.DN, err = normalizeACLDN(matcher.DN, normalizer)
	if err != nil {
		return nil, false
	}
	if !matchesDN(matcher, candidate) {
		return nil, false
	}
	candidateText := candidate.Key()
	matcherText := matcher.DN.Key()
	if normalizer != nil {
		candidateText = candidate.NormalizedString()
		matcherText = matcher.DN.NormalizedString()
	}
	matches := []string{candidateText}
	switch matcher.Style {
	case DNOne, DNSubtree, DNChildren:
		matches = append(matches, matcherText)
	}
	return matches, true
}

func matchesTargetAttribute(attributes []string, target Target) bool {
	for _, selector := range attributes {
		switch {
		case selector == "*":
			if target.Schema == nil || !target.Schema.IsOperational(target.Attribute) {
				return true
			}
		case selector == "+":
			if target.Schema != nil && target.Schema.IsOperational(target.Attribute) {
				return true
			}
		case strings.HasPrefix(selector, "-"):
			if strings.EqualFold(selector[1:], target.Attribute) {
				return true
			}
		case strings.HasPrefix(selector, "@") ||
			(strings.HasPrefix(selector, "+") && len(selector) > 1):
			if target.Schema == nil {
				continue
			}
			allowed, known := target.Schema.ObjectClassAllowsAttribute(
				selector[1:],
				target.Attribute,
			)
			if known && allowed {
				return true
			}
		case strings.HasPrefix(selector, "!"):
			if target.Schema == nil {
				continue
			}
			allowed, known := target.Schema.ObjectClassAllowsAttribute(
				selector[1:],
				target.Attribute,
			)
			if known && !allowed {
				return true
			}
		default:
			if target.Schema != nil {
				if target.Schema.AttributeDescriptionSubtype(target.Attribute, selector) {
					return true
				}
				if !target.Schema.HasAttributeType(selector) {
					allowed, known := target.Schema.ObjectClassAllowsAttribute(
						selector,
						target.Attribute,
					)
					if known && allowed {
						return true
					}
				}
				continue
			}
			if strings.EqualFold(selector, target.Attribute) {
				return true
			}
		}
	}
	return false
}

func matchesTargetValue(selector ValueSelector, target Target) bool {
	matched, _ := matchTargetValue(selector, target)
	return matched
}

func matchTargetValue(selector ValueSelector, target Target) (bool, []string) {
	if target.Value == nil {
		return false, nil
	}
	candidateValue := target.Value
	if target.Schema != nil {
		normalized, err := target.Schema.NormalizeEqualityValue(
			target.Attribute,
			target.Value,
		)
		if err != nil {
			return false, nil
		}
		candidateValue = normalized
	}
	if selector.Style == DNRegex {
		if selector.Pattern == nil {
			return false, nil
		}
		captures := selector.Pattern.FindSubmatch(candidateValue)
		if captures == nil {
			return false, nil
		}
		matches := make([]string, len(captures))
		for index := range captures {
			matches[index] = string(captures[index])
		}
		return true, matches
	}
	dnValued := target.DNValued
	if target.Schema != nil {
		dnValued = target.Schema.IsDNValued(target.Attribute)
	}
	if dnValued {
		candidate, candidateErr := parseACLDN(
			string(candidateValue),
			target.DNNormalizer,
		)
		assertion, assertionErr := parseACLDN(
			string(selector.Assertion),
			target.DNNormalizer,
		)
		if candidateErr != nil || assertionErr != nil {
			return false, nil
		}
		return matchesDN(DNMatcher{Style: selector.Style, DN: assertion}, candidate), nil
	}
	if selector.Style != DNExact {
		return false, nil
	}
	matcher := directory.ValueMatcher(directory.BasicMatcher{})
	if target.Schema != nil {
		matcher = target.Schema
	}
	comparison, err := matcher.Compare(
		target.Attribute,
		selector.MatchingRule,
		candidateValue,
		selector.Assertion,
	)
	return err == nil && comparison == 0, nil
}

type whoMatchResult struct {
	matched bool
	dynamic bool
	grant   Privilege
	deny    Privilege
}

func matchesWho(
	matchers []WhoMatcher,
	grant Grant,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) whoMatchResult {
	result := whoMatchResult{matched: true}
	for _, matcher := range matchers {
		if matcher.Kind == WhoACI {
			result.dynamic = true
			grant, deny := evaluateACIMatcher(
				matcher,
				subject,
				target,
				targetDN,
				reader,
				context,
			)
			result.grant |= grant
			result.deny |= deny
			continue
		}
		if !matchesOneWho(matcher, subject, target, targetDN, reader, context) {
			return whoMatchResult{}
		}
	}
	if grant.SelfValue {
		if !targetIsDNValued(target) ||
			!valueIsSubjectDN(target.Value, subject.DN, target.DNNormalizer) {
			return whoMatchResult{}
		}
	}
	if grant.RealSelfValue {
		if !targetIsDNValued(target) ||
			!valueIsSubjectDN(
				target.Value,
				realSubjectDN(subject),
				target.DNNormalizer,
			) {
			return whoMatchResult{}
		}
	}
	if result.dynamic && result.grant == 0 && result.deny == 0 {
		return whoMatchResult{}
	}
	return result
}

func matchesOneWho(
	matcher WhoMatcher,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) bool {
	subjectDN := subject.DN
	if matcher.Real {
		subjectDN = realSubjectDN(subject)
	}
	switch matcher.Kind {
	case WhoAny:
		return true
	case WhoAnonymous:
		return subjectDN == ""
	case WhoUsers:
		return subjectDN != ""
	case WhoSelf:
		return matchesSelfLevel(
			subjectDN,
			targetDN,
			matcher.SelfLevel,
			target.DNNormalizer,
		)
	case WhoDN:
		parsedSubject, err := parseACLDN(subjectDN, target.DNNormalizer)
		return err == nil && matchesExpandedACLDN(
			matcher.DN,
			parsedSubject,
			context,
			target.DNNormalizer,
		)
	case WhoDNAttribute:
		return entryContainsDNWithNormalizer(
			target.Entry,
			matcher.Attribute,
			subjectDN,
			target.Schema,
			target.DNNormalizer,
		)
	case WhoGroup:
		if target.DNNormalizer != nil {
			return matchesSchemaAwareGroup(
				matcher,
				subjectDN,
				target,
				reader,
				context,
			)
		}
		return matchesGroup(matcher, subjectDN, target, reader, context)
	case WhoPeerName:
		return matchesStringMatcher(matcher.Connection, subject.PeerName, context)
	case WhoSockName:
		return matchesStringMatcher(matcher.Connection, subject.SockName, context)
	case WhoDomain:
		return matchesStringMatcher(matcher.Connection, subject.Domain, context)
	case WhoSockURL:
		return matchesStringMatcher(matcher.Connection, subject.SockURL, context)
	case WhoSet:
		if target.DNNormalizer != nil {
			return matchesSchemaAwareSet(
				matcher,
				subjectDN,
				target,
				targetDN,
				reader,
				context,
			)
		}
		return matchesSet(matcher, subjectDN, target, targetDN, reader, context)
	case WhoSSF:
		strength := subject.SSF
		switch matcher.SSFKind {
		case SSFTransport:
			strength = subject.TransportSSF
		case SSFTLS:
			strength = subject.TLSSSF
		case SSFSASL:
			strength = subject.SASLSSF
		}
		return strength >= matcher.MinimumSSF
	default:
		return false
	}
}

func realSubjectDN(subject Subject) string {
	if subject.RealDN != "" {
		return subject.RealDN
	}
	return subject.DN
}

func parseACLDN(
	raw string,
	normalizer directory.DNAttributeNormalizer,
) (directory.DN, error) {
	if normalizer != nil {
		return directory.ParseDNWithNormalizer(raw, normalizer)
	}
	return directory.ParseDN(raw)
}

func normalizeACLDN(
	dn directory.DN,
	normalizer directory.DNAttributeNormalizer,
) (directory.DN, error) {
	if normalizer == nil {
		return dn, nil
	}
	return directory.ParseDNWithNormalizer(dn.String(), normalizer)
}

func targetIsDNValued(target Target) bool {
	if target.Schema != nil {
		return target.Schema.IsDNValued(target.Attribute)
	}
	return target.DNValued
}

func matchesExpandedACLDN(
	matcher DNMatcher,
	candidate directory.DN,
	context matchContext,
	normalizer directory.DNAttributeNormalizer,
) bool {
	if normalizer == nil {
		return matchesExpandedDN(matcher, candidate, context)
	}
	if matcher.Style == DNRegex {
		pattern := matcher.Raw
		if pattern == "" && matcher.Pattern != nil {
			return matcher.Pattern.MatchString(candidate.NormalizedString())
		}
		expanded, ok := expandACLPattern(pattern, context)
		if !ok {
			return false
		}
		compiled, err := compileACLRegex(expanded)
		return err == nil && compiled.MatchString(candidate.NormalizedString())
	}
	if matcher.Expand {
		expanded, ok := expandACLPattern(matcher.Raw, context)
		if !ok {
			return false
		}
		var err error
		matcher.DN, err = parseACLDN(expanded, normalizer)
		if err != nil {
			return false
		}
	} else {
		var err error
		matcher.DN, err = normalizeACLDN(matcher.DN, normalizer)
		if err != nil {
			return false
		}
	}
	return matchesDN(matcher, candidate)
}

func compileACLRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}

func matchesSchemaAwareGroup(
	matcher WhoMatcher,
	rawSubjectDN string,
	target Target,
	reader EntryReader,
	context matchContext,
) bool {
	if rawSubjectDN == "" || reader == nil || target.DNNormalizer == nil {
		return false
	}
	groupText := matcher.DN.DN.String()
	if matcher.GroupExpand {
		var ok bool
		groupText, ok = expandACLPattern(matcher.GroupPattern, context)
		if !ok {
			return false
		}
	}
	groupDN, err := parseACLDN(groupText, target.DNNormalizer)
	if err != nil {
		return false
	}
	group, err := reader.Get(groupDN)
	if err != nil {
		return false
	}
	if target.Schema != nil {
		if !target.Schema.EntryHasObjectClass(group, matcher.GroupObjectClass) {
			return false
		}
	} else if !group.HasValue("objectClass", []byte(matcher.GroupObjectClass)) {
		return false
	}
	if target.Schema != nil && target.Schema.AttributeDescriptionSubtype(
		matcher.GroupAttribute,
		"labeledURI",
	) {
		return schemaAwareDynamicGroupContainsSubject(
			group,
			matcher.GroupAttribute,
			rawSubjectDN,
			target,
			reader,
		)
	}
	return entryContainsDNWithNormalizer(
		group,
		matcher.GroupAttribute,
		rawSubjectDN,
		target.Schema,
		target.DNNormalizer,
	)
}

func schemaAwareDynamicGroupContainsSubject(
	group directory.Entry,
	attribute,
	rawSubjectDN string,
	target Target,
	reader EntryReader,
) bool {
	subjectDN, err := parseACLDN(rawSubjectDN, target.DNNormalizer)
	if err != nil {
		return false
	}
	values := group.Values(attribute)
	if target.Schema != nil {
		values = target.Schema.AttributeValues(group, attribute)
	}
	for _, value := range values {
		parsed, ok := parseACLDynamicGroupURL(string(value))
		if !ok {
			continue
		}
		base, err := normalizeACLDN(parsed.base, target.DNNormalizer)
		if err != nil || !directory.InScope(base, subjectDN, parsed.scope) {
			continue
		}
		if !parsed.filterSet {
			return true
		}
		subjectEntry := target.Entry
		targetDN, targetErr := parseACLDN(target.Entry.DN, target.DNNormalizer)
		if targetErr != nil || !targetDN.Equal(subjectDN) {
			subjectEntry, err = reader.Get(subjectDN)
			if err != nil {
				continue
			}
		}
		valueMatcher := directory.ValueMatcher(directory.BasicMatcher{})
		if target.Schema != nil {
			valueMatcher = target.Schema
		}
		matches, filterErr := parsed.filter.MatchWith(subjectEntry, valueMatcher)
		if filterErr == nil && matches {
			return true
		}
	}
	return false
}

type schemaACLSetValue struct {
	text string
	dn   directory.DN
	isDN bool
}

type schemaACLSet map[string]schemaACLSetValue

func (value schemaACLSetValue) key() string {
	if value.isDN {
		return "dn\x00" + value.dn.Key()
	}
	return "text\x00" + value.text
}

func schemaACLValue(
	raw string,
	normalizer directory.DNAttributeNormalizer,
) schemaACLSetValue {
	dn, err := parseACLDN(raw, normalizer)
	if err != nil {
		return schemaACLSetValue{text: raw}
	}
	return schemaACLSetValue{text: dn.NormalizedString(), dn: dn, isDN: true}
}

func singletonSchemaACLSet(value schemaACLSetValue) schemaACLSet {
	return schemaACLSet{value.key(): value}
}

func matchesSchemaAwareSet(
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
	values, err := evaluateSchemaACLSet(
		expression,
		schemaACLSetContext{
			subjectDN: subjectDN,
			target:    target,
			targetDN:  targetDN,
			reader:    reader,
		},
	)
	return err == nil && len(values) > 0
}

type schemaACLSetContext struct {
	subjectDN string
	target    Target
	targetDN  directory.DN
	reader    EntryReader
}

func evaluateSchemaACLSet(
	expression *setExpression,
	context schemaACLSetContext,
) (schemaACLSet, error) {
	if expression == nil {
		return nil, errors.New("nil set expression")
	}
	switch expression.kind {
	case setLiteral:
		return singletonSchemaACLSet(
			schemaACLValue(expression.value, context.target.DNNormalizer),
		), nil
	case setUser:
		value := schemaACLValue(context.subjectDN, context.target.DNNormalizer)
		if !value.isDN {
			return schemaACLSet{}, nil
		}
		return singletonSchemaACLSet(value), nil
	case setThis:
		return singletonSchemaACLSet(schemaACLSetValue{
			text: context.targetDN.NormalizedString(),
			dn:   context.targetDN,
			isDN: true,
		}), nil
	case setUnion, setIntersection, setConcat:
		left, err := evaluateSchemaACLSet(expression.left, context)
		if err != nil {
			return nil, err
		}
		right, err := evaluateSchemaACLSet(expression.right, context)
		if err != nil {
			return nil, err
		}
		return joinSchemaACLSets(left, right, expression.kind, context.target.DNNormalizer)
	case setChase:
		values, err := evaluateSchemaACLSet(expression.left, context)
		if err != nil {
			return nil, err
		}
		return chaseSchemaACLSet(values, expression.value, expression.closure, context)
	case setParents:
		values, err := evaluateSchemaACLSet(expression.left, context)
		if err != nil {
			return nil, err
		}
		return parentSchemaACLSet(values, expression.level, expression.allParent), nil
	default:
		return nil, errors.New("unknown set expression")
	}
}

func joinSchemaACLSets(
	left,
	right schemaACLSet,
	kind setExpressionKind,
	normalizer directory.DNAttributeNormalizer,
) (schemaACLSet, error) {
	result := make(schemaACLSet)
	switch kind {
	case setUnion:
		for key, value := range left {
			result[key] = value
		}
		for key, value := range right {
			result[key] = value
		}
	case setIntersection:
		for key, value := range left {
			if _, exists := right[key]; exists {
				result[key] = value
			}
		}
	case setConcat:
		if len(left) > 0 && len(right) > maxACLSetValues/len(left) {
			return nil, errors.New("set expression result is too large")
		}
		for _, leftValue := range left {
			for _, rightValue := range right {
				value := schemaACLValue(leftValue.text+rightValue.text, normalizer)
				result[value.key()] = value
			}
		}
	}
	if len(result) > maxACLSetValues {
		return nil, errors.New("set expression result is too large")
	}
	return result, nil
}

func chaseSchemaACLSet(
	values schemaACLSet,
	attribute string,
	closure bool,
	context schemaACLSetContext,
) (schemaACLSet, error) {
	result := make(schemaACLSet)
	queue := make([]schemaACLSetValue, 0, len(values))
	for _, value := range values {
		queue = append(queue, value)
	}
	initial := len(queue)
	for position := 0; position < len(queue); position++ {
		gathered := gatherSchemaACLSetValue(queue[position], attribute, context)
		for key, value := range gathered {
			if _, exists := result[key]; exists {
				continue
			}
			if len(result) >= maxACLSetValues {
				return nil, errors.New("set chase result is too large")
			}
			result[key] = value
			if closure {
				queue = append(queue, value)
			}
		}
		if !closure && position+1 == initial {
			break
		}
	}
	return result, nil
}

func gatherSchemaACLSetValue(
	value schemaACLSetValue,
	attribute string,
	context schemaACLSetContext,
) schemaACLSet {
	if strings.HasPrefix(strings.ToLower(value.text), "ldap:///") {
		return gatherSchemaACLSetURL(value.text, attribute, context)
	}
	if !value.isDN || context.reader == nil {
		return schemaACLSet{}
	}
	if strings.EqualFold(attribute, "entryDN") {
		return singletonSchemaACLSet(value)
	}
	entry := context.target.Entry
	if !value.dn.Equal(context.targetDN) {
		var err error
		entry, err = context.reader.Get(value.dn)
		if err != nil {
			return schemaACLSet{}
		}
	}
	return schemaACLAttributeValues(entry, attribute, context.target)
}

func schemaACLAttributeValues(
	entry directory.Entry,
	attribute string,
	target Target,
) schemaACLSet {
	values := entry.Values(attribute)
	if target.Schema != nil {
		values = target.Schema.AttributeValues(entry, attribute)
	}
	result := make(schemaACLSet)
	for _, raw := range values {
		value := schemaACLValue(string(raw), target.DNNormalizer)
		if !value.isDN && target.Schema != nil {
			normalized, err := target.Schema.NormalizeEqualityValue(attribute, raw)
			if err != nil {
				continue
			}
			value = schemaACLValue(string(normalized), target.DNNormalizer)
		}
		result[value.key()] = value
	}
	return result
}

func parentSchemaACLSet(values schemaACLSet, level int, all bool) schemaACLSet {
	result := make(schemaACLSet)
	for _, value := range values {
		if !value.isDN {
			continue
		}
		dn := value.dn
		if all {
			for {
				candidate := schemaACLSetValue{
					text: dn.NormalizedString(),
					dn:   dn,
					isDN: true,
				}
				result[candidate.key()] = candidate
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
			candidate := schemaACLSetValue{
				text: ancestor.NormalizedString(),
				dn:   ancestor,
				isDN: true,
			}
			result[candidate.key()] = candidate
		}
	}
	return result
}

func gatherSchemaACLSetURL(
	raw,
	chaseAttribute string,
	context schemaACLSetContext,
) schemaACLSet {
	scanner, ok := context.reader.(interface {
		ForEach(func(directory.Entry) error) error
	})
	if !ok {
		return schemaACLSet{}
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "ldap") || parsed.Host != "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return schemaACLSet{}
	}
	baseText, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil {
		return schemaACLSet{}
	}
	base, err := parseACLDN(baseText, context.target.DNNormalizer)
	if err != nil {
		return schemaACLSet{}
	}
	components := strings.Split(parsed.RawQuery, "?")
	for len(components) < 4 {
		components = append(components, "")
	}
	if len(components) > 4 || components[3] != "" {
		return schemaACLSet{}
	}
	attributesText, err := url.PathUnescape(components[0])
	if err != nil {
		return schemaACLSet{}
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
		return schemaACLSet{}
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
		return schemaACLSet{}
	}
	filterText, err := url.PathUnescape(components[2])
	if err != nil {
		return schemaACLSet{}
	}
	filter := directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"}
	if filterText != "" {
		filter, err = ldapwire.CompileFilter(filterText)
		if err != nil {
			return schemaACLSet{}
		}
	}
	valueMatcher := directory.ValueMatcher(directory.BasicMatcher{})
	if context.target.Schema != nil {
		valueMatcher = context.target.Schema
	}
	result := make(schemaACLSet)
	_ = scanner.ForEach(func(entry directory.Entry) error {
		dn, parseErr := parseACLDN(entry.DN, context.target.DNNormalizer)
		if parseErr != nil || !directory.InScope(base, dn, scope) {
			return nil
		}
		matches, matchErr := filter.MatchWith(entry, valueMatcher)
		if matchErr != nil || !matches {
			return nil
		}
		for _, attribute := range attributes {
			if strings.EqualFold(attribute, "entryDN") {
				value := schemaACLSetValue{
					text: dn.NormalizedString(),
					dn:   dn,
					isDN: true,
				}
				result[value.key()] = value
				continue
			}
			for key, value := range schemaACLAttributeValues(entry, attribute, context.target) {
				result[key] = value
			}
		}
		return nil
	})
	return result
}

func entryContainsDN(
	entry directory.Entry,
	attribute,
	rawDN string,
	schema TargetSchema,
) bool {
	return entryContainsDNWithNormalizer(entry, attribute, rawDN, schema, nil)
}

func entryContainsDNWithNormalizer(
	entry directory.Entry,
	attribute,
	rawDN string,
	schema TargetSchema,
	normalizer directory.DNAttributeNormalizer,
) bool {
	if rawDN == "" {
		return false
	}
	subjectDN, err := parseACLDN(rawDN, normalizer)
	if err != nil {
		return false
	}
	values := entry.Values(attribute)
	if schema != nil {
		values = schema.AttributeValues(entry, attribute)
	}
	for _, value := range values {
		candidate, candidateErr := parseACLDN(string(value), normalizer)
		if candidateErr == nil {
			if candidate.Equal(subjectDN) {
				return true
			}
			continue
		}
		if schema != nil {
			comparison, compareErr := schema.Compare(
				attribute,
				"",
				value,
				[]byte(rawDN),
			)
			if compareErr == nil && comparison == 0 {
				return true
			}
		}
	}
	return false
}

func valueIsSubjectDN(
	value []byte,
	rawSubject string,
	normalizer directory.DNAttributeNormalizer,
) bool {
	if len(value) == 0 || rawSubject == "" {
		return false
	}
	valueDN, valueErr := parseACLDN(string(value), normalizer)
	subjectDN, subjectErr := parseACLDN(rawSubject, normalizer)
	return valueErr == nil && subjectErr == nil && valueDN.Equal(subjectDN)
}

func equalRawDN(raw string, target directory.DN) bool {
	if raw == "" {
		return false
	}
	subject, err := directory.ParseDN(raw)
	return err == nil && subject.Equal(target)
}

func matchesSelfLevel(
	rawSubject string,
	target directory.DN,
	level int,
	normalizer directory.DNAttributeNormalizer,
) bool {
	if rawSubject == "" {
		return false
	}
	subject, err := parseACLDN(rawSubject, normalizer)
	if err != nil {
		return false
	}
	if level < 0 {
		ancestor, ok := dnAncestor(target, -level)
		return ok && subject.Equal(ancestor)
	}
	ancestor, ok := dnAncestor(subject, level)
	return ok && ancestor.Equal(target)
}

func dnAncestor(dn directory.DN, level int) (directory.DN, bool) {
	for ; level > 0; level-- {
		parent, ok := dn.Parent()
		if !ok || parent.Depth() == 0 {
			return directory.DN{}, false
		}
		dn = parent
	}
	return dn, dn.Depth() > 0
}

func matchesDN(matcher DNMatcher, candidate directory.DN) bool {
	switch matcher.Style {
	case DNAny:
		return true
	case DNExact:
		return matcher.DN.Equal(candidate)
	case DNOne:
		return matcher.DN.AncestorOf(candidate) &&
			candidate.Depth() == matcher.DN.Depth()+1
	case DNSubtree:
		return matcher.DN.Equal(candidate) || matcher.DN.AncestorOf(candidate)
	case DNChildren:
		return matcher.DN.AncestorOf(candidate)
	case DNLevel:
		ancestor, ok := dnAncestor(candidate, matcher.Level)
		return ok && matcher.DN.Equal(ancestor)
	case DNRegex:
		return matcher.Pattern != nil && matcher.Pattern.MatchString(candidate.Key())
	default:
		return false
	}
}

func applyGrant(current Privilege, grant Grant) Privilege {
	switch grant.Mode {
	case grantSet:
		return grant.Privileges
	case grantAdd:
		return current | grant.Privileges
	case grantRemove:
		return current &^ grant.Privileges
	case grantIdentity:
		return current
	default:
		return 0
	}
}

func sortDatabases(databases []databaseRules) {
	for i := 1; i < len(databases); i++ {
		for j := i; j > 0 && databases[j].Suffix.Depth() > databases[j-1].Suffix.Depth(); j-- {
			databases[j], databases[j-1] = databases[j-1], databases[j]
		}
	}
}

func staticDN(value string) directory.DN {
	dn, err := directory.ParseDN(value)
	if err != nil {
		panic(err)
	}
	return dn
}
