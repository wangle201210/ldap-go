package acl

import (
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
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
	targetDN, err := directory.ParseDN(target.Entry.DN)
	if err != nil {
		return false
	}
	rules := policy.rulesFor(targetDN)
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

func (policy *Policy) rulesFor(target directory.DN) []Rule {
	var database []Rule
	for _, candidate := range policy.databases {
		if candidate.Suffix.Equal(target) || candidate.Suffix.AncestorOf(target) {
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
	dnMatches, matched := targetDNMatches(selector.DN, targetDN)
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

func targetDNMatches(matcher DNMatcher, candidate directory.DN) ([]string, bool) {
	if matcher.Style == DNRegex {
		if matcher.Pattern == nil {
			return nil, false
		}
		matches := matcher.Pattern.FindStringSubmatch(candidate.Key())
		return matches, matches != nil
	}
	if !matchesDN(matcher, candidate) {
		return nil, false
	}
	matches := []string{candidate.Key()}
	switch matcher.Style {
	case DNOne, DNSubtree, DNChildren:
		matches = append(matches, matcher.DN.Key())
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
		candidate, candidateErr := directory.ParseDN(string(candidateValue))
		assertion, assertionErr := directory.ParseDN(string(selector.Assertion))
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
		if !target.DNValued || !valueIsSubjectDN(target.Value, subject.DN) {
			return whoMatchResult{}
		}
	}
	if grant.RealSelfValue {
		if !target.DNValued || !valueIsSubjectDN(target.Value, realSubjectDN(subject)) {
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
		return matchesSelfLevel(subjectDN, targetDN, matcher.SelfLevel)
	case WhoDN:
		parsedSubject, err := directory.ParseDN(subjectDN)
		return err == nil && matchesExpandedDN(matcher.DN, parsedSubject, context)
	case WhoDNAttribute:
		return entryContainsDN(target.Entry, matcher.Attribute, subjectDN, target.Schema)
	case WhoGroup:
		return matchesGroup(matcher, subject.DN, target, reader, context)
	case WhoPeerName:
		return matchesStringMatcher(matcher.Connection, subject.PeerName, context)
	case WhoSockName:
		return matchesStringMatcher(matcher.Connection, subject.SockName, context)
	case WhoDomain:
		return matchesStringMatcher(matcher.Connection, subject.Domain, context)
	case WhoSockURL:
		return matchesStringMatcher(matcher.Connection, subject.SockURL, context)
	case WhoSet:
		return matchesSet(matcher, subject.DN, target, targetDN, reader, context)
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

func entryContainsDN(
	entry directory.Entry,
	attribute,
	rawDN string,
	schema TargetSchema,
) bool {
	if rawDN == "" {
		return false
	}
	subjectDN, err := directory.ParseDN(rawDN)
	if err != nil {
		return false
	}
	values := entry.Values(attribute)
	if schema != nil {
		values = schema.AttributeValues(entry, attribute)
	}
	for _, value := range values {
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
		candidate, err := directory.ParseDN(string(value))
		if err == nil && candidate.Equal(subjectDN) {
			return true
		}
	}
	return false
}

func valueIsSubjectDN(value []byte, rawSubject string) bool {
	if len(value) == 0 || rawSubject == "" {
		return false
	}
	valueDN, valueErr := directory.ParseDN(string(value))
	subjectDN, subjectErr := directory.ParseDN(rawSubject)
	return valueErr == nil && subjectErr == nil && valueDN.Equal(subjectDN)
}

func equalRawDN(raw string, target directory.DN) bool {
	if raw == "" {
		return false
	}
	subject, err := directory.ParseDN(raw)
	return err == nil && subject.Equal(target)
}

func matchesSelfLevel(rawSubject string, target directory.DN, level int) bool {
	if rawSubject == "" {
		return false
	}
	subject, err := directory.ParseDN(rawSubject)
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
