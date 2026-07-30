package acl

import (
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
		if !matchesTarget(rule.Target, target, targetDN) {
			continue
		}
		breakRule := false
		for _, clause := range rule.By {
			if !matchesWho(clause.Who, clause.Grant, subject, target, targetDN, reader) {
				continue
			}
			privileges = applyGrant(privileges, clause.Grant)
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
	if !matchesDN(selector.DN, targetDN) {
		return false
	}
	if len(selector.Attributes) == 0 {
		return true
	}
	for _, attribute := range selector.Attributes {
		if strings.EqualFold(attribute, target.Attribute) {
			return true
		}
	}
	return false
}

func matchesWho(
	matchers []WhoMatcher,
	grant Grant,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
) bool {
	for _, matcher := range matchers {
		if !matchesOneWho(matcher, subject, target, targetDN, reader) {
			return false
		}
	}
	if grant.SelfValue {
		if !target.DNValued || !valueIsSubjectDN(target.Value, subject.DN) {
			return false
		}
	}
	return true
}

func matchesOneWho(
	matcher WhoMatcher,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
) bool {
	switch matcher.Kind {
	case WhoAny:
		return true
	case WhoAnonymous:
		return subject.DN == ""
	case WhoUsers:
		return subject.DN != ""
	case WhoSelf:
		return equalRawDN(subject.DN, targetDN)
	case WhoDN:
		subjectDN, err := directory.ParseDN(subject.DN)
		return err == nil && matchesDN(matcher.DN, subjectDN)
	case WhoDNAttribute:
		return entryContainsDN(target.Entry, matcher.Attribute, subject.DN)
	case WhoGroup:
		return matchesGroup(matcher, subject.DN, reader)
	case WhoSSF:
		return subject.SSF >= matcher.MinimumSSF
	default:
		return false
	}
}

func matchesGroup(matcher WhoMatcher, subjectDN string, reader EntryReader) bool {
	if subjectDN == "" || reader == nil {
		return false
	}
	group, err := reader.Get(matcher.DN.DN)
	if err != nil {
		return false
	}
	if !group.HasValue("objectClass", []byte(matcher.GroupObjectClass)) {
		return false
	}
	return entryContainsDN(group, matcher.GroupAttribute, subjectDN)
}

func entryContainsDN(entry directory.Entry, attribute, rawDN string) bool {
	if rawDN == "" {
		return false
	}
	subjectDN, err := directory.ParseDN(rawDN)
	if err != nil {
		return false
	}
	for _, value := range entry.Values(attribute) {
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
