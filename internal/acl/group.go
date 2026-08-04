package acl

import (
	"net/url"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type aclDynamicGroupURL struct {
	base      directory.DN
	scope     directory.Scope
	filter    directory.Filter
	filterSet bool
}

func matchesGroup(
	matcher WhoMatcher,
	subjectDN string,
	target Target,
	reader EntryReader,
	context matchContext,
) bool {
	if subjectDN == "" || reader == nil {
		return false
	}
	groupDN := matcher.DN.DN
	if matcher.GroupExpand {
		expanded, ok := expandACLPattern(matcher.GroupPattern, context)
		if !ok {
			return false
		}
		var err error
		groupDN, err = directory.ParseDN(expanded)
		if err != nil {
			return false
		}
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
		return dynamicGroupContainsSubject(
			group,
			matcher.GroupAttribute,
			subjectDN,
			target,
			reader,
		)
	}
	return entryContainsDN(group, matcher.GroupAttribute, subjectDN, target.Schema)
}

func dynamicGroupContainsSubject(
	group directory.Entry,
	attribute,
	rawSubjectDN string,
	target Target,
	reader EntryReader,
) bool {
	subjectDN, err := directory.ParseDN(rawSubjectDN)
	if err != nil {
		return false
	}
	values := group.Values(attribute)
	if target.Schema != nil {
		values = target.Schema.AttributeValues(group, attribute)
	}
	for _, value := range values {
		parsed, ok := parseACLDynamicGroupURL(string(value))
		if !ok || !directory.InScope(parsed.base, subjectDN, parsed.scope) {
			continue
		}
		if !parsed.filterSet {
			return true
		}
		subject := target.Entry
		targetDN, targetErr := directory.ParseDN(target.Entry.DN)
		if targetErr != nil || !targetDN.Equal(subjectDN) {
			subject, err = reader.Get(subjectDN)
			if err != nil {
				continue
			}
		}
		matcher := directory.ValueMatcher(directory.BasicMatcher{})
		if target.Schema != nil {
			matcher = target.Schema
		}
		matches, filterErr := parsed.filter.MatchWith(subject, matcher)
		if filterErr == nil && matches {
			return true
		}
	}
	return false
}

func parseACLDynamicGroupURL(raw string) (aclDynamicGroupURL, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "ldap") ||
		parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return aclDynamicGroupURL{}, false
	}
	baseText, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil {
		return aclDynamicGroupURL{}, false
	}
	base, err := directory.ParseDN(baseText)
	if err != nil {
		return aclDynamicGroupURL{}, false
	}
	result := aclDynamicGroupURL{base: base, scope: directory.ScopeBase}
	components := []string(nil)
	if parsed.RawQuery != "" {
		components = strings.Split(parsed.RawQuery, "?")
	}
	if len(components) > 3 {
		return aclDynamicGroupURL{}, false
	}
	for len(components) < 3 {
		components = append(components, "")
	}
	attributes, err := url.PathUnescape(components[0])
	if err != nil || attributes != "" {
		return aclDynamicGroupURL{}, false
	}
	scope, err := url.PathUnescape(components[1])
	if err != nil {
		return aclDynamicGroupURL{}, false
	}
	switch strings.ToLower(scope) {
	case "", "base":
	case "one", "onelevel":
		result.scope = directory.ScopeSingleLevel
	case "sub", "subtree":
		result.scope = directory.ScopeWholeSubtree
	case "children", "subord", "subordinate":
		result.scope = directory.ScopeChildren
	default:
		return aclDynamicGroupURL{}, false
	}
	filterText, err := url.PathUnescape(components[2])
	if err != nil {
		return aclDynamicGroupURL{}, false
	}
	if filterText != "" {
		result.filter, err = ldapwire.CompileFilter(filterText)
		if err != nil {
			return aclDynamicGroupURL{}, false
		}
		result.filterSet = true
	}
	return result, true
}
