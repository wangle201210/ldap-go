package acl

import (
	"strings"

	openldapaci "github.com/wangle201210/ldap-go/internal/aci"
	"github.com/wangle201210/ldap-go/internal/directory"
)

type aciAssertionScope uint8

const (
	aciAssertEntry aciAssertionScope = iota
	aciAssertChildren
)

func evaluateACIMatcher(
	matcher WhoMatcher,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) (Privilege, Privilege) {
	if targetDN.Depth() == 0 {
		return 0, 0
	}
	grant, deny := evaluateACIValues(
		aciAttributeValues(target.Entry, matcher.ACIAttribute, target.Schema),
		aciAssertEntry,
		subject,
		target,
		targetDN,
		reader,
		context,
	)
	if grant != 0 || deny != 0 || reader == nil {
		return grant, deny
	}

	parent, ok := targetDN.Parent()
	for ok && parent.Depth() > 0 {
		entry, err := reader.Get(parent)
		if err != nil {
			break
		}
		grant, deny = evaluateACIValues(
			aciAttributeValues(entry, matcher.ACIAttribute, target.Schema),
			aciAssertChildren,
			subject,
			target,
			targetDN,
			reader,
			context,
		)
		if grant != 0 || deny != 0 {
			return grant, deny
		}
		parent, ok = parent.Parent()
	}
	return 0, 0
}

func evaluateACIValues(
	values [][]byte,
	assertedScope aciAssertionScope,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) (Privilege, Privilege) {
	var grant Privilege
	var deny Privilege
	for _, raw := range values {
		value, err := openldapaci.Parse(string(raw))
		if err != nil || !aciScopeMatches(value.Scope, assertedScope) {
			continue
		}
		candidateGrant, candidateDeny := aciValueMask(
			value,
			subject,
			target,
			targetDN,
			reader,
			context,
		)
		grant |= candidateGrant
		deny |= candidateDeny
	}
	return grant, deny
}

func aciScopeMatches(scope openldapaci.Scope, asserted aciAssertionScope) bool {
	switch asserted {
	case aciAssertEntry:
		return scope == openldapaci.ScopeEntry || scope == openldapaci.ScopeSubtree
	case aciAssertChildren:
		return scope == openldapaci.ScopeChildren || scope == openldapaci.ScopeSubtree
	default:
		return false
	}
}

func aciValueMask(
	value openldapaci.Value,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) (Privilege, Privilege) {
	var grant Privilege
	var deny Privilege
	for _, permission := range value.Permissions {
		if !aciPermissionApplies(permission, target) {
			continue
		}
		rights := aciRights(permission.Rights)
		if permission.Grant {
			grant |= rights
		} else {
			deny |= rights
		}
	}
	if grant == 0 && deny == 0 ||
		!aciSubjectMatches(value, subject, target, targetDN, reader, context) {
		return 0, 0
	}
	return grant, deny
}

func aciPermissionApplies(permission openldapaci.Permission, target Target) bool {
	attribute := target.Attribute
	if separator := strings.IndexByte(attribute, ';'); separator >= 0 {
		attribute = attribute[:separator]
	}
	if attribute == "" {
		attribute = "entry"
	}
	for _, selector := range permission.Attributes {
		if selector.All {
			return true
		}
		if !strings.EqualFold(selector.Name, attribute) {
			continue
		}
		if !selector.HasValue || target.Value == nil {
			return true
		}
		candidate := string(target.Value)
		if selector.Prefix {
			if len(candidate) >= len(selector.Value) &&
				strings.EqualFold(candidate[:len(selector.Value)], selector.Value) {
				return true
			}
			continue
		}
		if strings.EqualFold(candidate, selector.Value) {
			return true
		}
	}
	return false
}

func aciRights(rights openldapaci.Right) Privilege {
	var result Privilege
	if rights&openldapaci.RightAuth != 0 {
		result |= Auth
	}
	if rights&openldapaci.RightDisclose != 0 {
		result |= Disclose
	}
	if rights&openldapaci.RightCompare != 0 {
		result |= Compare
	}
	if rights&openldapaci.RightSearch != 0 {
		result |= Search
	}
	if rights&openldapaci.RightRead != 0 {
		result |= Read
	}
	if rights&openldapaci.RightWrite != 0 {
		result |= Write
	}
	return result
}

func aciSubjectMatches(
	value openldapaci.Value,
	subject Subject,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) bool {
	if value.SubjectKind == openldapaci.SubjectPublic {
		return true
	}
	if subject.DN == "" {
		return false
	}
	if value.SubjectKind == openldapaci.SubjectUsers {
		return true
	}
	subjectDN, err := directory.ParseDN(subject.DN)
	if err != nil {
		return false
	}
	switch value.SubjectKind {
	case openldapaci.SubjectSelf:
		return subjectDN.Equal(targetDN)
	case openldapaci.SubjectAccessID:
		assertion, err := directory.ParseDN(value.Subject)
		return err == nil && subjectDN.Equal(assertion)
	case openldapaci.SubjectSubtree:
		assertion, err := directory.ParseDN(value.Subject)
		return err == nil && (subjectDN.Equal(assertion) || assertion.AncestorOf(subjectDN))
	case openldapaci.SubjectOneLevel:
		assertion, err := directory.ParseDN(value.Subject)
		if err != nil {
			return false
		}
		parent, ok := assertion.Parent()
		return ok && subjectDN.Equal(parent)
	case openldapaci.SubjectChildren:
		assertion, err := directory.ParseDN(value.Subject)
		return err == nil && !subjectDN.Equal(assertion) && assertion.AncestorOf(subjectDN)
	case openldapaci.SubjectDNAttribute:
		return entryContainsDN(target.Entry, value.Subject, subject.DN, target.Schema)
	case openldapaci.SubjectGroup, openldapaci.SubjectRole:
		groupDN, err := directory.ParseDN(value.Subject)
		if err != nil {
			return false
		}
		return matchesGroup(
			WhoMatcher{
				Kind:             WhoGroup,
				DN:               DNMatcher{Style: DNExact, DN: groupDN},
				GroupObjectClass: value.ObjectClass,
				GroupAttribute:   value.GroupAttribute,
				GroupPattern:     value.Subject,
				GroupExpand:      hasACLExpansion(value.Subject),
			},
			subject.DN,
			target,
			reader,
			context,
		)
	case openldapaci.SubjectSet:
		return matchesSet(
			WhoMatcher{Kind: WhoSet, SetPattern: value.Subject},
			subject.DN,
			target,
			targetDN,
			reader,
			context,
		)
	case openldapaci.SubjectSetReference:
		return matchesACISetReference(
			value.Subject,
			subject.DN,
			target,
			targetDN,
			reader,
			context,
		)
	default:
		return false
	}
}

func matchesACISetReference(
	reference,
	subjectDN string,
	target Target,
	targetDN directory.DN,
	reader EntryReader,
	context matchContext,
) bool {
	if reader == nil {
		return false
	}
	parts := strings.SplitN(reference, "/", 2)
	dn, err := directory.ParseDN(parts[0])
	if err != nil {
		return false
	}
	attribute := "template"
	if len(parts) == 2 && parts[1] != "" {
		attribute = parts[1]
	}
	entry := target.Entry
	if !dn.Equal(targetDN) {
		entry, err = reader.Get(dn)
		if err != nil {
			return false
		}
	}
	values := aciAttributeValues(entry, attribute, target.Schema)
	if len(values) == 0 {
		return false
	}
	return matchesSet(
		WhoMatcher{Kind: WhoSet, SetPattern: string(values[0])},
		subjectDN,
		target,
		targetDN,
		reader,
		context,
	)
}

func aciAttributeValues(
	entry directory.Entry,
	attribute string,
	schema TargetSchema,
) [][]byte {
	if schema != nil {
		return schema.AttributeValues(entry, attribute)
	}
	return entry.Values(attribute)
}
