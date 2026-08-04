package aci

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const (
	SyntaxOID       = "1.3.6.1.4.1.4203.666.2.1"
	MatchingRuleOID = "1.3.6.1.4.1.4203.666.4.2"
	AttributeName   = "OpenLDAPaci"
)

type Scope uint8

const (
	ScopeEntry Scope = iota
	ScopeChildren
	ScopeSubtree
)

type SubjectKind uint8

const (
	SubjectPublic SubjectKind = iota
	SubjectUsers
	SubjectSelf
	SubjectAccessID
	SubjectSubtree
	SubjectOneLevel
	SubjectChildren
	SubjectDNAttribute
	SubjectGroup
	SubjectRole
	SubjectSet
	SubjectSetReference
)

type Right uint8

const (
	RightAuth Right = 1 << iota
	RightDisclose
	RightCompare
	RightSearch
	RightRead
	RightWrite
)

type AttributeSelector struct {
	Name     string
	Value    string
	All      bool
	HasValue bool
	Prefix   bool
}

type Permission struct {
	Grant      bool
	Rights     Right
	Attributes []AttributeSelector
	Action     int
}

type Value struct {
	OID            string
	Scope          Scope
	Permissions    []Permission
	SubjectKind    SubjectKind
	Subject        string
	ObjectClass    string
	GroupAttribute string
}

func Parse(raw string) (Value, error) {
	parts := strings.SplitN(raw, "#", 5)
	if len(parts) != 5 {
		return Value{}, errors.New("ACI requires five #-separated fields")
	}
	result := Value{OID: strings.TrimSpace(parts[0]), Subject: parts[4]}
	if !validNumericOID(result.OID) {
		return Value{}, fmt.Errorf("invalid ACI OID %q", result.OID)
	}

	switch strings.ToLower(strings.TrimSpace(parts[1])) {
	case "entry":
		result.Scope = ScopeEntry
	case "children":
		result.Scope = ScopeChildren
	case "subtree":
		result.Scope = ScopeSubtree
	default:
		return Value{}, fmt.Errorf("invalid ACI scope %q", parts[1])
	}

	permissions, err := parsePermissions(parts[2])
	if err != nil {
		return Value{}, err
	}
	result.Permissions = permissions
	if err := result.parseSubjectType(parts[3]); err != nil {
		return Value{}, err
	}
	return result, nil
}

func (value *Value) parseSubjectType(raw string) error {
	parts := strings.Split(raw, "/")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	kind := strings.ToLower(parts[0])
	switch kind {
	case "public":
		value.SubjectKind = SubjectPublic
	case "users":
		value.SubjectKind = SubjectUsers
	case "self":
		value.SubjectKind = SubjectSelf
	case "access-id":
		value.SubjectKind = SubjectAccessID
	case "subtree":
		value.SubjectKind = SubjectSubtree
	case "onelevel":
		value.SubjectKind = SubjectOneLevel
	case "children":
		value.SubjectKind = SubjectChildren
	case "dnattr":
		value.SubjectKind = SubjectDNAttribute
	case "group", "role":
		if len(parts) > 3 {
			return fmt.Errorf("invalid ACI %s options", kind)
		}
		if kind == "group" {
			value.SubjectKind = SubjectGroup
			value.ObjectClass = "groupOfNames"
			value.GroupAttribute = "member"
		} else {
			value.SubjectKind = SubjectRole
			value.ObjectClass = "organizationalRole"
			value.GroupAttribute = "roleOccupant"
		}
		if len(parts) > 1 {
			if parts[1] == "" {
				return fmt.Errorf("empty ACI %s object class", kind)
			}
			value.ObjectClass = parts[1]
		}
		if len(parts) > 2 {
			if parts[2] == "" {
				return fmt.Errorf("empty ACI %s attribute", kind)
			}
			value.GroupAttribute = parts[2]
		}
	case "set":
		value.SubjectKind = SubjectSet
	case "set-ref":
		value.SubjectKind = SubjectSetReference
	default:
		return fmt.Errorf("invalid ACI subject type %q", raw)
	}
	if value.SubjectKind != SubjectGroup && value.SubjectKind != SubjectRole && len(parts) != 1 {
		return fmt.Errorf("ACI subject type %q does not accept options", kind)
	}

	switch value.SubjectKind {
	case SubjectAccessID, SubjectSubtree, SubjectOneLevel, SubjectChildren,
		SubjectGroup, SubjectRole:
		if value.Subject == "" {
			return errors.New("ACI DN subject is empty")
		}
		if _, err := directory.ParseDN(value.Subject); err != nil {
			return fmt.Errorf("invalid ACI subject DN: %w", err)
		}
	case SubjectDNAttribute:
		if strings.TrimSpace(value.Subject) == "" {
			return errors.New("ACI dnattr subject is empty")
		}
	}
	return nil
}

func parsePermissions(raw string) ([]Permission, error) {
	actions := strings.Split(raw, "$")
	if len(actions) == 0 {
		return nil, errors.New("ACI permissions are empty")
	}
	result := make([]Permission, 0, len(actions))
	for actionIndex, action := range actions {
		parts := strings.Split(action, ";")
		if len(parts) < 3 || len(parts)%2 == 0 {
			return nil, fmt.Errorf("invalid ACI permission %q", action)
		}
		grant := false
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "grant":
			grant = true
		case "deny":
		case "":
			return nil, errors.New("ACI permission action is empty")
		default:
			return nil, fmt.Errorf("invalid ACI permission action %q", parts[0])
		}
		for index := 1; index < len(parts); index += 2 {
			rights, err := parseRights(parts[index])
			if err != nil {
				return nil, err
			}
			selectors, err := parseAttributeSelectors(parts[index+1])
			if err != nil {
				return nil, err
			}
			for selectorIndex := range selectors {
				selectors[selectorIndex].Name = strings.TrimSpace(selectors[selectorIndex].Name)
			}
			result = append(result, Permission{
				Grant:      grant,
				Rights:     rights,
				Attributes: selectors,
				Action:     actionIndex,
			})
		}
	}
	return result, nil
}

func parseRights(raw string) (Right, error) {
	var result Right
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if len(part) != 1 {
			return 0, fmt.Errorf("invalid ACI right %q", part)
		}
		switch part[0] {
		case 'x':
			result |= RightAuth
		case 'd':
			result |= RightDisclose
		case 'c':
			result |= RightCompare
		case 's':
			result |= RightSearch
		case 'r':
			result |= RightRead
		case 'w':
			result |= RightWrite
		default:
			return 0, fmt.Errorf("invalid ACI right %q", part)
		}
	}
	if result == 0 {
		return 0, errors.New("ACI rights are empty")
	}
	return result, nil
}

func parseAttributeSelectors(raw string) ([]AttributeSelector, error) {
	parts := strings.Split(raw, ",")
	result := make([]AttributeSelector, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("ACI attribute selector is empty")
		}
		switch strings.ToLower(part) {
		case "[all]":
			result = append(result, AttributeSelector{All: true})
			continue
		case "[entry]":
			part = "entry"
		case "[children]":
			part = "children"
		}
		selector := AttributeSelector{Name: part}
		if separator := strings.IndexByte(part, '='); separator >= 0 {
			selector.Name = strings.TrimSpace(part[:separator])
			selector.Value = strings.TrimSpace(part[separator+1:])
			selector.HasValue = true
			if wildcard := strings.IndexByte(selector.Value, '*'); wildcard >= 0 {
				selector.Value = selector.Value[:wildcard]
				selector.Prefix = true
			}
		}
		if selector.Name == "" {
			return nil, errors.New("ACI attribute name is empty")
		}
		result = append(result, selector)
	}
	return result, nil
}

func Normalize(raw []byte) ([]byte, error) {
	value, err := Parse(string(raw))
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteString(value.OID)
	output.WriteByte('#')
	switch value.Scope {
	case ScopeEntry:
		output.WriteString("entry")
	case ScopeChildren:
		output.WriteString("children")
	case ScopeSubtree:
		output.WriteString("subtree")
	}
	output.WriteByte('#')
	for permissionIndex, permission := range value.Permissions {
		newAction := permissionIndex == 0 ||
			permission.Action != value.Permissions[permissionIndex-1].Action
		if permissionIndex > 0 && newAction {
			output.WriteByte('$')
		}
		if newAction {
			if permission.Grant {
				output.WriteString("grant")
			} else {
				output.WriteString("deny")
			}
		}
		output.WriteByte(';')
		writeRights(&output, permission.Rights)
		output.WriteByte(';')
		for selectorIndex, selector := range permission.Attributes {
			if selectorIndex > 0 {
				output.WriteByte(',')
			}
			if selector.All {
				output.WriteString("[all]")
				continue
			}
			output.WriteString(strings.ToLower(selector.Name))
			if selector.HasValue {
				output.WriteByte('=')
				output.WriteString(selector.Value)
				if selector.Prefix {
					output.WriteByte('*')
				}
			}
		}
	}
	output.WriteByte('#')
	writeSubjectType(&output, value)
	output.WriteByte('#')
	if normalizedSubject, ok := normalizedDNSubject(value); ok {
		output.WriteString(normalizedSubject)
	} else if value.SubjectKind == SubjectDNAttribute {
		output.WriteString(strings.ToLower(strings.TrimSpace(value.Subject)))
	} else if value.SubjectKind == SubjectSet || value.SubjectKind == SubjectSetReference {
		output.WriteString(value.Subject)
	}
	return []byte(output.String()), nil
}

func Compare(left, right []byte) (int, error) {
	normalizedLeft, err := Normalize(left)
	if err != nil {
		return 0, err
	}
	normalizedRight, err := Normalize(right)
	if err != nil {
		return 0, err
	}
	return bytes.Compare(normalizedLeft, normalizedRight), nil
}

func writeRights(output *strings.Builder, rights Right) {
	letters := []struct {
		right  Right
		letter byte
	}{
		{RightAuth, 'x'},
		{RightDisclose, 'd'},
		{RightCompare, 'c'},
		{RightSearch, 's'},
		{RightRead, 'r'},
		{RightWrite, 'w'},
	}
	written := false
	for _, candidate := range letters {
		if rights&candidate.right == 0 {
			continue
		}
		if written {
			output.WriteByte(',')
		}
		output.WriteByte(candidate.letter)
		written = true
	}
}

func writeSubjectType(output *strings.Builder, value Value) {
	names := map[SubjectKind]string{
		SubjectPublic:       "public",
		SubjectUsers:        "users",
		SubjectSelf:         "self",
		SubjectAccessID:     "access-id",
		SubjectSubtree:      "subtree",
		SubjectOneLevel:     "onelevel",
		SubjectChildren:     "children",
		SubjectDNAttribute:  "dnattr",
		SubjectGroup:        "group",
		SubjectRole:         "role",
		SubjectSet:          "set",
		SubjectSetReference: "set-ref",
	}
	output.WriteString(names[value.SubjectKind])
	if value.SubjectKind == SubjectGroup || value.SubjectKind == SubjectRole {
		output.WriteByte('/')
		output.WriteString(strings.ToLower(value.ObjectClass))
		output.WriteByte('/')
		output.WriteString(strings.ToLower(value.GroupAttribute))
	}
}

func normalizedDNSubject(value Value) (string, bool) {
	switch value.SubjectKind {
	case SubjectAccessID, SubjectSubtree, SubjectOneLevel, SubjectChildren,
		SubjectGroup, SubjectRole:
		dn, err := directory.ParseDN(value.Subject)
		if err != nil {
			return "", false
		}
		return dn.Key(), true
	default:
		return "", false
	}
}

func validNumericOID(value string) bool {
	if value == "" || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	lastDot := false
	for _, character := range value {
		switch {
		case character == '.' && !lastDot:
			lastDot = true
		case character >= '0' && character <= '9':
			lastDot = false
		default:
			return false
		}
	}
	return !lastDot
}
