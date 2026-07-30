package server

import (
	"errors"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type filterResult uint8

const (
	filterFalse filterResult = iota
	filterTrue
	filterUndefined
)

func (server *Server) allowed(
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	attribute string,
	value []byte,
	privilege acl.Privilege,
) bool {
	if server.isRoot(subjectDN) {
		return true
	}
	return server.access.Allowed(
		acl.Subject{DN: subjectDN},
		acl.Target{
			Entry:     entry,
			Attribute: attribute,
			Value:     value,
			DNValued:  server.schema.IsDNValued(attribute),
		},
		privilege,
		reader,
	)
}

func (server *Server) attributesWithPrivilege(
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	privilege acl.Privilege,
	typesOnly bool,
) directory.Entry {
	filtered := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		if typesOnly {
			if server.allowed(
				reader,
				subjectDN,
				entry,
				attribute.Description,
				nil,
				privilege,
			) {
				filtered.Attributes = append(filtered.Attributes, directory.Attribute{
					Description: attribute.Description,
				})
			}
			continue
		}
		selected := directory.Attribute{Description: attribute.Description}
		for _, value := range attribute.Values {
			if server.allowed(
				reader,
				subjectDN,
				entry,
				attribute.Description,
				value,
				privilege,
			) {
				selected.Values = append(selected.Values, value)
			}
		}
		if len(attribute.Values) == 0 && server.allowed(
			reader,
			subjectDN,
			entry,
			attribute.Description,
			nil,
			privilege,
		) {
			filtered.Attributes = append(filtered.Attributes, selected)
			continue
		}
		if len(selected.Values) > 0 {
			filtered.Attributes = append(filtered.Attributes, selected)
		}
	}
	return filtered
}

func (server *Server) filterMatches(
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	filter directory.Filter,
) (bool, error) {
	result, err := server.evaluateFilter(reader, subjectDN, entry, filter)
	return result == filterTrue, err
}

func (server *Server) evaluateFilter(
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	filter directory.Filter,
) (filterResult, error) {
	switch filter.Kind {
	case directory.FilterAnd:
		result := filterTrue
		for _, child := range filter.Children {
			childResult, err := server.evaluateFilter(reader, subjectDN, entry, child)
			if err != nil {
				return filterUndefined, err
			}
			if childResult == filterFalse {
				return filterFalse, nil
			}
			if childResult == filterUndefined {
				result = filterUndefined
			}
		}
		return result, nil
	case directory.FilterOr:
		result := filterFalse
		for _, child := range filter.Children {
			childResult, err := server.evaluateFilter(reader, subjectDN, entry, child)
			if err != nil {
				return filterUndefined, err
			}
			if childResult == filterTrue {
				return filterTrue, nil
			}
			if childResult == filterUndefined {
				result = filterUndefined
			}
		}
		return result, nil
	case directory.FilterNot:
		if len(filter.Children) != 1 {
			return filterUndefined, errors.New("not filter requires exactly one child")
		}
		result, err := server.evaluateFilter(reader, subjectDN, entry, filter.Children[0])
		switch result {
		case filterTrue:
			return filterFalse, err
		case filterFalse:
			return filterTrue, err
		default:
			return filterUndefined, err
		}
	case directory.FilterEquality,
		directory.FilterApprox,
		directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual:
		if !server.allowed(
			reader,
			subjectDN,
			entry,
			filter.Attribute,
			filter.Assertion,
			acl.Search,
		) {
			return filterUndefined, nil
		}
	case directory.FilterPresent, directory.FilterSubstrings:
		if !server.allowed(
			reader,
			subjectDN,
			entry,
			filter.Attribute,
			nil,
			acl.Search,
		) {
			return filterUndefined, nil
		}
	case directory.FilterExtensible:
		if filter.Attribute == "" {
			filtered := directory.Entry{DN: entry.DN}
			for _, attribute := range entry.Attributes {
				if server.allowed(
					reader,
					subjectDN,
					entry,
					attribute.Description,
					filter.Assertion,
					acl.Search,
				) {
					filtered.Attributes = append(filtered.Attributes, attribute)
				}
			}
			matches, err := filter.MatchWith(filtered, server.schema)
			return booleanFilterResult(matches), err
		}
		if !server.allowed(
			reader,
			subjectDN,
			entry,
			filter.Attribute,
			filter.Assertion,
			acl.Search,
		) {
			return filterUndefined, nil
		}
	default:
		return filterUndefined, errors.New("unknown filter kind")
	}

	matches, err := filter.MatchWith(entry, server.schema)
	return booleanFilterResult(matches), err
}

func booleanFilterResult(value bool) filterResult {
	if value {
		return filterTrue
	}
	return filterFalse
}

func (server *Server) canAccessAttribute(
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	attribute directory.Attribute,
	privilege acl.Privilege,
) bool {
	if len(attribute.Values) == 0 {
		return server.allowed(reader, subjectDN, entry, attribute.Description, nil, privilege)
	}
	for _, value := range attribute.Values {
		if !server.allowed(reader, subjectDN, entry, attribute.Description, value, privilege) {
			return false
		}
	}
	return true
}

func (server *Server) canApplyModifications(
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	changes []ldapwire.Modification,
) bool {
	for _, change := range changes {
		switch change.Operation {
		case ldapwire.ModificationAdd:
			if !server.canAccessAttribute(
				reader,
				subjectDN,
				entry,
				change.Attribute,
				acl.WriteAdd,
			) {
				return false
			}
		case ldapwire.ModificationDelete:
			if !server.canAccessAttribute(
				reader,
				subjectDN,
				entry,
				change.Attribute,
				acl.WriteDelete,
			) {
				return false
			}
		case ldapwire.ModificationReplace, ldapwire.ModificationIncrement:
			if !server.allowed(
				reader,
				subjectDN,
				entry,
				change.Attribute.Description,
				nil,
				acl.WriteDelete,
			) {
				return false
			}
			if len(change.Attribute.Values) > 0 && !server.canAccessAttribute(
				reader,
				subjectDN,
				entry,
				change.Attribute,
				acl.WriteAdd,
			) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func parentEntry(reader storage.Reader, dn directory.DN) (directory.Entry, error) {
	parent, ok := dn.Parent()
	if !ok || parent.Depth() == 0 {
		return directory.Entry{DN: ""}, nil
	}
	entry, err := reader.Get(parent)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return directory.Entry{DN: parent.String()}, nil
	}
	return entry, err
}
