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
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	attribute string,
	value []byte,
	privilege acl.Privilege,
) bool {
	subject := accessSubject(reader, subjectDN)
	if server.isRoot(runtime, subject.DN, entry.DN, attribute) {
		return true
	}
	if mapped, ok := reader.(interface {
		remoteACLView(
			string,
			directory.Entry,
			string,
			[]byte,
		) (storage.Reader, string, directory.Entry, string, []byte, error)
	}); ok {
		remoteReader, remoteSubject, remoteEntry, remoteAttribute, remoteValue, err :=
			mapped.remoteACLView(subject.DN, entry, attribute, value)
		if err != nil {
			return false
		}
		subject.DN = remoteSubject
		if subject.RealDN != "" {
			if identityMapper, ok := reader.(interface {
				remoteACLIdentity(string) (string, error)
			}); ok {
				subject.RealDN, err = identityMapper.remoteACLIdentity(subject.RealDN)
				if err != nil {
					return false
				}
			}
		}
		return runtime.access.Allowed(
			subject,
			acl.Target{
				Entry:        remoteEntry,
				Attribute:    remoteAttribute,
				Value:        remoteValue,
				DNValued:     runtime.schema.IsDNValued(remoteAttribute),
				Schema:       runtime.schema,
				DNNormalizer: runtime.schema,
			},
			privilege,
			remoteReader,
		)
	}
	return runtime.access.Allowed(
		subject,
		acl.Target{
			Entry:        entry,
			Attribute:    attribute,
			Value:        value,
			DNValued:     runtime.schema.IsDNValued(attribute),
			Schema:       runtime.schema,
			DNNormalizer: runtime.schema,
		},
		privilege,
		reader,
	)
}

func (server *Server) attributesWithPrivilege(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	privilege acl.Privilege,
	typesOnly bool,
) directory.Entry {
	subject := accessSubject(reader, subjectDN)
	if server.isRoot(runtime, subject.DN, entry.DN, "") {
		return rootVisibleEntry(entry, typesOnly)
	}
	filtered := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		if typesOnly {
			if server.allowed(
				runtime,
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
				runtime,
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
			runtime,
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

func rootVisibleEntry(entry directory.Entry, typesOnly bool) directory.Entry {
	if !typesOnly {
		return entry
	}
	filtered := directory.Entry{
		DN:         entry.DN,
		Attributes: make([]directory.Attribute, 0, len(entry.Attributes)),
	}
	for _, attribute := range entry.Attributes {
		filtered.Attributes = append(filtered.Attributes, directory.Attribute{
			Description: attribute.Description,
		})
	}
	return filtered
}

func (server *Server) filterMatches(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	filter directory.Filter,
) (bool, error) {
	return server.filterMatchesWithPrivilege(
		runtime,
		reader,
		subjectDN,
		entry,
		filter,
		acl.Search,
	)
}

func (server *Server) filterMatchesWithPrivilege(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	filter directory.Filter,
	privilege acl.Privilege,
) (bool, error) {
	result, err := server.evaluateFilterWithPrivilege(
		runtime,
		reader,
		subjectDN,
		entry,
		filter,
		privilege,
	)
	return result == filterTrue, err
}

func (server *Server) evaluateFilterWithPrivilege(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	filter directory.Filter,
	privilege acl.Privilege,
) (filterResult, error) {
	switch filter.Kind {
	case directory.FilterAnd:
		result := filterTrue
		for _, child := range filter.Children {
			childResult, err := server.evaluateFilterWithPrivilege(
				runtime,
				reader,
				subjectDN,
				entry,
				child,
				privilege,
			)
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
			childResult, err := server.evaluateFilterWithPrivilege(
				runtime,
				reader,
				subjectDN,
				entry,
				child,
				privilege,
			)
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
		result, err := server.evaluateFilterWithPrivilege(
			runtime,
			reader,
			subjectDN,
			entry,
			filter.Children[0],
			privilege,
		)
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
			runtime,
			reader,
			subjectDN,
			entry,
			filter.Attribute,
			filter.Assertion,
			privilege,
		) {
			return filterUndefined, nil
		}
	case directory.FilterPresent, directory.FilterSubstrings:
		if !server.allowed(
			runtime,
			reader,
			subjectDN,
			entry,
			filter.Attribute,
			nil,
			privilege,
		) {
			return filterUndefined, nil
		}
	case directory.FilterExtensible:
		if filter.Attribute == "" {
			filtered := directory.Entry{DN: entry.DN}
			for _, attribute := range entry.Attributes {
				if server.allowed(
					runtime,
					reader,
					subjectDN,
					entry,
					attribute.Description,
					filter.Assertion,
					privilege,
				) {
					filtered.Attributes = append(filtered.Attributes, attribute)
				}
			}
			matches, err := filter.MatchWith(filtered, runtime.schema)
			return booleanFilterResult(matches), err
		}
		if !server.allowed(
			runtime,
			reader,
			subjectDN,
			entry,
			filter.Attribute,
			filter.Assertion,
			privilege,
		) {
			return filterUndefined, nil
		}
	default:
		return filterUndefined, errors.New("unknown filter kind")
	}

	matches, err := filter.MatchWith(entry, runtime.schema)
	return booleanFilterResult(matches), err
}

func booleanFilterResult(value bool) filterResult {
	if value {
		return filterTrue
	}
	return filterFalse
}

func (server *Server) canAccessAttribute(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	attribute directory.Attribute,
	privilege acl.Privilege,
) bool {
	if len(attribute.Values) == 0 {
		return server.allowed(
			runtime,
			reader,
			subjectDN,
			entry,
			attribute.Description,
			nil,
			privilege,
		)
	}
	for _, value := range attribute.Values {
		if !server.allowed(
			runtime,
			reader,
			subjectDN,
			entry,
			attribute.Description,
			value,
			privilege,
		) {
			return false
		}
	}
	return true
}

func (server *Server) canApplyModifications(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	changes []ldapwire.Modification,
) bool {
	for _, change := range changes {
		switch change.Operation {
		case ldapwire.ModificationAdd:
			if !server.canAccessAttribute(
				runtime,
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
				runtime,
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
				runtime,
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
				runtime,
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
