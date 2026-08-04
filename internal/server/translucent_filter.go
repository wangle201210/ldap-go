package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type translucentAttributeSet map[string]struct{}

func parseTranslucentAttributeSet(
	entry directory.Entry,
	attribute string,
) (translucentAttributeSet, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return nil, nil
	}
	result := make(translucentAttributeSet)
	for _, rawValue := range values {
		for _, rawName := range strings.Split(string(rawValue), ",") {
			name := strings.TrimSpace(rawName)
			if !validTranslucentAttributeDescription(name) {
				return nil, fmt.Errorf(
					"%s %s has invalid attribute description %q",
					entry.DN,
					attribute,
					rawName,
				)
			}
			result[strings.ToLower(name)] = struct{}{}
		}
	}
	return result, nil
}

func validTranslucentAttributeDescription(value string) bool {
	return validateConstraintAttributeDescription(value) == nil
}

func (attributes translucentAttributeSet) matches(
	registry *schema.Registry,
	description string,
) bool {
	if description == "" {
		return true
	}
	if _, ok := attributes[strings.ToLower(strings.TrimSpace(description))]; ok {
		return true
	}
	if registry == nil {
		return false
	}
	for configured := range attributes {
		if registry.AttributeDescriptionSubtype(description, configured) ||
			registry.AttributeDescriptionSubtype(configured, description) {
			return true
		}
	}
	return false
}

func translucentFilterSubset(
	filter directory.Filter,
	attributes translucentAttributeSet,
	registry *schema.Registry,
) (*directory.Filter, bool) {
	if len(attributes) == 0 {
		return nil, false
	}
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr, directory.FilterNot:
		children := make([]directory.Filter, 0, len(filter.Children))
		for _, child := range filter.Children {
			selected, ok := translucentFilterSubset(child, attributes, registry)
			if ok {
				children = append(children, *selected)
			}
		}
		if len(children) == 0 {
			return nil, false
		}
		if filter.Kind != directory.FilterNot && len(children) == 1 {
			selected := children[0]
			return &selected, true
		}
		selected := directory.Filter{Kind: filter.Kind, Children: children}
		return &selected, true
	default:
		if !attributes.matches(registry, filter.Attribute) {
			return nil, false
		}
		selected := cloneTranslucentFilter(filter)
		return &selected, true
	}
}

func cloneTranslucentFilter(filter directory.Filter) directory.Filter {
	cloned := filter
	cloned.Assertion = bytes.Clone(filter.Assertion)
	cloned.Substring.Initial = bytes.Clone(filter.Substring.Initial)
	cloned.Substring.Final = bytes.Clone(filter.Substring.Final)
	cloned.Substring.Any = make([][]byte, len(filter.Substring.Any))
	for index := range filter.Substring.Any {
		cloned.Substring.Any[index] = bytes.Clone(filter.Substring.Any[index])
	}
	cloned.Children = make([]directory.Filter, len(filter.Children))
	for index := range filter.Children {
		cloned.Children[index] = cloneTranslucentFilter(filter.Children[index])
	}
	return cloned
}

func (server *Server) translucentSearchCandidates(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	messageID int64,
	request ldapwire.SearchRequest,
	route databaseSearchRoute,
) ([]directory.Entry, [][]string, ldapwire.Result, *ldapwire.Result, error) {
	configuration := activeTranslucentConfiguration(&database)
	if configuration == nil {
		failure := ldapwire.ResultError(ldapwire.ResultUnavailable, "remote DB not available")
		return nil, nil, ldapwire.Result{}, &failure, nil
	}

	localFilter, hasLocalFilter := translucentFilterSubset(
		request.Filter,
		configuration.local,
		state.runtime.schema,
	)
	remoteFilter, hasRemoteFilter := translucentFilterSubset(
		request.Filter,
		configuration.remote,
		state.runtime.schema,
	)

	remoteEntries := make(map[string]directory.Entry)
	var references [][]string
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	runRemoteSearch := hasRemoteFilter || !hasLocalFilter
	if runRemoteSearch {
		selectedFilter := request.Filter
		if hasLocalFilter {
			selectedFilter = *remoteFilter
		}
		remoteRequest := request
		remoteRequest.BaseDN = route.base.String()
		remoteRequest.Scope = route.scope
		remoteRequest.SizeLimit = 0
		remoteRequest.TypesOnly = false
		remoteRequest.Filter = selectedFilter
		remoteRequest.Attributes = []string{"*", "+"}
		attempt, failure := server.executeTranslucentOperation(
			ctx,
			state,
			database,
			ldapwire.Message{ID: messageID, Request: remoteRequest},
		)
		if failure != nil {
			return nil, nil, result, failure, nil
		}
		var err error
		result, err = translucentSearchAttemptResult(attempt)
		if err != nil {
			return nil, nil, result, nil, err
		}
		entries, decodedReferences, err := decodeTranslucentSearchPackets(attempt.packets)
		if err != nil {
			return nil, nil, result, nil, err
		}
		references = decodedReferences
		for _, entry := range entries {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return nil, nil, result, nil, err
			}
			remoteEntries[dn.Key()] = entry.Clone()
		}
	}

	if hasLocalFilter {
		localDNs, err := server.translucentLocalFilterDNs(
			ctx,
			state,
			database,
			route,
			*localFilter,
		)
		if err != nil {
			return nil, nil, result, nil, err
		}
		for _, dn := range localDNs {
			if _, ok := remoteEntries[dn.Key()]; ok {
				continue
			}
			entry, failure, err := server.translucentRemoteBase(
				ctx,
				state,
				database,
				messageID,
				dn,
				request.DerefAliases,
				request.TimeLimit,
			)
			if err != nil {
				return nil, nil, result, nil, err
			}
			if failure != nil {
				if failure.Code == ldapwire.ResultNoSuchObject {
					continue
				}
				return nil, nil, result, failure, nil
			}
			if entry != nil {
				remoteEntries[dn.Key()] = entry.Clone()
			}
		}
	}

	entries := make([]directory.Entry, 0, len(remoteEntries))
	for _, entry := range remoteEntries {
		entries = append(entries, entry.Clone())
	}
	sortTranslucentEntries(entries)
	return entries, references, result, nil, nil
}

func (server *Server) translucentLocalFilterDNs(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	route databaseSearchRoute,
	filter directory.Filter,
) ([]directory.DN, error) {
	var result []directory.DN
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		return tx.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !directory.InScope(route.base, dn, route.scope) {
				return nil
			}
			matches, err := filter.MatchWith(entry, state.runtime.schema)
			if err != nil {
				return err
			}
			if matches {
				result = append(result, dn)
			}
			return nil
		})
	})
	return result, err
}

func sortTranslucentEntries(entries []directory.Entry) {
	for index := 1; index < len(entries); index++ {
		for current := index; current > 0; current-- {
			left, leftErr := directory.ParseDN(entries[current-1].DN)
			right, rightErr := directory.ParseDN(entries[current].DN)
			if leftErr != nil || rightErr != nil || left.Key() <= right.Key() {
				break
			}
			entries[current-1], entries[current] = entries[current], entries[current-1]
		}
	}
}
