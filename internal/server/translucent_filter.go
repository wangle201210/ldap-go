package server

import (
	"bytes"
	"context"
	"fmt"
	"sort"
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
		remoteEntries, err = server.translucentEntryMap(
			ctx,
			database,
			entries,
		)
		if err != nil {
			return nil, nil, result, nil, err
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
			identityKey := dn.Key()
			if _, ok := remoteEntries[identityKey]; ok {
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
				entryKey, err := server.translucentEntryIdentityKey(
					ctx,
					database,
					entry.DN,
				)
				if err != nil {
					return nil, nil, result, nil, err
				}
				remoteEntries[entryKey] = entry.Clone()
			}
		}
	}

	entries := make([]directory.Entry, 0, len(remoteEntries))
	for _, entry := range remoteEntries {
		entries = append(entries, entry.Clone())
	}
	if err := server.sortTranslucentEntries(ctx, database, entries); err != nil {
		return nil, nil, result, nil, err
	}
	return entries, references, result, nil, nil
}

func (server *Server) translucentEntryMap(
	ctx context.Context,
	database runtimeDatabase,
	entries []directory.Entry,
) (map[string]directory.Entry, error) {
	result := make(map[string]directory.Entry, len(entries))
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		for _, entry := range entries {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			dn, err = storage.NormalizeReaderDN(tx, dn)
			if err != nil {
				return fmt.Errorf(
					"normalize translucent remote entry DN %q: %w",
					entry.DN,
					err,
				)
			}
			result[dn.Key()] = entry.Clone()
		}
		return nil
	})
	return result, err
}

func (server *Server) translucentEntryIdentityKey(
	ctx context.Context,
	database runtimeDatabase,
	rawDN string,
) (string, error) {
	var key string
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		dn, err := directory.ParseDN(rawDN)
		if err != nil {
			return fmt.Errorf("parse translucent entry DN %q: %w", rawDN, err)
		}
		dn, err = storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return fmt.Errorf("normalize translucent entry DN %q: %w", rawDN, err)
		}
		key = dn.Key()
		return nil
	})
	return key, err
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
		scopeBase, err := storage.NormalizeReaderDN(tx, route.base)
		if err != nil {
			return fmt.Errorf(
				"normalize translucent local filter base %q: %w",
				route.base.String(),
				err,
			)
		}
		return tx.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			dn, err = storage.NormalizeReaderDN(tx, dn)
			if err != nil {
				return fmt.Errorf(
					"normalize translucent local entry DN %q: %w",
					entry.DN,
					err,
				)
			}
			if !directory.InScope(scopeBase, dn, route.scope) {
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

func (server *Server) sortTranslucentEntries(
	ctx context.Context,
	database runtimeDatabase,
	entries []directory.Entry,
) error {
	type sortableEntry struct {
		entry    directory.Entry
		orderKey string
	}

	sorted := make([]sortableEntry, len(entries))
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		for index, entry := range entries {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf(
					"parse translucent result entry DN %q: %w",
					entry.DN,
					err,
				)
			}
			dn, err = storage.NormalizeReaderDN(tx, dn)
			if err != nil {
				return fmt.Errorf(
					"normalize translucent result entry DN %q: %w",
					entry.DN,
					err,
				)
			}
			orderKey, err := storage.ReaderDNOrderKey(tx, dn)
			if err != nil {
				return fmt.Errorf(
					"order translucent result entry DN %q: %w",
					entry.DN,
					err,
				)
			}
			sorted[index] = sortableEntry{entry: entry, orderKey: orderKey}
		}
		return nil
	})
	if err != nil {
		return err
	}

	sort.SliceStable(sorted, func(left, right int) bool {
		if sorted[left].orderKey != sorted[right].orderKey {
			return sorted[left].orderKey < sorted[right].orderKey
		}
		return sorted[left].entry.DN < sorted[right].entry.DN
	})
	for index := range sorted {
		entries[index] = sorted[index].entry
	}
	return nil
}
