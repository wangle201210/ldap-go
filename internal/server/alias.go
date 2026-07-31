package server

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const defaultAliasDerefDepth = 15

type aliasDerefFailure struct {
	code       ldapwire.ResultCode
	diagnostic string
	matched    directory.Entry
}

type aliasDerefState struct {
	seen  map[string]struct{}
	depth int
}

type aliasSearchEntry struct {
	dn    directory.DN
	entry directory.Entry
}

func derefAliasesWhileFinding(mode int) bool {
	return mode == ldapwire.DerefFindingBaseObject ||
		mode == ldapwire.DerefAlways
}

func derefAliasesWhileSearching(mode int) bool {
	return mode == ldapwire.DerefInSearching ||
		mode == ldapwire.DerefAlways
}

func (server *Server) prepareAliasSearch(
	ctx context.Context,
	state *connectionState,
	base directory.DN,
	scope directory.Scope,
	mode int,
	routes []databaseSearchRoute,
) (
	directory.DN,
	[]databaseSearchRoute,
	*ldapwire.Result,
	error,
) {
	if len(routes) == 0 ||
		(!derefAliasesWhileFinding(mode) &&
			!derefAliasesWhileSearching(mode)) {
		return base, routes, nil, nil
	}

	effectiveBase := base
	effectiveRoutes := append([]databaseSearchRoute(nil), routes...)
	var failureResult *ldapwire.Result
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		if derefAliasesWhileFinding(mode) {
			primary := effectiveRoutes[0]
			database := &state.runtime.databases[primary.databaseIndex]
			tx := storage.ReaderInPartition(reader, database.partition)
			resolved, changed, failure, err := resolveAliasSearchBase(
				tx,
				state.runtime.schema,
				effectiveBase,
				database.maxDerefDepth,
			)
			if err != nil {
				return err
			}
			if failure != nil {
				result, err := server.aliasSearchFailureResult(
					state,
					tx,
					*failure,
				)
				if err != nil {
					return err
				}
				failureResult = &result
				return nil
			}
			if changed {
				effectiveBase = resolved
				effectiveRoutes = databaseSearchRoutesFromPrimary(
					state.runtime.databases,
					primary.databaseIndex,
					effectiveBase,
					scope,
				)
			}
		}
		if failureResult != nil ||
			!derefAliasesWhileSearching(mode) {
			return nil
		}

		var err error
		effectiveRoutes, err = expandAliasSearchRoutes(
			reader,
			state.runtime,
			effectiveRoutes,
		)
		return err
	})
	return effectiveBase, effectiveRoutes, failureResult, err
}

func resolveAliasSearchBase(
	reader storage.Reader,
	registry *schema.Registry,
	requested directory.DN,
	maxDepth int,
) (directory.DN, bool, *aliasDerefFailure, error) {
	current := requested
	changed := false
	state := aliasDerefState{seen: make(map[string]struct{})}

	for {
		entry, err := reader.Get(current)
		switch {
		case err == nil:
			if !registry.EntryHasObjectClass(entry, "alias") {
				return current, changed, nil, nil
			}
			target, failure, err := dereferenceAlias(
				reader,
				registry,
				entry,
				maxDepth,
				&state,
				nil,
			)
			if err != nil {
				return directory.DN{}, false, nil, err
			}
			if failure != nil {
				return directory.DN{}, false, failure, nil
			}
			targetDN, err := directory.ParseDN(target.DN)
			if err != nil {
				return directory.DN{}, false, nil, fmt.Errorf(
					"parse alias target entry DN %q: %w",
					target.DN,
					err,
				)
			}
			return targetDN, true, nil, nil
		case !errors.Is(err, storage.ErrEntryNotFound):
			return directory.DN{}, false, nil, err
		}

		ancestor, found, err := closestExistingAncestor(reader, current)
		if err != nil {
			return directory.DN{}, false, nil, err
		}
		if !found || !registry.EntryHasObjectClass(ancestor, "alias") {
			return current, changed, nil, nil
		}
		ancestorDN, err := directory.ParseDN(ancestor.DN)
		if err != nil {
			return directory.DN{}, false, nil, fmt.Errorf(
				"parse alias ancestor DN %q: %w",
				ancestor.DN,
				err,
			)
		}
		target, failure, err := dereferenceAlias(
			reader,
			registry,
			ancestor,
			maxDepth,
			&state,
			nil,
		)
		if err != nil {
			return directory.DN{}, false, nil, err
		}
		if failure != nil {
			return directory.DN{}, false, failure, nil
		}
		targetDN, err := directory.ParseDN(target.DN)
		if err != nil {
			return directory.DN{}, false, nil, fmt.Errorf(
				"parse alias target entry DN %q: %w",
				target.DN,
				err,
			)
		}
		current, err = current.ReplaceAncestor(ancestorDN, targetDN)
		if err != nil {
			return directory.DN{}, false, nil, fmt.Errorf(
				"rewrite search base through alias %q: %w",
				ancestor.DN,
				err,
			)
		}
		changed = true
	}
}

func dereferenceAlias(
	reader storage.Reader,
	registry *schema.Registry,
	start directory.Entry,
	maxDepth int,
	state *aliasDerefState,
	searchVisited map[string]struct{},
) (directory.Entry, *aliasDerefFailure, error) {
	current := start
	for registry.EntryHasObjectClass(current, "alias") {
		currentDN, err := directory.ParseDN(current.DN)
		if err != nil {
			return directory.Entry{}, nil, fmt.Errorf(
				"parse alias entry DN %q: %w",
				current.DN,
				err,
			)
		}
		if state.depth >= maxDepth {
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasDereferencingProblem,
				diagnostic: "maximum deref depth exceeded",
				matched:    current,
			}, nil
		}
		if searchVisited != nil {
			if _, exists := searchVisited[currentDN.Key()]; exists {
				return directory.Entry{}, &aliasDerefFailure{
					code:       ldapwire.ResultAliasDereferencingProblem,
					diagnostic: "alias was already dereferenced",
					matched:    current,
				}, nil
			}
			searchVisited[currentDN.Key()] = struct{}{}
		}
		if _, exists := state.seen[currentDN.Key()]; exists {
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasProblem,
				diagnostic: "circular alias",
				matched:    current,
			}, nil
		}
		state.seen[currentDN.Key()] = struct{}{}
		state.depth++

		values := current.Values("aliasedObjectName")
		switch len(values) {
		case 0:
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasProblem,
				diagnostic: "alias missing aliasedObjectName attribute",
				matched:    current,
			}, nil
		case 1:
		default:
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasProblem,
				diagnostic: "alias has multivalued aliasedObjectName",
				matched:    current,
			}, nil
		}
		if len(values[0]) == 0 {
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasProblem,
				diagnostic: "alias missing aliasedObjectName value",
				matched:    current,
			}, nil
		}
		targetDN, err := directory.ParseDN(string(values[0]))
		if err != nil {
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasProblem,
				diagnostic: "alias has invalid aliasedObjectName",
				matched:    current,
			}, nil
		}
		target, err := reader.Get(targetDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return directory.Entry{}, &aliasDerefFailure{
				code:       ldapwire.ResultAliasProblem,
				diagnostic: "aliasedObject not found",
				matched:    current,
			}, nil
		}
		if err != nil {
			return directory.Entry{}, nil, err
		}
		current = target
	}
	return current, nil, nil
}

func (server *Server) aliasSearchFailureResult(
	state *connectionState,
	reader storage.Reader,
	failure aliasDerefFailure,
) (ldapwire.Result, error) {
	logicalEntry, err := withCollectiveAttributes(
		state.runtime.schema,
		reader,
		failure.matched,
	)
	if err != nil {
		return ldapwire.Result{}, err
	}
	if !server.allowed(
		state.runtime,
		reader,
		state.boundDN,
		logicalEntry,
		"entry",
		nil,
		acl.Disclose,
	) {
		return ldapwire.Result{Code: ldapwire.ResultNoSuchObject}, nil
	}
	return ldapwire.Result{
		Code:              failure.code,
		MatchedDN:         failure.matched.DN,
		DiagnosticMessage: failure.diagnostic,
	}, nil
}

func expandAliasSearchRoutes(
	reader storage.Reader,
	runtime *runtimeState,
	routes []databaseSearchRoute,
) ([]databaseSearchRoute, error) {
	expanded := append([]databaseSearchRoute(nil), routes...)
	known := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		known[aliasRouteKey(route)] = struct{}{}
	}

	for _, route := range routes {
		database := &runtime.databases[route.databaseIndex]
		tx := storage.ReaderInPartition(reader, database.partition)
		additions, err := aliasSearchRoutesForRoute(
			tx,
			runtime.schema,
			route,
			database.maxDerefDepth,
		)
		if err != nil {
			return nil, err
		}
		for _, addition := range additions {
			key := aliasRouteKey(addition)
			if _, exists := known[key]; exists {
				continue
			}
			known[key] = struct{}{}
			expanded = append(expanded, addition)
		}
	}
	return expanded, nil
}

func aliasSearchRoutesForRoute(
	reader storage.Reader,
	registry *schema.Registry,
	route databaseSearchRoute,
	maxDepth int,
) ([]databaseSearchRoute, error) {
	if route.scope == directory.ScopeBase {
		return nil, nil
	}

	targetScope := directory.ScopeBase
	if route.scope == directory.ScopeWholeSubtree {
		targetScope = directory.ScopeWholeSubtree
	}
	processedAliases := make(map[string]struct{})
	searchVisited := make(map[string]struct{})
	knownTargets := make(map[string]struct{})
	priorScopes := []databaseSearchRoute{route}
	roundScopes := []databaseSearchRoute{route}
	var additions []databaseSearchRoute

	var aliases []aliasSearchEntry
	if err := reader.ForEach(func(entry directory.Entry) error {
		if !registry.EntryHasObjectClass(entry, "alias") {
			return nil
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		aliases = append(aliases, aliasSearchEntry{dn: dn, entry: entry})
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(aliases, func(i, j int) bool {
		return aliases[i].dn.Key() < aliases[j].dn.Key()
	})

	for len(roundScopes) > 0 {
		var nextRound []databaseSearchRoute
		for _, alias := range aliases {
			key := alias.dn.Key()
			if _, done := processedAliases[key]; done {
				continue
			}
			inScope := false
			for _, scope := range roundScopes {
				if aliasIsSearchSubordinate(scope, alias.dn) {
					inScope = true
					break
				}
			}
			if !inScope {
				continue
			}
			processedAliases[key] = struct{}{}
			state := aliasDerefState{seen: make(map[string]struct{})}
			target, failure, err := dereferenceAlias(
				reader,
				registry,
				alias.entry,
				maxDepth,
				&state,
				searchVisited,
			)
			if err != nil {
				return nil, err
			}
			if failure != nil {
				continue
			}
			targetDN, err := directory.ParseDN(target.DN)
			if err != nil {
				return nil, fmt.Errorf(
					"parse alias target entry DN %q: %w",
					target.DN,
					err,
				)
			}
			if _, exists := knownTargets[targetDN.Key()]; exists {
				continue
			}
			if targetScope == directory.ScopeWholeSubtree &&
				withinAnyAliasScope(priorScopes, targetDN) {
				continue
			}
			if route.scope == directory.ScopeSingleLevel &&
				directory.InScope(route.base, targetDN, route.scope) {
				continue
			}

			knownTargets[targetDN.Key()] = struct{}{}
			addition := databaseSearchRoute{
				databaseIndex: route.databaseIndex,
				base:          targetDN,
				scope:         targetScope,
			}
			additions = append(additions, addition)
			nextRound = append(nextRound, addition)
		}

		if route.scope != directory.ScopeWholeSubtree {
			break
		}
		priorScopes = append(priorScopes, nextRound...)
		roundScopes = nextRound
	}
	return additions, nil
}

func aliasIsSearchSubordinate(
	scope databaseSearchRoute,
	candidate directory.DN,
) bool {
	switch scope.scope {
	case directory.ScopeSingleLevel:
		return directory.InScope(
			scope.base,
			candidate,
			directory.ScopeSingleLevel,
		)
	case directory.ScopeWholeSubtree:
		return scope.base.AncestorOf(candidate)
	default:
		return false
	}
}

func withinAnyAliasScope(
	scopes []databaseSearchRoute,
	target directory.DN,
) bool {
	for _, scope := range scopes {
		if directory.InScope(scope.base, target, scope.scope) {
			return true
		}
	}
	return false
}

func aliasRouteKey(route databaseSearchRoute) string {
	return fmt.Sprintf(
		"%d\x00%d\x00%s",
		route.databaseIndex,
		route.scope,
		route.base.Key(),
	)
}
