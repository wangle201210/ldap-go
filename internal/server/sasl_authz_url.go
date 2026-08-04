package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var errStopSASLAuthzSearch = errors.New(
	"SASL authorization search has multiple matches",
)

type saslAuthzLDAPURL struct {
	base   directory.DN
	scope  directory.Scope
	filter directory.Filter
}

func (server *Server) searchSASLAuthzLDAPURL(
	ctx context.Context,
	runtime *runtimeState,
	requestDN directory.DN,
	rawURL string,
	subjectDN string,
) (directory.DN, error) {
	search, err := parseSASLAuthzLDAPURL(rawURL)
	if err != nil {
		return directory.DN{}, err
	}
	routes := databaseSearchRoutes(
		runtime.databases,
		search.base,
		search.scope,
	)
	if len(routes) == 0 {
		return directory.DN{}, errors.New(
			"SASL authorization search has no database",
		)
	}

	primary := &runtime.databases[routes[0].databaseIndex]
	visible, err := server.saslAuthorizationSearchBaseVisible(
		ctx,
		runtime,
		*primary,
		search.base,
		subjectDN,
	)
	if err != nil {
		return directory.DN{}, err
	}
	if !visible {
		return directory.DN{}, fmt.Errorf(
			"authz-regexp search for %q returned no entries",
			requestDN.String(),
		)
	}

	var matched *directory.DN
	for _, route := range routes {
		database := &runtime.databases[route.databaseIndex]
		candidates, err := server.searchSASLAuthorizationRoute(
			ctx,
			runtime,
			*database,
			route,
			subjectDN,
			search.filter,
		)
		if err != nil {
			if errors.Is(err, errStopSASLAuthzSearch) {
				return directory.DN{}, fmt.Errorf(
					"authz-regexp search for %q returned multiple entries",
					requestDN.String(),
				)
			}
			return directory.DN{}, err
		}
		for _, candidate := range candidates {
			if matched != nil {
				return directory.DN{}, fmt.Errorf(
					"authz-regexp search for %q returned multiple entries",
					requestDN.String(),
				)
			}
			copy := candidate
			matched = &copy
		}
	}
	if matched == nil {
		return directory.DN{}, fmt.Errorf(
			"authz-regexp search for %q returned no entries",
			requestDN.String(),
		)
	}
	return *matched, nil
}

func (server *Server) saslAuthorizationSearchBaseVisible(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	base directory.DN,
	subjectDN string,
) (bool, error) {
	if saslAuthorizationUsesProxyBackend(&database) {
		_, found, err := server.lookupProxySASLAuthorizationEntry(
			ctx,
			runtime,
			database,
			base,
			[]string{"1.1"},
			subjectDN,
		)
		return found, err
	}

	visible := false
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		entry, err := tx.Get(base)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		visible = server.allowed(
			runtime,
			tx,
			subjectDN,
			entry,
			"entry",
			nil,
			acl.Auth,
		)
		return nil
	})
	return visible, err
}

func (server *Server) searchSASLAuthorizationRoute(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	route databaseSearchRoute,
	subjectDN string,
	filter directory.Filter,
) ([]directory.DN, error) {
	if saslAuthorizationUsesProxyBackend(&database) {
		entries, err := server.searchProxySASLAuthorization(
			ctx,
			runtime,
			database,
			ldapwire.SearchRequest{
				BaseDN:       route.base.String(),
				Scope:        route.scope,
				DerefAliases: ldapwire.NeverDerefAliases,
				SizeLimit:    1,
				TypesOnly:    true,
				Filter:       filter,
				Attributes:   []string{"1.1"},
			},
			subjectDN,
		)
		if err != nil {
			return nil, err
		}
		defer clearSASLAuthorizationEntries(entries)
		candidates := make([]directory.DN, 0, len(entries))
		for _, entry := range entries {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return nil, err
			}
			if !directory.InScope(route.base, candidate, route.scope) {
				return nil, fmt.Errorf(
					"SASL authorization search returned out-of-scope entry %q",
					entry.DN,
				)
			}
			candidates = append(candidates, candidate)
		}
		return candidates, nil
	}

	var candidates []directory.DN
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		return tx.ForEach(func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !directory.InScope(route.base, candidate, route.scope) ||
				!server.allowed(
					runtime,
					tx,
					subjectDN,
					entry,
					"entry",
					nil,
					acl.Auth,
				) {
				return nil
			}
			matches, err := server.filterMatchesWithPrivilege(
				runtime,
				tx,
				subjectDN,
				entry,
				filter,
				acl.Auth,
			)
			if err != nil || !matches {
				return err
			}
			candidates = append(candidates, candidate)
			if len(candidates) > 1 {
				return errStopSASLAuthzSearch
			}
			return nil
		})
	})
	return candidates, err
}

func parseSASLAuthzLDAPURL(value string) (saslAuthzLDAPURL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"parse authz-regexp LDAP URL: %w",
			err,
		)
	}
	if !strings.EqualFold(parsed.Scheme, "ldap") ||
		parsed.Host != "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return saslAuthzLDAPURL{}, errors.New(
			"authz-regexp LDAP URL must be a local ldap:/// URL",
		)
	}

	rawBase := strings.TrimPrefix(parsed.EscapedPath(), "/")
	baseText, err := url.PathUnescape(rawBase)
	if err != nil {
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"decode authz-regexp LDAP URL base: %w",
			err,
		)
	}
	base, err := directory.ParseDN(baseText)
	if err != nil {
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"authz-regexp LDAP URL base: %w",
			err,
		)
	}

	components := strings.Split(parsed.RawQuery, "?")
	if len(components) > 4 {
		return saslAuthzLDAPURL{}, errors.New(
			"authz-regexp LDAP URL has too many components",
		)
	}
	for len(components) < 4 {
		components = append(components, "")
	}
	if components[0] != "" {
		return saslAuthzLDAPURL{}, errors.New(
			"authz-regexp LDAP URL attributes are not supported",
		)
	}
	if components[3] != "" {
		return saslAuthzLDAPURL{}, errors.New(
			"authz-regexp LDAP URL extensions are not supported",
		)
	}

	scope := directory.ScopeBase
	rawScope, err := url.PathUnescape(components[1])
	if err != nil {
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"decode authz-regexp LDAP URL scope: %w",
			err,
		)
	}
	switch strings.ToLower(rawScope) {
	case "", "base":
	case "one":
		scope = directory.ScopeSingleLevel
	case "sub":
		scope = directory.ScopeWholeSubtree
	case "children":
		scope = directory.ScopeChildren
	default:
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"authz-regexp LDAP URL has unknown scope %q",
			rawScope,
		)
	}

	filterText, err := url.PathUnescape(components[2])
	if err != nil {
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"decode authz-regexp LDAP URL filter: %w",
			err,
		)
	}
	if filterText == "" {
		filterText = "(objectClass=*)"
	}
	filter, err := compileSyncConsumerFilter(filterText)
	if err != nil {
		return saslAuthzLDAPURL{}, fmt.Errorf(
			"authz-regexp LDAP URL filter: %w",
			err,
		)
	}
	return saslAuthzLDAPURL{
		base:   base,
		scope:  scope,
		filter: filter,
	}, nil
}
