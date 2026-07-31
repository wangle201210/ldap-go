package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
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

	var matched *directory.DN
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		primary := &runtime.databases[routes[0].databaseIndex]
		primaryReader := storage.ReaderInPartition(
			reader,
			primary.partition,
		)
		baseEntry, err := primaryReader.Get(search.base)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !server.allowed(
			runtime,
			primaryReader,
			"",
			baseEntry,
			"entry",
			nil,
			acl.Auth,
		) {
			return nil
		}

		for _, route := range routes {
			database := &runtime.databases[route.databaseIndex]
			tx := storage.ReaderInPartition(reader, database.partition)
			err := tx.ForEach(func(entry directory.Entry) error {
				candidate, err := directory.ParseDN(entry.DN)
				if err != nil {
					return err
				}
				if !directory.InScope(
					route.base,
					candidate,
					route.scope,
				) {
					return nil
				}
				if !server.allowed(
					runtime,
					tx,
					"",
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
					"",
					entry,
					search.filter,
					acl.Auth,
				)
				if err != nil || !matches {
					return err
				}
				if matched != nil {
					return errStopSASLAuthzSearch
				}
				copy := candidate
				matched = &copy
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, errStopSASLAuthzSearch):
		return directory.DN{}, fmt.Errorf(
			"authz-regexp search for %q returned multiple entries",
			requestDN.String(),
		)
	case err != nil:
		return directory.DN{}, err
	case matched == nil:
		return directory.DN{}, fmt.Errorf(
			"authz-regexp search for %q returned no entries",
			requestDN.String(),
		)
	default:
		return *matched, nil
	}
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
