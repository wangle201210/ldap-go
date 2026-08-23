package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func normalizeSASLAuthorizationDN(
	runtime *runtimeState,
	dn directory.DN,
) (directory.DN, error) {
	if runtime == nil {
		return dn, nil
	}
	return normalizeSASLAuthorizationDatabaseDN(
		runtime,
		databaseForDN(runtime, dn),
		dn,
	)
}

func normalizeSASLAuthorizationDatabaseDN(
	runtime *runtimeState,
	database *runtimeDatabase,
	dn directory.DN,
) (directory.DN, error) {
	if database != nil && database.dnNormalizer != nil {
		return normalizeRuntimeDatabaseDN(*database, dn)
	}
	if runtime != nil && runtime.schema != nil {
		return parseRuntimeDN(dn.String(), runtime.schema)
	}
	if database != nil {
		return normalizeRuntimeDatabaseDN(*database, dn)
	}
	return dn, nil
}

func normalizeSASLAuthorizationScope(
	runtime *runtimeState,
	base directory.DN,
	candidate directory.DN,
) (directory.DN, directory.DN, error) {
	if runtime == nil {
		return base, candidate, nil
	}
	database := databaseForDN(runtime, base)
	if database == nil {
		database = databaseForDN(runtime, candidate)
	}
	normalizedBase, err := normalizeSASLAuthorizationDatabaseDN(
		runtime,
		database,
		base,
	)
	if err != nil {
		return directory.DN{}, directory.DN{}, err
	}
	normalizedCandidate, err := normalizeSASLAuthorizationDatabaseDN(
		runtime,
		database,
		candidate,
	)
	return normalizedBase, normalizedCandidate, err
}

func (server *Server) saslAuthorized(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	authorizationDN directory.DN,
) (bool, error) {
	if authorizationDN.Depth() == 0 {
		return true, nil
	}
	if authenticationDN.Depth() == 0 {
		return false, nil
	}
	if runtimeDNEqual(runtime, authenticationDN, authorizationDN) ||
		saslRootMayAuthorize(runtime, authenticationDN, authorizationDN) {
		return true, nil
	}

	policy := runtime.sasl.authorizationPolicy
	if policy == 0 {
		return false, nil
	}

	toMatched := false
	if policy&saslAuthorizationTo != 0 {
		var err error
		toMatched, err = server.authorizationRulesMatch(
			ctx,
			runtime,
			authenticationDN,
			authenticationDN,
			"authzTo",
			authorizationDN,
		)
		if err != nil {
			toMatched = false
		}
		if policy&saslAuthorizationAll == 0 && toMatched {
			return true, nil
		}
		if policy&saslAuthorizationAll != 0 && !toMatched {
			return false, nil
		}
	}

	fromMatched := false
	if policy&saslAuthorizationFrom != 0 {
		var err error
		fromMatched, err = server.authorizationRulesMatch(
			ctx,
			runtime,
			authenticationDN,
			authorizationDN,
			"authzFrom",
			authenticationDN,
		)
		if err != nil {
			fromMatched = false
		}
	}
	if policy&saslAuthorizationAll != 0 {
		return toMatched && fromMatched, nil
	}
	return fromMatched, nil
}

func (server *Server) authorizationRulesMatch(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	rulesDN directory.DN,
	attribute string,
	assertedDN directory.DN,
) (bool, error) {
	database := databaseForDN(runtime, rulesDN)
	if database == nil {
		return false, nil
	}

	var rules [][]byte
	defer func() {
		for _, rule := range rules {
			clear(rule)
		}
	}()
	if saslAuthorizationUsesProxyBackend(database) {
		entry, found, err := server.lookupProxySASLAuthorizationEntry(
			ctx,
			runtime,
			*database,
			rulesDN,
			[]string{attribute},
			authenticationDN.String(),
		)
		if err != nil {
			return false, err
		}
		if found {
			defer clearSASLCredentialEntry(&entry)
			for _, value := range runtime.schema.AttributeValues(entry, attribute) {
				rules = append(rules, bytes.Clone(value))
			}
		}
	} else {
		err := server.config.Store.View(ctx, func(reader storage.Reader) error {
			tx := readerForDatabase(reader, *database)
			entry, err := tx.Get(rulesDN)
			if errors.Is(err, storage.ErrEntryNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			for _, value := range runtime.schema.AttributeValues(entry, attribute) {
				if server.allowed(
					runtime,
					tx,
					authenticationDN.String(),
					entry,
					attribute,
					value,
					acl.Auth,
				) {
					rules = append(rules, bytes.Clone(value))
				}
			}
			return nil
		})
		if err != nil {
			return false, err
		}
	}

	var lastErr error
	for _, rawRule := range rules {
		matched, err := server.authorizationRuleMatches(
			ctx,
			runtime,
			authenticationDN,
			string(rawRule),
			assertedDN,
		)
		if err != nil {
			lastErr = err
			continue
		}
		if matched {
			return true, nil
		}
	}
	return false, lastErr
}

func (server *Server) authorizationRuleMatches(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	rawRule string,
	assertedDN directory.DN,
) (bool, error) {
	_, _, rule, err := orderedSASLConfigurationValue(rawRule)
	if err != nil {
		return false, err
	}
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return false, errors.New("authorization rule is empty")
	}
	lower := strings.ToLower(rule)

	dnStyles := []struct {
		prefix string
		scope  directory.Scope
		regex  bool
	}{
		{prefix: "dn:", scope: directory.ScopeBase},
		{prefix: "dn.exact:", scope: directory.ScopeBase},
		{prefix: "dn.onelevel:", scope: directory.ScopeSingleLevel},
		{prefix: "dn.children:", scope: directory.ScopeChildren},
		{prefix: "dn.subtree:", scope: directory.ScopeWholeSubtree},
		{prefix: "dn.regex:", regex: true},
	}
	for _, style := range dnStyles {
		if !strings.HasPrefix(lower, style.prefix) {
			continue
		}
		pattern := strings.TrimLeft(
			rule[len(style.prefix):],
			" \t",
		)
		if pattern == "*" {
			return assertedDN.Depth() != 0, nil
		}
		if style.regex {
			if _, err := regexp.CompilePOSIX(pattern); err != nil {
				return false, fmt.Errorf(
					"compile POSIX authorization DN expression %q: %w",
					pattern,
					err,
				)
			}
			expression, err := regexp.Compile("(?i:" + pattern + ")")
			if err != nil {
				return false, fmt.Errorf(
					"compile authorization DN expression %q: %w",
					pattern,
					err,
				)
			}
			normalized, err := normalizeSASLAuthorizationDN(runtime, assertedDN)
			if err != nil {
				return false, err
			}
			// OpenLDAP applies authorization regexes to the normalized textual
			// DN, not ldap-go's opaque dn:v2 identity key.
			return expression.MatchString(normalized.NormalizedString()), nil
		}
		base, err := directory.ParseDN(pattern)
		if err != nil {
			return false, err
		}
		base, candidate, err := normalizeSASLAuthorizationScope(
			runtime,
			base,
			assertedDN,
		)
		return err == nil && directory.InScope(base, candidate, style.scope), err
	}

	if rule == "*" {
		return assertedDN.Depth() != 0, nil
	}
	if strings.HasPrefix(lower, "u:") ||
		strings.HasPrefix(lower, "u.") {
		separator := strings.IndexByte(rule, ':')
		if separator < 1 {
			return false, fmt.Errorf("invalid user authorization rule %q", rule)
		}
		qualifier := rule[:separator]
		user := rule[separator+1:]
		mechanism := "AUTHZ"
		realm := ""
		if len(qualifier) > 1 {
			if qualifier[1] != '.' {
				return false, fmt.Errorf(
					"invalid user authorization rule %q",
					rule,
				)
			}
			mechanism = qualifier[2:]
			if slash := strings.IndexByte(mechanism, '/'); slash >= 0 {
				realm = mechanism[slash+1:]
				mechanism = mechanism[:slash]
			}
			if mechanism == "" {
				return false, fmt.Errorf(
					"invalid user authorization rule %q",
					rule,
				)
			}
		}
		mapped, err := server.saslUserDNAs(
			ctx,
			runtime,
			mechanism,
			user,
			realm,
			authenticationDN.String(),
		)
		if err != nil {
			return false, err
		}
		mapped, candidate, err := normalizeSASLAuthorizationScope(
			runtime,
			mapped,
			assertedDN,
		)
		return err == nil && mapped.Equal(candidate), err
	}

	if strings.HasPrefix(lower, "group") {
		return server.authorizationGroupRuleMatches(
			ctx,
			runtime,
			authenticationDN,
			rule,
			assertedDN,
		)
	}
	if strings.HasPrefix(lower, "ldap:") {
		return server.authorizationURLRuleMatches(
			ctx,
			runtime,
			authenticationDN,
			rule,
			assertedDN,
		)
	}

	exact, err := directory.ParseDN(rule)
	if err != nil {
		return false, err
	}
	exact, candidate, err := normalizeSASLAuthorizationScope(
		runtime,
		exact,
		assertedDN,
	)
	return err == nil && exact.Equal(candidate), err
}

func (server *Server) authorizationGroupRuleMatches(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	rule string,
	assertedDN directory.DN,
) (bool, error) {
	separator := strings.IndexByte(rule, ':')
	if separator < 0 {
		return false, fmt.Errorf("invalid group authorization rule %q", rule)
	}
	selector := strings.Split(rule[:separator], "/")
	if !strings.EqualFold(selector[0], "group") || len(selector) > 3 {
		return false, fmt.Errorf("invalid group authorization rule %q", rule)
	}
	objectClass := "groupOfNames"
	memberAttribute := "member"
	if len(selector) > 1 && selector[1] != "" {
		objectClass = selector[1]
	}
	if len(selector) > 2 && selector[2] != "" {
		memberAttribute = selector[2]
	}
	groupDN, err := directory.ParseDN(rule[separator+1:])
	if err != nil {
		return false, err
	}
	database := databaseForDN(runtime, groupDN)
	if database == nil {
		return false, nil
	}
	groupDN, err = normalizeSASLAuthorizationDatabaseDN(runtime, database, groupDN)
	if err != nil {
		return false, err
	}
	comparisonAssertedDN, err := normalizeSASLAuthorizationDatabaseDN(
		runtime,
		database,
		assertedDN,
	)
	if err != nil {
		return false, err
	}
	if saslAuthorizationUsesProxyBackend(database) {
		entries, err := server.searchProxySASLAuthorization(
			ctx,
			runtime,
			*database,
			ldapwire.SearchRequest{
				BaseDN:       groupDN.String(),
				Scope:        directory.ScopeBase,
				DerefAliases: ldapwire.NeverDerefAliases,
				SizeLimit:    1,
				TypesOnly:    true,
				Filter: directory.Filter{
					Kind: directory.FilterAnd,
					Children: []directory.Filter{
						{
							Kind:      directory.FilterEquality,
							Attribute: "objectClass",
							Assertion: []byte(objectClass),
						},
						{
							Kind:      directory.FilterEquality,
							Attribute: memberAttribute,
							Assertion: []byte(comparisonAssertedDN.String()),
						},
					},
				},
				Attributes: []string{"1.1"},
			},
			authenticationDN.String(),
		)
		if err != nil {
			return false, err
		}
		defer clearSASLAuthorizationEntries(entries)
		if len(entries) > 1 {
			return false, errors.New(
				"SASL authorization group search returned multiple entries",
			)
		}
		for _, entry := range entries {
			entryDN, parseErr := directory.ParseDN(entry.DN)
			if parseErr == nil {
				entryDN, parseErr = normalizeSASLAuthorizationDatabaseDN(
					runtime,
					database,
					entryDN,
				)
			}
			if parseErr != nil || !entryDN.Equal(groupDN) {
				return false, fmt.Errorf(
					"SASL authorization group search for %q returned unexpected entry %q",
					groupDN.String(),
					entry.DN,
				)
			}
		}
		return len(entries) == 1, nil
	}

	matched := false
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, *database)
		entry, err := tx.Get(groupDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !runtime.schema.EntryHasObjectClass(entry, objectClass) ||
			!server.allowed(
				runtime,
				tx,
				authenticationDN.String(),
				entry,
				"objectClass",
				[]byte(objectClass),
				acl.Auth,
			) {
			return nil
		}
		for _, value := range runtime.schema.AttributeValues(
			entry,
			memberAttribute,
		) {
			if !server.allowed(
				runtime,
				tx,
				authenticationDN.String(),
				entry,
				memberAttribute,
				value,
				acl.Auth,
			) {
				continue
			}
			memberDN, err := directory.ParseDN(string(value))
			if err != nil {
				continue
			}
			memberDN, err = normalizeRuntimeReaderDN(tx, *database, memberDN)
			if err != nil {
				continue
			}
			candidate, err := normalizeRuntimeReaderDN(
				tx,
				*database,
				comparisonAssertedDN,
			)
			if err != nil {
				return err
			}
			if memberDN.Equal(candidate) {
				matched = true
				break
			}
		}
		return nil
	})
	return matched, err
}

func (server *Server) authorizationURLRuleMatches(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	rule string,
	assertedDN directory.DN,
) (bool, error) {
	search, err := parseSASLAuthzLDAPURL(rule)
	if err != nil {
		return false, err
	}
	base, comparisonAssertedDN, err := normalizeSASLAuthorizationScope(
		runtime,
		search.base,
		assertedDN,
	)
	if err != nil || !directory.InScope(base, comparisonAssertedDN, search.scope) {
		return false, err
	}
	search.base = base
	routes := databaseSearchRoutes(
		runtime.databases,
		search.base,
		search.scope,
	)
	if len(routes) == 0 {
		return false, nil
	}

	primary := &runtime.databases[routes[0].databaseIndex]
	visible, err := server.saslAuthorizationSearchBaseVisible(
		ctx,
		runtime,
		*primary,
		search.base,
		authenticationDN.String(),
	)
	if err != nil || !visible {
		return false, err
	}

	matches := 0
	for _, route := range routes {
		database := &runtime.databases[route.databaseIndex]
		routeBase, routeAssertedDN, err := normalizeSASLAuthorizationScope(
			runtime,
			route.base,
			comparisonAssertedDN,
		)
		if err != nil {
			return false, err
		}
		if !directory.InScope(routeBase, routeAssertedDN, route.scope) {
			continue
		}
		if saslAuthorizationUsesProxyBackend(database) {
			entries, err := server.searchProxySASLAuthorization(
				ctx,
				runtime,
				*database,
				ldapwire.SearchRequest{
					BaseDN:       routeAssertedDN.String(),
					Scope:        directory.ScopeBase,
					DerefAliases: ldapwire.NeverDerefAliases,
					SizeLimit:    1,
					TypesOnly:    true,
					Filter:       search.filter,
					Attributes:   []string{"1.1"},
				},
				authenticationDN.String(),
			)
			if err != nil {
				return false, err
			}
			defer clearSASLAuthorizationEntries(entries)
			for _, entry := range entries {
				entryDN, parseErr := directory.ParseDN(entry.DN)
				if parseErr == nil {
					entryDN, parseErr = normalizeSASLAuthorizationDatabaseDN(
						runtime,
						database,
						entryDN,
					)
				}
				if parseErr != nil || !entryDN.Equal(routeAssertedDN) {
					return false, fmt.Errorf(
						"SASL authorization URL search for %q returned unexpected entry %q",
						routeAssertedDN.String(),
						entry.DN,
					)
				}
				matches++
			}
		} else {
			matched, err := server.localSASLAuthorizationEntryMatches(
				ctx,
				runtime,
				*database,
				authenticationDN.String(),
				routeAssertedDN,
				search.filter,
			)
			if err != nil {
				return false, err
			}
			if matched {
				matches++
			}
		}
		if matches > 1 {
			return false, errors.New(
				"SASL authorization URL search returned multiple matching entries",
			)
		}
	}
	return matches == 1, nil
}

func (server *Server) localSASLAuthorizationEntryMatches(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	subjectDN string,
	assertedDN directory.DN,
	filter directory.Filter,
) (bool, error) {
	matched := false
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		entry, err := tx.Get(assertedDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !server.allowed(
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
		matched, err = server.filterMatchesWithPrivilege(
			runtime,
			tx,
			subjectDN,
			entry,
			filter,
			acl.Auth,
		)
		return err
	})
	return matched, err
}
