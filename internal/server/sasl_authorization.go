package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

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
	if authenticationDN.Equal(authorizationDN) ||
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
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
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
				rules = append(rules, value)
			}
		}
		return nil
	})
	if err != nil {
		return false, err
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
			return expression.MatchString(assertedDN.Key()), nil
		}
		base, err := directory.ParseDN(pattern)
		if err != nil {
			return false, err
		}
		return directory.InScope(base, assertedDN, style.scope), nil
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
		return mapped.Equal(assertedDN), nil
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
	return exact.Equal(assertedDN), nil
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

	matched := false
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
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
			if memberDN.Equal(assertedDN) {
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
	if !directory.InScope(search.base, assertedDN, search.scope) {
		return false, nil
	}
	routes := databaseSearchRoutes(
		runtime.databases,
		search.base,
		search.scope,
	)
	if len(routes) == 0 {
		return false, nil
	}

	matched := false
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
			authenticationDN.String(),
			baseEntry,
			"entry",
			nil,
			acl.Auth,
		) {
			return nil
		}

		for _, route := range routes {
			if !directory.InScope(
				route.base,
				assertedDN,
				route.scope,
			) {
				continue
			}
			database := &runtime.databases[route.databaseIndex]
			tx := storage.ReaderInPartition(reader, database.partition)
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
				authenticationDN.String(),
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
				authenticationDN.String(),
				entry,
				search.filter,
				acl.Auth,
			)
			return err
		}
		return nil
	})
	return matched, err
}
