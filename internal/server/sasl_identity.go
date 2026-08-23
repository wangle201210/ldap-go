package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
)

var errSASLAuthorizationDenied = errors.New(
	"SASL authorization identity is not permitted",
)

type saslIdentityRewrite struct {
	requestDN directory.DN
	value     string
}

func (server *Server) saslAuthenticationDN(
	ctx context.Context,
	runtime *runtimeState,
	mechanism string,
	authenticationID string,
) (directory.DN, error) {
	return server.saslUserDN(
		ctx,
		runtime,
		mechanism,
		authenticationID,
		runtime.sasl.realm,
	)
}

func (server *Server) saslUserDN(
	ctx context.Context,
	runtime *runtimeState,
	mechanism string,
	user string,
	realm string,
) (directory.DN, error) {
	return server.saslUserDNAs(
		ctx,
		runtime,
		mechanism,
		user,
		realm,
		"",
	)
}

func (server *Server) saslUserDNAs(
	ctx context.Context,
	runtime *runtimeState,
	mechanism string,
	user string,
	realm string,
	subjectDN string,
) (directory.DN, error) {
	rewrite, err := runtime.sasl.rewriteUserIdentity(
		runtime,
		mechanism,
		user,
		realm,
	)
	if err != nil {
		return directory.DN{}, err
	}
	if strings.HasPrefix(strings.ToLower(rewrite.value), "ldap:") {
		return server.searchSASLAuthzLDAPURL(
			ctx,
			runtime,
			rewrite.requestDN,
			rewrite.value,
			subjectDN,
		)
	}
	mapped, err := normalizeSASLIdentityDN(runtime, rewrite.value)
	if err != nil {
		return directory.DN{}, fmt.Errorf(
			"authz-regexp produced invalid DN %q: %w",
			rewrite.value,
			err,
		)
	}
	return mapped, nil
}

func (configuration saslRuntimeConfiguration) rewriteUserIdentity(
	runtime *runtimeState,
	mechanism string,
	user string,
	realm string,
) (saslIdentityRewrite, error) {
	if user == "" {
		return saslIdentityRewrite{}, errors.New(
			"SASL user identity is empty",
		)
	}
	components := []string{"uid=" + ldap.EscapeDN(user)}
	if realm != "" {
		components = append(
			components,
			"cn="+ldap.EscapeDN(realm),
		)
	}
	components = append(
		components,
		"cn="+ldap.EscapeDN(strings.ToLower(mechanism)),
		"cn=auth",
	)
	requestDN, err := normalizeSASLIdentityDN(
		runtime,
		strings.Join(components, ","),
	)
	if err != nil {
		return saslIdentityRewrite{}, fmt.Errorf(
			"construct SASL authentication request DN: %w",
			err,
		)
	}

	normalized := requestDN.NormalizedString()
	for _, rule := range configuration.authzRegexps {
		submatches := rule.expression.FindStringSubmatchIndex(normalized)
		if submatches == nil {
			continue
		}
		rewritten := rule.expression.ExpandString(
			nil,
			rule.replacement,
			normalized,
			submatches,
		)
		value := string(rewritten)
		return saslIdentityRewrite{
			requestDN: requestDN,
			value:     value,
		}, nil
	}
	return saslIdentityRewrite{
		requestDN: requestDN,
		value:     requestDN.String(),
	}, nil
}

func (server *Server) resolveSASLAuthorizationDN(
	ctx context.Context,
	runtime *runtimeState,
	mechanism string,
	authenticationID string,
	authenticationDN directory.DN,
	authorizationID string,
) (directory.DN, error) {
	if authorizationID == "" || authorizationID == authenticationID {
		return authenticationDN, nil
	}

	var (
		target directory.DN
		err    error
	)
	switch {
	case strings.HasPrefix(strings.ToLower(authorizationID), "dn:"):
		target, err = normalizeSASLIdentityDN(
			runtime,
			authorizationID[3:],
		)
	case strings.HasPrefix(strings.ToLower(authorizationID), "u:"):
		target, err = server.saslUserDN(
			ctx,
			runtime,
			mechanism,
			authorizationID[2:],
			runtime.sasl.realm,
		)
	default:
		return directory.DN{}, errSASLAuthorizationDenied
	}
	if err != nil {
		return directory.DN{}, errSASLAuthorizationDenied
	}
	authorized, err := server.saslAuthorized(
		ctx,
		runtime,
		authenticationDN,
		target,
	)
	if err == nil && authorized {
		return target, nil
	}
	return directory.DN{}, errSASLAuthorizationDenied
}

func normalizeSASLIdentityDN(
	runtime *runtimeState,
	value string,
) (directory.DN, error) {
	var (
		dn  directory.DN
		err error
	)
	if runtime != nil && runtime.schema != nil {
		dn, err = runtime.schema.NormalizeDN(value)
	} else {
		dn, err = directory.ParseDN(value)
	}
	if err != nil {
		return directory.DN{}, err
	}
	return normalizeSASLAuthorizationDN(runtime, dn)
}

func saslRootMayAuthorize(
	runtime *runtimeState,
	authenticationDN directory.DN,
	authorizationDN directory.DN,
) bool {
	database := databaseForDN(runtime, authorizationDN)
	return database != nil && databaseRootMatches(
		runtime,
		*database,
		authenticationDN,
	)
}

func runtimeDNEqual(
	runtime *runtimeState,
	left directory.DN,
	right directory.DN,
) bool {
	if database := databaseForDN(runtime, left); database != nil {
		return databaseDNEqual(*database, left, right)
	}
	if database := databaseForDN(runtime, right); database != nil {
		return databaseDNEqual(*database, left, right)
	}
	return left.Equal(right)
}
