package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var configurationSuffix = staticRuntimeDN("cn=config")

type runtimeState struct {
	schema              *schema.Registry
	access              *acl.Policy
	databases           []runtimeDatabase
	serverID            uint16
	allows              allowsRuntimeConfiguration
	disallows           disallowsRuntimeConfiguration
	passwordHashSchemes []string
	sasl                saslRuntimeConfiguration
	syncContexts        map[string]syncCSNState
}

type allowsRuntimeConfiguration struct {
	bindV2                   bool
	bindAnonymousCredentials bool
	bindAnonymousDN          bool
	anonymousUpdates         bool
	anonymousProxyAuthz      bool
}

type disallowsRuntimeConfiguration struct {
	anonymousBind                 bool
	simpleBind                    bool
	tlsToAnonymous                bool
	tlsAuthenticated              bool
	noncriticalProxyAuthorization bool
	noncriticalDontUseCopy        bool
}

func (server *Server) buildRuntimeState(reader storage.Reader) (*runtimeState, error) {
	registry := server.baseSchema.Clone()
	if _, err := schema.LoadOpenLDAPConfigReader(reader, registry); err != nil {
		return nil, fmt.Errorf("load OpenLDAP schema configuration: %w", err)
	}

	access := server.config.AccessPolicy
	if access == nil {
		var err error
		access, _, err = acl.LoadOpenLDAPConfigReader(reader)
		if err != nil {
			return nil, err
		}
	}

	databases, err := loadRuntimeDatabasesReader(reader)
	if err != nil {
		return nil, err
	}
	for index := range databases {
		if err := validateConstraintSchema(
			registry,
			databases[index].constraint,
		); err != nil {
			return nil, fmt.Errorf(
				"%s constraint overlay: %w",
				databases[index].name,
				err,
			)
		}
	}
	serverID, err := loadServerID(reader, server.config.ListenerURLs)
	if err != nil {
		return nil, err
	}
	for _, database := range databases {
		if database.multiProvider && serverID == 0 {
			return nil, fmt.Errorf(
				"%s olcMultiProvider requires a non-zero olcServerID",
				database.name,
			)
		}
	}
	allows, err := loadAllowsRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	disallows, err := loadDisallowsRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	passwordHashSchemes, err := loadPasswordHashSchemes(reader)
	if err != nil {
		return nil, err
	}
	sasl, err := loadSASLRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	if server.config.RootDN != "" {
		if err := applyBootstrapRoot(
			databases,
			server.config.RootDN,
			server.config.RootPassword,
		); err != nil {
			return nil, err
		}
	}
	return &runtimeState{
		schema:              registry,
		access:              access,
		databases:           databases,
		serverID:            serverID,
		allows:              allows,
		disallows:           disallows,
		passwordHashSchemes: passwordHashSchemes,
		sasl:                sasl,
	}, nil
}

func loadPasswordHashSchemes(reader storage.Reader) ([]string, error) {
	var globalValues [][]byte
	global, err := reader.Get(configurationSuffix)
	switch {
	case err == nil:
		globalValues = global.Values("olcPasswordHash")
	case errors.Is(err, storage.ErrEntryNotFound):
	default:
		return nil, fmt.Errorf("load global password hash configuration: %w", err)
	}

	var frontendValues [][]byte
	frontendFound := false
	err = reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !configurationSuffix.Equal(entryDN) &&
			!configurationSuffix.AncestorOf(entryDN) {
			return nil
		}
		databaseValues := entry.Values("olcDatabase")
		if len(databaseValues) != 1 ||
			databaseType(string(databaseValues[0])) != "frontend" {
			return nil
		}
		if frontendFound {
			return fmt.Errorf("multiple frontend database entries configure password hashes")
		}
		frontendFound = true
		frontendValues = entry.Values("olcPasswordHash")
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load frontend password hash configuration: %w", err)
	}

	values := globalValues
	if len(frontendValues) > 0 {
		values = frontendValues
	}
	if len(values) == 0 {
		return []string{auth.OpenLDAPDefaultHashScheme}, nil
	}

	var schemes []string
	for _, rawValue := range values {
		fields := strings.Fields(string(rawValue))
		if len(fields) == 0 {
			return nil, errors.New("olcPasswordHash contains an empty value")
		}
		for _, field := range fields {
			scheme, err := auth.NormalizePasswordHashScheme(field)
			if err != nil {
				return nil, fmt.Errorf("olcPasswordHash: %w", err)
			}
			schemes = append(schemes, scheme)
		}
	}
	return schemes, nil
}

func loadAllowsRuntimeConfiguration(
	reader storage.Reader,
) (allowsRuntimeConfiguration, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return allowsRuntimeConfiguration{}, nil
	}
	if err != nil {
		return allowsRuntimeConfiguration{}, fmt.Errorf(
			"load global configuration: %w",
			err,
		)
	}

	var configuration allowsRuntimeConfiguration
	for _, rawValue := range entry.Values("olcAllows") {
		for _, feature := range strings.Fields(string(rawValue)) {
			switch strings.ToLower(feature) {
			case "bind_v2":
				configuration.bindV2 = true
			case "bind_anon_cred":
				configuration.bindAnonymousCredentials = true
			case "bind_anon_dn":
				configuration.bindAnonymousDN = true
			case "update_anon":
				configuration.anonymousUpdates = true
			case "proxy_authz_anon":
				configuration.anonymousProxyAuthz = true
			default:
				return allowsRuntimeConfiguration{}, fmt.Errorf(
					"%s olcAllows has unknown feature %q",
					entry.DN,
					feature,
				)
			}
		}
	}
	return configuration, nil
}

func loadDisallowsRuntimeConfiguration(
	reader storage.Reader,
) (disallowsRuntimeConfiguration, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return disallowsRuntimeConfiguration{}, nil
	}
	if err != nil {
		return disallowsRuntimeConfiguration{}, fmt.Errorf(
			"load global configuration: %w",
			err,
		)
	}

	var configuration disallowsRuntimeConfiguration
	for _, rawValue := range entry.Values("olcDisallows") {
		for _, feature := range strings.Fields(string(rawValue)) {
			switch strings.ToLower(feature) {
			case "bind_anon":
				configuration.anonymousBind = true
			case "bind_simple":
				configuration.simpleBind = true
			case "tls_2_anon":
				configuration.tlsToAnonymous = true
			case "tls_authc":
				configuration.tlsAuthenticated = true
			case "proxy_authz_non_critical":
				configuration.noncriticalProxyAuthorization = true
			case "dontusecopy_non_critical":
				configuration.noncriticalDontUseCopy = true
			default:
				return disallowsRuntimeConfiguration{}, fmt.Errorf(
					"%s olcDisallows has unknown feature %q",
					entry.DN,
					feature,
				)
			}
		}
	}
	return configuration, nil
}

func updateOperationPrecondition(
	runtime *runtimeState,
	boundDN string,
	target directory.DN,
) *ldapwire.Result {
	if boundDN == "" && !runtime.allows.anonymousUpdates {
		result := ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"modifications require authentication",
		)
		return &result
	}
	if database := databaseForDN(runtime, target); database != nil && database.readOnly {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
		return &result
	}
	if database := databaseForDN(runtime, target); database != nil && database.shadow {
		if database.updateDN != nil && boundDN != "" {
			bound, err := directory.ParseDN(boundDN)
			if err == nil && database.updateDN.Equal(bound) {
				return nil
			}
		}
		result := shadowUpdateResult(*database, target)
		return &result
	}
	return nil
}

func lastModEnabled(runtime *runtimeState, target directory.DN) bool {
	database := databaseForDN(runtime, target)
	return database == nil || database.lastMod
}

func (server *Server) validateRuntimeConfiguration(
	reader storage.Reader,
) (*runtimeState, error) {
	runtime, err := server.buildRuntimeState(reader)
	if err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid cn=config: "+err.Error(),
		)
	}
	if err := server.observeRuntimeCSNs(reader, runtime); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid sync provider state: "+err.Error(),
		)
	}
	return runtime, nil
}

func isConfigurationDN(dn directory.DN) bool {
	return configurationSuffix.Equal(dn) || configurationSuffix.AncestorOf(dn)
}

func staticRuntimeDN(value string) directory.DN {
	dn, err := directory.ParseDN(value)
	if err != nil {
		panic(err)
	}
	return dn
}
