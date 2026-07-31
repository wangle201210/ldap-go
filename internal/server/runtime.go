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
	schema                *schema.Registry
	access                *acl.Policy
	databases             []runtimeDatabase
	allowAnonymousUpdates bool
	passwordHashSchemes   []string
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
	allowAnonymousUpdates, err := loadAnonymousUpdateAllowance(reader)
	if err != nil {
		return nil, err
	}
	passwordHashSchemes, err := loadPasswordHashSchemes(reader)
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
		schema:                registry,
		access:                access,
		databases:             databases,
		allowAnonymousUpdates: allowAnonymousUpdates,
		passwordHashSchemes:   passwordHashSchemes,
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

func loadAnonymousUpdateAllowance(reader storage.Reader) (bool, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load global configuration: %w", err)
	}

	allowAnonymousUpdates := false
	for _, rawValue := range entry.Values("olcAllows") {
		for _, feature := range strings.Fields(string(rawValue)) {
			switch strings.ToLower(feature) {
			case "update_anon":
				allowAnonymousUpdates = true
			case "bind_v2", "bind_anon_cred", "bind_anon_dn", "proxy_authz_anon":
				// These OpenLDAP features do not alter update authorization.
			default:
				return false, fmt.Errorf(
					"%s olcAllows has unknown feature %q",
					entry.DN,
					feature,
				)
			}
		}
	}
	return allowAnonymousUpdates, nil
}

func updateOperationPrecondition(
	runtime *runtimeState,
	boundDN string,
	target directory.DN,
) *ldapwire.Result {
	if boundDN == "" && !runtime.allowAnonymousUpdates {
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
