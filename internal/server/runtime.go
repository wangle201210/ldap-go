package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
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
	}, nil
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
