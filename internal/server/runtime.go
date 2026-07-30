package server

import (
	"fmt"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var configurationSuffix = staticRuntimeDN("cn=config")

type runtimeState struct {
	schema    *schema.Registry
	access    *acl.Policy
	databases []runtimeDatabase
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
		schema:    registry,
		access:    access,
		databases: databases,
	}, nil
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
