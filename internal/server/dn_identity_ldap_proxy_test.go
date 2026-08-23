package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestDNIdentityLDAPProxyDatabaseSelection(t *testing.T) {
	registry := dnIdentityLDAPProxyRegistry(t)
	upperSuffix := mustDNIdentityLDAPProxyDN(t, registry, "proxyExactName=Tenant")
	lowerSuffix := mustDNIdentityLDAPProxyDN(t, registry, "proxyExactName=tenant")
	runtime := &runtimeState{
		schema: registry,
		databases: []runtimeDatabase{
			{
				name:         "{1}ldap",
				suffixes:     []directory.DN{upperSuffix},
				dnNormalizer: registry,
				ldapBackend:  &ldapBackendRuntimeConfiguration{},
				configDNKey:  "upper",
			},
			{
				name:         "{2}ldap",
				suffixes:     []directory.DN{lowerSuffix},
				dnNormalizer: registry,
				ldapBackend:  &ldapBackendRuntimeConfiguration{},
				configDNKey:  "lower",
			},
		},
	}
	state := &connectionState{
		boundDN:          "proxyExactName=tenant",
		authMechanism:    "SIMPLE",
		bindCredentialDN: "proxyExactName=tenant",
		bindCredentials:  []byte("secret"),
		runtime:          runtime,
	}

	if database := ldapBackendDatabaseForBoundIdentity(state); database == nil ||
		database.configDNKey != "lower" {
		t.Fatalf("caseExact bound identity database = %#v, want lower", database)
	}
	if ldapBackendHasReusableSimpleIdentity(state, runtime.databases[0]) {
		t.Fatal("caseExact-different database reused SIMPLE credentials")
	}
	if !ldapBackendHasReusableSimpleIdentity(state, runtime.databases[1]) {
		t.Fatal("caseExact-equal database did not reuse SIMPLE credentials")
	}

	foldSuffix := mustDNIdentityLDAPProxyDN(t, registry, "proxyFoldName=Tenant")
	runtime.databases = []runtimeDatabase{{
		name:         "{3}ldap",
		suffixes:     []directory.DN{foldSuffix},
		dnNormalizer: registry,
		ldapBackend:  &ldapBackendRuntimeConfiguration{},
		configDNKey:  "fold",
	}}
	state.boundDN = "proxyFoldName=tenant"
	state.bindCredentialDN = "proxyFoldName=TENANT"
	if database := ldapBackendDatabaseForBoundIdentity(state); database == nil ||
		database.configDNKey != "fold" {
		t.Fatalf("caseIgnore bound identity database = %#v, want fold", database)
	}
	if !ldapBackendHasReusableSimpleIdentity(state, runtime.databases[0]) {
		t.Fatal("caseIgnore-equivalent database did not reuse SIMPLE credentials")
	}
}

func TestDNIdentityLDAPProxyPassThroughCredentials(t *testing.T) {
	_, runtime, database := dnIdentityLDAPProxyRuntime(t)
	remote := defaultChainRemoteConfiguration()
	state := &connectionState{
		boundDN:          "proxyExactName=Alice,dc=example,dc=com",
		authMechanism:    "SIMPLE",
		bindCredentialDN: "proxyExactName=alice,dc=example,dc=com",
		bindCredentials:  []byte("exact-secret"),
		runtime:          runtime,
	}
	identity := mustDNIdentityLDAPProxyLegacyDN(
		t,
		"proxyExactName=Alice,dc=example,dc=com",
	)
	if _, ok := chainPassThroughRemote(state, remote, identity); ok {
		t.Fatal("caseExact-different identity reused SIMPLE credentials")
	}
	if !ldapBackendHasReusableSimpleIdentity(state, database) {
		t.Fatal("back-ldap did not recognize reusable credential database")
	}
	bound := mustDNIdentityLDAPProxyLegacyDN(t, state.boundDN)
	if _, ok := chainPassThroughRemote(state, remote, bound); ok {
		t.Fatal("back-ldap pass-through reused caseExact-different credentials")
	}

	state.boundDN = "proxyFoldName=Alice,dc=example,dc=com"
	state.bindCredentialDN = "proxyFoldName=alice,dc=example,dc=com"
	state.bindCredentials = []byte("fold-secret")
	identity = mustDNIdentityLDAPProxyLegacyDN(t, state.boundDN)
	passthrough, ok := chainPassThroughRemote(state, remote, identity)
	if !ok || passthrough.bind.bindDN != state.bindCredentialDN ||
		string(passthrough.bind.credentials) != "fold-secret" {
		t.Fatalf("caseIgnore pass-through = %#v, %t", passthrough.bind, ok)
	}

	legacy := &connectionState{
		authMechanism:    "SIMPLE",
		bindCredentialDN: "uid=Alice,dc=example,dc=com",
		bindCredentials:  []byte("legacy-secret"),
	}
	legacyIdentity := mustDNIdentityLDAPProxyLegacyDN(
		t,
		"UID=alice,DC=EXAMPLE,DC=COM",
	)
	if _, ok := chainPassThroughRemote(legacy, remote, legacyIdentity); !ok {
		t.Fatal("legacy case-insensitive SIMPLE credential reuse changed")
	}
}

func TestDNIdentityLDAPProxyAuthorizationControl(t *testing.T) {
	_, runtime, database := dnIdentityLDAPProxyRuntime(t)
	server := &Server{}
	message := ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN: "dc=example,dc=com",
			Scope:  directory.ScopeBase,
		},
	}
	state := &connectionState{
		operationRealDN: "proxyExactName=Alice,dc=example,dc=com",
		boundDN:         "proxyExactName=alice,dc=example,dc=com",
		runtime:         runtime,
	}

	_, forwarded, failure := server.ldapBackendRemote(
		context.Background(),
		state,
		database,
		defaultChainRemoteConfiguration(),
		message,
	)
	if failure != nil {
		t.Fatalf("caseExact ldapBackendRemote failure = %#v", failure)
	}
	control := chainedProxyAuthorizationControl(forwarded.Controls)
	if control == nil || !control.Critical ||
		string(control.Value) != "dn:proxyExactName=alice,dc=example,dc=com" {
		t.Fatalf("caseExact proxyAuthz control = %#v", control)
	}

	state.operationRealDN = "proxyFoldName=Alice,dc=example,dc=com"
	state.boundDN = "proxyFoldName=alice,dc=example,dc=com"
	_, forwarded, failure = server.ldapBackendRemote(
		context.Background(),
		state,
		database,
		defaultChainRemoteConfiguration(),
		message,
	)
	if failure != nil {
		t.Fatalf("caseIgnore ldapBackendRemote failure = %#v", failure)
	}
	if control := chainedProxyAuthorizationControl(forwarded.Controls); control != nil {
		t.Fatalf("caseIgnore-equivalent identities produced proxyAuthz = %#v", control)
	}

	legacy := &connectionState{
		operationRealDN: "uid=Alice,dc=example,dc=com",
		boundDN:         "UID=alice,DC=EXAMPLE,DC=COM",
	}
	if authorizationID, proxied := ldapBackendProxiedAuthorization(legacy); proxied {
		t.Fatalf("legacy equivalent identities produced proxyAuthz %q", authorizationID)
	}
}

func TestDNIdentityLDAPProxyPasswordCredentialUpdate(t *testing.T) {
	_, runtime, _ := dnIdentityLDAPProxyRuntime(t)
	request := func(identity string, password string) ldapwire.ExtendedRequest {
		return ldapwire.ExtendedRequest{
			Name: passwordModifyOID,
			Value: encodeChainedPasswordModifyValue(
				ldapwire.PasswordModifyRequestValue{
					UserIdentity:    []byte(identity),
					HasUserIdentity: true,
					NewPassword:     []byte(password),
					HasNewPassword:  true,
				},
			),
			HasValue: true,
		}
	}

	state := &connectionState{
		boundDN:          "proxyExactName=Alice,dc=example,dc=com",
		bindCredentialDN: "proxyExactName=Alice,dc=example,dc=com",
		bindCredentials:  []byte("old-exact"),
		runtime:          runtime,
	}
	updateLDAPBackendSimpleCredentials(
		state,
		request("proxyExactName=alice,dc=example,dc=com", "wrong-exact"),
	)
	if got := string(state.bindCredentials); got != "old-exact" {
		t.Fatalf("caseExact-different password update = %q", got)
	}
	updateLDAPBackendSimpleCredentials(
		state,
		request("proxyExactName=Alice,dc=example,dc=com", "new-exact"),
	)
	if got := string(state.bindCredentials); got != "new-exact" {
		t.Fatalf("caseExact-equal password update = %q", got)
	}

	state.boundDN = "proxyFoldName=Alice,dc=example,dc=com"
	state.bindCredentialDN = "proxyFoldName=Alice,dc=example,dc=com"
	state.bindCredentials = []byte("old-fold")
	updateLDAPBackendSimpleCredentials(
		state,
		request("proxyFoldName=alice,dc=example,dc=com", "new-fold"),
	)
	if got := string(state.bindCredentials); got != "new-fold" {
		t.Fatalf("caseIgnore-equivalent password update = %q", got)
	}

	legacy := &connectionState{
		boundDN:          "uid=Alice,dc=example,dc=com",
		bindCredentialDN: "uid=Alice,dc=example,dc=com",
		bindCredentials:  []byte("old-legacy"),
	}
	updateLDAPBackendSimpleCredentials(
		legacy,
		request("UID=alice,DC=EXAMPLE,DC=COM", "new-legacy"),
	)
	if got := string(legacy.bindCredentials); got != "new-legacy" {
		t.Fatalf("legacy equivalent password update = %q", got)
	}
}

func TestDNIdentityLDAPProxyPrivilegedPool(t *testing.T) {
	_, runtime, _ := dnIdentityLDAPProxyRuntime(t)
	message := ldapwire.Message{
		Request: ldapwire.SearchRequest{
			BaseDN: "dc=example,dc=com",
			Scope:  directory.ScopeBase,
		},
	}
	remote := defaultChainRemoteConfiguration()
	remote.identity.configured = true
	remote.bind.credentials = []byte("secret")
	remote.bind.credentialsSet = true
	state := &connectionState{
		bindCredentialDN: "proxyExactName=Alice,dc=example,dc=com",
		bindCredentials:  []byte("secret"),
		runtime:          runtime,
	}
	remote.bind.bindDN = "proxyExactName=alice,dc=example,dc=com"
	if !metaBackendUsesPrivilegedPool(state, remote, message) {
		t.Fatal("caseExact-different bind was treated as the frontend identity")
	}

	state.bindCredentialDN = "proxyFoldName=Alice,dc=example,dc=com"
	remote.bind.bindDN = "proxyFoldName=alice,dc=example,dc=com"
	if metaBackendUsesPrivilegedPool(state, remote, message) {
		t.Fatal("caseIgnore-equivalent bind was treated as privileged")
	}

	state.bindCredentialDN = "cn=config"
	remote.bind.bindDN = "CN=CONFIG"
	if metaBackendUsesPrivilegedPool(state, remote, message) {
		t.Fatal("cn=config legacy DN comparison changed")
	}
}

func dnIdentityLDAPProxyRuntime(
	t *testing.T,
) (*schema.Registry, *runtimeState, runtimeDatabase) {
	t.Helper()
	registry := dnIdentityLDAPProxyRegistry(t)
	suffix := mustDNIdentityLDAPProxyDN(t, registry, "dc=example,dc=com")
	database := runtimeDatabase{
		name:         "{1}ldap",
		suffixes:     []directory.DN{suffix},
		dnNormalizer: registry,
		ldapBackend:  &ldapBackendRuntimeConfiguration{},
		configDNKey:  "ldap",
	}
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
	return registry, runtime, database
}

func dnIdentityLDAPProxyRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.921.1 NAME 'proxyExactName' EQUALITY caseExactMatch " +
			"ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.921.2 NAME 'proxyFoldName' EQUALITY caseIgnoreMatch " +
			"ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func mustDNIdentityLDAPProxyDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	return dn
}

func mustDNIdentityLDAPProxyLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
