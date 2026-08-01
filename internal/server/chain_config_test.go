package server

import (
	"context"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadChainRuntimeConfigurationFromOpenLDAPDIT(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	overlayDN := "olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config"
	entries := []directory.Entry{
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: overlayDN,
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}chain")},
				{Description: "olcChainCacheURI", Values: stringValues("TRUE")},
				{Description: "olcChainMaxReferralDepth", Values: stringValues("4")},
				{Description: "olcChainReturnError", Values: stringValues("TRUE")},
			},
		},
		{
			DN: "olcDatabase={0}ldap," + overlayDN,
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{0}ldap")},
				{
					Description: "olcDbACLBind",
					Values: stringValues(
						`bindmethod=simple binddn="cn=acl,dc=example,dc=com" credentials=acl-secret`,
					),
				},
				{Description: "olcDbNetworkTimeout", Values: stringValues("7")},
				{Description: "olcDbRebindAsUser", Values: stringValues("TRUE")},
				{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
				{Description: "olcDbKeepalive", Values: stringValues("30:3:10")},
				{Description: "olcDbTimeout", Values: stringValues("5 search=7")},
				{Description: "olcDbIdleTimeout", Values: stringValues("1h30m")},
				{Description: "olcDbConnTtl", Values: stringValues("2h")},
				{Description: "olcDbSingleConn", Values: stringValues("TRUE")},
				{Description: "olcDbUseTemporaryConn", Values: stringValues("TRUE")},
				{Description: "olcDbConnectionPoolMax", Values: stringValues("32")},
				{Description: "olcDbQuarantine", Values: stringValues("5,2;1m,+")},
				{Description: "olcDbTFSupport", Values: stringValues("discover")},
				{Description: "olcDbSessionTrackingRequest", Values: stringValues("TRUE")},
			},
		},
		{
			DN: "olcDatabase={1}ldap," + overlayDN,
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}ldap")},
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1:1389/")},
				{
					Description: "olcDbIDAssertBind",
					Values: stringValues(
						`bindmethod=simple binddn="cn=proxy,dc=example,dc=com" ` +
							`credentials=secret mode=self ` +
							`flags=override,non-prescriptive,proxy-authz-critical`,
					),
				},
				{
					Description: "olcDbIDAssertAuthzFrom",
					Values:      stringValues("{0}dn.subtree:dc=example,dc=com"),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed chain configuration: %v", err)
	}

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	if len(databases) != 2 {
		t.Fatalf("runtime database count = %d, want 2: %#v", len(databases), databases)
	}
	var frontend *runtimeDatabase
	for index := range databases {
		if databaseType(databases[index].name) == "frontend" {
			frontend = &databases[index]
		}
	}
	if frontend == nil || frontend.chain == nil {
		t.Fatal("frontend chain overlay was not loaded")
	}
	chain := frontend.chain
	if !chain.cacheURI || chain.maxReferralDepth != 4 || !chain.returnError {
		t.Fatalf("chain settings = %#v", chain)
	}
	if len(chain.remotes) != 1 {
		t.Fatalf("chain remotes = %#v", chain.remotes)
	}
	remote := chain.remotes[0]
	if remote.endpointKey != "ldap://127.0.0.1:1389" ||
		remote.bind.networkTimeout != 7*time.Second ||
		!remote.rebindAsUser || remote.chaseReferrals ||
		!remote.bind.keepalive.set ||
		remote.aclBind.bindDN != "cn=acl,dc=example,dc=com" ||
		string(remote.aclBind.credentials) != "acl-secret" ||
		remote.operationTimeouts[ldapwire.ApplicationBindRequest] != 5*time.Second ||
		remote.operationTimeouts[ldapwire.ApplicationSearchRequest] != 7*time.Second ||
		remote.idleTimeout != 90*time.Minute ||
		remote.connectionTTL != 2*time.Hour ||
		!remote.singleConnection || !remote.useTemporary ||
		remote.connectionPoolMax != 32 || len(remote.quarantine) != 2 ||
		remote.quarantine[1].attempts != -1 ||
		remote.absoluteFilters != chainFeatureDiscover || !remote.sessionTracking {
		t.Fatalf("inherited remote settings = %#v", remote)
	}
	if remote.bind.bindMethod != "simple" ||
		remote.bind.bindDN != "cn=proxy,dc=example,dc=com" ||
		string(remote.bind.credentials) != "secret" ||
		remote.identity.mode != chainIdentitySelf ||
		!remote.identity.override || remote.identity.prescriptive ||
		!remote.identity.proxyAuthzCritical ||
		len(remote.identity.authzFrom) != 1 {
		t.Fatalf("remote identity assertion = %#v, bind %#v", remote.identity, remote.bind)
	}
	if chain.common.uri != "" ||
		chain.common.bind.networkTimeout != 7*time.Second ||
		!chain.common.rebindAsUser || chain.common.chaseReferrals {
		t.Fatalf("chain common settings = %#v", chain.common)
	}
}

func TestParseChainBackendConnectionSettings(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		description string
		value       string
	}{
		{name: "pool too small", description: "olcDbConnectionPoolMax", value: "0"},
		{name: "pool too large", description: "olcDbConnectionPoolMax", value: "257"},
		{name: "bad idle timeout", description: "olcDbIdleTimeout", value: "1x"},
		{name: "bad quarantine", description: "olcDbQuarantine", value: "5,+;10,2"},
		{name: "bad cancel", description: "olcDbCancel", value: "cancel"},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: "olcDatabase={0}ldap,cn=config",
				Attributes: []directory.Attribute{{
					Description: test.description,
					Values:      stringValues(test.value),
				}},
			}
			configuration := defaultChainRemoteConfiguration()
			if err := loadChainRemoteConfiguration(entry, &configuration); err == nil {
				t.Fatalf("%s=%q was accepted", test.description, test.value)
			}
		})
	}
}

func TestLoadChainRuntimeConfigurationRejectsDuplicateURI(t *testing.T) {
	t.Parallel()

	overlay := directory.Entry{
		DN: "olcOverlay={0}chain,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues("{0}chain")},
		},
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			overlay,
			{
				DN: "olcDatabase={0}ldap," + overlay.DN,
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{0}ldap")},
					{Description: "olcDbURI", Values: stringValues("ldap://LDAP.EXAMPLE:389")},
				},
			},
			{
				DN: "olcDatabase={1}ldap," + overlay.DN,
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}ldap")},
					{Description: "olcDbURI", Values: stringValues("ldap://ldap.example:389/")},
				},
			},
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed duplicate chain URI: %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := loadChainRuntimeConfiguration(reader, overlay)
		return err
	}); err == nil {
		t.Fatal("duplicate chain URI was accepted")
	}
}

func TestChainLDAPISocketURLsShareEndpoint(t *testing.T) {
	t.Parallel()

	encodedURI, encodedKey, err := parseChainConfiguredURI(
		"ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
	)
	if err != nil {
		t.Fatalf("parse encoded ldapi URI: %v", err)
	}
	pathURI, pathKey, err := parseChainConfiguredURI(
		"ldapi:///var/run/slapd/ldapi",
	)
	if err != nil {
		t.Fatalf("parse path ldapi URI: %v", err)
	}
	if encodedURI == pathURI || encodedKey != pathKey {
		t.Fatalf(
			"ldapi endpoints = (%q, %q) and (%q, %q)",
			encodedURI,
			encodedKey,
			pathURI,
			pathKey,
		)
	}
	if encodedKey != "ldapi:///var/run/slapd/ldapi" {
		t.Fatalf("ldapi endpoint key = %q", encodedKey)
	}
}

func TestChainProtocolVersionMatchesOpenLDAPRange(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"0", "2", "3"} {
		entry := directory.Entry{
			DN: "olcDatabase={0}ldap,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDbProtocolVersion", Values: stringValues(version)},
			},
		}
		configuration := defaultChainRemoteConfiguration()
		if err := loadChainRemoteConfiguration(entry, &configuration); err != nil {
			t.Fatalf("version %s was rejected: %v", version, err)
		}
	}

	for _, version := range []string{"-1", "1", "4"} {
		entry := directory.Entry{
			DN: "olcDatabase={0}ldap,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDbProtocolVersion", Values: stringValues(version)},
			},
		}
		configuration := defaultChainRemoteConfiguration()
		if err := loadChainRemoteConfiguration(entry, &configuration); err == nil {
			t.Fatalf("version %s was accepted", version)
		}
	}
}

func TestParseConfiguredChainingBehavior(t *testing.T) {
	t.Parallel()

	control, err := parseConfiguredChainingBehavior(
		"resolve=chainingRequired continuation=referralsPreferred critical",
	)
	if err != nil {
		t.Fatalf("parseConfiguredChainingBehavior(): %v", err)
	}
	decoded, err := decodeChainingBehaviorControl(control)
	if err != nil || !control.Critical || !control.HasValue ||
		decoded.resolve != chainBehaviorChainingRequired ||
		decoded.continuation != chainBehaviorReferralsPreferred {
		t.Fatalf("configured chaining control = %#v, decoded %#v, %v", control, decoded, err)
	}

	control, err = parseConfiguredChainingBehavior("critical")
	if err != nil || !control.Critical || control.HasValue {
		t.Fatalf("critical default chaining control = %#v, %v", control, err)
	}
	for _, value := range []string{
		"resolve=unknown",
		"resolve=chainingPreferred resolve=chainingRequired",
		"continuation=chainingPreferred continuation=chainingRequired",
		"critical critical",
	} {
		if _, err := parseConfiguredChainingBehavior(value); err == nil {
			t.Fatalf("invalid chaining behavior %q was accepted", value)
		}
	}
}
