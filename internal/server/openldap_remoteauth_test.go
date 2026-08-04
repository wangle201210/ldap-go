package server

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	remoteAuthReferenceProviderDN    = "uid=alice,ou=people,dc=example,dc=com"
	remoteAuthReferenceDelegateDN    = "uid=delegate,ou=people,dc=example,dc=com"
	remoteAuthReferenceLocalDN       = "uid=local,ou=people,dc=example,dc=com"
	remoteAuthReferenceUnavailableDN = "uid=unavailable,ou=people,dc=example,dc=com"
)

func TestOpenLDAPReferenceRemoteAuthOverlay(t *testing.T) {
	tools := requireOpenLDAPRemoteAuthReferenceTools(t)

	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	providerRunning := true
	t.Cleanup(func() {
		if providerRunning {
			stopProvider()
		}
	})

	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		openLDAPRemoteAuthReferenceConfiguration(providerAddress),
		openLDAPRemoteAuthReferenceData(),
	)
	defer stopOpenLDAP()

	ldapGoURI, stopLDAPGo := startLDAPGoRemoteAuthReferenceConsumer(
		t,
		providerAddress,
	)
	defer stopLDAPGo()

	wantAvailable := remoteAuthReferenceAvailableResult{
		delegatedWrongPassword:   ldap.LDAPResultInvalidCredentials,
		delegatedCorrectPassword: ldap.LDAPResultSuccess,
		localCorrectPassword:     ldap.LDAPResultSuccess,
		localRemotePassword:      ldap.LDAPResultInvalidCredentials,
	}
	openLDAPAvailable := runRemoteAuthReferenceAvailableScenario(t, openLDAPURI)
	if openLDAPAvailable != wantAvailable {
		t.Errorf(
			"OpenLDAP remoteauth available scenario = %#v, want %#v",
			openLDAPAvailable,
			wantAvailable,
		)
	}
	ldapGoAvailable := runRemoteAuthReferenceAvailableScenario(t, ldapGoURI)
	if ldapGoAvailable != openLDAPAvailable {
		t.Errorf(
			"ldap-go remoteauth available scenario = %#v, want OpenLDAP %#v",
			ldapGoAvailable,
			openLDAPAvailable,
		)
	}

	stopProvider()
	providerRunning = false

	wantUnavailable := remoteAuthReferenceUnavailableResult{
		storedPassword: ldap.LDAPResultSuccess,
		providerDown:   ldap.LDAPResultOperationsError,
	}
	openLDAPUnavailable := runRemoteAuthReferenceUnavailableScenario(t, openLDAPURI)
	if openLDAPUnavailable != wantUnavailable {
		t.Errorf(
			"OpenLDAP remoteauth unavailable scenario = %#v, want %#v",
			openLDAPUnavailable,
			wantUnavailable,
		)
	}
	ldapGoUnavailable := runRemoteAuthReferenceUnavailableScenario(t, ldapGoURI)
	if ldapGoUnavailable != openLDAPUnavailable {
		t.Errorf(
			"ldap-go remoteauth unavailable scenario = %#v, want OpenLDAP %#v",
			ldapGoUnavailable,
			openLDAPUnavailable,
		)
	}
}

func requireOpenLDAPRemoteAuthReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil {
		t.Skipf(
			"inspect OpenLDAP overlays: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "remoteauth") {
			return tools
		}
	}
	t.Skip("the selected OpenLDAP slapd was not built with the remoteauth overlay")
	return openLDAPReferenceTools{}
}

type remoteAuthReferenceAvailableResult struct {
	delegatedWrongPassword   uint16
	delegatedCorrectPassword uint16
	localCorrectPassword     uint16
	localRemotePassword      uint16
}

type remoteAuthReferenceUnavailableResult struct {
	storedPassword uint16
	providerDown   uint16
}

func runRemoteAuthReferenceAvailableScenario(
	t *testing.T,
	uri string,
) remoteAuthReferenceAvailableResult {
	t.Helper()
	return remoteAuthReferenceAvailableResult{
		delegatedWrongPassword: remoteAuthReferenceBindCode(
			t,
			uri,
			remoteAuthReferenceDelegateDN,
			"wrong-password",
		),
		delegatedCorrectPassword: remoteAuthReferenceBindCode(
			t,
			uri,
			remoteAuthReferenceDelegateDN,
			"secret",
		),
		localCorrectPassword: remoteAuthReferenceBindCode(
			t,
			uri,
			remoteAuthReferenceLocalDN,
			"local-secret",
		),
		localRemotePassword: remoteAuthReferenceBindCode(
			t,
			uri,
			remoteAuthReferenceLocalDN,
			"secret",
		),
	}
}

func runRemoteAuthReferenceUnavailableScenario(
	t *testing.T,
	uri string,
) remoteAuthReferenceUnavailableResult {
	t.Helper()
	return remoteAuthReferenceUnavailableResult{
		storedPassword: remoteAuthReferenceBindCode(
			t,
			uri,
			remoteAuthReferenceDelegateDN,
			"secret",
		),
		providerDown: remoteAuthReferenceBindCode(
			t,
			uri,
			remoteAuthReferenceUnavailableDN,
			"secret",
		),
	}
}

func remoteAuthReferenceBindCode(
	t *testing.T,
	uri,
	dn,
	password string,
) uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()
	return overlayLDAPResultCode(t, client.Bind(dn, password))
}

func openLDAPRemoteAuthReferenceConfiguration(providerAddress string) string {
	return fmt.Sprintf(
		`overlay remoteauth
remoteauth_dn_attribute seeAlso
remoteauth_domain_attribute description
remoteauth_mapping example ldap://%s
remoteauth_retry_count 0
remoteauth_store on
remoteauth_tls starttls=no`,
		providerAddress,
	)
}

func openLDAPRemoteAuthReferenceData() string {
	return `
dn: uid=delegate,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: delegate
cn: Delegate
sn: Delegate
seeAlso: uid=alice,ou=people,dc=example,dc=com
description: EXAMPLE:delegate

dn: uid=local,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: local
cn: Local
sn: Local
userPassword: local-secret
seeAlso: uid=alice,ou=people,dc=example,dc=com
description: EXAMPLE:local

dn: uid=unavailable,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: unavailable
cn: Unavailable
sn: Unavailable
seeAlso: uid=alice,ou=people,dc=example,dc=com
description: EXAMPLE:unavailable
`
}

func startLDAPGoRemoteAuthReferenceConsumer(
	t *testing.T,
	providerAddress string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedLDAPGoRemoteAuthReferenceConfiguration(t, store, providerAddress)
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func seedLDAPGoRemoteAuthReferenceConfiguration(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	entries := []directory.Entry{
		remoteAuthReferenceEntry(remoteAuthReferenceDelegateDN, "Delegate", ""),
		remoteAuthReferenceEntry(remoteAuthReferenceLocalDN, "Local", "local-secret"),
		remoteAuthReferenceEntry(remoteAuthReferenceUnavailableDN, "Unavailable", ""),
		{
			DN: "olcOverlay={0}remoteauth,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}remoteauth")},
				{Description: "olcRemoteAuthDNAttribute", Values: stringValues("seeAlso")},
				{Description: "olcRemoteAuthDomainAttribute", Values: stringValues("description")},
				{
					Description: "olcRemoteAuthMapping",
					Values:      stringValues("example ldap://" + providerAddress),
				},
				{Description: "olcRemoteAuthRetryCount", Values: stringValues("0")},
				{Description: "olcRemoteAuthStore", Values: stringValues("TRUE")},
				{Description: "olcRemoteAuthTLS", Values: stringValues("starttls=no")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap-go remoteauth reference configuration: %v", err)
	}
}

func remoteAuthReferenceEntry(
	dn,
	commonName,
	password string,
) directory.Entry {
	attributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("inetOrgPerson")},
		{Description: "uid", Values: stringValues(strings.ToLower(commonName))},
		{Description: "cn", Values: stringValues(commonName)},
		{Description: "sn", Values: stringValues(commonName)},
		{Description: "seeAlso", Values: stringValues(remoteAuthReferenceProviderDN)},
		{Description: "description", Values: stringValues("EXAMPLE:" + strings.ToLower(commonName))},
	}
	if password != "" {
		attributes = append(attributes, directory.Attribute{
			Description: "userPassword",
			Values:      stringValues(password),
		})
	}
	return directory.Entry{DN: dn, Attributes: attributes}
}
