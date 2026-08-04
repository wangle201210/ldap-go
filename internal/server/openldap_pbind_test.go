package server

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferencePBindOverlay(t *testing.T) {
	tools := requireOpenLDAPPBindReferenceTools(t)

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
		fmt.Sprintf(
			"overlay pbind\nuri ldap://%s\nnetwork-timeout 1",
			providerAddress,
		),
		"",
	)
	defer stopOpenLDAP()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedPBindConfiguration(
		t,
		consumerStore,
		"ldap://"+providerAddress,
		"local-only",
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()
	ldapGoURI := "ldap://" + consumerAddress

	openLDAPResult := runPBindReferenceScenario(t, openLDAPURI)
	want := pbindReferenceResult{
		correctPasswordCode: ldap.LDAPResultSuccess,
		wrongPasswordCode:   ldap.LDAPResultInvalidCredentials,
		whoAmICode:          ldap.LDAPResultSuccess,
		whoAmIIdentity:      "dn:" + pbindReferenceUserDN,
	}
	if openLDAPResult != want {
		t.Fatalf(
			"OpenLDAP pbind scenario = %#v, want %#v",
			openLDAPResult,
			want,
		)
	}
	ldapGoResult := runPBindReferenceScenario(t, ldapGoURI)
	if ldapGoResult != openLDAPResult {
		t.Fatalf(
			"ldap-go pbind scenario = %#v, want OpenLDAP %#v",
			ldapGoResult,
			openLDAPResult,
		)
	}

	stopProvider()
	providerRunning = false
	openLDAPUnavailable := pbindReferenceBindCode(
		t,
		openLDAPURI,
		pbindReferenceUserDN,
		"secret",
	)
	if openLDAPUnavailable != ldap.LDAPResultUnavailable {
		t.Fatalf(
			"OpenLDAP unavailable provider result = %d, want %d",
			openLDAPUnavailable,
			ldap.LDAPResultUnavailable,
		)
	}
	ldapGoUnavailable := pbindReferenceBindCode(
		t,
		ldapGoURI,
		pbindReferenceUserDN,
		"secret",
	)
	if ldapGoUnavailable != openLDAPUnavailable {
		t.Fatalf(
			"ldap-go unavailable provider result = %d, want OpenLDAP %d",
			ldapGoUnavailable,
			openLDAPUnavailable,
		)
	}
}

func requireOpenLDAPPBindReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if len(output) == 0 {
		t.Skipf("inspect OpenLDAP backends: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "ldap") {
			return tools
		}
	}
	t.Skipf(
		"the selected OpenLDAP slapd was not built with the ldap backend (back_ldap)",
	)
	return openLDAPReferenceTools{}
}

const pbindReferenceUserDN = "uid=alice,ou=people,dc=example,dc=com"

type pbindReferenceResult struct {
	correctPasswordCode uint16
	wrongPasswordCode   uint16
	whoAmICode          uint16
	whoAmIIdentity      string
}

func runPBindReferenceScenario(t *testing.T, uri string) pbindReferenceResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	defer client.Close()

	result := pbindReferenceResult{
		correctPasswordCode: overlayLDAPResultCode(
			t,
			client.Bind(pbindReferenceUserDN, "secret"),
		),
	}
	identity, err := client.WhoAmI(nil)
	result.whoAmICode = overlayLDAPResultCode(t, err)
	if err == nil {
		result.whoAmIIdentity = identity.AuthzID
	}
	result.wrongPasswordCode = pbindReferenceBindCode(
		t,
		uri,
		pbindReferenceUserDN,
		"wrong-password",
	)
	return result
}

func pbindReferenceBindCode(
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
