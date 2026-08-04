package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPBackendURIHealthPreferenceAndRecovery(t *testing.T) {
	tests := []struct {
		name      string
		operation func(*testing.T, string)
	}{
		{
			name: "Bind",
			operation: func(t *testing.T, address string) {
				client := bindLDAPBackendUser(t, address, ldapBackendTestUserPassword)
				client.Close()
			},
		},
		{
			name: "Search",
			operation: func(t *testing.T, address string) {
				client := dialLDAPBackendClient(t, address)
				defer client.Close()
				result, err := client.Search(ldap.NewSearchRequest(
					ldapBackendTestUserDN,
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"uid"},
					nil,
				))
				if err != nil || len(result.Entries) != 1 ||
					result.Entries[0].DN != ldapBackendTestUserDN {
					t.Fatalf("Search through back-ldap URI list = %#v, %v", result, err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testLDAPBackendURIHealthPreference(t, test.operation)
		})
	}
}

func testLDAPBackendURIHealthPreference(
	t *testing.T,
	operation func(*testing.T, string),
) {
	t.Helper()
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	allowAnonymousMetaURIReads(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	t.Cleanup(stopProvider)

	first := newMetaURITestProvider(t, providerAddress)
	t.Cleanup(first.stop)
	second := newMetaURITestProvider(t, providerAddress)
	second.start(t)
	t.Cleanup(second.stop)

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxyURI(t, proxyStore, fmt.Sprintf(
		"ldap://%s ldap://%s",
		first.address,
		second.address,
	))
	allowAnonymousLDAPBackendIdentityAssertion(t, proxyStore)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	t.Cleanup(stopProxy)

	operation(t, proxyAddress)
	if got := second.accepted(); got != 1 {
		t.Fatalf("healthy second URI connections after failover = %d, want 1", got)
	}

	first.start(t)
	operation(t, proxyAddress)
	if got := first.accepted(); got != 0 {
		t.Fatalf("recovered first URI was probed while preferred URI was healthy: %d", got)
	}
	if got := second.accepted(); got != 2 {
		t.Fatalf("preferred second URI connections = %d, want 2", got)
	}

	second.stop()
	operation(t, proxyAddress)
	if got := first.accepted(); got != 1 {
		t.Fatalf("recovered first URI connections after preferred failure = %d, want 1", got)
	}

	second.start(t)
	operation(t, proxyAddress)
	if got := first.accepted(); got != 2 {
		t.Fatalf("new preferred first URI connections = %d, want 2", got)
	}
	if got := second.accepted(); got != 2 {
		t.Fatalf("recovered second URI unexpectedly preempted first URI: %d", got)
	}
}

func TestLDAPBackendURIConfigurationReloadClearsPreference(t *testing.T) {
	initial, err := loadLDAPBackendRuntimeConfiguration(ldapBackendDatabaseEntry(
		"{1}ldap",
		ldapBackendTestSuffix,
		"ldap://127.0.0.1:1389 ldap://127.0.0.1:2389 ldap://127.0.0.1:3389",
	))
	if err != nil {
		t.Fatalf("load initial URI configuration: %v", err)
	}
	rememberPreferredProxyRemote(initial.preferred, 2)
	if got := preferredProxyRemoteOrder(initial.preferred, 3); !equalInts(got, []int{2, 0, 1}) {
		t.Fatalf("initial preferred URI order = %v", got)
	}

	updated, err := loadLDAPBackendRuntimeConfiguration(ldapBackendDatabaseEntry(
		"{1}ldap",
		ldapBackendTestSuffix,
		"ldap://127.0.0.1:4389 ldap://127.0.0.1:5389",
	))
	if err != nil {
		t.Fatalf("load updated URI configuration: %v", err)
	}
	if initial.preferred == updated.preferred {
		t.Fatal("configuration reload retained the previous URI preference state")
	}
	if got := preferredProxyRemoteOrder(updated.preferred, 2); !equalInts(got, []int{0, 1}) {
		t.Fatalf("updated URI order inherited a stale index: %v", got)
	}
}

func TestOpenLDAPReferenceLDAPBackendURISelectionSource(t *testing.T) {
	_ = requireOpenLDAPLDAPBackendReferenceTools(t)
	const commit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("LDAP URI selection reference requires a verified OpenLDAP build")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != commit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, commit)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	path := filepath.Join(sourceRoot, "servers", "slapd", "back-ldap", "bind.c")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(contents)),
		"8b01620934ce7436f99b577ced3d1d242651a07d0a107db4d6a09c748701c5d1"; got != want {
		t.Fatalf("pinned OpenLDAP source %s SHA-256 = %s, want %s", path, got, want)
	}
	section := openLDAPSourceSection(
		t,
		string(contents),
		"ldap_back_default_urllist(",
		"ldap_back_cancel(",
	)
	for _, anchor := range []string{
		"*urltail = *urllist;",
		"*urllist = *url;",
		"*url = NULL;",
		"ldap_get_option( ld, LDAP_OPT_URI, (void *)&li->li_uri );",
	} {
		if !strings.Contains(section, anchor) {
			t.Fatalf("pinned LDAP URI selection source lacks %q", anchor)
		}
	}

	initPath := filepath.Join(sourceRoot, "servers", "slapd", "back-ldap", "init.c")
	initContents, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP source %s: %v", initPath, err)
	}
	if got, want := fmt.Sprintf("%x", sha256.Sum256(initContents)),
		"8ec3c11de464911167c7cb247dc9ba16cb9fcae67a14408034274828aa3ad6b5"; got != want {
		t.Fatalf("pinned OpenLDAP source %s SHA-256 = %s, want %s", initPath, got, want)
	}
	for _, anchor := range []string{
		"li->li_urllist_f = ldap_back_default_urllist;",
		"li->li_urllist_p = li;",
	} {
		if !strings.Contains(string(initContents), anchor) {
			t.Fatalf("pinned LDAP URI selection initialization lacks %q", anchor)
		}
	}
}
