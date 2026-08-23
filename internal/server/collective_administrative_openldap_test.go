package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceCollectiveAdministrativeAreaDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	assertPinnedOpenLDAPCollectiveAdministrativeReference(t)

	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"attributetype ( 1.2.3.4 NAME 'c-description' SUP description COLLECTIVE )",
		"",
		"",
	)
	defer stopReference()
	reference := bindOverlayReferenceClient(t, referenceURI, "secret")
	defer reference.Close()

	referenceSource := ldap.NewAddRequest(
		"cn=collective,ou=people,dc=example,dc=com",
		nil,
	)
	referenceSource.Attribute(
		"objectClass",
		[]string{"subentry", "collectiveAttributeSubentry"},
	)
	referenceSource.Attribute("cn", []string{"collective"})
	referenceSource.Attribute("subtreeSpecification", []string{"{}"})
	referenceSource.Attribute("c-description", []string{"shared"})
	if code := collectLDAPResultCode(t, reference.Add(referenceSource)); code != ldap.LDAPResultInvalidAttributeSyntax {
		t.Fatalf(
			"OpenLDAP collectiveAttributeSubentry result = %d, want %d",
			code,
			ldap.LDAPResultInvalidAttributeSyntax,
		)
	}

	role := ldap.NewModifyRequest("ou=people,dc=example,dc=com", nil)
	role.Add("administrativeRole", []string{"collectiveAttributeSpecificArea"})
	if code := collectLDAPResultCode(t, reference.Modify(role)); code != ldap.LDAPResultInvalidAttributeSyntax {
		t.Fatalf("OpenLDAP administrativeRole result = %d, want %d", code, ldap.LDAPResultInvalidAttributeSyntax)
	}
	referenceEntry := collectiveAdministrativeSearchEntry(
		t,
		reference,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if values := referenceEntry.GetAttributeValues("c-description"); len(values) != 0 {
		t.Fatalf("OpenLDAP unexpectedly derived X.501 collective values: %q", values)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	setCollectiveAdministrativeRoles(
		t,
		store,
		"ou=people,dc=example,dc=com",
		"collectiveAttributeSpecificArea",
	)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Schema:       collectiveServerRegistry(t),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(ldap-go): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(ldap-go): %v", err)
	}
	source := ldap.NewAddRequest("cn=collective,ou=people,dc=example,dc=com", nil)
	source.Attribute("objectClass", []string{"subentry", "collectiveAttributeSubentry"})
	source.Attribute("cn", []string{"collective"})
	source.Attribute("subtreeSpecification", []string{"{}"})
	source.Attribute("c-description", []string{"shared"})
	if err := client.Add(source); err != nil {
		t.Fatalf("Add(ldap-go collective subentry): %v", err)
	}
	entry := collectiveAdministrativeSearchEntry(
		t,
		client,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if got := entry.GetAttributeValue("c-description"); got != "shared" {
		t.Fatalf("ldap-go X.501 collective value = %q, want shared", got)
	}
}

func assertPinnedOpenLDAPCollectiveAdministrativeReference(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" ||
		os.Getenv("OPENLDAP_ACTUAL_VERSION") != openLDAPCollectVersion ||
		os.Getenv("OPENLDAP_COMMIT") != openLDAPCollectCommit {
		t.Fatal("collective administrative differential requires pinned OpenLDAP 2.6.13")
	}
	sourcePath := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"servers",
		"slapd",
		"schema_prep.c",
	)
	contents, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read pinned schema_prep.c: %v", err)
	}
	for _, anchor := range []string{
		"administrativeRoleAttribute",
		`attribute \"%s\" not supported!`,
	} {
		if !strings.Contains(string(contents), anchor) {
			t.Fatalf("pinned schema_prep.c lacks %q", anchor)
		}
	}
}

func collectiveAdministrativeSearchEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"c-description", "collectiveAttributeSubentries"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%q): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%q) entries = %d, want 1", dn, len(result.Entries))
	}
	return result.Entries[0]
}
