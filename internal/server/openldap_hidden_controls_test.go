package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceHiddenControlDiscovery(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServer(t, tools, nil)
	t.Cleanup(stopReference)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	localAddress, stopLocal := startServer(t, store, Config{})
	t.Cleanup(stopLocal)

	for name, address := range map[string]string{
		"OpenLDAP": trimLDAPURI(referenceURI),
		"ldap-go":  localAddress,
	} {
		client, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatalf("DialURL(%s): %v", name, err)
		}
		result, err := client.Search(ldap.NewSearchRequest(
			"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)",
			[]string{"supportedControl", "supportedExtension"}, nil,
		))
		_ = client.Close()
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("%s Root DSE = %#v, %v", name, result, err)
		}
		controls := result.Entries[0].GetAttributeValues("supportedControl")
		for _, hidden := range []string{relaxControlOID, transactionSpecificationControlOID} {
			if containsString(controls, hidden) {
				t.Errorf("%s publishes hidden control %s", name, hidden)
			}
		}
		if name == "ldap-go" {
			extensions := result.Entries[0].GetAttributeValues("supportedExtension")
			if !containsString(extensions, transactionStartOID) ||
				!containsString(extensions, transactionEndOID) {
				t.Errorf("ldap-go transaction extensions = %q", extensions)
			}
		}
	}
}
