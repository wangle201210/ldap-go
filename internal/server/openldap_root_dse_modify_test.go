package server

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceRootDSEOnlineRemoval(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	reference := startOpenLDAPDynamicConfigReferralServer(t, tools)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	first, second := filepath.Join(t.TempDir(), "first.ldif"), filepath.Join(t.TempDir(), "second.ldif")
	writeRootDSETestFile(t, first, "dn:\ndescription: first\n")
	writeRootDSETestFile(t, second, "dn:\ndescription: second\n")
	var clients []*ldap.Conn
	for _, uri := range []string{reference, "ldap://" + address} {
		client, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Bind("cn=config", "config-secret"); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	type observation struct {
		code               uint16
		diagnostic         string
		files, description []string
	}
	for _, test := range []struct {
		name      string
		operation uint
		attribute string
		values    []string
	}{
		{"delete absent", ldap.DeleteAttribute, "olcRootDSE", []string{first}},
		{"empty replace absent", ldap.ReplaceAttribute, "olcRootDSE", nil},
		{"replace absent", ldap.ReplaceAttribute, "olcRootDSE", []string{first}},
		{"add first", ldap.AddAttribute, "olcRootDSE", []string{first}},
		{"replace same", ldap.ReplaceAttribute, "olcRootDSE", []string{first}},
		{"replace different", ldap.ReplaceAttribute, "olcRootDSE", []string{second}},
		{"delete missing value", ldap.DeleteAttribute, "olcRootDSE", []string{"missing"}},
		{"delete existing value", ldap.DeleteAttribute, "olcRootDSE", []string{first}},
		{"delete attribute", ldap.DeleteAttribute, "olcRootDSE", nil},
		{"append second", ldap.AddAttribute, "olcRootDSE", []string{second}},
		{"delete first of two", ldap.DeleteAttribute, "olcRootDSE", []string{first}},
		{"delete second of two", ldap.DeleteAttribute, "olcRootDSE", []string{second}},
		{"delete both values", ldap.DeleteAttribute, "olcRootDSE", []string{first, second}},
		{"delete two-value attribute", ldap.DeleteAttribute, "olcRootDSE", nil},
		{"empty replace existing", ldap.ReplaceAttribute, "olcRootDSE", nil},
		{"delete second by OID", ldap.DeleteAttribute, "1.3.6.1.4.1.4203.1.12.2.3.0.51", []string{second}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var observations []observation
			for _, client := range clients {
				request := ldap.NewModifyRequest("cn=config", nil)
				request.Changes = []ldap.Change{{Operation: test.operation, Modification: ldap.PartialAttribute{Type: test.attribute, Vals: test.values}}}
				err := client.Modify(request)
				var ldapFailure *ldap.Error
				diagnostic := ""
				if errors.As(err, &ldapFailure) && ldapFailure.Err != nil {
					diagnostic = ldapFailure.Err.Error()
				}
				result, readErr := client.Search(ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 2, false,
					"(objectClass=*)", []string{"olcRootDSE"}, nil))
				if readErr != nil || len(result.Entries) != 1 {
					t.Fatalf("configuration read: %v %v", result, readErr)
				}
				observations = append(observations, observation{code: ldapOperationResultCode(err), diagnostic: diagnostic,
					files:       result.Entries[0].GetAttributeValues("olcRootDSE"),
					description: searchRootDSEConfigurationEntry(t, client).GetAttributeValues("description")})
				t.Logf("endpoint=%d modify=%v", len(observations)-1, err)
			}
			if !reflect.DeepEqual(observations[0], observations[1]) {
				t.Fatalf("OpenLDAP=%#v ldap-go=%#v", observations[0], observations[1])
			}
		})
	}
}
