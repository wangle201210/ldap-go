package server

import (
	"context"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientObjectClassAttributeSelection(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	alice := readStoredEntry(t, store, aliceDN)
	alice.Attributes = append(alice.Attributes, directory.Attribute{
		Description: "description;lang-en",
		Values:      stringValues("English description"),
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(alice, true)
	}); err != nil {
		t.Fatalf("seed optioned attribute: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	for _, test := range []struct {
		name       string
		attributes []string
		present    []string
		absent     []string
		typesOnly  bool
	}{
		{
			name:       "RFC selector",
			attributes: []string{"@inetOrgPerson"},
			present:    []string{"objectClass", "uid", "cn", "sn", "jpegPhoto", "description;lang-en"},
			absent:     []string{"userPassword"},
		},
		{
			name:       "inherited person attributes",
			attributes: []string{"@person"},
			present:    []string{"objectClass", "cn", "sn", "description;lang-en"},
			absent:     []string{"uid", "jpegPhoto", "userPassword"},
		},
		{
			name:       "numeric object class OID",
			attributes: []string{"@2.16.840.1.113730.3.2.2"},
			present:    []string{"objectClass", "uid", "cn", "sn", "jpegPhoto", "description;lang-en"},
		},
		{
			name:       "plus class is an unknown attribute",
			attributes: []string{"+person"},
			absent:     []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
		},
		{
			name:       "bang class is an unknown attribute",
			attributes: []string{"!person"},
			absent:     []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
		},
		{
			name:       "extensible object",
			attributes: []string{"@extensibleObject"},
			present:    []string{"objectClass", "uid", "cn", "sn", "jpegPhoto", "description;lang-en", "subschemaSubentry"},
			absent:     []string{"userPassword"},
		},
		{
			name:       "no attributes plus class",
			attributes: []string{"1.1", "@person"},
			present:    []string{"objectClass", "cn", "sn", "description;lang-en"},
			absent:     []string{"uid", "jpegPhoto", "userPassword"},
		},
		{
			name:       "unknown class",
			attributes: []string{"@notInSchema"},
			absent:     []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
		},
		{
			name:       "unsupported object class option",
			attributes: []string{"@inetOrgPerson;x-test"},
			absent:     []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
		},
		{
			name:       "leading whitespace is unknown",
			attributes: []string{"@ person"},
			absent:     []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
		},
		{
			name:       "trailing whitespace is unknown",
			attributes: []string{"@person "},
			absent:     []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
		},
		{
			name:       "typesOnly",
			attributes: []string{"@inetOrgPerson"},
			present:    []string{"objectClass", "uid", "cn", "sn", "jpegPhoto"},
			typesOnly:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := client.Search(ldap.NewSearchRequest(
				"uid=alice,ou=people,dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				test.typesOnly,
				"(objectClass=*)",
				test.attributes,
				nil,
			))
			if err != nil || len(result.Entries) != 1 {
				t.Fatalf("Search() = %#v, %v", result, err)
			}
			entry := result.Entries[0]
			for _, attribute := range test.present {
				if !entryHasLDAPAttribute(entry, attribute) {
					t.Errorf("attribute %q is absent: %#v", attribute, entry.Attributes)
				}
				if test.typesOnly && len(entry.GetRawAttributeValues(attribute)) != 0 {
					t.Errorf("typesOnly attribute %q has values", attribute)
				}
			}
			for _, attribute := range test.absent {
				if entryHasLDAPAttribute(entry, attribute) {
					t.Errorf("attribute %q is present: %#v", attribute, entry.Attributes)
				}
			}
		})
	}
}

func TestRootDSEPublishesObjectClassAttributeSelection(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	result, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedFeatures"}, nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		!slices.Contains(result.Entries[0].GetAttributeValues("supportedFeatures"), objectClassAttributesFeatureOID) {
		t.Fatalf("Root DSE supportedFeatures = %#v, %v", result, err)
	}
}

func TestLDAPReadControlsObjectClassAttributeSelection(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
	t.Cleanup(func() { _ = connection.Close() })

	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(aliceDN, "cn", "Alice RFC 4529"),
		rawReadControl(preReadControlOID, true, "@person"),
		rawReadControl(postReadControlOID, true, "@inetOrgPerson"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	preRead := rawReadControlEntry(t, response, preReadControlOID)
	postRead := rawReadControlEntry(t, response, postReadControlOID)
	if singleRawValue(t, preRead, "cn") != "Alice Example" ||
		singleRawValue(t, postRead, "cn") != "Alice RFC 4529" ||
		!preRead.HasAttribute("sn") || preRead.HasAttribute("uid") ||
		!postRead.HasAttribute("uid") || postRead.HasAttribute("userPassword") {
		t.Fatalf("RFC 4529 read controls = pre %#v, post %#v", preRead, postRead)
	}

	response = sendRawLDAPOperation(
		t,
		connection,
		3,
		rawModifyReplaceRequest(aliceDN, "cn", "must roll back"),
		rawReadControl(postReadControlOID, true, "@notInSchema"),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultUndefinedAttributeType))
	if got := string(readStoredEntry(t, store, aliceDN).Values("cn")[0]); got != "Alice RFC 4529" {
		t.Fatalf("critical unknown-class read control did not roll back: cn=%q", got)
	}
}
