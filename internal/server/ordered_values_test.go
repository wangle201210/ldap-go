package server

import (
	"context"
	"reflect"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSchemaModificationMaintainsOrderedValueIndexes(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []string{"authzTo", "olcAccess"} {
		if !registry.HasOrderedValues(attribute) {
			t.Fatalf("%s is not registered as X-ORDERED VALUES", attribute)
		}
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{
		Description: "authzTo",
		Values: stringValues(
			"{0}dn:uid=first,dc=example,dc=com",
			"{1}dn:uid=second,dc=example,dc=com",
		),
	}}}
	add := ldapwire.Modification{
		Operation: ldapwire.ModificationAdd,
		Attribute: directory.Attribute{
			Description: "authzTo",
			Values:      stringValues("{1}dn:uid=inserted,dc=example,dc=com"),
		},
	}
	if err := applyModificationWithSchema(&entry, add, registry); err != nil {
		t.Fatal(err)
	}
	assertOrderedServerValues(t, entry.Values("authzTo"), []string{
		"{0}dn:uid=first,dc=example,dc=com",
		"{1}dn:uid=inserted,dc=example,dc=com",
		"{2}dn:uid=second,dc=example,dc=com",
	})
	deleteFirst := ldapwire.Modification{
		Operation: ldapwire.ModificationDelete,
		Attribute: directory.Attribute{
			Description: "authzTo",
			Values:      stringValues("{0}"),
		},
	}
	if err := applyModificationWithSchema(&entry, deleteFirst, registry); err != nil {
		t.Fatal(err)
	}
	assertOrderedServerValues(t, entry.Values("authzTo"), []string{
		"{0}dn:uid=inserted,dc=example,dc=com",
		"{1}dn:uid=second,dc=example,dc=com",
	})
	replace := ldapwire.Modification{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{
			Description: "authzTo",
			Values: stringValues(
				"{1}dn:uid=last,dc=example,dc=com",
				"{0}dn:uid=first,dc=example,dc=com",
			),
		},
	}
	if err := applyModificationWithSchema(&entry, replace, registry); err != nil {
		t.Fatal(err)
	}
	assertOrderedServerValues(t, entry.Values("authzTo"), []string{
		"{0}dn:uid=first,dc=example,dc=com",
		"{1}dn:uid=last,dc=example,dc=com",
	})
}

func TestOnlineConfigMaintainsOrderedAccessValues(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOfflineToolStore(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={0}config,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRootPW", stringValues("config-secret"))
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	target := "olcDatabase={1}mdb,cn=config"

	replace := ldap.NewModifyRequest(target, nil)
	replace.Replace("olcAccess", []string{
		"to attrs=description by * read",
		"to * by users read by * none",
	})
	if err := client.Modify(replace); err != nil {
		t.Fatalf("Replace(unindexed): %v", err)
	}
	assertOnlineOrderedAccess(t, client, target, []string{
		"{0}to attrs=description by * read",
		"{1}to * by users read by * none",
	})

	insert := ldap.NewModifyRequest(target, nil)
	insert.Add("olcAccess", []string{"{1}to attrs=cn by * search"})
	if err := client.Modify(insert); err != nil {
		t.Fatalf("Add(indexed): %v", err)
	}
	assertOnlineOrderedAccess(t, client, target, []string{
		"{0}to attrs=description by * read",
		"{1}to attrs=cn by * search",
		"{2}to * by users read by * none",
	})

	deleteFirst := ldap.NewModifyRequest(target, nil)
	deleteFirst.Delete("olcAccess", []string{"{0}"})
	if err := client.Modify(deleteFirst); err != nil {
		t.Fatalf("Delete(index): %v", err)
	}
	assertOnlineOrderedAccess(t, client, target, []string{
		"{0}to attrs=cn by * search",
		"{1}to * by users read by * none",
	})

	reorder := ldap.NewModifyRequest(target, nil)
	reorder.Replace("olcAccess", []string{
		"{1}to * by users read by * none",
		"{0}to attrs=mail by * read",
	})
	if err := client.Modify(reorder); err != nil {
		t.Fatalf("Replace(indexed): %v", err)
	}
	assertOnlineOrderedAccess(t, client, target, []string{
		"{0}to attrs=mail by * read",
		"{1}to * by users read by * none",
	})
}

func TestOpenLDAPReferenceOrderedConfigValues(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI := startOpenLDAPDynamicConfigReferralServer(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOfflineToolStore(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={0}config,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.GetIn(storage.OpenLDAPConfigPartition, dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRootPW", stringValues("config-secret"))
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()

	reference := runOrderedConfigScenario(t, referenceURI)
	implementation := runOrderedConfigScenario(t, "ldap://"+address)
	if !reflect.DeepEqual(implementation, reference) {
		t.Fatalf("ordered config values:\nldap-go:  %q\nOpenLDAP: %q", implementation, reference)
	}
}

func runOrderedConfigScenario(t *testing.T, uri string) [][]string {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}
	target := "olcDatabase={1}mdb,cn=config"
	var observations [][]string
	apply := func(request *ldap.ModifyRequest) {
		t.Helper()
		if err := client.Modify(request); err != nil {
			t.Fatalf("Modify(%s): %v", uri, err)
		}
		observations = append(
			observations,
			readOnlineOrderedAccess(t, client, target),
		)
	}
	replace := ldap.NewModifyRequest(target, nil)
	replace.Replace("olcAccess", []string{
		"to attrs=description by * read",
		"to * by users read by * none",
	})
	apply(replace)
	insert := ldap.NewModifyRequest(target, nil)
	insert.Add("olcAccess", []string{"{1}to attrs=cn by * search"})
	apply(insert)
	deleteFirst := ldap.NewModifyRequest(target, nil)
	deleteFirst.Delete("olcAccess", []string{"{0}"})
	apply(deleteFirst)
	reorder := ldap.NewModifyRequest(target, nil)
	reorder.Replace("olcAccess", []string{
		"{1}to * by users read by * none",
		"{0}to attrs=mail by * read",
	})
	apply(reorder)
	return observations
}

func assertOnlineOrderedAccess(
	t *testing.T,
	client *ldap.Conn,
	target string,
	want []string,
) {
	t.Helper()
	got := readOnlineOrderedAccess(t, client, target)
	if !slices.Equal(got, want) {
		t.Fatalf("olcAccess = %q, want %q", got, want)
	}
}

func readOnlineOrderedAccess(
	t *testing.T,
	client *ldap.Conn,
	target string,
) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		target,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"olcAccess"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search(olcAccess) = %#v, %v", result, err)
	}
	return result.Entries[0].GetAttributeValues("olcAccess")
}

func assertOrderedServerValues(t *testing.T, values [][]byte, want []string) {
	t.Helper()
	got := make([]string, len(values))
	for index := range values {
		got[index] = string(values[index])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ordered values = %q, want %q", got, want)
	}
}
