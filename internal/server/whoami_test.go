package server

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientWhoAmI(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	result, err := client.WhoAmI(nil)
	if err != nil {
		t.Fatalf("anonymous WhoAmI(): %v", err)
	}
	if result.AuthzID != "" {
		t.Fatalf("anonymous authzID = %q", result.AuthzID)
	}
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	result, err = client.WhoAmI(nil)
	if err != nil {
		t.Fatalf("authenticated WhoAmI(): %v", err)
	}
	if result.AuthzID != "dn:"+aliceDN {
		t.Fatalf("authenticated authzID = %q", result.AuthzID)
	}

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension", "supportedFeatures"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedExtension"),
			whoAmIOID,
		) ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedExtension"),
			cancelOID,
		) ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedFeatures"),
			absoluteFiltersFeatureOID,
		) {
		t.Fatalf("Who Am I Root DSE = %#v, %v", rootDSE, err)
	}
}

func TestLDAPClientWhoAmIRejectsRequestValue(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	value := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		"",
		"requestValue",
	)
	_, err = client.Extended(ldap.NewExtendedRequest(whoAmIOID, value))
	assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
}
