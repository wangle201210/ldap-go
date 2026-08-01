package server

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientDITStructureRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	registry := serverDITStructureRegistry(t)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Schema:       registry,
	})
	defer stop()
	client := bindContentRuleClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer client.Close()

	assertPublishedDITStructureSchema(t, client)

	validDN := "uid=structured,ou=people,dc=example,dc=com"
	valid := structureRulePersonAdd(validDN, "structured")
	valid.Attribute("governingStructureRule", []string{"999"})
	if err := client.Add(valid); err != nil {
		t.Fatalf("Add(valid governed entry): %v", err)
	}
	assertGoverningStructureRule(t, client, validDN, "3")

	invalidName := structureRulePersonAdd(
		"cn=wrong-rdn,ou=people,dc=example,dc=com",
		"wrong-rdn",
	)
	assertLDAPResultCode(
		t,
		client.Add(invalidName),
		ldap.LDAPResultNamingViolation,
	)

	wrongParent := structureRulePersonAdd(
		"uid=wrong-parent,dc=example,dc=com",
		"wrong-parent",
	)
	assertLDAPResultCode(
		t,
		client.Add(wrongParent),
		ldap.LDAPResultNamingViolation,
	)

	invalidRename := ldap.NewModifyDNRequest(
		validDN,
		"cn=Structured",
		false,
		"",
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(invalidRename),
		ldap.LDAPResultNamingViolation,
	)
	assertGoverningStructureRule(t, client, validDN, "3")

	renamedDN := "uid=renamed,ou=people,dc=example,dc=com"
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		validDN,
		"uid=renamed",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(valid governed rename): %v", err)
	}
	assertGoverningStructureRule(t, client, renamedDN, "3")

	invalidMove := ldap.NewModifyDNRequest(
		renamedDN,
		"uid=renamed",
		true,
		"dc=example,dc=com",
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(invalidMove),
		ldap.LDAPResultNamingViolation,
	)
	assertGoverningStructureRule(t, client, renamedDN, "3")

	modifyClass := ldap.NewModifyRequest(renamedDN, nil)
	modifyClass.Replace("objectClass", []string{"person", "extensibleObject"})
	assertLDAPResultCode(
		t,
		client.Modify(modifyClass),
		ldap.LDAPResultNamingViolation,
	)
	assertGoverningStructureRule(t, client, renamedDN, "3")

	modifyClass.Controls = []ldap.Control{relaxLDAPControl()}
	if err := client.Modify(modifyClass); err != nil {
		t.Fatalf("Modify(relaxed invalid name form): %v", err)
	}
	assertGoverningStructureRule(t, client, renamedDN, "")

	relaxedDN := "cn=relaxed,ou=people,dc=example,dc=com"
	relaxed := structureRulePersonAdd(relaxedDN, "relaxed")
	relaxed.Controls = []ldap.Control{relaxLDAPControl()}
	if err := client.Add(relaxed); err != nil {
		t.Fatalf("Add(relaxed invalid name form): %v", err)
	}
	assertGoverningStructureRule(t, client, relaxedDN, "")
}

func serverDITStructureRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( 1.3.6.1.4.1.99999.20 NAME 'domainNameForm' OC domain MUST dc )",
		"( 1.3.6.1.4.1.99999.21 NAME 'ouNameForm' OC organizationalUnit MUST ou )",
		"( 1.3.6.1.4.1.99999.22 NAME 'inetPersonNameForm' OC inetOrgPerson MUST uid MAY cn )",
		"( 1.3.6.1.4.1.99999.23 NAME 'personNameForm' OC person MUST cn MAY uid )",
	} {
		if err := registry.ParseAndRegisterNameForm(description); err != nil {
			t.Fatalf("register name form: %v", err)
		}
	}
	for _, description := range []string{
		"( 1 NAME 'domainRule' FORM domainNameForm )",
		"( 2 NAME 'ouRule' FORM ouNameForm SUP 1 )",
		"( 3 NAME 'inetPersonRule' FORM inetPersonNameForm SUP 2 )",
		"( 4 NAME 'personRule' FORM personNameForm SUP 2 )",
	} {
		if err := registry.ParseAndRegisterDITStructureRule(description); err != nil {
			t.Fatalf("register DIT structure rule: %v", err)
		}
	}
	return registry
}

func structureRulePersonAdd(dn, uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{"User"})
	return request
}

func relaxLDAPControl() ldap.Control {
	return &ldap.ControlString{
		ControlType: relaxControlOID,
		Criticality: true,
	}
}

func assertGoverningStructureRule(
	t *testing.T,
	client *ldap.Conn,
	dn,
	want string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"governingStructureRule"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%s governingStructureRule): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s) entries = %d", dn, len(result.Entries))
	}
	if got := result.Entries[0].GetAttributeValue(
		"governingStructureRule",
	); got != want {
		t.Fatalf("%s governingStructureRule = %q, want %q", dn, got, want)
	}
}

func assertPublishedDITStructureSchema(t *testing.T, client *ldap.Conn) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"cn=Subschema",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"nameForms", "dITStructureRules", "attributeTypes"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(cn=Subschema structure schema): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("subschema entries = %d", len(result.Entries))
	}
	entry := result.Entries[0]
	for attribute, fragment := range map[string]string{
		"nameForms":         "NAME 'inetPersonNameForm'",
		"dITStructureRules": "NAME 'inetPersonRule'",
		"attributeTypes":    "NAME 'governingStructureRule'",
	} {
		found := false
		for _, value := range entry.GetAttributeValues(attribute) {
			if strings.Contains(value, fragment) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s does not contain %q: %#v", attribute, fragment, entry)
		}
	}
	for _, filter := range []string{
		"(nameForms=1.3.6.1.4.1.99999.22)",
		"(dITStructureRules=3)",
	} {
		filtered, err := client.Search(ldap.NewSearchRequest(
			"cn=Subschema",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"cn"},
			nil,
		))
		if err != nil || len(filtered.Entries) != 1 {
			t.Fatalf("Search(cn=Subschema, %s) = %#v, %v", filter, filtered, err)
		}
	}
}
