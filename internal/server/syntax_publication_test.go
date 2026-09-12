package server

import (
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestLDAPSyntaxPublicationSelectionAndReload(t *testing.T) {
	client, config := matchingRulesTestClient(t)
	for _, attrs := range [][]string{nil, {"*"}, {"1.1"}} {
		if len(matchingRulesTestSearch(t, client, attrs, false).GetAttributeValues("ldapSyntaxes")) != 0 {
			t.Fatal("ordinary selection exposed operational syntax descriptions")
		}
	}
	for _, attrs := range [][]string{{"ldapSyntaxes"}, {"1.3.6.1.4.1.1466.101.120.16"}, {"+"}} {
		entry := matchingRulesTestSearch(t, client, attrs, false)
		descriptions := entry.GetAttributeValues("ldapSyntaxes")
		if len(descriptions) < 20 {
			t.Fatalf("missing published syntaxes: %d", len(descriptions))
		}
		seen := make(map[string]schema.LDAPSyntax)
		for _, value := range descriptions {
			parsed, err := schema.ParseLDAPSyntax(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := seen[parsed.OID]; exists {
				t.Fatalf("duplicate syntax %s", parsed.OID)
			}
			seen[parsed.OID] = parsed
		}
		if seen[schema.SyntaxBitString].Description != "Bit String" || seen[schema.SyntaxDirectoryString].Description != "Directory String" {
			t.Fatal("native syntax descriptions absent")
		}
		for _, oid := range []string{schema.SyntaxCSN, schema.SyntaxAuthz, schema.SyntaxOpenLDAPVoid, schema.SyntaxMatchingRule, schema.SyntaxLDAPSyntaxDescription} {
			if _, present := seen[oid]; present {
				t.Fatalf("hidden/native-validatorless syntax published: %s", oid)
			}
		}
		if !slices.Equal(seen[schema.SyntaxCertificate].Extensions["X-BINARY-TRANSFER-REQUIRED"], []string{"TRUE"}) {
			t.Fatal("certificate binary-transfer declaration lost")
		}
		if len(seen[schema.SyntaxPKCS8PrivateKey].Extensions) != 0 {
			t.Fatal("invented metadata from native internal flags")
		}
	}
	entry := matchingRulesTestSearch(t, client, []string{"ldapSyntaxes"}, true)
	if len(entry.Attributes) != 1 || len(entry.Attributes[0].Values) != 0 {
		t.Fatalf("typesOnly=%+v", entry.Attributes)
	}
	const customOID = "1.3.6.1.4.1.99999.932.1"
	add := ldap.NewAddRequest("cn={9}syntax-test,cn=schema,cn=config", nil)
	add.Attribute("objectClass", []string{"olcSchemaConfig"})
	add.Attribute("cn", []string{"{9}syntax-test"})
	add.Attribute("olcLdapSyntaxes", []string{"( " + customOID + " DESC 'test text' X-SUBST '" + schema.SyntaxDirectoryString + "' )"})
	if err := config.Add(add); err != nil {
		t.Fatal(err)
	}
	matched, err := client.Compare("cn=Subschema", "ldapSyntaxes", customOID)
	if err != nil || !matched {
		t.Fatalf("new syntax not published: %v %v", matched, err)
	}
	modify := ldap.NewModifyRequest("cn={9}syntax-test,cn=schema,cn=config", nil)
	modify.Add("olcLdapSyntaxes", []string{"( 1.3.6.1.4.1.99999.932.2 DESC 'invalid substitute' X-SUBST '1.2.3.99999' )"})
	if err := config.Modify(modify); err == nil {
		t.Fatal("invalid substitute committed")
	}
	matched, err = client.Compare("cn=Subschema", "ldapSyntaxes", customOID)
	if err != nil || !matched {
		t.Fatal("failed update replaced syntax snapshot")
	}
}
