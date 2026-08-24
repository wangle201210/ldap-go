package server

import (
	"context"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPMatchedValuesDN = "uid=values,ou=people,dc=example,dc=com"

func TestOpenLDAPReferenceMatchedValuesControl(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`access to attrs=userPassword
    by anonymous auth
    by self write
    by * none
access to *
    by * read`,
		`
dn: uid=values,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: values
cn: Alice Example
cn: Directory Admin
cn;lang-en: Alice English
cn;lang-fr: Alice French
sn: Values
mail: alice@example.com
mail: alice@other.test
mail: admin@example.com
userPassword: secret
`,
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: openLDAPMatchedValuesDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "person", "organizationalPerson", "inetOrgPerson")},
				{Description: "uid", Values: stringValues("values")},
				{Description: "cn", Values: stringValues("Alice Example", "Directory Admin")},
				{Description: "cn;lang-en", Values: stringValues("Alice English")},
				{Description: "cn;lang-fr", Values: stringValues("Alice French")},
				{Description: "sn", Values: stringValues("Values")},
				{Description: "mail", Values: stringValues("alice@example.com", "alice@other.test", "admin@example.com")},
				{Description: "userPassword", Values: stringValues("secret")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed ldap-go matched values entry: %v", err)
	}
	goAddress, stopGo := startServer(t, store, Config{})
	t.Cleanup(stopGo)

	for _, test := range []struct {
		name       string
		filters    []string
		attributes []string
		typesOnly  bool
	}{
		{
			name:       "union",
			filters:    []string{"(mail=*@example.com)", "(cn=Alice*)"},
			attributes: []string{"mail", "cn", "sn"},
		},
		{
			name:       "unknown attribute computes false",
			filters:    []string{"(notInSchema=value)"},
			attributes: []string{"mail", "cn"},
		},
		{
			name:       "unknown complex choice computes false",
			filters:    []string{"(&(cn=Alice Example)(mail=alice@example.com))"},
			attributes: []string{"mail", "cn"},
		},
		{
			name:       "numeric OID matches attribute alias",
			filters:    []string{"(2.5.4.3=Alice Example)"},
			attributes: []string{"cn"},
		},
		{
			name:       "attribute options remain distinct",
			filters:    []string{"(cn;lang-en=Alice English)"},
			attributes: []string{"cn;lang-en", "cn;lang-fr"},
		},
		{
			name:       "OpenLDAP approx item is inert",
			filters:    []string{"(cn~=Alice Example)"},
			attributes: []string{"cn"},
		},
		{
			name:       "empty sequence is inert",
			attributes: []string{"mail", "cn"},
		},
		{
			name:       "typesOnly is inert",
			filters:    []string{"(mail=does-not-match)"},
			attributes: []string{"mail", "cn", "sn"},
			typesOnly:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeMatchedValuesSearch(
				t,
				trimLDAPURI(referenceURI),
				test.filters,
				test.attributes,
				test.typesOnly,
			)
			implementation := observeMatchedValuesSearch(
				t,
				goAddress,
				test.filters,
				test.attributes,
				test.typesOnly,
			)
			if !matchedValuesObservationsEqual(reference, implementation) {
				t.Fatalf(
					"matched values mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					implementation,
				)
			}
		})
	}
}

func observeMatchedValuesSearch(
	t *testing.T,
	address string,
	filters, attributes []string,
	typesOnly bool,
) map[string][]string {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	if err := client.Bind(openLDAPMatchedValuesDN, "secret"); err != nil {
		t.Fatalf("Bind(%s): %v", address, err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPMatchedValuesDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		typesOnly,
		"(objectClass=*)",
		attributes,
		[]ldap.Control{matchedValuesControl(t, true, filters...)},
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("matched values Search(%s) = %#v, %v", address, result, err)
	}
	observation := make(map[string][]string, len(result.Entries[0].Attributes))
	for _, attribute := range result.Entries[0].Attributes {
		values := append([]string(nil), attribute.Values...)
		slices.Sort(values)
		observation[attribute.Name] = values
	}
	return observation
}

func matchedValuesObservationsEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for description, values := range left {
		if !slices.Equal(values, right[description]) {
			return false
		}
	}
	return true
}
