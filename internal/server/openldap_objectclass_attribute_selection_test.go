package server

import (
	"context"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPObjectClassSelectionDN = "uid=ocselect,ou=people,dc=example,dc=com"

func TestOpenLDAPReferenceObjectClassAttributeSelection(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`access to attrs=userPassword
    by anonymous auth
    by self =xw
    by * none
access to *
    by * read`,
		`
dn: uid=ocselect,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: ocselect
cn: Object Class Selection
sn: Selection
description: RFC 4529 fixture
description;lang-en: English description
telephoneNumber: +1 555 0100
mail: ocselect@example.com
jpegPhoto:: AP8Q
userPassword: secret
`,
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: openLDAPObjectClassSelectionDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "person", "organizationalPerson", "inetOrgPerson")},
				{Description: "uid", Values: stringValues("ocselect")},
				{Description: "cn", Values: stringValues("Object Class Selection")},
				{Description: "sn", Values: stringValues("Selection")},
				{Description: "description", Values: stringValues("RFC 4529 fixture")},
				{Description: "description;lang-en", Values: stringValues("English description")},
				{Description: "telephoneNumber", Values: stringValues("+1 555 0100")},
				{Description: "mail", Values: stringValues("ocselect@example.com")},
				{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
				{Description: "userPassword", Values: stringValues("secret")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed ldap-go RFC 4529 entry: %v", err)
	}
	goAddress, stopGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopGo)

	for _, test := range []struct {
		name       string
		attributes []string
		typesOnly  bool
	}{
		{name: "RFC class", attributes: []string{"@inetOrgPerson"}},
		{name: "inherited class", attributes: []string{"@person"}},
		{name: "numeric OID", attributes: []string{"@2.16.840.1.113730.3.2.2"}},
		{name: "plus class is unknown", attributes: []string{"+person"}},
		{name: "bang class is unknown", attributes: []string{"!person"}},
		{name: "extensible object", attributes: []string{"@extensibleObject"}},
		{name: "unknown class", attributes: []string{"@notInSchema"}},
		{name: "unsupported option", attributes: []string{"@inetOrgPerson;x-test"}},
		{name: "leading whitespace", attributes: []string{"@ person"}},
		{name: "trailing whitespace", attributes: []string{"@person "}},
		{name: "mixed explicit and class", attributes: []string{"@person", "mail"}},
		{name: "no attributes plus class", attributes: []string{"1.1", "@person"}},
		{name: "typesOnly", attributes: []string{"@inetOrgPerson"}, typesOnly: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeObjectClassAttributeSelection(
				t,
				trimLDAPURI(referenceURI),
				test.attributes,
				test.typesOnly,
			)
			implementation := observeObjectClassAttributeSelection(
				t,
				goAddress,
				test.attributes,
				test.typesOnly,
			)
			if !objectClassSelectionEqual(reference, implementation) {
				t.Fatalf(
					"RFC 4529 mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					implementation,
				)
			}
		})
	}

	referenceRead := observeObjectClassAttributeSelectionReadControls(
		t,
		trimLDAPURI(referenceURI),
	)
	implementationRead := observeObjectClassAttributeSelectionReadControls(t, goAddress)
	if referenceRead.code != uint16(ldap.LDAPResultUndefinedAttributeType) {
		t.Fatalf("OpenLDAP RFC 4529 read-control result = %#v", referenceRead)
	}
	preCN := implementationRead.pre["cn"]
	postDescription := implementationRead.post["description"]
	if implementationRead.code != uint16(ldap.LDAPResultSuccess) ||
		len(preCN) != 1 || preCN[0] != "Object Class Selection" ||
		len(postDescription) != 1 || postDescription[0] != "RFC 4529 read control" ||
		len(implementationRead.pre["uid"]) != 0 ||
		len(implementationRead.post["uid"]) != 1 {
		t.Fatalf("ldap-go RFC 4529 read-control result = %#v", implementationRead)
	}
}

var objectClassSelectionUserAttributes = map[string]struct{}{
	"objectclass":         {},
	"uid":                 {},
	"cn":                  {},
	"sn":                  {},
	"description":         {},
	"description;lang-en": {},
	"telephonenumber":     {},
	"mail":                {},
	"jpegphoto":           {},
	"userpassword":        {},
}

func observeObjectClassAttributeSelection(
	t *testing.T,
	address string,
	attributes []string,
	typesOnly bool,
) map[string][]string {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	if err := client.Bind(openLDAPObjectClassSelectionDN, "secret"); err != nil {
		t.Fatalf("Bind(%s): %v", address, err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		openLDAPObjectClassSelectionDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		typesOnly,
		"(objectClass=*)",
		attributes,
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("RFC 4529 Search(%s) = %#v, %v", address, result, err)
	}
	observation := map[string][]string{}
	for _, attribute := range result.Entries[0].Attributes {
		name := strings.ToLower(attribute.Name)
		if _, user := objectClassSelectionUserAttributes[name]; !user {
			continue
		}
		values := append([]string(nil), attribute.Values...)
		slices.Sort(values)
		observation[name] = values
	}
	return observation
}

func objectClassSelectionEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for attribute, values := range left {
		if !slices.Equal(values, right[attribute]) {
			return false
		}
	}
	return true
}

type objectClassSelectionReadObservation struct {
	code uint16
	pre  map[string][]string
	post map[string][]string
}

func observeObjectClassAttributeSelectionReadControls(
	t *testing.T,
	address string,
) objectClassSelectionReadObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(
			openLDAPObjectClassSelectionDN,
			"description",
			"RFC 4529 read control",
		),
		rawReadControl(preReadControlOID, true, "@person"),
		rawReadControl(postReadControlOID, true, "@inetOrgPerson"),
	)
	observation := objectClassSelectionReadObservation{
		code: uint16(rawLDAPResultCode(t, response.Children[1])),
	}
	if observation.code == uint16(ldap.LDAPResultSuccess) {
		observation.pre = objectClassSelectionEntryAttributes(
			rawReadControlEntry(t, response, preReadControlOID),
		)
		observation.post = objectClassSelectionEntryAttributes(
			rawReadControlEntry(t, response, postReadControlOID),
		)
	}
	return observation
}

func objectClassSelectionEntryAttributes(entry directory.Entry) map[string][]string {
	observation := map[string][]string{}
	for _, attribute := range entry.Attributes {
		name := strings.ToLower(attribute.Description)
		if _, user := objectClassSelectionUserAttributes[name]; !user {
			continue
		}
		values := make([]string, len(attribute.Values))
		for index := range attribute.Values {
			values[index] = string(attribute.Values[index])
		}
		slices.Sort(values)
		observation[name] = values
	}
	return observation
}
