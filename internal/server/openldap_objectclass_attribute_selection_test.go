package server

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
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

	for _, oid := range []string{preReadControlOID, postReadControlOID} {
		for _, critical := range []bool{true, false} {
			for _, attributes := range [][]string{
				{"@person"}, {"@inetOrgPerson"}, {"@2.16.840.1.113730.3.2.2"},
				{"@notInSchema"}, {"@extensibleObject"}, {"@person", "description"},
				{"1.1", "@person"}, {"cn", "description"},
				{"@"}, {"@ person"}, {"@person "}, {"@person;x-test"},
			} {
				if !critical && slices.ContainsFunc(attributes, func(attribute string) bool {
					return strings.HasPrefix(attribute, "@")
				}) {
					// 2.6.13 keeps these names in a freed BER buffer. Compare only
					// defined native behavior; the safe projection has local tests.
					// TestOpenLDAPReadControlNameLifetimeSource pins this exception.
					continue
				}
				t.Run(fmt.Sprintf("read/%s/critical=%t/%v", oid, critical, attributes), func(t *testing.T) {
					reference := observeObjectClassAttributeSelectionReadControls(
						t, trimLDAPURI(referenceURI), oid, critical, attributes,
					)
					implementation := observeObjectClassAttributeSelectionReadControls(
						t, goAddress, oid, critical, attributes,
					)
					if !reflect.DeepEqual(reference, implementation) {
						t.Fatalf("read-control mismatch\nOpenLDAP: %#v\nldap-go: %#v", reference, implementation)
					}
				})
			}
		}
	}

	for _, test := range []struct {
		name      string
		oid       string
		operation *ber.Packet
	}{
		{"Add", postReadControlOID, rawAddRequest(readControlTestEntry("uid=ocselect-added,ou=people,dc=example,dc=com", "ocselect-added"))},
		{"Modify missing", preReadControlOID, rawModifyReplaceRequest("uid=ocselect-missing,ou=people,dc=example,dc=com", "description", "unreachable")},
		{"Delete", preReadControlOID, rawDeleteRequest(openLDAPObjectClassSelectionDN)},
		{"Delete missing", preReadControlOID, rawDeleteRequest("uid=ocselect-missing,ou=people,dc=example,dc=com")},
		{"ModifyDN pre", preReadControlOID, rawModifyDNRequest(openLDAPObjectClassSelectionDN, "uid=ocselect-renamed", true)},
		{"ModifyDN post", postReadControlOID, rawModifyDNRequest(openLDAPObjectClassSelectionDN, "uid=ocselect-renamed", true)},
	} {
		t.Run("read/write rejection/"+test.name, func(t *testing.T) {
			for _, address := range []string{trimLDAPURI(referenceURI), goAddress} {
				client, err := ldap.DialURL("ldap://" + address)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
					t.Fatal(err)
				}
				search := ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree,
					ldap.NeverDerefAliases, 0, 0, false, "(uid=ocselect*)", []string{"*", "+"}, nil)
				before, err := client.Search(search)
				if err != nil || len(before.Entries) != 1 {
					t.Fatalf("read original entries = %#v, %v", before, err)
				}
				connection := dialAndBindRawLDAP(t, address, "cn=admin,dc=example,dc=com", "secret")
				defer connection.Close()
				response := sendRawLDAPOperation(t, connection, 2, test.operation,
					rawReadControl(test.oid, true, "@person"))
				assertRawLDAPResult(t, response, int64(ldap.LDAPResultUndefinedAttributeType))
				if diagnostic := rawLDAPDiagnostic(response); diagnostic != "AttributeDescription contains inappropriate characters" {
					t.Fatalf("read-control diagnostic = %q", diagnostic)
				}
				after, err := client.Search(search)
				if err != nil || !reflect.DeepEqual(before.Entries, after.Entries) {
					t.Fatalf("rejected read control changed entries or operational attributes: before=%#v after=%#v err=%v", before, after, err)
				}
			}
		})
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
	code       uint16
	diagnostic string
	attributes map[string][]string
	stored     string
}

func observeObjectClassAttributeSelectionReadControls(
	t *testing.T,
	address string,
	oid string,
	critical bool,
	attributes []string,
) objectClassSelectionReadObservation {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	reset := ldap.NewModifyRequest(openLDAPObjectClassSelectionDN, nil)
	reset.Replace("description", []string{"before read control"})
	if err := client.Modify(reset); err != nil {
		t.Fatal(err)
	}
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
		rawReadControl(oid, critical, attributes...),
	)
	observation := objectClassSelectionReadObservation{
		code:       uint16(rawLDAPResultCode(t, response.Children[1])),
		diagnostic: rawLDAPDiagnostic(response),
	}
	wantCode := uint16(ldap.LDAPResultSuccess)
	for _, attribute := range attributes {
		if critical && strings.HasPrefix(attribute, "@") {
			wantCode = uint16(ldap.LDAPResultUndefinedAttributeType)
		}
	}
	if observation.code != wantCode {
		t.Fatalf("read-control result = %#v, want code %d", observation, wantCode)
	}
	if observation.code == uint16(ldap.LDAPResultSuccess) {
		entry := rawReadControlEntry(t, response, oid)
		if entry.DN != openLDAPObjectClassSelectionDN {
			t.Fatalf("read-control DN = %q", entry.DN)
		}
		observation.attributes = objectClassSelectionEntryAttributes(
			entry,
		)
	} else if len(response.Children) != 2 {
		t.Fatalf("failed read-control returned controls: %#v", response)
	}
	result, err := client.Search(ldap.NewSearchRequest(openLDAPObjectClassSelectionDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"description"}, nil))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read persisted entry = %#v, %v", result, err)
	}
	observation.stored = result.Entries[0].GetAttributeValue("description")
	wantStored := "before read control"
	if wantCode == uint16(ldap.LDAPResultSuccess) {
		wantStored = "RFC 4529 read control"
	}
	if observation.stored != wantStored {
		t.Fatalf("persisted description = %q, want %q", observation.stored, wantStored)
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
