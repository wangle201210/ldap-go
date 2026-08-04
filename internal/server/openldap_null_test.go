package server

import (
	"context"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type nullReferenceSearch struct {
	base       string
	scope      int
	filter     string
	resultCode uint16
	entries    []string
}

type nullReferenceResult struct {
	searches          []nullReferenceSearch
	bindAllowedCode   uint16
	bindDeniedCode    uint16
	rootBindCode      uint16
	writeCodes        []uint16
	compareValue      bool
	compareCode       uint16
	assertSearchCode  uint16
	assertModifyCode  uint16
	pagedEntries      []string
	pagedControlFound bool
	typesOnlyEntries  []string
	readControlShapes []string
	noOpCodes         []uint16
	emptyAddCode      uint16
}

func TestOpenLDAPReferenceNullBackend(t *testing.T) {
	tools := requireOpenLDAPNullReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`access to * by * read

database null
suffix "dc=null,dc=example"
bind on
dosearch on
rootdn "cn=admin,dc=null,dc=example"
rootpw null-secret
access to * by * read

database null
suffix "dc=empty,dc=example"
rootdn "cn=admin,dc=empty,dc=example"
rootpw empty-secret
access to * by * read`,
		"",
	)
	defer stop()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNullConfiguration(t, store)
	address, stopLDAPGo := startServer(t, store, Config{})
	defer stopLDAPGo()

	reference := observeNullReference(t, uri)
	implementation := observeNullReference(t, "ldap://"+address)
	want := expectedNullReferenceResult()
	if !reflect.DeepEqual(reference, want) {
		t.Fatalf(
			"OpenLDAP null backend behavior changed\nOpenLDAP: %#v\nexpected: %#v",
			reference,
			want,
		)
	}
	if !reflect.DeepEqual(implementation, want) {
		t.Fatalf(
			"ldap-go null backend behavior mismatch\nldap-go:  %#v\nexpected: %#v",
			implementation,
			want,
		)
	}
}

func requireOpenLDAPNullReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil {
		t.Skipf("inspect OpenLDAP backends: %v", err)
	}
	if !strings.Contains(strings.ToLower(string(output)), "    null") {
		t.Skip("the selected OpenLDAP slapd was not built with the null backend")
	}
	return tools
}

func observeNullReference(t *testing.T, uri string) nullReferenceResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("uid=anything,dc=null,dc=example", "anything"); err != nil {
		t.Fatalf("bind to enabled null database: %v", err)
	}

	result := nullReferenceResult{}
	searches := []struct {
		base   string
		scope  int
		filter string
	}{
		{"dc=null,dc=example", ldap.ScopeBaseObject, "(objectClass=*)"},
		{"dc=null,dc=example", ldap.ScopeSingleLevel, "(objectClass=*)"},
		{"dc=null,dc=example", ldap.ScopeWholeSubtree, "(objectClass=domain)"},
		{"uid=child,dc=null,dc=example", ldap.ScopeBaseObject, "(dc=missing)"},
		{"dc=empty,dc=example", ldap.ScopeBaseObject, "(objectClass=*)"},
	}
	for _, query := range searches {
		searchResult, searchErr := client.Search(ldap.NewSearchRequest(
			query.base,
			query.scope,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			query.filter,
			[]string{"*", "+"},
			nil,
		))
		observation := nullReferenceSearch{
			base:       query.base,
			scope:      query.scope,
			filter:     query.filter,
			resultCode: monitorLDAPResultCode(searchErr),
		}
		if searchResult != nil {
			for _, entry := range searchResult.Entries {
				attributes := make([]string, 0, len(entry.Attributes))
				for _, attribute := range entry.Attributes {
					values := append([]string(nil), attribute.Values...)
					sort.Strings(values)
					attributes = append(attributes, strings.ToLower(attribute.Name)+"="+strings.Join(values, ","))
				}
				sort.Strings(attributes)
				observation.entries = append(observation.entries, strings.ToLower(entry.DN)+"|"+strings.Join(attributes, ";"))
			}
		}
		result.searches = append(result.searches, observation)
	}

	result.bindAllowedCode = nullBindResultCode(t, uri, "uid=arbitrary,dc=null,dc=example", "wrong")
	result.bindDeniedCode = nullBindResultCode(t, uri, "uid=arbitrary,dc=empty,dc=example", "wrong")
	result.rootBindCode = nullBindResultCode(t, uri, "cn=admin,dc=empty,dc=example", "empty-secret")

	add := ldap.NewAddRequest("uid=discarded,dc=null,dc=example", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"discarded"})
	add.Attribute("cn", []string{"Discarded"})
	add.Attribute("sn", []string{"Entry"})
	modify := ldap.NewModifyRequest("uid=missing,dc=null,dc=example", nil)
	modify.Replace("cn", []string{"Changed"})
	result.writeCodes = []uint16{
		monitorLDAPResultCode(client.Add(add)),
		monitorLDAPResultCode(client.Modify(modify)),
		monitorLDAPResultCode(client.Del(ldap.NewDelRequest("uid=missing,dc=null,dc=example", nil))),
		monitorLDAPResultCode(client.ModifyDN(ldap.NewModifyDNRequest(
			"uid=missing,dc=null,dc=example",
			"uid=moved",
			true,
			"",
		))),
	}
	result.compareValue, err = client.Compare("uid=missing,dc=null,dc=example", "cn", "anything")
	result.compareCode = monitorLDAPResultCode(err)

	assertion := newAssertionControl(t, "(objectClass=*)")
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=null,dc=example",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		[]ldap.Control{assertion},
	))
	result.assertSearchCode = monitorLDAPResultCode(err)
	assertModify := ldap.NewModifyRequest(
		"uid=missing,dc=null,dc=example",
		[]ldap.Control{assertion},
	)
	assertModify.Replace("cn", []string{"Changed"})
	result.assertModifyCode = monitorLDAPResultCode(client.Modify(assertModify))

	paging := ldap.NewControlPaging(1)
	paged, err := client.Search(ldap.NewSearchRequest(
		"dc=null,dc=example",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		[]ldap.Control{paging},
	))
	if err != nil {
		t.Fatalf("paged null search: %v", err)
	}
	for _, entry := range paged.Entries {
		result.pagedEntries = append(result.pagedEntries, strings.ToLower(entry.DN))
	}
	result.pagedControlFound = ldap.FindControl(paged.Controls, paging.GetControlType()) != nil

	typesOnly, err := client.Search(ldap.NewSearchRequest(
		"uid=outside,dc=null,dc=example",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		true,
		"(dc=never)",
		[]string{"dc", "objectClass", "+"},
		nil,
	))
	if err != nil {
		t.Fatalf("types-only null search: %v", err)
	}
	for _, entry := range typesOnly.Entries {
		for _, attribute := range entry.Attributes {
			result.typesOnlyEntries = append(
				result.typesOnlyEntries,
				strings.ToLower(attribute.Name)+"="+strings.Join(attribute.Values, ","),
			)
		}
	}
	sort.Strings(result.typesOnlyEntries)

	raw := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"uid=anything,dc=null,dc=example",
		"anything",
	)
	defer raw.Close()
	response := sendRawLDAPOperation(
		t,
		raw,
		2,
		rawModifyReplaceRequest("uid=missing,dc=null,dc=example", "cn", "Changed"),
		rawReadControl(preReadControlOID, true, "*", "+"),
		rawReadControl(postReadControlOID, true, "*", "+"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	for _, oid := range []string{preReadControlOID, postReadControlOID} {
		entry := rawReadControlEntry(t, response, oid)
		attributes := make([]string, 0, len(entry.Attributes))
		for _, attribute := range entry.Attributes {
			attributes = append(attributes, strings.ToLower(attribute.Description))
		}
		sort.Strings(attributes)
		result.readControlShapes = append(
			result.readControlShapes,
			oid+"|"+strings.ToLower(entry.DN)+"|"+strings.Join(attributes, ","),
		)
	}

	noOpRequests := []*ber.Packet{
		rawAddRequest(readControlTestEntry("uid=noop,dc=null,dc=example", "noop")),
		rawModifyReplaceRequest("uid=missing,dc=null,dc=example", "cn", "Changed"),
		rawDeleteRequest("uid=missing,dc=null,dc=example"),
		rawModifyDNRequest("uid=missing,dc=null,dc=example", "uid=moved", true),
	}
	for index, request := range noOpRequests {
		response = sendRawLDAPOperation(
			t,
			raw,
			int64(index+3),
			request,
			rawOIDControl(noOpControlOID, true),
		)
		result.noOpCodes = append(result.noOpCodes, uint16(rawLDAPResultCode(t, response.Children[1])))
	}
	response = sendRawLDAPOperation(
		t,
		raw,
		7,
		rawAddRequest(directory.Entry{DN: "uid=empty,dc=null,dc=example"}),
	)
	result.emptyAddCode = uint16(rawLDAPResultCode(t, response.Children[1]))
	return result
}

func nullBindResultCode(t *testing.T, uri, dn, password string) uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind(dn, password); err != nil {
		return monitorLDAPResultCode(err)
	}
	return ldap.LDAPResultSuccess
}

func seedNullConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "olcDatabase={2}null,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcNullConfig")},
				{Description: "olcDatabase", Values: stringValues("{2}null")},
				{Description: "olcSuffix", Values: stringValues("dc=null,dc=example")},
				{Description: "olcDbBindAllowed", Values: stringValues("TRUE")},
				{Description: "olcDbDoSearch", Values: stringValues("TRUE")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=null,dc=example")},
				{Description: "olcRootPW", Values: stringValues("null-secret")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
			},
		},
		{
			DN: "olcDatabase={3}null,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcNullConfig")},
				{Description: "olcDatabase", Values: stringValues("{3}null")},
				{Description: "olcSuffix", Values: stringValues("dc=empty,dc=example")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=empty,dc=example")},
				{Description: "olcRootPW", Values: stringValues("empty-secret")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed null database configuration: %v", err)
	}
}

func rawOIDControl(oid string, critical bool) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(rawOctetString([]byte(oid)))
	if critical {
		control.AppendChild(ber.NewBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	return control
}
