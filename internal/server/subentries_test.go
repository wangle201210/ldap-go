package server

import (
	"errors"
	"slices"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientSubentriesSearchVisibility(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindSubentriesRootClient(t, address)
	defer client.Close()

	addSubentry(
		t,
		client,
		"cn=people-policy,ou=people,dc=example,dc=com",
		"people-policy",
	)
	addSubentry(
		t,
		client,
		"cn=archive-policy,ou=archive,dc=example,dc=com",
		"archive-policy",
	)

	peopleDN := "ou=people,dc=example,dc=com"
	peoplePolicyDN := "cn=people-policy," + peopleDN
	aliceDN := "uid=alice," + peopleDN
	assertSubentrySearchDNs(t, client, peopleDN, ldap.ScopeSingleLevel, nil, []string{
		aliceDN,
	})
	assertSubentrySearchDNs(
		t,
		client,
		peopleDN,
		ldap.ScopeSingleLevel,
		subentriesControl(true),
		[]string{peoplePolicyDN},
	)
	assertSubentrySearchDNs(
		t,
		client,
		peopleDN,
		ldap.ScopeSingleLevel,
		subentriesControl(false),
		[]string{aliceDN},
	)

	assertSubentrySearchDNs(
		t,
		client,
		peoplePolicyDN,
		ldap.ScopeBaseObject,
		nil,
		[]string{peoplePolicyDN},
	)
	assertSubentrySearchDNs(
		t,
		client,
		peoplePolicyDN,
		ldap.ScopeBaseObject,
		subentriesControl(false),
		nil,
	)
	assertSubentrySearchDNs(
		t,
		client,
		peoplePolicyDN,
		ldap.ScopeBaseObject,
		subentriesControl(true),
		[]string{peoplePolicyDN},
	)
	assertSubentrySearchDNs(
		t,
		client,
		aliceDN,
		ldap.ScopeBaseObject,
		subentriesControl(true),
		nil,
	)
	assertSubentrySearchDNs(
		t,
		client,
		aliceDN,
		ldap.ScopeBaseObject,
		subentriesControl(false),
		[]string{aliceDN},
	)

	allSubentries, err := client.SearchWithPaging(
		ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"cn"},
			[]ldap.Control{subentriesControl(true)},
		),
		1,
	)
	if err != nil {
		t.Fatalf("SearchWithPaging(subentries): %v", err)
	}
	if got, want := sortedSubentryDNs(allSubentries), []string{
		"cn=archive-policy,ou=archive,dc=example,dc=com",
		peoplePolicyDN,
	}; !slices.Equal(got, want) {
		t.Fatalf("paged subentry DNs = %q, want %q", got, want)
	}

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		[]ldap.Control{subentriesControl(true)},
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedControl"),
			subentriesControlOID,
		) {
		t.Fatalf("Root DSE subentries support = %#v, %v", rootDSE, err)
	}

	subschema, err := client.Search(ldap.NewSearchRequest(
		"cn=Subschema",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectClass", "structuralObjectClass"},
		[]ldap.Control{subentriesControl(false)},
	))
	if err != nil || len(subschema.Entries) != 1 ||
		!slices.Contains(
			subschema.Entries[0].GetAttributeValues("objectClass"),
			"subentry",
		) ||
		subschema.Entries[0].GetAttributeValue("structuralObjectClass") !=
			"subentry" {
		t.Fatalf("subschema subentry = %#v, %v", subschema, err)
	}
}

func TestParseRequestControlsRejectsInvalidSubentries(t *testing.T) {
	t.Parallel()

	validTrue := ldapwire.Control{
		OID:      subentriesControlOID,
		Critical: true,
		Value:    []byte{0x01, 0x01, 0xff},
		HasValue: true,
	}
	validFalse := ldapwire.Control{
		OID:      subentriesControlOID,
		Value:    []byte{0x01, 0x01, 0x00},
		HasValue: true,
	}
	for _, test := range []struct {
		name     string
		controls []ldapwire.Control
		wantCode ldapwire.ResultCode
	}{
		{
			name:     "absent value",
			controls: []ldapwire.Control{{OID: subentriesControlOID}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "empty value",
			controls: []ldapwire.Control{{
				OID:      subentriesControlOID,
				HasValue: true,
			}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "wrong tag",
			controls: []ldapwire.Control{{
				OID:      subentriesControlOID,
				Value:    []byte{0x02, 0x01, 0x01},
				HasValue: true,
			}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "wrong length",
			controls: []ldapwire.Control{{
				OID:      subentriesControlOID,
				Value:    []byte{0x01, 0x02, 0x00},
				HasValue: true,
			}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "duplicate",
			controls: []ldapwire.Control{validTrue, validFalse},
			wantCode: ldapwire.ResultProtocolError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, result := parseRequestControls(
				test.controls,
				supportsSubentries,
			)
			if result == nil || result.Code != test.wantCode {
				t.Fatalf("parse result = %#v, want code %d", result, test.wantCode)
			}
		})
	}

	parsed, result := parseRequestControls(
		[]ldapwire.Control{validTrue},
		supportsSubentries,
	)
	if result != nil || parsed.subentries == nil || !*parsed.subentries {
		t.Fatalf("valid TRUE control = %#v, %#v", parsed, result)
	}
	parsed, result = parseRequestControls(
		[]ldapwire.Control{validFalse},
		supportsSubentries,
	)
	if result != nil || parsed.subentries == nil || *parsed.subentries {
		t.Fatalf("valid FALSE control = %#v, %#v", parsed, result)
	}

	parsed, result = parseRequestControls(
		[]ldapwire.Control{{
			OID:      subentriesControlOID,
			Value:    []byte{0x01, 0x01, 0xff},
			HasValue: true,
		}},
		0,
	)
	if result != nil || parsed.subentries != nil {
		t.Fatalf("unsupported noncritical control = %#v, %#v", parsed, result)
	}
	_, result = parseRequestControls(
		[]ldapwire.Control{validTrue},
		0,
	)
	if result == nil ||
		result.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("unsupported critical control result = %#v", result)
	}
}

func TestLDAPClientSubentryWriteRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindSubentriesRootClient(t, address)
	defer client.Close()

	subentryDN := "cn=bind-policy,ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(subentryDN, nil)
	add.Attribute(
		"objectClass",
		[]string{"subentry", "extensibleObject"},
	)
	add.Attribute("cn", []string{"bind-policy"})
	add.Attribute("subtreeSpecification", []string{"{}"})
	add.Attribute("userPassword", []string{"policy-secret"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(subentry): %v", err)
	}

	subentryClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(subentry bind): %v", err)
	}
	defer subentryClient.Close()
	assertLDAPResultCode(
		t,
		subentryClient.Bind(subentryDN, "policy-secret"),
		ldap.LDAPResultInvalidCredentials,
	)

	matches, err := client.Compare(
		subentryDN,
		"cn",
		"bind-policy",
	)
	if err != nil || !matches {
		t.Fatalf("Compare(subentry) = %t, %v", matches, err)
	}
	_, err = client.Compare(subentryDN, "subtreeSpecification", "{}")
	assertLDAPResultCode(t, err, ldap.LDAPResultInappropriateMatching)
	modify := ldap.NewModifyRequest(subentryDN, nil)
	modify.Replace("subtreeSpecification", []string{"{ minimum 1 }"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(subentry): %v", err)
	}

	child := ldap.NewAddRequest("cn=child,"+subentryDN, nil)
	child.Attribute("objectClass", []string{"organizationalRole"})
	child.Attribute("cn", []string{"child"})
	assertLDAPResultCode(
		t,
		client.Add(child),
		ldap.LDAPResultObjectClassViolation,
	)

	move := ldap.NewModifyDNRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid=alice",
		true,
		subentryDN,
	)
	if err := client.ModifyDN(move); err != nil {
		t.Fatalf("ModifyDN(into subentry): %v", err)
	}
	movedAliceDN := "uid=alice," + subentryDN
	assertSubentrySearchDNs(
		t,
		client,
		subentryDN,
		ldap.ScopeSingleLevel,
		nil,
		[]string{movedAliceDN},
	)
	moveBack := ldap.NewModifyDNRequest(
		movedAliceDN,
		"uid=alice",
		true,
		"ou=people,dc=example,dc=com",
	)
	if err := client.ModifyDN(moveBack); err != nil {
		t.Fatalf("ModifyDN(out of subentry): %v", err)
	}

	missing := ldap.NewAddRequest(
		"cn=missing-spec,ou=people,dc=example,dc=com",
		nil,
	)
	missing.Attribute("objectClass", []string{"subentry"})
	missing.Attribute("cn", []string{"missing-spec"})
	assertLDAPResultCode(
		t,
		client.Add(missing),
		ldap.LDAPResultObjectClassViolation,
	)

	ordinary := ldap.NewAddRequest(
		"cn=ordinary,ou=people,dc=example,dc=com",
		nil,
	)
	ordinary.Attribute(
		"objectClass",
		[]string{"organizationalRole", "extensibleObject"},
	)
	ordinary.Attribute("cn", []string{"ordinary"})
	ordinary.Attribute("subtreeSpecification", []string{"{}"})
	assertLDAPResultCode(
		t,
		client.Add(ordinary),
		ldap.LDAPResultObjectClassViolation,
	)

	criticalOnAdd := ldap.NewAddRequest(
		"cn=control-on-add,ou=people,dc=example,dc=com",
		[]ldap.Control{subentriesControl(true)},
	)
	criticalOnAdd.Attribute("objectClass", []string{"organizationalRole"})
	criticalOnAdd.Attribute("cn", []string{"control-on-add"})
	assertLDAPResultCode(
		t,
		client.Add(criticalOnAdd),
		ldap.LDAPResultUnavailableCriticalExtension,
	)

	rename := ldap.NewModifyDNRequest(
		subentryDN,
		"cn=renamed-policy",
		true,
		"",
	)
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("ModifyDN(subentry): %v", err)
	}
	renamedDN := "cn=renamed-policy,ou=people,dc=example,dc=com"
	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("Delete(subentry): %v", err)
	}
}

func bindSubentriesRootClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		client.Close()
		t.Fatalf("Bind(root): %v", err)
	}
	return client
}

func addSubentry(t *testing.T, client *ldap.Conn, dn, cn string) {
	t.Helper()

	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"subentry"})
	request.Attribute("cn", []string{cn})
	request.Attribute("subtreeSpecification", []string{"{}"})
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(%s): %v", dn, err)
	}
}

func subentriesControl(visible bool) ldap.Control {
	value := "\x01\x01\x00"
	if visible {
		value = "\x01\x01\xff"
	}
	return ldap.NewControlString(subentriesControlOID, true, value)
}

func assertSubentrySearchDNs(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope int,
	control ldap.Control,
	want []string,
) {
	t.Helper()

	var controls []ldap.Control
	if control != nil {
		controls = append(controls, control)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		controls,
	))
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			t.Fatalf(
				"Search(%q) result code = %d: %v",
				base,
				ldapErr.ResultCode,
				err,
			)
		}
		t.Fatalf("Search(%q): %v", base, err)
	}
	if got := sortedSubentryDNs(result); !slices.Equal(got, want) {
		t.Fatalf("Search(%q) DNs = %q, want %q", base, got, want)
	}
}

func sortedSubentryDNs(result *ldap.SearchResult) []string {
	dns := make([]string, len(result.Entries))
	for index, entry := range result.Entries {
		dns[index] = entry.DN
	}
	sort.Strings(dns)
	return dns
}
