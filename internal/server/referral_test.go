package server

import (
	"errors"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRewriteReferralURLMatchesOpenLDAPRules(t *testing.T) {
	t.Parallel()

	base := mustParseReferralTestDN(t, "ou=remote,dc=example,dc=com")
	child := mustParseReferralTestDN(
		t,
		"uid=alice,ou=remote,dc=example,dc=com",
	)
	tests := []struct {
		name   string
		raw    string
		target *directory.DN
		scope  referralURLScope
		want   string
		ok     bool
	}{
		{
			name:   "replace local suffix with URL suffix",
			raw:    "ldap://remote.example/ou=people,dc=remote,dc=example Label",
			target: &child,
			scope:  referralScopeSubtree,
			want:   "ldap://remote.example/uid=alice,ou=people,dc=remote,dc=example??sub",
			ok:     true,
		},
		{
			name:   "children search uses subordinate scope",
			raw:    "ldap://remote.example/ou=people,dc=remote,dc=example",
			target: &child,
			scope:  referralScopeForSearch(directory.ScopeChildren),
			want:   "ldap://remote.example/uid=alice,ou=people,dc=remote,dc=example??subordinate",
			ok:     true,
		},
		{
			name:   "URL without DN uses target",
			raw:    "ldap://remote.example Remote",
			target: &child,
			scope:  referralScopeBase,
			want:   "ldap://remote.example/uid=alice,ou=remote,dc=example,dc=com??base",
			ok:     true,
		},
		{
			name:  "continuation uses URL DN",
			raw:   "ldaps://remote.example/dc=remote,dc=example",
			scope: referralScopeSubtree,
			want:  "ldaps://remote.example/dc=remote,dc=example??sub",
			ok:    true,
		},
		{
			name:   "explicit scope is preserved",
			raw:    "ldap://remote.example/dc=remote,dc=example??one",
			target: &base,
			scope:  referralScopeBase,
			want:   "ldap://remote.example/dc=remote,dc=example??one",
			ok:     true,
		},
		{
			name:   "OpenLDAP scope alias is canonicalized",
			raw:    "ldap://remote.example/dc=remote,dc=example??SUBTREE",
			target: &base,
			scope:  referralScopeBase,
			want:   "ldap://remote.example/dc=remote,dc=example??sub",
			ok:     true,
		},
		{
			name:   "historic URL enclosure is normalized",
			raw:    "<URL:ldap://remote.example/dc=remote,dc=example>",
			target: &base,
			scope:  referralScopeBase,
			want:   "ldap://remote.example/dc=remote,dc=example??base",
			ok:     true,
		},
		{
			name:   "proxied LDAP scheme is supported",
			raw:    "pldap://remote.example/dc=remote,dc=example",
			target: &base,
			scope:  referralScopeBase,
			want:   "pldap://remote.example/dc=remote,dc=example??base",
			ok:     true,
		},
		{
			name:   "TLCP LDAP scheme is supported",
			raw:    "ldap+tlcp://remote.example/dc=remote,dc=example",
			target: &base,
			scope:  referralScopeBase,
			want:   "ldap+tlcp://remote.example/dc=remote,dc=example??base",
			ok:     true,
		},
		{
			name:   "non LDAP URI is preserved without label",
			raw:    "https://directory.example/lookup Directory",
			target: &child,
			scope:  referralScopeSubtree,
			want:   "https://directory.example/lookup",
			ok:     true,
		},
		{
			name:   "malformed LDAP URL is omitted",
			raw:    "ldap:/missing-authority",
			target: &child,
			scope:  referralScopeSubtree,
			ok:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := referralURI(test.raw)
			got, ok := rewriteReferralURL(
				raw,
				&base,
				test.target,
				test.scope,
			)
			if ok != test.ok || got != test.want {
				t.Fatalf(
					"rewriteReferralURL() = %q, %t; want %q, %t",
					got,
					ok,
					test.want,
					test.ok,
				)
			}
		})
	}
}

func TestParseManageDsaITControl(t *testing.T) {
	t.Parallel()

	parsed, failure := parseRequestControls(
		[]ldapwire.Control{{
			OID:      manageDsaITControlOID,
			Critical: true,
		}},
		supportsManageDsaIT,
	)
	if failure != nil || !parsed.manageDsaIT {
		t.Fatalf("parseRequestControls() = %#v, %#v", parsed, failure)
	}

	_, failure = parseRequestControls(
		[]ldapwire.Control{
			{OID: manageDsaITControlOID},
			{OID: manageDsaITControlOID},
		},
		supportsManageDsaIT,
	)
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("duplicate ManageDsaIT result = %#v", failure)
	}

	_, failure = parseRequestControls(
		[]ldapwire.Control{{
			OID:      manageDsaITControlOID,
			HasValue: true,
		}},
		supportsManageDsaIT,
	)
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("valued ManageDsaIT result = %#v", failure)
	}
}

func TestLDAPClientManageDsaITAndReferrals(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	manage := ldap.NewControlManageDsaIT(true)
	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	if err != nil {
		t.Fatalf("Root DSE Search(): %v", err)
	}
	if !containsString(
		rootDSE.Entries[0].GetAttributeValues("supportedControl"),
		manageDsaITControlOID,
	) {
		t.Fatal("Root DSE does not advertise ManageDsaIT")
	}

	referralDN := "ou=remote,dc=example,dc=com"
	referralURL := "ldap://remote.example/dc=remote,dc=example Remote"
	add := ldap.NewAddRequest(referralDN, []ldap.Control{manage})
	add.Attribute("objectClass", []string{"referral", "extensibleObject"})
	add.Attribute("ou", []string{"remote"})
	add.Attribute("ref", []string{referralURL})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(referral): %v", err)
	}

	baseResult, err := client.Search(ldap.NewSearchRequest(
		referralDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	))
	if baseResult == nil {
		t.Fatal("base referral Search() returned nil result")
	}
	assertLDAPReferral(
		t,
		err,
		referralDN,
		"ldap://remote.example/dc=remote,dc=example??base",
	)

	childrenBaseResult, err := client.Search(ldap.NewSearchRequest(
		referralDN,
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if childrenBaseResult == nil {
		t.Fatal("children referral Search() returned nil result")
	}
	assertLDAPReferral(
		t,
		err,
		referralDN,
		"ldap://remote.example/dc=remote,dc=example??subordinate",
	)

	subtree, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=filter-does-not-match-referral)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("subtree Search(): %v", err)
	}
	if len(subtree.Referrals) != 1 ||
		subtree.Referrals[0] !=
			"ldap://remote.example/dc=remote,dc=example??sub" {
		t.Fatalf("subtree referrals = %q", subtree.Referrals)
	}

	children, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=filter-does-not-match-referral)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("children Search(): %v", err)
	}
	if len(children.Referrals) != 1 ||
		children.Referrals[0] !=
			"ldap://remote.example/dc=remote,dc=example??sub" {
		t.Fatalf("children referrals = %q", children.Referrals)
	}

	oneLevel, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=filter-does-not-match-referral)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("one-level Search(): %v", err)
	}
	if len(oneLevel.Referrals) != 1 ||
		oneLevel.Referrals[0] !=
			"ldap://remote.example/dc=remote,dc=example??base" {
		t.Fatalf("one-level referrals = %q", oneLevel.Referrals)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		"uid=child,"+referralDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	assertLDAPReferral(
		t,
		err,
		referralDN,
		"ldap://remote.example/uid=child,dc=remote,dc=example??sub",
	)

	managed, err := client.Search(ldap.NewSearchRequest(
		referralDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=referral)",
		[]string{"*", "ref"},
		[]ldap.Control{manage},
	))
	if err != nil {
		t.Fatalf("managed referral Search(): %v", err)
	}
	if len(managed.Entries) != 1 ||
		managed.Entries[0].GetAttributeValue("ref") != referralURL {
		t.Fatalf("managed referral entries = %#v", managed.Entries)
	}

	managedChildren, err := client.Search(ldap.NewSearchRequest(
		referralDN,
		ldap.ScopeChildren,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=referral)",
		[]string{"*", "ref"},
		[]ldap.Control{manage},
	))
	if err != nil {
		t.Fatalf("managed children referral Search(): %v", err)
	}
	if len(managedChildren.Entries) != 0 {
		t.Fatalf("managed children referral entries = %#v", managedChildren.Entries)
	}

	modify := ldap.NewModifyRequest(referralDN, nil)
	modify.Replace(
		"ref",
		[]string{"ldap://other.example/dc=other,dc=example"},
	)
	assertLDAPResultCode(t, client.Modify(modify), ldap.LDAPResultReferral)
	modify.Controls = []ldap.Control{manage}
	if err := client.Modify(modify); err != nil {
		t.Fatalf("managed Modify(referral): %v", err)
	}

	matches, err := client.Compare(
		referralDN,
		"ref",
		"ldap://other.example/dc=other,dc=example",
	)
	if matches {
		t.Fatal("unmanaged Compare(referral) returned true")
	}
	assertLDAPResultCode(t, err, ldap.LDAPResultReferral)
	if code := rawCompareWithManageDsaIT(
		t,
		address,
		referralDN,
		"ref",
		"ldap://other.example/dc=other,dc=example",
	); code != ldap.LDAPResultCompareTrue {
		t.Fatalf("managed Compare result = %d, want compareTrue", code)
	}

	passwordResult, err := client.PasswordModify(
		ldap.NewPasswordModifyRequest(
			referralDN,
			"",
			"managed-password",
		),
	)
	if passwordResult == nil {
		t.Fatal("unmanaged Password Modify returned nil result")
	}
	assertLDAPResultCode(t, err, ldap.LDAPResultReferral)
	if passwordResult.Referral !=
		"ldap://other.example/dc=other,dc=example" {
		t.Fatalf(
			"Password Modify referral = %q",
			passwordResult.Referral,
		)
	}
	if code := rawPasswordModifyWithManageDsaIT(
		t,
		address,
		referralDN,
		"managed-password",
	); code != ldap.LDAPResultSuccess {
		t.Fatalf("managed Password Modify result = %d, want success", code)
	}
	referralClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(referral bind): %v", err)
	}
	defer referralClient.Close()
	assertLDAPResultCode(
		t,
		referralClient.Bind(referralDN, "managed-password"),
		ldap.LDAPResultInvalidCredentials,
	)

	rename := ldap.NewModifyDNRequest(
		referralDN,
		"ou=renamed",
		true,
		"",
	)
	assertLDAPResultCode(t, client.ModifyDN(rename), ldap.LDAPResultReferral)
	rename.Controls = []ldap.Control{manage}
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("managed ModifyDN(referral): %v", err)
	}
	referralDN = "ou=renamed,dc=example,dc=com"

	child := ldap.NewAddRequest(
		"uid=child,"+referralDN,
		[]ldap.Control{manage},
	)
	child.Attribute("objectClass", []string{"inetOrgPerson"})
	child.Attribute("uid", []string{"child"})
	child.Attribute("cn", []string{"Child"})
	child.Attribute("sn", []string{"Child"})
	err = client.Add(child)
	assertLDAPReferral(
		t,
		err,
		referralDN,
		"ldap://other.example/uid=child,dc=other,dc=example",
	)

	deleteRequest := ldap.NewDelRequest(referralDN, nil)
	assertLDAPResultCode(
		t,
		client.Del(deleteRequest),
		ldap.LDAPResultReferral,
	)
	deleteRequest.Controls = []ldap.Control{manage}
	if err := client.Del(deleteRequest); err != nil {
		t.Fatalf("managed Delete(referral): %v", err)
	}
}

func mustParseReferralTestDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", raw, err)
	}
	return dn
}

func rawCompareWithManageDsaIT(
	t *testing.T,
	address, dn, attribute, value string,
) int64 {
	t.Helper()
	connection := rawBoundReferralConnection(t, address)
	defer connection.Close()

	compare := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationCompareRequest,
		nil,
		"CompareRequest",
	)
	compare.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		dn,
		"entry",
	))
	ava := ber.NewSequence("AttributeValueAssertion")
	ava.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		attribute,
		"attribute",
	))
	ava.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		value,
		"value",
	))
	compare.AppendChild(ava)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		compare,
		rawManageDsaITControl(),
	)
	return readRawLDAPResultCode(t, connection)
}

func rawPasswordModifyWithManageDsaIT(
	t *testing.T,
	address, dn, password string,
) int64 {
	t.Helper()
	connection := rawBoundReferralConnection(t, address)
	defer connection.Close()

	value := ber.NewSequence("PasswordModifyRequestValue")
	value.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		dn,
		"userIdentity",
	))
	value.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		2,
		password,
		"newPassword",
	))
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationExtendedRequest,
		nil,
		"ExtendedRequest",
	)
	request.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		passwordModifyOID,
		"requestName",
	))
	request.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		string(value.Bytes()),
		"requestValue",
	))
	writeRawLDAPRequest(
		t,
		connection,
		2,
		request,
		rawManageDsaITControl(),
	)
	return readRawLDAPResultCode(t, connection)
}

func rawBoundReferralConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}

	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		3,
		"version",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"cn=admin,dc=example,dc=com",
		"name",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"admin-secret",
		"simple",
	))
	writeRawLDAPRequest(t, connection, 1, bind, nil)
	if code := readRawLDAPResultCode(t, connection); code != 0 {
		_ = connection.Close()
		t.Fatalf("raw Bind result = %d", code)
	}
	return connection
}

func rawManageDsaITControl() *ber.Packet {
	control := ber.NewSequence("ManageDsaITControl")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		manageDsaITControlOID,
		"controlType",
	))
	control.AppendChild(ber.NewBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"criticality",
	))
	return control
}

func assertLDAPReferral(
	t *testing.T,
	err error,
	matchedDN string,
	referral string,
) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultReferral ||
		ldapErr.MatchedDN != matchedDN {
		t.Fatalf(
			"LDAP error = %v, matchedDN %q; want referral matchedDN %q",
			err,
			ldapErrMatchedDN(ldapErr),
			matchedDN,
		)
	}
	referrals := ldapResultReferrals(ldapErr.Packet)
	if len(referrals) != 1 || referrals[0] != referral {
		t.Fatalf("LDAP referrals = %q, want %q", referrals, referral)
	}
}

func ldapErrMatchedDN(err *ldap.Error) string {
	if err == nil {
		return ""
	}
	return err.MatchedDN
}

func ldapResultReferrals(packet *ber.Packet) []string {
	if packet == nil || len(packet.Children) < 2 {
		return nil
	}
	response := packet.Children[1]
	for _, child := range response.Children {
		if child.ClassType != ber.ClassContext ||
			child.TagType != ber.TypeConstructed ||
			child.Tag != 3 {
			continue
		}
		referrals := make([]string, 0, len(child.Children))
		for _, value := range child.Children {
			if referral, ok := value.Value.(string); ok {
				referrals = append(referrals, referral)
			}
		}
		return referrals
	}
	return nil
}
