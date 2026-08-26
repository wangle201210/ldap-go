package server

import (
	"context"
	"slices"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const domainScopeReferralDN = "ou=remote,dc=example,dc=com"

func TestParseDomainScopeAndSearchOptionsControls(t *testing.T) {
	supported := supportsDomainScope | supportsSearchOptions
	domain := func(critical, hasValue bool, value []byte) ldapwire.Control {
		return ldapwire.Control{
			OID: domainScopeControlOID, Critical: critical,
			HasValue: hasValue, Value: value,
		}
	}
	options := func(flags int32, critical bool) ldapwire.Control {
		return ldapwire.Control{
			OID: searchOptionsControlOID, Critical: critical,
			HasValue: true, Value: ldapwire.EncodeSearchOptionsValue(flags),
		}
	}

	for _, controls := range [][]ldapwire.Control{
		{domain(false, false, nil)},
		{domain(true, true, nil)},
		{options(1, false)},
		{options(1, true)},
		{options(0, false), options(0, true), domain(false, false, nil)},
		{domain(false, false, nil), options(0, false)},
	} {
		parsed, failure := parseRequestControls(controls, supported)
		if failure != nil || !parsed.domainScope {
			t.Errorf("domain-scope controls %#v = %#v, %#v", controls, parsed, failure)
		}
	}

	parsed, failure := parseRequestControls(
		[]ldapwire.Control{options(2, false)},
		supported,
	)
	if failure != nil || parsed.domainScope {
		t.Fatalf("noncritical phantom-root = %#v, %#v", parsed, failure)
	}
	parsed, failure = parseRequestControls(
		[]ldapwire.Control{options(3, false)},
		supported,
	)
	if failure != nil || parsed.domainScope {
		t.Fatalf("noncritical mixed unknown flags = %#v, %#v", parsed, failure)
	}

	for _, test := range []struct {
		name     string
		controls []ldapwire.Control
		code     ldapwire.ResultCode
	}{
		{
			name: "domain value",
			controls: []ldapwire.Control{
				domain(false, true, []byte{0}),
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "duplicate domain",
			controls: []ldapwire.Control{
				domain(false, false, nil), domain(true, true, nil),
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "domain plus option one",
			controls: []ldapwire.Control{
				domain(false, false, nil), options(1, false),
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "option one twice",
			controls: []ldapwire.Control{
				options(1, false), options(1, false),
			},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "critical phantom root",
			controls: []ldapwire.Control{
				options(2, true),
			},
			code: ldapwire.ResultUnwillingToPerform,
		},
		{
			name: "absent options value",
			controls: []ldapwire.Control{{
				OID: searchOptionsControlOID,
			}},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "empty options value",
			controls: []ldapwire.Control{{
				OID: searchOptionsControlOID, HasValue: true,
			}},
			code: ldapwire.ResultProtocolError,
		},
		{
			name: "malformed options value",
			controls: []ldapwire.Control{{
				OID: searchOptionsControlOID, HasValue: true, Value: []byte{0x30, 0x01},
			}},
			code: ldapwire.ResultProtocolError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failure := parseRequestControls(test.controls, supported)
			if failure == nil || failure.Code != test.code {
				t.Fatalf("parse controls = %#v, want %d", failure, test.code)
			}
		})
	}

	invalid := domain(false, true, []byte("ignored"))
	if _, failure := parseRequestControls([]ldapwire.Control{invalid}, 0); failure != nil {
		t.Fatalf("unsupported noncritical control was validated: %#v", failure)
	}
	invalid.Critical = true
	if _, failure := parseRequestControls([]ldapwire.Control{invalid}, 0); failure == nil || failure.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("unsupported critical control = %#v", failure)
	}
}

func TestLDAPClientDomainScopeSuppressesSearchReferences(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedDomainScopeReferral(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	search := func(controls []ldap.Control) (*ldap.SearchResult, error) {
		return client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"1.1"},
			controls,
		))
	}
	ordinary, err := search(nil)
	if err != nil || len(ordinary.Referrals) != 1 {
		t.Fatalf("ordinary referrals = %#v, %v", ordinary, err)
	}
	for _, control := range []ldap.Control{
		ldap.NewControlString(domainScopeControlOID, true, ""),
		ldap.NewControlString(
			searchOptionsControlOID,
			true,
			string(ldapwire.EncodeSearchOptionsValue(1)),
		),
	} {
		result, err := search([]ldap.Control{control})
		if err != nil || len(result.Referrals) != 0 || len(result.Entries) == 0 {
			t.Errorf("domain-scope Search(%s) = %#v, %v", control.GetControlType(), result, err)
		}
	}
	ignored, err := search([]ldap.Control{ldap.NewControlString(
		searchOptionsControlOID,
		false,
		string(ldapwire.EncodeSearchOptionsValue(3)),
	)})
	if err != nil || len(ignored.Referrals) != 1 {
		t.Fatalf("noncritical unknown search options = %#v, %v", ignored, err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		domainScopeReferralDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"1.1"},
		[]ldap.Control{ldap.NewControlString(domainScopeControlOID, true, "")},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func TestLDAPBackendDomainScopeSuppressesProviderReferences(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	t.Cleanup(stopProvider)

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	t.Cleanup(stopProxy)
	client := dialLDAPBackendClient(t, proxyAddress)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(proxy root): %v", err)
	}

	search := func(controls []ldap.Control) (*ldap.SearchResult, error) {
		return client.Search(ldap.NewSearchRequest(
			ldapBackendTestSuffix,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			[]string{"1.1"},
			controls,
		))
	}
	ordinary, err := search(nil)
	if err != nil || len(ordinary.Referrals) != 1 {
		t.Fatalf("ordinary proxy referrals = %#v, %v", ordinary, err)
	}
	scoped, err := search([]ldap.Control{
		ldap.NewControlString(domainScopeControlOID, true, ""),
	})
	if err != nil || len(scoped.Referrals) != 0 || len(scoped.Entries) == 0 {
		t.Fatalf("domain-scope proxy Search = %#v, %v", scoped, err)
	}

	_, err = client.Search(ldap.NewSearchRequest(
		"ou=referral,"+ldapBackendTestSuffix,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"1.1"},
		[]ldap.Control{ldap.NewControlString(domainScopeControlOID, true, "")},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func TestDomainScopeResponseTransformAndHiddenControls(t *testing.T) {
	connection := &domainScopeConnection{messageID: 7}
	if _, suppress, err := connection.transform(
		ldapwire.EncodeSearchResultReference(7, []string{"ldap://remote.example"}, nil),
	); err != nil || !suppress {
		t.Fatalf("reference transform = suppress %t, error %v", suppress, err)
	}
	responseControl := ldapwire.Control{OID: "1.2.3", HasValue: true, Value: []byte("value")}
	encoded, suppress, err := connection.transform(ldapwire.EncodeSearchResultDone(
		7,
		ldapwire.Result{
			Code: ldapwire.ResultReferral, MatchedDN: "dc=example,dc=com",
			DiagnosticMessage: "referral", Referrals: []string{"ldap://remote.example"},
		},
		[]ldapwire.Control{responseControl},
	))
	if err != nil || suppress {
		t.Fatalf("done transform = suppress %t, error %v", suppress, err)
	}
	packet, err := decodeLDAPPacket(encoded)
	if err != nil {
		t.Fatalf("decode transformed done: %v", err)
	}
	result, err := chainLDAPResult(packet, 7, ldapwire.ApplicationSearchResultDone)
	if err != nil || result.Code != ldapwire.ResultNoSuchObject ||
		result.MatchedDN != "dc=example,dc=com" || result.DiagnosticMessage != "referral" ||
		len(result.Referrals) != 0 {
		t.Fatalf("transformed done = %#v, %v", result, err)
	}
	controls, err := decodePBindResponseControls(packet)
	if err != nil || len(controls) != 1 || controls[0].OID != responseControl.OID {
		t.Fatalf("transformed controls = %#v, %v", controls, err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	root, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil,
	))
	if err != nil || len(root.Entries) != 1 {
		t.Fatalf("Root DSE Search = %#v, %v", root, err)
	}
	supportedControls := root.Entries[0].GetAttributeValues("supportedControl")
	if slices.Contains(supportedControls, domainScopeControlOID) ||
		slices.Contains(supportedControls, searchOptionsControlOID) {
		t.Fatalf("hidden controls were published: %q", supportedControls)
	}
	filtered := withoutDomainScopeControls([]ldapwire.Control{
		{OID: domainScopeControlOID},
		{OID: "1.2.3"},
		{OID: searchOptionsControlOID},
	})
	if len(filtered) != 1 || filtered[0].OID != "1.2.3" {
		t.Fatalf("filtered domain-scope controls = %#v", filtered)
	}
}

func seedDomainScopeReferral(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: domainScopeReferralDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
				{Description: "ou", Values: stringValues("remote")},
				{Description: "ref", Values: stringValues("ldap://remote.example/dc=remote,dc=example")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed domain-scope referral: %v", err)
	}
}

func decodeLDAPPacket(value []byte) (*ber.Packet, error) {
	return ber.DecodePacketErr(value)
}
