package server

import (
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseLazyCommitControl(t *testing.T) {
	control := func(critical, hasValue bool, value []byte) ldapwire.Control {
		return ldapwire.Control{
			OID: lazyCommitControlOID, Critical: critical,
			HasValue: hasValue, Value: value,
		}
	}
	for _, critical := range []bool{false, true} {
		parsed, failure := parseRequestControls(
			[]ldapwire.Control{control(critical, false, nil)},
			supportsLazyCommit,
		)
		if failure != nil || !parsed.lazyCommit {
			t.Errorf("critical=%t parsed=%#v failure=%#v", critical, parsed, failure)
		}
	}
	for _, test := range []struct {
		name     string
		controls []ldapwire.Control
	}{
		{name: "empty value", controls: []ldapwire.Control{control(false, true, nil)}},
		{name: "nonempty value", controls: []ldapwire.Control{control(true, true, []byte{0})}},
		{name: "duplicate before value", controls: []ldapwire.Control{
			control(false, false, nil), control(true, true, []byte{0}),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failure := parseRequestControls(test.controls, supportsLazyCommit)
			if failure == nil || failure.Code != ldapwire.ResultProtocolError {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}
	invalid := control(false, true, []byte("ignored"))
	if _, failure := parseRequestControls([]ldapwire.Control{invalid}, 0); failure != nil {
		t.Fatalf("unsupported noncritical Lazy Commit = %#v", failure)
	}
	invalid.Critical = true
	if _, failure := parseRequestControls([]ldapwire.Control{invalid}, 0); failure == nil || failure.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("unsupported critical Lazy Commit = %#v", failure)
	}
}

func TestLDAPLazyCommitLifecycleAndUnsupportedOperations(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	lazy := ldap.NewControlString(lazyCommitControlOID, true, "")
	_, err = client.SimpleBind(ldap.NewSimpleBindRequest(
		"cn=admin,dc=example,dc=com",
		"secret",
		[]ldap.Control{&domainScopeWireControl{
			oid: lazyCommitControlOID, hasValue: true, value: []byte("ignored"),
		}},
	))
	if err != nil {
		t.Fatalf("noncritical unsupported Bind control: %v", err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, []ldap.Control{lazy},
	))
	if err != nil {
		t.Fatalf("Lazy Commit Search: %v", err)
	}

	dn := "uid=lazy,ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(dn, []ldap.Control{lazy})
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"lazy"})
	add.Attribute("cn", []string{"Lazy Commit"})
	add.Attribute("sn", []string{"Commit"})
	if err := client.Add(add); err != nil {
		t.Fatalf("Lazy Commit Add: %v", err)
	}
	modify := ldap.NewModifyRequest(dn, []ldap.Control{lazy})
	modify.Replace("cn", []string{"Lazy Commit Updated"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Lazy Commit Modify: %v", err)
	}
	rename := ldap.NewModifyDNRequest(dn, "uid=lazy-renamed", true, "")
	rename.Controls = []ldap.Control{lazy}
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("Lazy Commit ModifyDN: %v", err)
	}
	renamedDN := "uid=lazy-renamed,ou=people,dc=example,dc=com"
	if err := client.Del(ldap.NewDelRequest(renamedDN, []ldap.Control{lazy})); err != nil {
		t.Fatalf("Lazy Commit Delete: %v", err)
	}
	if entryExists(t, store, renamedDN) {
		t.Fatal("Lazy Commit Delete did not commit")
	}

	noOpDN := "uid=lazy-noop,ou=people,dc=example,dc=com"
	noOp := ldap.NewAddRequest(noOpDN, []ldap.Control{
		lazy,
		ldap.NewControlString(noOpControlOID, true, ""),
	})
	noOp.Attribute("objectClass", []string{"inetOrgPerson"})
	noOp.Attribute("uid", []string{"lazy-noop"})
	noOp.Attribute("cn", []string{"Lazy NoOp"})
	noOp.Attribute("sn", []string{"NoOp"})
	assertLDAPResultCode(t, client.Add(noOp), uint16(ldapwire.ResultNoOperation))
	if entryExists(t, store, noOpDN) {
		t.Fatal("Lazy Commit plus No-Op committed")
	}

	whoami := ldap.NewExtendedRequest(whoAmIOID, nil)
	whoami.Controls = []ldap.Control{&domainScopeWireControl{
		oid: lazyCommitControlOID, hasValue: true, value: []byte("ignored"),
	}}
	if _, err := client.Extended(whoami); err != nil {
		t.Fatalf("noncritical unsupported Extended control: %v", err)
	}
	whoami.Controls = []ldap.Control{lazy}
	_, err = client.Extended(whoami)
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailableCriticalExtension)
}

func TestRootDSEHidesLazyCommitControl(t *testing.T) {
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
	result, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Root DSE = %#v, %v", result, err)
	}
	if slices.Contains(
		result.Entries[0].GetAttributeValues("supportedControl"),
		lazyCommitControlOID,
	) {
		t.Fatal("hidden Lazy Commit control was published")
	}
}

func TestLDAPBackendForwardsLazyCommitControl(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	sink := &recordingAuditSink{}
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
		AuditSink:    sink,
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
	if _, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"uid"},
		[]ldap.Control{ldap.NewControlString(lazyCommitControlOID, true, "")},
	)); err != nil {
		t.Fatalf("proxied Lazy Commit Search: %v", err)
	}
	events := waitForAuditEvents(t, sink, 2)
	found := false
	for _, event := range events {
		if event.Operation == "search" &&
			slices.Contains(event.RequestControls, lazyCommitControlOID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("provider audit lacks forwarded Lazy Commit: %#v", events)
	}
}
