package server

import (
	"errors"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

type openLDAPMetaResultMappingOutcome struct {
	search  ldapBackendMissingResult
	compare ldapBackendMissingResult
	modify  ldapBackendMissingResult
	delete  ldapBackendMissingResult
}

func TestOpenLDAPReferenceMetaResultNamespace(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	run := func(t *testing.T, ldapGo bool) openLDAPMetaResultMappingOutcome {
		t.Helper()
		providerOne, stopProviderOne := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-one",
			"provider-one",
		)
		defer stopProviderOne()
		providerTwo, stopProviderTwo := startOpenLDAPMetaProvider(
			t,
			tools,
			"route-two",
			"provider-two",
		)
		defer stopProviderTwo()
		var proxyURI string
		var stop func()
		if ldapGo {
			proxyURI, stop = startLDAPGoMetaReferenceFixture(t, "", providerOne, providerTwo)
		} else {
			proxyURI, stop = startOpenLDAPMetaUnionProxy(t, tools, providerOne, providerTwo)
		}
		defer stop()
		return observeOpenLDAPMetaResultNamespace(t, proxyURI)
	}

	reference := run(t, false)
	got := run(t, true)
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf(
			"ldap-go back-meta result namespace differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			got,
		)
	}
}

func observeOpenLDAPMetaResultNamespace(
	t *testing.T,
	proxyURI string,
) openLDAPMetaResultMappingOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta result fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta result fixture: %v", err)
	}
	missing := "uid=missing,ou=people," + openLDAPMetaBaseDN
	_, searchErr := client.Search(ldap.NewSearchRequest(
		missing,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	_, compareErr := client.Compare(missing, "uid", "missing")
	modify := ldap.NewModifyRequest(missing, nil)
	modify.Replace("description", []string{"missing"})
	modifyErr := client.Modify(modify)
	deleteErr := client.Del(ldap.NewDelRequest(missing, nil))
	return openLDAPMetaResultMappingOutcome{
		search:  metaMissingResult(t, searchErr),
		compare: metaMissingResult(t, compareErr),
		modify:  metaMissingResult(t, modifyErr),
		delete:  metaMissingResult(t, deleteErr),
	}
}

func metaMissingResult(t *testing.T, err error) ldapBackendMissingResult {
	t.Helper()
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("LDAP operation error = %v, want LDAP result", err)
	}
	return ldapBackendMissingResult{
		code:       ldapError.ResultCode,
		matchedDN:  ldapError.MatchedDN,
		diagnostic: ldapError.Err.Error(),
	}
}
