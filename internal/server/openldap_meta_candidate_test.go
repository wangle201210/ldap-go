package server

import (
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

type openLDAPMetaCandidateOutcome struct {
	broadBindCode        uint16
	crossTargetCode      uint16
	crossTargetDesc      string
	broadCompareCode     uint16
	broadCompareMatched  bool
	broadModifyCode      uint16
	broadProviderDesc    string
	parentFallbackAdd    uint16
	parentProviderCode   uint16
	crossTargetRename    uint16
	ambiguousCompareCode uint16
}

func TestOpenLDAPReferenceMetaUniqueCandidateSelection(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	run := func(t *testing.T, ldapGo bool) openLDAPMetaCandidateOutcome {
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
		seedOpenLDAPMetaCandidateProviders(t, providerOne, providerTwo)

		var proxyURI string
		var stop func()
		if ldapGo {
			proxyURI, stop = startLDAPGoMetaReferenceFixture(t, "", providerOne, providerTwo)
		} else {
			proxyURI, stop = startOpenLDAPMetaUnionProxy(t, tools, providerOne, providerTwo)
		}
		defer stop()
		return observeOpenLDAPMetaCandidates(t, proxyURI, providerOne)
	}

	reference := run(t, false)
	if reference.broadBindCode != ldap.LDAPResultSuccess ||
		reference.crossTargetCode != ldap.LDAPResultSuccess ||
		reference.crossTargetDesc != "provider-two" ||
		reference.broadCompareCode != ldap.LDAPResultSuccess ||
		!reference.broadCompareMatched ||
		reference.broadModifyCode != ldap.LDAPResultSuccess ||
		reference.parentFallbackAdd != ldap.LDAPResultSuccess ||
		reference.parentProviderCode != ldap.LDAPResultSuccess ||
		reference.crossTargetRename != ldap.LDAPResultUnwillingToPerform ||
		reference.ambiguousCompareCode != ldap.LDAPResultSuccess {
		t.Fatalf("OpenLDAP unique-candidate fixture drifted: %#v", reference)
	}
	got := run(t, true)
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf(
			"ldap-go back-meta candidate selection differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			got,
		)
	}
}

func seedOpenLDAPMetaCandidateProviders(
	t *testing.T,
	providerOneURI string,
	providerTwoURI string,
) {
	t.Helper()
	providerOne, err := ldap.DialURL(providerOneURI)
	if err != nil {
		t.Fatalf("dial broad candidate provider: %v", err)
	}
	defer providerOne.Close()
	if err := providerOne.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind broad candidate provider: %v", err)
	}
	adds := []*ldap.AddRequest{
		metaCandidateOUAdd("ou=team,dc=example,dc=com", "team"),
		metaCandidateUserAdd(
			"uid=broad-only,ou=team,dc=example,dc=com",
			"broad-only",
			"broad-provider",
			"broad-secret",
		),
		metaCandidateOUAdd("ou=parent,ou=team,dc=example,dc=com", "parent"),
		metaCandidateUserAdd(
			"uid=ambiguous,ou=team,dc=example,dc=com",
			"ambiguous",
			"broad-ambiguous",
			"ambiguous-secret",
		),
	}
	for _, request := range adds {
		if err := providerOne.Add(request); err != nil {
			t.Fatalf("seed broad candidate provider %s: %v", request.DN, err)
		}
	}

	providerTwo, err := ldap.DialURL(providerTwoURI)
	if err != nil {
		t.Fatalf("dial specific candidate provider: %v", err)
	}
	defer providerTwo.Close()
	if err := providerTwo.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("bind specific candidate provider: %v", err)
	}
	request := metaCandidateUserAdd(
		"uid=ambiguous,ou=people,dc=example,dc=com",
		"ambiguous",
		"specific-ambiguous",
		"ambiguous-secret",
	)
	if err := providerTwo.Add(request); err != nil {
		t.Fatalf("seed specific candidate provider %s: %v", request.DN, err)
	}
	requestOU := metaCandidateOUAdd(
		"ou=specific-parent,ou=people,dc=example,dc=com",
		"specific-parent",
	)
	if err := providerTwo.Add(requestOU); err != nil {
		t.Fatalf("seed specific candidate provider %s: %v", requestOU.DN, err)
	}
}

func metaCandidateOUAdd(dn string, ou string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"organizationalUnit"})
	request.Attribute("ou", []string{ou})
	return request
}

func metaCandidateUserAdd(
	dn string,
	uid string,
	description string,
	password string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{"Candidate"})
	request.Attribute("description", []string{description})
	request.Attribute("userPassword", []string{password})
	return request
}

func observeOpenLDAPMetaCandidates(
	t *testing.T,
	proxyURI string,
	providerOneURI string,
) openLDAPMetaCandidateOutcome {
	t.Helper()
	outcome := openLDAPMetaCandidateOutcome{}
	broadDN := "uid=broad-only,ou=team," + openLDAPMetaBaseDN
	user, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial candidate proxy as user: %v", err)
	}
	outcome.broadBindCode = monitorLDAPResultCode(user.Bind(broadDN, "broad-secret"))
	if outcome.broadBindCode == ldap.LDAPResultSuccess {
		result, searchErr := user.Search(ldap.NewSearchRequest(
			"uid=route-two,"+openLDAPMetaSpecificBase,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"description"},
			nil,
		))
		outcome.crossTargetCode = monitorLDAPResultCode(searchErr)
		if result != nil && len(result.Entries) == 1 {
			outcome.crossTargetDesc = result.Entries[0].GetAttributeValue("description")
		}
	}
	user.Close()

	root, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial candidate proxy as root: %v", err)
	}
	defer root.Close()
	if err := root.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind candidate proxy root: %v", err)
	}
	outcome.broadCompareMatched, err = root.Compare(
		broadDN,
		"description",
		"broad-provider",
	)
	outcome.broadCompareCode = monitorLDAPResultCode(err)
	modify := ldap.NewModifyRequest(broadDN, nil)
	modify.Replace("description", []string{"broad-modified"})
	outcome.broadModifyCode = monitorLDAPResultCode(root.Modify(modify))
	outcome.broadProviderDesc = searchOpenLDAPMetaURI(
		t,
		providerOneURI,
		"uid=broad-only,ou=team,dc=example,dc=com",
	).description

	addDN := "uid=parent-add,ou=parent,ou=team," + openLDAPMetaBaseDN
	add := ldap.NewAddRequest(addDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"parent-add"})
	add.Attribute("cn", []string{"parent-add"})
	add.Attribute("sn", []string{"Candidate"})
	outcome.parentFallbackAdd = monitorLDAPResultCode(root.Add(add))
	outcome.parentProviderCode = searchOpenLDAPMetaURI(
		t,
		providerOneURI,
		"uid=parent-add,ou=parent,ou=team,dc=example,dc=com",
	).code
	outcome.crossTargetRename = monitorLDAPResultCode(root.ModifyDN(
		ldap.NewModifyDNRequest(
			broadDN,
			"uid=broad-only",
			true,
			"ou=specific-parent,"+openLDAPMetaSpecificBase,
		),
	))
	_, err = root.Compare(
		"uid=ambiguous,ou=team,"+openLDAPMetaBaseDN,
		"uid",
		"ambiguous",
	)
	outcome.ambiguousCompareCode = monitorLDAPResultCode(err)
	return outcome
}
