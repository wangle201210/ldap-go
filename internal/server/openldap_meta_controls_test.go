package server

import (
	"errors"
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type openLDAPMetaControlOutcome struct {
	initialModifyCode uint16
	postReadDN        string
	postReadSeeAlso   string
	dnAssertionCode   uint16
	providerSeeAlso   string
	providerDesc      string
}

func TestOpenLDAPReferenceMetaStructuredControls(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)

	run := func(t *testing.T, ldapGo bool) openLDAPMetaControlOutcome {
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
		deadURI := reserveClosedOpenLDAPMetaURI(t)
		var proxyURI string
		var stop func()
		if ldapGo {
			proxyURI, stop = startLDAPGoMetaReferenceFixture(
				t,
				deadURI,
				providerOne,
				providerTwo,
			)
		} else {
			proxyURI, stop = startOpenLDAPMetaProxy(
				t,
				tools,
				deadURI,
				providerOne,
				providerTwo,
			)
		}
		defer stop()
		return observeOpenLDAPMetaControls(t, proxyURI, providerOne)
	}

	reference := run(t, false)
	got := run(t, true)
	if !reflect.DeepEqual(got, reference) {
		t.Fatalf(
			"ldap-go back-meta structured controls differ from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			got,
		)
	}
}

func observeOpenLDAPMetaControls(
	t *testing.T,
	proxyURI string,
	providerOneURI string,
) openLDAPMetaControlOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-meta control fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind back-meta control fixture: %v", err)
	}

	targetDN := "uid=route-one,ou=people," + openLDAPMetaBaseDN
	initial := ldap.NewModifyRequest(targetDN, []ldap.Control{
		newAssertionControl(t, "(description=provider-one)"),
		ldap.NewControlString(
			postReadControlOID,
			true,
			string(rawAttributeSelection("seeAlso")),
		),
	})
	initial.Add("seeAlso", []string{targetDN})
	initialResult, initialErr := client.ModifyWithResult(initial)
	outcome := openLDAPMetaControlOutcome{
		initialModifyCode: monitorLDAPResultCode(initialErr),
	}
	if initialResult != nil {
		for _, control := range initialResult.Controls {
			if control.GetControlType() != postReadControlOID {
				continue
			}
			value, ok := control.(*ldap.ControlString)
			if !ok {
				t.Fatalf("post-read response control type = %T", control)
			}
			entry, decodeErr := decodeOpenLDAPMetaReadResponseControl(
				[]byte(value.ControlValue),
			)
			if decodeErr != nil {
				t.Fatalf("decode post-read response control: %v", decodeErr)
			}
			outcome.postReadDN = entry.DN
			if values := entry.Values("seeAlso"); len(values) > 0 {
				outcome.postReadSeeAlso = string(values[0])
			}
		}
	}

	assertDN := ldap.NewModifyRequest(targetDN, []ldap.Control{
		newAssertionControl(t, "(seeAlso="+targetDN+")"),
	})
	assertDN.Replace("description", []string{"assertion-dn-mapped"})
	outcome.dnAssertionCode = monitorLDAPResultCode(client.Modify(assertDN))

	provider := searchOpenLDAPMetaURI(t, providerOneURI, "uid=route-one,ou=people,dc=example,dc=com")
	outcome.providerDesc = provider.description
	providerClient, err := ldap.DialURL(providerOneURI)
	if err != nil {
		t.Fatalf("dial provider for DN-valued control state: %v", err)
	}
	defer providerClient.Close()
	providerResult, err := providerClient.Search(ldap.NewSearchRequest(
		"uid=route-one,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"seeAlso"},
		nil,
	))
	if err != nil || len(providerResult.Entries) != 1 {
		t.Fatalf("read provider DN-valued control state: %#v, %v", providerResult, err)
	}
	outcome.providerSeeAlso = providerResult.Entries[0].GetAttributeValue("seeAlso")
	return outcome
}

func decodeOpenLDAPMetaReadResponseControl(value []byte) (directory.Entry, error) {
	operation, err := ber.DecodePacketErr(value)
	if err != nil {
		return directory.Entry{}, err
	}
	if operation.ClassType != ber.ClassApplication ||
		operation.Tag != ldapwire.ApplicationSearchResultEntry {
		return directory.Entry{}, errors.New("read response control is not a SearchResultEntry")
	}
	envelope := ber.NewSequence("LDAPMessage")
	envelope.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		0,
		"messageID",
	))
	envelope.AppendChild(operation)
	return decodeTranslucentSearchEntry(envelope)
}
