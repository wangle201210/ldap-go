package server

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceDomainScopeAndSearchOptions(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"access to * by * read",
		`
dn: ou=remote,dc=example,dc=com
objectClass: referral
objectClass: extensibleObject
ou: remote
ref: ldap://remote.example/dc=remote,dc=example
`,
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedDomainScopeReferral(t, store)
	goAddress, stopGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopGo)

	domain := func(critical, hasValue bool, value []byte) ldap.Control {
		return &domainScopeWireControl{
			oid: domainScopeControlOID, critical: critical,
			hasValue: hasValue, value: value,
		}
	}
	optionsValue := func(value []byte, critical, hasValue bool) ldap.Control {
		return &domainScopeWireControl{
			oid: searchOptionsControlOID, critical: critical,
			hasValue: hasValue, value: value,
		}
	}
	options := func(flags int32, critical bool) ldap.Control {
		return optionsValue(ldapwire.EncodeSearchOptionsValue(flags), critical, true)
	}

	for _, test := range []struct {
		name     string
		base     string
		scope    int
		controls []ldap.Control
	}{
		{name: "ordinary subtree"},
		{name: "domain absent", controls: []ldap.Control{domain(false, false, nil)}},
		{name: "critical domain absent", controls: []ldap.Control{domain(true, false, nil)}},
		{name: "domain empty", controls: []ldap.Control{domain(false, true, nil)}},
		{name: "domain nonempty", controls: []ldap.Control{domain(false, true, []byte{0})}},
		{name: "options zero", controls: []ldap.Control{options(0, false)}},
		{name: "options domain", controls: []ldap.Control{options(1, false)}},
		{name: "critical options domain", controls: []ldap.Control{options(1, true)}},
		{name: "phantom root ignored", controls: []ldap.Control{options(2, false)}},
		{name: "phantom root critical", controls: []ldap.Control{options(2, true)}},
		{name: "mixed flags ignored", controls: []ldap.Control{options(3, false)}},
		{name: "negative flags ignored", controls: []ldap.Control{options(-1, false)}},
		{name: "negative flags critical", controls: []ldap.Control{options(-1, true)}},
		{name: "options absent", controls: []ldap.Control{optionsValue(nil, false, false)}},
		{name: "options empty", controls: []ldap.Control{optionsValue(nil, false, true)}},
		{name: "options malformed", controls: []ldap.Control{optionsValue([]byte{0x30, 0x01}, false, true)}},
		{
			name: "permissive tags",
			controls: []ldap.Control{optionsValue(
				[]byte{0x04, 0x03, 0x01, 0x01, 0x01}, false, true,
			)},
		},
		{
			name: "permissive trailing data",
			controls: []ldap.Control{optionsValue(
				[]byte{0x30, 0x03, 0x02, 0x01, 0x01, 0xff}, false, true,
			)},
		},
		{
			name: "zero length integer",
			controls: []ldap.Control{optionsValue(
				[]byte{0x30, 0x02, 0x02, 0x00}, false, true,
			)},
		},
		{
			name: "duplicate domain",
			controls: []ldap.Control{
				domain(false, false, nil), domain(false, true, nil),
			},
		},
		{
			name: "domain then options zero",
			controls: []ldap.Control{
				domain(false, false, nil), options(0, false),
			},
		},
		{
			name: "options zero then domain",
			controls: []ldap.Control{
				options(0, false), domain(false, false, nil),
			},
		},
		{
			name: "domain then options domain",
			controls: []ldap.Control{
				domain(false, false, nil), options(1, false),
			},
		},
		{
			name: "options domain then domain",
			controls: []ldap.Control{
				options(1, false), domain(false, false, nil),
			},
		},
		{
			name:     "options zero twice",
			controls: []ldap.Control{options(0, false), options(0, true)},
		},
		{
			name:     "options zero then domain option",
			controls: []ldap.Control{options(0, false), options(1, true)},
		},
		{
			name:     "options domain twice",
			controls: []ldap.Control{options(1, false), options(1, false)},
		},
		{
			name: "base referral ordinary",
			base: domainScopeReferralDN, scope: ldap.ScopeBaseObject,
		},
		{
			name: "base referral domain",
			base: domainScopeReferralDN, scope: ldap.ScopeBaseObject,
			controls: []ldap.Control{domain(true, false, nil)},
		},
		{
			name: "base referral search options",
			base: domainScopeReferralDN, scope: ldap.ScopeBaseObject,
			controls: []ldap.Control{options(1, true)},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := test.base
			if base == "" {
				base = "dc=example,dc=com"
			}
			scope := test.scope
			if test.base == "" {
				scope = ldap.ScopeWholeSubtree
			}
			reference := observeDomainScopeSearch(
				t,
				trimLDAPURI(referenceURI),
				base,
				scope,
				test.controls,
			)
			implementation := observeDomainScopeSearch(
				t,
				goAddress,
				base,
				scope,
				test.controls,
			)
			if !reflect.DeepEqual(reference, implementation) {
				t.Fatalf(
					"domain-scope mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					implementation,
				)
			}
		})
	}
}

type domainScopeSearchObservation struct {
	code      uint16
	referrals []string
}

func observeDomainScopeSearch(
	t *testing.T,
	address,
	base string,
	scope int,
	controls []ldap.Control,
) domainScopeSearchObservation {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(%s): %v", address, err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"1.1"},
		controls,
	))
	observation := domainScopeSearchObservation{code: monitorLDAPResultCode(err)}
	if result != nil {
		observation.referrals = append([]string(nil), result.Referrals...)
		slices.Sort(observation.referrals)
	}
	return observation
}

type domainScopeWireControl struct {
	oid      string
	critical bool
	hasValue bool
	value    []byte
}

func (control *domainScopeWireControl) GetControlType() string { return control.oid }

func (control *domainScopeWireControl) Encode() *ber.Packet {
	packet := ber.NewSequence("Control")
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		control.oid, "controlType",
	))
	if control.critical {
		packet.AppendChild(ber.NewBoolean(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean,
			true, "criticality",
		))
	}
	if control.hasValue {
		value := ber.Encode(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
			nil, "controlValue",
		)
		_, _ = value.Data.Write(control.value)
		packet.AppendChild(value)
	}
	return packet
}

func (control *domainScopeWireControl) String() string {
	return fmt.Sprintf(
		"Control Type: %s Criticality: %t Value: %x",
		control.oid,
		control.critical,
		control.value,
	)
}
