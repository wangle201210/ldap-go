package server

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceSessionTrackingControl(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"access to * by * read",
		"",
	)
	t.Cleanup(stopReference)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	goAddress, stopGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopGo)

	validValue := ldapwire.SessionTrackingValue{
		SessionSourceIP:           []byte("192.0.2.10"),
		SessionSourceName:         []byte("gateway.example"),
		FormatOID:                 []byte(sessionTrackingUsernameFormatOID),
		SessionTrackingIdentifier: []byte("alice"),
	}
	control := func(value []byte, critical, hasValue bool) ldap.Control {
		return &domainScopeWireControl{
			oid: ldapwire.SessionTrackingControlOID, critical: critical,
			hasValue: hasValue, value: value,
		}
	}
	encoded := func(value ldapwire.SessionTrackingValue) []byte {
		return ldapwire.EncodeSessionTrackingValue(value)
	}
	valid := control(encoded(validValue), false, true)
	validOID1024 := strings.Repeat("1.", 511) + "11"

	for _, test := range []struct {
		name     string
		controls []ldap.Control
	}{
		{name: "valid", controls: []ldap.Control{valid}},
		{name: "duplicate", controls: []ldap.Control{valid, valid}},
		{name: "critical", controls: []ldap.Control{control(encoded(validValue), true, true)}},
		{name: "absent", controls: []ldap.Control{control(nil, false, false)}},
		{name: "empty", controls: []ldap.Control{control(nil, false, true)}},
		{name: "malformed", controls: []ldap.Control{control([]byte{0x30, 0x00}, false, true)}},
		{name: "arbitrary inner tags", controls: []ldap.Control{control(sessionTrackingValueWithTags(
			validValue,
			[]ber.Tag{ber.TagInteger, 0, ber.TagSet, 7},
		), false, true)}},
		{name: "empty optional fields", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			FormatOID: []byte("1.2.3"),
		}), false, true)}},
		{name: "non-printable fields", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			SessionSourceIP:           []byte{0, 1},
			SessionSourceName:         []byte{0xff},
			FormatOID:                 []byte("1.2.3"),
			SessionTrackingIdentifier: []byte{0xff},
		}), false, true)}},
		{name: "invalid OID ignored", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			SessionSourceIP: []byte("192.0.2.10"), FormatOID: []byte("invalid"),
		}), false, true)}},
		{name: "IP at limit", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			SessionSourceIP: bytes.Repeat([]byte{'i'}, 128), FormatOID: []byte("1.2"),
		}), false, true)}},
		{name: "IP over limit", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			SessionSourceIP: bytes.Repeat([]byte{'i'}, 129), FormatOID: []byte("1.2"),
		}), false, true)}},
		{name: "name at limit", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			SessionSourceName: bytes.Repeat([]byte{'n'}, 65536), FormatOID: []byte("1.2"),
		}), false, true)}},
		{name: "name over limit", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			SessionSourceName: bytes.Repeat([]byte{'n'}, 65537), FormatOID: []byte("1.2"),
		}), false, true)}},
		{name: "OID at limit", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			FormatOID: []byte(validOID1024),
		}), false, true)}},
		{name: "OID over limit", controls: []ldap.Control{control(encoded(ldapwire.SessionTrackingValue{
			FormatOID: []byte(validOID1024 + "1"),
		}), false, true)}},
		{name: "extra field", controls: []ldap.Control{control(sessionTrackingValueWithExtraField(validValue), false, true)}},
		{name: "trailing byte", controls: []ldap.Control{control(append(encoded(validValue), 0), false, true)}},
		{name: "valid then malformed", controls: []ldap.Control{valid, control([]byte{0x30, 0x00}, false, true)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeSessionTrackingSearch(
				t,
				trimLDAPURI(referenceURI),
				test.controls,
			)
			implementation := observeSessionTrackingSearch(t, goAddress, test.controls)
			if reference != implementation {
				t.Fatalf("result mismatch: OpenLDAP=%d ldap-go=%d", reference, implementation)
			}
		})
	}

	referenceOperations := observeSessionTrackingOperations(
		t,
		trimLDAPURI(referenceURI),
		valid,
		"reference",
	)
	implementationOperations := observeSessionTrackingOperations(
		t,
		goAddress,
		valid,
		"implementation",
	)
	for index, code := range referenceOperations {
		if code != uint16(ldap.LDAPResultSuccess) {
			t.Fatalf("OpenLDAP supported operation %d result = %d", index, code)
		}
	}
	if !reflect.DeepEqual(referenceOperations, implementationOperations) {
		t.Fatalf(
			"operation mismatch\nOpenLDAP: %v\nldap-go:  %v",
			referenceOperations,
			implementationOperations,
		)
	}
}

func observeSessionTrackingSearch(
	t *testing.T,
	address string,
	controls []ldap.Control,
) uint16 {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(%s): %v", address, err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, controls,
	))
	return monitorLDAPResultCode(err)
}

func observeSessionTrackingOperations(
	t *testing.T,
	address string,
	control ldap.Control,
	identifier string,
) []uint16 {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	_, err = client.SimpleBind(ldap.NewSimpleBindRequest(
		"cn=admin,dc=example,dc=com",
		"secret",
		[]ldap.Control{control},
	))
	codes := []uint16{monitorLDAPResultCode(err)}
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, []ldap.Control{control},
	))
	codes = append(codes, monitorLDAPResultCode(err))

	dn := "uid=session-" + identifier + ",ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(dn, []ldap.Control{control})
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"session-" + identifier})
	add.Attribute("cn", []string{"Session Tracking"})
	add.Attribute("sn", []string{"Tracking"})
	codes = append(codes, monitorLDAPResultCode(client.Add(add)))
	modify := ldap.NewModifyRequest(dn, []ldap.Control{control})
	modify.Replace("cn", []string{"Session Tracking Updated"})
	codes = append(codes, monitorLDAPResultCode(client.Modify(modify)))
	renamedDN := "uid=session-renamed-" + identifier + ",ou=people,dc=example,dc=com"
	rename := ldap.NewModifyDNRequest(dn, "uid=session-renamed-"+identifier, true, "")
	rename.Controls = []ldap.Control{control}
	codes = append(codes, monitorLDAPResultCode(client.ModifyDN(rename)))
	codes = append(codes, monitorLDAPResultCode(client.Del(ldap.NewDelRequest(
		renamedDN,
		[]ldap.Control{control},
	))))
	whoami := ldap.NewExtendedRequest(whoAmIOID, nil)
	whoami.Controls = []ldap.Control{control}
	_, err = client.Extended(whoami)
	codes = append(codes, monitorLDAPResultCode(err))
	return codes
}

func sessionTrackingValueWithTags(
	value ldapwire.SessionTrackingValue,
	tags []ber.Tag,
) []byte {
	sequence := ber.NewSequence("SessionIdentifierControlValue")
	fields := [][]byte{
		value.SessionSourceIP,
		value.SessionSourceName,
		value.FormatOID,
		value.SessionTrackingIdentifier,
	}
	for index, field := range fields {
		class := ber.ClassUniversal
		if tags[index] == 0 || tags[index] == 7 {
			class = ber.ClassContext
		}
		child := ber.Encode(class, ber.TypePrimitive, tags[index], nil, "field")
		_, _ = child.Data.Write(field)
		sequence.AppendChild(child)
	}
	return sequence.Bytes()
}

func sessionTrackingValueWithExtraField(value ldapwire.SessionTrackingValue) []byte {
	sequence := ber.NewSequence("SessionIdentifierControlValue")
	for _, field := range [][]byte{
		value.SessionSourceIP,
		value.SessionSourceName,
		value.FormatOID,
		value.SessionTrackingIdentifier,
		[]byte("extra"),
	} {
		child := ber.Encode(
			ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
			nil, "field",
		)
		_, _ = child.Data.Write(field)
		sequence.AppendChild(child)
	}
	return sequence.Bytes()
}
