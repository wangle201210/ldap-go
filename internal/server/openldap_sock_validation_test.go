package server

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPSockValidationDN = "uid=validation," + openLDAPSockBaseDN

type openLDAPSockValidationCase struct {
	name      string
	anonymous bool
	request   func() *ber.Packet
	want      openLDAPSockValidationObservation
}

type openLDAPSockValidationObservation struct {
	responseTag uint64
	code        int64
	matchedDN   string
	diagnostic  string
	networkErr  string
	socket      string
}

func TestOpenLDAPReferenceSockFrontendValidation(t *testing.T) {
	tools := requireOpenLDAPSockReferenceTools(t)
	fixture := startOpenLDAPSockFixture(t)

	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"include "+filepath.Join(tools.schemaDir, "nis.schema"),
		fmt.Sprintf(`database sock
suffix "%s"
socketpath "%s"
extensions binddn peername ssf connid
access to * by * manage`, openLDAPSockBaseDN, fixture.path),
		"",
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoSockValidationConfiguration(t, store, fixture.path)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{})
	defer stopLDAPGo()

	tests := openLDAPSockValidationCases()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reference := observeOpenLDAPSockValidation(
				t,
				strings.TrimPrefix(openLDAPURI, "ldap://"),
				fixture,
				test,
			)
			if !reflect.DeepEqual(reference, test.want) {
				t.Errorf(
					"pinned OpenLDAP validation = %#v, want observed 2.6.13 behavior %#v",
					reference,
					test.want,
				)
			}

			implementation := observeOpenLDAPSockValidation(
				t,
				ldapGoAddress,
				fixture,
				test,
			)
			if !reflect.DeepEqual(implementation, reference) {
				t.Errorf(
					"ldap-go validation differs\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					implementation,
				)
			}
		})
	}
}

func openLDAPSockValidationCases() []openLDAPSockValidationCase {
	return []openLDAPSockValidationCase{
		{
			name: "Add without attributes",
			request: func() *ber.Packet {
				return rawAddRequest(directory.Entry{DN: openLDAPSockValidationDN})
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationAddResponse,
				code:        int64(ldapwire.ResultProtocolError),
				diagnostic:  "no attributes provided",
			},
		},
		{
			name: "Add with undefined attribute",
			request: func() *ber.Packet {
				entry := openLDAPSockValidationEntry("undefined")
				entry.Attributes = append(entry.Attributes, directory.Attribute{
					Description: "notRegistered",
					Values:      stringValues("value"),
				})
				return rawAddRequest(entry)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationAddResponse,
				code:        int64(ldapwire.ResultUndefinedAttributeType),
				diagnostic:  "notRegistered: attribute type undefined",
			},
		},
		{
			name: "Add with invalid attribute syntax",
			request: func() *ber.Packet {
				entry := openLDAPSockValidationEntry("invalid-add")
				entry.Attributes[0].Values = stringValues("inetOrgPerson", "posixAccount")
				entry.Attributes = append(entry.Attributes,
					directory.Attribute{Description: "uidNumber", Values: stringValues("not-an-integer")},
					directory.Attribute{Description: "gidNumber", Values: stringValues("1000")},
					directory.Attribute{Description: "homeDirectory", Values: stringValues("/home/validation")},
				)
				return rawAddRequest(entry)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationAddResponse,
				code:        int64(ldapwire.ResultInvalidAttributeSyntax),
				diagnostic:  "uidNumber: value #0 invalid per syntax",
			},
		},
		{
			name: "Modify without changes",
			request: func() *ber.Packet {
				return rawOpenLDAPSockEmptyModifyRequest(openLDAPSockValidationDN)
			},
			// OpenLDAP 2.6.13 accepts the empty sequence and delegates it.
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyResponse,
				code:        int64(ldapwire.ResultSuccess),
				diagnostic:  " modify complete",
				socket:      "MODIFY",
			},
		},
		{
			name: "Modify with undefined attribute",
			request: func() *ber.Packet {
				return rawModifyReplaceRequest(
					openLDAPSockValidationDN,
					"notRegistered",
					"value",
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyResponse,
				code:        int64(ldapwire.ResultUndefinedAttributeType),
				diagnostic:  "notRegistered: attribute type undefined",
			},
		},
		{
			name: "Modify with invalid attribute syntax",
			request: func() *ber.Packet {
				return rawModifyReplaceRequest(
					openLDAPSockValidationDN,
					"uidNumber",
					"not-an-integer",
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyResponse,
				code:        int64(ldapwire.ResultInvalidAttributeSyntax),
				diagnostic:  "uidNumber: value #0 invalid per syntax",
			},
		},
		{
			name: "Modify increment with multiple values",
			request: func() *ber.Packet {
				return rawOpenLDAPSockModifyRequest(
					openLDAPSockValidationDN,
					ldapwire.ModificationIncrement,
					"uidNumber",
					"1",
					"2",
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyResponse,
				code:        int64(ldapwire.ResultProtocolError),
				diagnostic:  "modify/increment operation requires single value",
			},
		},
		{
			name: "Compare with undefined attribute",
			request: func() *ber.Packet {
				return rawDontUseCopyCompareRequest(
					openLDAPSockValidationDN,
					"notRegistered",
					"value",
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationCompareResponse,
				code:        int64(ldapwire.ResultUndefinedAttributeType),
			},
		},
		{
			name: "Compare with invalid assertion syntax",
			request: func() *ber.Packet {
				return rawDontUseCopyCompareRequest(
					openLDAPSockValidationDN,
					"uidNumber",
					"not-an-integer",
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationCompareResponse,
				code:        int64(ldapwire.ResultInvalidAttributeSyntax),
				diagnostic:  "value does not conform to assertion syntax",
			},
		},
		{
			name: "ModifyDN with invalid new RDN",
			request: func() *ber.Packet {
				return rawOpenLDAPSockModifyDNRequest(
					openLDAPSockValidationDN,
					"uid",
					true,
					"",
					false,
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyDNResponse,
				code:        int64(ldapwire.ResultInvalidDNSyntax),
				diagnostic:  "invalid new RDN",
			},
		},
		{
			name: "ModifyDN with invalid new superior",
			request: func() *ber.Packet {
				return rawOpenLDAPSockModifyDNRequest(
					openLDAPSockValidationDN,
					"uid=validation",
					true,
					"not-a-dn",
					true,
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyDNResponse,
				code:        int64(ldapwire.ResultInvalidDNSyntax),
				diagnostic:  "invalid newSuperior",
			},
		},
		{
			name: "ModifyDN across naming contexts",
			request: func() *ber.Packet {
				return rawOpenLDAPSockModifyDNRequest(
					openLDAPSockValidationDN,
					"uid=validation",
					true,
					"ou=people,dc=example,dc=com",
					true,
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationModifyDNResponse,
				code:        int64(ldapwire.ResultAffectsMultipleDSAs),
				diagnostic:  "cannot rename between DSAs",
			},
		},
		{
			name:      "anonymous Password Modify",
			anonymous: true,
			request: func() *ber.Packet {
				return rawExtendedRequest(
					passwordModifyOID,
					rawOpenLDAPSockPasswordModifyValue("replacement"),
					true,
				)
			},
			want: openLDAPSockValidationObservation{
				responseTag: ldapwire.ApplicationExtendedResponse,
				code:        int64(ldapwire.ResultStrongerAuthRequired),
				diagnostic:  "only authenticated users may change passwords",
			},
		},
	}
}

func seedLDAPGoSockValidationConfiguration(
	t *testing.T,
	store storage.Store,
	socketPath string,
) {
	t.Helper()
	seedLDAPGoSockReferenceConfiguration(t, store, socketPath)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{
			DN: "olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{2}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		}, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{
			openLDAPSockBaseDN,
			"dc=example,dc=com",
			"cn=config",
		})
	}); err != nil {
		t.Fatalf("seed ldap-go sock validation configuration: %v", err)
	}
}

func openLDAPSockValidationEntry(uid string) directory.Entry {
	return directory.Entry{
		DN: "uid=" + uid + "," + openLDAPSockBaseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues("Validation User")},
			{Description: "sn", Values: stringValues("User")},
		},
	}
}

func observeOpenLDAPSockValidation(
	t *testing.T,
	address string,
	fixture *openLDAPSockFixture,
	test openLDAPSockValidationCase,
) openLDAPSockValidationObservation {
	t.Helper()
	bindDN := openLDAPSockBindDN
	password := openLDAPSockPassword
	if test.anonymous {
		bindDN = ""
		password = ""
	}
	connection := dialAndBindRawLDAP(t, address, bindDN, password)
	defer connection.Close()
	if !test.anonymous {
		requests := fixture.take(t, 1)
		if requests[0].command != "BIND" {
			t.Fatalf(
				"%s setup socket command = %q, want BIND\n%s",
				test.name,
				requests[0].command,
				requests[0].raw,
			)
		}
	}

	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(2),
		"messageID",
	))
	message.AppendChild(test.request())
	if err := ldapwire.Write(connection, message.Bytes()); err != nil {
		t.Fatalf("%s write LDAP operation: %v", test.name, err)
	}

	observation := openLDAPSockValidationObservation{}
	response, err := ber.ReadPacket(connection)
	if err != nil {
		observation.networkErr = err.Error()
	} else if response == nil || len(response.Children) < 2 {
		observation.networkErr = fmt.Sprintf("malformed LDAP response: %#v", response)
	} else {
		operation := response.Children[1]
		observation.responseTag = uint64(operation.Tag)
		observation.code = rawLDAPResultCode(t, operation)
		if len(operation.Children) > 1 {
			observation.matchedDN = string(operation.Children[1].Data.Bytes())
		}
		if len(operation.Children) > 2 {
			observation.diagnostic = string(operation.Children[2].Data.Bytes())
		}
	}

	select {
	case request := <-fixture.requests:
		observation.socket = request.command
	case err := <-fixture.failures:
		t.Fatalf("%s socket fixture failed: %v", test.name, err)
	case <-time.After(20 * time.Millisecond):
	}
	return observation
}

func rawOpenLDAPSockEmptyModifyRequest(dn string) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationModifyRequest,
		nil,
		"ModifyRequest",
	)
	request.AppendChild(rawOctetString([]byte(dn)))
	request.AppendChild(ber.NewSequence("changes"))
	return request
}

func rawOpenLDAPSockModifyRequest(
	dn string,
	operation ldapwire.ModificationOperation,
	description string,
	values ...string,
) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationModifyRequest,
		nil,
		"ModifyRequest",
	)
	request.AppendChild(rawOctetString([]byte(dn)))
	changes := ber.NewSequence("changes")
	change := ber.NewSequence("change")
	change.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(operation),
		"operation",
	))
	rawValues := make([][]byte, len(values))
	for index := range values {
		rawValues[index] = []byte(values[index])
	}
	change.AppendChild(rawPartialAttribute(description, rawValues))
	changes.AppendChild(change)
	request.AppendChild(changes)
	return request
}

func rawOpenLDAPSockModifyDNRequest(
	dn, newRDN string,
	deleteOldRDN bool,
	newSuperior string,
	hasNewSuperior bool,
) *ber.Packet {
	request := rawModifyDNRequest(dn, newRDN, deleteOldRDN)
	if hasNewSuperior {
		superior := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			0,
			nil,
			"newSuperior",
		)
		_, _ = superior.Data.Write([]byte(newSuperior))
		request.AppendChild(superior)
	}
	return request
}

func rawOpenLDAPSockPasswordModifyValue(newPassword string) []byte {
	value := ber.NewSequence("PasswordModifyRequestValue")
	password := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		2,
		nil,
		"newPasswd",
	)
	_, _ = password.Data.Write([]byte(newPassword))
	value.AppendChild(password)
	return value.Bytes()
}
