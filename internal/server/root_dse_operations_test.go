package server

import (
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type rootDSEOperationResult struct {
	code       int64
	diagnostic string
}

func TestRootDSECoreOperationResultsAndConnectionReuse(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		request ldapwire.Request
		want    rootDSEOperationResult
	}{
		{
			name: "Add",
			request: ldapwire.AddRequest{Entry: directory.Entry{
				DN: "",
				Attributes: []directory.Attribute{{
					Description: "objectClass",
					Values:      stringValues("top"),
				}},
			}},
			want: rootDSEOperationResult{
				code:       int64(ldap.LDAPResultEntryAlreadyExists),
				diagnostic: "root DSE already exists",
			},
		},
		{
			name: "Modify",
			request: ldapwire.ModifyRequest{
				DN: "",
				Changes: []ldapwire.Modification{{
					Operation: ldapwire.ModificationReplace,
					Attribute: directory.Attribute{
						Description: "description",
						Values:      stringValues("unsupported"),
					},
				}},
			},
			want: rootDSEOperationResult{
				code:       int64(ldap.LDAPResultUnwillingToPerform),
				diagnostic: "modify upon the root DSE not supported",
			},
		},
		{
			name:    "Delete",
			request: ldapwire.DeleteRequest{DN: ""},
			want: rootDSEOperationResult{
				code:       int64(ldap.LDAPResultUnwillingToPerform),
				diagnostic: "cannot delete the root DSE",
			},
		},
		{
			name: "ModifyDN",
			request: ldapwire.ModifyDNRequest{
				DN:           "",
				NewRDN:       "cn=renamed",
				DeleteOldRDN: true,
			},
			want: rootDSEOperationResult{
				code:       int64(ldap.LDAPResultUnwillingToPerform),
				diagnostic: "cannot rename the root DSE",
			},
		},
		{
			name: "ModifyDN with empty newSuperior",
			request: ldapwire.ModifyDNRequest{
				DN:             "",
				NewRDN:         "cn=renamed",
				DeleteOldRDN:   true,
				HasNewSuperior: true,
				NewSuperior:    "",
			},
			want: rootDSEOperationResult{
				code:       int64(ldap.LDAPResultUnwillingToPerform),
				diagnostic: "cannot rename the root DSE",
			},
		},
		{
			name: "Compare without equality matching rule",
			request: ldapwire.CompareRequest{
				DN:        "",
				Attribute: "supportedLDAPVersion",
				Assertion: []byte("3"),
			},
			want: rootDSEOperationResult{
				code:       int64(ldap.LDAPResultInappropriateMatching),
				diagnostic: "inappropriate matching request",
			},
		},
		{
			name: "Compare true",
			request: ldapwire.CompareRequest{
				DN:        "",
				Attribute: "objectClass",
				Assertion: []byte("top"),
			},
			want: rootDSEOperationResult{code: int64(ldap.LDAPResultCompareTrue)},
		},
		{
			name: "Compare false",
			request: ldapwire.CompareRequest{
				DN:        "",
				Attribute: "objectClass",
				Assertion: []byte("person"),
			},
			want: rootDSEOperationResult{code: int64(ldap.LDAPResultCompareFalse)},
		},
		{
			name: "Compare missing attribute",
			request: ldapwire.CompareRequest{
				DN:        "",
				Attribute: "description",
				Assertion: []byte("missing"),
			},
			want: rootDSEOperationResult{code: int64(ldap.LDAPResultNoSuchAttribute)},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			messageID := int64(index + 1)
			encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
				ID:      messageID,
				Request: test.request,
			})
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			if err := ldapwire.Write(connection, encoded); err != nil {
				t.Fatalf("write request: %v", err)
			}
			got := readRootDSEOperationResult(t, connection, messageID)
			if got != test.want {
				t.Fatalf("result = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestRootDSEWriteSkipsSecurityWhileCompareEnforcesIt(t *testing.T) {
	state := &connectionState{runtime: &runtimeState{
		security: securityStrengthRequirements{overall: 1},
	}}
	if result := requestSecurityResult(state, ldapwire.AddRequest{
		Entry: directory.Entry{DN: ""},
	}); result != nil {
		t.Fatalf("Root DSE Add security result = %#v", result)
	}
	result := requestSecurityResult(state, ldapwire.CompareRequest{DN: ""})
	assertSecurityResult(
		t,
		result,
		ldapwire.ResultConfidentialityRequired,
		"confidentiality required",
	)
}

func readRootDSEOperationResult(
	t *testing.T,
	connection net.Conn,
	wantMessageID int64,
) rootDSEOperationResult {
	t.Helper()
	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(response.Children) < 2 || len(response.Children[1].Children) < 3 {
		t.Fatalf("malformed response: %#v", response)
	}
	messageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil || messageID != wantMessageID {
		t.Fatalf("message ID = %d, %v; want %d", messageID, err, wantMessageID)
	}
	code, err := ber.ParseInt64(response.Children[1].Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return rootDSEOperationResult{
		code:       code,
		diagnostic: response.Children[1].Children[2].Data.String(),
	}
}
