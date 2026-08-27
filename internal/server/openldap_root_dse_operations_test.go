package server

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPRootDSECoreOperationDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServer(t, tools, nil)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	localAddress, stopLocal := startServer(t, store, Config{})
	t.Cleanup(stopLocal)

	reference := observeRootDSECoreOperations(
		t,
		strings.TrimPrefix(referenceURI, "ldap://"),
	)
	local := observeRootDSECoreOperations(t, localAddress)
	if !reflect.DeepEqual(local, reference) {
		t.Fatalf("Root DSE operations differ:\nOpenLDAP: %#v\nldap-go:  %#v", reference, local)
	}
}

func observeRootDSECoreOperations(
	t *testing.T,
	address string,
) []rootDSEOperationResult {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	requests := []ldapwire.Request{
		ldapwire.AddRequest{Entry: directory.Entry{
			DN: "",
			Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      stringValues("top"),
			}},
		}},
		ldapwire.ModifyRequest{
			DN: "",
			Changes: []ldapwire.Modification{{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "description",
					Values:      stringValues("unsupported"),
				},
			}},
		},
		ldapwire.DeleteRequest{DN: ""},
		ldapwire.ModifyDNRequest{
			DN:           "",
			NewRDN:       "cn=renamed",
			DeleteOldRDN: true,
		},
		ldapwire.CompareRequest{
			DN:        "",
			Attribute: "objectClass",
			Assertion: []byte("top"),
		},
	}
	results := make([]rootDSEOperationResult, 0, len(requests))
	for index, request := range requests {
		messageID := int64(index + 1)
		encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
			ID:      messageID,
			Request: request,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := ldapwire.Write(connection, encoded); err != nil {
			t.Fatal(err)
		}
		results = append(results, readRootDSEOperationResult(t, connection, messageID))
	}
	return results
}
