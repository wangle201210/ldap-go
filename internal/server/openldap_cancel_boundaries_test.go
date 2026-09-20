package server

import (
	"math"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceCancelRequestBoundaries(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServer(t, tools, nil)
	t.Cleanup(stopReference)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)

	for _, endpoint := range []struct{ name, address string }{
		{"OpenLDAP", trimLDAPURI(referenceURI)},
		{"ldap-go", address},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, test := range []struct {
				name       string
				value      []byte
				absent     bool
				code       int64
				diagnostic string
			}{
				{"absent", nil, true, 2, "no message ID supplied"},
				{"empty", []byte{}, false, 2, "empty request data field"},
				{"empty sequence", []byte{0x30, 0}, false, 2, "message ID parse failed"},
				{"unknown", ldapwire.EncodeCancelRequestValue(99), false, 119, "message ID not found"},
				{"self", ldapwire.EncodeCancelRequestValue(2), false, 0, ""},
				{"self with trailing bytes", append(ldapwire.EncodeCancelRequestValue(2), 0xff), false, 0, ""},
				{"outer trailing bytes", append(ldapwire.EncodeCancelRequestValue(99), 0xff), false, 119, "message ID not found"},
				{"outer second ID", append(ldapwire.EncodeCancelRequestValue(99), ldapwire.EncodeCancelRequestValue(2)...), false, 119, "message ID not found"},
				{"inner second ID", []byte{0x30, 6, 2, 1, 99, 2, 1, 2}, false, 119, "message ID not found"},
				{"inner trailing bytes", []byte{0x30, 4, 2, 1, 99, 0xff}, false, 119, "message ID not found"},
				{"zero", ldapwire.EncodeCancelRequestValue(0), false, 119, "message ID not found"},
				{"empty integer", []byte{0x30, 2, 2, 0}, false, 119, "message ID not found"},
				{"negative", ldapwire.EncodeCancelRequestValue(-1), false, 2, "message ID invalid"},
				{"minimum ID", ldapwire.EncodeCancelRequestValue(math.MinInt32), false, 2, "message ID invalid"},
				{"large ID", ldapwire.EncodeCancelRequestValue(math.MaxInt32), false, 119, "message ID not found"},
				{"overflow", ldapwire.EncodeCancelRequestValue(math.MaxInt32 + 1), false, 2, "message ID parse failed"},
				{"nonminimal length", []byte{0x30, 0x81, 3, 2, 1, 99}, false, 119, "message ID not found"},
				{"nonminimal integer length", []byte{0x30, 4, 2, 0x81, 1, 99}, false, 119, "message ID not found"},
				{"outer tag ignored", []byte{0x31, 3, 2, 1, 99}, false, 119, "message ID not found"},
				{"integer tag ignored", []byte{0x30, 3, 4, 1, 99}, false, 119, "message ID not found"},
				{"high outer tag", []byte{0x3f, 0x1f, 3, 2, 1, 99}, false, 119, "message ID not found"},
				{"high integer tag", []byte{0x30, 4, 0x1f, 0x1f, 1, 99}, false, 119, "message ID not found"},
				{"ID outside declared sequence", []byte{0x30, 0, 2, 1, 99}, false, 119, "message ID not found"},
				{"indefinite length", []byte{0x30, 0x80, 2, 1, 99, 0, 0}, false, 2, "message ID parse failed"},
				{"truncated ID", []byte{0x30, 3, 2, 2, 99}, false, 2, "message ID parse failed"},
				{"truncated outer", []byte{0x30, 4, 2, 1, 99}, false, 2, "message ID parse failed"},
				{"overflowing length", []byte{0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false, 2, "message ID parse failed"},
				{"oversized length", []byte{0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2, 1, 99}, false, 2, "message ID parse failed"},
				{"truncated tag", []byte{0x3f, 0x80}, false, 2, "message ID parse failed"},
				{"oversized tag", []byte{0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 3, 2, 1, 99}, false, 2, "message ID parse failed"},
			} {
				t.Run(test.name, func(t *testing.T) {
					connection := dialAndBindRawLDAP(t, endpoint.address, "", "")
					defer connection.Close()
					response := sendRawLDAPOperation(t, connection, 2,
						rawExtendedRequest(cancelOID, test.value, !test.absent))
					assertRawLDAPEnvelope(t, response, 2, ldapwire.ApplicationExtendedResponse, test.code)
					if diagnostic := rawLDAPDiagnostic(response); diagnostic != test.diagnostic {
						t.Fatalf("diagnostic = %q, want %q", diagnostic, test.diagnostic)
					}
					if len(response.Children) != 2 || len(response.Children[1].Children) != 3 {
						t.Fatalf("unexpected Cancel response fields: %#v", response)
					}
					response = sendRawLDAPOperation(t, connection, 3, rawExtendedRequest(whoAmIOID, nil, false))
					assertRawLDAPEnvelope(t, response, 3, ldapwire.ApplicationExtendedResponse, int64(ldap.LDAPResultSuccess))
				})
			}
		})
	}
}
