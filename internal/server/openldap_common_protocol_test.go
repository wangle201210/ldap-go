package server

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferencePagingIgnoredAtRequestSizeLimit(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServer(t, tools, nil)
	defer stopReference()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedCommonProtocolPeople(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLocal()

	reference := observeIgnoredPaging(
		t,
		referenceURI,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	local := observeIgnoredPaging(
		t,
		"ldap://"+localAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	if reference != local {
		t.Fatalf("ignored paging: OpenLDAP=%#v ldap-go=%#v", reference, local)
	}
	if reference.resultCode != ldap.LDAPResultSizeLimitExceeded ||
		reference.entries != 2 || reference.pagingResponse {
		t.Fatalf("OpenLDAP ignored paging observation = %#v", reference)
	}
}

func TestOpenLDAPReferenceStartTLSRejectsOutstandingSearch(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{"retcode\nretcode-sleep 2"},
		openLDAPReferenceStartTLSConfiguration(t),
		"",
		"",
	)
	defer stop()
	probe, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP): %v", err)
	}
	rootDSE, err := probe.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension"},
		nil,
	))
	probe.Close()
	if err != nil {
		t.Fatalf("Search(OpenLDAP Root DSE): %v", err)
	}
	if len(rootDSE.Entries) != 1 {
		t.Fatalf("OpenLDAP Root DSE entries = %d", len(rootDSE.Entries))
	}
	extensions := rootDSE.Entries[0].GetAttributeValues("supportedExtension")
	foundStartTLS := false
	for _, extension := range extensions {
		if extension == startTLSOID {
			foundStartTLS = true
			break
		}
	}
	if !foundStartTLS {
		t.Fatalf("OpenLDAP supportedExtension = %v; StartTLS is absent", extensions)
	}

	connection, err := net.DialTimeout(
		"tcp",
		strings.TrimPrefix(uri, "ldap://"),
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("Dial(OpenLDAP): %v", err)
	}
	defer connection.Close()
	writeRawLDAPRequest(t, connection, 1, rawCancellationSearch(t), nil)
	time.Sleep(100 * time.Millisecond)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawExtendedRequest(startTLSOID, nil, false),
		nil,
	)
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read OpenLDAP StartTLS response: %v", err)
	}
	assertRawLDAPEnvelope(
		t,
		response,
		2,
		ldapwire.ApplicationExtendedResponse,
		int64(ldap.LDAPResultOperationsError),
	)
	if diagnostic := rawLDAPDiagnostic(response); diagnostic !=
		"cannot start TLS when operations are outstanding" {
		t.Fatalf("OpenLDAP StartTLS diagnostic = %q", diagnostic)
	}
}

func TestOpenLDAPReferenceConnectionPendingOverflowClosesSilently(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{"retcode\nretcode-sleep 2"},
		"threads 2\nconn_max_pending 1\nconn_max_pending_auth 1",
		"",
		"",
	)
	defer stop()

	connection, err := net.DialTimeout(
		"tcp",
		strings.TrimPrefix(uri, "ldap://"),
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("Dial(OpenLDAP): %v", err)
	}
	defer connection.Close()
	writeRawLDAPRequest(t, connection, 1, rawCancellationSearch(t), nil)
	time.Sleep(100 * time.Millisecond)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(whoAmIOID, nil, false),
		nil,
	)
	assertLDAPConnectionClosedWithoutResponse(t, connection)
}

type ignoredPagingObservation struct {
	resultCode     uint16
	entries        int
	pagingResponse bool
}

func observeIgnoredPaging(
	t *testing.T,
	uri,
	bindDN,
	password string,
) ignoredPagingObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind(bindDN, password); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}

	request := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		[]ldap.Control{ldap.NewControlPaging(2)},
	)
	result, searchErr := client.Search(request)
	observation := ignoredPagingObservation{}
	if searchErr != nil {
		var ldapError *ldap.Error
		if !errors.As(searchErr, &ldapError) {
			t.Fatalf("Search(%s): %v", uri, searchErr)
		}
		observation.resultCode = ldapError.ResultCode
	}
	if result != nil {
		observation.entries = len(result.Entries)
		observation.pagingResponse = ldap.FindControl(
			result.Controls,
			ldap.ControlTypePaging,
		) != nil
	}
	return observation
}

func seedCommonProtocolPeople(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, uid := range []string{"bob", "carol"} {
			if err := writer.Put(directory.Entry{
				DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues(uid)},
					{Description: "cn", Values: stringValues(uid)},
					{Description: "sn", Values: stringValues(uid)},
				},
			}, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed common protocol people: %v", err)
	}
}

func openLDAPReferenceStartTLSConfiguration(t *testing.T) string {
	t.Helper()
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	directory := t.TempDir()
	certificatePath := directory + "/server.crt"
	keyPath := directory + "/server.key"
	if err := os.WriteFile(certificatePath, certificate.certificatePEM, 0o600); err != nil {
		t.Fatalf("write OpenLDAP TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, certificate.privateKeyPEM, 0o600); err != nil {
		t.Fatalf("write OpenLDAP TLS key: %v", err)
	}
	return "TLSCertificateFile " + certificatePath +
		"\nTLSCertificateKeyFile " + keyPath
}
