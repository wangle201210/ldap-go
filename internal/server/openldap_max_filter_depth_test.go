package server

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type maxFilterDepthDisconnectObservation struct {
	messageID      int64
	applicationTag uint64
	resultCode     int64
	diagnostic     string
	responseName   string
	closed         bool
}

func TestOpenLDAPMaxFilterDepthDisconnectDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"maxfilterdepth 1",
		"",
		"",
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcMaxFilterDepth",
				Values:      stringValues("1"),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed olcMaxFilterDepth: %v", err)
	}
	localAddress, stopLocal := startServer(t, store, Config{})
	t.Cleanup(stopLocal)

	reference := observeMaxFilterDepthDisconnect(
		t,
		strings.TrimPrefix(referenceURI, "ldap://"),
	)
	local := observeMaxFilterDepthDisconnect(t, localAddress)
	if !reflect.DeepEqual(local, reference) {
		t.Fatalf("max filter depth disconnect differs:\nOpenLDAP: %#v\nldap-go:  %#v", reference, local)
	}
	want := maxFilterDepthDisconnectObservation{
		messageID:      0,
		applicationTag: ldapwire.ApplicationExtendedResponse,
		resultCode:     int64(ldap.LDAPResultProtocolError),
		diagnostic:     "filter nested too deeply",
		responseName:   "1.3.6.1.4.1.1466.20036",
		closed:         true,
	}
	if !reflect.DeepEqual(reference, want) {
		t.Fatalf("OpenLDAP observation drifted: got %#v, want %#v", reference, want)
	}
}

func observeMaxFilterDepthDisconnect(
	t *testing.T,
	address string,
) maxFilterDepthDisconnectObservation {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeRawLDAPRequest(
		t,
		connection,
		1,
		rawMaxFilterDepthSearch(rawNestedNotFilter(2)),
	)
	response, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("read filter-depth response: %v", err)
	}
	if len(response.Children) < 2 || len(response.Children[1].Children) < 4 {
		t.Fatalf("malformed filter-depth response: %#v", response)
	}
	operation := response.Children[1]
	messageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	code, err := ber.ParseInt64(operation.Children[0].Data.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	observation := maxFilterDepthDisconnectObservation{
		messageID:      messageID,
		applicationTag: uint64(operation.Tag),
		resultCode:     code,
		diagnostic:     operation.Children[2].Data.String(),
		responseName:   operation.Children[3].Data.String(),
	}
	_, err = ber.ReadPacket(connection)
	if err != nil {
		if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
			observation.closed = true
		}
	}
	return observation
}
