package server

import (
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type noOpSearchObservation struct {
	outerResult int64
	innerResult int64
	entries     int64
	references  int64
	wireEntries int
	hasControl  bool
}

func TestNoOpSearchOverlayCountsWithoutReturningEntries(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNoOpSearchOverlay(t, store)
	address, stop := startServer(t, store, Config{
		MaxSearchEntries: 100,
		RootDN:           "cn=admin,dc=example,dc=com",
		RootPassword:     []byte("secret"),
	})
	t.Cleanup(stop)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		client.Close()
		t.Fatal(err)
	}
	direct, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	client.Close()
	if err != nil || len(root.Entries) != 1 ||
		!containsString(root.Entries[0].GetAttributeValues("supportedControl"), noOpSearchControlOID) {
		t.Fatalf("Root DSE noopsrch capability = %#v, %v", root, err)
	}

	observation := observeNoOpSearch(t, address, 0)
	if observation.outerResult != int64(ldap.LDAPResultSuccess) ||
		observation.innerResult != int64(ldap.LDAPResultSuccess) ||
		observation.entries != int64(len(direct.Entries)) ||
		observation.references != 0 || observation.wireEntries != 0 ||
		!observation.hasControl {
		t.Fatalf("noopsrch observation = %#v, direct entries=%d", observation, len(direct.Entries))
	}
	limited := observeNoOpSearch(t, address, 1)
	if limited.outerResult != int64(ldap.LDAPResultSuccess) ||
		limited.innerResult != int64(ldap.LDAPResultSizeLimitExceeded) ||
		limited.entries != int64(len(direct.Entries)) || limited.wireEntries != 0 ||
		!limited.hasControl {
		t.Fatalf("limited noopsrch observation = %#v", limited)
	}
	rootNoOp := observeNoOpSearchRequest(
		t,
		address,
		"",
		ldap.ScopeBaseObject,
		0,
	)
	if rootNoOp.outerResult != int64(ldap.LDAPResultSuccess) ||
		rootNoOp.wireEntries != 1 || rootNoOp.hasControl {
		t.Fatalf("database-local Root DSE noopsrch = %#v", rootNoOp)
	}
}

func TestNoOpSearchFrontendOverlayCoversRootDSE(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedFrontendNoOpSearchOverlay(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stop)

	observation := observeNoOpSearchRequest(
		t,
		address,
		"",
		ldap.ScopeBaseObject,
		0,
	)
	if observation.outerResult != int64(ldap.LDAPResultSuccess) ||
		observation.innerResult != int64(ldap.LDAPResultSuccess) ||
		observation.entries != 1 || observation.references != 0 ||
		observation.wireEntries != 0 || !observation.hasControl {
		t.Fatalf("frontend Root DSE noopsrch = %#v", observation)
	}
}

func TestNoOpSearchControlValidation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNoOpSearchOverlay(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stop)
	for _, controls := range [][]ldapwire.Control{
		{{OID: noOpSearchControlOID, Critical: true, HasValue: true, Value: []byte{}}},
		{{OID: noOpSearchControlOID}, {OID: noOpSearchControlOID}},
	} {
		connection := dialRawNoOpSearch(t, address)
		packets := make([]*ber.Packet, len(controls))
		for index, control := range controls {
			packets[index] = encodeRawLDAPControl(control)
		}
		writeRawLDAPRequest(
			t,
			connection,
			1,
			rawSyncSearchRequestFor(
				t,
				"dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
			packets...,
		)
		if code := readRawLDAPResultCode(t, connection); code != int64(ldap.LDAPResultProtocolError) {
			t.Fatalf("control validation result = %d", code)
		}
		connection.Close()
	}
}

func seedNoOpSearchOverlay(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}noopsrch,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      stringValues("{0}noopsrch"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
}

func seedFrontendNoOpSearchOverlay(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				}},
			},
			{
				DN: "olcOverlay={0}noopsrch,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcOverlay",
					Values:      stringValues("{0}noopsrch"),
				}},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func observeNoOpSearch(t *testing.T, address string, sizeLimit int) noOpSearchObservation {
	t.Helper()
	return observeNoOpSearchRequest(
		t,
		address,
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		sizeLimit,
	)
}

func observeNoOpSearchRequest(
	t *testing.T,
	address,
	baseDN string,
	scope int,
	sizeLimit int,
) noOpSearchObservation {
	t.Helper()
	connection := dialRawNoOpSearch(t, address)
	defer connection.Close()
	operation := rawSyncSearchRequestFor(
		t,
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		"(objectClass=*)",
	)
	operation.Children[3] = ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(sizeLimit),
		"sizeLimit",
	)
	rebuilt := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationSearchRequest,
		nil,
		"SearchRequest",
	)
	for _, child := range operation.Children {
		rebuilt.AppendChild(child)
	}
	writeRawLDAPRequest(
		t,
		connection,
		1,
		rebuilt,
		encodeRawLDAPControl(ldapwire.Control{OID: noOpSearchControlOID, Critical: true}),
	)
	var observation noOpSearchObservation
	for {
		response, err := ber.ReadPacket(connection)
		if err != nil {
			t.Fatalf("read noopsrch response: %v", err)
		}
		operation := response.Children[1]
		switch uint64(operation.Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			observation.wireEntries++
		case ldapwire.ApplicationSearchResultDone:
			observation.outerResult, err = ber.ParseInt64(operation.Children[0].Data.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			controls := openLDAPReferenceControls(response)
			for _, control := range controls {
				if control.oid != noOpSearchControlOID {
					continue
				}
				value, err := ber.DecodePacketErr(control.value)
				if err != nil || len(value.Children) != 3 {
					t.Fatalf("decode noopsrch response control: %#v, %v", value, err)
				}
				observation.innerResult, _ = ber.ParseInt64(value.Children[0].Data.Bytes())
				observation.entries, _ = ber.ParseInt64(value.Children[1].Data.Bytes())
				observation.references, _ = ber.ParseInt64(value.Children[2].Data.Bytes())
				observation.hasControl = true
				return observation
			}
			return observation
		}
	}
}

func noOpSearchControlResult(
	t *testing.T,
	address string,
	controls []ldapwire.Control,
) int64 {
	t.Helper()
	connection := dialRawNoOpSearch(t, address)
	defer connection.Close()
	packets := make([]*ber.Packet, len(controls))
	for index, control := range controls {
		packets[index] = encodeRawLDAPControl(control)
	}
	writeRawLDAPRequest(
		t,
		connection,
		1,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		packets...,
	)
	return readRawLDAPResultCode(t, connection)
}

func dialRawNoOpSearch(t *testing.T, address string) net.Conn {
	t.Helper()
	return dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
}
