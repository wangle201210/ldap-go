package server

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseSessionTrackingControls(t *testing.T) {
	valid := sessionTrackingTestControl(ldapwire.SessionTrackingValue{
		SessionSourceIP:           []byte("192.0.2.10"),
		SessionSourceName:         []byte("edge.example.com"),
		FormatOID:                 []byte(sessionTrackingUsernameFormatOID),
		SessionTrackingIdentifier: []byte("alice"),
	})
	for _, request := range []ldapwire.Request{
		ldapwire.BindRequest{},
		ldapwire.SearchRequest{},
		ldapwire.CompareRequest{},
		ldapwire.AddRequest{},
		ldapwire.ModifyRequest{},
		ldapwire.DeleteRequest{},
		ldapwire.ModifyDNRequest{},
		ldapwire.ExtendedRequest{Name: passwordModifyOID},
		ldapwire.ExtendedRequest{Name: whoAmIOID},
		ldapwire.ExtendedRequest{Name: dynamicRefreshOID},
	} {
		values, failure := parseSessionTrackingControls(
			request,
			[]ldapwire.Control{valid, valid},
		)
		if failure != nil || len(values) != 2 ||
			values[0].SourceIP != "192.0.2.10" ||
			values[0].FormatName != "USERNAME" ||
			values[0].Identifier != "alice" {
			t.Errorf("parse %T session tracking = %#v, %#v", request, values, failure)
		}
	}

	for _, test := range []struct {
		name     string
		request  ldapwire.Request
		control  ldapwire.Control
		wantCode ldapwire.ResultCode
	}{
		{
			name:    "critical supported",
			request: ldapwire.SearchRequest{},
			control: func() ldapwire.Control {
				control := valid
				control.Critical = true
				return control
			}(),
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "absent value",
			request:  ldapwire.SearchRequest{},
			control:  ldapwire.Control{OID: ldapwire.SessionTrackingControlOID},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "empty value",
			request:  ldapwire.SearchRequest{},
			control:  ldapwire.Control{OID: ldapwire.SessionTrackingControlOID, HasValue: true},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "malformed value",
			request:  ldapwire.SearchRequest{},
			control:  ldapwire.Control{OID: ldapwire.SessionTrackingControlOID, HasValue: true, Value: []byte{0x30, 0x00}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:    "critical unsupported extended",
			request: ldapwire.ExtendedRequest{Name: "1.2.3.4"},
			control: func() ldapwire.Control {
				control := valid
				control.Critical = true
				return control
			}(),
			wantCode: ldapwire.ResultUnavailableCriticalExtension,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failure := parseSessionTrackingControls(
				test.request,
				[]ldapwire.Control{test.control},
			)
			if failure == nil || failure.Code != test.wantCode {
				t.Fatalf("failure = %#v, want %d", failure, test.wantCode)
			}
		})
	}

	values, failure := parseSessionTrackingControls(
		ldapwire.ExtendedRequest{Name: "1.2.3.4"},
		[]ldapwire.Control{{
			OID: ldapwire.SessionTrackingControlOID, HasValue: true,
			Value: []byte("ignored malformed value"),
		}},
	)
	if failure != nil || len(values) != 0 {
		t.Fatalf("unsupported noncritical control = %#v, %#v", values, failure)
	}

	invalidOID := sessionTrackingTestControl(ldapwire.SessionTrackingValue{
		SessionSourceIP: []byte("192.0.2.10"),
		FormatOID:       []byte("invalid"),
	})
	values, failure = parseSessionTrackingControls(
		ldapwire.SearchRequest{},
		[]ldapwire.Control{invalidOID},
	)
	if failure != nil || len(values) != 0 {
		t.Fatalf("invalid format OID = %#v, %#v", values, failure)
	}

	nonPrintable := sessionTrackingTestControl(ldapwire.SessionTrackingValue{
		SessionSourceIP:           []byte{0, 1},
		SessionSourceName:         []byte(" printable "),
		FormatOID:                 []byte("1.2.3"),
		SessionTrackingIdentifier: []byte{0xff},
	})
	values, failure = parseSessionTrackingControls(
		ldapwire.SearchRequest{},
		[]ldapwire.Control{nonPrintable},
	)
	if failure != nil || len(values) != 1 || values[0].SourceIP != "" ||
		values[0].SourceName != "" || values[0].Identifier != "" ||
		!values[0].IdentifierPresent {
		t.Fatalf("non-printable session tracking = %#v, %#v", values, failure)
	}
}

func TestSessionTrackingOperationAuditIsolation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	sink := &recordingAuditSink{}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
		AuditSink:    sink,
	})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	search := func(identifier string, controls int) {
		requestControls := make([]ldap.Control, controls)
		for index := range requestControls {
			requestControls[index] = &domainScopeWireControl{
				oid:      ldapwire.SessionTrackingControlOID,
				hasValue: true,
				value: ldapwire.EncodeSessionTrackingValue(ldapwire.SessionTrackingValue{
					SessionSourceIP:           []byte("203.0.113.9"),
					SessionSourceName:         []byte("gateway.example"),
					FormatOID:                 []byte(sessionTrackingUsernameFormatOID),
					SessionTrackingIdentifier: []byte(identifier + string(rune('0'+index))),
				}),
			}
		}
		_, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"1.1"}, requestControls,
		))
		if err != nil {
			t.Fatalf("Search(%s): %v", identifier, err)
		}
	}
	search("first-", 2)
	search("second-", 1)

	events := waitForAuditEvents(t, sink, 3)
	first := events[1]
	second := events[2]
	if len(first.SessionTracking) != 2 ||
		first.SessionTracking[0].Identifier != "first-0" ||
		first.SessionTracking[1].Identifier != "first-1" ||
		len(second.SessionTracking) != 1 ||
		second.SessionTracking[0].Identifier != "second-0" {
		t.Fatalf("session tracking audit isolation = first %#v, second %#v", first, second)
	}
	if first.RemoteAddress == "203.0.113.9" ||
		first.AuthenticationDN != "cn=admin,dc=example,dc=com" ||
		first.AuthorizationDN != "cn=admin,dc=example,dc=com" ||
		!slices.Contains(first.RequestControls, ldapwire.SessionTrackingControlOID) {
		t.Fatalf("session tracking polluted trusted audit identity: %#v", first)
	}
}

func TestLDAPBackendSessionTrackingForwarding(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAudit := &recordingAuditSink{}
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
		AuditSink:    providerAudit,
	})
	t.Cleanup(stopProvider)

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedLDAPBackendProxy(t, proxyStore, providerAddress)
	if err := proxyStore.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(ldapBackendTestDatabaseDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbSessionTrackingRequest", stringValues("TRUE"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("enable LDAP backend session tracking: %v", err)
	}
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	t.Cleanup(stopProxy)
	client := dialLDAPBackendClient(t, proxyAddress)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(proxy root): %v", err)
	}
	control := &domainScopeWireControl{
		oid:      ldapwire.SessionTrackingControlOID,
		hasValue: true,
		value: ldapwire.EncodeSessionTrackingValue(ldapwire.SessionTrackingValue{
			SessionSourceIP:           []byte("198.51.100.20"),
			FormatOID:                 []byte(sessionTrackingUsernameFormatOID),
			SessionTrackingIdentifier: []byte("client-session"),
		}),
	}
	if _, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"uid"}, []ldap.Control{control},
	)); err != nil {
		t.Fatalf("proxied Search(): %v", err)
	}

	events := waitForAuditEvents(t, providerAudit, 2)
	var searchEvent *audit.Event
	for index := range events {
		if events[index].Operation == "search" {
			searchEvent = &events[index]
		}
	}
	if searchEvent == nil || len(searchEvent.SessionTracking) != 2 ||
		searchEvent.SessionTracking[0].Identifier != "client-session" ||
		searchEvent.SessionTracking[1].Identifier != ldapBackendTestLocalRootDN {
		t.Fatalf("provider session tracking event = %#v; all events %#v", searchEvent, events)
	}

	replay := pcacheReplayMessage(ldapwire.Message{Controls: []ldapwire.Control{
		{OID: "1.2.3"},
		sessionTrackingTestControl(ldapwire.SessionTrackingValue{FormatOID: []byte("1.2")}),
	}})
	if len(replay.Controls) != 1 || replay.Controls[0].OID != "1.2.3" {
		t.Fatalf("pcache replay controls = %#v", replay.Controls)
	}
}

func TestSockOverlayConsumesSessionTrackingControl(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command != "SEARCH" {
			return fmt.Errorf("unexpected socket command %q", request.command)
		}
		return writeAll(connection, []byte("CONTINUE\n\n"))
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockOverlayRuntimeConfiguration(
		t,
		store,
		fixture.path,
		[]string{"search"},
		nil,
	)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client := dialSockRuntimeClient(t, address)
	t.Cleanup(func() { _ = client.Close() })
	control := &domainScopeWireControl{
		oid:      ldapwire.SessionTrackingControlOID,
		hasValue: true,
		value: ldapwire.EncodeSessionTrackingValue(ldapwire.SessionTrackingValue{
			SessionSourceIP:           []byte("192.0.2.10"),
			FormatOID:                 []byte(sessionTrackingUsernameFormatOID),
			SessionTrackingIdentifier: []byte("sock-client"),
		}),
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"uid"},
		[]ldap.Control{control},
	))
	if err != nil || len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("uid") != "alice" {
		t.Fatalf("session-tracked sock overlay Search = %#v, %v", result, err)
	}
	assertSockRuntimeCommand(t, fixture.take(t), "SEARCH")
}

func TestRootDSEHidesSessionTrackingControl(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	result, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Root DSE Search = %#v, %v", result, err)
	}
	if slices.Contains(
		result.Entries[0].GetAttributeValues("supportedControl"),
		ldapwire.SessionTrackingControlOID,
	) {
		t.Fatal("hidden Session Tracking control was published")
	}
}

func sessionTrackingTestControl(value ldapwire.SessionTrackingValue) ldapwire.Control {
	return ldapwire.Control{
		OID:      ldapwire.SessionTrackingControlOID,
		HasValue: true,
		Value:    ldapwire.EncodeSessionTrackingValue(value),
	}
}
