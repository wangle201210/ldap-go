package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestAuthzidBindWire(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			store := authzidTestStore(t, enabled)
			address, stop := startServer(t, store, Config{})
			defer stop()
			for _, test := range []struct {
				name, dn, password string
				controls           []ldapwire.Control
				enabledCode        ldapwire.ResultCode
				disabledCode       ldapwire.ResultCode
				diagnostic         string
				identity           string
				response           bool
			}{
				{name: "no request", dn: aliceDN, password: "secret"},
				{name: "noncritical", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID}}, response: true, identity: "dn:" + aliceDN},
				{name: "stored DN spelling", dn: "uid=ALICE,ou=PEOPLE,dc=EXAMPLE,dc=COM", password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID}}, response: true, identity: "dn:" + aliceDN},
				{name: "critical", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID, Critical: true}}, disabledCode: ldapwire.ResultUnavailableCriticalExtension, response: true, identity: "dn:" + aliceDN},
				{name: "anonymous", controls: []ldapwire.Control{{OID: authzidRequestControlOID}}, response: true},
				{name: "wrong password", dn: aliceDN, password: "wrong", controls: []ldapwire.Control{{OID: authzidRequestControlOID}}, enabledCode: ldapwire.ResultInvalidCredentials, disabledCode: ldapwire.ResultInvalidCredentials},
				{name: "absent user", dn: "uid=missing,ou=people,dc=example,dc=com", password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID}}, enabledCode: ldapwire.ResultInvalidCredentials, disabledCode: ldapwire.ResultInvalidCredentials},
				{name: "empty value", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID, HasValue: true}}, enabledCode: ldapwire.ResultProtocolError, diagnostic: "authzid control value not absent"},
				{name: "nonempty value", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID, HasValue: true, Value: []byte("dn:any")}}, enabledCode: ldapwire.ResultProtocolError, diagnostic: "authzid control value not absent"},
				{name: "critical empty value", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID, Critical: true, HasValue: true}}, enabledCode: ldapwire.ResultProtocolError, disabledCode: ldapwire.ResultUnavailableCriticalExtension, diagnostic: "authzid control value not absent"},
				{name: "duplicate", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID}, {OID: authzidRequestControlOID}}, enabledCode: ldapwire.ResultProtocolError, diagnostic: "authzid control specified multiple times"},
				{name: "duplicate mixed criticality", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidRequestControlOID}, {OID: authzidRequestControlOID, Critical: true}}, enabledCode: ldapwire.ResultProtocolError, disabledCode: ldapwire.ResultUnavailableCriticalExtension, diagnostic: "authzid control specified multiple times"},
				{name: "response OID is not a request", dn: aliceDN, password: "secret", controls: []ldapwire.Control{{OID: authzidResponseControlOID, Critical: true}}, enabledCode: ldapwire.ResultUnavailableCriticalExtension, disabledCode: ldapwire.ResultUnavailableCriticalExtension},
			} {
				t.Run(test.name, func(t *testing.T) {
					connection := authzidTestDial(t, address)
					response := authzidTestExchange(t, connection, ldapwire.Message{
						ID: 1, Request: ldapwire.BindRequest{Version: 3, Name: test.dn, Authentication: ldapwire.Authentication{Simple: []byte(test.password)}}, Controls: test.controls,
					})
					want := test.disabledCode
					if enabled {
						want = test.enabledCode
					}
					assertRawLDAPEnvelope(t, response, 1, ldapwire.ApplicationBindResponse, int64(want))
					if enabled && test.diagnostic != "" && string(response.Children[1].Children[2].Data.Bytes()) != test.diagnostic {
						t.Fatalf("diagnostic = %q, want %q", response.Children[1].Children[2].Data.Bytes(), test.diagnostic)
					}
					assertAuthzidResponse(t, response, enabled && test.response, test.identity)
				})
			}
		})
	}
}

func TestAuthzidControlScopeAndIdentityReset(t *testing.T) {
	store := authzidTestStore(t, true)
	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := authzidTestDial(t, address)
	bind := ldapwire.Message{ID: 1, Request: ldapwire.BindRequest{Version: 3, Name: aliceDN, Authentication: ldapwire.Authentication{Simple: []byte("secret")}}, Controls: []ldapwire.Control{{OID: authzidRequestControlOID}}}
	assertAuthzidResponse(t, authzidTestExchange(t, connection, bind), true, "dn:"+aliceDN)
	bind.ID = 2
	bind.Controls[0].HasValue = true
	response := authzidTestExchange(t, connection, bind)
	assertRawLDAPEnvelope(t, response, 2, ldapwire.ApplicationBindResponse, int64(ldapwire.ResultProtocolError))
	assertAuthzidResponse(t, response, false, "")
	response = authzidTestExchange(t, connection, ldapwire.Message{ID: 3, Request: ldapwire.ExtendedRequest{Name: whoAmIOID}})
	assertRawLDAPEnvelope(t, response, 3, ldapwire.ApplicationExtendedResponse, 0)
	for _, child := range response.Children[1].Children[3:] {
		if child.Tag == 11 && child.Data.Len() != 0 {
			t.Fatalf("failed controlled Bind retained previous identity: %q", child.Data.Bytes())
		}
	}
	response = authzidTestExchange(t, connection, ldapwire.Message{ID: 4, Request: ldapwire.ExtendedRequest{Name: whoAmIOID}, Controls: []ldapwire.Control{{OID: authzidRequestControlOID, Critical: true}}})
	assertRawLDAPEnvelope(t, response, 4, ldapwire.ApplicationExtendedResponse, int64(ldapwire.ResultUnavailableCriticalExtension))
	assertAuthzidResponse(t, response, false, "")
	bind.ID, bind.Controls = 5, nil
	response = authzidTestExchange(t, connection, bind)
	assertRawLDAPEnvelope(t, response, 5, ldapwire.ApplicationBindResponse, 0)
	assertAuthzidResponse(t, response, false, "")
	bind.ID, bind.Controls = 6, []ldapwire.Control{{OID: authzidRequestControlOID}}
	bind.Request = ldapwire.BindRequest{Version: 3}
	assertAuthzidResponse(t, authzidTestExchange(t, connection, bind), true, "")

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(3 * time.Second)
	root, err := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil))
	if err != nil || len(root.Entries) != 1 {
		t.Fatalf("Root DSE: %+v %v", root, err)
	}
	for _, oid := range root.Entries[0].GetAttributeValues("supportedControl") {
		if oid == authzidRequestControlOID || oid == authzidResponseControlOID {
			t.Fatalf("Root DSE advertises hidden authzid control %s", oid)
		}
	}
}

func TestAuthzidRootBindUsesConfiguredDN(t *testing.T) {
	store := authzidTestStore(t, true)
	const rootDN = "cn=Directory Manager,dc=example,dc=com"
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(staticRuntimeDN("olcDatabase={1}mdb,cn=config"))
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRootDN", stringValues(rootDN))
		entry.ReplaceValues("olcRootPW", stringValues("root-secret"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()
	response := authzidTestExchange(t, authzidTestDial(t, address), ldapwire.Message{
		ID: 1, Request: ldapwire.BindRequest{Version: 3,
			Name: "cn=directory manager,dc=EXAMPLE,dc=COM", Authentication: ldapwire.Authentication{Simple: []byte("root-secret")}},
		Controls: []ldapwire.Control{{OID: authzidRequestControlOID}},
	})
	assertRawLDAPEnvelope(t, response, 1, ldapwire.ApplicationBindResponse, 0)
	assertAuthzidResponse(t, response, true, "dn:"+rootDN)
}

func TestAuthzidSASLBindWire(t *testing.T) {
	store := authzidTestStore(t, true)
	seedSASLPlainConfiguration(t, store, "none")
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(staticRuntimeDN("olcDatabase={1}mdb,cn=config"))
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcReadOnly", stringValues("TRUE"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()
	for _, finalControl := range []bool{false, true} {
		t.Run(fmt.Sprintf("finalControl=%t", finalControl), func(t *testing.T) {
			connection := authzidTestDial(t, address)
			request := ldapwire.BindRequest{Version: 3, Authentication: ldapwire.Authentication{IsSASL: true, SASLMechanism: "PLAIN"}}
			message := ldapwire.Message{ID: 1, Request: request, Controls: []ldapwire.Control{{OID: authzidRequestControlOID, Critical: true}}}
			response := authzidTestExchange(t, connection, message)
			assertRawLDAPEnvelope(t, response, 1, ldapwire.ApplicationBindResponse, int64(ldapwire.ResultSASLBindInProgress))
			assertAuthzidResponse(t, response, false, "")
			request.Authentication.HasSASLCredentials = true
			request.Authentication.SASLCredentials = []byte("\x00alice\x00secret")
			message.ID, message.Request = 2, request
			if !finalControl {
				message.Controls = nil
			}
			response = authzidTestExchange(t, connection, message)
			assertRawLDAPEnvelope(t, response, 2, ldapwire.ApplicationBindResponse, 0)
			assertAuthzidResponse(t, response, finalControl, "dn:"+aliceDN)
		})
	}
}

func TestAuthzidDisclosureRestrictionsWire(t *testing.T) {
	for _, test := range []struct{ name, attribute, value, diagnostic string }{
		{"update strength", "olcSecurity", "update_ssf=128", "confidentiality required for update"},
		{"read only", "olcReadOnly", "TRUE", "operation restricted"},
		{"modify restricted", "olcRestrict", "modify", "operation restricted"},
		{"SASL required", "olcRequires", "SASL", "SASL authentication required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := authzidTestStore(t, true)
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				entry, err := writer.Get(staticRuntimeDN("olcDatabase={1}mdb,cn=config"))
				if err != nil {
					return err
				}
				entry.ReplaceValues(test.attribute, stringValues(test.value))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatal(err)
			}
			address, stop := startServer(t, store, Config{})
			defer stop()
			connection := authzidTestDial(t, address)
			bind := ldapwire.Message{ID: 1, Request: ldapwire.BindRequest{Version: 3, Name: aliceDN, Authentication: ldapwire.Authentication{Simple: []byte("secret")}}}
			response := authzidTestExchange(t, connection, bind)
			assertRawLDAPEnvelope(t, response, 1, ldapwire.ApplicationBindResponse, 0)
			bind.ID, bind.Controls = 2, []ldapwire.Control{{OID: authzidRequestControlOID}}
			response = authzidTestExchange(t, connection, bind)
			assertRawLDAPEnvelope(t, response, 2, ldapwire.ApplicationBindResponse, int64(ldapwire.ResultConfidentialityRequired))
			if got := string(response.Children[1].Children[2].Data.Bytes()); got != test.diagnostic {
				t.Fatalf("diagnostic = %q, want %q", got, test.diagnostic)
			}
			assertAuthzidResponse(t, response, false, "")
			bind.ID, bind.Request = 3, ldapwire.BindRequest{Version: 3}
			response = authzidTestExchange(t, connection, bind)
			assertRawLDAPEnvelope(t, response, 3, ldapwire.ApplicationBindResponse, 0)
			assertAuthzidResponse(t, response, true, "")
		})
	}
}

func TestAuthzidResponsePreservesSASLCredentialsAndControls(t *testing.T) {
	state := &connectionState{boundDN: aliceDN, runtime: &runtimeState{}}
	connection := &authzidBindResponseConnection{state: state, messageID: 7}
	policy := ldapwire.Control{OID: passwordPolicyControlOID, HasValue: true, Value: []byte{0x30, 0}}
	credentials := []byte{0x00, 0xff, 'v', '='}
	for _, code := range []ldapwire.ResultCode{ldapwire.ResultSuccess, ldapwire.ResultSASLBindInProgress, ldapwire.ResultInvalidCredentials} {
		encoded := ldapwire.EncodeSASLBindResponse(7, ldapwire.Result{Code: code}, credentials, true, []ldapwire.Control{policy})
		output, err := connection.transform(encoded)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := ber.DecodePacketErr(output)
		if err != nil {
			t.Fatal(err)
		}
		controls, err := decodePBindResponseControls(packet)
		if err != nil || len(controls) == 0 || !reflect.DeepEqual(controls[0], policy) {
			t.Fatalf("password policy control changed: %#v %v", controls, err)
		}
		assertAuthzidResponse(t, packet, code == ldapwire.ResultSuccess, "dn:"+aliceDN)
		if len(packet.Children[1].Children) != 4 || !bytes.Equal(packet.Children[1].Children[3].Data.Bytes(), credentials) {
			t.Fatal("SASL server credentials changed")
		}
		if code != ldapwire.ResultSuccess && !bytes.Equal(output, encoded) {
			t.Fatal("non-success response changed")
		}
	}
	otherID := ldapwire.EncodeBindResponse(8, ldapwire.Result{}, nil)
	otherOperation := ldapwire.EncodeSearchResultDone(7, ldapwire.Result{}, nil)
	for _, encoded := range [][]byte{otherID, otherOperation} {
		output, err := connection.transform(encoded)
		if err != nil || !bytes.Equal(output, encoded) {
			t.Fatalf("unrelated response changed: %v", err)
		}
	}
}

func TestAuthzidOverlayConfiguration(t *testing.T) {
	for _, test := range []struct{ name, parent, value string }{
		{"frontend", "olcDatabase={-1}frontend,cn=config", "{0}authzid"},
		{"data database", "olcDatabase={1}mdb,cn=config", "{0}authzid"},
		{"missing parent", "olcDatabase={2}mdb,cn=config", "{0}authzid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := authzidTestStore(t, false)
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				return writer.Put(authzidTestOverlayEntry(test.parent, test.value), false)
			}); err != nil {
				t.Fatal(err)
			}
			databases, err := loadRuntimeDatabases(t.Context(), store)
			if test.name != "frontend" {
				if err == nil || (test.name == "data database" && !strings.Contains(err.Error(), "slapo-authzid must be global")) {
					t.Fatalf("invalid overlay configuration accepted: %v", err)
				}
				return
			}
			if err != nil || !runtimeAuthzidEnabled(&runtimeState{databases: databases, features: runtimeFeaturesForDatabases(databases)}) {
				t.Fatalf("frontend authzid configuration: %v", err)
			}
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				return writer.Put(authzidTestOverlayEntry(test.parent, "{1}authzid"), false)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRuntimeDatabases(t.Context(), store); err == nil || !strings.Contains(err.Error(), "duplicate authzid") {
				t.Fatalf("duplicate overlay accepted: %v", err)
			}
		})
	}
	invalid := []runtimeDatabase{{name: "mdb", authzidOverlay: true}}
	if runtimeAuthzidEnabled(&runtimeState{databases: invalid, features: runtimeFeaturesForDatabases(invalid)}) {
		t.Fatal("non-global authzid flag enabled global control")
	}
	if got := runtimeDatabaseOverlayCount(runtimeDatabase{authzidOverlay: true}); got != 1 {
		t.Fatalf("authzid overlay count = %d", got)
	}
}

func TestAuthzidBindControlBeforeSecurity(t *testing.T) {
	databases := []runtimeDatabase{{name: "frontend", authzidOverlay: true}}
	state := &connectionState{runtime: &runtimeState{databases: databases, features: runtimeFeaturesForDatabases(databases)}}
	message := ldapwire.Message{Request: ldapwire.BindRequest{Version: 3}, Controls: []ldapwire.Control{{OID: authzidRequestControlOID, Critical: true}}}
	if failure := requestControlFailureBeforeSecurity(state, message); failure != nil {
		t.Fatalf("enabled Bind control rejected before security: %+v", failure)
	}
	message.Controls[0].HasValue = true
	if failure := requestControlFailureBeforeSecurity(state, message); failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("malformed enabled Bind control accepted: %+v", failure)
	}
	state.runtime.databases = nil
	state.runtime.features = runtimeOperationFeatures{}
	if failure := requestControlFailureBeforeSecurity(state, message); failure == nil || failure.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("disabled Bind control accepted: %+v", failure)
	}
}

func TestAuthzidWrapperPreservesAuditAndFinalization(t *testing.T) {
	underlying := &authzidTestAuditConnection{}
	connection := &authzidBindResponseConnection{Conn: underlying}
	setAuditAuthorizationDN(connection, aliceDN)
	tracking := []audit.SessionTracking{{Identifier: "bind-session"}}
	setAuditSessionTracking(connection, tracking)
	if err := connection.beginFinalResponse(); err != nil {
		t.Fatal(err)
	}
	if underlying.identity != aliceDN || !reflect.DeepEqual(underlying.tracking, tracking) || underlying.finalized != 1 {
		t.Fatalf("wrapper lost operation metadata: %#v", underlying)
	}
	setAuthzidBindDN(&lastBindResponseConnection{Conn: &sockOverlayResponseConnection{Conn: connection}}, aliceDN)
	if connection.entryDN != aliceDN {
		t.Fatal("effective Bind DN was lost through response wrappers")
	}
}

type authzidTestAuditConnection struct {
	net.Conn
	identity  string
	tracking  []audit.SessionTracking
	finalized int
}

func (connection *authzidTestAuditConnection) setAuditAuthorizationDN(value string) {
	connection.identity = value
}

func (connection *authzidTestAuditConnection) setAuditSessionTracking(values []audit.SessionTracking) {
	connection.tracking = values
}

func (connection *authzidTestAuditConnection) beginFinalResponse() error {
	connection.finalized++
	return nil
}

func authzidTestStore(t *testing.T, enabled bool) storage.Store {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		parent := "olcDatabase={-1}frontend,cn=config"
		if err := writer.Put(directory.Entry{DN: parent, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcFrontendConfig")},
			{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
		}}, false); err != nil {
			return err
		}
		if enabled {
			return writer.Put(authzidTestOverlayEntry(parent, "{0}authzid"), false)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func authzidTestOverlayEntry(parent, value string) directory.Entry {
	return directory.Entry{DN: "olcOverlay=" + value + "," + parent, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
		{Description: "olcOverlay", Values: stringValues(value)},
	}}
}

func authzidTestDial(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func authzidTestExchange(t *testing.T, connection net.Conn, message ldapwire.Message) *ber.Packet {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	encoded, err := ldapwire.EncodeRequestMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := ldapwire.Write(connection, encoded); err != nil {
		t.Fatal(err)
	}
	return readRawLDAPPacket(t, connection)
}

func assertAuthzidResponse(t *testing.T, packet *ber.Packet, present bool, identity string) {
	t.Helper()
	controls, err := decodePBindResponseControls(packet)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, control := range controls {
		if control.OID != authzidResponseControlOID {
			continue
		}
		count++
		if control.Critical || !control.HasValue || string(control.Value) != identity {
			t.Fatalf("authzid response = %#v, want present noncritical %q", control, identity)
		}
	}
	if (present && count != 1) || (!present && count != 0) {
		t.Fatalf("authzid response count = %d, want present=%t", count, present)
	}
}
