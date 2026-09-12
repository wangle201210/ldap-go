package lloadd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	ldapserver "github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	vcProjectAuthzRequest  = "2.16.840.1.113730.3.4.16"
	vcProjectAuthzResponse = "2.16.840.1.113730.3.4.15"
)

// All LDAP responses come from the real server. Its audit stream proves the
// physical service identity independently of each client's ACL-visible data.
func TestVerifyCredentialsProjectServerPoolIsolationAndReconnect(t *testing.T) {
	for _, method := range []string{"simple", "SCRAM-SHA-256"} {
		t.Run(method, func(t *testing.T) {
			backend, events := startVCProjectServer(t)
			config := serviceSASLRuntimeConfig(backend, "SCRAM-SHA-256", "u:service", "")
			if method == "simple" {
				config.Bind = RuntimeBindConfig{Method: "simple", DN: serviceSASLTestDN,
					Credentials: []byte(serviceSASLTestPassword), Timeout: 2 * time.Second}
			}
			config.VerifyCredentials = true
			config.Tiers[0].Backends[0].BindConnections = 3
			proxy, address := startRuntimeProxy(t, config)
			waitForReadyConnections(t, proxy, PoolRegular, 1)
			initial := awaitVCProjectServiceBind(t, events, method)
			old := vcProjectRegularUpstream(t, proxy)

			alice, bob := dialVCProjectClient(t, address), dialVCProjectClient(t, address)
			clients := []*ldap.Conn{alice, bob}
			names := []string{"alice", "bob"}
			for index, client := range clients {
				vcProjectBind(t, client, names[index], names[index]+"-secret", 0)
				assertVCProjectVerification(t, events, initial.ConnectionID, 0)
				vcProjectSearch(t, client, names[index], events, initial.ConnectionID)
			}
			for index, client := range clients {
				vcProjectBind(t, client, names[index], "wrong-password", ldap.LDAPResultInvalidCredentials)
				assertVCProjectVerification(t, events, initial.ConnectionID, ldap.LDAPResultInvalidCredentials)
				vcProjectSearch(t, client, "", events, initial.ConnectionID)
				vcProjectSearch(t, clients[1-index], names[1-index], events, initial.ConnectionID)
				vcProjectBind(t, client, names[index], names[index]+"-secret", 0)
				assertVCProjectVerification(t, events, initial.ConnectionID, 0)
			}

			// Two client connections issue overlapping searches through one
			// regular upstream; each result must retain its own effective DN.
			for range 4 {
				start := make(chan struct{})
				results := make(chan error, 2)
				for index, client := range clients {
					go func() {
						<-start
						result, err := client.Search(vcProjectSearchRequest(nil))
						if err == nil {
							err = validateVCProjectSearch(result, names[index])
						}
						results <- err
					}()
				}
				close(start)
				var searchErrors []error
				for range clients {
					if err := <-results; err != nil {
						searchErrors = append(searchErrors, err)
					}
				}
				if err := errors.Join(searchErrors...); err != nil {
					t.Fatal(err)
				}
				seen := make(map[string]bool)
				for range clients {
					event := awaitVCProjectAudit(t, events, "search")
					assertVCProjectServiceOperation(t, event, initial.ConnectionID, 0)
					if !slices.Equal(event.RequestControls, []string{ProxyAuthzControlOID}) ||
						(event.AuthorizationDN != vcProjectUserDN("alice") && event.AuthorizationDN != vcProjectUserDN("bob")) ||
						seen[event.AuthorizationDN] {
						t.Fatalf("concurrent search identity/control mismatch: %+v", event)
					}
					seen[event.AuthorizationDN] = true
				}
			}

			anonymous := dialVCProjectClient(t, address)
			vcProjectSearch(t, anonymous, "", events, initial.ConnectionID)
			for _, client := range []*ldap.Conn{alice, anonymous} {
				spoof := ldap.NewControlString(ProxyAuthzControlOID, true, "dn:"+vcProjectUserDN("bob"))
				result, err := client.Search(vcProjectSearchRequest([]ldap.Control{spoof}))
				if !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) || (result != nil && len(result.Entries) != 0) {
					t.Fatalf("client-supplied ProxyAuthz was not rejected: %+v, %v", result, err)
				}
				event := awaitVCProjectAudit(t, events, "search")
				assertVCProjectServiceOperation(t, event, initial.ConnectionID, ldap.LDAPResultProtocolError)
				if !slices.Equal(event.RequestControls, []string{ProxyAuthzControlOID, ProxyAuthzControlOID}) {
					t.Fatalf("client-supplied control replaced authenticated identity: %+v", event)
				}
			}
			vcProjectSearch(t, alice, "alice", events, initial.ConnectionID)
			vcProjectSearch(t, anonymous, "", events, initial.ConnectionID)

			// Close the actual socket and let the regular pool detect EOF and
			// reauthenticate. Existing downstream clients must remain usable.
			if err := old.conn.Close(); err != nil {
				t.Fatal(err)
			}
			reconnected := awaitVCProjectServiceBind(t, events, method)
			if reconnected.ConnectionID == initial.ConnectionID {
				t.Fatal("reconnect did not create a new physical server connection")
			}
			waitForReadyConnections(t, proxy, PoolRegular, 1)
			if next := vcProjectRegularUpstream(t, proxy); next == old || next.conn == old.conn {
				t.Fatal("regular pool reused the disconnected socket")
			}
			for index, client := range clients {
				vcProjectSearch(t, client, names[index], events, reconnected.ConnectionID)
			}
			vcProjectSearch(t, anonymous, "", events, reconnected.ConnectionID)
			vcProjectBind(t, alice, "bob", "wrong-password", ldap.LDAPResultInvalidCredentials)
			assertVCProjectVerification(t, events, reconnected.ConnectionID, ldap.LDAPResultInvalidCredentials)
			vcProjectSearch(t, alice, "", events, reconnected.ConnectionID)
			vcProjectSearch(t, bob, "bob", events, reconnected.ConnectionID)
			vcProjectBind(t, alice, "alice", "alice-secret", 0)
			assertVCProjectVerification(t, events, reconnected.ConnectionID, 0)
			vcProjectSearch(t, alice, "alice", events, reconnected.ConnectionID)
		})
	}
}

func startVCProjectServer(t *testing.T) (string, vcProjectAuditEvents) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	frontend := "olcDatabase={-1}frontend,cn=config"
	entries := []directory.Entry{
		{DN: "cn=config", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("olcGlobal")},
			{Description: "cn", Values: serviceSASLValues("config")},
			{Description: "olcSaslHost", Values: serviceSASLValues("ldap.example.test")},
			{Description: "olcSaslRealm", Values: serviceSASLValues("example.com")},
			{Description: "olcSaslSecProps", Values: serviceSASLValues("none")},
			{Description: "olcAuthzRegexp", Values: serviceSASLValues(
				`^uid=service,cn=example\.com,cn=scram-sha-256,cn=auth$ ` + serviceSASLTestDN)},
		}},
		{DN: "cn=module{0},cn=config", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("olcModuleList")},
			{Description: "cn", Values: serviceSASLValues("module{0}")},
			{Description: "olcModuleLoad", Values: serviceSASLValues("vc.la")},
		}},
		{DN: frontend, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("olcDatabaseConfig", "olcFrontendConfig")},
			{Description: "olcDatabase", Values: serviceSASLValues("{-1}frontend")},
		}},
		{DN: "olcOverlay={0}authzid," + frontend, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("olcOverlayConfig")},
			{Description: "olcOverlay", Values: serviceSASLValues("{0}authzid")},
		}},
		{DN: "olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("olcDatabaseConfig", "olcMdbConfig")},
			{Description: "olcDatabase", Values: serviceSASLValues("{1}mdb")},
			{Description: "olcSuffix", Values: serviceSASLValues(serviceSASLTestBaseDN)},
			{Description: "olcRootDN", Values: serviceSASLValues(serviceSASLTestDN)},
			{Description: "olcRootPW", Values: serviceSASLValues(serviceSASLTestPassword)},
			{Description: "olcAccess", Values: serviceSASLValues(
				"{0}to attrs=userPassword by anonymous auth by self auth by * none",
				"{1}to attrs=description by self read by * none",
				"{2}to * by * read",
			)},
		}},
		{DN: serviceSASLTestBaseDN, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("domain")},
			{Description: "dc", Values: serviceSASLValues("example")},
		}},
	}
	for _, name := range []string{"alice", "bob"} {
		entries = append(entries, directory.Entry{DN: vcProjectUserDN(name), Attributes: []directory.Attribute{
			{Description: "objectClass", Values: serviceSASLValues("inetOrgPerson")},
			{Description: "uid", Values: serviceSASLValues(name)},
			{Description: "cn", Values: serviceSASLValues(name)},
			{Description: "sn", Values: serviceSASLValues(name)},
			{Description: "description", Values: serviceSASLValues("private-" + name)},
			{Description: "userPassword", Values: serviceSASLValues(name + "-secret")},
		}})
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{serviceSASLTestBaseDN})
	}); err != nil {
		t.Fatal(err)
	}
	events := make(vcProjectAuditEvents, 256)
	instance, err := ldapserver.New(ldapserver.Config{Store: store, AuditSink: events,
		RootDN: serviceSASLTestDN, RootPassword: []byte(serviceSASLTestPassword)})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("VC project server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("VC project server did not stop")
		}
	})
	return listener.Addr().String(), events
}

type vcProjectAuditEvents chan audit.Event

func (events vcProjectAuditEvents) Record(event audit.Event) error {
	select {
	case events <- event:
		return nil
	default:
		return errors.New("VC test audit buffer is full")
	}
}

func awaitVCProjectAudit(t *testing.T, events vcProjectAuditEvents, operation string) audit.Event {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.Operation == "unbind" || (event.Operation == "bind" && event.ResultCode != nil &&
				*event.ResultCode == int(ldapwire.ResultSASLBindInProgress)) {
				continue
			}
			if event.Operation != operation {
				t.Fatalf("expected %s audit, received %+v", operation, event)
			}
			return event
		case <-timer.C:
			t.Fatalf("timed out waiting for %s audit", operation)
		}
	}
}

func awaitVCProjectServiceBind(t *testing.T, events vcProjectAuditEvents, method string) audit.Event {
	t.Helper()
	event := awaitVCProjectAudit(t, events, "bind")
	if event.ResultCode == nil || *event.ResultCode != 0 || event.AuthorizationDN != serviceSASLTestDN ||
		!strings.EqualFold(event.AuthenticationMechanism, method) || len(event.RequestControls) != 0 {
		t.Fatalf("regular upstream did not authenticate the service: %+v", event)
	}
	return event
}

func assertVCProjectServiceOperation(t *testing.T, event audit.Event, connectionID uint64, result uint16) {
	t.Helper()
	if event.ConnectionID != connectionID || event.AuthenticationDN != serviceSASLTestDN ||
		event.ResultCode == nil || *event.ResultCode != int(result) {
		t.Fatalf("operation lost its service connection/identity: %+v", event)
	}
}

func assertVCProjectVerification(t *testing.T, events vcProjectAuditEvents, connectionID uint64, result uint16) {
	t.Helper()
	event := awaitVCProjectAudit(t, events, "extended")
	assertVCProjectServiceOperation(t, event, connectionID, result)
	if event.ExtendedOperation != ldapwire.VerifyCredentialsOID || event.AuthorizationDN != serviceSASLTestDN ||
		len(event.RequestControls) != 0 {
		t.Fatalf("user Bind was not translated to VC on the service connection: %+v", event)
	}
}

func vcProjectRegularUpstream(t *testing.T, proxy *Proxy) *upstreamConnection {
	t.Helper()
	for _, connection := range proxy.scheduler.Snapshot().Connections {
		if connection.Pool == PoolBind {
			t.Fatal("VC feature created a Bind pool")
		}
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if len(proxy.upstreams) != 1 {
		t.Fatalf("expected exactly one pooled upstream, got %d", len(proxy.upstreams))
	}
	for _, upstream := range proxy.upstreams {
		if upstream.bind {
			t.Fatal("VC users acquired a dedicated Bind connection")
		}
		return upstream
	}
	return nil
}

func vcProjectUserDN(name string) string { return "uid=" + name + "," + serviceSASLTestBaseDN }

func dialVCProjectClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	client.SetTimeout(3 * time.Second)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func vcProjectBind(t *testing.T, client *ldap.Conn, name, password string, code uint16) {
	t.Helper()
	result, err := client.SimpleBind(&ldap.SimpleBindRequest{Username: vcProjectUserDN(name), Password: password,
		Controls: []ldap.Control{ldap.NewControlString(vcProjectAuthzRequest, true, "")}})
	if code != 0 {
		if !ldap.IsErrorWithCode(err, code) {
			t.Fatalf("%s failed Bind: %v, want %d", name, err, code)
		}
		if result != nil && ldap.FindControl(result.Controls, vcProjectAuthzResponse) != nil {
			t.Fatal("failed Bind disclosed an authorization identity")
		}
		return
	}
	if err != nil || result == nil {
		t.Fatalf("%s VC Bind: %v", name, err)
	}
	control, ok := ldap.FindControl(result.Controls, vcProjectAuthzResponse).(*ldap.ControlString)
	if !ok || control.ControlValue != "dn:"+vcProjectUserDN(name) || control.Criticality || len(result.Controls) != 1 {
		t.Fatalf("%s VC Bind did not return its authzid response: %+v", name, result.Controls)
	}
}

func vcProjectSearchRequest(controls []ldap.Control) *ldap.SearchRequest {
	return ldap.NewSearchRequest(serviceSASLTestBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=inetOrgPerson)", []string{"uid", "description", "userPassword"}, controls)
}

func validateVCProjectSearch(result *ldap.SearchResult, user string) error {
	if result == nil || len(result.Entries) != 2 {
		return fmt.Errorf("expected both public user entries, got %+v", result)
	}
	seen := make(map[string]bool)
	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("uid")
		if (name != "alice" && name != "bob") || entry.DN != vcProjectUserDN(name) || seen[name] {
			return fmt.Errorf("unexpected or duplicate user entry %q", entry.DN)
		}
		seen[name] = true
		var want []string
		if name == user {
			want = []string{"private-" + name}
		}
		if !slices.Equal(entry.GetAttributeValues("description"), want) || len(entry.GetAttributeValues("userPassword")) != 0 {
			return fmt.Errorf("client %q received incorrect private attributes for %q", user, name)
		}
	}
	return nil
}

func vcProjectSearch(t *testing.T, client *ldap.Conn, user string, events vcProjectAuditEvents, connectionID uint64) {
	t.Helper()
	result, err := client.Search(vcProjectSearchRequest(nil))
	if err == nil {
		err = validateVCProjectSearch(result, user)
	}
	if err != nil {
		t.Fatalf("client %q search: %v", user, err)
	}
	event := awaitVCProjectAudit(t, events, "search")
	assertVCProjectServiceOperation(t, event, connectionID, 0)
	identity := ""
	if user != "" {
		identity = vcProjectUserDN(user)
	}
	if event.AuthorizationDN != identity || !slices.Equal(event.RequestControls, []string{ProxyAuthzControlOID}) {
		t.Fatalf("client %q lost per-operation ProxyAuthz: %+v", user, event)
	}
}
