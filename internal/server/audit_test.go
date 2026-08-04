package server

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type recordingAuditSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (sink *recordingAuditSink) Record(event audit.Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	event.RequestControls = append([]string(nil), event.RequestControls...)
	sink.events = append(sink.events, event)
	return nil
}

func (sink *recordingAuditSink) snapshot() []audit.Event {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]audit.Event(nil), sink.events...)
}

func TestLDAPOperationAuditCoverageAndRedaction(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	sink := &recordingAuditSink{}
	const (
		rootDN          = "cn=admin,dc=example,dc=com"
		rootPassword    = "audit-admin-password"
		wrongPassword   = "audit-wrong-password"
		addedPassword   = "audit-added-password"
		filterAssertion = "audit-filter-assertion"
		compareValue    = "audit-compare-assertion"
		modifyValue     = "audit-modify-value"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
		AuditSink:    sink,
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(rootDN, wrongPassword); err == nil {
		t.Fatal("Bind() accepted an invalid password")
	}
	if err := client.Bind(rootDN, rootPassword); err != nil {
		t.Fatalf("Bind(root): %v", err)
	}
	if _, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description="+filterAssertion+")",
		[]string{"uid", "description"},
		nil,
	)); err != nil {
		t.Fatalf("Search(): %v", err)
	}
	matched, err := client.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		compareValue,
	)
	if err != nil || matched {
		t.Fatalf("Compare() = %t, %v", matched, err)
	}

	addedDN := "uid=audit-user,ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(addedDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"audit-user"})
	add.Attribute("cn", []string{"Audit User"})
	add.Attribute("sn", []string{"User"})
	add.Attribute("userPassword", []string{addedPassword})
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(): %v", err)
	}
	passwordResult, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		addedDN,
		"",
		"",
	))
	if err != nil {
		t.Fatalf("PasswordModify(): %v", err)
	}
	if passwordResult.GeneratedPassword == "" {
		t.Fatal("PasswordModify() did not generate a password")
	}
	renamedDN := "uid=audit-renamed,ou=people,dc=example,dc=com"
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		addedDN,
		"uid=audit-renamed",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(): %v", err)
	}
	modify := ldap.NewModifyRequest(renamedDN, nil)
	modify.Add("description", []string{modifyValue})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("Delete(): %v", err)
	}

	events := waitForAuditEvents(t, sink, 9)
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("Marshal(events): %v", err)
	}
	for _, secret := range []string{
		rootPassword,
		wrongPassword,
		addedPassword,
		filterAssertion,
		compareValue,
		modifyValue,
		passwordResult.GeneratedPassword,
	} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("audit events contain request secret %q: %s", secret, encoded)
		}
	}

	wantOperations := []string{
		"bind",
		"bind",
		"search",
		"compare",
		"add",
		"extended",
		"modify_dn",
		"modify",
		"delete",
	}
	if len(events) != len(wantOperations) {
		t.Fatalf("event count = %d, want %d: %#v", len(events), len(wantOperations), events)
	}
	for index, want := range wantOperations {
		if events[index].Operation != want {
			t.Fatalf("event %d operation = %q, want %q", index, events[index].Operation, want)
		}
		if events[index].ConnectionID == 0 || events[index].DurationMicros < 0 {
			t.Fatalf("event %d metadata = %#v", index, events[index])
		}
	}
	assertAuditResult(t, events[0], int(ldapwire.ResultInvalidCredentials), "failure")
	assertAuditResult(t, events[1], int(ldapwire.ResultSuccess), "success")
	assertAuditResult(t, events[2], int(ldapwire.ResultSuccess), "success")
	assertAuditResult(t, events[3], int(ldapwire.ResultCompareFalse), "success")
	assertAuditResult(t, events[4], int(ldapwire.ResultSuccess), "success")
	assertAuditResult(t, events[5], int(ldapwire.ResultSuccess), "success")
	assertAuditResult(t, events[6], int(ldapwire.ResultSuccess), "success")
	assertAuditResult(t, events[7], int(ldapwire.ResultSuccess), "success")
	assertAuditResult(t, events[8], int(ldapwire.ResultSuccess), "success")
	if events[5].ExtendedOperation != passwordModifyOID {
		t.Fatalf("Password Modify audit event = %#v", events[5])
	}
	if events[0].TargetDN != rootDN || events[1].AuthorizationDN != rootDN {
		t.Fatalf("bind audit events = %#v, %#v", events[0], events[1])
	}
	for _, event := range events[2:] {
		if event.AuthenticationDN != rootDN || event.AuthorizationDN != rootDN {
			t.Fatalf("operation identity = %#v", event)
		}
	}
}

func TestImmediateOperationsAndMalformedMessagesAreAudited(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	sink := &recordingAuditSink{}
	address, stop := startServer(t, store, Config{AuditSink: sink})
	defer stop()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	cancel := ldapwire.Message{
		ID: 1,
		Request: ldapwire.ExtendedRequest{
			Name:     cancelOID,
			Value:    ldapwire.EncodeCancelRequestValue(99),
			HasValue: true,
		},
	}
	abandon := ldapwire.Message{
		ID:      2,
		Request: ldapwire.AbandonRequest{MessageID: 98},
	}
	unbind := ldapwire.Message{ID: 3, Request: ldapwire.UnbindRequest{}}
	for _, message := range []ldapwire.Message{cancel} {
		encoded, err := ldapwire.EncodeRequestMessage(message)
		if err != nil {
			t.Fatalf("EncodeRequestMessage(%T): %v", message.Request, err)
		}
		if _, err := connection.Write(encoded); err != nil {
			t.Fatalf("Write(%T): %v", message.Request, err)
		}
	}
	if _, err := ber.ReadPacket(connection); err != nil {
		t.Fatalf("read Cancel response: %v", err)
	}
	for _, message := range []ldapwire.Message{abandon, unbind} {
		encoded, err := ldapwire.EncodeRequestMessage(message)
		if err != nil {
			t.Fatalf("EncodeRequestMessage(%T): %v", message.Request, err)
		}
		if _, err := connection.Write(encoded); err != nil {
			t.Fatalf("Write(%T): %v", message.Request, err)
		}
	}
	_ = connection.Close()

	malformed, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(malformed): %v", err)
	}
	if _, err := malformed.Write([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err != nil {
		t.Fatalf("Write(malformed): %v", err)
	}
	_ = malformed.Close()

	events := waitForAuditEvents(t, sink, 4)
	if len(events) != 4 {
		t.Fatalf("events = %#v", events)
	}
	byOperation := make(map[string]audit.Event, len(events))
	for _, event := range events {
		byOperation[event.Operation] = event
	}
	cancelEvent := byOperation["extended"]
	if cancelEvent.ExtendedOperation != cancelOID ||
		cancelEvent.RelatedMessageID != 99 {
		t.Fatalf("Cancel event = %#v", cancelEvent)
	}
	assertAuditResult(t, cancelEvent, int(ldapwire.ResultNoSuchOperation), "failure")
	abandonEvent := byOperation["abandon"]
	if abandonEvent.RelatedMessageID != 98 ||
		abandonEvent.ResultCode != nil ||
		abandonEvent.Outcome != "no_response" {
		t.Fatalf("Abandon event = %#v", abandonEvent)
	}
	unbindEvent := byOperation["unbind"]
	if unbindEvent.ResultCode != nil || unbindEvent.Outcome != "no_response" {
		t.Fatalf("Unbind event = %#v", unbindEvent)
	}
	malformedEvent := byOperation["malformed_message"]
	if malformedEvent.Operation == "" {
		t.Fatalf("malformed event is missing: %#v", events)
	}
	assertAuditResult(t, malformedEvent, int(ldapwire.ResultProtocolError), "failure")
}

func waitForAuditEvents(
	t *testing.T,
	sink *recordingAuditSink,
	want int,
) []audit.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events := sink.snapshot()
		if len(events) >= want {
			return events
		}
		time.Sleep(5 * time.Millisecond)
	}
	events := sink.snapshot()
	t.Fatalf("audit event count = %d, want at least %d: %#v", len(events), want, events)
	return nil
}

func assertAuditResult(t *testing.T, event audit.Event, code int, outcome string) {
	t.Helper()
	if event.ResultCode == nil || *event.ResultCode != code || event.Outcome != outcome {
		t.Fatalf("audit result = %#v, want code %d and outcome %q", event, code, outcome)
	}
}

func TestAuditLDAPResultCodeIgnoresSearchEntries(t *testing.T) {
	t.Parallel()

	if _, ok := auditLDAPResultCode(ldapwire.EncodeSearchResultEntry(
		1,
		seedAuditEntry(),
		nil,
	)); ok {
		t.Fatal("auditLDAPResultCode() treated a SearchResultEntry as a final result")
	}
	encoded := ldapwire.EncodeSearchResultDone(
		1,
		ldapwire.Result{Code: ldapwire.ResultSizeLimitExceeded},
		nil,
	)
	if code, ok := auditLDAPResultCode(encoded); !ok || code != int(ldapwire.ResultSizeLimitExceeded) {
		t.Fatalf("auditLDAPResultCode() = %d, %t", code, ok)
	}
}

func seedAuditEntry() directory.Entry {
	return directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "objectClass",
			Values:      [][]byte{[]byte("domain")},
		}},
	}
}
