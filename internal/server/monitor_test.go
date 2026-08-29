package server

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPMonitorBackendCoreBehavior(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedMonitorConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous Bind(): %v", err)
	}

	rootDSE := monitorSearch(t, client, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"monitorContext"})
	if len(rootDSE.Entries) != 1 ||
		rootDSE.Entries[0].GetAttributeValue("monitorContext") != "cn=Monitor" {
		t.Fatalf("root DSE monitorContext entries = %#v", rootDSE.Entries)
	}

	root := monitorSearch(
		t,
		client,
		"cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"*", "+"},
	)
	if len(root.Entries) != 1 {
		t.Fatalf("monitor root entry count = %d, want 1", len(root.Entries))
	}
	rootEntry := root.Entries[0]
	if !ldapEntryHasValue(rootEntry, "objectClass", "monitorServer") {
		t.Fatalf("monitor root objectClass = %v", rootEntry.GetAttributeValues("objectClass"))
	}
	if got := rootEntry.GetAttributeValue("entryDN"); got != "cn=Monitor" {
		t.Fatalf("monitor root entryDN = %q", got)
	}
	if got := rootEntry.GetAttributeValue("hasSubordinates"); !strings.EqualFold(got, "TRUE") {
		t.Fatalf("monitor root hasSubordinates = %q", got)
	}
	for _, attribute := range []string{"createTimestamp", "modifyTimestamp"} {
		if _, err := time.Parse(monitorGeneralizedTimeLayout, rootEntry.GetAttributeValue(attribute)); err != nil {
			t.Fatalf("monitor root %s = %q: %v", attribute, rootEntry.GetAttributeValue(attribute), err)
		}
	}

	containers := monitorSearch(
		t,
		client,
		"cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=monitorContainer)",
		[]string{"cn"},
	)
	wantContainers := map[string]bool{
		"Backends": false, "Connections": false, "Databases": false,
		"Listeners": false, "Log": false, "Operations": false,
		"Overlays": false, "SASL": false, "Statistics": false,
		"Threads": false, "Time": false, "TLS": false, "Waiters": false,
	}
	if len(containers.Entries) != len(wantContainers) {
		t.Fatalf("monitor container count = %d, want %d", len(containers.Entries), len(wantContainers))
	}
	for _, entry := range containers.Entries {
		name := entry.GetAttributeValue("cn")
		if _, exists := wantContainers[name]; !exists {
			t.Fatalf("unexpected monitor container %q", name)
		}
		wantContainers[name] = true
	}
	for name, found := range wantContainers {
		if !found {
			t.Errorf("monitor container %q was not returned", name)
		}
	}

	operations := monitorSearch(
		t,
		client,
		"cn=Operations,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=monitorOperation)",
		[]string{"cn", "monitorOpInitiated", "monitorOpCompleted"},
	)
	if len(operations.Entries) != len(monitorOperationNames) {
		t.Fatalf("monitor operation count = %d, want %d", len(operations.Entries), len(monitorOperationNames))
	}
	searchOperation := ldapEntryByCN(operations.Entries, "Search")
	if searchOperation == nil {
		t.Fatal("Search monitor operation was not returned")
	}
	initiated := ldapEntryUint64(t, searchOperation, "monitorOpInitiated")
	completed := ldapEntryUint64(t, searchOperation, "monitorOpCompleted")
	if initiated <= completed {
		t.Fatalf("Search initiated/completed = %d/%d, current search should be executing", initiated, completed)
	}

	connections := monitorSearch(
		t,
		client,
		"cn=Connections,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=*)",
		[]string{"*", "+"},
	)
	connectionEntry := ldapEntryByObjectClass(connections.Entries, "monitorConnection")
	if connectionEntry == nil {
		t.Fatalf("active monitor connection not returned: %#v", connections.Entries)
	}
	if got := connectionEntry.GetAttributeValue("monitorConnectionProtocol"); got != "3" {
		t.Fatalf("monitorConnectionProtocol = %q, want 3", got)
	}
	if got := ldapEntryUint64(t, connectionEntry, "monitorConnectionOpsExecuting"); got == 0 {
		t.Fatal("current monitor search was not reported as executing")
	}
	if got := ldapEntryUint64(t, connectionEntry, "monitorConnectionOpsReceived"); got < 5 {
		t.Fatalf("monitorConnectionOpsReceived = %d, want at least 5", got)
	}
	if connectionEntry.GetAttributeValue("monitorConnectionListener") == "" ||
		connectionEntry.GetAttributeValue("monitorConnectionPeerAddress") == "" ||
		connectionEntry.GetAttributeValue("monitorConnectionLocalAddress") == "" {
		t.Fatalf("connection addresses/listener are incomplete: %#v", connectionEntry.Attributes)
	}

	statistics := monitorSearch(
		t,
		client,
		"cn=Statistics,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=monitorCounterObject)",
		[]string{"cn", "monitorCounter"},
	)
	for _, name := range []string{"Bytes", "PDU", "Entries"} {
		entry := ldapEntryByCN(statistics.Entries, name)
		if entry == nil || ldapEntryUint64(t, entry, "monitorCounter") == 0 {
			t.Errorf("monitor statistic %q is absent or zero", name)
		}
	}
	if entry := ldapEntryByCN(statistics.Entries, "Referrals"); entry == nil {
		t.Fatal("monitor Referrals statistic was not returned")
	}

	paged, err := client.SearchWithPaging(ldap.NewSearchRequest(
		"cn=Monitor",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	), 7)
	if err != nil {
		t.Fatalf("monitor SearchWithPaging(): %v", err)
	}
	if len(paged.Entries) < 40 {
		t.Fatalf("paged monitor entry count = %d, want at least 40", len(paged.Entries))
	}
	seenDNs := make(map[string]struct{}, len(paged.Entries))
	for _, entry := range paged.Entries {
		key := strings.ToLower(entry.DN)
		if _, exists := seenDNs[key]; exists {
			t.Fatalf("paged monitor search returned duplicate DN %q", entry.DN)
		}
		seenDNs[key] = struct{}{}
	}

	matched, err := client.Compare("cn=Search,cn=Operations,cn=Monitor", "cn", "search")
	if err != nil || !matched {
		t.Fatalf("monitor Compare(case-ignore cn) = %t, %v", matched, err)
	}
	_, err = client.Compare("cn=Search,cn=Operations,cn=Monitor", "mail", "none@example.com")
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchAttribute)
	_, err = client.Compare("cn=Missing,cn=Time,cn=Monitor", "cn", "Missing")
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
	var missingCompare *ldap.Error
	if !errors.As(err, &missingCompare) || !strings.EqualFold(missingCompare.MatchedDN, "cn=Time,cn=Monitor") {
		t.Fatalf("missing monitor Compare matchedDN = %q", missingCompare.MatchedDN)
	}

	missingSearch := ldap.NewSearchRequest(
		"cn=Missing,cn=Time,cn=Monitor",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	)
	_, err = client.Search(missingSearch)
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
	var missingSearchError *ldap.Error
	if !errors.As(err, &missingSearchError) ||
		!strings.EqualFold(missingSearchError.MatchedDN, "cn=Time,cn=Monitor") {
		t.Fatalf("missing monitor Search matchedDN = %q", missingSearchError.MatchedDN)
	}

	assertMonitorWriteResultCodes(t, client, ldap.LDAPResultStrongAuthRequired)
	if err := client.Bind("cn=admin,cn=Monitor", "monitor-secret"); err != nil {
		t.Fatalf("monitor root Bind(): %v", err)
	}
	assertMonitorWriteResultCodes(t, client, ldap.LDAPResultUnwillingToPerform)
}

func TestMonitorListenerURLPreservesTLCPListenerScheme(t *testing.T) {
	t.Parallel()

	address := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1636}
	if got := monitorListenerURLWithScheme(address, "ldap+tlcp"); got != "ldap+tlcp://127.0.0.1:1636/" {
		t.Fatalf("TLCP listener URL = %q", got)
	}
}

func TestMonitorStateConcurrentSnapshots(t *testing.T) {
	t.Parallel()

	monitor := newMonitorState()
	serverConnection, clientConnection := netPipe(t)
	defer serverConnection.Close()
	defer clientConnection.Close()
	connection := monitor.registerConnection(1, serverConnection, false)
	defer monitor.unregisterConnection(1)

	done := make(chan struct{})
	for worker := 0; worker < 8; worker++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for iteration := 0; iteration < 100; iteration++ {
				monitor.queueOperation(connection)
				monitor.startOperation(connection, true)
				monitor.completeOperation(connection, ldapwire.SearchRequest{}, true)
				_ = monitor.connectionSnapshots()
			}
		}()
	}
	for worker := 0; worker < 8; worker++ {
		<-done
	}

	snapshots := monitor.connectionSnapshots()
	if len(snapshots) != 1 || snapshots[0].completed != 800 ||
		snapshots[0].pending != 0 || snapshots[0].executing != 0 {
		t.Fatalf("concurrent monitor snapshot = %#v", snapshots)
	}
}

func TestLDAPMonitorBackendManagedLogAndDatabase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedMonitorConfiguration(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("data-secret"),
	})
	defer stop()

	monitorClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(monitor): %v", err)
	}
	defer monitorClient.Close()
	if err := monitorClient.Bind("cn=admin,cn=Monitor", "monitor-secret"); err != nil {
		t.Fatalf("monitor root Bind(): %v", err)
	}

	logEntry := monitorSearch(
		t,
		monitorClient,
		"cn=Log,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"monitorDebugLevel", "monitorLogLevel"},
	).Entries[0]
	if got := logEntry.GetAttributeValues("monitorDebugLevel"); len(got) != 1 || got[0] != "0" {
		t.Fatalf("initial monitorDebugLevel = %v", got)
	}
	if got := logEntry.GetAttributeValues("monitorLogLevel"); len(got) != 1 || got[0] != "0" {
		t.Fatalf("initial monitorLogLevel = %v", got)
	}

	modifyLog := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	modifyLog.Replace("monitorDebugLevel", []string{"Stats", "Sync"})
	modifyLog.Replace("monitorLogLevel", []string{"ACL"})
	if err := monitorClient.Modify(modifyLog); err != nil {
		t.Fatalf("replace monitor log levels: %v", err)
	}
	logEntry = monitorSearch(
		t,
		monitorClient,
		"cn=Log,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"monitorDebugLevel", "monitorLogLevel"},
	).Entries[0]
	if got := sortedStrings(logEntry.GetAttributeValues("monitorDebugLevel")); !equalStrings(got, []string{"Stats", "Sync"}) {
		t.Fatalf("updated monitorDebugLevel = %v", got)
	}
	if got := logEntry.GetAttributeValues("monitorLogLevel"); len(got) != 1 || got[0] != "ACL" {
		t.Fatalf("updated monitorLogLevel = %v", got)
	}

	duplicate := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	duplicate.Add("monitorDebugLevel", []string{"stats"})
	if err := monitorClient.Modify(duplicate); err != nil {
		t.Fatalf("OpenLDAP-compatible log Add(): %v", err)
	}
	invalid := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	invalid.Replace("monitorDebugLevel", []string{"not-a-level"})
	if err := monitorClient.Modify(invalid); err != nil {
		t.Fatalf("OpenLDAP-compatible invalid log Replace(): %v", err)
	}
	logEntry = monitorSearch(
		t,
		monitorClient,
		"cn=Log,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"monitorDebugLevel"},
	).Entries[0]
	if got := logEntry.GetAttributeValues("monitorDebugLevel"); len(got) != 1 || got[0] != "not-a-level" {
		t.Fatalf("OpenLDAP-compatible log replacement state = %v", got)
	}
	unmanaged := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	unmanaged.Replace("description", []string{"blocked"})
	assertLDAPResultCode(
		t,
		monitorClient.Modify(unmanaged),
		ldap.LDAPResultUnwillingToPerform,
	)

	readOnly := ldap.NewModifyRequest("cn=Database 0,cn=Databases,cn=Monitor", nil)
	readOnly.Replace("readOnly", []string{"TRUE"})
	if err := monitorClient.Modify(readOnly); err != nil {
		t.Fatalf("enable database readOnly through monitor: %v", err)
	}
	databaseEntry := monitorSearch(
		t,
		monitorClient,
		"cn=Database 0,cn=Databases,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"readOnly", "restrictedOperation"},
	).Entries[0]
	if !strings.EqualFold(databaseEntry.GetAttributeValue("readOnly"), "TRUE") ||
		len(databaseEntry.GetAttributeValues("restrictedOperation")) != 4 {
		t.Fatalf("read-only database monitor entry = %#v", databaseEntry.Attributes)
	}

	dataClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(data): %v", err)
	}
	defer dataClient.Close()
	if err := dataClient.Bind("cn=admin,dc=example,dc=com", "data-secret"); err != nil {
		t.Fatalf("data root Bind(): %v", err)
	}
	blockedAdd := newPersonAddRequest("monitor-read-only")
	assertLDAPResultCode(
		t,
		dataClient.Add(blockedAdd),
		ldap.LDAPResultUnwillingToPerform,
	)

	writable := ldap.NewModifyRequest("cn=Database 0,cn=Databases,cn=Monitor", nil)
	writable.Replace("readOnly", []string{"FALSE"})
	if err := monitorClient.Modify(writable); err != nil {
		t.Fatalf("disable database readOnly through monitor: %v", err)
	}
	if err := dataClient.Add(newPersonAddRequest("monitor-writable")); err != nil {
		t.Fatalf("Add() after disabling monitor readOnly: %v", err)
	}

	monitorDatabase := ldap.NewModifyRequest("cn=Database 1,cn=Databases,cn=Monitor", nil)
	monitorDatabase.Replace("readOnly", []string{"TRUE"})
	assertLDAPResultCode(
		t,
		monitorClient.Modify(monitorDatabase),
		ldap.LDAPResultUnwillingToPerform,
	)
}

func seedMonitorConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={2}monitor,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcMonitorConfig")},
			{Description: "olcDatabase", Values: stringValues("{2}monitor")},
			{Description: "olcRootDN", Values: stringValues("cn=admin,cn=Monitor")},
			{Description: "olcRootPW", Values: stringValues("monitor-secret")},
			{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed monitor configuration: %v", err)
	}
}

func monitorSearch(
	t *testing.T,
	client *ldap.Conn,
	baseDN string,
	scope int,
	filter string,
	attributes []string,
) *ldap.SearchResult {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	))
	if err != nil {
		t.Fatalf("monitor Search(%q): %v", baseDN, err)
	}
	return result
}

func ldapEntryByCN(entries []*ldap.Entry, name string) *ldap.Entry {
	for _, entry := range entries {
		if strings.EqualFold(entry.GetAttributeValue("cn"), name) {
			return entry
		}
	}
	return nil
}

func ldapEntryByObjectClass(entries []*ldap.Entry, objectClass string) *ldap.Entry {
	for _, entry := range entries {
		if ldapEntryHasValue(entry, "objectClass", objectClass) {
			return entry
		}
	}
	return nil
}

func ldapEntryHasValue(entry *ldap.Entry, attribute, value string) bool {
	for _, candidate := range entry.GetAttributeValues(attribute) {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func ldapEntryUint64(t *testing.T, entry *ldap.Entry, attribute string) uint64 {
	t.Helper()
	if entry == nil {
		t.Fatalf("cannot read %s from a nil LDAP entry", attribute)
	}
	raw := entry.GetAttributeValue(attribute)
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		t.Fatalf("%s %s = %q: %v", entry.DN, attribute, raw, err)
	}
	return value
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func assertMonitorWriteResultCodes(t *testing.T, client *ldap.Conn, want uint16) {
	t.Helper()

	add := ldap.NewAddRequest("cn=Blocked,cn=Monitor", nil)
	add.Attribute("objectClass", []string{"monitorContainer"})
	add.Attribute("cn", []string{"Blocked"})
	assertLDAPResultCode(t, client.Add(add), want)

	modify := ldap.NewModifyRequest("cn=Monitor", nil)
	modify.Replace("description", []string{"blocked"})
	assertLDAPResultCode(t, client.Modify(modify), want)

	assertLDAPResultCode(
		t,
		client.Del(ldap.NewDelRequest("cn=Monitor", nil)),
		want,
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(ldap.NewModifyDNRequest("cn=Time,cn=Monitor", "cn=Moved", true, "")),
		want,
	)
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	return server, client
}
