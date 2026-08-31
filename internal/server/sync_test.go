package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncTestRootDN       = "cn=admin,dc=example,dc=com"
	syncTestRootPassword = "admin-secret"
)

func TestSyncRefreshOnlyInitialAndIncrementalRefresh(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	client := dialLDAPRoot(t, address)
	defer client.Close()
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
	if err != nil {
		t.Fatalf("Root DSE Search(): %v", err)
	}
	if len(root.Entries) != 1 ||
		!syncContainsString(
			root.Entries[0].GetAttributeValues("supportedControl"),
			syncRequestControlOID,
		) {
		t.Fatalf("supportedControl = %#v", root.Entries)
	}

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()

	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
	)
	initial := readRawSyncRefresh(t, connection, 2)
	if initial.resultCode != int64(ldapwire.ResultSuccess) ||
		len(initial.entries) != 4 ||
		len(initial.presentUUIDs()) != 0 ||
		initial.done == nil ||
		!initial.done.HasCookie ||
		len(initial.done.Cookie) == 0 {
		t.Fatalf("initial Sync refresh = %#v", initial)
	}
	for _, entry := range initial.entries {
		if entry.state.State != ldapwire.SyncStateAdd ||
			entry.state.HasCookie {
			t.Fatalf("initial Sync entry = %#v", entry)
		}
		if syncContainsString(entry.attributeNames, "contextCSN") {
			t.Fatalf("Sync entry exposed contextCSN: %#v", entry)
		}
	}
	initialCookie := bytes.Clone(initial.done.Cookie)

	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Updated"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(alice): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}

	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    initialCookie,
			HasCookie: true,
		}, true),
	)
	incremental := readRawSyncRefresh(t, connection, 3)
	if incremental.resultCode != int64(ldapwire.ResultSuccess) ||
		len(incremental.entries) != 1 ||
		incremental.entries[0].dn !=
			"uid=alice,ou=people,dc=example,dc=com" ||
		incremental.entries[0].state.State != ldapwire.SyncStateAdd ||
		len(incremental.presentUUIDs()) != 2 ||
		incremental.done == nil ||
		!incremental.done.HasCookie ||
		bytes.Equal(incremental.done.Cookie, initialCookie) {
		t.Fatalf("incremental Sync refresh = %#v", incremental)
	}
}

func TestSyncProviderPublishesOperationalContextCSN(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	client := dialLDAPRoot(t, address)
	defer client.Close()
	searchContext := func(attributes ...string) *ldap.Entry {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			attributes,
			nil,
		))
		if err != nil {
			t.Fatalf("Search(contextCSN): %v", err)
		}
		if len(result.Entries) != 1 {
			t.Fatalf("Search(contextCSN) entries = %#v", result.Entries)
		}
		return result.Entries[0]
	}

	initialEntry := searchContext("contextCSN")
	initial := initialEntry.GetAttributeValues("contextCSN")
	if len(initial) != 1 {
		t.Fatalf("initial contextCSN = %q", initial)
	}
	storedInitial := readStoredEntry(t, store, "dc=example,dc=com")
	if values := storedInitial.Values("contextCSN"); len(values) != 1 ||
		string(values[0]) != initial[0] {
		t.Fatalf("stored initial contextCSN = %q, want %q", values, initial)
	}

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(
			"dc=example,dc=com",
			"description",
			"updated sync context",
		),
		rawReadControl(preReadControlOID, true, "contextCSN"),
		rawReadControl(postReadControlOID, true, "contextCSN"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	preRead := singleRawValue(
		t,
		rawReadControlEntry(t, response, preReadControlOID),
		"contextCSN",
	)
	postRead := singleRawValue(
		t,
		rawReadControlEntry(t, response, postReadControlOID),
		"contextCSN",
	)
	if preRead != initial[0] || postRead == preRead {
		t.Fatalf(
			"contextCSN read controls = pre %q, post %q, initial %q",
			preRead,
			postRead,
			initial,
		)
	}

	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}
	operational := searchContext("+")
	current := operational.GetAttributeValues("contextCSN")
	if len(current) != 1 || current[0] == postRead {
		t.Fatalf("current contextCSN = %q, post-read %q", current, postRead)
	}
	if userAttributes := searchContext("*"); len(
		userAttributes.GetAttributeValues("contextCSN"),
	) != 0 {
		t.Fatalf("contextCSN returned by *: %#v", userAttributes)
	}

	matched, err := client.Compare(
		"dc=example,dc=com",
		"contextCSN",
		current[0],
	)
	if err != nil || !matched {
		t.Fatalf("Compare(current contextCSN) = %t, %v", matched, err)
	}
	matched, err = client.Compare(
		"dc=example,dc=com",
		"contextCSN",
		initial[0],
	)
	if err != nil || matched {
		t.Fatalf("Compare(stale contextCSN) = %t, %v", matched, err)
	}

	storedAfter := readStoredEntry(t, store, "dc=example,dc=com")
	if values := storedAfter.Values("contextCSN"); len(values) != 1 ||
		string(values[0]) != initial[0] {
		t.Fatalf(
			"stored contextCSN was rewritten = %q, want static %q",
			values,
			initial,
		)
	}
	modifyContext := ldap.NewModifyRequest("dc=example,dc=com", nil)
	modifyContext.Replace("contextCSN", current)
	assertLDAPResultCode(
		t,
		client.Modify(modifyContext),
		ldap.LDAPResultConstraintViolation,
	)
}

func TestOpenLDAPLDAPSearchSyncInteroperability(t *testing.T) {
	t.Parallel()

	ldapsearch, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Skip("OpenLDAP ldapsearch is not installed")
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		ldapsearch,
		"-LLL",
		"-H", "ldap://"+address,
		"-x",
		"-D", syncTestRootDN,
		"-w", syncTestRootPassword,
		"-b", "dc=example,dc=com",
		"-s", "sub",
		"-E", "!sync=ro",
		"(objectClass=*)",
		"1.1",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP ldapsearch Sync failed: %v\n%s", err, output)
	}
	if count := bytes.Count(output, []byte("dn: ")); count != 4 {
		t.Fatalf("OpenLDAP ldapsearch returned %d entries, want 4:\n%s", count, output)
	}
}

func TestSyncDeleteContextPersistsAcrossServerRestart(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	config := Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	}

	address, stopFirst := startServer(t, store, config)
	firstStopped := false
	defer func() {
		if !firstStopped {
			stopFirst()
		}
	}()
	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
	)
	initial := readRawSyncRefresh(t, connection, 2)
	if initial.done == nil || !initial.done.HasCookie {
		t.Fatalf("initial Sync refresh = %#v", initial)
	}
	initialCookie := bytes.Clone(initial.done.Cookie)

	client := dialLDAPRoot(t, address)
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}
	client.Close()
	connection.Close()
	stopFirst()
	firstStopped = true

	restartedAddress, stopRestarted := startServer(t, store, config)
	defer stopRestarted()
	restarted := dialAndBindRawLDAP(
		t,
		restartedAddress,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer restarted.Close()
	writeRawLDAPRequest(
		t,
		restarted,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    initialCookie,
			HasCookie: true,
		}, true),
	)
	refresh := readRawSyncRefresh(t, restarted, 2)
	if refresh.resultCode != int64(ldapwire.ResultSuccess) ||
		len(refresh.entries) != 0 ||
		len(refresh.presentUUIDs()) != 3 ||
		refresh.done == nil ||
		!refresh.done.HasCookie ||
		bytes.Equal(refresh.done.Cookie, initialCookie) {
		t.Fatalf("post-restart Sync refresh = %#v", refresh)
	}
}

func TestSyncRefreshAndPersistStreamsChangesAndCancels(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)

	initialEntries := 0
	for {
		message := readRawSyncMessage(t, connection, 2)
		if message.entry != nil {
			initialEntries++
			continue
		}
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoRefreshPresent {
			if !message.info.RefreshDone || !message.info.HasCookie {
				t.Fatalf("refresh completion = %#v", message.info)
			}
			break
		}
		t.Fatalf("unexpected initial persistent response = %#v", message)
	}
	if initialEntries != 4 {
		t.Fatalf("initial persistent entry count = %d, want 4", initialEntries)
	}

	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newPersonAddRequest("bob")); err != nil {
		t.Fatalf("Add(bob): %v", err)
	}
	added := readRawSyncEntryState(t, connection, 2)
	if added.dn != "uid=bob,ou=people,dc=example,dc=com" ||
		added.state.State != ldapwire.SyncStateAdd ||
		!added.state.HasCookie {
		t.Fatalf("persistent add = %#v", added)
	}

	modify := ldap.NewModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Bob Updated"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(bob): %v", err)
	}
	modified := readRawSyncEntryState(t, connection, 2)
	if modified.state.State != ldapwire.SyncStateModify ||
		modified.state.EntryUUID != added.state.EntryUUID {
		t.Fatalf("persistent modify = %#v", modified)
	}

	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=robert",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(bob): %v", err)
	}
	renamed := readRawSyncEntryState(t, connection, 2)
	if renamed.dn != "uid=robert,ou=people,dc=example,dc=com" ||
		renamed.state.State != ldapwire.SyncStateModify ||
		renamed.state.EntryUUID != added.state.EntryUUID {
		t.Fatalf("persistent modDN = %#v", renamed)
	}

	if err := client.Del(ldap.NewDelRequest(
		"uid=robert,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(robert): %v", err)
	}
	deleted := readRawSyncEntryState(t, connection, 2)
	if deleted.dn != "uid=robert,ou=people,dc=example,dc=com" ||
		deleted.attributeCount != 0 ||
		deleted.state.State != ldapwire.SyncStateDelete ||
		deleted.state.EntryUUID != added.state.EntryUUID {
		t.Fatalf("persistent delete = %#v", deleted)
	}

	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(
			cancelOID,
			ldapwire.EncodeCancelRequestValue(2),
			true,
		),
		nil,
	)
	results := make(map[int64]rawSyncMessage)
	for len(results) < 2 {
		message := readRawSyncMessage(t, connection, -1)
		results[message.messageID] = message
	}
	if cancel := results[3]; cancel.applicationTag !=
		ldapwire.ApplicationExtendedResponse ||
		cancel.resultCode != int64(ldapwire.ResultSuccess) {
		t.Fatalf("Cancel response = %#v", cancel)
	}
	if search := results[2]; search.applicationTag !=
		ldapwire.ApplicationSearchResultDone ||
		search.resultCode != int64(ldapwire.ResultCanceled) {
		t.Fatalf("canceled Sync search response = %#v", search)
	}
}

func TestSyncRefreshAndPersistTracksFilterTransitions(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(cn=Visible*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)
	for {
		message := readRawSyncMessage(t, connection, 2)
		if message.entry != nil {
			t.Fatalf("unexpected initial filtered entry = %#v", message.entry)
		}
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoRefreshPresent {
			break
		}
	}

	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newPersonAddRequest("filtered")); err != nil {
		t.Fatalf("Add(filtered): %v", err)
	}
	notVisible := readRawSyncMessage(t, connection, 2)
	if notVisible.info == nil ||
		notVisible.info.Kind != ldapwire.SyncInfoNewCookie {
		t.Fatalf("nonmatching add response = %#v", notVisible)
	}

	modify := ldap.NewModifyRequest(
		"uid=filtered,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Visible User"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("make filtered entry visible: %v", err)
	}
	visible := readRawSyncEntryState(t, connection, 2)
	if visible.state.State != ldapwire.SyncStateAdd {
		t.Fatalf("filter entry transition = %#v, want add", visible)
	}

	modify = ldap.NewModifyRequest(
		"uid=filtered,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Hidden User"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("hide filtered entry: %v", err)
	}
	hidden := readRawSyncEntryState(t, connection, 2)
	if hidden.state.State != ldapwire.SyncStateDelete ||
		hidden.attributeCount != 0 ||
		hidden.state.EntryUUID != visible.state.EntryUUID {
		t.Fatalf("filter exit transition = %#v, want delete", hidden)
	}
}

func TestSyncPersistentSearchRequiresRefreshWhenBaseChanges(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=archive,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)
	for {
		message := readRawSyncMessage(t, connection, 2)
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoRefreshPresent {
			break
		}
	}

	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(sync base): %v", err)
	}
	done := readRawSyncMessage(t, connection, 2)
	if done.applicationTag != ldapwire.ApplicationSearchResultDone ||
		done.resultCode != int64(ldapwire.ResultSyncRefreshRequired) {
		t.Fatalf("changed-base Sync result = %#v", done)
	}
}

func TestSyncControlValidationAndDatabaseConfiguration(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)

	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databases[databaseIndexForDN(databases, suffix)]
	if !database.syncProvider || !runtimeSupportsSyncProvider(databases) {
		t.Fatalf("sync provider database = %#v", database)
	}

	request := ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly}
	parsed, failure := parseRequestControls(
		[]ldapwire.Control{{
			OID:      syncRequestControlOID,
			Critical: true,
			Value:    ldapwire.EncodeSyncRequestValue(request),
			HasValue: true,
		}},
		supportsSync,
	)
	if failure != nil || parsed.sync == nil ||
		parsed.sync.request.Mode != ldapwire.SyncRefreshOnly {
		t.Fatalf("parsed Sync control = %#v, failure %#v", parsed, failure)
	}

	for _, controls := range [][]ldapwire.Control{
		{{OID: syncRequestControlOID, Critical: true}},
		{{
			OID:      syncRequestControlOID,
			Critical: true,
			Value:    []byte{},
			HasValue: true,
		}},
		{
			{
				OID:      syncRequestControlOID,
				Value:    ldapwire.EncodeSyncRequestValue(request),
				HasValue: true,
			},
			{
				OID:      syncRequestControlOID,
				Value:    ldapwire.EncodeSyncRequestValue(request),
				HasValue: true,
			},
		},
		{
			{
				OID:      syncRequestControlOID,
				Value:    ldapwire.EncodeSyncRequestValue(request),
				HasValue: true,
			},
			{
				OID: pagedResultsControlOID,
				Value: ldapwire.EncodePagedResultsValue(
					10,
					nil,
				),
				HasValue: true,
			},
		},
	} {
		if _, failure := parseRequestControls(
			controls,
			supportsSync|supportsPagedResults,
		); failure == nil || failure.Code != ldapwire.ResultProtocolError {
			t.Fatalf("invalid Sync controls failure = %#v", failure)
		}
	}

	first, err := parseOpenLDAPCSN(
		"20260730010101.000001Z#000000#000#000000",
	)
	if err != nil {
		t.Fatalf("parse first CSN: %v", err)
	}
	second, err := parseOpenLDAPCSN(
		"20260730010101.000002Z#000000#001#000000",
	)
	if err != nil {
		t.Fatalf("parse second CSN: %v", err)
	}
	state := syncCSNState{0: first, 1: second}
	cookie := composeOpenLDAPSyncCookie(42, state)
	parsedCookie := parseOpenLDAPSyncCookie(cookie)
	if parsedCookie.rid != 42 ||
		len(parsedCookie.csns) != 2 ||
		compareOpenLDAPCSN(parsedCookie.csns[0], first) != 0 ||
		compareOpenLDAPCSN(parsedCookie.csns[1], second) != 0 {
		t.Fatalf("parsed multi-SID cookie = %#v from %q", parsedCookie, cookie)
	}
	deleteCookie := composeOpenLDAPSyncDeleteCookie(42, state, first)
	parsedDeleteCookie := parseOpenLDAPSyncCookie(deleteCookie)
	if !parsedDeleteCookie.hasDeletion ||
		compareOpenLDAPCSN(parsedDeleteCookie.deletionCSN, first) != 0 {
		t.Fatalf(
			"parsed delete cookie = %#v from %q",
			parsedDeleteCookie,
			deleteCookie,
		)
	}

	legacy, err := parseOpenLDAPCSN(
		"20260730010101Z#00000A#01#00000B",
	)
	if err != nil {
		t.Fatalf("parse OpenLDAP 2.3 CSN: %v", err)
	}
	if legacy.raw != "20260730010101.000000Z#00000a#001#00000b" ||
		legacy.serverID != 1 {
		t.Fatalf("normalized OpenLDAP 2.3 CSN = %#v", legacy)
	}
	leapSecond, err := parseOpenLDAPCSN(
		"20161231235960.000000Z#000001#001#000001",
	)
	if err != nil ||
		leapSecond.raw != "20161231235960.000000Z#000001#001#000001" {
		t.Fatalf("parse leap-second CSN = %#v, %v", leapSecond, err)
	}
	afterLeapSecond, err := parseOpenLDAPCSN(
		"20170101000000.000000Z#000001#001#000001",
	)
	if err != nil || compareOpenLDAPCSN(leapSecond, afterLeapSecond) >= 0 {
		t.Fatalf(
			"leap-second ordering = %d, %v",
			compareOpenLDAPCSN(leapSecond, afterLeapSecond),
			err,
		)
	}
	for _, malformed := range []string{
		"20260730010101.000001Z#+00001#001#000001",
		"20260730010101.000001Z#000001#0+1#000001",
		" 20260730010101.000001Z#000001#001#000001",
	} {
		if _, err := parseOpenLDAPCSN(malformed); err == nil {
			t.Fatalf("parseOpenLDAPCSN(%q) succeeded", malformed)
		}
	}
}

func TestSyncProviderConfigurationRejectsInvalidOverlay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		lastMod  string
		overlays int
	}{
		{name: "lastmod disabled", lastMod: "FALSE", overlays: 1},
		{name: "duplicate", lastMod: "TRUE", overlays: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			err := store.Update(
				context.Background(),
				func(writer storage.Writer) error {
					database := directory.Entry{
						DN: "olcDatabase={1}mdb,cn=config",
						Attributes: []directory.Attribute{
							{
								Description: "olcDatabase",
								Values:      stringValues("{1}mdb"),
							},
							{
								Description: "olcSuffix",
								Values:      stringValues("dc=example,dc=com"),
							},
							{
								Description: "olcLastMod",
								Values:      stringValues(test.lastMod),
							},
						},
					}
					if err := writer.Put(database, false); err != nil {
						return err
					}
					for index := range test.overlays {
						overlay := directory.Entry{
							DN: fmt.Sprintf(
								"olcOverlay={%d}syncprov,%s",
								index,
								database.DN,
							),
							Attributes: []directory.Attribute{{
								Description: "olcOverlay",
								Values: stringValues(fmt.Sprintf(
									"{%d}syncprov",
									index,
								)),
							}},
						}
						if err := writer.Put(overlay, false); err != nil {
							return err
						}
					}
					return nil
				},
			)
			if err != nil {
				t.Fatalf("seed invalid overlay: %v", err)
			}
			if _, err := loadRuntimeDatabases(
				context.Background(),
				store,
			); err == nil {
				t.Fatal("loadRuntimeDatabases() accepted invalid syncprov overlay")
			}
		})
	}
}

func TestSyncSearchRejectsIllegalContext(t *testing.T) {
	t.Parallel()

	t.Run("deref in searching", func(t *testing.T) {
		t.Parallel()
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedSyncProviderDirectory(t, store)
		address, stop := startServer(t, store, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stop()
		connection := dialAndBindRawLDAP(
			t,
			address,
			syncTestRootDN,
			syncTestRootPassword,
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawSyncSearchRequest(t, ldap.DerefInSearching),
			rawSyncRequestControl(ldapwire.SyncRequestValue{
				Mode: ldapwire.SyncRefreshOnly,
			}, true),
		)
		response := readRawSyncMessage(t, connection, 2)
		if response.applicationTag != ldapwire.ApplicationSearchResultDone ||
			response.resultCode != int64(ldapwire.ResultProtocolError) {
			t.Fatalf("illegal deref Sync response = %#v", response)
		}
	})

	t.Run("provider not configured", func(t *testing.T) {
		t.Parallel()
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		address, stop := startServer(t, store, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stop()
		connection := dialAndBindRawLDAP(
			t,
			address,
			syncTestRootDN,
			syncTestRootPassword,
		)
		defer connection.Close()
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawSyncSearchRequest(t, ldap.NeverDerefAliases),
			rawSyncRequestControl(ldapwire.SyncRequestValue{
				Mode: ldapwire.SyncRefreshOnly,
			}, true),
		)
		response := readRawSyncMessage(t, connection, 2)
		if response.applicationTag != ldapwire.ApplicationSearchResultDone ||
			response.resultCode !=
				int64(ldapwire.ResultUnavailableCriticalExtension) {
			t.Fatalf("unconfigured Sync response = %#v", response)
		}
	})
}

type rawSyncRefresh struct {
	entries      []rawSyncEntry
	infos        []ldapwire.SyncInfoValue
	done         *ldapwire.SyncDoneValue
	doneControls map[string][]byte
	resultCode   int64
}

type rawSyncEntry struct {
	dn             string
	attributeCount int
	attributeNames []string
	attributes     map[string][]string
	state          ldapwire.SyncStateValue
	controls       map[string][]byte
}

type rawSyncMessage struct {
	messageID      int64
	applicationTag uint64
	entry          *rawSyncEntry
	info           *ldapwire.SyncInfoValue
	done           *ldapwire.SyncDoneValue
	controls       map[string][]byte
	resultCode     int64
}

func (refresh rawSyncRefresh) presentUUIDs() []ldapwire.SyncUUID {
	var uuids []ldapwire.SyncUUID
	for _, info := range refresh.infos {
		if info.Kind == ldapwire.SyncInfoIDSet && !info.RefreshDeletes {
			uuids = append(uuids, info.UUIDs...)
		}
	}
	return uuids
}

func readRawSyncRefresh(
	t *testing.T,
	connection net.Conn,
	messageID int64,
) rawSyncRefresh {
	t.Helper()
	var refresh rawSyncRefresh
	for {
		message := readRawSyncMessage(t, connection, messageID)
		switch {
		case message.entry != nil:
			refresh.entries = append(refresh.entries, *message.entry)
		case message.info != nil:
			refresh.infos = append(refresh.infos, *message.info)
		case message.applicationTag == ldapwire.ApplicationSearchResultDone:
			refresh.done = message.done
			refresh.doneControls = message.controls
			refresh.resultCode = message.resultCode
			return refresh
		default:
			t.Fatalf("unexpected Sync response = %#v", message)
		}
	}
}

func readRawSyncEntryState(
	t *testing.T,
	connection net.Conn,
	messageID int64,
) rawSyncEntry {
	t.Helper()
	for {
		message := readRawSyncMessage(t, connection, messageID)
		if message.entry != nil {
			return *message.entry
		}
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoNewCookie {
			continue
		}
		t.Fatalf("unexpected persistent Sync response = %#v", message)
	}
}

func readRawSyncMessage(
	t *testing.T,
	connection net.Conn,
	wantMessageID int64,
) rawSyncMessage {
	t.Helper()
	packet := readRawLDAPPacket(t, connection)
	if len(packet.Children) < 2 {
		t.Fatalf("malformed LDAP message: %#v", packet)
	}
	messageID, err := ber.ParseInt64(packet.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP message ID: %v", err)
	}
	if wantMessageID >= 0 && messageID != wantMessageID {
		t.Fatalf("LDAP message ID = %d, want %d", messageID, wantMessageID)
	}
	operation := packet.Children[1]
	message := rawSyncMessage{
		messageID:      messageID,
		applicationTag: uint64(operation.Tag),
		controls:       rawLDAPResponseControls(packet),
	}
	switch uint64(operation.Tag) {
	case ldapwire.ApplicationSearchResultEntry:
		if len(operation.Children) != 2 {
			t.Fatalf("malformed SearchResultEntry: %#v", operation)
		}
		attributeNames := make(
			[]string,
			0,
			len(operation.Children[1].Children),
		)
		attributes := make(
			map[string][]string,
			len(operation.Children[1].Children),
		)
		for _, attribute := range operation.Children[1].Children {
			if len(attribute.Children) != 2 {
				t.Fatalf("malformed PartialAttribute: %#v", attribute)
			}
			description := attribute.Children[0].Data.String()
			attributeNames = append(
				attributeNames,
				description,
			)
			values := make([]string, 0, len(attribute.Children[1].Children))
			for _, value := range attribute.Children[1].Children {
				values = append(values, value.Data.String())
			}
			attributes[description] = values
		}
		control := rawLDAPResponseControl(t, packet, syncStateControlOID)
		state, err := ldapwire.DecodeSyncStateValue(control)
		if err != nil {
			t.Fatalf("DecodeSyncStateValue(): %v", err)
		}
		message.entry = &rawSyncEntry{
			dn:             operation.Children[0].Data.String(),
			attributeCount: len(operation.Children[1].Children),
			attributeNames: attributeNames,
			attributes:     attributes,
			state:          state,
			controls:       message.controls,
		}
	case ldapwire.ApplicationIntermediateResponse:
		var name string
		var value []byte
		for _, child := range operation.Children {
			switch child.Tag {
			case 0:
				name = child.Data.String()
			case 1:
				value = bytes.Clone(child.Data.Bytes())
			}
		}
		if name != syncInfoOID {
			t.Fatalf("intermediate response name = %q", name)
		}
		info, err := ldapwire.DecodeSyncInfoValue(value)
		if err != nil {
			t.Fatalf("DecodeSyncInfoValue(): %v", err)
		}
		message.info = &info
	case ldapwire.ApplicationSearchResultDone:
		message.resultCode = rawLDAPResultCode(t, operation)
		if len(packet.Children) == 3 {
			value := rawLDAPResponseControl(t, packet, syncDoneControlOID)
			done, err := ldapwire.DecodeSyncDoneValue(value)
			if err != nil {
				t.Fatalf("DecodeSyncDoneValue(): %v", err)
			}
			message.done = &done
		}
	case ldapwire.ApplicationExtendedResponse:
		message.resultCode = rawLDAPResultCode(t, operation)
	default:
		t.Fatalf("unexpected LDAP application tag %d", operation.Tag)
	}
	return message
}

func rawLDAPResultCode(t *testing.T, operation *ber.Packet) int64 {
	t.Helper()
	if len(operation.Children) == 0 {
		t.Fatalf("LDAP result has no resultCode: %#v", operation)
	}
	code, err := ber.ParseInt64(operation.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP resultCode: %v", err)
	}
	return code
}

func rawLDAPResponseControl(
	t *testing.T,
	message *ber.Packet,
	oid string,
) []byte {
	t.Helper()
	value, exists := rawLDAPResponseControls(message)[oid]
	if exists {
		return value
	}
	t.Fatalf("LDAP response control %s not found", oid)
	return nil
}

func rawLDAPResponseControls(message *ber.Packet) map[string][]byte {
	if len(message.Children) != 3 {
		return nil
	}
	controls := make(map[string][]byte, len(message.Children[2].Children))
	for _, control := range message.Children[2].Children {
		if len(control.Children) == 0 {
			continue
		}
		oid := control.Children[0].Data.String()
		for _, child := range control.Children[1:] {
			if child.ClassType == ber.ClassUniversal &&
				child.Tag == ber.TagOctetString {
				controls[oid] = bytes.Clone(child.Data.Bytes())
			}
		}
	}
	return controls
}

func rawSyncSearchRequest(t *testing.T, derefAliases int) *ber.Packet {
	t.Helper()
	return rawSyncSearchRequestFor(
		t,
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		derefAliases,
		"(objectClass=*)",
	)
}

func rawSyncSearchRequestFor(
	t *testing.T,
	baseDN string,
	scope int,
	derefAliases int,
	filterString string,
) *ber.Packet {
	t.Helper()
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationSearchRequest,
		nil,
		"SearchRequest",
	)
	request.AppendChild(rawOctetString([]byte(baseDN)))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(scope),
		"scope",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(derefAliases),
		"derefAliases",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"sizeLimit",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"timeLimit",
	))
	request.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		false,
		"typesOnly",
	))
	filter, err := ldap.CompileFilter(filterString)
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	request.AppendChild(filter)
	attributes := ber.NewSequence("attributes")
	attributes.AppendChild(rawOctetString([]byte("*")))
	attributes.AppendChild(rawOctetString([]byte("+")))
	request.AppendChild(attributes)
	return request
}

func rawSyncRequestControl(
	request ldapwire.SyncRequestValue,
	critical bool,
) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(rawOctetString([]byte(syncRequestControlOID)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	control.AppendChild(rawOctetString(
		ldapwire.EncodeSyncRequestValue(request),
	))
	return control
}

func seedSyncProviderDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	seedDirectory(t, store)
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		var entries []directory.Entry
		if err := writer.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			suffix, err := directory.ParseDN("dc=example,dc=com")
			if err != nil {
				return err
			}
			if suffix.Equal(dn) || suffix.AncestorOf(dn) {
				entries = append(entries, entry)
			}
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].DN < entries[j].DN
		})
		var contextCSN string
		for index := range entries {
			csn := fmt.Sprintf(
				"20260730010101.%06dZ#000000#000#000000",
				index+1,
			)
			uuid := fmt.Sprintf(
				"00000000-0000-4000-8000-%012x",
				index+1,
			)
			entries[index].ReplaceValues("entryUUID", stringValues(uuid))
			entries[index].ReplaceValues("entryCSN", stringValues(csn))
			contextCSN = csn
		}
		for index := range entries {
			if entries[index].DN == "dc=example,dc=com" {
				entries[index].ReplaceValues(
					"contextCSN",
					stringValues(contextCSN),
				)
			}
			if err := writer.Put(entries[index], true); err != nil {
				return err
			}
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      stringValues("{0}syncprov"),
			}},
		}, false)
	})
	if err != nil {
		t.Fatalf("seed Sync provider directory: %v", err)
	}
}

func dialLDAPRoot(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		client.Close()
		t.Fatalf("root Bind(): %v", err)
	}
	return client
}

func syncContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
