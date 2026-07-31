package server

import (
	"bytes"
	"context"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncProviderSessionLogReplaysDeletes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	configureSyncProviderPolicy(t, store, map[string]string{
		"olcSpSessionlog": "10",
	})
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
	initial := requestRawSyncRefresh(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)
	archiveUUID := rawSyncUUIDForDN(
		t,
		initial,
		"ou=archive,dc=example,dc=com",
	)

	client := dialLDAPRoot(t, address)
	defer client.Close()
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Session Log"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(alice): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}

	incremental := requestRawSyncRefresh(
		t,
		connection,
		3,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    bytes.Clone(initial.done.Cookie),
			HasCookie: true,
		},
	)
	deleted := rawSyncDeletedUUIDs(incremental)
	if incremental.resultCode != int64(ldapwire.ResultSuccess) ||
		incremental.done == nil ||
		!incremental.done.RefreshDeletes ||
		len(incremental.presentUUIDs()) != 0 ||
		len(deleted) != 1 ||
		deleted[0] != archiveUUID ||
		len(incremental.entries) != 1 ||
		incremental.entries[0].dn !=
			"uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("session-log incremental refresh = %#v", incremental)
	}
}

func TestSyncProviderSessionLogReportsFilterExit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	configureSyncProviderPolicy(t, store, map[string]string{
		"olcSpSessionlog": "10",
	})
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
	search := rawSyncSearchRequestFor(
		t,
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		"(cn=Alice Example)",
	)
	initial := requestRawSyncRefresh(
		t,
		connection,
		2,
		search,
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)
	aliceUUID := rawSyncUUIDForDN(
		t,
		initial,
		"uid=alice,ou=people,dc=example,dc=com",
	)

	client := dialLDAPRoot(t, address)
	defer client.Close()
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Bob"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(alice filter exit): %v", err)
	}

	incremental := requestRawSyncRefresh(
		t,
		connection,
		3,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(cn=Alice Example)",
		),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    bytes.Clone(initial.done.Cookie),
			HasCookie: true,
		},
	)
	deleted := rawSyncDeletedUUIDs(incremental)
	if incremental.resultCode != int64(ldapwire.ResultSuccess) ||
		incremental.done == nil ||
		!incremental.done.RefreshDeletes ||
		len(incremental.entries) != 0 ||
		len(deleted) != 1 ||
		deleted[0] != aliceUUID {
		t.Fatalf("filter-exit incremental refresh = %#v", incremental)
	}
}

func TestSyncProviderSessionLogFallsBackToPresentAfterEviction(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	configureSyncProviderPolicy(t, store, map[string]string{
		"olcSpSessionlog": "1",
	})
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
	initial := requestRawSyncRefresh(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)

	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Evicted Log"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(alice): %v", err)
	}

	incremental := requestRawSyncRefresh(
		t,
		connection,
		3,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    bytes.Clone(initial.done.Cookie),
			HasCookie: true,
		},
	)
	if incremental.resultCode != int64(ldapwire.ResultSuccess) ||
		incremental.done == nil ||
		incremental.done.RefreshDeletes ||
		len(rawSyncDeletedUUIDs(incremental)) != 0 ||
		len(incremental.presentUUIDs()) != 2 ||
		len(incremental.entries) != 1 {
		t.Fatalf("evicted session-log refresh = %#v", incremental)
	}
}

func TestSyncProviderNoPresentSkipsPresentPhase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	configureSyncProviderPolicy(t, store, map[string]string{
		"olcSpNoPresent": "TRUE",
	})
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
	initial := requestRawSyncRefresh(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)

	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}
	incremental := requestRawSyncRefresh(
		t,
		connection,
		3,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    bytes.Clone(initial.done.Cookie),
			HasCookie: true,
		},
	)
	if incremental.resultCode != int64(ldapwire.ResultSuccess) ||
		incremental.done == nil ||
		!incremental.done.RefreshDeletes ||
		len(incremental.entries) != 0 ||
		len(incremental.infos) != 0 {
		t.Fatalf("no-present incremental refresh = %#v", incremental)
	}
}

func TestSyncProviderReloadHintControlsStaleCookie(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	configureSyncProviderPolicy(t, store, map[string]string{
		"olcSpSessionlog": "1",
		"olcSpReloadHint": "TRUE",
	})
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
	initial := requestRawSyncRefresh(
		t,
		connection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)
	cookie := bytes.Clone(initial.done.Cookie)

	client := dialLDAPRoot(t, address)
	defer client.Close()
	for _, modification := range []struct {
		dn        string
		attribute string
		value     string
	}{
		{
			dn:        "dc=example,dc=com",
			attribute: "description",
			value:     "newer base",
		},
		{
			dn:        "ou=people,dc=example,dc=com",
			attribute: "description",
			value:     "newer people",
		},
		{
			dn:        "uid=alice,ou=people,dc=example,dc=com",
			attribute: "cn",
			value:     "Newer Alice",
		},
	} {
		request := ldap.NewModifyRequest(modification.dn, nil)
		request.Replace(modification.attribute, []string{modification.value})
		if err := client.Modify(request); err != nil {
			t.Fatalf("Modify(%s): %v", modification.dn, err)
		}
	}
	if err := client.Del(ldap.NewDelRequest(
		"ou=archive,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(archive): %v", err)
	}

	rejected := requestRawSyncRefresh(
		t,
		connection,
		3,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    bytes.Clone(cookie),
			HasCookie: true,
		},
	)
	if rejected.resultCode != int64(ldapwire.ResultSyncRefreshRequired) ||
		rejected.done != nil ||
		len(rejected.entries) != 0 {
		t.Fatalf("stale-cookie response = %#v", rejected)
	}

	reloaded := requestRawSyncRefresh(
		t,
		connection,
		4,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		ldapwire.SyncRequestValue{
			Mode:       ldapwire.SyncRefreshOnly,
			Cookie:     bytes.Clone(cookie),
			HasCookie:  true,
			ReloadHint: true,
		},
	)
	if reloaded.resultCode != int64(ldapwire.ResultSuccess) ||
		reloaded.done == nil ||
		reloaded.done.RefreshDeletes ||
		len(reloaded.entries) != 3 ||
		len(reloaded.infos) != 0 {
		t.Fatalf("reload-hint refresh = %#v", reloaded)
	}
}

func TestSyncSessionLogConfigurationPreservesAndTrimsWindow(t *testing.T) {
	t.Parallel()

	csn := func(raw string) openLDAPCSN {
		t.Helper()
		parsed, err := parseOpenLDAPCSN(raw)
		if err != nil {
			t.Fatalf("parseOpenLDAPCSN(%q): %v", raw, err)
		}
		return parsed
	}
	baseline := csn("20260730010101.000001Z#000000#000#000000")
	first := csn("20260730010101.000002Z#000000#000#000000")
	second := csn("20260730010101.000003Z#000000#000#000000")
	const partition = "session-log-test"
	runtime := &runtimeState{
		databases: []runtimeDatabase{{
			partition:          partition,
			syncProvider:       true,
			syncSessionLogSize: 2,
		}},
		syncContexts: map[string]syncCSNState{
			partition: {0: baseline},
		},
	}
	hub := newSyncChangeHub()
	hub.configure(runtime)
	hub.publish(syncChange{
		partition: partition,
		csn:       first,
		before:    directory.Entry{DN: "uid=one,dc=example,dc=com"},
		hasBefore: true,
		after:     directory.Entry{DN: "uid=one,dc=example,dc=com"},
		hasAfter:  true,
	})
	hub.publish(syncChange{
		partition: partition,
		csn:       second,
		before:    directory.Entry{DN: "uid=two,dc=example,dc=com"},
		hasBefore: true,
	})

	cookie := syncCSNState{0: baseline}
	snapshot := syncCSNState{0: second}
	replay, usable := hub.replay(partition, cookie, snapshot)
	if !usable || len(replay) != 2 {
		t.Fatalf("initial replay = %#v, usable %t", replay, usable)
	}

	runtime.syncContexts[partition] = snapshot
	hub.configure(runtime)
	replay, usable = hub.replay(partition, cookie, snapshot)
	if !usable || len(replay) != 2 {
		t.Fatalf("replay after runtime refresh = %#v, usable %t", replay, usable)
	}

	runtime.databases[0].syncSessionLogSize = 1
	hub.configure(runtime)
	if replay, usable = hub.replay(partition, cookie, snapshot); usable {
		t.Fatalf("evicted cookie unexpectedly replayed %#v", replay)
	}
	replay, usable = hub.replay(
		partition,
		syncCSNState{0: first},
		snapshot,
	)
	if !usable || len(replay) != 1 ||
		compareOpenLDAPCSN(replay[0].csn, second) != 0 {
		t.Fatalf("trimmed replay = %#v, usable %t", replay, usable)
	}
}

func configureSyncProviderPolicy(
	t *testing.T,
	store storage.Store,
	attributes map[string]string,
) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(
			"olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		overlay, err := writer.Get(dn)
		if err != nil {
			return err
		}
		for description, value := range attributes {
			overlay.ReplaceValues(description, stringValues(value))
		}
		return writer.Put(overlay, true)
	})
	if err != nil {
		t.Fatalf("configure Sync provider policy: %v", err)
	}
}

func requestRawSyncRefresh(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	searchRequest *ber.Packet,
	request ldapwire.SyncRequestValue,
) rawSyncRefresh {
	t.Helper()
	writeRawLDAPRequest(
		t,
		connection,
		messageID,
		searchRequest,
		rawSyncRequestControl(request, true),
	)
	return readRawSyncRefresh(t, connection, messageID)
}

func rawSyncDeletedUUIDs(refresh rawSyncRefresh) []ldapwire.SyncUUID {
	var uuids []ldapwire.SyncUUID
	for _, info := range refresh.infos {
		if info.Kind == ldapwire.SyncInfoIDSet && info.RefreshDeletes {
			uuids = append(uuids, info.UUIDs...)
		}
	}
	return uuids
}

func rawSyncUUIDForDN(
	t *testing.T,
	refresh rawSyncRefresh,
	dn string,
) ldapwire.SyncUUID {
	t.Helper()
	for _, entry := range refresh.entries {
		if entry.dn == dn {
			return entry.state.EntryUUID
		}
	}
	t.Fatalf("Sync refresh has no entry %q: %#v", dn, refresh)
	return ldapwire.SyncUUID{}
}
