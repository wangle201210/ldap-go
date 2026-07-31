package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerAppliesRenameDeleteAndCookieAtomically(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	identifier := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	firstCookie := []byte(
		"rid=001,csn=20260730010101.000001Z#000000#001#000000",
	)
	first := ldap.NewEntry(
		"uid=alice,dc=example,dc=com",
		map[string][]string{
			"objectClass": {"inetOrgPerson"},
			"cn":          {"Alice"},
			"sn":          {"Example"},
			"uid":         {"alice"},
			"entryCSN": {
				"20260730010101.000001Z#000000#001#000000",
			},
		},
	)
	if err := server.applySyncConsumerEntry(
		context.Background(),
		config,
		first,
		&ldap.ControlSyncState{
			State:     ldap.SyncStateAdd,
			EntryUUID: identifier,
			Cookie:    firstCookie,
		},
	); err != nil {
		t.Fatalf("apply add: %v", err)
	}

	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
		identifier.String(),
		"Alice",
	)
	assertSyncConsumerCookie(t, store, config, firstCookie)
	assertSyncConsumerContextCSN(
		t,
		store,
		config.partition,
		"20260730010101.000001Z#000000#001#000000",
	)

	secondCookie := []byte(
		"rid=001,csn=20260730010102.000001Z#000000#001#000000",
	)
	renamed := ldap.NewEntry(
		"uid=renamed,dc=example,dc=com",
		map[string][]string{
			"objectClass": {"inetOrgPerson"},
			"cn":          {"Renamed"},
			"sn":          {"Example"},
			"uid":         {"renamed"},
			"entryCSN": {
				"20260730010102.000001Z#000000#001#000000",
			},
		},
	)
	if err := server.applySyncConsumerEntry(
		context.Background(),
		config,
		renamed,
		&ldap.ControlSyncState{
			State:     ldap.SyncStateModify,
			EntryUUID: identifier,
			Cookie:    secondCookie,
		},
	); err != nil {
		t.Fatalf("apply rename: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
	)
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=renamed,dc=example,dc=com",
		identifier.String(),
		"Renamed",
	)
	assertSyncConsumerCookie(t, store, config, secondCookie)

	thirdCookie := []byte(
		"rid=001,csn=20260730010103.000001Z#000000#001#000000",
	)
	if err := server.applySyncConsumerEntry(
		context.Background(),
		config,
		ldap.NewEntry("uid=renamed,dc=example,dc=com", nil),
		&ldap.ControlSyncState{
			State:     ldap.SyncStateDelete,
			EntryUUID: identifier,
			Cookie:    thirdCookie,
		},
	); err != nil {
		t.Fatalf("apply delete: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=renamed,dc=example,dc=com",
	)
	assertSyncConsumerCookie(t, store, config, thirdCookie)
}

func TestSyncConsumerPresentPhaseDeletesNonpresentEntries(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	presentUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	staleUUID := "11111111-aaaa-bbbb-cccc-222222222222"
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		syncConsumerTestEntry(
			"uid=present,dc=example,dc=com",
			presentUUID,
			"Present",
		),
		syncConsumerTestEntry(
			"uid=stale,dc=example,dc=com",
			staleUUID,
			"Stale",
		),
	})
	cookie := []byte(
		"rid=001,csn=20260730010201.000001Z#000000#001#000000",
	)
	refresh := syncConsumerRefreshState{
		seen: map[string]struct{}{presentUUID: {}},
	}
	if err := server.finishSyncConsumerRefresh(
		context.Background(),
		config,
		&refresh,
		false,
		cookie,
	); err != nil {
		t.Fatalf("finish refreshPresent: %v", err)
	}
	if !refresh.complete {
		t.Fatal("refresh was not marked complete")
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=present,dc=example,dc=com",
		presentUUID,
		"Present",
	)
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=stale,dc=example,dc=com",
	)
	assertSyncConsumerCookie(t, store, config, cookie)
}

func TestSyncConsumerRefreshDeletesKeepsUnmentionedEntries(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	identifier := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		syncConsumerTestEntry(
			"uid=existing,dc=example,dc=com",
			identifier,
			"Existing",
		),
	})
	refresh := syncConsumerRefreshState{seen: make(map[string]struct{})}
	if err := server.finishSyncConsumerRefresh(
		context.Background(),
		config,
		&refresh,
		true,
		[]byte("rid=001"),
	); err != nil {
		t.Fatalf("finish refreshDelete: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=existing,dc=example,dc=com",
		identifier,
		"Existing",
	)
}

func TestSyncConsumerRollsBackCookieOnEntryConflict(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	identifier := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		syncConsumerTestEntry(
			"uid=one,dc=example,dc=com",
			identifier,
			"One",
		),
		syncConsumerTestEntry(
			"uid=two,dc=example,dc=com",
			identifier,
			"Two",
		),
	})
	err := server.applySyncConsumerEntry(
		context.Background(),
		config,
		ldap.NewEntry(
			"uid=next,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"cn":          {"Next"},
				"sn":          {"Example"},
			},
		),
		&ldap.ControlSyncState{
			State:     ldap.SyncStateModify,
			EntryUUID: uuid.MustParse(identifier),
			Cookie:    []byte("rid=001"),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("conflict error = %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
		return err
	}); !errors.Is(err, storage.ErrMetadataNotFound) {
		t.Fatalf("cookie after rolled-back update error = %v", err)
	}
}

func TestSyncConsumerRequestedAttributesIncludeProtocolRequirements(t *testing.T) {
	t.Parallel()

	config := syncConsumerConfig{attributes: []string{"+"}}
	attributes := syncConsumerRequestedAttributes(config)
	if !slices.Contains(attributes, "objectClass") {
		t.Fatalf("operational-only attributes = %q", attributes)
	}
	config.attributes = []string{"*"}
	attributes = syncConsumerRequestedAttributes(config)
	for _, required := range []string{
		"structuralObjectClass",
		"entryCSN",
		"entryUUID",
	} {
		if !slices.Contains(attributes, required) {
			t.Fatalf("user-only attributes = %q, missing %s", attributes, required)
		}
	}
}

func TestSyncConsumerSuffixMassageMapsDNValuedAttributes(t *testing.T) {
	t.Parallel()

	server, _, _ := newSyncConsumerUnitServer(t)
	local := mustSyncConsumerDN(t, "dc=local,dc=com")
	config, err := parseSyncConsumerConfig(
		`rid=1 provider=ldap://provider `+
			`searchbase="dc=example,dc=com" `+
			`suffixmassage="dc=local,dc=com"`,
		"consumer-local",
		[]directory.DN{local},
	)
	if err != nil {
		t.Fatalf("parseSyncConsumerConfig(): %v", err)
	}
	identifier := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	entry, err := syncConsumerDirectoryEntry(
		server.runtime.Load(),
		config,
		ldap.NewEntry(
			"cn=alias,dc=example,dc=com",
			map[string][]string{
				"objectClass":       {"alias"},
				"cn":                {"alias"},
				"aliasedObjectName": {"uid=alice,dc=example,dc=com"},
			},
		),
		&ldap.ControlSyncState{
			State:     ldap.SyncStateAdd,
			EntryUUID: identifier,
		},
	)
	if err != nil {
		t.Fatalf("syncConsumerDirectoryEntry(): %v", err)
	}
	if entry.DN != "cn=alias,dc=local,dc=com" {
		t.Fatalf("mapped DN = %q", entry.DN)
	}
	values := entry.Values("aliasedObjectName")
	if len(values) != 1 ||
		string(values[0]) != "uid=alice,dc=local,dc=com" {
		t.Fatalf("mapped aliasedObjectName = %q", values)
	}
}

func TestSyncConsumerRetryCursor(t *testing.T) {
	t.Parallel()

	cursor := syncConsumerRetryCursor{policy: []syncConsumerRetry{
		{interval: 5, attempts: 2},
		{interval: 60, attempts: 1},
	}}
	var intervals []int64
	for {
		interval, ok := cursor.next()
		if !ok {
			break
		}
		intervals = append(intervals, int64(interval))
	}
	if !slices.Equal(intervals, []int64{5, 5, 60}) {
		t.Fatalf("retry intervals = %v", intervals)
	}
}

func TestSyncreplConsumerConvergesWithLDAPGoProvider(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedSyncConsumerDatabase(
		t,
		consumerStore,
		providerAddress,
		syncTestRootPassword,
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer func() {
		if stopConsumer != nil {
			stopConsumer()
		}
	}()

	consumer := dialLDAPRoot(t, consumerAddress)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)
	direct := newPersonAddRequest("direct")
	assertLDAPReferral(
		t,
		consumer.Add(direct),
		"",
		"ldap://"+providerAddress+
			"/uid=direct,ou=people,dc=example,dc=com",
	)

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	if err := provider.Add(newPersonAddRequest("bob")); err != nil {
		t.Fatalf("provider add bob: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"cn",
		"Test User",
	)
	rename := ldap.NewModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)
	rename.Replace("cn", []string{"Bob Online"})
	if err := provider.Modify(rename); err != nil {
		t.Fatalf("provider modify bob: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"cn",
		"Bob Online",
	)

	consumer.Close()
	stopConsumer()
	stopConsumer = nil

	offline := ldap.NewModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)
	offline.Replace("cn", []string{"Bob Offline"})
	if err := provider.Modify(offline); err != nil {
		t.Fatalf("provider offline modify: %v", err)
	}
	if err := provider.Add(newPersonAddRequest("carol")); err != nil {
		t.Fatalf("provider offline add: %v", err)
	}
	if err := provider.Del(ldap.NewDelRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("provider offline delete: %v", err)
	}

	consumerAddress, stopConsumer = startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	consumer = dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"cn",
		"Bob Offline",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=carol,ou=people,dc=example,dc=com",
		"uid",
		"carol",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
	)

	if err := provider.Del(ldap.NewDelRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("provider persistent delete: %v", err)
	}
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
	)
}

func TestSyncreplConsumerFollowsOnlineConfiguration(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()
	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedOnlineConfiguration(t, consumerStore)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()
	configClient, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	consumer, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(consumer): %v", err)
	}
	defer consumer.Close()

	beforeStart := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	beforeStart.Replace("cn", []string{"Alice Before Start"})
	if err := provider.Modify(beforeStart); err != nil {
		t.Fatalf("provider modify before enable: %v", err)
	}
	dataConfigDN := "olcDatabase={1}mdb,cn=config"
	enable := ldap.NewModifyRequest(dataConfigDN, nil)
	enable.Add("olcSyncrepl", []string{
		syncConsumerConfigValue(providerAddress, syncTestRootPassword),
	})
	enable.Add("olcUpdateRef", []string{"ldap://" + providerAddress})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable online syncrepl: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Before Start",
	)

	invalid := ldap.NewModifyRequest(dataConfigDN, nil)
	invalid.Replace("olcSyncrepl", []string{
		`{0}rid=001 searchbase="dc=example,dc=com"`,
	})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	afterRollback := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	afterRollback.Replace("cn", []string{"Alice After Rollback"})
	if err := provider.Modify(afterRollback); err != nil {
		t.Fatalf("provider modify after rollback: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice After Rollback",
	)

	disable := ldap.NewModifyRequest(dataConfigDN, nil)
	disable.Delete("olcSyncrepl", []string{})
	disable.Delete("olcUpdateRef", []string{})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable online syncrepl: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	afterStop := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	afterStop.Replace("cn", []string{"Alice After Stop"})
	if err := provider.Modify(afterStop); err != nil {
		t.Fatalf("provider modify after stop: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	assertSyncConsumerLDAPAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice After Rollback",
	)

	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("re-enable online syncrepl: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice After Stop",
	)
}

func TestSyncreplConsumerSuffixMassage(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedSyncConsumerSuffixDatabase(t, consumerStore, providerAddress)
	const localRootDN = "cn=admin,dc=local,dc=com"
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       localRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(local consumer): %v", err)
	}
	defer consumer.Close()
	if err := consumer.Bind(localRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("Bind(local consumer): %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=local,dc=com",
		"cn",
		"Alice Example",
	)

	direct := ldap.NewAddRequest(
		"uid=direct,ou=people,dc=local,dc=com",
		nil,
	)
	direct.Attribute("objectClass", []string{"inetOrgPerson"})
	direct.Attribute("uid", []string{"direct"})
	direct.Attribute("cn", []string{"Direct"})
	direct.Attribute("sn", []string{"Direct"})
	assertLDAPReferral(
		t,
		consumer.Add(direct),
		"",
		"ldap://"+providerAddress+
			"/uid=direct,ou=people,dc=example,dc=com",
	)

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	if err := provider.Add(newPersonAddRequest("frank")); err != nil {
		t.Fatalf("provider add frank: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=frank,ou=people,dc=local,dc=com",
		"uid",
		"frank",
	)
}

func TestSyncreplConsumerFractionalAttributes(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedFractionalSyncConsumerDatabase(t, consumerStore, providerAddress)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)
	assertFractionalSyncConsumerEntry(t, consumer, "Alice Example")

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Fractional"})
	modify.Replace("jpegPhoto", []string{"excluded-photo"})
	if err := provider.Modify(modify); err != nil {
		t.Fatalf("provider fractional modify: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Fractional",
	)
	assertFractionalSyncConsumerEntry(t, consumer, "Alice Fractional")
}

func TestSyncreplConsumerFilteredEntryExitAndReentry(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedSpecialSyncConsumerDatabase(
		t,
		consumerStore,
		providerAddress,
		`filter="(cn=Alice Example)" type=refreshAndPersist`,
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
	)

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	exit := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	exit.Replace("cn", []string{"Outside Filter"})
	if err := provider.Modify(exit); err != nil {
		t.Fatalf("provider filter exit: %v", err)
	}
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
	)

	reenter := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	reenter.Replace("cn", []string{"Alice Example"})
	if err := provider.Modify(reenter); err != nil {
		t.Fatalf("provider filter reentry: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)
}

func TestSyncreplConsumerRefreshOnlyInterval(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedSyncProviderDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedSpecialSyncConsumerDatabase(
		t,
		consumerStore,
		providerAddress,
		`filter="(objectClass=*)" type=refreshOnly interval=00:00:00:01`,
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	if err := provider.Add(newPersonAddRequest("grace")); err != nil {
		t.Fatalf("provider refreshOnly add: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=grace,ou=people,dc=example,dc=com",
		"uid",
		"grace",
	)
}

func newSyncConsumerUnitServer(
	t *testing.T,
) (*Server, storage.Store, syncConsumerConfig) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	config, err := parseSyncConsumerConfig(
		`rid=1 provider=ldap://provider `+
			`searchbase="dc=example,dc=com" type=refreshAndPersist`,
		"consumer-test",
		[]directory.DN{suffix},
	)
	if err != nil {
		t.Fatalf("parseSyncConsumerConfig(): %v", err)
	}
	return instance, store, config
}

func seedSyncConsumerDatabase(
	t *testing.T,
	store storage.Store,
	providerAddress,
	providerPassword string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					syncConsumerConfigValue(
						providerAddress,
						providerPassword,
					),
				),
			},
			{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://" + providerAddress),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed sync consumer database: %v", err)
	}
}

func seedSyncConsumerSuffixDatabase(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=local,dc=com")},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					`{0}rid=001 provider=ldap://` + providerAddress +
						` bindmethod=simple binddn="` + syncTestRootDN +
						`" credentials="` + syncTestRootPassword +
						`" searchbase="dc=example,dc=com"` +
						` suffixmassage="dc=local,dc=com"` +
						` filter="(objectClass=*)" scope=sub attrs="*,+"` +
						` type=refreshAndPersist retry="1 +"`,
				),
			},
			{
				Description: "olcUpdateRef",
				Values: stringValues(
					"ldap://" + providerAddress + "/dc=example,dc=com",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=local,dc=com"})
	}); err != nil {
		t.Fatalf("seed suffix-massage consumer: %v", err)
	}
}

func seedFractionalSyncConsumerDatabase(
	t *testing.T,
	store storage.Store,
	providerAddress string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					`{0}rid=001 provider=ldap://` + providerAddress +
						` bindmethod=simple binddn="` + syncTestRootDN +
						`" credentials="` + syncTestRootPassword +
						`" searchbase="dc=example,dc=com"` +
						` filter="(objectClass=*)" scope=sub` +
						` attrs="objectClass,uid,cn,sn,ou,dc"` +
						` exattrs="userPassword,jpegPhoto"` +
						` type=refreshAndPersist retry="1 +"`,
				),
			},
			{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://" + providerAddress),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed fractional consumer: %v", err)
	}
}

func seedSpecialSyncConsumerDatabase(
	t *testing.T,
	store storage.Store,
	providerAddress,
	searchSettings string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{
				Description: "olcSyncrepl",
				Values: stringValues(
					`{0}rid=001 provider=ldap://` + providerAddress +
						` bindmethod=simple binddn="` + syncTestRootDN +
						`" credentials="` + syncTestRootPassword +
						`" searchbase="dc=example,dc=com"` +
						` scope=sub attrs="*,+" ` + searchSettings +
						` retry="1 +"`,
				),
			},
			{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://" + providerAddress),
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed special sync consumer: %v", err)
	}
}

func syncConsumerConfigValue(
	providerAddress,
	providerPassword string,
) string {
	return `{0}rid=001 provider=ldap://` + providerAddress +
		` bindmethod=simple binddn="` + syncTestRootDN +
		`" credentials="` + providerPassword +
		`" searchbase="dc=example,dc=com"` +
		` filter="(objectClass=*)" scope=sub attrs="*,+"` +
		` schemachecking=off type=refreshAndPersist` +
		` retry="1 +"`
}

func waitForSyncConsumerAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	want string,
) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var last string
	var lastErr error
	for time.Now().Before(deadline) {
		result, err := client.Search(ldap.NewSearchRequest(
			dn,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=*)",
			[]string{attribute},
			nil,
		))
		lastErr = err
		if err == nil && len(result.Entries) == 1 {
			last = result.Entries[0].GetAttributeValue(attribute)
			if last == want {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf(
		"consumer %s %s = %q, want %q (last error %v)",
		dn,
		attribute,
		last,
		want,
		lastErr,
	)
}

func waitForSyncConsumerMissing(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		result, err := client.Search(ldap.NewSearchRequest(
			dn,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		))
		lastErr = err
		if err != nil {
			var ldapErr *ldap.Error
			if errors.As(err, &ldapErr) &&
				ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
				return
			}
		} else if len(result.Entries) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer still contains %s (last error %v)", dn, lastErr)
}

func assertSyncConsumerLDAPAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	want string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{attribute},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("consumer Search(%s) = %#v, %v", dn, result, err)
	}
	if got := result.Entries[0].GetAttributeValue(attribute); got != want {
		t.Fatalf("consumer %s %s = %q, want %q", dn, attribute, got, want)
	}
}

func assertFractionalSyncConsumerEntry(
	t *testing.T,
	client *ldap.Conn,
	wantCN string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{
			"cn",
			"userPassword",
			"jpegPhoto",
			"entryUUID",
			"entryCSN",
		},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("fractional Search() = %#v, %v", result, err)
	}
	entry := result.Entries[0]
	if got := entry.GetAttributeValue("cn"); got != wantCN {
		t.Fatalf("fractional cn = %q, want %q", got, wantCN)
	}
	if values := entry.GetAttributeValues("userPassword"); len(values) != 0 {
		t.Fatalf("fractional userPassword = %q", values)
	}
	if values := entry.GetRawAttributeValues("jpegPhoto"); len(values) != 0 {
		t.Fatalf("fractional jpegPhoto = %q", values)
	}
	if entry.GetAttributeValue("entryUUID") == "" ||
		entry.GetAttributeValue("entryCSN") == "" {
		t.Fatalf(
			"fractional operational attributes = UUID %q, CSN %q",
			entry.GetAttributeValue("entryUUID"),
			entry.GetAttributeValue("entryCSN"),
		)
	}
}

func seedSyncConsumerEntries(
	t *testing.T,
	store storage.Store,
	partition string,
	entries []directory.Entry,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.PutIn(partition, entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed consumer entries: %v", err)
	}
}

func syncConsumerTestEntry(
	dn,
	identifier,
	commonName string,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("inetOrgPerson"),
			},
			{Description: "cn", Values: stringValues(commonName)},
			{Description: "sn", Values: stringValues("Example")},
			{
				Description: "entryUUID",
				Values:      stringValues(identifier),
			},
		},
	}
}

func assertSyncConsumerStoredEntry(
	t *testing.T,
	store storage.Store,
	partition,
	rawDN,
	identifier,
	commonName string,
) {
	t.Helper()
	dn := mustSyncConsumerDN(t, rawDN)
	var entry directory.Entry
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		entry, err = reader.GetIn(partition, dn)
		return err
	}); err != nil {
		t.Fatalf("read %s: %v", rawDN, err)
	}
	if values := entry.Values("entryUUID"); len(values) != 1 ||
		!strings.EqualFold(string(values[0]), identifier) {
		t.Fatalf("%s entryUUID = %q", rawDN, values)
	}
	if values := entry.Values("cn"); len(values) != 1 ||
		string(values[0]) != commonName {
		t.Fatalf("%s cn = %q", rawDN, values)
	}
}

func assertSyncConsumerMissingEntry(
	t *testing.T,
	store storage.Store,
	partition,
	rawDN string,
) {
	t.Helper()
	dn := mustSyncConsumerDN(t, rawDN)
	err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.GetIn(partition, dn)
		return err
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("read missing %s error = %v", rawDN, err)
	}
}

func assertSyncConsumerCookie(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	want []byte,
) {
	t.Helper()
	var cookie []byte
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		cookie, err = reader.Metadata(syncConsumerCookieMetadataKey(config))
		return err
	}); err != nil {
		t.Fatalf("read syncrepl cookie: %v", err)
	}
	if !slices.Equal(cookie, want) {
		t.Fatalf("cookie = %q, want %q", cookie, want)
	}
}

func assertSyncConsumerContextCSN(
	t *testing.T,
	store storage.Store,
	partition,
	want string,
) {
	t.Helper()
	var raw []byte
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		raw, err = reader.Metadata(syncContextCSNMetadataKey(partition))
		return err
	}); err != nil {
		t.Fatalf("read contextCSN metadata: %v", err)
	}
	if string(raw) != want {
		t.Fatalf("contextCSN = %q, want %q", raw, want)
	}
}
