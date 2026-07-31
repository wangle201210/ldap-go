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
					`{0}rid=001 provider=ldap://` + providerAddress +
						` bindmethod=simple binddn="` + syncTestRootDN +
						`" credentials="` + providerPassword +
						`" searchbase="dc=example,dc=com"` +
						` filter="(objectClass=*)" scope=sub attrs="*,+"` +
						` schemachecking=off type=refreshAndPersist` +
						` retry="1 +"`,
				),
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
