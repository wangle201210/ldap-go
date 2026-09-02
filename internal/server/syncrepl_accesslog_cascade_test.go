package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerAccesslogCascadeDeduplicatesSharedCSNAcrossRIDs(t *testing.T) {
	server, store := newDeltaCascadeUnitServer(t)
	configOne, database := deltaCascadeUnitConfig(t, server, 1)
	configTwo, _ := deltaCascadeUnitConfig(t, server, 2)
	const (
		targetDN = "uid=loop,ou=people,dc=example,dc=com"
		csn      = "20260902010101.000001Z#000000#000#000000"
	)
	source := deltaCascadeAddEntry(targetDN, "Loop Original", csn)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		configOne,
		source,
		composeOpenLDAPSyncCookie(configOne.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
	); err != nil {
		t.Fatalf("apply first cascade operation: %v", err)
	}

	replayed := deltaCascadeAddEntry(targetDN, "Loop Replay", csn)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		configTwo,
		replayed,
		composeOpenLDAPSyncCookie(configTwo.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
	); err != nil {
		t.Fatalf("apply cross-RID replay: %v", err)
	}

	assertSyncConsumerStoredEntry(
		t,
		store,
		database.partition,
		targetDN,
		"10000000-0000-4000-8000-000000000001",
		"Loop Original",
	)
	if got := deltaCascadeAccesslogOperationCount(
		t, store, server.runtime.Load(), database, targetDN, "add",
	); got != 1 {
		t.Fatalf("cascade accesslog add count = %d, want 1", got)
	}
	assertSyncConsumerCookie(
		t,
		store,
		configTwo,
		composeOpenLDAPSyncCookie(configTwo.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
	)

	const duplicateCSN = "20260902010102.000001Z#000000#000#000000"
	duplicate := deltaCascadeAddEntry(targetDN, "Duplicate Add", duplicateCSN)
	err := server.applySyncConsumerAccesslogEntry(
		context.Background(), configOne, duplicate,
		composeOpenLDAPSyncCookie(
			configOne.rid,
			syncCSNState{0: mustOpenLDAPCSN(t, duplicateCSN)},
		),
	)
	if !errors.Is(err, storage.ErrEntryExists) {
		t.Fatalf("duplicate add error = %v, want entry exists", err)
	}
	if got := deltaCascadeAccesslogOperationCount(
		t, store, server.runtime.Load(), database, targetDN, "add",
	); got != 1 {
		t.Fatalf("accesslog add count after rejected duplicate = %d, want 1", got)
	}
	assertSyncConsumerCookie(
		t,
		store,
		configOne,
		composeOpenLDAPSyncCookie(configOne.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
	)
}

func TestSyncConsumerAccesslogCascadePersistsCookieAndDedupAcrossRestart(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "cascade.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	seedLDAPGoAccesslogProvider(t, store)
	server, err := New(Config{
		Store:        store,
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	config, database := deltaCascadeUnitConfig(t, server, 1)
	const (
		targetDN = "uid=restart,ou=people,dc=example,dc=com"
		addCSN   = "20260902010201.000001Z#000000#000#000000"
	)
	add := deltaCascadeAddEntry(targetDN, "Restart Original", addCSN)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(), config, add,
		composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, addCSN)}),
	); err != nil {
		t.Fatalf("apply pre-restart add: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close pre-restart store: %v", err)
	}

	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatalf("reopen Bolt: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server, err = New(Config{
		Store:        store,
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatalf("New() after restart: %v", err)
	}
	config, database = deltaCascadeUnitConfig(t, server, 1)
	replayed := deltaCascadeAddEntry(targetDN, "Restart Replay", addCSN)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(), config, replayed,
		composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, addCSN)}),
	); err != nil {
		t.Fatalf("replay after restart: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		database.partition,
		targetDN,
		"10000000-0000-4000-8000-000000000001",
		"Restart Original",
	)
	if got := deltaCascadeAccesslogOperationCount(
		t, store, server.runtime.Load(), database, targetDN, "add",
	); got != 1 {
		t.Fatalf("post-restart accesslog add count = %d, want 1", got)
	}

	const modifyCSN = "20260902010202.000001Z#000000#000#000000"
	modify := syncConsumerAccesslogTestEntry(
		"reqStart=20260902010202.000001Z,cn=log",
		targetDN,
		"modify",
		modifyCSN,
		[]string{"cn:= Restart Updated", "entryCSN:= " + modifyCSN},
		nil,
	)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(), config, modify,
		composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, modifyCSN)}),
	); err != nil {
		t.Fatalf("apply post-restart modify: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		database.partition,
		targetDN,
		"10000000-0000-4000-8000-000000000001",
		"Restart Updated",
	)
}

func TestSyncConsumerAccesslogCascadeRollsBackOnLocalLogFailure(t *testing.T) {
	server, store := newDeltaCascadeUnitServer(t)
	config, database := deltaCascadeUnitConfig(t, server, 1)
	runtime := server.runtime.Load()
	for index := range runtime.databases {
		if runtime.databases[index].partition == database.partition {
			runtime.databases[index].accesslog.targetDatabaseIndex = len(runtime.databases)
			break
		}
	}
	const csn = "20260902010301.000001Z#000000#000#000000"
	modify := syncConsumerAccesslogTestEntry(
		"reqStart=20260902010301.000001Z,cn=log",
		"uid=alice,ou=people,dc=example,dc=com",
		"modify",
		csn,
		[]string{"cn:= Must Roll Back", "entryCSN:= " + csn},
		nil,
	)
	err := server.applySyncConsumerAccesslogEntry(
		context.Background(), config, modify,
		composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
	)
	if err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("cascade log failure = %v, want unresolved target", err)
	}
	assertSyncConsumerEntryValues(
		t,
		store,
		database.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		[]string{"Alice Example"},
	)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
		return err
	}); !errors.Is(err, storage.ErrMetadataNotFound) {
		t.Fatalf("cookie persisted after rollback: %v", err)
	}
}

func TestSyncConsumerAccesslogCascadePreservesRawModifyDNRDN(t *testing.T) {
	server, store := newDeltaCascadeUnitServer(t)
	_, database := deltaCascadeUnitConfig(t, server, 1)
	config, err := parseSyncConsumerConfigWithNormalizer(
		`rid=001 provider=ldap://provider `+
			`searchbase="dc=remote,dc=com" `+
			`suffixmassage="dc=example,dc=com" `+
			`logbase="cn=log" `+
			`logfilter="(&(objectClass=auditWriteObject)(reqResult=0))" `+
			`syncdata=accesslog`,
		database.partition,
		database.suffixes,
		database.dnNormalizer,
	)
	if err != nil {
		t.Fatalf("parse suffixmassage cascade config: %v", err)
	}
	const rawRDN = `uid=renamed+cn=Smith\, Alice`
	entry := syncConsumerAccesslogTestEntry(
		"reqStart=20260902010401.000001Z,cn=log",
		"uid=alice,ou=people,dc=remote,dc=com",
		"modrdn",
		"20260902010401.000001Z#000000#000#000000",
		nil,
		map[string][]string{
			"reqNewRDN":       {rawRDN},
			"reqDeleteOldRDN": {"TRUE"},
			"reqNewSuperior":  {"ou=people,dc=remote,dc=com"},
		},
	)
	operation, err := parseSyncConsumerAccesslogOperation(
		server.runtime.Load(), config, entry,
	)
	if err != nil {
		t.Fatalf("parse multi-AVA ModDN: %v", err)
	}
	var applied syncConsumerAccesslogApplyResult
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		var err error
		applied, err = prepareSyncConsumerAccesslogApplyResult(
			writer, config, operation,
		)
		return err
	}); err != nil {
		t.Fatalf("prepare suffixmassage ModDN: %v", err)
	}
	applied.after = &directory.Entry{DN: applied.newDN.String()}
	record := syncConsumerAccesslogWriteRecord(operation, applied)
	if record.newRDN != rawRDN {
		t.Fatalf("cascaded reqNewRDN = %q, want exact %q", record.newRDN, rawRDN)
	}
	if record.requestDN.String() != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("cascaded reqDN = %q, want local suffix", record.requestDN.String())
	}
	if record.newSuperior == nil ||
		record.newSuperior.String() != "ou=people,dc=example,dc=com" {
		t.Fatalf("cascaded reqNewSuperior = %#v", record.newSuperior)
	}
}

func TestSyncConsumerAccesslogCascadeScopeTransitionsFailClosedOrDelete(
	t *testing.T,
) {
	t.Run("move into scope requires full refresh", func(t *testing.T) {
		server, store := newDeltaCascadeUnitServer(t)
		config, database := deltaCascadeUnitConfig(t, server, 1)
		setDeltaCascadePeopleScope(t, &config)
		const csn = "20260902010501.000001Z#000000#000#000000"
		moveIn := syncConsumerAccesslogTestEntry(
			"reqStart=20260902010501.000001Z,cn=log",
			"uid=outside,ou=outside,dc=example,dc=com",
			"modrdn",
			csn,
			[]string{"entryCSN:= " + csn},
			map[string][]string{
				"reqNewRDN":       {"uid=outside"},
				"reqDeleteOldRDN": {"TRUE"},
				"reqNewSuperior":  {"ou=people,dc=example,dc=com"},
			},
		)
		err := server.applySyncConsumerAccesslogEntry(
			context.Background(), config, moveIn,
			composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
		)
		if err == nil || !strings.Contains(err.Error(), "enters the replication scope") {
			t.Fatalf("move-in error = %v, want fail-closed refresh trigger", err)
		}
		assertSyncConsumerMissingEntry(
			t,
			store,
			database.partition,
			"uid=outside,ou=people,dc=example,dc=com",
		)
		if got := deltaCascadeAccesslogOperationCount(
			t,
			store,
			server.runtime.Load(),
			database,
			"uid=outside,ou=outside,dc=example,dc=com",
			"add",
		); got != 0 {
			t.Fatalf("move-in emitted %d synthetic adds before refresh", got)
		}
	})

	t.Run("move out of scope cascades as delete", func(t *testing.T) {
		server, store := newDeltaCascadeUnitServer(t)
		config, database := deltaCascadeUnitConfig(t, server, 1)
		setDeltaCascadePeopleScope(t, &config)
		const csn = "20260902010502.000001Z#000000#000#000000"
		moveOut := syncConsumerAccesslogTestEntry(
			"reqStart=20260902010502.000001Z,cn=log",
			"uid=alice,ou=people,dc=example,dc=com",
			"modrdn",
			csn,
			[]string{"entryCSN:= " + csn},
			map[string][]string{
				"reqNewRDN":       {"uid=alice"},
				"reqDeleteOldRDN": {"TRUE"},
				"reqNewSuperior":  {"ou=outside,dc=example,dc=com"},
			},
		)
		if err := server.applySyncConsumerAccesslogEntry(
			context.Background(), config, moveOut,
			composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
		); err != nil {
			t.Fatalf("apply move-out: %v", err)
		}
		assertSyncConsumerMissingEntry(
			t,
			store,
			database.partition,
			"uid=alice,ou=people,dc=example,dc=com",
		)
		if got := deltaCascadeAccesslogOperationCount(
			t,
			store,
			server.runtime.Load(),
			database,
			"uid=alice,ou=people,dc=example,dc=com",
			"delete",
		); got != 1 {
			t.Fatalf("move-out accesslog delete count = %d, want 1", got)
		}
		if got := deltaCascadeAccesslogOperationCount(
			t,
			store,
			server.runtime.Load(),
			database,
			"uid=alice,ou=people,dc=example,dc=com",
			"modrdn",
		); got != 0 {
			t.Fatalf("move-out retained %d misleading ModDN records", got)
		}
	})
}

func TestSyncConsumerAccesslogCascadePurgeRetainsGapBoundary(t *testing.T) {
	server, store := newDeltaCascadeUnitServer(t)
	config, database := deltaCascadeUnitConfig(t, server, 1)
	const (
		targetDN = "uid=purge-cascade,ou=people,dc=example,dc=com"
		csn      = "20260902010601.000001Z#000000#000#000000"
	)
	if err := server.applySyncConsumerAccesslogEntry(
		context.Background(),
		config,
		deltaCascadeAddEntry(targetDN, "Purge Cascade", csn),
		composeOpenLDAPSyncCookie(config.rid, syncCSNState{0: mustOpenLDAPCSN(t, csn)}),
	); err != nil {
		t.Fatalf("apply purge candidate: %v", err)
	}

	runtime := server.runtime.Load()
	database.accesslog.purgeAge = time.Hour
	target := runtime.databases[database.accesslog.targetDatabaseIndex]
	const oldStart = "20000101000000.000000Z"
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		content := writerForDatabase(writer, target)
		var record directory.Entry
		if err := content.ForEach(func(entry directory.Entry) error {
			if entry.HasValue("reqDN", []byte(targetDN)) &&
				entry.HasValue("reqType", []byte("add")) {
				record = entry
			}
			return nil
		}); err != nil {
			return err
		}
		if record.DN == "" {
			return errors.New("cascaded accesslog purge candidate is missing")
		}
		oldDN, err := syncConsumerParseDN(content, record.DN)
		if err != nil {
			return err
		}
		if err := content.Delete(oldDN); err != nil {
			return err
		}
		record.DN = "reqStart=" + oldStart + ",cn=log"
		record.ReplaceValues("reqStart", stringValues(oldStart))
		return content.Put(record, false)
	}); err != nil {
		t.Fatalf("age cascaded accesslog record: %v", err)
	}
	if err := server.purgeAccesslogDatabase(
		context.Background(), runtime, database, time.Now().UTC(),
	); err != nil {
		t.Fatalf("purge cascaded accesslog: %v", err)
	}

	if got := deltaCascadeAccesslogOperationCount(
		t, store, runtime, database, targetDN, "add",
	); got != 0 {
		t.Fatalf("purged cascade accesslog count = %d, want 0", got)
	}
	var minimum string
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		container, err := reader.GetIn(target.partition, database.accesslog.targetSuffix)
		if err != nil {
			return err
		}
		values := container.Values("minCSN")
		if len(values) != 1 {
			return fmt.Errorf("minCSN = %q", values)
		}
		minimum = string(values[0])
		return nil
	}); err != nil {
		t.Fatalf("read cascaded minCSN: %v", err)
	}
	if minimum != csn {
		t.Fatalf("cascaded minCSN = %q, want incoming %q", minimum, csn)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	connection := dialAndBindRawLDAP(
		t, address, syncTestRootDN, syncTestRootPassword,
	)
	defer connection.Close()
	stale := mustOpenLDAPCSN(
		t,
		"20000101000000.000000Z#000000#000#000000",
	)
	response := requestRawSyncRefresh(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"cn=log",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=auditWriteObject)",
		),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    composeOpenLDAPSyncCookie(0, syncCSNState{0: stale}),
			HasCookie: true,
		},
	)
	if response.resultCode != int64(ldapwire.ResultSyncRefreshRequired) ||
		response.done != nil || len(response.entries) != 0 {
		t.Fatalf("stale cascaded accesslog cookie response = %#v", response)
	}
}

func TestLDAPGoDeltaSyncreplCascadesThroughSingleProvider(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPGoAccesslogProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	relayStore := storage.NewMemory()
	t.Cleanup(func() { _ = relayStore.Close() })
	seedLDAPGoAccesslogProvider(t, relayStore)
	configureDeltaCascadeConsumer(t, relayStore, providerAddress, 1)
	relayAddress, stopRelay := startServer(t, relayStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopRelay()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedOpenLDAPAccesslogConsumer(t, consumerStore, relayAddress)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()

	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	relay := dialLDAPRoot(t, relayAddress)
	defer relay.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	if err := provider.Add(newAccesslogPersonAddRequest("cascade")); err != nil {
		t.Fatalf("provider add cascade: %v", err)
	}
	addCSN := ldapEntryAttribute(
		t,
		provider,
		"uid=cascade,ou=people,dc=example,dc=com",
		"entryCSN",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=cascade,ou=people,dc=example,dc=com",
		"uid",
		"cascade",
	)
	assertDeltaCascadeCSN(
		t,
		relay,
		consumer,
		"uid=cascade,ou=people,dc=example,dc=com",
		"add",
		addCSN,
	)

	modify := ldap.NewModifyRequest(
		"uid=cascade,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Cascade Updated"})
	if err := provider.Modify(modify); err != nil {
		t.Fatalf("provider modify cascade: %v", err)
	}
	modifyCSN := ldapEntryAttribute(
		t,
		provider,
		"uid=cascade,ou=people,dc=example,dc=com",
		"entryCSN",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=cascade,ou=people,dc=example,dc=com",
		"cn",
		"Cascade Updated",
	)
	assertDeltaCascadeCSN(
		t,
		relay,
		consumer,
		"uid=cascade,ou=people,dc=example,dc=com",
		"modify",
		modifyCSN,
	)

	rename := ldap.NewModifyDNRequest(
		"uid=cascade,ou=people,dc=example,dc=com",
		"uid=cascade-renamed",
		true,
		"",
	)
	if err := provider.ModifyDN(rename); err != nil {
		t.Fatalf("provider rename cascade: %v", err)
	}
	renameCSN := ldapEntryAttribute(
		t,
		provider,
		"uid=cascade-renamed,ou=people,dc=example,dc=com",
		"entryCSN",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=cascade-renamed,ou=people,dc=example,dc=com",
		"uid",
		"cascade-renamed",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=cascade,ou=people,dc=example,dc=com",
	)
	assertDeltaCascadeCSN(
		t,
		relay,
		consumer,
		"uid=cascade,ou=people,dc=example,dc=com",
		"modrdn",
		renameCSN,
	)

	if err := provider.Del(ldap.NewDelRequest(
		"uid=cascade-renamed,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("provider delete cascade: %v", err)
	}
	deleteCSN := waitForAccesslogOperationCSN(
		t,
		provider,
		"uid=cascade-renamed,ou=people,dc=example,dc=com",
		"delete",
		"",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=cascade-renamed,ou=people,dc=example,dc=com",
	)
	waitForAccesslogOperationCSN(
		t,
		relay,
		"uid=cascade-renamed,ou=people,dc=example,dc=com",
		"delete",
		deleteCSN,
	)
}

func TestLDAPGoDeltaSyncreplMoveIntoScopeRecoversByFallbackRefresh(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPGoAccesslogProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedLDAPGoAccesslogProvider(t, consumerStore)
	configureDeltaCascadeConsumerForBase(
		t,
		consumerStore,
		providerAddress,
		1,
		"ou=people,dc=example,dc=com",
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
	outside := ldap.NewAddRequest("ou=outside,dc=example,dc=com", nil)
	outside.Attribute("objectClass", []string{"top", "organizationalUnit"})
	outside.Attribute("ou", []string{"outside"})
	if err := provider.Add(outside); err != nil {
		t.Fatalf("provider add outside scope: %v", err)
	}
	const oldDN = "uid=scope-move,ou=outside,dc=example,dc=com"
	move := newAccesslogPersonAddRequest("scope-move")
	move.DN = oldDN
	if err := provider.Add(move); err != nil {
		t.Fatalf("provider add move-in candidate: %v", err)
	}
	outsideCSN := ldapEntryAttribute(t, provider, oldDN, "entryCSN")
	waitForDeltaCascadeCookie(
		t,
		consumerStore,
		configuredDatabasePartition("{1}mdb"),
		1,
		outsideCSN,
	)

	const newDN = "uid=scope-move,ou=people,dc=example,dc=com"
	if err := provider.ModifyDN(ldap.NewModifyDNRequest(
		oldDN,
		"uid=scope-move",
		true,
		"ou=people,dc=example,dc=com",
	)); err != nil {
		t.Fatalf("provider move entry into scope: %v", err)
	}
	moveCSN := ldapEntryAttribute(t, provider, newDN, "entryCSN")
	waitForSyncConsumerAttribute(t, consumer, newDN, "entryCSN", moveCSN)
	waitForSyncConsumerAttribute(t, consumer, newDN, "uid", "scope-move")
	waitForDeltaCascadeCookie(
		t,
		consumerStore,
		configuredDatabasePartition("{1}mdb"),
		1,
		moveCSN,
	)
}

func TestOpenLDAP2613DeltaSyncreplCascadesThroughSingleProvider(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	providerURI, stopProvider := startOpenLDAPAccesslogProvider(t, tools)
	defer stopProvider()
	provider, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatalf("dial OpenLDAP cascade provider: %v", err)
	}
	defer provider.Close()
	if err := provider.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("bind OpenLDAP cascade provider: %v", err)
	}
	seedOpenLDAPAccesslogData(t, provider)

	relayOptions := fmt.Sprintf(
		`syncrepl rid=002 provider=%s`+
			` bindmethod=simple binddn="%s" credentials="%s"`+
			` searchbase="dc=example,dc=com"`+
			` filter="(objectClass=*)" scope=sub attrs="*,+"`+
			` logbase="cn=log"`+
			` logfilter="(&(objectClass=auditWriteObject)(reqResult=0))"`+
			` syncdata=accesslog schemachecking=off`+
			` type=refreshAndPersist retry="1 +"`+"\n"+
			`updateref %s`,
		providerURI,
		syncTestRootDN,
		syncTestRootPassword,
		providerURI,
	)
	relayURI, stopRelay := startOpenLDAPAccesslogProviderWithOptions(
		t, tools, relayOptions,
	)
	defer stopRelay()
	relay, err := ldap.DialURL(relayURI)
	if err != nil {
		t.Fatalf("dial OpenLDAP cascade relay: %v", err)
	}
	defer relay.Close()
	if err := relay.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("bind OpenLDAP cascade relay: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		relay,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice",
	)

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedOpenLDAPAccesslogConsumer(
		t,
		consumerStore,
		strings.TrimPrefix(relayURI, "ldap://"),
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
		"Alice",
	)

	const addDN = "uid=openldap-cascade,ou=people,dc=example,dc=com"
	if err := provider.Add(newAccesslogPersonAddRequest("openldap-cascade")); err != nil {
		t.Fatalf("OpenLDAP provider add cascade entry: %v", err)
	}
	addCSN := ldapEntryAttribute(t, provider, addDN, "entryCSN")
	waitForSyncConsumerAttribute(t, consumer, addDN, "entryCSN", addCSN)
	waitForAccesslogOperationCSN(t, relay, addDN, "add", addCSN)

	modify := ldap.NewModifyRequest(addDN, nil)
	modify.Replace("cn", []string{"OpenLDAP Cascade Updated"})
	if err := provider.Modify(modify); err != nil {
		t.Fatalf("OpenLDAP provider modify cascade entry: %v", err)
	}
	modifyCSN := ldapEntryAttribute(t, provider, addDN, "entryCSN")
	waitForSyncConsumerAttribute(t, consumer, addDN, "entryCSN", modifyCSN)
	waitForSyncConsumerAttribute(
		t, consumer, addDN, "cn", "OpenLDAP Cascade Updated",
	)
	waitForAccesslogOperationCSN(t, relay, addDN, "modify", modifyCSN)

	const renamedDN = "uid=openldap-cascade-renamed,ou=people,dc=example,dc=com"
	if err := provider.ModifyDN(ldap.NewModifyDNRequest(
		addDN,
		"uid=openldap-cascade-renamed",
		true,
		"",
	)); err != nil {
		t.Fatalf("OpenLDAP provider rename cascade entry: %v", err)
	}
	renameCSN := ldapEntryAttribute(t, provider, renamedDN, "entryCSN")
	waitForSyncConsumerAttribute(t, consumer, renamedDN, "entryCSN", renameCSN)
	waitForSyncConsumerMissing(t, consumer, addDN)
	waitForAccesslogOperationCSN(t, relay, addDN, "modrdn", renameCSN)

	if err := provider.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("OpenLDAP provider delete cascade entry: %v", err)
	}
	deleteCSN := waitForAccesslogOperationCSN(
		t, provider, renamedDN, "delete", "",
	)
	waitForSyncConsumerMissing(t, consumer, renamedDN)
	waitForAccesslogOperationCSN(t, relay, renamedDN, "delete", deleteCSN)
}

func assertDeltaCascadeCSN(
	t *testing.T,
	relay,
	consumer *ldap.Conn,
	requestDN,
	requestType,
	want string,
) {
	t.Helper()
	entryDN := requestDN
	if requestType == "modrdn" {
		entryDN = "uid=cascade-renamed,ou=people,dc=example,dc=com"
	}
	waitForSyncConsumerAttribute(t, relay, entryDN, "entryCSN", want)
	waitForSyncConsumerAttribute(t, consumer, entryDN, "entryCSN", want)
	waitForAccesslogOperationCSN(t, relay, requestDN, requestType, want)
}

func ldapEntryAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	description string,
) string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{description},
		nil,
	))
	if err != nil {
		t.Fatalf("read %s %s: %v", dn, description, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("read %s returned %d entries", dn, len(result.Entries))
	}
	value := result.Entries[0].GetAttributeValue(description)
	if value == "" {
		t.Fatalf("%s has no %s", dn, description)
	}
	return value
}

func waitForAccesslogOperationCSN(
	t *testing.T,
	client *ldap.Conn,
	requestDN,
	requestType,
	want string,
) string {
	t.Helper()
	filter := fmt.Sprintf(
		"(&(reqDN=%s)(reqType=%s))",
		ldap.EscapeFilter(requestDN),
		ldap.EscapeFilter(requestType),
	)
	deadline := time.Now().Add(syncConsumerWaitTimeout())
	var observed []string
	for time.Now().Before(deadline) {
		result, err := client.Search(ldap.NewSearchRequest(
			"cn=log",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"entryCSN"},
			nil,
		))
		if err == nil {
			observed = observed[:0]
			for _, entry := range result.Entries {
				csn := entry.GetAttributeValue("entryCSN")
				observed = append(observed, csn)
				if csn != "" && (want == "" || csn == want) {
					return csn
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf(
		"accesslog %s %s entryCSN = %q, want %q",
		requestType,
		requestDN,
		observed,
		want,
	)
	return ""
}

func configureDeltaCascadeConsumer(
	t *testing.T,
	store storage.Store,
	providerAddress string,
	rid int,
) {
	configureDeltaCascadeConsumerForBase(
		t,
		store,
		providerAddress,
		rid,
		"dc=example,dc=com",
	)
}

func configureDeltaCascadeConsumerForBase(
	t *testing.T,
	store storage.Store,
	providerAddress string,
	rid int,
	searchBase string,
) {
	t.Helper()
	dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatalf("parse cascade database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSyncrepl", stringValues(
			`{0}rid=`+fmt.Sprintf("%03d", rid)+
				` provider=ldap://`+providerAddress+
				` bindmethod=simple binddn="`+syncTestRootDN+
				`" credentials="`+syncTestRootPassword+
				`" searchbase="`+searchBase+`"`+
				` filter="(objectClass=*)" scope=sub attrs="*,+"`+
				` logbase="cn=log"`+
				` logfilter="(&(objectClass=auditWriteObject)(reqResult=0))"`+
				` syncdata=accesslog schemachecking=off`+
				` type=refreshAndPersist retry="1 +"`,
		))
		entry.ReplaceValues(
			"olcUpdateRef",
			stringValues("ldap://"+providerAddress),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure cascade consumer: %v", err)
	}
}

func waitForDeltaCascadeCookie(
	t *testing.T,
	store storage.Store,
	partition string,
	rid int,
	wantRaw string,
) {
	t.Helper()
	want := mustOpenLDAPCSN(t, wantRaw)
	config := syncConsumerConfig{partition: partition, rid: rid}
	deadline := time.Now().Add(syncConsumerWaitTimeout())
	var observed string
	for time.Now().Before(deadline) {
		reached := false
		_ = store.View(context.Background(), func(reader storage.Reader) error {
			raw, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
			if err != nil {
				return err
			}
			current, found := parseOpenLDAPSyncCookie(raw).csns[want.serverID]
			if found {
				observed = current.raw
				if compareOpenLDAPCSN(current, want) >= 0 {
					reached = true
				}
			}
			return nil
		})
		if reached {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("delta cascade cookie = %q, want at least %q", observed, wantRaw)
}

func newDeltaCascadeUnitServer(
	t *testing.T,
) (*Server, storage.Store) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)
	server, err := New(Config{
		Store:        store,
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return server, store
}

func deltaCascadeUnitConfig(
	t *testing.T,
	server *Server,
	rid int,
) (syncConsumerConfig, runtimeDatabase) {
	t.Helper()
	runtime := server.runtime.Load()
	for index := range runtime.databases {
		database := runtime.databases[index]
		if database.accesslog == nil ||
			len(database.suffixes) != 1 ||
			database.suffixes[0].String() != "dc=example,dc=com" {
			continue
		}
		config, err := parseSyncConsumerConfigWithNormalizer(
			fmt.Sprintf(
				`rid=%03d provider=ldap://provider `+
					`searchbase="dc=example,dc=com" `+
					`logbase="cn=log" `+
					`logfilter="(&(objectClass=auditWriteObject)(reqResult=0))" `+
					`syncdata=accesslog type=refreshAndPersist`,
				rid,
			),
			database.partition,
			database.suffixes,
			database.dnNormalizer,
		)
		if err != nil {
			t.Fatalf("parse unit cascade config: %v", err)
		}
		return config, database
	}
	t.Fatal("cascade source database is missing")
	return syncConsumerConfig{}, runtimeDatabase{}
}

func setDeltaCascadePeopleScope(t *testing.T, config *syncConsumerConfig) {
	t.Helper()
	base, err := parseRuntimeDN(
		"ou=people,dc=example,dc=com",
		config.normalizer,
	)
	if err != nil {
		t.Fatalf("parse cascade people scope: %v", err)
	}
	config.searchBase = base
	config.localBase = base
	config.scope = directory.ScopeWholeSubtree
}

func deltaCascadeAddEntry(
	targetDN,
	commonName,
	csn string,
) *ldap.Entry {
	return syncConsumerAccesslogTestEntry(
		"reqStart="+strings.ReplaceAll(csn[:22], ".", "")+",cn=log",
		targetDN,
		"add",
		csn,
		[]string{
			"objectClass:+ top",
			"objectClass:+ person",
			"objectClass:+ organizationalPerson",
			"objectClass:+ inetOrgPerson",
			"uid:+ " + strings.TrimPrefix(strings.SplitN(targetDN, ",", 2)[0], "uid="),
			"cn:+ " + commonName,
			"sn:+ Example",
			"entryUUID:+ 10000000-0000-4000-8000-000000000001",
			"entryCSN:+ " + csn,
		},
		nil,
	)
}

func mustOpenLDAPCSN(t *testing.T, raw string) openLDAPCSN {
	t.Helper()
	csn, err := parseOpenLDAPCSN(raw)
	if err != nil {
		t.Fatalf("parse CSN %q: %v", raw, err)
	}
	return csn
}

func deltaCascadeAccesslogOperationCount(
	t *testing.T,
	store storage.Store,
	runtime *runtimeState,
	database runtimeDatabase,
	requestDN,
	requestType string,
) int {
	t.Helper()
	if database.accesslog == nil ||
		database.accesslog.targetDatabaseIndex < 0 ||
		database.accesslog.targetDatabaseIndex >= len(runtime.databases) {
		t.Fatal("cascade accesslog target is unresolved")
	}
	target := runtime.databases[database.accesslog.targetDatabaseIndex]
	count := 0
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return reader.ForEachIn(target.partition, func(entry directory.Entry) error {
			if entry.HasValue("reqDN", []byte(requestDN)) &&
				entry.HasValue("reqType", []byte(requestType)) {
				count++
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("count cascade accesslog records: %v", err)
	}
	return count
}
