package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDeltaMultiProviderBootstrapRetriesInterruptedRefreshAfterRestart(
	t *testing.T,
) {
	path := filepath.Join(t.TempDir(), "bootstrap.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	instance := newDeltaMPRServerWithStore(t, store, 10)
	config, database := deltaCascadeUnitConfig(t, instance, 1)
	clearDeltaBootstrapContent(t, store, database, config)
	config.mode = syncConsumerRefreshOnly
	config.bindDN = syncTestRootDN
	config.credentials = []byte(syncTestRootPassword)
	config.credentialsSet = true
	config.operationTimeout = 5 * time.Second

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	providerDone := make(chan error, 1)
	go func() {
		providerDone <- serveDeltaBootstrapProvider(listener)
	}()
	t.Cleanup(func() { _ = listener.Close() })
	providerURL := "ldap://" + listener.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = instance.runSyncConsumerCycle(ctx, config, providerURL)
	cancel()
	if err == nil {
		t.Fatal("interrupted bootstrap refresh succeeded")
	}
	assertSyncConsumerEntryValues(
		t,
		store,
		database.partition,
		"uid=newer,ou=people,dc=example,dc=com",
		"uid",
		[]string{"newer"},
	)
	assertSyncConsumerMissingEntry(
		t,
		store,
		database.partition,
		"uid=older,ou=people,dc=example,dc=com",
	)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		state, err := syncContextCSNs(reader, database.partition)
		if err != nil {
			return err
		}
		if got := state[1].raw; got !=
			"20260908030102.000001Z#000000#001#000000" {
			return fmt.Errorf("partial SID 1 contextCSN = %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertDeltaBootstrapState(t, store, config, false, false)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		state, err := syncConsumerAccesslogBootstrapStateReader(reader, config)
		if err != nil {
			return err
		}
		if state.status != syncConsumerAccesslogBootstrapInProgress ||
			!state.identityMatches {
			return fmt.Errorf("bootstrap state after interruption = %+v", state)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if cookie, err := instance.syncConsumerDeltaInitialCookie(
		context.Background(),
		config,
	); err != nil || len(cookie) != 0 {
		t.Fatalf("cookie synthesized after interrupted bootstrap = %q, %v", cookie, err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	instance, err = New(Config{
		Store:        store,
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	config, database = deltaCascadeUnitConfig(t, instance, 1)
	config.mode = syncConsumerRefreshOnly
	config.bindDN = syncTestRootDN
	config.credentials = []byte(syncTestRootPassword)
	config.credentialsSet = true
	config.operationTimeout = 5 * time.Second

	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	err = instance.runSyncConsumerCycle(ctx, config, providerURL)
	cancel()
	if err != nil {
		t.Fatalf("retry bootstrap refresh: %v", err)
	}
	if err := <-providerDone; err != nil {
		t.Fatalf("bootstrap provider: %v", err)
	}
	for _, uid := range []string{"newer", "older"} {
		assertSyncConsumerEntryValues(
			t,
			store,
			database.partition,
			"uid="+uid+",ou=people,dc=example,dc=com",
			"uid",
			[]string{uid},
		)
	}
	assertDeltaBootstrapState(t, store, config, true, true)

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	instance, err = New(Config{
		Store:        store,
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	config, _ = deltaCascadeUnitConfig(t, instance, 1)
	config.mode = syncConsumerRefreshOnly
	config.bindDN = syncTestRootDN
	config.credentials = []byte(syncTestRootPassword)
	config.credentialsSet = true
	config.operationTimeout = 5 * time.Second
	complete, err := instance.syncConsumerAccesslogBootstrapComplete(
		context.Background(),
		config,
	)
	if err != nil || !complete {
		t.Fatalf("persisted bootstrap completion = %v, %v", complete, err)
	}
	if cookie, err := instance.syncConsumerDeltaInitialCookie(
		context.Background(),
		config,
	); err != nil || len(cookie) == 0 {
		t.Fatalf("cookie after completed bootstrap = %q, %v", cookie, err)
	}
}

func clearDeltaBootstrapContent(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	config syncConsumerConfig,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		content := writerForDatabase(writer, database)
		var dns []directory.DN
		if err := content.ForEach(func(entry directory.Entry) error {
			dn, err := syncConsumerParseDN(content, entry.DN)
			if err != nil {
				return err
			}
			dns = append(dns, dn)
			return nil
		}); err != nil {
			return err
		}
		for _, dn := range dns {
			if err := content.Delete(dn); err != nil {
				return err
			}
		}
		for _, key := range []string{
			syncContextCSNMetadataKey(database.partition),
			syncConsumerCookieMetadataKey(config),
			syncConsumerAccesslogBootstrapMetadataKey(config),
		} {
			if err := deleteSyncConsumerMetadata(writer, key); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("clear bootstrap content: %v", err)
	}
}

func serveDeltaBootstrapProvider(listener net.Listener) error {
	root := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "domain")},
			{Description: "dc", Values: stringValues("example")},
			{Description: "entryCSN", Values: stringValues("20260908030100.000001Z#000000#001#000000")},
		},
	}
	people := directory.Entry{
		DN: "ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "organizationalUnit")},
			{Description: "ou", Values: stringValues("people")},
			{Description: "entryCSN", Values: stringValues("20260908030100.000002Z#000000#001#000000")},
		},
	}
	newer := deltaBootstrapEntry(
		"newer",
		"20260908030102.000001Z#000000#001#000000",
	)
	older := deltaBootstrapEntry(
		"older",
		"20260908030101.000001Z#000000#001#000000",
	)
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			_ = connection.Close()
			return err
		}
		if err := serveDeltaBootstrapConnection(
			connection,
			attempt,
			[]directory.Entry{root, people},
			newer,
			older,
		); err != nil {
			_ = connection.Close()
			return err
		}
		_ = connection.Close()
	}
	return nil
}

func serveDeltaBootstrapConnection(
	connection net.Conn,
	attempt int,
	parents []directory.Entry,
	newer,
	older directory.Entry,
) error {
	bind, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return err
	}
	if _, ok := bind.Request.(ldapwire.BindRequest); !ok {
		return fmt.Errorf("bootstrap request = %T, want Bind", bind.Request)
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		bind.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		return err
	}
	search, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return err
	}
	request, ok := search.Request.(ldapwire.SearchRequest)
	if !ok || request.BaseDN != "dc=example,dc=com" {
		return fmt.Errorf("attempt %d first search = %#v, want standard refresh", attempt+1, search.Request)
	}
	syncRequest, err := deltaBootstrapSyncRequest(search.Controls)
	if err != nil {
		return err
	}
	if syncRequest.HasCookie || len(syncRequest.Cookie) != 0 {
		return fmt.Errorf("attempt %d standard refresh cookie = %q, want empty", attempt+1, syncRequest.Cookie)
	}
	for _, entry := range parents {
		if err := writeDeltaBootstrapEntry(connection, search.ID, entry); err != nil {
			return err
		}
	}
	if err := writeDeltaBootstrapEntry(connection, search.ID, newer); err != nil {
		return err
	}
	if attempt == 0 {
		return nil
	}
	if err := writeDeltaBootstrapEntry(connection, search.ID, older); err != nil {
		return err
	}
	finalCookie := []byte(
		"rid=001,csn=20260908030102.000001Z#000000#001#000000",
	)
	if err := writeDeltaBootstrapDone(connection, search.ID, finalCookie); err != nil {
		return err
	}

	accesslog, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return err
	}
	request, ok = accesslog.Request.(ldapwire.SearchRequest)
	if !ok || request.BaseDN != "cn=log" {
		return fmt.Errorf("post-bootstrap search = %#v, want accesslog", accesslog.Request)
	}
	syncRequest, err = deltaBootstrapSyncRequest(accesslog.Controls)
	if err != nil {
		return err
	}
	if !syncRequest.HasCookie || !bytes.Equal(syncRequest.Cookie, finalCookie) {
		return fmt.Errorf("accesslog cookie = %q, want %q", syncRequest.Cookie, finalCookie)
	}
	return writeDeltaBootstrapDone(connection, accesslog.ID, finalCookie)
}

func deltaBootstrapEntry(uid, csn string) directory.Entry {
	return directory.Entry{
		DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "person", "organizationalPerson", "inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(uid)},
			{Description: "sn", Values: stringValues("Example")},
			{Description: "entryCSN", Values: stringValues(csn)},
		},
	}
}

func writeDeltaBootstrapEntry(
	connection net.Conn,
	messageID int64,
	entry directory.Entry,
) error {
	identifier := uuid.NewSHA1(uuid.NameSpaceOID, []byte(entry.DN))
	var syncIdentifier ldapwire.SyncUUID
	copy(syncIdentifier[:], identifier[:])
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(
		messageID,
		entry,
		[]ldapwire.Control{{
			OID: syncStateControlOID,
			Value: ldapwire.EncodeSyncStateValue(ldapwire.SyncStateValue{
				State:     ldapwire.SyncStateAdd,
				EntryUUID: syncIdentifier,
			}),
			HasValue: true,
		}},
	))
}

func writeDeltaBootstrapDone(
	connection net.Conn,
	messageID int64,
	cookie []byte,
) error {
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		[]ldapwire.Control{{
			OID: syncDoneControlOID,
			Value: ldapwire.EncodeSyncDoneValue(ldapwire.SyncDoneValue{
				Cookie:         cookie,
				HasCookie:      true,
				RefreshDeletes: true,
			}),
			HasValue: true,
		}},
	))
}

func deltaBootstrapSyncRequest(
	controls []ldapwire.Control,
) (ldapwire.SyncRequestValue, error) {
	for _, control := range controls {
		if control.OID == syncRequestControlOID {
			return ldapwire.DecodeSyncRequestValue(control.Value)
		}
	}
	return ldapwire.SyncRequestValue{}, errors.New("request has no Sync control")
}

func assertDeltaBootstrapState(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	wantComplete,
	wantCookie bool,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		complete, err := syncConsumerAccesslogBootstrapCompleteReader(reader, config)
		if err != nil {
			return err
		}
		if complete != wantComplete {
			return fmt.Errorf("bootstrap complete = %v, want %v", complete, wantComplete)
		}
		_, err = reader.Metadata(syncConsumerCookieMetadataKey(config))
		hasCookie := err == nil
		if err != nil && !errors.Is(err, storage.ErrMetadataNotFound) {
			return err
		}
		if hasCookie != wantCookie {
			return fmt.Errorf("cookie present = %v, want %v", hasCookie, wantCookie)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

var errDeltaBootstrapMarker = errors.New("fail bootstrap marker")

type deltaBootstrapFailingStore struct {
	storage.Store
}

func (store deltaBootstrapFailingStore) Update(
	ctx context.Context,
	fn func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return fn(deltaBootstrapFailingWriter{Writer: writer})
	})
}

type deltaBootstrapFailingWriter struct {
	storage.Writer
}

func (writer deltaBootstrapFailingWriter) SetMetadata(
	key string,
	value []byte,
) error {
	if len(key) >= len(syncConsumerAccesslogBootstrapMetadataPrefix) &&
		key[:len(syncConsumerAccesslogBootstrapMetadataPrefix)] ==
			syncConsumerAccesslogBootstrapMetadataPrefix {
		return errDeltaBootstrapMarker
	}
	return writer.Writer.SetMetadata(key, value)
}

func TestDeltaMultiProviderBootstrapCompletionAndCookieAreAtomic(t *testing.T) {
	instance, store := newDeltaMPRServer(t, "memory", 10)
	config, _ := deltaCascadeUnitConfig(t, instance, 1)
	instance.config.Store = deltaBootstrapFailingStore{Store: store}
	err := instance.finishSyncConsumerRefresh(
		context.Background(),
		config,
		&syncConsumerRefreshState{seen: make(map[string]struct{})},
		true,
		[]byte("rid=001,csn=20260908030201.000001Z#000000#001#000000"),
	)
	if !errors.Is(err, errDeltaBootstrapMarker) {
		t.Fatalf("finish refresh error = %v, want marker failure", err)
	}
	assertDeltaBootstrapState(t, store, config, false, false)
}

func TestDeltaMultiProviderBootstrapResetAndIdentityChangeAreAtomic(t *testing.T) {
	for _, test := range []struct {
		name         string
		mutate       func(*syncConsumerConfig)
		reset        bool
		wantComplete bool
		wantCookie   bool
	}{
		{
			name:  "gap reset",
			reset: true,
		},
		{
			name: "search identity change adopts local history",
			mutate: func(config *syncConsumerConfig) {
				config.filterText = "(uid=alice)"
			},
			wantComplete: true,
		},
		{
			name: "provider URI change preserves state",
			mutate: func(config *syncConsumerConfig) {
				config.providerURLs = []string{"ldap://replacement"}
			},
			wantComplete: true,
			wantCookie:   true,
		},
		{
			name: "database identity change adopts local history",
			mutate: func(config *syncConsumerConfig) {
				config.databaseID += "\x00entryUUID=changed"
			},
			wantComplete: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, store := newDeltaMPRServer(t, "memory", 10)
			config, _ := deltaCascadeUnitConfig(t, instance, 1)
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if err := writer.SetMetadata(
					syncConsumerCookieMetadataKey(config),
					[]byte("rid=001,csn=20260908030301.000001Z#000000#001#000000"),
				); err != nil {
					return err
				}
				return writer.SetMetadata(
					syncConsumerAccesslogBootstrapMetadataKey(config),
					syncConsumerAccesslogBootstrapValue(
						syncConsumerAccesslogBootstrapComplete,
						config,
					),
				)
			}); err != nil {
				t.Fatal(err)
			}
			activeConfig := config
			if test.mutate != nil {
				test.mutate(&activeConfig)
			}
			complete := false
			var err error
			if test.reset {
				err = instance.resetSyncConsumerCookie(
					context.Background(),
					activeConfig,
				)
			} else {
				complete, err = instance.prepareSyncConsumerAccesslogBootstrap(
					context.Background(),
					activeConfig,
				)
			}
			if err != nil {
				t.Fatal(err)
			}
			if complete != test.wantComplete {
				t.Fatalf("bootstrap complete = %v, want %v", complete, test.wantComplete)
			}
			assertDeltaBootstrapState(
				t,
				store,
				activeConfig,
				test.wantComplete,
				test.wantCookie,
			)
		})
	}
}
