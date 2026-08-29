package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncreplTwoNodeSingleWriterHAFailureMatrix(t *testing.T) {
	t.Run("provider pause and recovery converges latest state", func(t *testing.T) {
		providerStore := storage.NewMemory()
		defer providerStore.Close()
		seedSyncProviderDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopProvider()

		gate := startSyncreplHAGate(t, providerAddress)
		defer gate.stop()
		consumerStore := storage.NewMemory()
		defer consumerStore.Close()
		seedSyncConsumerDatabase(
			t,
			consumerStore,
			gate.address(),
			syncTestRootPassword,
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

		// A consumer is read-only in this topology, including for its root DN.
		assertLDAPReferral(
			t,
			consumer.Add(newPersonAddRequest("consumer-write")),
			"",
			"ldap://"+gate.address()+
				"/uid=consumer-write,ou=people,dc=example,dc=com",
		)

		provider := dialLDAPRoot(t, providerAddress)
		defer provider.Close()
		gate.pause()

		modifySyncreplHACN(t, provider, "alice", "Alice Outage Candidate")
		modifySyncreplHACN(t, provider, "alice", "Alice Recovery Winner")
		if err := provider.Add(newPersonAddRequest("bob")); err != nil {
			t.Fatalf("provider Add(bob): %v", err)
		}
		if err := provider.Add(newPersonAddRequest("transient")); err != nil {
			t.Fatalf("provider Add(transient): %v", err)
		}
		if err := provider.Del(ldap.NewDelRequest(
			"uid=transient,ou=people,dc=example,dc=com",
			nil,
		)); err != nil {
			t.Fatalf("provider Delete(transient): %v", err)
		}
		if err := provider.Del(ldap.NewDelRequest(
			"ou=archive,dc=example,dc=com",
			nil,
		)); err != nil {
			t.Fatalf("provider Delete(archive): %v", err)
		}

		assertSyncConsumerLDAPAttribute(
			t,
			consumer,
			"uid=alice,ou=people,dc=example,dc=com",
			"cn",
			"Alice Example",
		)
		assertSyncreplHAEntryMissing(
			t,
			consumer,
			"uid=bob,ou=people,dc=example,dc=com",
		)

		gate.resume()
		waitForSyncConsumerAttribute(
			t,
			consumer,
			"uid=alice,ou=people,dc=example,dc=com",
			"cn",
			"Alice Recovery Winner",
		)
		waitForSyncConsumerAttribute(
			t,
			consumer,
			"uid=bob,ou=people,dc=example,dc=com",
			"uid",
			"bob",
		)
		waitForSyncConsumerMissing(
			t,
			consumer,
			"uid=transient,ou=people,dc=example,dc=com",
		)
		waitForSyncConsumerMissing(
			t,
			consumer,
			"ou=archive,dc=example,dc=com",
		)
		assertSyncreplHAEntryMissing(
			t,
			provider,
			"uid=consumer-write,ou=people,dc=example,dc=com",
		)
	})

	t.Run("consumer restart resumes cookie and duplicate replay is idempotent", func(t *testing.T) {
		providerStore := storage.NewMemory()
		defer providerStore.Close()
		seedSyncProviderDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopProvider()
		provider := dialLDAPRoot(t, providerAddress)
		defer provider.Close()

		consumerStore := storage.NewMemory()
		defer consumerStore.Close()
		seedSyncConsumerDatabase(
			t,
			consumerStore,
			providerAddress,
			syncTestRootPassword,
		)
		consumerConfig := syncConsumerConfig{
			rid:       1,
			partition: storage.OpenLDAPDatabasePartition("{1}mdb", nil),
		}

		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		consumer := dialLDAPRoot(t, consumerAddress)
		waitForSyncConsumerAttribute(
			t,
			consumer,
			"uid=alice,ou=people,dc=example,dc=com",
			"cn",
			"Alice Example",
		)
		initialCookie := waitForSyncreplHACookie(
			t,
			consumerStore,
			consumerConfig,
		)
		consumer.Close()
		stopConsumer()

		modifySyncreplHACN(t, provider, "alice", "Alice Restart Candidate")
		modifySyncreplHACN(t, provider, "alice", "Alice Restart Winner")
		if err := provider.Add(newPersonAddRequest("bob")); err != nil {
			t.Fatalf("provider Add(bob): %v", err)
		}
		if err := provider.Add(newPersonAddRequest("transient")); err != nil {
			t.Fatalf("provider Add(transient): %v", err)
		}
		if err := provider.Del(ldap.NewDelRequest(
			"uid=transient,ou=people,dc=example,dc=com",
			nil,
		)); err != nil {
			t.Fatalf("provider Delete(transient): %v", err)
		}
		if err := provider.Del(ldap.NewDelRequest(
			"ou=archive,dc=example,dc=com",
			nil,
		)); err != nil {
			t.Fatalf("provider Delete(archive): %v", err)
		}

		consumerAddress, stopConsumer = startServer(t, consumerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		consumer = dialLDAPRoot(t, consumerAddress)
		waitForSyncConsumerAttribute(
			t,
			consumer,
			"uid=alice,ou=people,dc=example,dc=com",
			"cn",
			"Alice Restart Winner",
		)
		waitForSyncConsumerAttribute(
			t,
			consumer,
			"uid=bob,ou=people,dc=example,dc=com",
			"uid",
			"bob",
		)
		waitForSyncConsumerMissing(
			t,
			consumer,
			"uid=transient,ou=people,dc=example,dc=com",
		)
		waitForSyncConsumerMissing(
			t,
			consumer,
			"ou=archive,dc=example,dc=com",
		)
		latestCookie := waitForSyncreplHACookieAdvance(
			t,
			consumerStore,
			consumerConfig,
			initialCookie,
		)
		consumer.Close()
		stopConsumer()

		// Roll back only the checkpoint. The next refresh must safely replay
		// changes over an already-current local database.
		if err := consumerStore.Update(context.Background(), func(writer storage.Writer) error {
			return writer.SetMetadata(
				syncConsumerCookieMetadataKey(consumerConfig),
				initialCookie,
			)
		}); err != nil {
			t.Fatalf("restore stale consumer cookie: %v", err)
		}

		consumerAddress, stopConsumer = startServer(t, consumerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopConsumer()
		consumer = dialLDAPRoot(t, consumerAddress)
		defer consumer.Close()
		waitForSyncreplHACookieCoverage(
			t,
			consumerStore,
			consumerConfig,
			latestCookie,
		)
		assertSyncConsumerLDAPAttribute(
			t,
			consumer,
			"uid=alice,ou=people,dc=example,dc=com",
			"cn",
			"Alice Restart Winner",
		)
		assertSyncreplHAEntryCount(
			t,
			consumer,
			"(uid=bob)",
			1,
		)
		assertSyncreplHAEntryMissing(
			t,
			consumer,
			"uid=transient,ou=people,dc=example,dc=com",
		)
		assertSyncreplHAEntryMissing(
			t,
			consumer,
			"ou=archive,dc=example,dc=com",
		)
	})
}

func modifySyncreplHACN(
	t *testing.T,
	client *ldap.Conn,
	uid,
	commonName string,
) {
	t.Helper()
	request := ldap.NewModifyRequest(
		"uid="+uid+",ou=people,dc=example,dc=com",
		nil,
	)
	request.Replace("cn", []string{commonName})
	if err := client.Modify(request); err != nil {
		t.Fatalf("provider Modify(%s): %v", uid, err)
	}
}

func assertSyncreplHAEntryMissing(
	t *testing.T,
	client *ldap.Conn,
	dn string,
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
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) &&
			ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
			return
		}
		t.Fatalf("Search missing %s: %v", dn, err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("Search missing %s returned %d entries", dn, len(result.Entries))
	}
}

func assertSyncreplHAEntryCount(
	t *testing.T,
	client *ldap.Conn,
	filter string,
	want int,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%s): %v", filter, err)
	}
	if len(result.Entries) != want {
		t.Fatalf("Search(%s) returned %d entries, want %d", filter, len(result.Entries), want)
	}
}

func waitForSyncreplHACookie(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
) []byte {
	t.Helper()
	deadline := time.Now().Add(syncConsumerWaitTimeout())
	var (
		cookie  []byte
		lastErr error
	)
	for time.Now().Before(deadline) {
		lastErr = store.View(context.Background(), func(reader storage.Reader) error {
			var err error
			cookie, err = reader.Metadata(syncConsumerCookieMetadataKey(config))
			return err
		})
		if lastErr == nil && len(cookie) != 0 {
			return bytes.Clone(cookie)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer cookie was not stored: %v", lastErr)
	return nil
}

func waitForSyncreplHACookieAdvance(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	previous []byte,
) []byte {
	t.Helper()
	deadline := time.Now().Add(syncConsumerWaitTimeout())
	var current []byte
	for time.Now().Before(deadline) {
		current = waitForSyncreplHACookie(t, store, config)
		if syncreplHACookieStrictlyAdvances(previous, current) {
			return current
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer cookie %q did not advance beyond %q", current, previous)
	return nil
}

func waitForSyncreplHACookieCoverage(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	want []byte,
) {
	t.Helper()
	deadline := time.Now().Add(syncConsumerWaitTimeout())
	var current []byte
	for time.Now().Before(deadline) {
		current = waitForSyncreplHACookie(t, store, config)
		if syncreplHACookieCovers(current, want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer cookie %q does not cover %q", current, want)
}

func syncreplHACookieStrictlyAdvances(previous, current []byte) bool {
	before := parseOpenLDAPSyncCookie(previous).csns
	after := parseOpenLDAPSyncCookie(current).csns
	advanced := false
	for serverID, beforeCSN := range before {
		afterCSN, exists := after[serverID]
		if !exists || compareOpenLDAPCSN(afterCSN, beforeCSN) < 0 {
			return false
		}
		if compareOpenLDAPCSN(afterCSN, beforeCSN) > 0 {
			advanced = true
		}
	}
	return advanced || len(after) > len(before)
}

func syncreplHACookieCovers(current, want []byte) bool {
	currentState := parseOpenLDAPSyncCookie(current).csns
	for serverID, wantCSN := range parseOpenLDAPSyncCookie(want).csns {
		currentCSN, exists := currentState[serverID]
		if !exists || compareOpenLDAPCSN(currentCSN, wantCSN) < 0 {
			return false
		}
	}
	return true
}

type syncreplHAGate struct {
	listener net.Listener
	upstream string

	mu          sync.Mutex
	paused      bool
	stopped     bool
	connections map[net.Conn]struct{}
	wait        sync.WaitGroup
	stopOnce    sync.Once
}

func startSyncreplHAGate(t *testing.T, upstream string) *syncreplHAGate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(HA gate): %v", err)
	}
	gate := &syncreplHAGate{
		listener:    listener,
		upstream:    upstream,
		connections: make(map[net.Conn]struct{}),
	}
	gate.wait.Add(1)
	go gate.serve()
	return gate
}

func (gate *syncreplHAGate) address() string {
	return gate.listener.Addr().String()
}

func (gate *syncreplHAGate) serve() {
	defer gate.wait.Done()
	for {
		connection, err := gate.listener.Accept()
		if err != nil {
			return
		}
		if !gate.register(connection) {
			_ = connection.Close()
			continue
		}
		gate.wait.Add(1)
		go gate.forward(connection)
	}
}

func (gate *syncreplHAGate) forward(downstream net.Conn) {
	defer gate.wait.Done()
	defer gate.unregister(downstream)
	defer downstream.Close()

	upstream, err := net.DialTimeout("tcp", gate.upstream, time.Second)
	if err != nil {
		return
	}
	if !gate.register(upstream) {
		_ = upstream.Close()
		return
	}
	defer gate.unregister(upstream)
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, downstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(downstream, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = downstream.Close()
	_ = upstream.Close()
	<-done
}

func (gate *syncreplHAGate) register(connection net.Conn) bool {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.paused || gate.stopped {
		return false
	}
	gate.connections[connection] = struct{}{}
	return true
}

func (gate *syncreplHAGate) unregister(connection net.Conn) {
	gate.mu.Lock()
	delete(gate.connections, connection)
	gate.mu.Unlock()
}

func (gate *syncreplHAGate) pause() {
	gate.mu.Lock()
	gate.paused = true
	connections := make([]net.Conn, 0, len(gate.connections))
	for connection := range gate.connections {
		connections = append(connections, connection)
	}
	gate.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (gate *syncreplHAGate) resume() {
	gate.mu.Lock()
	gate.paused = false
	gate.mu.Unlock()
}

func (gate *syncreplHAGate) stop() {
	gate.stopOnce.Do(func() {
		gate.mu.Lock()
		gate.stopped = true
		connections := make([]net.Conn, 0, len(gate.connections))
		for connection := range gate.connections {
			connections = append(connections, connection)
		}
		gate.mu.Unlock()
		_ = gate.listener.Close()
		for _, connection := range connections {
			_ = connection.Close()
		}
		gate.wait.Wait()
	})
}
