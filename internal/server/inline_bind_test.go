package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const inlineBindRootDN = "cn=admin,dc=example,dc=com"

func TestInlineBindPipelinedRebindIdentityAndAccounting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &recordingAuditSink{}
		instance, connection, _, _ := startInlineBindTestConnection(t, Config{AuditSink: sink})
		for index, test := range []struct {
			dn       string
			password string
			code     ldapwire.ResultCode
			identity string
		}{
			{dn: inlineBindRootDN, password: "admin-secret", identity: "dn:" + inlineBindRootDN},
			{dn: inlineBindRootDN, password: "wrong", code: ldapwire.ResultInvalidCredentials},
			{dn: "uid=alice,ou=people,dc=example,dc=com", password: "secret",
				identity: "dn:uid=alice,ou=people,dc=example,dc=com"},
			{},
			{dn: inlineBindRootDN, password: "admin-secret", identity: "dn:" + inlineBindRootDN},
			{dn: "cn=broken,", password: "secret", code: ldapwire.ResultInvalidDNSyntax},
		} {
			id := int64(index*2 + 1)
			written := writeInlineBindTestPipeline(t, connection,
				inlineBindTestMessage(id, test.dn, test.password),
				ldapwire.Message{ID: id + 1, Request: ldapwire.ExtendedRequest{Name: whoAmIOID}},
			)
			synctest.Wait()
			registry := inlineBindTestRegistry(t, instance)
			if !registry.contains(id) || registry.contains(id+1) {
				t.Fatal("reader crossed the Bind barrier before its response was consumed")
			}
			if _, result := registry.cancel(id); result.Code != ldapwire.ResultCannotCancel {
				t.Fatalf("Bind Cancel result = %v", result)
			}
			registry.abandon(id)
			if instance.pendingByteLimiter.active.Load() <= 0 || instance.operationLimiter.active.Load() != 1 {
				t.Fatal("in-flight Bind was not charged against global admission")
			}
			assertRawLDAPEnvelope(t, readRawLDAPPacket(t, connection), id,
				ldapwire.ApplicationBindResponse, int64(test.code))
			response := readRawLDAPPacket(t, connection)
			assertRawLDAPEnvelope(t, response, id+1, ldapwire.ApplicationExtendedResponse, int64(ldapwire.ResultSuccess))
			value, present := rawExtendedResponseValue(response)
			if !present || string(value) != test.identity {
				t.Fatalf("Who Am I after Bind(%q) = %q, present=%v; want %q",
					test.dn, value, present, test.identity)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			assertInlineBindTestReleased(t, instance)
			if registry.hasOutstanding() {
				t.Fatal("completed Bind or Who Am I remained registered")
			}
			events := sink.snapshot()
			if len(events) != (index+1)*2 || events[index*2].ResultCode == nil ||
				ldapwire.ResultCode(*events[index*2].ResultCode) != test.code {
				t.Fatalf("Bind audit results = %#v", events)
			}
			instance.monitor.mu.Lock()
			for _, monitored := range instance.monitor.connections {
				monitored.mu.Lock()
				pending, executing, completed := monitored.pending, monitored.executing, monitored.completed
				monitored.mu.Unlock()
				if pending != 0 || executing != 0 || completed != uint64((index+1)*2) {
					t.Errorf("monitor pending=%d executing=%d completed=%d", pending, executing, completed)
				}
			}
			instance.monitor.mu.Unlock()
		}
	})
}

func TestInlineBindPendingByteAdmission(t *testing.T) {
	for _, config := range []Config{
		{MaxPendingOperationBytes: 1},
		{MaxPendingBytesPerConnection: 1},
	} {
		synctest.Test(t, func(t *testing.T) {
			sink := &recordingAuditSink{}
			config.AuditSink = sink
			instance, connection, _, done := startInlineBindTestConnection(t, config)
			written := writeInlineBindTestPipeline(t, connection,
				inlineBindTestMessage(1, inlineBindRootDN, "admin-secret"))
			if _, err := ber.ReadPacket(connection); err == nil {
				t.Fatal("byte-limited Bind produced a response instead of closing")
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			<-done
			assertInlineBindTestReleased(t, instance)
			if len(sink.snapshot()) != 0 {
				t.Fatal("byte-limited Bind reached dispatch")
			}
		})
	}
}

func TestInlineBindGlobalOperationAdmissionAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		instance, connection, cancel, done := startInlineBindTestConnection(t, Config{MaxConcurrentOperations: 1})
		if !instance.operationLimiter.acquire(t.Context()) {
			t.Fatal("failed to occupy the global operation slot")
		}
		defer instance.operationLimiter.release()
		written := writeInlineBindTestPipeline(t, connection,
			inlineBindTestMessage(1, inlineBindRootDN, "admin-secret"))
		synctest.Wait()
		if instance.operationLimiter.waiting.Load() != 1 || instance.pendingByteLimiter.active.Load() <= 0 {
			t.Fatal("Bind bypassed global operation or byte admission")
		}
		registry := inlineBindTestRegistry(t, instance)
		if !registry.contains(1) {
			t.Fatal("Bind waiting for global admission was not registered")
		}
		cancel()
		<-done
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		if registry.hasOutstanding() || instance.pendingByteLimiter.active.Load() != 0 ||
			instance.operationLimiter.waiting.Load() != 0 || instance.operationLimiter.active.Load() != 1 {
			t.Fatal("canceled admission leaked Bind resources or released another operation's slot")
		}
	})
}

func TestInlineBindAbandonsPriorOperations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := storage.NewMemory()
		t.Cleanup(func() { _ = base.Close() })
		seedDirectory(t, base)
		store := newResourceLimitStore(base)
		instance, connection, _, _ := startInlineBindTestConnection(t, Config{
			Store: store, MaxOperationsPerConnection: 1,
		})
		store.enable()
		defer store.unblock()
		search := ldapwire.SearchRequest{
			BaseDN: "dc=example,dc=com", Scope: directory.ScopeBase,
			Filter: directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
		}
		first := writeInlineBindTestPipeline(t, connection, ldapwire.Message{ID: 1, Request: search})
		synctest.Wait()
		if len(store.entered) != 1 {
			t.Fatal("Search did not reach storage")
		}
		if err := <-first; err != nil {
			t.Fatal(err)
		}
		registry := inlineBindTestRegistry(t, instance)
		written := writeInlineBindTestPipeline(t, connection,
			ldapwire.Message{ID: 2, Request: search},
			inlineBindTestMessage(3, "uid=alice,ou=people,dc=example,dc=com", "secret"),
			ldapwire.Message{ID: 4, Request: ldapwire.ExtendedRequest{Name: whoAmIOID}},
		)
		synctest.Wait()
		if registry.contains(1) || registry.contains(2) || !registry.contains(3) || registry.contains(4) {
			t.Fatal("Bind did not abandon prior operations or preserve its reader barrier")
		}
		if len(store.entered) != 2 {
			t.Fatalf("storage entered %d times, want active Search and Bind only", len(store.entered))
		}
		store.unblock()
		assertRawLDAPEnvelope(t, readRawLDAPPacket(t, connection), 3,
			ldapwire.ApplicationBindResponse, int64(ldapwire.ResultSuccess))
		assertRawLDAPEnvelope(t, readRawLDAPPacket(t, connection), 4,
			ldapwire.ApplicationExtendedResponse, int64(ldapwire.ResultSuccess))
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		assertInlineBindTestReleased(t, instance)
	})
}

func TestInlineBindAbortsTransaction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		instance, connection, _, _ := startInlineBindTestConnection(t, Config{})
		response := authzidTestExchange(t, connection, inlineBindTestMessage(1, inlineBindRootDN, "admin-secret"))
		assertRawLDAPEnvelope(t, response, 1, ldapwire.ApplicationBindResponse, int64(ldapwire.ResultSuccess))
		identifier := startRawLDAPTransaction(t, connection, 2)
		entry := transactionTestPerson("inline-bind-abort")
		assertRawLDAPResult(t, sendRawLDAPOperation(t, connection, 3,
			rawAddRequest(entry), rawTransactionSpecificationControl(identifier, true, true)), int64(ldapwire.ResultSuccess))
		synctest.Wait()
		if instance.pendingByteLimiter.active.Load() <= 0 {
			t.Fatal("transaction did not retain its queued Add")
		}
		response = authzidTestExchange(t, connection, inlineBindTestMessage(4, inlineBindRootDN, "wrong"))
		assertRawLDAPEnvelope(t, response, 4, ldapwire.ApplicationBindResponse, int64(ldapwire.ResultInvalidCredentials))
		synctest.Wait()
		assertInlineBindTestReleased(t, instance)
		if transactionEntryExists(t, instance.config.Store, entry.DN) {
			t.Fatal("failed rebind committed the aborted transaction")
		}
		response = authzidTestExchange(t, connection, inlineBindTestMessage(5, inlineBindRootDN, "admin-secret"))
		assertRawLDAPEnvelope(t, response, 5, ldapwire.ApplicationBindResponse, int64(ldapwire.ResultSuccess))
		assertRawLDAPResult(t, endRawLDAPTransaction(t, connection, 6, true, identifier), int64(ldapwire.ResultTransactionIDInvalid))
		synctest.Wait()
		assertInlineBindTestReleased(t, instance)
	})
}

func TestInlineBindResponseFailureReleasesAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		instance, connection, _, done := startInlineBindTestConnection(t, Config{})
		written := writeInlineBindTestPipeline(t, connection,
			inlineBindTestMessage(1, inlineBindRootDN, "admin-secret"))
		synctest.Wait()
		registry := inlineBindTestRegistry(t, instance)
		if !registry.contains(1) || instance.operationLimiter.active.Load() != 1 {
			t.Fatal("Bind was not executing before response failure")
		}
		_ = connection.Close()
		<-done
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		assertInlineBindTestReleased(t, instance)
		if registry.hasOutstanding() {
			t.Fatal("failed response left Bind registered")
		}
	})
}

func TestInlineBindShutdown(t *testing.T) {
	for _, force := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			base := storage.NewMemory()
			t.Cleanup(func() { _ = base.Close() })
			seedDirectory(t, base)
			store := newResourceLimitStore(base)
			instance, connection, cancel, done := startInlineBindTestConnection(t, Config{
				Store: store, ShutdownTimeout: 50 * time.Millisecond,
			})
			store.enable()
			defer store.unblock()
			written := writeInlineBindTestPipeline(t, connection,
				inlineBindTestMessage(1, "uid=alice,ou=people,dc=example,dc=com", "secret"))
			synctest.Wait()
			if len(store.entered) != 1 {
				t.Fatal("Bind did not reach storage")
			}
			instance.draining.Store(true)
			instance.beginConnectionDrain()
			drained := make(chan error, 1)
			go func() { drained <- instance.waitForConnectionDrain(cancel) }()
			synctest.Wait()
			if channelClosed(done) {
				t.Fatal("graceful drain canceled an in-flight Bind")
			}
			if force {
				if err := <-drained; !errors.Is(err, ErrShutdownTimeout) {
					t.Fatalf("forced drain = %v, want shutdown timeout", err)
				}
			} else {
				store.unblock()
				assertRawLDAPEnvelope(t, readRawLDAPPacket(t, connection), 1,
					ldapwire.ApplicationBindResponse, int64(ldapwire.ResultSuccess))
				if err := <-drained; err != nil {
					t.Fatalf("graceful drain = %v", err)
				}
			}
			<-done
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			assertInlineBindTestReleased(t, instance)
		})
	}
}

func startInlineBindTestConnection(t *testing.T, config Config) (*Server, net.Conn, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	if config.Store == nil {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		config.Store = store
	}
	config.RootDN = inlineBindRootDN
	config.RootPassword = []byte("admin-secret")
	instance, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	serverConnection, clientConnection := net.Pipe()
	instance.connections[serverConnection] = struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	instance.wg.Add(1)
	go func() {
		defer close(done)
		instance.serveConnection(ctx, serverConnection)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		<-done
		instance.monitor.closeLogFile()
		instance.closeSQLBackends()
		instance.metaTransports.close()
	})
	return instance, clientConnection, cancel, done
}

func writeInlineBindTestPipeline(t *testing.T, connection net.Conn, messages ...ldapwire.Message) <-chan error {
	t.Helper()
	var encoded []byte
	for _, message := range messages {
		packet, err := ldapwire.EncodeRequestMessage(message)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, packet...)
	}
	done := make(chan error, 1)
	go func() {
		_, err := connection.Write(encoded)
		done <- err
	}()
	return done
}

func inlineBindTestRegistry(t *testing.T, instance *Server) *operationRegistry {
	t.Helper()
	instance.mu.Lock()
	defer instance.mu.Unlock()
	for _, registry := range instance.connectionOperations {
		return registry
	}
	t.Fatal("connection has no operation registry")
	return nil
}

func assertInlineBindTestReleased(t *testing.T, instance *Server) {
	t.Helper()
	if retained, active, waiting := instance.pendingByteLimiter.active.Load(),
		instance.operationLimiter.active.Load(), instance.operationLimiter.waiting.Load(); retained != 0 || active != 0 || waiting != 0 {
		t.Fatalf("retained=%d active=%d waiting=%d after completion", retained, active, waiting)
	}
}
