package server

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPBackendSingleURIReconnectRetry(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	t.Cleanup(stopProvider)

	t.Run("Bind", func(t *testing.T) {
		upstream := startLDAPBackendDropFirstProxy(t, providerAddress)
		proxyStore := storage.NewMemory()
		t.Cleanup(func() { _ = proxyStore.Close() })
		seedLDAPBackendProxy(t, proxyStore, upstream.address)
		proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
		t.Cleanup(stopProxy)

		client := bindLDAPBackendUser(t, proxyAddress, ldapBackendTestUserPassword)
		client.Close()
		if got := upstream.accepted.Load(); got != 2 {
			t.Fatalf("remote Bind connection attempts = %d, want 2", got)
		}
	})

	t.Run("Search with identity assertion", func(t *testing.T) {
		upstream := startLDAPBackendDropFirstProxy(t, providerAddress)
		proxyStore := storage.NewMemory()
		t.Cleanup(func() { _ = proxyStore.Close() })
		seedLDAPBackendProxy(t, proxyStore, upstream.address)
		allowAnonymousLDAPBackendIdentityAssertion(t, proxyStore)
		proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
		t.Cleanup(stopProxy)

		client := dialLDAPBackendClient(t, proxyAddress)
		defer client.Close()
		result, err := client.Search(ldap.NewSearchRequest(
			ldapBackendTestUserDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"uid"},
			nil,
		))
		if err != nil || len(result.Entries) != 1 ||
			result.Entries[0].DN != ldapBackendTestUserDN {
			t.Fatalf("Search after reconnect = %#v, %v", result, err)
		}
		if got := upstream.accepted.Load(); got != 2 {
			t.Fatalf("remote Search connection attempts = %d, want 2", got)
		}
	})
}

func allowAnonymousLDAPBackendIdentityAssertion(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	dn, err := directory.ParseDN(ldapBackendTestDatabaseDN)
	if err != nil {
		t.Fatalf("parse LDAP backend database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbIDAssertAuthzFrom", stringValues("*"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("authorize anonymous LDAP backend identity assertion: %v", err)
	}
}

type ldapBackendDropFirstProxy struct {
	address  string
	upstream string
	listener net.Listener
	accepted atomic.Int64

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wait        sync.WaitGroup
}

func startLDAPBackendDropFirstProxy(
	t *testing.T,
	upstream string,
) *ldapBackendDropFirstProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start drop-first LDAP proxy: %v", err)
	}
	proxy := &ldapBackendDropFirstProxy{
		address:     listener.Addr().String(),
		upstream:    upstream,
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
	}
	proxy.wait.Add(1)
	go proxy.serve()
	t.Cleanup(proxy.stop)
	return proxy
}

func (proxy *ldapBackendDropFirstProxy) serve() {
	defer proxy.wait.Done()
	for {
		connection, err := proxy.listener.Accept()
		if err != nil {
			return
		}
		attempt := proxy.accepted.Add(1)
		if attempt == 1 {
			if tcp, ok := connection.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = connection.Close()
			continue
		}
		proxy.track(connection, true)
		proxy.wait.Add(1)
		go func() {
			defer proxy.wait.Done()
			defer proxy.track(connection, false)
			proxy.forward(connection)
		}()
	}
}

func (proxy *ldapBackendDropFirstProxy) forward(connection net.Conn) {
	upstream, err := net.Dial("tcp", proxy.upstream)
	if err != nil {
		_ = connection.Close()
		return
	}
	proxy.track(upstream, true)
	defer proxy.track(upstream, false)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, connection)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(connection, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = connection.Close()
	_ = upstream.Close()
	<-done
}

func (proxy *ldapBackendDropFirstProxy) track(connection net.Conn, add bool) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if add {
		proxy.connections[connection] = struct{}{}
	} else {
		delete(proxy.connections, connection)
	}
}

func (proxy *ldapBackendDropFirstProxy) stop() {
	_ = proxy.listener.Close()
	proxy.mu.Lock()
	for connection := range proxy.connections {
		_ = connection.Close()
	}
	proxy.mu.Unlock()
	proxy.wait.Wait()
}
