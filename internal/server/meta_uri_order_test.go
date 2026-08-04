package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestMetaBackendURIHealthPreferenceAndRecovery(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	allowAnonymousMetaURIReads(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	first := newMetaURITestProvider(t, providerAddress)
	defer first.stop()
	second := newMetaURITestProvider(t, providerAddress)
	second.start(t)
	defer second.stop()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedMetaURIOrderProxy(t, proxyStore, first.address, second.address)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	searchMetaURIOrderTarget(t, proxyAddress)
	if got := second.accepted(); got != 1 {
		t.Fatalf("healthy second URI connections after failover = %d, want 1", got)
	}

	first.start(t)
	searchMetaURIOrderTarget(t, proxyAddress)
	if got := first.accepted(); got != 0 {
		t.Fatalf("recovered first URI was probed while preferred URI was healthy: %d", got)
	}
	if got := second.accepted(); got != 2 {
		t.Fatalf("preferred second URI connections = %d, want 2", got)
	}

	second.stop()
	searchMetaURIOrderTarget(t, proxyAddress)
	if got := first.accepted(); got != 1 {
		t.Fatalf("recovered first URI connections after preferred failure = %d, want 1", got)
	}

	second.start(t)
	searchMetaURIOrderTarget(t, proxyAddress)
	if got := first.accepted(); got != 2 {
		t.Fatalf("new preferred first URI connections = %d, want 2", got)
	}
	if got := second.accepted(); got != 2 {
		t.Fatalf("recovered second URI unexpectedly preempted first URI: %d", got)
	}
}

func TestMetaBackendURIConfigurationReloadClearsPreference(t *testing.T) {
	initialTarget := metaBackendTestTarget(
		"{0}uri",
		`"ldap://127.0.0.1:1389/dc=meta,dc=test" ldap://127.0.0.1:2389/ ldap://127.0.0.1:3389/`,
		"",
	)
	initial, err := loadMetaBackendTestConfiguration(metaBackendTestParent(), initialTarget)
	if err != nil {
		t.Fatalf("load initial URI configuration: %v", err)
	}
	rememberMetaBackendRemote(initial.targets[0], 2)
	if got := metaBackendRemoteOrder(initial.targets[0], 3); !equalInts(got, []int{2, 0, 1}) {
		t.Fatalf("initial preferred URI order = %v", got)
	}

	updatedTarget := metaBackendTestTarget(
		"{0}uri",
		`"ldap://127.0.0.1:4389/dc=meta,dc=test" ldap://127.0.0.1:5389/`,
		"",
	)
	updated, err := loadMetaBackendTestConfiguration(metaBackendTestParent(), updatedTarget)
	if err != nil {
		t.Fatalf("load updated URI configuration: %v", err)
	}
	if initial.targets[0].preferred == updated.targets[0].preferred {
		t.Fatal("configuration reload retained the previous URI preference state")
	}
	if got := metaBackendRemoteOrder(updated.targets[0], 2); !equalInts(got, []int{0, 1}) {
		t.Fatalf("updated URI order inherited a stale index: %v", got)
	}
}

func allowAnonymousMetaURIReads(t *testing.T, store storage.Store) {
	t.Helper()
	databaseDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatalf("parse provider database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues("{0}to * by * read"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("allow anonymous provider reads: %v", err)
	}
}

func seedMetaURIOrderProxy(
	t *testing.T,
	store storage.Store,
	firstAddress,
	secondAddress string,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: metaOperationDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues(metaOperationLocalSuffix)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			},
		},
		{
			DN: "olcMetaSub={0}uri," + metaOperationDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(fmt.Sprintf(
					`"ldap://%s/%s" ldap://%s/`,
					firstAddress,
					metaOperationLocalSuffix,
					secondAddress,
				))},
				{Description: "olcDbRewrite", Values: stringValues(
					`suffixmassage "` + metaOperationLocalSuffix + `" "` + ldapBackendTestSuffix + `"`,
				)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{metaOperationLocalSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed back-meta URI order proxy: %v", err)
	}
}

func searchMetaURIOrderTarget(t *testing.T, proxyAddress string) {
	t.Helper()
	client := dialLDAPBackendClient(t, proxyAddress)
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		metaOperationLocalUser,
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
		result.Entries[0].DN != metaOperationLocalUser {
		t.Fatalf("Search through back-meta URI list = %#v, %v", result, err)
	}
}

type metaURITestProvider struct {
	address  string
	upstream string
	count    atomic.Int64

	mu     sync.Mutex
	active *metaURITestProviderRun
}

type metaURITestProviderRun struct {
	listener net.Listener

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wait        sync.WaitGroup
}

func newMetaURITestProvider(t *testing.T, upstream string) *metaURITestProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve fake meta provider address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release fake meta provider address: %v", err)
	}
	return &metaURITestProvider{address: address, upstream: upstream}
}

func (provider *metaURITestProvider) accepted() int64 {
	return provider.count.Load()
}

func (provider *metaURITestProvider) start(t *testing.T) {
	t.Helper()
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.active != nil {
		t.Fatalf("fake meta provider %s is already running", provider.address)
	}
	listener, err := net.Listen("tcp", provider.address)
	if err != nil {
		t.Fatalf("start fake meta provider %s: %v", provider.address, err)
	}
	run := &metaURITestProviderRun{
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
	}
	provider.active = run
	run.wait.Add(1)
	go provider.serve(run)
}

func (provider *metaURITestProvider) serve(run *metaURITestProviderRun) {
	defer run.wait.Done()
	for {
		connection, err := run.listener.Accept()
		if err != nil {
			return
		}
		provider.count.Add(1)
		run.track(connection, true)
		run.wait.Add(1)
		go func() {
			defer run.wait.Done()
			defer run.track(connection, false)
			provider.forward(run, connection)
		}()
	}
}

func (provider *metaURITestProvider) forward(
	run *metaURITestProviderRun,
	connection net.Conn,
) {
	upstream, err := net.Dial("tcp", provider.upstream)
	if err != nil {
		_ = connection.Close()
		return
	}
	run.track(upstream, true)
	defer run.track(upstream, false)

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

func (provider *metaURITestProvider) stop() {
	provider.mu.Lock()
	run := provider.active
	provider.active = nil
	provider.mu.Unlock()
	if run == nil {
		return
	}

	_ = run.listener.Close()
	run.mu.Lock()
	for connection := range run.connections {
		_ = connection.Close()
	}
	run.mu.Unlock()
	run.wait.Wait()
}

func (run *metaURITestProviderRun) track(connection net.Conn, add bool) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if add {
		run.connections[connection] = struct{}{}
	} else {
		delete(run.connections, connection)
	}
}
