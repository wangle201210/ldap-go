package server

import (
	"sync"
	"testing"
)

func TestActivateRuntimeRejectsOutOfOrderSnapshot(t *testing.T) {
	server := newRuntimeActivationTestServer()
	defer server.metaTransports.close()

	second := &runtimeState{revision: 2}
	first := &runtimeState{revision: 1}
	server.activateRuntime(second)
	server.activateRuntime(first)
	if got := server.runtime.Load(); got != second {
		if got == nil {
			t.Fatal("active runtime = nil, want revision 2")
		}
		t.Fatalf("active runtime = %p revision %d, want %p revision 2", got, got.revision, second)
	}
}

func TestActivateRuntimeConcurrentSnapshotsRemainMonotonic(t *testing.T) {
	server := newRuntimeActivationTestServer()
	defer server.metaTransports.close()

	runtimes := []*runtimeState{
		{revision: 2},
		{revision: 5},
		{revision: 3},
		{revision: 4},
		{revision: 1},
	}
	var wait sync.WaitGroup
	for _, runtime := range runtimes {
		wait.Add(1)
		go func() {
			defer wait.Done()
			server.activateRuntime(runtime)
		}()
	}
	wait.Wait()
	if got := server.runtime.Load(); got == nil || got.revision != 5 {
		if got == nil {
			t.Fatal("active runtime = nil, want revision 5")
		}
		t.Fatalf("active runtime revision = %d, want 5", got.revision)
	}
}

func TestActivateRuntimeRetiresRegisteredConnectionCaches(t *testing.T) {
	server := newRuntimeActivationTestServer()
	defer server.metaTransports.close()
	first := metaTransportLifecycleRuntime("ldap://first-cache.test", false)
	first.revision = 1
	server.activateRuntime(first)
	owner := metaBackendTransportOwner(first.databases[0].metaBackend.targets[0])

	cache := newMetaTransportCache(nil)
	server.registerMetaTransportCache(cache)
	defer func() {
		server.unregisterMetaTransportCache(cache)
		cache.close()
	}()
	transport, connection := newMetaPoolTestTransport()
	cache.releaseOwned(
		"registered-cache-key",
		owner,
		defaultChainRemoteConfiguration(),
		transport,
		true,
	)
	assertMetaPoolConnectionOpen(t, connection)

	second := metaTransportLifecycleRuntime("ldap://second-cache.test", false)
	second.revision = 2
	server.activateRuntime(second)
	assertMetaPoolConnectionClosed(t, connection)

	lateTransport, lateConnection := newMetaPoolTestTransport()
	cache.releaseOwned(
		"late-old-cache-key",
		owner,
		defaultChainRemoteConfiguration(),
		lateTransport,
		true,
	)
	assertMetaPoolConnectionClosed(t, lateConnection)
}

func newRuntimeActivationTestServer() *Server {
	server := &Server{
		metaTransports: newMetaTransportPool(nil),
		syncChanges:    newSyncChangeHub(),
		ddsWake:        make(chan struct{}, 1),
		accesslogWake:  make(chan struct{}, 1),
	}
	server.syncConsumers = newSyncConsumerManager(server)
	return server
}
