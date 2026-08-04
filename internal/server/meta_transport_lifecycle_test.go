package server

import (
	"context"
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestPrepareMetaTransportLifecycleGenerations(t *testing.T) {
	server := &Server{}
	first := metaTransportLifecycleRuntime("ldap://first.test", false)
	if retired := server.prepareMetaTransportLifecycle(nil, first); len(retired) != 0 {
		t.Fatalf("initial retired owners = %#v", retired)
	}
	firstTarget := first.databases[0].metaBackend.targets[0]
	if firstTarget.transportGeneration == 0 {
		t.Fatal("initial transport generation = 0")
	}

	unchanged := metaTransportLifecycleRuntime("ldap://first.test", false)
	if retired := server.prepareMetaTransportLifecycle(first, unchanged); len(retired) != 0 {
		t.Fatalf("unchanged retired owners = %#v", retired)
	}
	unchangedTarget := unchanged.databases[0].metaBackend.targets[0]
	if unchangedTarget.transportGeneration != firstTarget.transportGeneration {
		t.Fatalf(
			"unchanged generation = %d, want %d",
			unchangedTarget.transportGeneration,
			firstTarget.transportGeneration,
		)
	}

	changedURI := metaTransportLifecycleRuntime("ldap://second.test", false)
	retired := server.prepareMetaTransportLifecycle(unchanged, changedURI)
	assertRetiredMetaTransportOwner(t, retired, unchangedTarget)
	changedTarget := changedURI.databases[0].metaBackend.targets[0]
	if changedTarget.transportGeneration <= unchangedTarget.transportGeneration {
		t.Fatalf(
			"changed generation = %d, want greater than %d",
			changedTarget.transportGeneration,
			unchangedTarget.transportGeneration,
		)
	}

	unavailable := metaTransportLifecycleRuntime("ldap://second.test", true)
	retired = server.prepareMetaTransportLifecycle(changedURI, unavailable)
	assertRetiredMetaTransportOwner(t, retired, changedTarget)
	unavailableTarget := unavailable.databases[0].metaBackend.targets[0]
	if unavailableTarget.transportGeneration <= changedTarget.transportGeneration {
		t.Fatalf(
			"unavailable generation = %d, want greater than %d",
			unavailableTarget.transportGeneration,
			changedTarget.transportGeneration,
		)
	}

	removed := &runtimeState{}
	retired = server.prepareMetaTransportLifecycle(unavailable, removed)
	assertRetiredMetaTransportOwner(t, retired, unavailableTarget)
	readded := metaTransportLifecycleRuntime("ldap://second.test", false)
	if retired := server.prepareMetaTransportLifecycle(removed, readded); len(retired) != 0 {
		t.Fatalf("re-added retired owners = %#v", retired)
	}
	if generation := readded.databases[0].metaBackend.targets[0].transportGeneration; generation <= unavailableTarget.transportGeneration {
		t.Fatalf(
			"re-added generation = %d, want greater than %d",
			generation,
			unavailableTarget.transportGeneration,
		)
	}
}

func TestPrepareMetaTransportLifecycleMultiTargetTopology(t *testing.T) {
	server := &Server{}
	initial := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 1, uri: "ldap://right.test"},
	)
	if retired := server.prepareMetaTransportLifecycle(nil, initial); len(retired) != 0 {
		t.Fatalf("initial retired owners = %#v", retired)
	}
	leftInitial := metaTransportLifecycleTargetAt(t, initial, 0)
	rightInitial := metaTransportLifecycleTargetAt(t, initial, 1)

	expanded := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 1, uri: "ldap://right.test"},
		metaTransportLifecycleTarget{order: 2, uri: "ldap://added.test"},
	)
	if retired := server.prepareMetaTransportLifecycle(initial, expanded); len(retired) != 0 {
		t.Fatalf("expanded retired owners = %#v", retired)
	}
	leftExpanded := metaTransportLifecycleTargetAt(t, expanded, 0)
	rightExpanded := metaTransportLifecycleTargetAt(t, expanded, 1)
	addedExpanded := metaTransportLifecycleTargetAt(t, expanded, 2)
	assertMetaTransportGeneration(t, leftExpanded, leftInitial.transportGeneration)
	assertMetaTransportGeneration(t, rightExpanded, rightInitial.transportGeneration)
	if addedExpanded.transportGeneration == 0 ||
		addedExpanded.transportGeneration == leftExpanded.transportGeneration ||
		addedExpanded.transportGeneration == rightExpanded.transportGeneration {
		t.Fatalf(
			"added generation = %d, existing generations = (%d, %d)",
			addedExpanded.transportGeneration,
			leftExpanded.transportGeneration,
			rightExpanded.transportGeneration,
		)
	}

	changed := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 1, uri: "ldap://right-replaced.test"},
		metaTransportLifecycleTarget{order: 2, uri: "ldap://added.test"},
	)
	retired := server.prepareMetaTransportLifecycle(expanded, changed)
	assertRetiredMetaTransportOwner(t, retired, rightExpanded)
	leftChanged := metaTransportLifecycleTargetAt(t, changed, 0)
	rightChanged := metaTransportLifecycleTargetAt(t, changed, 1)
	addedChanged := metaTransportLifecycleTargetAt(t, changed, 2)
	assertMetaTransportGeneration(t, leftChanged, leftExpanded.transportGeneration)
	assertMetaTransportGeneration(t, addedChanged, addedExpanded.transportGeneration)
	if rightChanged.transportGeneration <= rightExpanded.transportGeneration {
		t.Fatalf(
			"changed target generation = %d, want greater than %d",
			rightChanged.transportGeneration,
			rightExpanded.transportGeneration,
		)
	}

	removed := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 2, uri: "ldap://added.test"},
	)
	retired = server.prepareMetaTransportLifecycle(changed, removed)
	assertRetiredMetaTransportOwner(t, retired, rightChanged)
	assertMetaTransportGeneration(
		t,
		metaTransportLifecycleTargetAt(t, removed, 0),
		leftChanged.transportGeneration,
	)
	assertMetaTransportGeneration(
		t,
		metaTransportLifecycleTargetAt(t, removed, 2),
		addedChanged.transportGeneration,
	)

	readded := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 1, uri: "ldap://right-replaced.test"},
		metaTransportLifecycleTarget{order: 2, uri: "ldap://added.test"},
	)
	if retired := server.prepareMetaTransportLifecycle(removed, readded); len(retired) != 0 {
		t.Fatalf("re-added retired owners = %#v", retired)
	}
	rightReadded := metaTransportLifecycleTargetAt(t, readded, 1)
	if rightReadded.transportGeneration <= rightChanged.transportGeneration {
		t.Fatalf(
			"re-added target generation = %d, want greater than retired generation %d",
			rightReadded.transportGeneration,
			rightChanged.transportGeneration,
		)
	}
	owners := metaBackendTransportOwners(readded)
	if len(owners) != 3 {
		t.Fatalf("active owners = %#v, want three targets", owners)
	}
	if _, found := owners[metaBackendTransportOwner(rightChanged)]; found {
		t.Fatalf("retired owner %q became active after re-add", metaBackendTransportOwner(rightChanged))
	}
}

func TestMetaTransportLifecycleTopologyRetiresOldConnections(t *testing.T) {
	server := &Server{
		metaTransports:      newMetaTransportPool(nil),
		metaTransportCaches: make(map[*metaTransportCache]struct{}),
	}
	t.Cleanup(server.metaTransports.close)
	cache := newMetaTransportCache(nil)
	server.metaTransportCaches[cache] = struct{}{}
	t.Cleanup(cache.close)
	remote := defaultChainRemoteConfiguration()

	initial := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 1, uri: "ldap://right.test"},
	)
	server.prepareMetaTransportLifecycle(nil, initial)
	server.configureMetaTransportOwners(metaBackendTransportOwners(initial))
	leftInitial := metaTransportLifecycleTargetAt(t, initial, 0)
	rightInitial := metaTransportLifecycleTargetAt(t, initial, 1)
	leftPool := seedIdleMetaLifecyclePoolTransport(t, server.metaTransports, leftInitial, remote)
	rightPool := seedIdleMetaLifecyclePoolTransport(t, server.metaTransports, rightInitial, remote)
	leftCache := seedIdleMetaLifecycleCacheTransport(t, cache, leftInitial, remote)
	rightCache := seedIdleMetaLifecycleCacheTransport(t, cache, rightInitial, remote)

	changed := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 1, uri: "ldap://right-replaced.test"},
		metaTransportLifecycleTarget{order: 2, uri: "ldap://added.test"},
	)
	server.prepareMetaTransportLifecycle(initial, changed)
	server.configureMetaTransportOwners(metaBackendTransportOwners(changed))
	assertMetaPoolConnectionOpen(t, leftPool.connection)
	assertMetaPoolConnectionOpen(t, leftCache.connection)
	assertMetaPoolConnectionClosed(t, rightPool.connection)
	assertMetaPoolConnectionClosed(t, rightCache.connection)

	rightChanged := metaTransportLifecycleTargetAt(t, changed, 1)
	addedChanged := metaTransportLifecycleTargetAt(t, changed, 2)
	rightPoolInUse := seedActiveMetaLifecyclePoolTransport(
		t,
		server.metaTransports,
		rightChanged,
		remote,
	)
	rightCacheInUse := seedActiveMetaLifecycleCacheTransport(t, cache, rightChanged, remote)
	addedPool := seedIdleMetaLifecyclePoolTransport(t, server.metaTransports, addedChanged, remote)
	addedCache := seedIdleMetaLifecycleCacheTransport(t, cache, addedChanged, remote)

	removed := metaTransportLifecycleTopology(
		metaTransportLifecycleTarget{order: 0, uri: "ldap://left.test"},
		metaTransportLifecycleTarget{order: 2, uri: "ldap://added.test"},
	)
	server.prepareMetaTransportLifecycle(changed, removed)
	server.configureMetaTransportOwners(metaBackendTransportOwners(removed))
	assertMetaPoolConnectionOpen(t, rightPoolInUse.connection)
	assertMetaPoolConnectionOpen(t, rightCacheInUse.connection)
	assertMetaPoolConnectionOpen(t, leftPool.connection)
	assertMetaPoolConnectionOpen(t, leftCache.connection)
	assertMetaPoolConnectionOpen(t, addedPool.connection)
	assertMetaPoolConnectionOpen(t, addedCache.connection)

	server.metaTransports.release(
		rightPoolInUse.lease,
		remote,
		rightPoolInUse.transport,
		true,
	)
	cache.releaseOwned(
		rightCacheInUse.key,
		rightCacheInUse.owner,
		remote,
		rightCacheInUse.transport,
		true,
	)
	assertMetaPoolConnectionClosed(t, rightPoolInUse.connection)
	assertMetaPoolConnectionClosed(t, rightCacheInUse.connection)

	latePoolTransport, latePoolConnection := newMetaPoolTestTransport()
	_, latePoolLease, err := server.metaTransports.acquireOwned(
		context.Background(),
		"late-pool",
		metaBackendTransportOwner(rightChanged),
		remote,
		1,
		false,
	)
	if err != nil || latePoolLease == nil || !latePoolLease.temporary {
		t.Fatalf("retired owner late pool lease = (%#v, %v)", latePoolLease, err)
	}
	server.metaTransports.release(latePoolLease, remote, latePoolTransport, true)
	assertMetaPoolConnectionClosed(t, latePoolConnection)

	lateCacheTransport, lateCacheConnection := newMetaPoolTestTransport()
	cache.releaseOwned(
		"late-cache",
		metaBackendTransportOwner(rightChanged),
		remote,
		lateCacheTransport,
		true,
	)
	assertMetaPoolConnectionClosed(t, lateCacheConnection)
}

func TestPrepareMetaTransportLifecycleClonesSharedTargets(t *testing.T) {
	server := &Server{}
	previous := metaTransportLifecycleRuntime("ldap://shared.test", false)
	server.prepareMetaTransportLifecycle(nil, previous)
	previousTarget := &previous.databases[0].metaBackend.targets[0]
	previousGeneration := previousTarget.transportGeneration

	next := *previous
	if retired := server.prepareMetaTransportLifecycle(previous, &next); len(retired) != 0 {
		t.Fatalf("shared runtime retired owners = %#v", retired)
	}
	nextTarget := &next.databases[0].metaBackend.targets[0]
	if next.databases[0].metaBackend == previous.databases[0].metaBackend ||
		nextTarget == previousTarget {
		t.Fatal("meta transport lifecycle retained shared mutable target storage")
	}
	if previousTarget.transportGeneration != previousGeneration {
		t.Fatalf(
			"previous generation changed to %d, want %d",
			previousTarget.transportGeneration,
			previousGeneration,
		)
	}
	if nextTarget.transportGeneration != previousGeneration {
		t.Fatalf(
			"cloned generation = %d, want %d",
			nextTarget.transportGeneration,
			previousGeneration,
		)
	}
}

func TestPrepareMetaTransportLifecycleIgnoresRWMSchemaIdentity(t *testing.T) {
	server := &Server{}
	previous := metaTransportLifecycleRuntime("ldap://rwm.test", false)
	previous.databases[0].metaBackend.targets[0].rwm = &rwmRuntimeConfiguration{
		attributesToRemote: map[string]string{"uid": "cn"},
		attributesToLocal:  map[string]string{"cn": "uid"},
		schema:             schema.NewRegistry(),
	}
	server.prepareMetaTransportLifecycle(nil, previous)
	previousTarget := previous.databases[0].metaBackend.targets[0]

	next := metaTransportLifecycleRuntime("ldap://rwm.test", false)
	next.databases[0].metaBackend.targets[0].rwm = &rwmRuntimeConfiguration{
		attributesToRemote: map[string]string{"uid": "cn"},
		attributesToLocal:  map[string]string{"cn": "uid"},
		schema:             schema.NewRegistry(),
	}
	if retired := server.prepareMetaTransportLifecycle(previous, next); len(retired) != 0 {
		t.Fatalf("schema-only RWM change retired owners = %#v", retired)
	}
	if generation := next.databases[0].metaBackend.targets[0].transportGeneration; generation != previousTarget.transportGeneration {
		t.Fatalf(
			"schema-only RWM generation = %d, want %d",
			generation,
			previousTarget.transportGeneration,
		)
	}

	changed := metaTransportLifecycleRuntime("ldap://rwm.test", false)
	changed.databases[0].metaBackend.targets[0].rwm = &rwmRuntimeConfiguration{
		attributesToRemote: map[string]string{"uid": "displayName"},
		attributesToLocal:  map[string]string{"displayname": "uid"},
		schema:             schema.NewRegistry(),
	}
	retired := server.prepareMetaTransportLifecycle(next, changed)
	assertRetiredMetaTransportOwner(
		t,
		retired,
		next.databases[0].metaBackend.targets[0],
	)
}

func metaTransportLifecycleRuntime(
	uri string,
	unavailable bool,
) *runtimeState {
	return metaTransportLifecycleTopology(metaTransportLifecycleTarget{
		order:       0,
		uri:         uri,
		unavailable: unavailable,
	})
}

type metaTransportLifecycleTarget struct {
	order       int
	uri         string
	unavailable bool
}

type metaTransportLifecycleFixture struct {
	key        string
	owner      string
	transport  *syncConsumerTransport
	connection *metaPoolTestConnection
	lease      *metaTransportPoolLease
}

func metaTransportLifecycleTopology(
	targets ...metaTransportLifecycleTarget,
) *runtimeState {
	configured := make([]metaBackendTargetRuntimeConfiguration, 0, len(targets))
	for _, target := range targets {
		remote := defaultChainRemoteConfiguration()
		remote.uri = target.uri
		remote.endpointKey = target.uri
		configured = append(configured, metaBackendTargetRuntimeConfiguration{
			configDNKey: fmt.Sprintf(
				"olcmetasub={%d}uri,olcdatabase={1}meta,cn=config",
				target.order,
			),
			onlineURIUnavailable: target.unavailable,
			order:                target.order,
			ldapBackend: &ldapBackendRuntimeConfiguration{
				remotes: []chainRemoteConfiguration{remote},
			},
		})
	}
	return &runtimeState{databases: []runtimeDatabase{{
		metaBackend: &metaBackendRuntimeConfiguration{
			configDNKey: "olcdatabase={1}meta,cn=config",
			targets:     configured,
		},
	}}}
}

func metaTransportLifecycleTargetAt(
	t *testing.T,
	runtime *runtimeState,
	order int,
) metaBackendTargetRuntimeConfiguration {
	t.Helper()
	if runtime != nil {
		for _, database := range runtime.databases {
			if database.metaBackend == nil {
				continue
			}
			for _, target := range database.metaBackend.targets {
				if target.order == order {
					return target
				}
			}
		}
	}
	t.Fatalf("meta target order %d not found", order)
	return metaBackendTargetRuntimeConfiguration{}
}

func assertMetaTransportGeneration(
	t *testing.T,
	target metaBackendTargetRuntimeConfiguration,
	want uint64,
) {
	t.Helper()
	if target.transportGeneration != want {
		t.Fatalf(
			"target %q generation = %d, want %d",
			target.configDNKey,
			target.transportGeneration,
			want,
		)
	}
}

func seedIdleMetaLifecyclePoolTransport(
	t *testing.T,
	pool *metaTransportPool,
	target metaBackendTargetRuntimeConfiguration,
	remote chainRemoteConfiguration,
) metaTransportLifecycleFixture {
	t.Helper()
	fixture := seedActiveMetaLifecyclePoolTransport(t, pool, target, remote)
	pool.release(fixture.lease, remote, fixture.transport, true)
	fixture.lease = nil
	return fixture
}

func seedActiveMetaLifecyclePoolTransport(
	t *testing.T,
	pool *metaTransportPool,
	target metaBackendTargetRuntimeConfiguration,
	remote chainRemoteConfiguration,
) metaTransportLifecycleFixture {
	t.Helper()
	owner := metaBackendTransportOwner(target)
	key := metaTransportKey(owner, remote)
	pooled, lease, err := pool.acquireOwned(
		context.Background(),
		key,
		owner,
		remote,
		1,
		false,
	)
	if err != nil || pooled != nil || lease == nil || !lease.reserved {
		t.Fatalf(
			"reserve target %q pool transport = (%p, %#v, %v)",
			target.configDNKey,
			pooled,
			lease,
			err,
		)
	}
	transport, connection := newMetaPoolTestTransport()
	if !pool.publish(lease, transport) {
		t.Fatalf("publish target %q pool transport = false", target.configDNKey)
	}
	return metaTransportLifecycleFixture{
		key:        key,
		owner:      owner,
		transport:  transport,
		connection: connection,
		lease:      lease,
	}
}

func seedIdleMetaLifecycleCacheTransport(
	t *testing.T,
	cache *metaTransportCache,
	target metaBackendTargetRuntimeConfiguration,
	remote chainRemoteConfiguration,
) metaTransportLifecycleFixture {
	t.Helper()
	owner := metaBackendTransportOwner(target)
	key := metaTransportKey(owner, remote)
	transport, connection := newMetaPoolTestTransport()
	cache.releaseOwned(key, owner, remote, transport, true)
	return metaTransportLifecycleFixture{
		key:        key,
		owner:      owner,
		transport:  transport,
		connection: connection,
	}
}

func seedActiveMetaLifecycleCacheTransport(
	t *testing.T,
	cache *metaTransportCache,
	target metaBackendTargetRuntimeConfiguration,
	remote chainRemoteConfiguration,
) metaTransportLifecycleFixture {
	t.Helper()
	fixture := seedIdleMetaLifecycleCacheTransport(t, cache, target, remote)
	if got := cache.acquireOwned(fixture.key, fixture.owner, remote); got != fixture.transport {
		t.Fatalf(
			"acquire target %q cache transport = %p, want %p",
			target.configDNKey,
			got,
			fixture.transport,
		)
	}
	return fixture
}

func assertRetiredMetaTransportOwner(
	t *testing.T,
	retired map[string]struct{},
	target metaBackendTargetRuntimeConfiguration,
) {
	t.Helper()
	owner := metaBackendTransportOwner(target)
	if _, found := retired[owner]; !found || len(retired) != 1 {
		t.Fatalf("retired owners = %#v, want only %q", retired, owner)
	}
}
