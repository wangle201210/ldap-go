package lloadd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

type sequenceRandom struct {
	values []int
	next   int
}

func (random *sequenceRandom) Intn(n int) int {
	if len(random.values) == 0 {
		return 0
	}
	value := random.values[random.next%len(random.values)]
	random.next++
	return value
}

func TestRoundRobinBackendAndConnectionRotation(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
		ID:     "primary",
		Policy: PolicyRoundRobin,
		Backends: []SchedulerBackendConfig{
			{
				ID:     "a",
				Weight: 1,
				Connections: []SchedulerConnectionConfig{
					{ID: "a-1"},
					{ID: "a-2"},
				},
			},
			{
				ID:          "b",
				Weight:      1,
				Connections: []SchedulerConnectionConfig{{ID: "b-1"}},
			},
		},
	}}})

	want := []struct {
		backend    string
		connection string
	}{
		{backend: "a", connection: "a-1"},
		{backend: "b", connection: "b-1"},
		{backend: "a", connection: "a-2"},
		{backend: "b", connection: "b-1"},
	}
	for index, expected := range want {
		lease := mustSelect(t, scheduler, SelectRequest{})
		if lease.BackendID != expected.backend ||
			lease.ConnectionID != expected.connection {
			t.Fatalf(
				"selection %d = %s/%s, want %s/%s",
				index,
				lease.BackendID,
				lease.ConnectionID,
				expected.backend,
				expected.connection,
			)
		}
		lease.Release()
	}
}

func TestTierFallbackDistinguishesUnavailableAndBusy(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{
		{
			ID:     "primary",
			Policy: PolicyRoundRobin,
			Backends: []SchedulerBackendConfig{{
				ID: "primary-backend",
				Connections: []SchedulerConnectionConfig{{
					ID:         "primary-connection",
					MaxPending: 1,
				}},
			}},
		},
		{
			ID:     "secondary",
			Policy: PolicyRoundRobin,
			Backends: []SchedulerBackendConfig{{
				ID:          "secondary-backend",
				Connections: []SchedulerConnectionConfig{{ID: "secondary-connection"}},
			}},
		},
	}})

	first := mustSelect(t, scheduler, SelectRequest{})
	if first.TierID != "primary" {
		t.Fatalf("first tier = %q, want primary", first.TierID)
	}
	assertSelectError(t, scheduler, SelectRequest{}, ErrBusy)
	first.Release()

	if err := scheduler.SetConnectionState(
		"primary-connection",
		ConnectionBusy,
	); err != nil {
		t.Fatalf("SetConnectionState(busy): %v", err)
	}
	assertSelectError(t, scheduler, SelectRequest{}, ErrBusy)

	if err := scheduler.SetConnectionState(
		"primary-connection",
		ConnectionUnavailable,
	); err != nil {
		t.Fatalf("SetConnectionState(unavailable): %v", err)
	}
	fallback := mustSelect(t, scheduler, SelectRequest{})
	if fallback.TierID != "secondary" {
		t.Fatalf("fallback tier = %q, want secondary", fallback.TierID)
	}
	fallback.Release()

	if err := scheduler.SetConnectionState(
		"secondary-connection",
		ConnectionUnavailable,
	); err != nil {
		t.Fatalf("disable secondary connection: %v", err)
	}
	assertSelectError(t, scheduler, SelectRequest{}, ErrUnavailable)
}

func TestBackendAndConnectionPendingCapacity(t *testing.T) {
	t.Run("backend total", func(t *testing.T) {
		scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
			ID:     "tier",
			Policy: PolicyRoundRobin,
			Backends: []SchedulerBackendConfig{{
				ID:         "backend",
				MaxPending: 2,
				Connections: []SchedulerConnectionConfig{
					{ID: "connection-1"},
					{ID: "connection-2"},
				},
			}},
		}}})

		first := mustSelect(t, scheduler, SelectRequest{})
		second := mustSelect(t, scheduler, SelectRequest{})
		assertSelectError(t, scheduler, SelectRequest{}, ErrBusy)
		first.Release()
		third := mustSelect(t, scheduler, SelectRequest{})
		second.Release()
		third.Release()
		assertNoPending(t, scheduler)
	})

	t.Run("per connection", func(t *testing.T) {
		scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
			ID:     "tier",
			Policy: PolicyRoundRobin,
			Backends: []SchedulerBackendConfig{{
				ID: "backend",
				Connections: []SchedulerConnectionConfig{
					{ID: "connection-1", MaxPending: 1},
					{ID: "connection-2", MaxPending: 1},
				},
			}},
		}}})

		first := mustSelect(t, scheduler, SelectRequest{})
		second := mustSelect(t, scheduler, SelectRequest{})
		if first.ConnectionID == second.ConnectionID {
			t.Fatalf("both leases used %q despite connection limit", first.ConnectionID)
		}
		assertSelectError(t, scheduler, SelectRequest{}, ErrBusy)
		first.Release()
		third := mustSelect(t, scheduler, SelectRequest{})
		if third.ConnectionID != first.ConnectionID {
			t.Fatalf(
				"reused connection = %q, want released %q",
				third.ConnectionID,
				first.ConnectionID,
			)
		}
		second.Release()
		third.Release()
		assertNoPending(t, scheduler)
	})
}

func TestBackendAndConnectionAffinity(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
		ID:     "tier",
		Policy: PolicyRoundRobin,
		Backends: []SchedulerBackendConfig{
			{
				ID: "a",
				Connections: []SchedulerConnectionConfig{
					{ID: "a-1"},
					{ID: "a-2", MaxPending: 1},
					{ID: "a-bind", Pool: PoolBind},
				},
			},
			{
				ID:          "b",
				Connections: []SchedulerConnectionConfig{{ID: "b-1"}},
			},
		},
	}}})

	backendLease := mustSelect(t, scheduler, SelectRequest{
		Affinity: Affinity{BackendID: "b"},
	})
	if backendLease.BackendID != "b" {
		t.Fatalf("backend affinity selected %q, want b", backendLease.BackendID)
	}
	if backendLease.BackendAffinity() != (Affinity{BackendID: "b"}) {
		t.Fatalf("BackendAffinity() = %#v", backendLease.BackendAffinity())
	}
	backendLease.Release()

	connectionLease := mustSelect(t, scheduler, SelectRequest{
		Affinity: Affinity{ConnectionID: "a-2"},
	})
	if connectionLease.ConnectionID != "a-2" {
		t.Fatalf(
			"connection affinity selected %q, want a-2",
			connectionLease.ConnectionID,
		)
	}
	if connectionLease.ConnectionAffinity() != (Affinity{
		BackendID:    "a",
		ConnectionID: "a-2",
	}) {
		t.Fatalf("ConnectionAffinity() = %#v", connectionLease.ConnectionAffinity())
	}
	assertSelectError(t, scheduler, SelectRequest{
		Affinity: Affinity{ConnectionID: "a-2"},
	}, ErrBusy)
	connectionLease.Release()

	assertSelectError(t, scheduler, SelectRequest{
		Affinity: Affinity{BackendID: "b", ConnectionID: "a-1"},
	}, ErrInvalidAffinity)
	assertSelectError(t, scheduler, SelectRequest{
		Pool:     PoolBind,
		Affinity: Affinity{ConnectionID: "a-1"},
	}, ErrUnavailable)

	bindLease := mustSelect(t, scheduler, SelectRequest{
		Pool:     PoolBind,
		Affinity: Affinity{BackendID: "a"},
	})
	if bindLease.ConnectionID != "a-bind" || bindLease.Pool != PoolBind {
		t.Fatalf("bind selection = %#v", bindLease)
	}
	bindLease.Release()
}

func TestPoolSpecificTierFallback(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{
		{
			ID:     "regular-only",
			Policy: PolicyRoundRobin,
			Backends: []SchedulerBackendConfig{{
				ID:          "regular-backend",
				Connections: []SchedulerConnectionConfig{{ID: "regular"}},
			}},
		},
		{
			ID:     "bind-tier",
			Policy: PolicyRoundRobin,
			Backends: []SchedulerBackendConfig{{
				ID: "bind-backend",
				Connections: []SchedulerConnectionConfig{{
					ID:   "bind",
					Pool: PoolBind,
				}},
			}},
		},
	}})

	lease := mustSelect(t, scheduler, SelectRequest{Pool: PoolBind})
	if lease.TierID != "bind-tier" || lease.ConnectionID != "bind" {
		t.Fatalf("bind fallback selected %#v", lease)
	}
	lease.Release()
}

func TestWeightedSelectionAndZeroWeightChance(t *testing.T) {
	config := func(random RandomSource) SchedulerConfig {
		return SchedulerConfig{
			Random: random,
			Tiers: []SchedulerTierConfig{{
				ID:     "weighted",
				Policy: PolicyWeighted,
				Backends: []SchedulerBackendConfig{
					{ID: "zero", Weight: 0, Connections: []SchedulerConnectionConfig{{ID: "zero-1"}}},
					{ID: "low", Weight: 1, Connections: []SchedulerConnectionConfig{{ID: "low-1"}}},
					{ID: "high", Weight: 9, Connections: []SchedulerConnectionConfig{{ID: "high-1"}}},
				},
			}},
		}
	}

	high := mustScheduler(t, config(&sequenceRandom{values: []int{10, 1, 0}}))
	highLease := mustSelect(t, high, SelectRequest{})
	if highLease.BackendID != "high" {
		t.Fatalf("weighted high draw selected %q, want high", highLease.BackendID)
	}
	highLease.Release()

	zero := mustScheduler(t, config(&sequenceRandom{values: []int{0}}))
	zeroLease := mustSelect(t, zero, SelectRequest{})
	if zeroLease.BackendID != "zero" {
		t.Fatalf("weighted zero draw selected %q, want zero", zeroLease.BackendID)
	}
	zeroLease.Release()
}

func TestWeightedTriesAnotherBackendBeforeReportingBusy(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{
		Random: &sequenceRandom{values: []int{0}},
		Tiers: []SchedulerTierConfig{{
			ID:     "weighted",
			Policy: PolicyWeighted,
			Backends: []SchedulerBackendConfig{
				{
					ID:     "busy",
					Weight: 1,
					Connections: []SchedulerConnectionConfig{{
						ID:    "busy-1",
						State: ConnectionBusy,
					}},
				},
				{
					ID:          "ready",
					Weight:      1,
					Connections: []SchedulerConnectionConfig{{ID: "ready-1"}},
				},
			},
		}},
	})

	lease := mustSelect(t, scheduler, SelectRequest{})
	if lease.BackendID != "ready" {
		t.Fatalf("weighted fallback selected %q, want ready", lease.BackendID)
	}
	lease.Release()
}

func TestBestOfRollingFitnessOpenLDAPSourceContract(t *testing.T) {
	const sourceHash = "89723da861c7cf68f49c2b0b68fac892f6fdac50ced2c91e93191132b6e84680"

	contents, ok := pinnedOpenLDAPSource(t, "servers/lloadd/tier_bestof.c")
	if !ok {
		return
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != sourceHash {
		t.Fatalf("OpenLDAP tier_bestof.c SHA-256 = %s, want %s", got, sourceHash)
	}
	for _, anchor := range []string{
		"gettimeofday( &now, NULL );",
		"factor = 1 / ( pow( ( 1 / factor ) + 1, now.tv_usec / 1000000.0 ) - 1 );",
		"steps = now - b->b_last_update;",
		"&b->b_operation_count, 0, __ATOMIC_RELAXED",
		"&b->b_operation_time, 0, __ATOMIC_RELAXED",
		"if ( steps > 10 ) {",
		"factor = 0; /* No recent data */",
		"} else if ( steps > 1 ) {",
		"factor = 1 / ( pow( ( 1 / factor ) + 1, steps ) - 1 );",
		"b->b_fitness = ( factor * b->b_fitness + fitness / count ) /",
	} {
		if !strings.Contains(string(contents), anchor) {
			t.Fatalf("pinned OpenLDAP tier_bestof.c lacks %q", anchor)
		}
	}
}

func TestBestOfRollingFitnessDecayMatchesOpenLDAP(t *testing.T) {
	clock := &schedulerClock{value: time.Unix(1_800_000_000, 0)}
	scheduler := mustSchedulerWithClock(t, SchedulerConfig{
		Tiers: []SchedulerTierConfig{{
			ID:     "best",
			Policy: PolicyBestOf,
			Backends: []SchedulerBackendConfig{{
				ID:     "backend",
				Weight: 2,
				Connections: []SchedulerConnectionConfig{{
					ID: "connection",
				}},
			}},
		}},
	}, clock.Now)

	recordBackendLatency(t, scheduler, "backend", 80*time.Millisecond)
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "backend", 160_000)

	recordBackendLatency(t, scheduler, "backend", 20*time.Millisecond)
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "backend", 100_000)

	// A no-sample update leaves fitnessUpdated unchanged. The next sample is
	// therefore blended with two elapsed steps: 1/4 old and 3/4 latest.
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "backend", 100_000)
	recordBackendLatency(t, scheduler, "backend", 20*time.Millisecond)
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "backend", 55_000)

	// OpenLDAP discards stale fitness after more than ten elapsed steps.
	clock.Advance(10 * time.Second)
	assertBestOfFitness(t, scheduler, "backend", 55_000)
	recordBackendLatency(t, scheduler, "backend", 5*time.Millisecond)
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "backend", 10_000)
}

func TestBestOfProjectsCurrentWindowBySecondFraction(t *testing.T) {
	clock := &schedulerClock{value: time.Unix(1_800_000_000, 0)}
	scheduler := mustSchedulerWithClock(t, SchedulerConfig{
		Tiers: []SchedulerTierConfig{{
			ID:     "best",
			Policy: PolicyBestOf,
			Backends: []SchedulerBackendConfig{{
				ID:     "backend",
				Weight: 1,
				Connections: []SchedulerConnectionConfig{{
					ID: "connection",
				}},
			}},
		}},
	}, clock.Now)

	recordBackendLatency(t, scheduler, "backend", 100*time.Millisecond)
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "backend", 100_000)
	recordBackendLatency(t, scheduler, "backend", 20*time.Millisecond)
	clock.Advance(500 * time.Millisecond)

	oldWeight := math.Exp2(-0.5)
	want := oldWeight*100_000 + (1-oldWeight)*20_000
	assertBestOfFitness(t, scheduler, "backend", want)
}

func TestBestOfRecentWindowOutweighsPermanentHistory(t *testing.T) {
	clock := &schedulerClock{value: time.Unix(1_800_000_000, 0)}
	scheduler := mustSchedulerWithClock(t, SchedulerConfig{
		Random: &sequenceRandom{values: []int{0, 0}},
		Tiers: []SchedulerTierConfig{{
			ID:     "best",
			Policy: PolicyBestOf,
			Backends: []SchedulerBackendConfig{
				{ID: "recently-slow", Weight: 1, Connections: []SchedulerConnectionConfig{{ID: "a-1"}}},
				{ID: "steady", Weight: 1, Connections: []SchedulerConnectionConfig{{ID: "b-1"}}},
			},
		}},
	}, clock.Now)

	for range 100 {
		recordBackendLatency(t, scheduler, "recently-slow", time.Millisecond)
	}
	recordBackendLatency(t, scheduler, "steady", 20*time.Millisecond)
	clock.Advance(time.Second)
	assertBestOfFitness(t, scheduler, "recently-slow", 1_000)
	assertBestOfFitness(t, scheduler, "steady", 20_000)

	recordBackendLatency(t, scheduler, "recently-slow", 100*time.Millisecond)
	clock.Advance(time.Second)
	lease := mustSelect(t, scheduler, SelectRequest{})
	if lease.BackendID != "steady" {
		t.Fatalf("bestof selected %q, want steady", lease.BackendID)
	}
	lease.Release()
}

func TestBestOfUsesFirstResponseLatencyAndInverseWeight(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{
		Random: &sequenceRandom{values: []int{0, 0}},
		Tiers: []SchedulerTierConfig{{
			ID:     "best",
			Policy: PolicyBestOf,
			Backends: []SchedulerBackendConfig{
				{ID: "fast", Weight: 10, Connections: []SchedulerConnectionConfig{{ID: "fast-1"}}},
				{ID: "slow", Weight: 1, Connections: []SchedulerConnectionConfig{{ID: "slow-1"}}},
			},
		}},
	})

	recordBackendLatency(t, scheduler, "fast", 10*time.Millisecond)
	recordBackendLatency(t, scheduler, "slow", 50*time.Millisecond)

	// bestof compares weighted latency. 10ms*10 is less favorable than
	// 50ms*1, matching OpenLDAP's inverse weight direction for this policy.
	lease := mustSelect(t, scheduler, SelectRequest{})
	if lease.BackendID != "slow" {
		t.Fatalf("bestof selected %q, want slow", lease.BackendID)
	}
	lease.Release()
}

func TestBestOfFallsBackWithinTier(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{
		Random: &sequenceRandom{values: []int{0, 0}},
		Tiers: []SchedulerTierConfig{
			{
				ID:     "best",
				Policy: PolicyBestOf,
				Backends: []SchedulerBackendConfig{
					{
						ID:     "preferred",
						Weight: 1,
						Connections: []SchedulerConnectionConfig{{
							ID: "preferred-1",
						}},
					},
					{
						ID:          "fallback",
						Weight:      1,
						Connections: []SchedulerConnectionConfig{{ID: "fallback-1"}},
					},
				},
			},
			{
				ID:     "lower",
				Policy: PolicyRoundRobin,
				Backends: []SchedulerBackendConfig{{
					ID:          "lower-backend",
					Connections: []SchedulerConnectionConfig{{ID: "lower-1"}},
				}},
			},
		},
	})

	// Equal unknown fitness makes the second sampled backend preferred. Mark
	// fallback slower so the busy backend is preferred before RR fallback.
	recordBackendLatency(t, scheduler, "preferred", time.Millisecond)
	recordBackendLatency(t, scheduler, "fallback", 10*time.Millisecond)
	if err := scheduler.SetConnectionState("preferred-1", ConnectionBusy); err != nil {
		t.Fatalf("mark preferred busy: %v", err)
	}
	lease := mustSelect(t, scheduler, SelectRequest{})
	if lease.BackendID != "fallback" || lease.TierID != "best" {
		t.Fatalf("bestof fallback selected %#v", lease)
	}
	lease.Release()

	if err := scheduler.SetConnectionState("fallback-1", ConnectionBusy); err != nil {
		t.Fatalf("mark fallback busy: %v", err)
	}
	assertSelectError(t, scheduler, SelectRequest{}, ErrBusy)
}

func TestFirstResponseRecordedOnceAndAveraged(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
		ID:     "tier",
		Policy: PolicyRoundRobin,
		Backends: []SchedulerBackendConfig{{
			ID:          "backend",
			Connections: []SchedulerConnectionConfig{{ID: "connection"}},
		}},
	}}})

	first := mustSelect(t, scheduler, SelectRequest{})
	if !first.RecordFirstResponse(10 * time.Millisecond) {
		t.Fatal("first latency was not recorded")
	}
	if first.RecordFirstResponse(100 * time.Millisecond) {
		t.Fatal("duplicate latency was recorded")
	}
	first.Release()

	second := mustSelect(t, scheduler, SelectRequest{})
	second.Release()
	if !second.RecordFirstResponse(30 * time.Millisecond) {
		t.Fatal("latency after Release was not recorded")
	}
	if second.RecordFirstResponse(-time.Nanosecond) {
		t.Fatal("negative duplicate latency was recorded")
	}

	snapshot := scheduler.Snapshot()
	if len(snapshot.Backends) != 1 {
		t.Fatalf("backend snapshots = %d, want 1", len(snapshot.Backends))
	}
	backend := snapshot.Backends[0]
	if backend.FirstResponseSamples != 2 {
		t.Fatalf("samples = %d, want 2", backend.FirstResponseSamples)
	}
	if backend.MeanFirstResponseLatency != 20*time.Millisecond {
		t.Fatalf(
			"mean latency = %s, want 20ms",
			backend.MeanFirstResponseLatency,
		)
	}
	assertNoPending(t, scheduler)
}

func TestCopiedLeaseSharesLifecycleState(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
		ID:     "tier",
		Policy: PolicyRoundRobin,
		Backends: []SchedulerBackendConfig{{
			ID:          "backend",
			Connections: []SchedulerConnectionConfig{{ID: "connection"}},
		}},
	}}})

	lease := mustSelect(t, scheduler, SelectRequest{})
	copyOfLease := *lease
	if !copyOfLease.RecordFirstResponse(5 * time.Millisecond) {
		t.Fatal("copied lease did not record latency")
	}
	if lease.RecordFirstResponse(10 * time.Millisecond) {
		t.Fatal("original lease recorded duplicate latency")
	}
	if !lease.Release() {
		t.Fatal("original lease did not release capacity")
	}
	if copyOfLease.Release() {
		t.Fatal("copied lease released capacity twice")
	}
	assertNoPending(t, scheduler)
}

func TestConcurrentSelectionHonorsAtomicCapacity(t *testing.T) {
	const (
		connectionCount = 8
		connectionLimit = 2
		attemptCount    = 128
	)
	connections := make([]SchedulerConnectionConfig, 0, connectionCount)
	for index := 0; index < connectionCount; index++ {
		connections = append(connections, SchedulerConnectionConfig{
			ID:         fmt.Sprintf("connection-%d", index),
			MaxPending: connectionLimit,
		})
	}
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
		ID:     "tier",
		Policy: PolicyRoundRobin,
		Backends: []SchedulerBackendConfig{{
			ID:          "backend",
			MaxPending:  connectionCount * connectionLimit,
			Connections: connections,
		}},
	}}})

	start := make(chan struct{})
	release := make(chan struct{})
	results := make(chan error, attemptCount)
	var attempts sync.WaitGroup
	var workers sync.WaitGroup
	attempts.Add(attemptCount)
	workers.Add(attemptCount)
	for range attemptCount {
		go func() {
			defer workers.Done()
			<-start
			lease, err := scheduler.Select(SelectRequest{})
			results <- err
			attempts.Done()
			if lease != nil {
				<-release
				lease.Release()
			}
		}()
	}
	close(start)
	attempts.Wait()

	selected := 0
	busy := 0
	for range attemptCount {
		err := <-results
		switch {
		case err == nil:
			selected++
		case errors.Is(err, ErrBusy):
			busy++
		default:
			t.Fatalf("concurrent Select error = %v", err)
		}
	}
	if selected != connectionCount*connectionLimit {
		t.Fatalf(
			"selected = %d, want exact capacity %d",
			selected,
			connectionCount*connectionLimit,
		)
	}
	if busy != attemptCount-selected {
		t.Fatalf("busy = %d, want %d", busy, attemptCount-selected)
	}

	close(release)
	workers.Wait()
	assertNoPending(t, scheduler)
}

func TestSchedulerConcurrentStateLatencyAndRelease(t *testing.T) {
	scheduler := mustScheduler(t, SchedulerConfig{Tiers: []SchedulerTierConfig{{
		ID:     "tier",
		Policy: PolicyRoundRobin,
		Backends: []SchedulerBackendConfig{{
			ID:          "backend",
			Connections: []SchedulerConnectionConfig{{ID: "connection"}},
		}},
	}}})

	const iterations = 300
	var workers sync.WaitGroup
	workers.Add(5)
	for worker := 0; worker < 4; worker++ {
		go func(worker int) {
			defer workers.Done()
			for index := 0; index < iterations; index++ {
				lease, err := scheduler.Select(SelectRequest{})
				if err != nil {
					if !errors.Is(err, ErrBusy) {
						t.Errorf("Select: %v", err)
					}
					continue
				}
				var leaseRace sync.WaitGroup
				leaseRace.Add(2)
				go func() {
					defer leaseRace.Done()
					lease.RecordFirstResponse(time.Duration(worker+1) * time.Millisecond)
				}()
				go func() {
					defer leaseRace.Done()
					lease.Release()
					lease.Release()
				}()
				leaseRace.Wait()
				_ = scheduler.Snapshot()
			}
		}(worker)
	}
	go func() {
		defer workers.Done()
		for index := 0; index < iterations; index++ {
			state := ConnectionReady
			if index%2 == 0 {
				state = ConnectionBusy
			}
			if err := scheduler.SetConnectionState("connection", state); err != nil {
				t.Errorf("SetConnectionState: %v", err)
			}
		}
		_ = scheduler.SetConnectionState("connection", ConnectionReady)
	}()
	workers.Wait()
	assertNoPending(t, scheduler)
}

func TestNewSchedulerValidation(t *testing.T) {
	tests := []struct {
		name   string
		config SchedulerConfig
	}{
		{
			name: "invalid policy",
			config: SchedulerConfig{Tiers: []SchedulerTierConfig{{
				ID:     "tier",
				Policy: Policy("random"),
			}}},
		},
		{
			name: "duplicate backend",
			config: SchedulerConfig{Tiers: []SchedulerTierConfig{
				{ID: "one", Policy: PolicyRoundRobin, Backends: []SchedulerBackendConfig{{ID: "same"}}},
				{ID: "two", Policy: PolicyRoundRobin, Backends: []SchedulerBackendConfig{{ID: "same"}}},
			}},
		},
		{
			name: "duplicate connection",
			config: SchedulerConfig{Tiers: []SchedulerTierConfig{{
				ID:     "tier",
				Policy: PolicyRoundRobin,
				Backends: []SchedulerBackendConfig{
					{ID: "one", Connections: []SchedulerConnectionConfig{{ID: "same"}}},
					{ID: "two", Connections: []SchedulerConnectionConfig{{ID: "same"}}},
				},
			}}},
		},
		{
			name: "negative capacity",
			config: SchedulerConfig{Tiers: []SchedulerTierConfig{{
				ID:       "tier",
				Policy:   PolicyRoundRobin,
				Backends: []SchedulerBackendConfig{{ID: "backend", MaxPending: -1}},
			}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewScheduler(test.config); err == nil {
				t.Fatal("NewScheduler unexpectedly succeeded")
			}
		})
	}

	empty := mustScheduler(t, SchedulerConfig{})
	assertSelectError(t, empty, SelectRequest{}, ErrUnavailable)
	assertSelectError(t, empty, SelectRequest{Pool: Pool(99)}, nil)
}

func recordBackendLatency(
	t *testing.T,
	scheduler *Scheduler,
	backendID string,
	latency time.Duration,
) {
	t.Helper()
	lease := mustSelect(t, scheduler, SelectRequest{
		Affinity: Affinity{BackendID: backendID},
	})
	if !lease.RecordFirstResponse(latency) {
		t.Fatalf("RecordFirstResponse(%q) failed", backendID)
	}
	lease.Release()
}

type schedulerClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *schedulerClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *schedulerClock) Advance(elapsed time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.value = clock.value.Add(elapsed)
}

func mustSchedulerWithClock(
	t *testing.T,
	config SchedulerConfig,
	now func() time.Time,
) *Scheduler {
	t.Helper()
	scheduler, err := newScheduler(config, now)
	if err != nil {
		t.Fatalf("newScheduler: %v", err)
	}
	return scheduler
}

func assertBestOfFitness(
	t *testing.T,
	scheduler *Scheduler,
	backendID string,
	want float64,
) {
	t.Helper()
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	backend := scheduler.backends[backendID]
	if backend == nil {
		t.Fatalf("unknown backend %q", backendID)
	}
	now := scheduler.now()
	scheduler.rollBackendFitnessLocked(backend, now)
	got := backendFitnessAt(backend, now)
	if math.Abs(got-want) > 1e-9*math.Max(1, math.Abs(want)) {
		t.Fatalf("backend %q fitness = %.9f us, want %.9f us", backendID, got, want)
	}
}

func mustScheduler(t *testing.T, config SchedulerConfig) *Scheduler {
	t.Helper()
	scheduler, err := NewScheduler(config)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return scheduler
}

func mustSelect(
	t *testing.T,
	scheduler *Scheduler,
	request SelectRequest,
) *Lease {
	t.Helper()
	lease, err := scheduler.Select(request)
	if err != nil {
		t.Fatalf("Select(%#v): %v", request, err)
	}
	if lease == nil {
		t.Fatalf("Select(%#v) returned a nil lease", request)
	}
	return lease
}

func assertSelectError(
	t *testing.T,
	scheduler *Scheduler,
	request SelectRequest,
	want error,
) {
	t.Helper()
	lease, err := scheduler.Select(request)
	if lease != nil {
		lease.Release()
		t.Fatalf("Select(%#v) returned lease %#v, want error", request, lease)
	}
	if want == nil {
		if err == nil {
			t.Fatalf("Select(%#v) unexpectedly succeeded", request)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("Select(%#v) error = %v, want %v", request, err, want)
	}
}

func assertNoPending(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	snapshot := scheduler.Snapshot()
	for _, backend := range snapshot.Backends {
		if backend.Pending != 0 {
			t.Errorf("backend %q pending = %d", backend.BackendID, backend.Pending)
		}
	}
	for _, connection := range snapshot.Connections {
		if connection.Pending != 0 {
			t.Errorf("connection %q pending = %d", connection.ID, connection.Pending)
		}
	}
}
