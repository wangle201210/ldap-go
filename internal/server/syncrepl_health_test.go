package server

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerHealthLifecycle(t *testing.T) {
	t.Parallel()

	config := syncConsumerConfig{
		rid:          7,
		partition:    "dc=example,dc=com",
		providerURLs: []string{"ldap://one.example", "ldaps://two.example"},
	}
	health := newSyncConsumerHealth(config)
	now := time.Date(2026, time.August, 29, 3, 4, 5, 0, time.UTC)
	health.beginAttempt(config.providerURLs[0], now)
	health.loadedCookie([]byte("persisted-cookie"))
	health.connected()
	health.succeeded([]byte("new-cookie"), now.Add(time.Second))
	health.waiting(errors.New("provider unavailable"), now.Add(2*time.Second))

	snapshot := health.snapshot()
	if snapshot.state != "retrying" || snapshot.rid != 7 ||
		snapshot.partition != config.partition || snapshot.attempts != 1 ||
		snapshot.retries != 1 || snapshot.provider != config.providerURLs[0] {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if string(snapshot.cookie) != "new-cookie" ||
		!snapshot.lastAttempt.Equal(now) ||
		!snapshot.lastSuccess.Equal(now.Add(time.Second)) ||
		!snapshot.degradedAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("snapshot timing/cookie = %#v", snapshot)
	}

	snapshot.cookie[0] = 'X'
	if got := string(health.snapshot().cookie); got != "new-cookie" {
		t.Fatalf("snapshot cookie mutated health state: %q", got)
	}
}

func TestSyncConsumerHealthBoundsMonitorValues(t *testing.T) {
	t.Parallel()

	health := newSyncConsumerHealth(syncConsumerConfig{
		rid:          1,
		partition:    "dc=example,dc=com",
		providerURLs: []string{"ldap://provider.example"},
	})
	health.loadedCookie([]byte(strings.Repeat("c", 5000)))
	health.waiting(errors.New(strings.Repeat("x", 1023)+"\u754c"), time.Now())
	snapshot := health.snapshot()
	if len(snapshot.lastError) > 1024 || !utf8.ValidString(snapshot.lastError) {
		t.Fatalf("bounded error length/UTF-8 = %d/%v", len(snapshot.lastError), utf8.ValidString(snapshot.lastError))
	}

	values := strings.Join(snapshot.monitorValues(), "\n")
	if !strings.Contains(values, "cookieBytes=5000") ||
		!strings.Contains(values, "cookieSHA256=") ||
		!strings.Contains(values, "configuredProvider=ldap://provider.example") {
		t.Fatalf("monitor values = %q", values)
	}
}

func TestSyncConsumerHealthConcurrentSnapshots(t *testing.T) {
	t.Parallel()

	health := newSyncConsumerHealth(syncConsumerConfig{
		rid:          2,
		partition:    "dc=example,dc=org",
		providerURLs: []string{"ldap://provider.example"},
	})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				health.beginAttempt("ldap://provider.example", time.Now())
				health.connected()
				health.succeeded([]byte("cookie"), time.Now())
				_ = health.snapshot()
			}
		}()
	}
	workers.Wait()
	if got := health.snapshot().attempts; got != 800 {
		t.Fatalf("attempts = %d, want 800", got)
	}
}

func TestSyncConsumerManagerReportsConfiguredConsumers(t *testing.T) {
	t.Parallel()

	manager := newSyncConsumerManager(&Server{})
	manager.configure(&runtimeState{databases: []runtimeDatabase{{
		partition: "dc=example,dc=com",
		syncConsumers: []syncConsumerConfig{{
			rid:          3,
			partition:    "dc=example,dc=com",
			providerURLs: []string{"ldap://provider.example"},
		}},
	}}})
	snapshots := manager.healthSnapshots()
	if len(snapshots) != 1 || snapshots[0].state != "configured" || snapshots[0].rid != 3 {
		t.Fatalf("snapshots = %#v", snapshots)
	}
}

func TestSyncConsumerProgressDoesNotReportInitialRefreshHealthy(t *testing.T) {
	t.Parallel()

	config := syncConsumerConfig{
		rid:          4,
		partition:    "dc=example,dc=com",
		providerURLs: []string{"ldap://provider.example"},
	}
	server := &Server{clock: time.Now}
	manager := newSyncConsumerManager(server)
	server.syncConsumers = manager
	health := manager.healthFor(syncConsumerWorkerKey(config), config)
	health.beginAttempt(config.providerURLs[0], time.Now())
	health.connected()
	manager.observeProgress(config, []byte("initial-refresh-cookie"))
	snapshot := health.snapshot()
	if snapshot.state != "synchronizing" || string(snapshot.cookie) != "initial-refresh-cookie" ||
		!snapshot.lastSuccess.IsZero() {
		t.Fatalf("initial refresh progress = %#v", snapshot)
	}
	manager.observeSuccess(config, []byte("converged-cookie"))
	if snapshot = health.snapshot(); snapshot.state != "healthy" || snapshot.lastSuccess.IsZero() {
		t.Fatalf("converged health = %#v", snapshot)
	}
}

func TestMonitorIncludesConfiguredReplicationConsumers(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedMonitorConfiguration(t, store)
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	instance.syncConsumers.mu.Lock()
	instance.syncConsumers.desired = []syncConsumerConfig{{
		rid:          9,
		partition:    "dc=example,dc=com",
		providerURLs: []string{"ldap://provider.example"},
	}}
	instance.syncConsumers.mu.Unlock()

	entries := instance.monitorEntries(instance.runtime.Load())
	var containerFound, consumerFound bool
	for _, entry := range entries {
		switch {
		case entry.DN == "cn=Monitor":
			values := strings.Join(byteValuesToStrings(entry.Values("monitoredInfo")), "\n")
			if !strings.Contains(values, "replicationConsumers=1") {
				t.Fatalf("monitor root monitoredInfo = %q", values)
			}
		case entry.DN == "cn=Replication,cn=Monitor":
			containerFound = true
		case strings.HasSuffix(entry.DN, ",cn=Replication,cn=Monitor"):
			consumerFound = true
			values := strings.Join(byteValuesToStrings(entry.Values("monitoredInfo")), "\n")
			if !strings.Contains(values, "state=configured") ||
				!strings.Contains(values, "rid=009") {
				t.Fatalf("consumer monitoredInfo = %q", values)
			}
		}
	}
	if !containerFound || !consumerFound {
		t.Fatalf("replication monitor entries found container=%v consumer=%v", containerFound, consumerFound)
	}
}
