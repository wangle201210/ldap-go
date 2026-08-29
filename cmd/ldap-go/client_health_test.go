package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestHealthCommandAgainstRunningServer(t *testing.T) {
	uri := startLDAPHealthTestServer(t)
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"health",
		"-H", uri,
		"-x",
		"-D", clientToolRootDN,
		"-w", clientToolRootPassword,
		"-json",
	}, "")
	if exitCode != 0 || stderr != "" {
		t.Fatalf("health exit=%d stderr=%q stdout=%q", exitCode, stderr, stdout)
	}
	var report healthReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("decode health report: %v", err)
	}
	if !report.Healthy || report.Endpoint != uri || len(report.Consumers) != 0 {
		t.Fatalf("health report = %#v", report)
	}
}

func TestParseReplicationConsumerHealth(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 29, 4, 0, 0, 0, time.UTC)
	consumer, err := parseReplicationConsumerHealth(
		"Consumer 0",
		[]string{
			"state=retrying",
			"rid=007",
			"partition=dc=example,dc=com",
			"provider=ldap://provider.example",
			"attempts=4",
			"retries=3",
			"degradedSince=20260829035900Z",
			"lastError=connection refused",
		},
		now,
		2*time.Minute,
	)
	if err != nil {
		t.Fatalf("parseReplicationConsumerHealth(): %v", err)
	}
	if !consumer.Healthy || consumer.RID != "007" || consumer.Attempts != 4 ||
		consumer.Retries != 3 || consumer.LastError != "connection refused" {
		t.Fatalf("consumer = %#v", consumer)
	}

	consumer, err = parseReplicationConsumerHealth(
		"Consumer 0",
		[]string{"state=retrying", "degradedSince=20260829035000Z"},
		now,
		2*time.Minute,
	)
	if err != nil || consumer.Healthy || consumer.UnhealthyReason == "" {
		t.Fatalf("stale consumer = %#v, err %v", consumer, err)
	}
}

func TestMonitorReplicationConsumerCount(t *testing.T) {
	t.Parallel()
	if count, err := monitorReplicationConsumerCount([]string{
		"ldap-go 0.1-dev",
		"replicationConsumers=2",
	}); err != nil || count != 2 {
		t.Fatalf("count = %d, err %v", count, err)
	}
	for _, values := range [][]string{
		{"ldap-go 0.1-dev"},
		{"replicationConsumers=-1"},
		{"replicationConsumers=2x"},
	} {
		if _, err := monitorReplicationConsumerCount(values); err == nil {
			t.Fatalf("values %q were accepted", values)
		}
	}
}

func TestEvaluateReplicationConsumerHealthStates(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	tests := []struct {
		state    string
		degraded time.Time
		healthy  bool
	}{
		{state: "healthy", healthy: true},
		{state: "connecting", degraded: now.Add(-time.Second), healthy: true},
		{state: "synchronizing", degraded: now.Add(-time.Hour), healthy: false},
		{state: "retrying", degraded: now.Add(-time.Hour), healthy: false},
		{state: "configured", healthy: false},
		{state: "stopped", healthy: false},
		{state: "unexpected", healthy: false},
	}
	for _, test := range tests {
		var degraded *time.Time
		if !test.degraded.IsZero() {
			value := test.degraded
			degraded = &value
		}
		healthy, _ := evaluateReplicationConsumerHealth(replicationConsumerHealth{
			State:         test.state,
			DegradedSince: degraded,
		}, now, time.Minute)
		if healthy != test.healthy {
			t.Errorf("state %q healthy = %v, want %v", test.state, healthy, test.healthy)
		}
	}
}

func TestWriteHealthReportJSON(t *testing.T) {
	t.Parallel()

	report := healthReport{
		Healthy:   false,
		CheckedAt: time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC),
		Endpoint:  "ldapi://%2Frun%2Fldap-go.sock",
		Consumers: []replicationConsumerHealth{{
			Name:            "Consumer 0",
			State:           "stopped",
			Healthy:         false,
			UnhealthyReason: "replication worker stopped",
		}},
	}
	var output bytes.Buffer
	if err := writeHealthReport(&output, report, true); err != nil {
		t.Fatalf("writeHealthReport(): %v", err)
	}
	var decoded healthReport
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output: %v", err)
	}
	if decoded.Healthy || len(decoded.Consumers) != 1 ||
		!strings.Contains(output.String(), "replication worker stopped") {
		t.Fatalf("decoded report/output = %#v / %q", decoded, output.String())
	}
}

func startLDAPHealthTestServer(t *testing.T) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPClientToolDirectory(t, store)
	monitor := directory.Entry{
		DN: "olcDatabase={9}monitor,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("olcMonitorConfig")}},
			{Description: "olcDatabase", Values: [][]byte{[]byte("{9}monitor")}},
			{Description: "olcRootDN", Values: [][]byte{[]byte(clientToolRootDN)}},
			{Description: "olcRootPW", Values: [][]byte{[]byte(clientToolRootPassword)}},
			{Description: "olcAccess", Values: [][]byte{[]byte("{0}to * by * read")}},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(monitor, false)
	}); err != nil {
		t.Fatalf("seed monitor configuration: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       clientToolRootDN,
		RootPassword: []byte(clientToolRootPassword),
		AccessPolicy: clientToolAccessPolicy(t),
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("health test server did not stop")
		}
	})
	return "ldap://" + listener.Addr().String()
}
