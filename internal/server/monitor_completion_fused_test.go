package server

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestMonitorCompleteOperationWithState(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		started   bool
		executing uint64
	}{
		{name: "started", started: true, executing: 1},
		{name: "not started", started: false, executing: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			monitor := newMonitorState()
			connection := &monitorConnection{
				authorizationDN: "uid=stale,dc=example,dc=com",
				localAddress:    "IP=stale-local",
				peerAddress:     "IP=stale-peer",
				activityAt:      time.Unix(1, 0).UTC(),
				executing:       test.executing,
			}
			state := &connectionState{
				boundDN: "uid=alice,dc=example,dc=com",
				connection: &monitorCompletionTestConnection{
					local:  monitorCompletionTestAddress("current-local"),
					remote: monitorCompletionTestAddress("current-peer"),
				},
			}
			before := time.Now().UTC()

			monitor.completeOperationWithState(
				connection,
				state,
				ldapwire.SearchRequest{},
				test.started,
			)
			after := time.Now().UTC()

			connection.mu.RLock()
			gotAuthorizationDN := connection.authorizationDN
			gotLocalAddress := connection.localAddress
			gotPeerAddress := connection.peerAddress
			gotExecuting := connection.executing
			gotCompleted := connection.completed
			gotActivityAt := connection.activityAt
			connection.mu.RUnlock()
			wantExecuting := test.executing
			if test.started {
				wantExecuting--
			}
			if gotAuthorizationDN != state.boundDN {
				t.Fatalf("authorizationDN = %q, want %q", gotAuthorizationDN, state.boundDN)
			}
			if gotLocalAddress != "IP=current-local" || gotPeerAddress != "IP=current-peer" {
				t.Fatalf("addresses = %q, %q", gotLocalAddress, gotPeerAddress)
			}
			if gotExecuting != wantExecuting || gotCompleted != 1 {
				t.Fatalf("operation counters = executing %d, completed %d", gotExecuting, gotCompleted)
			}
			if gotActivityAt.Before(before) || gotActivityAt.After(after) || gotActivityAt.Location() != time.UTC {
				t.Fatalf("activityAt = %v, want UTC time in completion interval", gotActivityAt)
			}
			if got := monitor.operations[2].completed.Load(); got != 1 {
				t.Fatalf("Search completed = %d, want 1", got)
			}
		})
	}
}

func TestMonitorCompleteOperationWithStateConcurrent(t *testing.T) {
	t.Parallel()

	const completions = 32
	monitor := newMonitorState()
	connection := &monitorConnection{executing: completions}
	state := &connectionState{
		boundDN: "uid=alice,dc=example,dc=com",
		connection: &monitorCompletionTestConnection{
			local:  monitorCompletionTestAddress("current-local"),
			remote: monitorCompletionTestAddress("current-peer"),
		},
	}
	var waitGroup sync.WaitGroup
	for range completions {
		waitGroup.Go(func() {
			monitor.completeOperationWithState(
				connection,
				state,
				ldapwire.SearchRequest{},
				true,
			)
		})
	}
	waitGroup.Wait()

	connection.mu.RLock()
	gotExecuting := connection.executing
	gotCompleted := connection.completed
	connection.mu.RUnlock()
	if gotExecuting != 0 || gotCompleted != completions {
		t.Fatalf("operation counters = executing %d, completed %d", gotExecuting, gotCompleted)
	}
	if got := monitor.operations[2].completed.Load(); got != completions {
		t.Fatalf("Search completed = %d, want %d", got, completions)
	}
}

type monitorCompletionTestConnection struct {
	local  net.Addr
	remote net.Addr
}

func (*monitorCompletionTestConnection) Read([]byte) (int, error) { return 0, io.EOF }

func (*monitorCompletionTestConnection) Write(value []byte) (int, error) {
	return len(value), nil
}

func (*monitorCompletionTestConnection) Close() error { return nil }

func (connection *monitorCompletionTestConnection) LocalAddr() net.Addr {
	return connection.local
}

func (connection *monitorCompletionTestConnection) RemoteAddr() net.Addr {
	return connection.remote
}

func (*monitorCompletionTestConnection) SetDeadline(time.Time) error      { return nil }
func (*monitorCompletionTestConnection) SetReadDeadline(time.Time) error  { return nil }
func (*monitorCompletionTestConnection) SetWriteDeadline(time.Time) error { return nil }

type monitorCompletionTestAddress string

func (monitorCompletionTestAddress) Network() string { return "test" }

func (address monitorCompletionTestAddress) String() string { return string(address) }
