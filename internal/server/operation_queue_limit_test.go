package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestOperationQueuePendingLimitExcludesExecutingCandidate(t *testing.T) {
	t.Parallel()

	queue := newOperationQueue()
	first := &queuedOperation{}
	if result := queue.push(first, 0); result != operationQueuePushed {
		t.Fatalf("first push = %d, want pushed", result)
	}
	if result := queue.push(&queuedOperation{}, 0); result !=
		operationQueueLimitExceeded {
		t.Fatalf("first pending push = %d, want limit exceeded", result)
	}
	if operation, ok := queue.pop(); !ok || operation != first {
		t.Fatalf("pop = %#v, %t", operation, ok)
	}

	for index := 0; index < 2; index++ {
		if result := queue.push(&queuedOperation{}, 2); result !=
			operationQueuePushed {
			t.Fatalf("pending push %d = %d, want pushed", index, result)
		}
	}
	if result := queue.push(&queuedOperation{}, 2); result !=
		operationQueueLimitExceeded {
		t.Fatalf("overflow push = %d, want limit exceeded", result)
	}

	queue.complete()
	if result := queue.push(&queuedOperation{}, 2); result != operationQueuePushed {
		t.Fatalf("push after completion = %d, want pushed", result)
	}
}

func TestTrackedOperationAbandonability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		request   ldapwire.Request
		abandoned bool
	}{
		{name: "Search", request: ldapwire.SearchRequest{}, abandoned: true},
		{name: "Modify", request: ldapwire.ModifyRequest{}, abandoned: true},
		{name: "Extended", request: ldapwire.ExtendedRequest{Name: passwordModifyOID}, abandoned: true},
		{name: "Bind", request: ldapwire.BindRequest{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := newTrackedOperation(context.Background(), ldapwire.Message{
				ID:      1,
				Request: test.request,
			})
			if !operation.start() {
				t.Fatal("operation did not start")
			}
			operation.requestAbandon()
			if got := operation.stopMode() == operationAbandoned; got != test.abandoned {
				t.Fatalf("abandoned = %v, want %v", got, test.abandoned)
			}
			operation.finish()
		})
	}
}

func TestConnectionReadBarrierClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		message ldapwire.Message
		barrier bool
	}{
		{name: "ordinary Search", message: ldapwire.Message{Request: ldapwire.SearchRequest{}}},
		{name: "Compare", message: ldapwire.Message{Request: ldapwire.CompareRequest{}}},
		{name: "Who Am I", message: ldapwire.Message{Request: ldapwire.ExtendedRequest{Name: whoAmIOID}}},
		{name: "Bind", message: ldapwire.Message{Request: ldapwire.BindRequest{}}, barrier: true},
		{name: "Modify", message: ldapwire.Message{Request: ldapwire.ModifyRequest{}}},
		{name: "Password Modify", message: ldapwire.Message{Request: ldapwire.ExtendedRequest{Name: passwordModifyOID}}},
		{name: "paged Search", message: ldapwire.Message{
			Request:  ldapwire.SearchRequest{},
			Controls: []ldapwire.Control{{OID: pagedResultsControlOID}},
		}},
		{name: "VLV Search", message: ldapwire.Message{
			Request:  ldapwire.SearchRequest{},
			Controls: []ldapwire.Control{{OID: vlvRequestControlOID}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := connectionReadBarrier(test.message); got != test.barrier {
				t.Fatalf("connectionReadBarrier() = %v, want %v", got, test.barrier)
			}
		})
	}
}

func TestTransactionAdmissionDisablesConcurrentClassification(t *testing.T) {
	t.Parallel()

	admission := &atomic.Bool{}
	state := &connectionState{transactionAdmission: admission}
	message := ldapwire.Message{Request: ldapwire.SearchRequest{}}
	if !connectionOperationCanRunConcurrent(state, message) {
		t.Fatal("ordinary Search was not concurrent before transaction admission")
	}
	admission.Store(true)
	if connectionOperationCanRunConcurrent(state, message) {
		t.Fatal("Search remained concurrent during transaction admission")
	}
	admission.Store(false)
	if !connectionOperationCanRunConcurrent(state, message) {
		t.Fatal("ordinary Search did not recover after transaction admission")
	}
}

func TestOperationQueueConcurrentSlotsAndFence(t *testing.T) {
	t.Parallel()

	queue := newOperationQueue(2)
	first := &queuedOperation{concurrent: true}
	second := &queuedOperation{concurrent: true}
	fence := &queuedOperation{}
	for _, operation := range []*queuedOperation{first, second, fence} {
		if result := queue.push(operation, 10); result != operationQueuePushed {
			t.Fatalf("push = %d", result)
		}
	}
	if operation, ok := queue.pop(); !ok || operation != first {
		t.Fatalf("first pop = %#v, %v", operation, ok)
	}
	if operation, ok := queue.pop(); !ok || operation != second {
		t.Fatalf("second pop = %#v, %v", operation, ok)
	}
	popped := make(chan *queuedOperation, 1)
	go func() {
		operation, _ := queue.pop()
		popped <- operation
	}()
	queue.complete()
	select {
	case operation := <-popped:
		t.Fatalf("fence passed an active operation: %#v", operation)
	case <-time.After(20 * time.Millisecond):
	}
	queue.complete()
	select {
	case operation := <-popped:
		if operation != fence {
			t.Fatalf("fence pop = %#v", operation)
		}
	case <-time.After(time.Second):
		t.Fatal("fence did not run after active operations completed")
	}
	queue.complete()
	queue.close()
}

func TestOperationQueueRetainedByteLimitAndRelease(t *testing.T) {
	t.Parallel()

	queue := newOperationQueue(1)
	queue.maximumRetainedBytes = 10
	releases := 0
	newQueued := func(size int64) *queuedOperation {
		return &queuedOperation{
			retainedBytes: size,
			releaseRetained: func() {
				releases++
			},
		}
	}
	first := newQueued(6)
	if result := queue.push(first, 10); result != operationQueuePushed {
		t.Fatalf("first push = %d", result)
	}
	if result := queue.push(newQueued(6), 10); result != operationQueueLimitExceeded {
		t.Fatalf("byte overflow push = %d", result)
	}
	if operation, ok := queue.pop(); !ok || operation != first {
		t.Fatalf("pop = %#v, %v", operation, ok)
	}
	queue.complete(first)
	if queue.retainedBytes != 0 || releases != 1 {
		t.Fatalf("complete retained=%d releases=%d", queue.retainedBytes, releases)
	}

	removed := newQueued(4)
	if queue.push(removed, 10) != operationQueuePushed || queue.remove(0) != removed {
		t.Fatal("remove did not return the retained operation")
	}
	discarded := newQueued(4)
	if queue.push(discarded, 10) != operationQueuePushed || len(queue.discardPending()) != 1 {
		t.Fatal("discard did not return the retained operation")
	}
	closed := newQueued(4)
	if queue.push(closed, 10) != operationQueuePushed {
		t.Fatal("close fixture push failed")
	}
	queue.close()
	if queue.retainedBytes != 0 || releases != 4 {
		t.Fatalf("final retained=%d releases=%d", queue.retainedBytes, releases)
	}
}

func TestOperationQueueNegativePendingLimitAllowsOnlyExecutingOperation(t *testing.T) {
	t.Parallel()

	queue := newOperationQueue()
	if result := queue.push(&queuedOperation{}, -1); result != operationQueuePushed {
		t.Fatalf("first push = %d, want pushed", result)
	}
	if result := queue.push(&queuedOperation{}, -1); result !=
		operationQueueLimitExceeded {
		t.Fatalf("pending push = %d, want limit exceeded", result)
	}
}
