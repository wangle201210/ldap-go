package server

import (
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
