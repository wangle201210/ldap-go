package server

import (
	"testing"
	"testing/synctest"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func inlineBindTestMessage(id int64, dn, password string) ldapwire.Message {
	return ldapwire.Message{
		ID: id,
		Request: ldapwire.BindRequest{
			Version: 3,
			Name:    dn,
			Authentication: ldapwire.Authentication{
				Simple: []byte(password),
			},
		},
	}
}

func TestOperationQueueIdleSimpleBindEligibility(t *testing.T) {
	for _, test := range []struct {
		name    string
		request ldapwire.Request
		want    bool
	}{
		{name: "simple v3", request: ldapwire.BindRequest{Version: 3}, want: true},
		{name: "simple v2", request: ldapwire.BindRequest{Version: 2}},
		{name: "invalid version", request: ldapwire.BindRequest{Version: 4}},
		{name: "SASL", request: ldapwire.BindRequest{Version: 3,
			Authentication: ldapwire.Authentication{IsSASL: true, SASLMechanism: "PLAIN"}}},
		{name: "StartTLS", request: ldapwire.ExtendedRequest{Name: startTLSOID}},
		{name: "Search", request: ldapwire.SearchRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			queue := newOperationQueue(2)
			operation := &queuedOperation{message: ldapwire.Message{Request: test.request}}
			if got := queue.tryClaimIdleSimpleBind(operation); got != test.want {
				t.Fatalf("claim = %v, want %v", got, test.want)
			}
			if test.want {
				queue.complete(operation)
			} else if queue.push(operation, 0) != operationQueuePushed {
				t.Fatal("ineligible request did not retain queued admission")
			}
			queue.close()
		})
	}
}

func TestOperationQueueIdleSimpleBindFallback(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*operationQueue)
		want  operationQueuePushResult
	}{
		{name: "queued", setup: func(queue *operationQueue) {
			queue.push(&queuedOperation{}, 1)
		}},
		{name: "active", setup: func(queue *operationQueue) {
			queue.push(&queuedOperation{concurrent: true}, 0)
			queue.pop()
		}},
		{name: "active fence", setup: func(queue *operationQueue) {
			queue.push(&queuedOperation{}, 0)
			queue.pop()
		}},
		{name: "fence without active", setup: func(queue *operationQueue) {
			queue.fence = true
		}},
		{name: "closed", setup: (*operationQueue).close, want: operationQueueClosed},
		{name: "draining", setup: (*operationQueue).closeAndDrain, want: operationQueueClosed},
		{name: "byte limit", setup: func(queue *operationQueue) {
			queue.maximumRetainedBytes = 9
		}, want: operationQueueLimitExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			queue := newOperationQueue(2)
			test.setup(queue)
			operation := &queuedOperation{message: inlineBindTestMessage(1, "", ""), retainedBytes: 10}
			active, fence, retained, pending := queue.active, queue.fence, queue.retainedBytes, queue.pending()
			if queue.tryClaimIdleSimpleBind(operation) {
				t.Fatal("claimed a non-idle or limited queue")
			}
			if queue.active != active || queue.fence != fence ||
				queue.retainedBytes != retained || queue.pending() != pending {
				t.Fatal("failed claim changed queue state")
			}
			if got := queue.push(operation, 1); got != test.want {
				t.Fatalf("fallback push = %v, want %v", got, test.want)
			}
			queue.close()
		})
	}
}

func TestOperationQueueIdleSimpleBindAdmissionAndCompletion(t *testing.T) {
	for _, maxPending := range []int{-1, 0, 1} {
		queue := newOperationQueue(2)
		queue.maximumRetainedBytes = 10
		releases := 0
		operation := &queuedOperation{
			message: inlineBindTestMessage(1, "", ""), retainedBytes: 10,
			releaseRetained: func() { releases++ },
		}
		if !queue.tryClaimIdleSimpleBind(operation) {
			t.Fatal("idle Bind was not admitted at the byte limit")
		}
		if queue.active != 1 || !queue.fence || queue.pending() != 0 || queue.retainedBytes != 10 {
			t.Fatalf("claim: active=%d fence=%v pending=%d retained=%d",
				queue.active, queue.fence, queue.pending(), queue.retainedBytes)
		}
		next := &queuedOperation{concurrent: true, retainedBytes: 1}
		if got := queue.push(next, maxPending); got != operationQueueLimitExceeded {
			t.Fatalf("byte-limited push = %v", got)
		}
		next.retainedBytes = 0
		want := operationQueuePushed
		if maxPending <= 0 {
			want = operationQueueLimitExceeded
		}
		if got := queue.push(next, maxPending); got != want {
			t.Fatalf("maxPending=%d push = %v, want %v", maxPending, got, want)
		}
		queue.complete(operation)
		if queue.active != 0 || queue.fence || queue.retainedBytes != 0 || releases != 1 {
			t.Fatalf("complete: active=%d fence=%v retained=%d releases=%d",
				queue.active, queue.fence, queue.retainedBytes, releases)
		}
		if operation.releaseRetainedBytes() {
			t.Fatal("completion released retained bytes twice")
		}
		queue.close()
	}
}

func TestOperationQueueIdleSimpleBindWorkerFenceAndClose(t *testing.T) {
	for _, drain := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			queue := newOperationQueue(2)
			bind := &queuedOperation{message: inlineBindTestMessage(1, "", ""), retainedBytes: 10}
			if !queue.tryClaimIdleSimpleBind(bind) {
				t.Fatal("idle claim failed")
			}
			next := &queuedOperation{concurrent: true, retainedBytes: 4}
			if queue.push(next, 1) != operationQueuePushed {
				t.Fatal("push behind inline Bind failed")
			}
			popped := operationQueuePopWaiters(queue, 2)
			synctest.Wait()
			if len(popped) != 0 {
				t.Fatal("worker passed the inline Bind fence")
			}
			if drain {
				queue.closeAndDrain()
			} else {
				queue.close()
			}
			synctest.Wait()
			if drain && len(popped) != 0 {
				t.Fatal("drain passed the inline Bind fence")
			}
			if queue.retainedBytes < bind.retainedBytes {
				t.Fatal("close released executing Bind bytes")
			}
			queue.complete(bind)
			synctest.Wait()
			if len(popped) != 2 {
				t.Fatalf("close left %d workers waiting", 2-len(popped))
			}
			executed := 0
			for range 2 {
				if operation := <-popped; operation != nil {
					if operation != next || !drain {
						t.Fatal("unexpected operation after close")
					}
					executed++
					queue.complete(operation)
				}
			}
			if (drain && executed != 1) || queue.retainedBytes != 0 || queue.active != 0 || queue.fence {
				t.Fatalf("drain=%v executed=%d retained=%d active=%d fence=%v",
					drain, executed, queue.retainedBytes, queue.active, queue.fence)
			}
		})
	}
}
