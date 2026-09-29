package server

import (
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// Keep the pre-optimization implementation as the count and allocation baseline.
func referenceQueuePendingAfterPush(queue *operationQueue, next *queuedOperation) int {
	items := make([]*queuedOperation, 0, len(queue.items)+1)
	items = append(items, queue.items...)
	items = append(items, next)
	pending := len(items)
	available := queue.maximum - queue.active
	if queue.fence || available < 0 {
		available = 0
	}
	for _, item := range items {
		if available == 0 {
			break
		}
		if !item.concurrent {
			if queue.active == 0 && pending == len(items) {
				pending--
			}
			break
		}
		pending--
		available--
	}
	return pending
}

func TestOperationQueueAdmissionReferenceEquivalence(t *testing.T) {
	t.Parallel()

	for length := range 7 {
		// Enumerate every concurrent/exclusive ordering, including the candidate.
		for pattern := range 1 << (length + 1) {
			backing := make([]*queuedOperation, length+2)
			for index := range backing {
				backing[index] = &queuedOperation{concurrent: pattern&(1<<index) != 0}
			}
			before := slices.Clone(backing)
			next := &queuedOperation{concurrent: pattern&(1<<length) != 0}
			for _, maximum := range []int{-1, 0, 1, 2, 4, 8} {
				for _, active := range []int{0, 1, 2, 4, 8, 9} {
					for _, fence := range []bool{false, true} {
						queue := &operationQueue{
							items:   backing[:length],
							maximum: maximum,
							active:  active,
							fence:   fence,
						}
						queue.mu.Lock()
						want := referenceQueuePendingAfterPush(queue, next)
						got := queue.pendingAfterPushLocked(next)
						queue.mu.Unlock()
						if got != want {
							t.Fatalf("length=%d pattern=%b maximum=%d active=%d fence=%v: pending=%d, want %d",
								length, pattern, maximum, active, fence, got, want)
						}
						if !slices.Equal(backing, before) || len(queue.items) != length ||
							cap(queue.items) != cap(backing) || queue.active != active ||
							queue.maximum != maximum || queue.fence != fence {
							t.Fatal("admission count mutated the queue or its spare backing capacity")
						}
					}
				}
			}
		}
	}
}

func TestOperationQueueAdmissionStopsBeforeBlockedTail(t *testing.T) {
	t.Parallel()

	concurrent := &queuedOperation{concurrent: true}
	exclusive := &queuedOperation{}
	tests := []struct {
		name    string
		items   []*queuedOperation
		maximum int
		active  int
		fence   bool
		want    int
	}{
		{name: "active fence", items: []*queuedOperation{nil}, maximum: 4, fence: true, want: 2},
		{name: "no slots", items: []*queuedOperation{nil}, maximum: 2, active: 2, want: 2},
		{name: "over capacity", items: []*queuedOperation{nil}, maximum: 2, active: 3, want: 2},
		{name: "exclusive head", items: []*queuedOperation{exclusive, nil}, maximum: 4, want: 2},
		{name: "exclusive waits for active", items: []*queuedOperation{exclusive, nil}, maximum: 4, active: 1, want: 3},
		{name: "exclusive behind concurrent", items: []*queuedOperation{concurrent, exclusive, nil}, maximum: 4, want: 3},
		{name: "last slot consumed", items: []*queuedOperation{concurrent, nil}, maximum: 1, want: 2},
		{name: "candidate blocked by exclusive", items: []*queuedOperation{exclusive}, maximum: 4, want: 1},
		{name: "candidate blocked by capacity", items: []*queuedOperation{concurrent}, maximum: 1, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			queue := &operationQueue{
				items: test.items, maximum: test.maximum, active: test.active, fence: test.fence,
			}
			queue.mu.Lock()
			defer queue.mu.Unlock()
			// A nil candidate/tail makes an eager traversal fail immediately.
			if got := referenceQueuePendingAfterPush(queue, nil); got != test.want {
				t.Fatalf("reference pending = %d, want %d", got, test.want)
			}
			if got := queue.pendingAfterPushLocked(nil); got != test.want {
				t.Fatalf("pending = %d, want %d", got, test.want)
			}
		})
	}
}

func TestOperationQueueAdmissionCancellationAndRemoval(t *testing.T) {
	t.Parallel()

	queue := newOperationQueue(3)
	defer queue.close()
	newQueued := func(id int64, concurrent bool) *queuedOperation {
		message := ldapwire.Message{ID: id, Request: ldapwire.SearchRequest{}}
		operation := newTrackedOperation(t.Context(), message)
		t.Cleanup(operation.finish)
		return &queuedOperation{message: message, operation: operation, concurrent: concurrent}
	}
	active := newQueued(1, true)
	barrier := newQueued(2, false)
	tail := newQueued(3, true)
	next := newQueued(4, true)
	checkPending := func(want int) {
		t.Helper()
		queue.mu.Lock()
		defer queue.mu.Unlock()
		if got := referenceQueuePendingAfterPush(queue, next); got != want {
			t.Fatalf("reference pending = %d, want %d", got, want)
		}
		if got := queue.pendingAfterPushLocked(next); got != want {
			t.Fatalf("pending = %d, want %d", got, want)
		}
	}
	if result := queue.push(active, -1); result != operationQueuePushed {
		t.Fatalf("active push = %d, want pushed", result)
	}
	if got, ok := queue.pop(); !ok || got != active || !active.operation.start() {
		t.Fatal("active operation did not start")
	}
	for _, operation := range []*queuedOperation{barrier, tail} {
		if result := queue.push(operation, 2); result != operationQueuePushed {
			t.Fatalf("pending push = %d, want pushed", result)
		}
	}
	checkPending(3)
	if result := barrier.operation.requestCancel(); result.Code != ldapwire.ResultCannotCancel {
		t.Fatalf("pending Cancel = %d, want cannot cancel", result.Code)
	}
	if barrier.operation.ctx.Err() != nil {
		t.Fatal("rejected pending Cancel canceled the operation")
	}
	checkPending(3)
	barrier.operation.requestAbandon()
	if barrier.operation.ctx.Err() == nil {
		t.Fatal("Abandon did not cancel the pending operation")
	}
	checkPending(3)
	if result := queue.push(next, 2); result != operationQueueLimitExceeded {
		t.Fatalf("push before removal = %d, want limit exceeded", result)
	}
	if got := queue.remove(barrier.message.ID); got != barrier {
		t.Fatalf("removed = %p, want barrier %p", got, barrier)
	}
	checkPending(0)
	if result := active.operation.requestCancel(); result.Code != ldapwire.ResultSuccess {
		t.Fatalf("active Cancel = %d, want success", result.Code)
	}
	if result := queue.push(next, -1); result != operationQueuePushed {
		t.Fatalf("push after barrier removal = %d, want pushed", result)
	}
	if !slices.Equal(queue.items, []*queuedOperation{tail, next}) {
		t.Fatal("removal or admission changed queue order")
	}
	for _, want := range []*queuedOperation{tail, next} {
		if got, ok := queue.pop(); !ok || got != want {
			t.Fatalf("pop = %p, %v, want %p", got, ok, want)
		}
	}
	extra := newQueued(5, true)
	if result := queue.push(extra, 0); result != operationQueueLimitExceeded {
		t.Fatalf("push before canceled active completion = %d, want limit exceeded", result)
	}
	queue.complete(active)
	if result := queue.push(extra, -1); result != operationQueuePushed {
		t.Fatalf("push after canceled active completion = %d, want pushed", result)
	}
	queue.complete(tail)
	queue.complete(next)
}
