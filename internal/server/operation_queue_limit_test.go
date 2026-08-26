package server

import "testing"

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
