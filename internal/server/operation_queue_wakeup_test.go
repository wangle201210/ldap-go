package server

import (
	"testing"
	"testing/synctest"
)

func TestOperationQueueEmptyBroadcastSuppression(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const workers = 8
		queue := newOperationQueue(workers)
		defer queue.close()
		releases := 0
		active := &queuedOperation{
			retainedBytes:   10,
			releaseRetained: func() { releases++ },
		}
		if queue.push(active, 0) != operationQueuePushed {
			t.Fatal("initial push failed")
		}
		if operation, ok := queue.pop(); !ok || operation != active {
			t.Fatalf("initial pop = %p, %v", operation, ok)
		}

		// Observe Cond wakeups directly: pop would hide them by waiting again.
		awakened := make(chan struct{}, workers)
		for range workers {
			go func() {
				queue.mu.Lock()
				queue.ready.Wait()
				queue.mu.Unlock()
				awakened <- struct{}{}
			}()
		}
		synctest.Wait()
		if discarded := queue.discardPending(); len(discarded) != 0 {
			t.Fatalf("discarded %d operations from empty queue", len(discarded))
		}
		synctest.Wait()
		if count := len(awakened); count != 0 {
			t.Fatalf("empty discard woke %d workers", count)
		}
		queue.complete(active)
		synctest.Wait()
		if count := len(awakened); count != 0 {
			t.Fatalf("empty completion woke %d workers", count)
		}
		if queue.active != 0 || queue.fence || queue.retainedBytes != 0 || releases != 1 {
			t.Fatalf("completion state: active=%d fence=%v retained=%d releases=%d",
				queue.active, queue.fence, queue.retainedBytes, releases)
		}
		if queue.push(&queuedOperation{}, 0) != operationQueuePushed {
			t.Fatal("push after idle failed")
		}
		synctest.Wait()
		if count := len(awakened); count != 1 {
			t.Fatalf("push after idle woke %d workers, want 1", count)
		}
	})
}

func TestOperationQueueWakeupAfterIdleAndClose(t *testing.T) {
	for _, drain := range []bool{false, true} {
		name := "close"
		if drain {
			name = "drain"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const workers = 8
				queue := newOperationQueue(workers)
				defer queue.close()
				popped := operationQueuePopWaiters(queue, workers)
				synctest.Wait()
				queue.discardPending()
				queue.complete()
				synctest.Wait()
				if len(popped) != 0 {
					t.Fatal("idle pop returned before push")
				}

				next := &queuedOperation{}
				if queue.push(next, 0) != operationQueuePushed {
					t.Fatal("push after idle failed")
				}
				synctest.Wait()
				if len(popped) != 1 {
					t.Fatalf("push resumed %d workers, want 1", len(popped))
				}
				if operation := <-popped; operation != next {
					t.Fatalf("pop = %p, want %p", operation, next)
				}
				queue.complete(next)
				if drain {
					queue.closeAndDrain()
				} else {
					queue.close()
				}
				synctest.Wait()
				if len(popped) != workers-1 {
					t.Fatalf("close resumed %d workers, want %d", len(popped), workers-1)
				}
				for range workers - 1 {
					if operation := <-popped; operation != nil {
						t.Fatalf("closed queue returned %p", operation)
					}
				}
			})
		})
	}
}

func TestOperationQueueWakeupFenceAndParallelAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newOperationQueue(2)
		defer queue.close()
		first := &queuedOperation{concurrent: true}
		second := &queuedOperation{concurrent: true}
		for _, operation := range []*queuedOperation{first, second} {
			if queue.push(operation, 0) != operationQueuePushed {
				t.Fatal("active operation push failed")
			}
			if got, ok := queue.pop(); !ok || got != operation {
				t.Fatalf("active pop = %p, %v; want %p", got, ok, operation)
			}
		}
		fence := &queuedOperation{}
		afterFirst := &queuedOperation{concurrent: true}
		afterSecond := &queuedOperation{concurrent: true}
		for _, operation := range []*queuedOperation{fence, afterFirst, afterSecond} {
			if queue.push(operation, 3) != operationQueuePushed {
				t.Fatal("pending operation push failed")
			}
		}
		if queue.push(&queuedOperation{concurrent: true}, 3) != operationQueueLimitExceeded {
			t.Fatal("pending limit allowed an extra operation")
		}
		popped := operationQueuePopWaiters(queue, 3)
		synctest.Wait()
		queue.complete(first)
		synctest.Wait()
		if len(popped) != 0 {
			t.Fatal("fence passed an active operation")
		}
		queue.complete(second)
		synctest.Wait()
		if len(popped) != 1 {
			t.Fatalf("fence admission resumed %d workers, want 1", len(popped))
		}
		if operation := <-popped; operation != fence {
			t.Fatalf("pop = %p, want fence %p", operation, fence)
		}
		queue.complete(fence)
		synctest.Wait()
		if len(popped) != 2 {
			t.Fatalf("fence completion resumed %d workers, want 2", len(popped))
		}
		gotFirst, gotSecond := <-popped, <-popped
		if !((gotFirst == afterFirst && gotSecond == afterSecond) ||
			(gotFirst == afterSecond && gotSecond == afterFirst)) {
			t.Fatalf("parallel pops = %p, %p; want %p, %p", gotFirst, gotSecond, afterFirst, afterSecond)
		}
		queue.complete(gotFirst)
		queue.complete(gotSecond)
	})
}

func TestOperationQueueWakeupCloseWithPendingFence(t *testing.T) {
	for _, drain := range []bool{false, true} {
		name := "close"
		if drain {
			name = "drain"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				queue := newOperationQueue(2)
				defer queue.close()
				active := &queuedOperation{concurrent: true}
				fence := &queuedOperation{}
				if queue.push(active, 0) != operationQueuePushed {
					t.Fatal("active push failed")
				}
				if operation, ok := queue.pop(); !ok || operation != active {
					t.Fatalf("active pop = %p, %v", operation, ok)
				}
				if queue.push(fence, 1) != operationQueuePushed {
					t.Fatal("fence push failed")
				}
				popped := operationQueuePopWaiters(queue, 2)
				synctest.Wait()
				if drain {
					queue.closeAndDrain()
					synctest.Wait()
					if len(popped) != 0 {
						t.Fatal("drain admitted fence before active operation completed")
					}
				} else {
					queue.close()
				}
				queue.complete(active)
				synctest.Wait()
				if len(popped) != 2 {
					t.Fatalf("close resumed %d workers, want 2", len(popped))
				}
				fences := 0
				for range 2 {
					if operation := <-popped; operation == fence {
						fences++
						queue.complete(operation)
					} else if operation != nil {
						t.Fatalf("closed queue returned unexpected operation %p", operation)
					}
				}
				if (drain && fences != 1) || (!drain && fences != 0) {
					t.Fatalf("drain=%v executed %d fences", drain, fences)
				}
				if queue.push(&queuedOperation{}, 1) != operationQueueClosed {
					t.Fatal("closed queue accepted another operation")
				}
			})
		})
	}
}

func operationQueuePopWaiters(queue *operationQueue, count int) <-chan *queuedOperation {
	popped := make(chan *queuedOperation, count)
	for range count {
		go func() {
			operation, _ := queue.pop()
			popped <- operation
		}()
	}
	return popped
}
