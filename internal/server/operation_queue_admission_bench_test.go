package server

import "testing"

func BenchmarkOperationQueueAdmission(b *testing.B) {
	cases := []struct {
		name           string
		depth          int
		maximum        int
		active         int
		fence          bool
		barrier        int
		nextConcurrent bool
	}{
		{name: "IdleConcurrent", maximum: 8, barrier: -1, nextConcurrent: true},
		{name: "IdleExclusive", maximum: 8, barrier: -1},
		{name: "ConcurrentWindow", depth: 32, maximum: 8, active: 4, barrier: -1, nextConcurrent: true},
		{name: "ExclusiveHead", depth: 32, maximum: 8, barrier: 0, nextConcurrent: true},
		{name: "ExclusiveAfterConcurrent", depth: 32, maximum: 8, barrier: 2, nextConcurrent: true},
		{name: "ExclusiveCandidate", depth: 2, maximum: 8, barrier: -1},
		{name: "Saturated1024", depth: 1024, maximum: 8, active: 8, barrier: -1, nextConcurrent: true},
		{name: "Fenced1024", depth: 1024, maximum: 8, active: 1, fence: true, barrier: -1, nextConcurrent: true},
		{name: "AvailableSlots1024", depth: 1024, maximum: 8, barrier: -1, nextConcurrent: true},
		{name: "FullScan1024", depth: 1024, maximum: 2048, barrier: -1, nextConcurrent: true},
	}
	for _, test := range cases {
		b.Run(test.name, func(b *testing.B) {
			for _, implementation := range []struct {
				name  string
				count func(*operationQueue, *queuedOperation) int
			}{
				{name: "Current", count: (*operationQueue).pendingAfterPushLocked},
				{name: "Reference", count: referenceQueuePendingAfterPush},
			} {
				b.Run(implementation.name, func(b *testing.B) {
					queue := &operationQueue{
						items: make([]*queuedOperation, test.depth), maximum: test.maximum,
						active: test.active, fence: test.fence,
					}
					for index := range queue.items {
						queue.items[index] = &queuedOperation{concurrent: index != test.barrier}
					}
					next := &queuedOperation{concurrent: test.nextConcurrent}
					queue.mu.Lock()
					defer queue.mu.Unlock()
					want := referenceQueuePendingAfterPush(queue, next)
					b.ReportAllocs()
					var pending int
					for b.Loop() {
						pending = implementation.count(queue, next)
					}
					if pending != want {
						b.Fatalf("pending = %d, want %d", pending, want)
					}
				})
			}
		})
	}
}
