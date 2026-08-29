package server

import (
	"context"
	"sync/atomic"
)

type resourceLimiter struct {
	slots   chan struct{}
	active  atomic.Int64
	waiting atomic.Int64
}

func newResourceLimiter(limit int) resourceLimiter {
	return resourceLimiter{slots: make(chan struct{}, limit)}
}

func (limiter *resourceLimiter) acquire(ctx context.Context) bool {
	limiter.waiting.Add(1)
	defer limiter.waiting.Add(-1)
	select {
	case limiter.slots <- struct{}{}:
		limiter.active.Add(1)
		return true
	case <-ctx.Done():
		return false
	}
}

func (limiter *resourceLimiter) release() {
	<-limiter.slots
	limiter.active.Add(-1)
}

func (limiter *resourceLimiter) limit() int {
	return cap(limiter.slots)
}
