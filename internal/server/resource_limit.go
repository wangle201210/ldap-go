package server

import (
	"context"
	"sync/atomic"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type resourceLimiter struct {
	slots   chan struct{}
	active  atomic.Int64
	waiting atomic.Int64
}

type resourceByteLimiter struct {
	maximum  int64
	active   atomic.Int64
	rejected atomic.Uint64
}

func newResourceByteLimiter(maximum int64) resourceByteLimiter {
	return resourceByteLimiter{maximum: maximum}
}

func (limiter *resourceByteLimiter) tryAcquire(size int64) bool {
	if size <= 0 {
		size = 1
	}
	for {
		active := limiter.active.Load()
		if size > limiter.maximum-active {
			limiter.rejected.Add(1)
			return false
		}
		if limiter.active.CompareAndSwap(active, active+size) {
			return true
		}
	}
}

func (limiter *resourceByteLimiter) release(size int64) {
	if size <= 0 {
		size = 1
	}
	limiter.active.Add(-size)
}

func (limiter *resourceByteLimiter) limit() int64 {
	return limiter.maximum
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

func ldapMessageRetainedBytes(message ldapwire.Message, encodedBytes int64) int64 {
	if encodedBytes < 1 {
		encodedBytes = 1
	}
	size := encodedBytes + int64(unsafe.Sizeof(message)) +
		int64(cap(message.Controls))*int64(unsafe.Sizeof(ldapwire.Control{}))
	switch request := message.Request.(type) {
	case ldapwire.BindRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.SearchRequest:
		size += int64(unsafe.Sizeof(request)) +
			int64(cap(request.Attributes))*int64(unsafe.Sizeof("")) +
			filterRetainedOverhead(request.Filter)
	case ldapwire.AddRequest:
		size += int64(unsafe.Sizeof(request)) + entryRetainedOverhead(request.Entry)
	case ldapwire.ModifyRequest:
		size += int64(unsafe.Sizeof(request)) +
			int64(cap(request.Changes))*int64(unsafe.Sizeof(ldapwire.Modification{}))
		for _, change := range request.Changes {
			size += attributeRetainedOverhead(change.Attribute)
		}
	case ldapwire.DeleteRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.ModifyDNRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.CompareRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.AbandonRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.ExtendedRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.UnsupportedRequest:
		size += int64(unsafe.Sizeof(request))
	case ldapwire.UnbindRequest:
		size += int64(unsafe.Sizeof(request))
	}
	return size
}

func filterRetainedOverhead(filter directory.Filter) int64 {
	size := int64(cap(filter.Children)) * int64(unsafe.Sizeof(directory.Filter{}))
	size += int64(cap(filter.Substring.Any)) * int64(unsafe.Sizeof([]byte{}))
	for _, child := range filter.Children {
		size += filterRetainedOverhead(child)
	}
	return size
}

func entryRetainedOverhead(entry directory.Entry) int64 {
	size := int64(cap(entry.Attributes)) * int64(unsafe.Sizeof(directory.Attribute{}))
	for _, attribute := range entry.Attributes {
		size += attributeRetainedOverhead(attribute)
	}
	return size
}

func attributeRetainedOverhead(attribute directory.Attribute) int64 {
	return int64(cap(attribute.Values)) * int64(unsafe.Sizeof([]byte{}))
}
