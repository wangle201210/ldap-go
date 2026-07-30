package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

var errOperationStopped = errors.New("LDAP operation stopped")

type operationStopMode uint8

const (
	operationRunning operationStopMode = iota
	operationAbandoned
	operationCanceled
)

type operationPhase uint8

const (
	operationPending operationPhase = iota
	operationExecuting
	operationFinalizing
	operationComplete
)

type trackedOperation struct {
	id          int64
	cancelable  bool
	abandonable bool
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	complete    sync.Once

	mu    sync.Mutex
	phase operationPhase
	stop  operationStopMode
}

func newTrackedOperation(
	parent context.Context,
	message ldapwire.Message,
) *trackedOperation {
	ctx, cancel := context.WithCancel(parent)
	_, isSearch := message.Request.(ldapwire.SearchRequest)
	return &trackedOperation{
		id:          message.ID,
		cancelable:  isSearch,
		abandonable: isSearch,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
}

func (operation *trackedOperation) start() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.phase != operationPending || operation.stop != operationRunning {
		return false
	}
	operation.phase = operationExecuting
	return true
}

func (operation *trackedOperation) requestAbandon() {
	operation.mu.Lock()
	if !operation.abandonable ||
		operation.phase >= operationFinalizing ||
		operation.stop != operationRunning {
		operation.mu.Unlock()
		return
	}
	operation.stop = operationAbandoned
	operation.mu.Unlock()
	operation.cancel()
}

func (operation *trackedOperation) requestCancel() ldapwire.Result {
	operation.mu.Lock()
	if !operation.cancelable {
		operation.mu.Unlock()
		return ldapwire.Result{Code: ldapwire.ResultCannotCancel}
	}
	if operation.phase == operationPending {
		operation.mu.Unlock()
		return ldapwire.ResultError(
			ldapwire.ResultCannotCancel,
			"too busy for Cancel, try Abandon instead",
		)
	}
	if operation.phase >= operationFinalizing {
		operation.mu.Unlock()
		return ldapwire.Result{Code: ldapwire.ResultTooLate}
	}
	if operation.stop != operationRunning {
		operation.mu.Unlock()
		return ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"message ID already being cancelled",
		)
	}
	operation.stop = operationCanceled
	operation.mu.Unlock()
	operation.cancel()
	return ldapwire.Result{Code: ldapwire.ResultSuccess}
}

func (operation *trackedOperation) beginFinalResponse() error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.stop != operationRunning {
		return errOperationStopped
	}
	if operation.phase >= operationFinalizing {
		return nil
	}
	operation.phase = operationFinalizing
	return nil
}

func (operation *trackedOperation) responseAllowed() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return operation.stop == operationRunning
}

func (operation *trackedOperation) stopMode() operationStopMode {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return operation.stop
}

func (operation *trackedOperation) finish() {
	operation.complete.Do(func() {
		operation.mu.Lock()
		operation.phase = operationComplete
		operation.mu.Unlock()
		operation.cancel()
		close(operation.done)
	})
}

type operationRegistry struct {
	mu         sync.Mutex
	operations map[int64]*trackedOperation
}

func newOperationRegistry() *operationRegistry {
	return &operationRegistry{
		operations: make(map[int64]*trackedOperation),
	}
}

func (registry *operationRegistry) contains(messageID int64) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.operations[messageID] != nil
}

func (registry *operationRegistry) register(
	parent context.Context,
	message ldapwire.Message,
) (*trackedOperation, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.operations[message.ID] != nil {
		return nil, false
	}
	operation := newTrackedOperation(parent, message)
	registry.operations[message.ID] = operation
	return operation, true
}

func (registry *operationRegistry) abandon(messageID int64) {
	registry.mu.Lock()
	operation := registry.operations[messageID]
	registry.mu.Unlock()
	if operation != nil {
		operation.requestAbandon()
	}
}

func (registry *operationRegistry) cancel(
	messageID int64,
) (*trackedOperation, ldapwire.Result) {
	registry.mu.Lock()
	operation := registry.operations[messageID]
	registry.mu.Unlock()
	if operation == nil {
		return nil, ldapwire.ResultError(
			ldapwire.ResultNoSuchOperation,
			"message ID not found",
		)
	}
	return operation, operation.requestCancel()
}

func (registry *operationRegistry) finish(operation *trackedOperation) {
	registry.mu.Lock()
	if registry.operations[operation.id] == operation {
		delete(registry.operations, operation.id)
	}
	registry.mu.Unlock()
	operation.finish()
}

func (registry *operationRegistry) shutdown() {
	registry.mu.Lock()
	operations := make([]*trackedOperation, 0, len(registry.operations))
	for _, operation := range registry.operations {
		operations = append(operations, operation)
	}
	clear(registry.operations)
	registry.mu.Unlock()
	for _, operation := range operations {
		operation.cancel()
		operation.finish()
	}
}

type queuedOperation struct {
	message    ldapwire.Message
	operation  *trackedOperation
	completion chan operationCompletion
}

type operationCompletion struct {
	closeConnection bool
	connection      net.Conn
	err             error
}

type operationQueue struct {
	mu     sync.Mutex
	ready  *sync.Cond
	items  []*queuedOperation
	closed bool
}

func newOperationQueue() *operationQueue {
	queue := &operationQueue{}
	queue.ready = sync.NewCond(&queue.mu)
	return queue
}

func (queue *operationQueue) push(operation *queuedOperation) bool {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.closed {
		return false
	}
	queue.items = append(queue.items, operation)
	queue.ready.Signal()
	return true
}

func (queue *operationQueue) pop() (*queuedOperation, bool) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	for len(queue.items) == 0 && !queue.closed {
		queue.ready.Wait()
	}
	if queue.closed {
		return nil, false
	}
	operation := queue.items[0]
	queue.items[0] = nil
	queue.items = queue.items[1:]
	if len(queue.items) == 0 {
		queue.items = nil
	}
	return operation, true
}

func (queue *operationQueue) close() {
	queue.mu.Lock()
	queue.closed = true
	queue.items = nil
	queue.ready.Broadcast()
	queue.mu.Unlock()
}

type serializedResponseConnection struct {
	net.Conn
	mu *sync.Mutex
}

func (connection *serializedResponseConnection) Write(value []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()

	written := 0
	for written < len(value) {
		count, err := connection.Conn.Write(value[written:])
		written += count
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

type operationResponseConnection struct {
	net.Conn
	operation *trackedOperation
}

func (connection *operationResponseConnection) Write(value []byte) (int, error) {
	if !connection.operation.responseAllowed() {
		return 0, errOperationStopped
	}
	return connection.Conn.Write(value)
}

func (connection *operationResponseConnection) beginFinalResponse() error {
	return connection.operation.beginFinalResponse()
}
