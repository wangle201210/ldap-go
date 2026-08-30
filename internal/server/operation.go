package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

var errOperationStopped = errors.New("LDAP operation stopped")
var errSearchResponseLimit = errors.New("LDAP search response byte budget exceeded")

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

type trackedOperationContextKey struct{}

type trackedOperation struct {
	id          int64
	cancelable  bool
	abandonable bool
	longLived   bool
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	complete    sync.Once

	mu                         sync.Mutex
	phase                      operationPhase
	stop                       operationStopMode
	metaBackendSearch          bool
	metaBackendResponseSeen    bool
	metaBackendCancelCompleted bool
}

func newTrackedOperation(
	parent context.Context,
	message ldapwire.Message,
) *trackedOperation {
	ctx, cancel := context.WithCancel(parent)
	cancelable := operationRequestCancelable(message.Request)
	abandonable := true
	switch message.Request.(type) {
	case ldapwire.BindRequest, ldapwire.UnbindRequest, ldapwire.AbandonRequest:
		abandonable = false
	}
	return &trackedOperation{
		id:          message.ID,
		cancelable:  cancelable,
		abandonable: abandonable,
		longLived:   isLongLivedOperation(message),
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
}

func operationRequestCancelable(request ldapwire.Request) bool {
	switch typed := request.(type) {
	case ldapwire.SearchRequest, ldapwire.CompareRequest, ldapwire.AddRequest,
		ldapwire.ModifyRequest, ldapwire.DeleteRequest, ldapwire.ModifyDNRequest:
		return true
	case ldapwire.ExtendedRequest:
		switch typed.Name {
		case cancelOID, startTLSOID, transactionStartOID, transactionEndOID,
			whoAmIOID:
			return false
		default:
			return true
		}
	default:
		return false
	}
}

func isLongLivedOperation(message ldapwire.Message) bool {
	if _, isSearch := message.Request.(ldapwire.SearchRequest); !isSearch {
		return false
	}
	for _, control := range message.Controls {
		if control.OID != syncRequestControlOID || !control.HasValue {
			continue
		}
		request, err := ldapwire.DecodeSyncRequestValue(control.Value)
		return err == nil && request.Mode == ldapwire.SyncRefreshAndPersist
	}
	return false
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

func (operation *trackedOperation) requestBindAbandon() {
	operation.mu.Lock()
	if operation.phase >= operationFinalizing || operation.stop != operationRunning {
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
	if operation.metaBackendSearch && operation.metaBackendResponseSeen {
		operation.metaBackendCancelCompleted = true
		operation.mu.Unlock()
		operation.cancel()
		return ldapwire.Result{Code: ldapwire.ResultTooLate}
	}
	operation.stop = operationCanceled
	operation.mu.Unlock()
	operation.cancel()
	return ldapwire.Result{Code: ldapwire.ResultSuccess}
}

func (operation *trackedOperation) enableMetaBackendSearch() {
	operation.mu.Lock()
	operation.metaBackendSearch = true
	operation.mu.Unlock()
}

func (operation *trackedOperation) observeMetaBackendResponse() {
	operation.mu.Lock()
	if operation.metaBackendSearch {
		operation.metaBackendResponseSeen = true
	}
	operation.mu.Unlock()
}

func (operation *trackedOperation) metaBackendCancelCompletesNormally() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return operation.metaBackendCancelCompleted
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

func (operation *trackedOperation) markCommitPoint() error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.stop != operationRunning {
		return errOperationStopped
	}
	if operation.phase < operationFinalizing {
		operation.phase = operationFinalizing
	}
	return nil
}

func withTrackedOperation(
	ctx context.Context,
	operation *trackedOperation,
) context.Context {
	return context.WithValue(ctx, trackedOperationContextKey{}, operation)
}

func markTrackedOperationCommitPoint(ctx context.Context) error {
	operation, _ := ctx.Value(trackedOperationContextKey{}).(*trackedOperation)
	if operation == nil {
		return nil
	}
	return operation.markCommitPoint()
}

func (operation *trackedOperation) disableCancellationForRemoteCommit() error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.stop != operationRunning {
		return errOperationStopped
	}
	operation.cancelable = false
	return nil
}

func disableTrackedOperationCancellationForRemoteCommit(
	ctx context.Context,
) error {
	operation, _ := ctx.Value(trackedOperationContextKey{}).(*trackedOperation)
	if operation == nil {
		return ctx.Err()
	}
	return operation.disableCancellationForRemoteCommit()
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

func (operation *trackedOperation) executing() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return operation.phase >= operationExecuting &&
		operation.phase < operationComplete
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

func (registry *operationRegistry) hasOutstanding() bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.operations) != 0
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

func (registry *operationRegistry) abandonLongLived() {
	registry.mu.Lock()
	operations := make([]*trackedOperation, 0, len(registry.operations))
	for _, operation := range registry.operations {
		if operation.longLived {
			operations = append(operations, operation)
		}
	}
	registry.mu.Unlock()
	for _, operation := range operations {
		operation.requestAbandon()
	}
}

func (registry *operationRegistry) abandonForBind() {
	registry.mu.Lock()
	operations := make([]*trackedOperation, 0, len(registry.operations))
	for _, operation := range registry.operations {
		operations = append(operations, operation)
	}
	registry.mu.Unlock()
	for _, operation := range operations {
		operation.requestBindAbandon()
	}
}

func (registry *operationRegistry) closeIfIdle(
	activity *connectionActivity,
	timeout time.Duration,
	now time.Time,
	closeConnection func(),
) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, operation := range registry.operations {
		if operation.executing() {
			return false
		}
	}
	if !activity.expired(timeout, now) {
		return false
	}
	closeConnection()
	return true
}

type queuedOperation struct {
	message             ldapwire.Message
	operation           *trackedOperation
	completion          chan operationCompletion
	state               *connectionState
	concurrent          bool
	retainedBytes       int64
	releaseRetained     func()
	releaseRetainedOnce sync.Once
}

func (operation *queuedOperation) releaseRetainedBytes() bool {
	if operation == nil {
		return false
	}
	released := false
	operation.releaseRetainedOnce.Do(func() {
		released = true
		if operation.releaseRetained != nil {
			operation.releaseRetained()
		}
	})
	return released
}

type operationCompletion struct {
	closeConnection bool
	connection      net.Conn
	err             error
}

type operationQueue struct {
	mu                   sync.Mutex
	ready                *sync.Cond
	items                []*queuedOperation
	active               int
	maximum              int
	fence                bool
	retainedBytes        int64
	maximumRetainedBytes int64
	closed               bool
	drain                bool
}

type operationQueuePushResult uint8

const (
	operationQueuePushed operationQueuePushResult = iota
	operationQueueClosed
	operationQueueLimitExceeded
)

func newOperationQueue(maximum ...int) *operationQueue {
	limit := 1
	if len(maximum) != 0 && maximum[0] > 0 {
		limit = maximum[0]
	}
	queue := &operationQueue{maximum: limit}
	queue.ready = sync.NewCond(&queue.mu)
	return queue
}

func (queue *operationQueue) push(
	operation *queuedOperation,
	maxPending int,
) operationQueuePushResult {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.closed {
		return operationQueueClosed
	}
	if queue.maximumRetainedBytes > 0 &&
		operation.retainedBytes > queue.maximumRetainedBytes-queue.retainedBytes {
		return operationQueueLimitExceeded
	}
	pending := queue.pendingAfterPushLocked(operation)
	if pending > 0 && pending > maxPending {
		return operationQueueLimitExceeded
	}
	queue.items = append(queue.items, operation)
	queue.retainedBytes += operation.retainedBytes
	queue.ready.Signal()
	return operationQueuePushed
}

func (queue *operationQueue) pendingAfterPushLocked(next *queuedOperation) int {
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

func (queue *operationQueue) pop() (*queuedOperation, bool) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	for {
		if len(queue.items) == 0 {
			if queue.closed {
				return nil, false
			}
			queue.ready.Wait()
			continue
		}
		if queue.closed && !queue.drain {
			return nil, false
		}
		next := queue.items[0]
		if queue.fence || queue.active >= queue.maximum ||
			(!next.concurrent && queue.active != 0) {
			queue.ready.Wait()
			continue
		}
		break
	}
	operation := queue.items[0]
	queue.items[0] = nil
	queue.items = queue.items[1:]
	queue.active++
	if !operation.concurrent {
		queue.fence = true
	}
	if len(queue.items) == 0 {
		queue.items = nil
	}
	return operation, true
}

func (queue *operationQueue) complete(operations ...*queuedOperation) {
	queue.mu.Lock()
	if queue.active > 0 {
		queue.active--
	}
	if queue.fence {
		queue.fence = false
	}
	for _, operation := range operations {
		if operation == nil {
			continue
		}
		if operation.releaseRetainedBytes() {
			queue.retainedBytes -= operation.retainedBytes
		}
	}
	queue.ready.Broadcast()
	queue.mu.Unlock()
}

func (queue *operationQueue) remove(messageID int64) *queuedOperation {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	for index, queued := range queue.items {
		if queued == nil || queued.message.ID != messageID {
			continue
		}
		copy(queue.items[index:], queue.items[index+1:])
		last := len(queue.items) - 1
		queue.items[last] = nil
		queue.items = queue.items[:last]
		if len(queue.items) == 0 {
			queue.items = nil
		} else {
			queue.ready.Signal()
		}
		if queued.releaseRetainedBytes() {
			queue.retainedBytes -= queued.retainedBytes
		}
		return queued
	}
	return nil
}

func (queue *operationQueue) discardPending() []*queuedOperation {
	queue.mu.Lock()
	discarded := queue.items
	queue.items = nil
	for _, operation := range discarded {
		if operation != nil {
			if operation.releaseRetainedBytes() {
				queue.retainedBytes -= operation.retainedBytes
			}
		}
	}
	queue.ready.Broadcast()
	queue.mu.Unlock()
	return discarded
}

func (queue *operationQueue) pending() int {
	if queue == nil {
		return 0
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return len(queue.items)
}

func (queue *operationQueue) close() {
	queue.mu.Lock()
	queue.closed = true
	queue.drain = false
	for _, operation := range queue.items {
		if operation != nil {
			if operation.releaseRetainedBytes() {
				queue.retainedBytes -= operation.retainedBytes
			}
		}
	}
	queue.items = nil
	queue.ready.Broadcast()
	queue.mu.Unlock()
}

func (queue *operationQueue) closeAndDrain() {
	queue.mu.Lock()
	queue.closed = true
	queue.drain = true
	queue.ready.Broadcast()
	queue.mu.Unlock()
}

type serializedResponseConnection struct {
	net.Conn
	mu                *sync.Mutex
	monitor           *monitorState
	monitorConnection *monitorConnection
	writeTimeout      func() time.Duration
	terminal          *atomic.Bool
}

func (connection *serializedResponseConnection) Write(value []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.writeLocked(value)
}

func (connection *serializedResponseConnection) writeOperationResponse(
	operation *trackedOperation,
	value []byte,
) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if operation == nil || !operation.responseAllowed() {
		return 0, errOperationStopped
	}
	return connection.writeLocked(value)
}

func (connection *serializedResponseConnection) writeOperationResponseBatch(
	operation *trackedOperation,
	values [][]byte,
) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if operation == nil || !operation.responseAllowed() {
		return 0, errOperationStopped
	}
	return connection.writeLockedBatch(values)
}

func (connection *serializedResponseConnection) writeLocked(value []byte) (int, error) {
	written, err := connection.writeRawLocked(value)
	if err == nil && connection.monitor != nil && connection.monitorConnection != nil {
		connection.monitor.observeResponse(connection.monitorConnection, value)
	}
	return written, err
}

func (connection *serializedResponseConnection) writeLockedBatch(
	values [][]byte,
) (int, error) {
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) == 1 {
		return connection.writeLocked(values[0])
	}
	total := 0
	for _, value := range values {
		total += len(value)
	}
	combined := make([]byte, total)
	offset := 0
	for _, value := range values {
		offset += copy(combined[offset:], value)
	}
	written, err := connection.writeRawLocked(combined)
	if err == nil && connection.monitor != nil && connection.monitorConnection != nil {
		connection.monitor.observeResponses(connection.monitorConnection, values)
	}
	return written, err
}

func (connection *serializedResponseConnection) writeRawLocked(value []byte) (int, error) {
	if connection.terminal != nil && connection.terminal.Load() {
		return 0, net.ErrClosed
	}
	fail := func(written int, err error) (int, error) {
		if connection.terminal != nil {
			connection.terminal.Store(true)
		}
		_ = connection.Conn.Close()
		return written, err
	}

	written := 0
	for written < len(value) {
		timeout := time.Duration(0)
		if connection.writeTimeout != nil {
			timeout = connection.writeTimeout()
		}
		if timeout > 0 {
			if err := connection.Conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return fail(written, err)
			}
		}
		if connection.monitor != nil && connection.monitorConnection != nil {
			connection.monitor.setWriteWaiter(connection.monitorConnection, true)
		}
		count, err := connection.Conn.Write(value[written:])
		if connection.monitor != nil && connection.monitorConnection != nil {
			connection.monitor.setWriteWaiter(connection.monitorConnection, false)
		}
		if timeout > 0 {
			clearErr := connection.Conn.SetWriteDeadline(time.Time{})
			if err == nil && clearErr != nil {
				err = clearErr
			}
		}
		written += count
		if err != nil {
			return fail(written, err)
		}
		if count == 0 {
			return fail(written, io.ErrShortWrite)
		}
	}
	return written, nil
}

type operationResponseConnection struct {
	net.Conn
	operation            *trackedOperation
	audit                *operationAuditObservation
	maximumResponseBytes int64
	maximumPDUBytes      int64
	responseBytes        int64
	budgetMu             sync.Mutex
	reserveResponseBytes func(int64) (func(), bool)
}

func (connection *operationResponseConnection) enableMetaBackendSearch() {
	connection.operation.enableMetaBackendSearch()
}

func (connection *operationResponseConnection) observeMetaBackendResponse() {
	connection.operation.observeMetaBackendResponse()
}

func (connection *operationResponseConnection) metaBackendCancelCompletesNormally() bool {
	return connection.operation.metaBackendCancelCompletesNormally()
}

func (connection *operationResponseConnection) Write(value []byte) (int, error) {
	connection.budgetMu.Lock()
	defer connection.budgetMu.Unlock()
	if connection.maximumPDUBytes > 0 && int64(len(value)) > connection.maximumPDUBytes {
		return 0, errSearchResponseLimit
	}
	releaseResponseBytes := func() {}
	if connection.reserveResponseBytes != nil {
		var acquired bool
		releaseResponseBytes, acquired = connection.reserveResponseBytes(int64(len(value)))
		if !acquired {
			return 0, errSearchResponseLimit
		}
	}
	defer releaseResponseBytes()
	if connection.maximumResponseBytes > 0 &&
		int64(len(value)) > connection.maximumResponseBytes-connection.responseBytes {
		return 0, errSearchResponseLimit
	}
	var written int
	var err error
	if writer, ok := connection.Conn.(interface {
		writeOperationResponse(*trackedOperation, []byte) (int, error)
	}); ok {
		written, err = writer.writeOperationResponse(connection.operation, value)
	} else {
		if !connection.operation.responseAllowed() {
			return 0, errOperationStopped
		}
		written, err = connection.Conn.Write(value)
	}
	connection.responseBytes += int64(written)
	if written == len(value) {
		connection.audit.observeResponse(value)
	}
	return written, err
}

func (connection *operationResponseConnection) writeLDAPResponseBatch(
	values [][]byte,
) (int, error) {
	connection.budgetMu.Lock()
	defer connection.budgetMu.Unlock()
	total := 0
	for _, value := range values {
		if connection.maximumPDUBytes > 0 && int64(len(value)) > connection.maximumPDUBytes {
			return 0, errSearchResponseLimit
		}
		total += len(value)
	}
	if connection.reserveResponseBytes != nil {
		for _, value := range values {
			releaseResponseBytes, acquired := connection.reserveResponseBytes(int64(len(value)))
			if !acquired {
				return 0, errSearchResponseLimit
			}
			releaseResponseBytes()
		}
	}
	if connection.maximumResponseBytes > 0 &&
		int64(total) > connection.maximumResponseBytes-connection.responseBytes {
		return 0, errSearchResponseLimit
	}
	var written int
	var err error
	if writer, ok := connection.Conn.(interface {
		writeOperationResponseBatch(*trackedOperation, [][]byte) (int, error)
	}); ok {
		written, err = writer.writeOperationResponseBatch(connection.operation, values)
	} else {
		for _, value := range values {
			if !connection.operation.responseAllowed() {
				err = errOperationStopped
				break
			}
			count, writeErr := connection.Conn.Write(value)
			written += count
			if writeErr != nil {
				err = writeErr
				break
			}
		}
	}
	connection.responseBytes += int64(written)
	if err == nil && written == total {
		for _, value := range values {
			connection.audit.observeResponse(value)
		}
	}
	return written, err
}

func (connection *operationResponseConnection) beginFinalResponse() error {
	return connection.operation.beginFinalResponse()
}

func (connection *operationResponseConnection) setAuditAuthorizationDN(value string) {
	connection.audit.setAuthorizationDN(value)
}

func (connection *operationResponseConnection) setAuditSessionTracking(
	values []audit.SessionTracking,
) {
	connection.audit.setSessionTracking(values)
}
