package lloadd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type reserveResult uint8

const (
	reserveUnavailable reserveResult = iota
	reserveBusy
	reserveSuccess
)

const (
	clientStartTLSOID = "1.3.6.1.4.1.1466.20037"
	clientCancelOID   = "1.3.6.1.1.8"
)

var errOperationFinished = errors.New("lloadd operation already finished")

func (client *clientConnection) serve(ctx context.Context) {
	defer client.close()
	go func() {
		select {
		case <-ctx.Done():
			_ = client.conn.Close()
		case <-client.done:
		}
	}()
	for {
		frame, err := client.proxy.codec.Read(
			client.conn,
			client.proxy.config.ClientMaxMessageSize,
		)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				client.proxy.config.Logger.Debug("closing malformed lloadd client", "error", err)
			}
			return
		}
		if !client.handleFrame(frame) {
			return
		}
	}
}

func (client *clientConnection) handleFrame(frame proxyFrame) bool {
	if frame.MessageID == 0 || !isClientRequestTag(frame.ProtocolTag) {
		return false
	}
	switch frame.ProtocolTag {
	case ldapwire.ApplicationUnbindRequest:
		return false
	case ldapwire.ApplicationAbandonRequest:
		client.handleAbandon(frame)
		return true
	case ldapwire.ApplicationBindRequest:
		client.handleBind(frame)
		return true
	}
	if frame.ProtocolTag == ldapwire.ApplicationExtendedRequest {
		switch frame.ExtendedOID {
		case clientStartTLSOID:
			client.sendResult(
				frame.MessageID,
				frame.ProtocolTag,
				ldapwire.ResultUnwillingToPerform,
				"client StartTLS is not implemented",
			)
			return true
		case clientCancelOID:
			client.sendResult(
				frame.MessageID,
				frame.ProtocolTag,
				ldapwire.ResultUnwillingToPerform,
				"client Cancel target rewriting is not implemented",
			)
			return true
		}
	}

	client.mu.Lock()
	binding := client.binding
	client.mu.Unlock()
	if binding {
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultProtocolError,
			"bind in progress",
		)
		return true
	}
	client.route(frame, false)
	return true
}

func isClientRequestTag(tag uint64) bool {
	switch tag {
	case ldapwire.ApplicationBindRequest,
		ldapwire.ApplicationUnbindRequest,
		ldapwire.ApplicationSearchRequest,
		ldapwire.ApplicationModifyRequest,
		ldapwire.ApplicationAddRequest,
		ldapwire.ApplicationDeleteRequest,
		ldapwire.ApplicationModifyDNRequest,
		ldapwire.ApplicationCompareRequest,
		ldapwire.ApplicationAbandonRequest,
		ldapwire.ApplicationExtendedRequest:
		return true
	default:
		return false
	}
}

func (client *clientConnection) handleBind(frame proxyFrame) {
	client.mu.Lock()
	client.bindGeneration++
	client.mu.Unlock()
	if frame.BindVersion != 3 {
		client.resetForBind(false)
		client.sendResult(
			frame.MessageID,
			ldapwire.ApplicationBindRequest,
			ldapwire.ResultProtocolError,
			"LDAP version unsupported",
		)
		return
	}
	if frame.BindSASL && strings.EqualFold(frame.BindMechanism, "EXTERNAL") {
		client.resetForBind(false)
		client.sendResult(
			frame.MessageID,
			ldapwire.ApplicationBindRequest,
			ldapwire.ResultAuthMethodNotSupported,
			"SASL EXTERNAL requires local transport identity support",
		)
		return
	}

	client.mu.Lock()
	continuation := client.binding && client.bindPin != nil && frame.BindSASL
	client.mu.Unlock()
	if !continuation {
		client.resetForBind(true)
	}
	client.mu.Lock()
	client.binding = true
	client.mu.Unlock()
	client.route(frame, true)
}

func (client *clientConnection) resetForBind(reuseBindPin bool) {
	client.mu.Lock()
	operations := make([]*proxyOperation, 0, len(client.ops))
	for _, operation := range client.ops {
		operations = append(operations, operation)
	}
	linked := client.upstreamAffinity
	bindPin := client.bindPin
	// A forwarded replacement Bind can reuse the exclusive in-progress Bind
	// connection; a locally completed Bind must release it.
	if !reuseBindPin {
		client.bindPin = nil
	}
	client.binding = false
	client.authzID = nil
	client.restriction = RuntimeRestrictionNone
	client.backendAffinity = nil
	client.upstreamAffinity = nil
	client.writeInflight = 0
	client.writeCompletedAt = time.Time{}
	client.mu.Unlock()
	for _, operation := range operations {
		client.abandonOperation(operation, nil, true)
	}
	if linked != nil && linked.ownerFor(client) {
		linked.closeWithError(errors.New("client Bind reset upstream identity"))
	}
	if !reuseBindPin && bindPin != nil && bindPin != linked && bindPin.ownerFor(client) {
		bindPin.closeWithError(errors.New("client Bind ended local authentication exchange"))
	}
}

func (client *clientConnection) route(frame proxyFrame, bind bool) {
	restriction := RuntimeRestrictionNone
	if !bind {
		restriction = client.requestRestriction(frame)
		if restriction == RuntimeRestrictionReject {
			client.sendResult(
				frame.MessageID,
				frame.ProtocolTag,
				ldapwire.ResultUnwillingToPerform,
				"extended operation or control disallowed",
			)
			return
		}
	}

	operation := &proxyOperation{
		client:      client,
		clientID:    frame.MessageID,
		requestTag:  frame.ProtocolTag,
		restriction: restriction,
		bind:        bind,
		bindSASL:    frame.BindSASL,
		bindDN:      frame.BindDN,
		started:     time.Now(),
	}
	if bind {
		client.mu.Lock()
		operation.bindGeneration = client.bindGeneration
		client.mu.Unlock()
	}
	if code, diagnostic, closeClient, ok := client.register(operation); !ok {
		if closeClient {
			client.close()
			return
		}
		client.sendResult(frame.MessageID, frame.ProtocolTag, code, diagnostic)
		client.clearBindAttempt(operation)
		return
	}

	upstream, selection := client.proxy.selectUpstream(client, operation, bind)
	if selection != reserveSuccess {
		if !operation.finish(false) {
			return
		}
		code := ldapwire.ResultUnavailable
		diagnostic := "no connections available"
		if selection == reserveBusy {
			code = ldapwire.ResultBusy
			diagnostic = "all upstream connections are busy"
		}
		client.sendResult(frame.MessageID, frame.ProtocolTag, code, diagnostic)
		client.clearBindAttempt(operation)
		return
	}

	var encoded []byte
	var err error
	useProxyAuthz := !bind && client.proxy.config.ProxyAuthz &&
		!client.privileged() && !upstream.ownerFor(client)
	if useProxyAuthz {
		encoded, err = client.proxy.codec.PrependProxyAuthz(
			frame,
			operation.upstreamID,
			client.authorizationIdentity(),
		)
	} else {
		encoded, err = client.proxy.codec.RewriteMessageID(frame, operation.upstreamID)
	}
	if err == nil {
		err = operation.writeRequest(encoded)
	}
	if errors.Is(err, errOperationFinished) {
		return
	}
	if err != nil {
		operation.responseMu.Lock()
		won := operation.finish(false)
		if won {
			client.sendResult(
				frame.MessageID,
				frame.ProtocolTag,
				ldapwire.ResultOther,
				"connection to the remote server has been severed",
			)
			client.clearBindAttempt(operation)
		}
		operation.responseMu.Unlock()
		upstream.closeWithError(err)
	}
}

func (operation *proxyOperation) writeRequest(encoded []byte) error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished.Load() || operation.abandoning || operation.upstream == nil {
		return errOperationFinished
	}
	if err := operation.upstream.write(encoded); err != nil {
		return err
	}
	operation.requestSent = true
	return nil
}

func (client *clientConnection) clearBindAttempt(operation *proxyOperation) {
	if operation == nil || !operation.bind {
		return
	}
	client.mu.Lock()
	if operation.bindGeneration == client.bindGeneration {
		client.binding = false
	}
	client.mu.Unlock()
}

func (client *clientConnection) requestRestriction(frame proxyFrame) RuntimeRestriction {
	restriction := RuntimeRestrictionNone
	for _, oid := range frame.Controls {
		if candidate := client.proxy.config.RestrictControls[oid]; candidate > restriction {
			restriction = candidate
		}
	}
	if frame.ExtendedOID != "" {
		candidate, configured := client.proxy.config.RestrictExtended[frame.ExtendedOID]
		if !configured {
			candidate = client.proxy.config.RestrictExtended["1.1"]
		}
		if candidate > restriction {
			restriction = candidate
		}
	}
	if restriction < RuntimeRestrictionWrite &&
		client.proxy.config.WriteCoherence != 0 &&
		frame.ProtocolTag != ldapwire.ApplicationSearchRequest &&
		frame.ProtocolTag != ldapwire.ApplicationCompareRequest {
		restriction = RuntimeRestrictionWrite
	}
	return restriction
}

func (client *clientConnection) register(operation *proxyOperation) (
	ldapwire.ResultCode,
	string,
	bool,
	bool,
) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return ldapwire.ResultUnavailable, "client connection is closed", false, false
	}
	if _, exists := client.ops[operation.clientID]; exists {
		return ldapwire.ResultProtocolError, "message ID is already in use", true, false
	}
	if limit := client.proxy.config.ClientMaxPending; limit > 0 &&
		!operation.bind && len(client.ops)+1 >= limit {
		return ldapwire.ResultBusy, "too many pending operations", false, false
	}
	client.ops[operation.clientID] = operation
	return ldapwire.ResultSuccess, "", false, true
}

func (client *clientConnection) handleAbandon(frame proxyFrame) {
	client.mu.Lock()
	operation := client.ops[frame.AbandonID]
	client.mu.Unlock()
	if operation == nil {
		return
	}
	client.abandonOperation(operation, &frame, false)
}

func (client *clientConnection) abandonOperation(
	operation *proxyOperation,
	frame *proxyFrame,
	finishBind bool,
) {
	operation.responseMu.Lock()
	operation.mu.Lock()
	bind := operation.bind
	if bind {
		operation.mu.Unlock()
		if finishBind {
			if operation.finish(false) {
				client.clearBindAttempt(operation)
			}
		}
		operation.responseMu.Unlock()
		return
	}
	if operation.finished.Load() || operation.abandoning {
		operation.mu.Unlock()
		operation.responseMu.Unlock()
		return
	}
	operation.abandoning = true
	upstream := operation.upstream
	upstreamID := operation.upstreamID
	requestSent := operation.requestSent
	operation.mu.Unlock()
	if !operation.finish(false) {
		operation.responseMu.Unlock()
		return
	}
	operation.responseMu.Unlock()
	if upstream != nil && requestSent {
		if abandonID, ok := upstream.allocateMessageID(); ok {
			var encoded []byte
			var err error
			if frame == nil {
				encoded, err = client.proxy.codec.EncodeAbandon(abandonID, upstreamID)
			} else {
				encoded, err = client.proxy.codec.RewriteAbandon(*frame, abandonID, upstreamID)
			}
			if err == nil {
				err = upstream.write(encoded)
			}
			if err != nil {
				upstream.closeWithError(err)
			}
		}
	}
}

func (client *clientConnection) sendResult(
	messageID int64,
	requestTag uint64,
	code ldapwire.ResultCode,
	diagnostic string,
) {
	encoded, err := client.proxy.codec.EncodeResult(messageID, requestTag, code, diagnostic)
	if err != nil {
		client.close()
		return
	}
	client.writeMu.Lock()
	err = writeConnection(client.conn, encoded, client.proxy.config.IOTimeout)
	client.writeMu.Unlock()
	if err != nil {
		client.close()
	}
}

func (client *clientConnection) write(encoded []byte) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return writeConnection(client.conn, encoded, client.proxy.config.IOTimeout)
}

func (client *clientConnection) authorizationIdentity() []byte {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]byte(nil), client.authzID...)
}

func (client *clientConnection) privileged() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.proxy.config.PrivilegedIdentity != "" &&
		strings.EqualFold(string(client.authzID), client.proxy.config.PrivilegedIdentity)
}

func (client *clientConnection) close() {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return
	}
	client.closed = true
	close(client.done)
	operations := make([]*proxyOperation, 0, len(client.ops))
	for _, operation := range client.ops {
		operations = append(operations, operation)
	}
	owned := client.upstreamAffinity
	if owned == nil {
		owned = client.bindPin
	}
	client.mu.Unlock()
	_ = client.conn.Close()
	for _, operation := range operations {
		client.abandonOperation(operation, nil, true)
	}
	if owned != nil && owned.ownerFor(client) {
		owned.closeWithError(errors.New("lloadd client disconnected"))
	}
	client.proxy.mu.Lock()
	delete(client.proxy.clients, client)
	client.proxy.mu.Unlock()
}

func (proxy *Proxy) selectUpstream(
	client *clientConnection,
	operation *proxyOperation,
	bind bool,
) (*upstreamConnection, reserveResult) {
	client.mu.Lock()
	client.expireWriteAffinityLocked(time.Now())
	forcedUpstream := client.upstreamAffinity
	if bind && client.bindPin != nil {
		forcedUpstream = client.bindPin
	}
	forcedBackend := client.backendAffinity
	clientRestriction := client.restriction
	client.mu.Unlock()

	if forcedUpstream != nil {
		pendingLimit := forcedUpstream.backend.config.ConnectionMaxPending
		if bind {
			pendingLimit = 1
		}
		lease, err := proxy.scheduler.reserveOwnedConnection(
			forcedUpstream.id,
			pendingLimit,
		)
		if err != nil {
			if errors.Is(err, ErrBusy) {
				return nil, reserveBusy
			}
			return nil, reserveUnavailable
		}
		proxy.mu.Lock()
		current := proxy.upstreams[forcedUpstream.id]
		proxy.mu.Unlock()
		if current != forcedUpstream {
			lease.Release()
			return nil, reserveUnavailable
		}
		if forcedUpstream.attach(operation, bind, lease, clientRestriction) {
			return forcedUpstream, reserveSuccess
		}
		lease.Release()
		forcedUpstream.mu.Lock()
		closed := forcedUpstream.closed
		forcedUpstream.mu.Unlock()
		if closed {
			proxy.mu.Lock()
			current = proxy.upstreams[forcedUpstream.id]
			proxy.mu.Unlock()
			if current == forcedUpstream {
				_ = proxy.scheduler.SetConnectionState(
					forcedUpstream.id,
					ConnectionUnavailable,
				)
			}
			return nil, reserveUnavailable
		}
		return nil, reserveBusy
	}

	pool := PoolRegular
	if bind {
		pool = PoolBind
	}
	affinity := Affinity{}
	if forcedBackend != nil {
		affinity.BackendID = forcedBackend.id
	}

	for range 2 {
		lease, err := proxy.scheduler.Select(SelectRequest{Pool: pool, Affinity: affinity})
		if err != nil {
			if errors.Is(err, ErrBusy) {
				return nil, reserveBusy
			}
			return nil, reserveUnavailable
		}
		proxy.mu.Lock()
		upstream := proxy.upstreams[lease.ConnectionID]
		proxy.mu.Unlock()
		if upstream == nil {
			lease.Release()
			_ = proxy.scheduler.SetConnectionState(
				lease.ConnectionID,
				ConnectionUnavailable,
			)
			continue
		}
		if !upstream.attach(operation, bind, lease, clientRestriction) {
			lease.Release()
			upstream.mu.Lock()
			closed := upstream.closed
			upstream.mu.Unlock()
			if closed {
				_ = proxy.scheduler.SetConnectionState(
					lease.ConnectionID,
					ConnectionUnavailable,
				)
				continue
			}
			return nil, reserveBusy
		}
		return upstream, reserveSuccess
	}
	return nil, reserveUnavailable
}

func (upstream *upstreamConnection) attach(
	operation *proxyOperation,
	bind bool,
	lease *Lease,
	existingRestriction RuntimeRestriction,
) bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished.Load() {
		return false
	}
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	client := operation.client
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return false
	}
	if upstream.closed || bind && !upstream.bind {
		return false
	}
	if bind {
		if upstream.owner != nil && upstream.owner != client {
			return false
		}
		if len(upstream.pending) != 0 {
			return false
		}
		upstream.owner = client
		upstream.ownerGeneration = operation.bindGeneration
	} else if upstream.bind && upstream.owner != client {
		return false
	}
	if lease == nil {
		if limit := upstream.backend.config.ConnectionMaxPending; limit > 0 &&
			len(upstream.pending) >= limit {
			return false
		}
	}
	messageID := upstream.nextID
	upstream.nextID++
	if upstream.nextID <= 0 || upstream.nextID > 1<<31-1 {
		upstream.nextID = 1
	}
	for upstream.pending[messageID] != nil {
		messageID = upstream.nextID
		upstream.nextID++
	}
	operation.upstream = upstream
	operation.upstreamID = messageID
	operation.lease = lease
	upstream.pending[messageID] = operation
	if bind {
		client.bindPin = upstream
	}
	client.commitRestrictionLocked(operation, existingRestriction)
	return true
}

func (upstream *upstreamConnection) allocateMessageID() (int64, bool) {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.closed {
		return 0, false
	}
	messageID := upstream.nextID
	upstream.nextID++
	if upstream.nextID <= 0 || upstream.nextID > 1<<31-1 {
		upstream.nextID = 1
	}
	return messageID, true
}

func (upstream *upstreamConnection) write(encoded []byte) error {
	upstream.writeMu.Lock()
	defer upstream.writeMu.Unlock()
	upstream.mu.Lock()
	closed := upstream.closed
	upstream.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return writeConnection(upstream.conn, encoded, upstream.backend.proxy.config.IOTimeout)
}

func (upstream *upstreamConnection) ownerFor(client *clientConnection) bool {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.owner == client
}

func (client *clientConnection) expireWriteAffinityLocked(now time.Time) {
	if client.restriction != RuntimeRestrictionWrite || client.writeInflight != 0 ||
		client.proxy.config.WriteCoherence < 0 || client.writeCompletedAt.IsZero() {
		return
	}
	if now.Sub(client.writeCompletedAt) >= client.proxy.config.WriteCoherence {
		client.restriction = RuntimeRestrictionNone
		client.backendAffinity = nil
		client.writeCompletedAt = time.Time{}
	}
}

func (client *clientConnection) commitRestrictionLocked(
	operation *proxyOperation,
	existing RuntimeRestriction,
) {
	if client.restriction > existing {
		existing = client.restriction
	}
	restriction := operation.restriction
	if restriction < existing {
		restriction = existing
		operation.restriction = restriction
	}
	if restriction > client.restriction {
		client.restriction = restriction
	}
	switch restriction {
	case RuntimeRestrictionWrite:
		client.backendAffinity = operation.upstream.backend
		client.writeInflight++
	case RuntimeRestrictionBackend:
		client.backendAffinity = operation.upstream.backend
	case RuntimeRestrictionConnection, RuntimeRestrictionIsolate:
		client.upstreamAffinity = operation.upstream
		client.backendAffinity = nil
	}
}

func (operation *proxyOperation) finish(response bool) bool {
	operation.mu.Lock()
	if !operation.finished.CompareAndSwap(false, true) {
		operation.mu.Unlock()
		return false
	}
	client := operation.client
	upstream := operation.upstream
	lease := operation.lease
	operation.mu.Unlock()
	if upstream != nil {
		upstream.mu.Lock()
		if upstream.pending[operation.upstreamID] == operation {
			delete(upstream.pending, operation.upstreamID)
		}
		upstream.mu.Unlock()
	}
	if lease != nil {
		lease.Release()
	}
	client.mu.Lock()
	if client.ops[operation.clientID] == operation {
		delete(client.ops, operation.clientID)
	}
	if operation.restriction == RuntimeRestrictionWrite && client.writeInflight > 0 {
		client.writeInflight--
		if client.writeInflight == 0 {
			client.writeCompletedAt = time.Now()
		}
	}
	client.mu.Unlock()
	_ = response
	return true
}

func (frame proxyFrame) String() string {
	return fmt.Sprintf("LDAP tag=%d messageID=%d", frame.ProtocolTag, frame.MessageID)
}
