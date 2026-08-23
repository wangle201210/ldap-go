package lloadd

import (
	"bytes"
	"context"
	"crypto/tls"
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
	transport := client.currentConnection()
	go func() {
		select {
		case <-ctx.Done():
			_ = transport.Close()
		case <-client.done:
		}
	}()
	for {
		frame, err := client.proxy.codec.Read(
			client.currentConnection(),
			client.proxy.config.ClientMaxMessageSize,
		)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				client.proxy.config.Logger.Debug("closing malformed lloadd client", "error", err)
			}
			return
		}
		if !client.handleFrame(ctx, frame) {
			return
		}
	}
}

func (client *clientConnection) handleFrame(ctx context.Context, frame proxyFrame) bool {
	if frame.MessageID == 0 || !isClientRequestTag(frame.ProtocolTag) {
		return false
	}
	client.mu.Lock()
	_, duplicateMessageID := client.ops[frame.MessageID]
	client.mu.Unlock()
	if duplicateMessageID {
		client.close()
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
	if frame.ProtocolTag == ldapwire.ApplicationExtendedRequest &&
		frame.ExtendedOID == clientStartTLSOID {
		return client.handleStartTLS(ctx, frame)
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
	if frame.ProtocolTag == ldapwire.ApplicationExtendedRequest {
		switch frame.ExtendedOID {
		case clientCancelOID:
			client.handleCancel(frame)
			return true
		}
	}
	client.route(frame, false)
	return true
}

func (client *clientConnection) handleStartTLS(
	ctx context.Context,
	frame proxyFrame,
) bool {
	client.mu.Lock()
	switch {
	case client.protocolVersion != 3:
		client.mu.Unlock()
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultProtocolError,
			"StartTLS requires LDAP version 3",
		)
		return true
	case frame.HasExtendedValue:
		client.mu.Unlock()
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultProtocolError,
			"StartTLS requestValue must be absent",
		)
		return true
	case client.tlsActive || client.tlsUpgrading:
		client.mu.Unlock()
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultOperationsError,
			"TLS is already active",
		)
		return true
	case client.binding || len(client.ops) != 0:
		client.mu.Unlock()
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultOperationsError,
			"StartTLS requires no operations in progress",
		)
		return true
	case client.proxy.config.ClientTLS == nil:
		client.mu.Unlock()
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultUnavailable,
			"client TLS configuration is unavailable",
		)
		return true
	default:
		client.tlsUpgrading = true
		client.mu.Unlock()
	}

	encoded, err := client.proxy.codec.EncodeResult(
		frame.MessageID,
		frame.ProtocolTag,
		ldapwire.ResultSuccess,
		"",
	)
	if err != nil {
		client.clearTLSUpgrade()
		return false
	}

	client.writeMu.Lock()
	connection := client.currentConnection()
	if connection == nil {
		err = net.ErrClosed
	} else {
		err = writeConnection(connection, encoded, client.proxy.config.IOTimeout)
	}
	var secured *tls.Conn
	if err == nil {
		secured = tls.Server(connection, client.proxy.config.ClientTLS.Clone())
		var clearDeadline func()
		clearDeadline, err = setConnectionNegotiationDeadline(
			ctx,
			secured,
			client.proxy.config.IOTimeout,
		)
		if err == nil {
			err = secured.HandshakeContext(ctx)
			clearDeadline()
		}
	}
	if err == nil {
		client.mu.Lock()
		if client.closed {
			err = net.ErrClosed
		} else {
			client.conn = secured
			client.tlsActive = true
			client.tlsUpgrading = false
		}
		client.mu.Unlock()
	}
	client.writeMu.Unlock()
	if err != nil {
		client.clearTLSUpgrade()
		if connection != nil {
			_ = connection.Close()
		}
		client.proxy.config.Logger.Debug("client StartTLS handshake failed", "error", err)
		return false
	}
	return true
}

func (client *clientConnection) clearTLSUpgrade() {
	client.mu.Lock()
	client.tlsUpgrading = false
	client.mu.Unlock()
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
	client.protocolVersion = frame.BindVersion
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
		!operation.bind && !operation.cancel && len(client.ops)+1 >= limit {
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

func (client *clientConnection) handleCancel(frame proxyFrame) {
	operation := &proxyOperation{
		client:     client,
		clientID:   frame.MessageID,
		requestTag: frame.ProtocolTag,
		cancel:     true,
		started:    time.Now(),
	}
	if _, _, closeClient, ok := client.register(operation); !ok {
		if closeClient {
			client.close()
		}
		return
	}
	reject := func(code ldapwire.ResultCode, diagnostic string) {
		operation.responseMu.Lock()
		won := operation.finish(false)
		operation.responseMu.Unlock()
		if won {
			client.sendResult(frame.MessageID, frame.ProtocolTag, code, diagnostic)
		}
	}

	if client.requestRestriction(frame) == RuntimeRestrictionReject {
		reject(ldapwire.ResultUnwillingToPerform, "extended operation or control disallowed")
		return
	}
	if !frame.HasExtendedValue {
		reject(ldapwire.ResultProtocolError, "no message ID supplied")
		return
	}
	if len(frame.ExtendedValue) == 0 {
		reject(ldapwire.ResultProtocolError, "empty request data field")
		return
	}
	targetID, err := ldapwire.DecodeCancelRequestValue([]byte(frame.ExtendedValue))
	if err != nil {
		reject(ldapwire.ResultProtocolError, "message ID parse failed")
		return
	}

	client.mu.Lock()
	target := client.ops[targetID]
	client.mu.Unlock()
	if target == nil {
		reject(ldapwire.ResultNoSuchOperation, "message ID not found")
		return
	}
	if target == operation {
		reject(ldapwire.ResultCannotCancel, "Cancel operations cannot be canceled")
		return
	}

	target.responseMu.Lock()
	client.mu.Lock()
	current := client.ops[targetID]
	client.mu.Unlock()
	if current != target || target.finished.Load() {
		target.responseMu.Unlock()
		reject(ldapwire.ResultNoSuchOperation, "message ID not found")
		return
	}
	if target.bind || target.cancel {
		target.responseMu.Unlock()
		diagnostic := "operation does not support cancellation"
		if target.cancel {
			diagnostic = "Cancel operations cannot be canceled"
		}
		reject(ldapwire.ResultCannotCancel, diagnostic)
		return
	}
	upstream, upstreamTargetID, duplicate, attached := attachCancelOperation(operation, target)
	if !attached {
		target.responseMu.Unlock()
		if duplicate {
			reject(ldapwire.ResultOperationsError, "message ID already being cancelled")
			return
		}
		reject(ldapwire.ResultTooLate, "operation can no longer be canceled")
		return
	}

	encoded, err := client.proxy.codec.RewriteExtendedRequestValue(
		frame,
		operation.upstreamID,
		ldapwire.EncodeCancelRequestValue(upstreamTargetID),
	)
	useProxyAuthz := client.proxy.config.ProxyAuthz &&
		!client.privileged() && !upstream.ownerFor(client)
	if err == nil && useProxyAuthz {
		var rewritten proxyFrame
		rewritten, err = client.proxy.codec.Read(bytes.NewReader(encoded), int64(len(encoded)))
		if err == nil {
			encoded, err = client.proxy.codec.PrependProxyAuthz(
				rewritten,
				operation.upstreamID,
				client.authorizationIdentity(),
			)
		}
	}
	writeAttempted := false
	if err == nil {
		writeAttempted = true
		err = operation.writeRequest(encoded)
	}
	target.responseMu.Unlock()
	if errors.Is(err, errOperationFinished) {
		return
	}
	if err == nil {
		return
	}
	operation.responseMu.Lock()
	won := operation.finish(false)
	operation.responseMu.Unlock()
	if won {
		client.sendResult(
			frame.MessageID,
			frame.ProtocolTag,
			ldapwire.ResultOther,
			"connection to the remote server has been severed",
		)
	}
	if writeAttempted {
		upstream.closeWithError(err)
	}
}

func (client *clientConnection) abandonOperation(
	operation *proxyOperation,
	frame *proxyFrame,
	finishUnabandonable bool,
) {
	operation.responseMu.Lock()
	operation.mu.Lock()
	bind := operation.bind
	unabandonable := bind || operation.cancel
	if unabandonable {
		operation.mu.Unlock()
		if finishUnabandonable {
			if operation.finish(false) {
				if bind {
					client.clearBindAttempt(operation)
				}
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
	err = writeConnection(client.currentConnection(), encoded, client.proxy.config.IOTimeout)
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
	connection := client.conn
	client.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return writeConnection(connection, encoded, client.proxy.config.IOTimeout)
}

func (client *clientConnection) currentConnection() net.Conn {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.conn
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
	connection := client.conn
	client.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
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
	messageID, ok := upstream.nextMessageIDLocked()
	if !ok {
		return false
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

func attachCancelOperation(
	operation *proxyOperation,
	target *proxyOperation,
) (*upstreamConnection, int64, bool, bool) {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	target.mu.Lock()
	defer target.mu.Unlock()
	if target.cancelInFlight {
		return nil, 0, true, false
	}
	if operation.finished.Load() || target.finished.Load() || target.abandoning ||
		!target.requestSent || target.upstream == nil || target.client != operation.client {
		return nil, 0, false, false
	}
	upstream := target.upstream
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	client := operation.client
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || upstream.closed ||
		upstream.pending[target.upstreamID] != target {
		return nil, 0, false, false
	}
	lease, err := client.proxy.scheduler.reserveSignalingConnection(upstream.id)
	if err != nil {
		return nil, 0, false, false
	}
	messageID, ok := upstream.nextMessageIDLocked()
	if !ok {
		lease.Release()
		return nil, 0, false, false
	}
	operation.upstream = upstream
	operation.upstreamID = messageID
	operation.lease = lease
	operation.cancelTarget = target
	target.cancelInFlight = true
	upstream.pending[messageID] = operation
	return upstream, target.upstreamID, false, true
}

func (upstream *upstreamConnection) allocateMessageID() (int64, bool) {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.nextMessageIDLocked()
}

func (upstream *upstreamConnection) nextMessageIDLocked() (int64, bool) {
	if upstream.closed {
		return 0, false
	}
	if upstream.nextID <= 0 || upstream.nextID > MaxMessageID {
		upstream.nextID = 1
	}
	first := upstream.nextID
	for {
		messageID := upstream.nextID
		upstream.nextID++
		if upstream.nextID > MaxMessageID {
			upstream.nextID = 1
		}
		if upstream.pending[messageID] == nil {
			return messageID, true
		}
		if upstream.nextID == first {
			return 0, false
		}
	}
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
	cancelTarget := operation.cancelTarget
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
	if cancelTarget != nil {
		cancelTarget.mu.Lock()
		cancelTarget.cancelInFlight = false
		cancelTarget.mu.Unlock()
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
