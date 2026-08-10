package lloadd

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func (upstream *upstreamConnection) readLoop(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			upstream.closeWithError(ctx.Err())
		case <-upstream.done:
		}
	}()
	for {
		frame, err := upstream.backend.proxy.codec.Read(
			upstream.conn,
			upstream.backend.proxy.config.UpstreamMaxMessageSize,
		)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				upstream.backend.proxy.config.Logger.Debug(
					"lloadd upstream read failed",
					"uri", upstream.backend.config.URI,
					"error", err,
				)
			}
			upstream.closeWithError(err)
			return
		}
		upstream.handleResponse(frame)
	}
}

func (upstream *upstreamConnection) handleResponse(frame proxyFrame) {
	if frame.MessageID == 0 {
		upstream.closeWithError(errors.New("unsolicited upstream response"))
		return
	}
	upstream.mu.Lock()
	operation := upstream.pending[frame.MessageID]
	upstream.mu.Unlock()
	if operation == nil {
		return
	}
	operation.responseMu.Lock()
	if operation.finished.Load() {
		operation.responseMu.Unlock()
		return
	}
	if operation.bind && frame.ProtocolTag != ldapwire.ApplicationBindResponse {
		operation.responseMu.Unlock()
		upstream.closeWithError(errors.New("unexpected response type for upstream Bind"))
		return
	}
	if operation.firstSeen.CompareAndSwap(false, true) {
		if operation.lease != nil {
			operation.lease.RecordFirstResponse(time.Since(operation.started))
		}
	}
	bindResponse := operation.bind &&
		frame.ProtocolTag == ldapwire.ApplicationBindResponse
	if bindResponse {
		if !frame.HasResultCode {
			operation.responseMu.Unlock()
			upstream.closeWithError(errors.New("upstream Bind response has no LDAP result"))
			return
		}
	}
	encoded, err := upstream.backend.proxy.codec.RewriteMessageID(frame, operation.clientID)
	if err != nil {
		operation.responseMu.Unlock()
		upstream.closeWithError(err)
		return
	}
	if bindResponse {
		publish, closeClient, closeUpstream := upstream.handleBindResponse(operation, frame)
		if !publish {
			operation.responseMu.Unlock()
			if closeUpstream {
				upstream.closeWithError(errors.New("stale Bind left an authenticated upstream"))
			}
			if closeClient {
				operation.client.close()
			}
			return
		}
	} else if frame.FinalResponse {
		if !operation.finish(true) {
			operation.responseMu.Unlock()
			return
		}
	}
	err = operation.client.write(encoded)
	operation.responseMu.Unlock()
	if err != nil {
		operation.client.close()
	}
}

func (upstream *upstreamConnection) handleBindResponse(
	operation *proxyOperation,
	frame proxyFrame,
) (publish bool, closeClient bool, closeUpstream bool) {
	client := operation.client
	result := frame.ResultCode
	keepConnection := result == ldapwire.ResultSASLBindInProgress ||
		(result == ldapwire.ResultSuccess &&
			(!client.proxy.config.ProxyAuthz || operation.bindSASL))
	if !operation.finish(true) {
		if keepConnection {
			return false, false, upstream.claimStaleOwnerForClose(operation)
		}
		upstream.releaseOwner(operation)
		return false, false, false
	}
	if keepConnection {
		upstream.mu.Lock()
		client.mu.Lock()
		if operation.bindGeneration != client.bindGeneration {
			closeUpstream = !upstream.closed &&
				upstream.owner == client &&
				upstream.ownerGeneration == operation.bindGeneration
			if closeUpstream {
				upstream.closed = true
			}
			client.mu.Unlock()
			upstream.mu.Unlock()
			return false, false, closeUpstream
		}
		if upstream.closed || upstream.owner != client ||
			upstream.ownerGeneration != operation.bindGeneration {
			client.binding = false
			client.bindPin = nil
			client.authzID = nil
			client.restriction = RuntimeRestrictionNone
			client.upstreamAffinity = nil
			client.mu.Unlock()
			upstream.mu.Unlock()
			return false, true, false
		}
		applyBindResultLocked(client, operation, result, upstream)
		client.mu.Unlock()
		_ = upstream.backend.proxy.scheduler.SetConnectionState(
			upstream.id,
			ConnectionBusy,
		)
		upstream.mu.Unlock()
		return true, false, false
	}
	client.mu.Lock()
	if operation.bindGeneration != client.bindGeneration {
		client.mu.Unlock()
		upstream.releaseOwner(operation)
		return false, false, false
	}
	applyBindResultLocked(client, operation, result, upstream)
	client.mu.Unlock()
	upstream.releaseOwner(operation)
	return true, false, false
}

func (upstream *upstreamConnection) claimStaleOwnerForClose(operation *proxyOperation) bool {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.closed || upstream.owner != operation.client ||
		upstream.ownerGeneration != operation.bindGeneration {
		return false
	}
	upstream.closed = true
	return true
}

func applyBindResultLocked(
	client *clientConnection,
	operation *proxyOperation,
	result ldapwire.ResultCode,
	upstream *upstreamConnection,
) {
	if result == ldapwire.ResultSASLBindInProgress {
		client.binding = true
		client.bindPin = upstream
		return
	}
	client.binding = false
	client.bindPin = nil
	if result == ldapwire.ResultSuccess {
		if operation.bindSASL {
			client.authzID = nil
		} else if operation.bindDN == "" {
			client.authzID = []byte{}
		} else {
			client.authzID = []byte("dn:" + operation.bindDN)
		}
	} else {
		client.authzID = nil
	}
	if result == ldapwire.ResultSuccess &&
		(!client.proxy.config.ProxyAuthz || operation.bindSASL) {
		client.restriction = RuntimeRestrictionConnection
		client.upstreamAffinity = upstream
	}
}

func (upstream *upstreamConnection) releaseOwner(operation *proxyOperation) {
	upstream.mu.Lock()
	released := false
	if upstream.owner == operation.client &&
		upstream.ownerGeneration == operation.bindGeneration {
		upstream.owner = nil
		upstream.ownerGeneration = 0
		released = !upstream.closed
	}
	if released {
		_ = upstream.backend.proxy.scheduler.SetConnectionState(
			upstream.id,
			ConnectionReady,
		)
	}
	upstream.mu.Unlock()
}

func (upstream *upstreamConnection) closeWithError(cause error) {
	upstream.once.Do(func() {
		upstream.mu.Lock()
		upstream.closed = true
		close(upstream.done)
		operations := make([]*proxyOperation, 0, len(upstream.pending))
		for _, operation := range upstream.pending {
			operations = append(operations, operation)
		}
		owner := upstream.owner
		upstream.owner = nil
		upstream.ownerGeneration = 0
		upstream.pending = make(map[int64]*proxyOperation)
		upstream.mu.Unlock()
		_ = upstream.conn.Close()
		upstream.backend.remove(upstream)

		for _, operation := range operations {
			operation.responseMu.Lock()
			if operation.finish(false) {
				operation.client.clearBindAttempt(operation)
				operation.client.sendResult(
					operation.clientID,
					operation.requestTag,
					ldapwire.ResultOther,
					"connection to the remote server has been severed",
				)
			}
			operation.responseMu.Unlock()
		}
		clients := make(map[*clientConnection]struct{})
		if owner != nil {
			clients[owner] = struct{}{}
		}
		upstream.backend.proxy.mu.Lock()
		for client := range upstream.backend.proxy.clients {
			clients[client] = struct{}{}
		}
		upstream.backend.proxy.mu.Unlock()
		for client := range clients {
			client.mu.Lock()
			linked := client.upstreamAffinity == upstream
			pinned := client.bindPin == upstream
			if pinned {
				client.bindPin = nil
				client.binding = false
			}
			if linked {
				client.upstreamAffinity = nil
				client.restriction = RuntimeRestrictionNone
			}
			client.mu.Unlock()
			if linked || (pinned && owner == client) {
				client.close()
			}
		}
		if cause != nil && !errors.Is(cause, context.Canceled) &&
			!errors.Is(cause, ErrProxyClosed) {
			upstream.backend.proxy.config.Logger.Debug(
				"lloadd upstream closed",
				"uri", upstream.backend.config.URI,
				"error", cause,
			)
		}
	})
}
