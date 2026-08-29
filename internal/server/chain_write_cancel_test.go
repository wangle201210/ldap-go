package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestDelegatedWriteCancelDispatchBoundary(t *testing.T) {
	t.Parallel()

	mutations := []struct {
		name    string
		request ldapwire.Request
	}{
		{name: "Add", request: ldapwire.AddRequest{}},
		{name: "Modify", request: ldapwire.ModifyRequest{}},
		{name: "Delete", request: ldapwire.DeleteRequest{}},
		{name: "ModifyDN", request: ldapwire.ModifyDNRequest{}},
		{
			name: "Password Modify",
			request: ldapwire.ExtendedRequest{
				Name: passwordModifyOID,
			},
		},
		{
			name: "Dynamic Refresh",
			request: ldapwire.ExtendedRequest{
				Name: dynamicRefreshOID,
			},
		},
	}
	for index, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			message := ldapwire.Message{ID: int64(index + 1), Request: test.request}

			t.Run("Cancel wins", func(t *testing.T) {
				operations := newOperationRegistry()
				operation, ok := operations.register(context.Background(), message)
				if !ok || !operation.start() {
					t.Fatal("register or start operation failed")
				}
				ctx := withTrackedOperation(operation.ctx, operation)
				if _, result := operations.cancel(message.ID); result.Code != ldapwire.ResultSuccess {
					t.Fatalf("Cancel result = %d, want success", result.Code)
				}
				if err := disableTrackedOperationCancellationForRemoteCommit(ctx); !errors.Is(err, errOperationStopped) {
					t.Fatalf("remote dispatch boundary error = %v, want operation stopped", err)
				}
				if operation.stopMode() != operationCanceled {
					t.Fatalf("operation stop mode = %d, want canceled", operation.stopMode())
				}
				operations.finish(operation)
			})

			t.Run("Dispatch wins", func(t *testing.T) {
				operations := newOperationRegistry()
				operation, ok := operations.register(context.Background(), message)
				if !ok || !operation.start() {
					t.Fatal("register or start operation failed")
				}
				ctx := withTrackedOperation(operation.ctx, operation)
				if err := disableTrackedOperationCancellationForRemoteCommit(ctx); err != nil {
					t.Fatalf("remote dispatch boundary: %v", err)
				}
				if _, result := operations.cancel(message.ID); result.Code != ldapwire.ResultCannotCancel {
					t.Fatalf("Cancel result = %d, want cannotCancel", result.Code)
				}
				if err := ctx.Err(); err != nil {
					t.Fatalf("cannotCancel changed operation context: %v", err)
				}
				if operation.stopMode() != operationRunning {
					t.Fatalf("operation stop mode = %d, want running", operation.stopMode())
				}
				operations.finish(operation)
			})
		})
	}
}

func TestDelegatedReadCancellationRemainsEnabled(t *testing.T) {
	t.Parallel()

	for index, request := range []ldapwire.Request{
		ldapwire.SearchRequest{},
		ldapwire.CompareRequest{},
	} {
		if chainDelegatedRequestMayCommit(request) {
			t.Fatalf("request %T classified as committing", request)
		}
		operations := newOperationRegistry()
		operation, ok := operations.register(context.Background(), ldapwire.Message{
			ID:      int64(index + 1),
			Request: request,
		})
		if !ok || !operation.start() {
			t.Fatalf("register or start %T failed", request)
		}
		if _, result := operations.cancel(operation.id); result.Code != ldapwire.ResultSuccess {
			t.Fatalf("Cancel %T result = %d, want success", request, result.Code)
		}
		operations.finish(operation)
	}
}

func TestChainIgnoreCancelCannotRaceDelegatedAddCommit(t *testing.T) {
	_, chain, remote, peer := newBackMetaSafetyTransport(t, nil)
	remote.cancelMode = "ignore"

	entry := directory.Entry{
		DN: "uid=remote,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("remote")},
			{Description: "cn", Values: stringValues("Remote User")},
			{Description: "sn", Values: stringValues("User")},
		},
	}
	message := ldapwire.Message{
		ID:      41,
		Request: ldapwire.AddRequest{Entry: entry},
	}
	operations := newOperationRegistry()
	operation, ok := operations.register(context.Background(), message)
	if !ok || !operation.start() {
		t.Fatal("register or start Add operation failed")
	}
	ctx := withTrackedOperation(operation.ctx, operation)

	upstreamReceived := make(chan int64, 1)
	allowCommit := make(chan struct{})
	providerDone := make(chan error, 1)
	go func() {
		messageID, err := readBackMetaSafetyRequest(peer, ldapwire.ApplicationAddRequest)
		if err != nil {
			providerDone <- err
			return
		}
		upstreamReceived <- messageID
		<-allowCommit
		providerDone <- ldapwire.Write(peer, ldapwire.EncodeResultResponse(
			messageID,
			ldapwire.ApplicationAddResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}()

	attemptDone := make(chan chainAttempt, 1)
	go func() {
		attemptDone <- (&Server{}).executeChainTarget(
			ctx,
			&connectionState{protocolVersion: 3},
			chain,
			remote,
			message,
			0,
		)
	}()

	select {
	case <-upstreamReceived:
	case <-time.After(time.Second):
		t.Fatal("delegated Add did not reach upstream")
	}
	if _, result := operations.cancel(message.ID); result.Code != ldapwire.ResultCannotCancel {
		t.Fatalf("Cancel after upstream Add dispatch = %d, want cannotCancel", result.Code)
	}
	if operation.stopMode() != operationRunning {
		t.Fatalf("operation stop mode = %d, want running", operation.stopMode())
	}
	close(allowCommit)

	select {
	case attempt := <-attemptDone:
		if attempt.transportErr != nil || !attempt.hasResult ||
			attempt.result.Code != ldapwire.ResultSuccess {
			t.Fatalf("delegated Add attempt = %#v, want success", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("delegated Add did not complete")
	}
	select {
	case err := <-providerDone:
		if err != nil {
			t.Fatalf("upstream provider: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream provider did not complete")
	}
	operations.finish(operation)
}

func TestChainDoesNotDispatchDelegatedAddAfterCancelWins(t *testing.T) {
	_, chain, remote, peer := newBackMetaSafetyTransport(t, nil)
	remote.cancelMode = "ignore"
	message := ldapwire.Message{
		ID: 51,
		Request: ldapwire.AddRequest{Entry: directory.Entry{
			DN: "uid=canceled,dc=example,dc=com",
		}},
	}
	operations := newOperationRegistry()
	operation, ok := operations.register(context.Background(), message)
	if !ok || !operation.start() {
		t.Fatal("register or start Add operation failed")
	}
	ctx := withTrackedOperation(operation.ctx, operation)
	if _, result := operations.cancel(message.ID); result.Code != ldapwire.ResultSuccess {
		t.Fatalf("Cancel before upstream dispatch = %d, want success", result.Code)
	}

	attempt := (&Server{}).executeChainTarget(
		ctx,
		&connectionState{protocolVersion: 3},
		chain,
		remote,
		message,
		0,
	)
	if attempt.requestSent {
		t.Fatal("canceled delegated Add was marked as sent")
	}
	if !errors.Is(attempt.transportErr, context.Canceled) &&
		!errors.Is(attempt.transportErr, errOperationStopped) {
		t.Fatalf("canceled delegated Add error = %v", attempt.transportErr)
	}
	if err := peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set upstream read deadline: %v", err)
	}
	if _, err := readSyncConsumerPacket(peer); err == nil {
		t.Fatal("canceled delegated Add reached upstream")
	} else {
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("read canceled delegated Add: %v, want timeout", err)
		}
	}
	operations.finish(operation)
}
