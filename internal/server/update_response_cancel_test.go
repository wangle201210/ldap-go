package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestCancelIsTooLateAfterUpdateFinalResponseStarts(t *testing.T) {
	t.Parallel()

	client, serverConnection := net.Pipe()
	defer client.Close()
	defer serverConnection.Close()
	transport := &blockedWriteConnection{
		Conn:    serverConnection,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	message := ldapwire.Message{ID: 2, Request: ldapwire.ModifyRequest{}}
	operations := newOperationRegistry()
	operation, ok := operations.register(context.Background(), message)
	if !ok || !operation.start() {
		t.Fatal("register or start Modify operation failed")
	}
	connection := &operationResponseConnection{
		Conn: &serializedResponseConnection{
			Conn: transport,
			mu:   &sync.Mutex{},
		},
		operation: operation,
	}

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeResultForMessage(
			connection,
			message,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
		)
	}()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("Modify final response did not reach the transport")
	}

	_, result := operations.cancel(message.ID)
	close(transport.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("write Modify final response: %v", err)
	}
	if result.Code != ldapwire.ResultTooLate {
		t.Fatalf(
			"Cancel after Modify final response started = %d, want tooLate",
			result.Code,
		)
	}
	operations.finish(operation)
}

func TestCanceledOperationResponseTags(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		req  ldapwire.Request
		tag  uint64
	}{
		{name: "Search", req: ldapwire.SearchRequest{}, tag: ldapwire.ApplicationSearchResultDone},
		{name: "Compare", req: ldapwire.CompareRequest{}, tag: ldapwire.ApplicationCompareResponse},
		{name: "Add", req: ldapwire.AddRequest{}, tag: ldapwire.ApplicationAddResponse},
		{name: "Modify", req: ldapwire.ModifyRequest{}, tag: ldapwire.ApplicationModifyResponse},
		{name: "Delete", req: ldapwire.DeleteRequest{}, tag: ldapwire.ApplicationDeleteResponse},
		{name: "ModifyDN", req: ldapwire.ModifyDNRequest{}, tag: ldapwire.ApplicationModifyDNResponse},
		{
			name: "Extended",
			req:  ldapwire.ExtendedRequest{Name: "1.3.6.1.4.1.4203.666.999"},
			tag:  ldapwire.ApplicationExtendedResponse,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, serverConnection := net.Pipe()
			defer client.Close()
			defer serverConnection.Close()
			message := ldapwire.Message{ID: 9, Request: test.req}
			done := make(chan error, 1)
			go func() {
				done <- writeResultForMessage(
					serverConnection,
					message,
					ldapwire.Result{Code: ldapwire.ResultCanceled},
				)
			}()
			response := readRawLDAPPacket(t, client)
			assertRawLDAPEnvelope(
				t,
				response,
				9,
				test.tag,
				int64(ldapwire.ResultCanceled),
			)
			if err := <-done; err != nil {
				t.Fatalf("write canceled response: %v", err)
			}
		})
	}
}
