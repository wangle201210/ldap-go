package server

import (
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestEffectiveChainProtocolVersion(t *testing.T) {
	t.Parallel()

	search := ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"}
	tests := []struct {
		name          string
		remoteVersion int
		state         *connectionState
		request       ldapwire.Request
		want          int
	}{
		{
			name:          "explicit LDAPv2 overrides LDAPv3 Bind and state",
			remoteVersion: 2,
			state:         &connectionState{protocolVersion: 3},
			request:       ldapwire.BindRequest{Version: 3},
			want:          2,
		},
		{
			name:          "explicit LDAPv3 overrides LDAPv2 Bind and state",
			remoteVersion: 3,
			state:         &connectionState{protocolVersion: 2},
			request:       ldapwire.BindRequest{Version: 2},
			want:          3,
		},
		{
			name:    "Bind inherits LDAPv2 request",
			state:   &connectionState{protocolVersion: 3},
			request: ldapwire.BindRequest{Version: 2},
			want:    2,
		},
		{
			name:    "Bind inherits LDAPv3 request",
			state:   &connectionState{protocolVersion: 2},
			request: ldapwire.BindRequest{Version: 3},
			want:    3,
		},
		{
			name:    "connection state supplies LDAPv2",
			state:   &connectionState{protocolVersion: 2},
			request: search,
			want:    2,
		},
		{
			name:    "connection state supplies LDAPv3",
			state:   &connectionState{protocolVersion: 3},
			request: search,
			want:    3,
		},
		{
			name:    "unsupported Bind version falls back to connection state",
			state:   &connectionState{protocolVersion: 2},
			request: ldapwire.BindRequest{Version: 1},
			want:    2,
		},
		{
			name:    "nil connection state defaults to LDAPv3",
			request: search,
			want:    3,
		},
		{
			name:    "unsupported connection version defaults to LDAPv3",
			state:   &connectionState{protocolVersion: 1},
			request: search,
			want:    3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := effectiveChainProtocolVersion(
				test.state,
				chainRemoteConfiguration{protocolVersion: test.remoteVersion},
				ldapwire.Message{Request: test.request},
			)
			if got != test.want {
				t.Fatalf("effectiveChainProtocolVersion() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestPrepareChainProtocolLDAPv2Bind(t *testing.T) {
	t.Parallel()

	message := ldapwire.Message{
		ID: 7,
		Request: ldapwire.BindRequest{
			Version: 3,
			Name:    "uid=alice,dc=example,dc=com",
		},
	}
	remote := chainRemoteConfiguration{protocolVersion: 2, sessionTracking: true}

	prepared, preparedRemote, result := prepareChainProtocolMessage(message, remote)
	if result != nil {
		t.Fatalf("prepareChainProtocolMessage() result = %#v, want nil", result)
	}
	request, ok := prepared.Request.(ldapwire.BindRequest)
	if !ok {
		t.Fatalf("prepared request type = %T, want ldapwire.BindRequest", prepared.Request)
	}
	if request.Version != 2 {
		t.Fatalf("prepared Bind version = %d, want 2", request.Version)
	}
	if preparedRemote.sessionTracking {
		t.Fatal("LDAPv2 left session tracking enabled")
	}
}

func TestPrepareChainProtocolLDAPv2Controls(t *testing.T) {
	t.Parallel()

	t.Run("noncritical controls are stripped", func(t *testing.T) {
		t.Parallel()

		message := ldapwire.Message{
			ID:      8,
			Request: ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
			Controls: []ldapwire.Control{
				{OID: manageDsaITControlOID},
				{OID: sessionTrackingControlOID, HasValue: true, Value: []byte("session")},
			},
		}
		remote := chainRemoteConfiguration{protocolVersion: 2, sessionTracking: true}

		prepared, preparedRemote, result := prepareChainProtocolMessage(message, remote)
		if result != nil {
			t.Fatalf("prepareChainProtocolMessage() result = %#v, want nil", result)
		}
		if len(prepared.Controls) != 0 {
			t.Fatalf("LDAPv2 controls = %#v, want none", prepared.Controls)
		}
		if preparedRemote.sessionTracking {
			t.Fatal("LDAPv2 left session tracking enabled")
		}
	})

	t.Run("critical control returns NoSuchObject", func(t *testing.T) {
		t.Parallel()

		message := ldapwire.Message{
			ID:      9,
			Request: ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
			Controls: []ldapwire.Control{{
				OID:      manageDsaITControlOID,
				Critical: true,
			}},
		}

		_, _, result := prepareChainProtocolMessage(
			message,
			chainRemoteConfiguration{protocolVersion: 2},
		)
		if result == nil || result.Code != ldapwire.ResultNoSuchObject {
			t.Fatalf("LDAPv2 critical control result = %#v, want NoSuchObject", result)
		}
	})
}

func TestPrepareChainProtocolLDAPv2ProxyAuthorization(t *testing.T) {
	t.Parallel()

	message := ldapwire.Message{
		ID:      10,
		Request: ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
		Controls: []ldapwire.Control{{
			OID:      proxyAuthorizationControlOID,
			HasValue: true,
			Value:    []byte("dn:uid=alice,dc=example,dc=com"),
		}},
	}

	_, _, result := prepareChainProtocolMessage(
		message,
		chainRemoteConfiguration{protocolVersion: 2},
	)
	if result == nil || result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("LDAPv2 proxyAuthz result = %#v, want UnwillingToPerform", result)
	}
}

func TestPrepareChainProtocolLDAPv3Controls(t *testing.T) {
	t.Parallel()

	message := ldapwire.Message{
		ID:      11,
		Request: ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
		Controls: []ldapwire.Control{
			{OID: manageDsaITControlOID, Critical: true},
			{
				OID:      proxyAuthorizationControlOID,
				HasValue: true,
				Value:    []byte("dn:uid=alice,dc=example,dc=com"),
			},
		},
	}
	remote := chainRemoteConfiguration{protocolVersion: 3, sessionTracking: true}

	prepared, preparedRemote, result := prepareChainProtocolMessage(message, remote)
	if result != nil {
		t.Fatalf("prepareChainProtocolMessage() result = %#v, want nil", result)
	}
	if !reflect.DeepEqual(prepared.Controls, message.Controls) {
		t.Fatalf("LDAPv3 controls = %#v, want %#v", prepared.Controls, message.Controls)
	}
	if !preparedRemote.sessionTracking {
		t.Fatal("LDAPv3 disabled session tracking")
	}
}
