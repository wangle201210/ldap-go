package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestChainNativeSASLAuthorizationIDByMode(t *testing.T) {
	t.Parallel()

	const boundDN = "uid=alice,ou=people,dc=example,dc=com"
	server := &Server{}
	state := &connectionState{
		boundDN: boundDN,
		runtime: &runtimeState{},
	}
	tests := []struct {
		name       string
		mode       chainIdentityMode
		assertedID string
		want       string
	}{
		{name: "anonymous", mode: chainIdentityAnonymous, want: "dn:"},
		{name: "self", mode: chainIdentitySelf, want: "dn:" + boundDN},
		{name: "legacy", mode: chainIdentityLegacy, want: "dn:" + boundDN},
		{
			name:       "other DN",
			mode:       chainIdentityOtherDN,
			assertedID: "dn:cn=asserted,dc=example,dc=com",
			want:       "dn:cn=asserted,dc=example,dc=com",
		},
		{
			name:       "other ID",
			mode:       chainIdentityOtherID,
			assertedID: "u:asserted",
			want:       "u:asserted",
		},
		{name: "none", mode: chainIdentityNone, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remote := nativeSASLChainRemote(test.mode, test.assertedID)
			remote.bind.authorizationID = "stale-configured-authzid"
			message := ldapwire.Message{
				ID:      1,
				Request: ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
				Controls: []ldapwire.Control{
					{
						OID:      proxyAuthorizationControlOID,
						Critical: true,
						Value:    []byte("dn:stale,dc=example,dc=com"),
						HasValue: true,
					},
					{OID: manageDsaITControlOID, Critical: true},
				},
			}

			gotRemote, gotMessage, failure := server.applyChainIdentity(
				context.Background(),
				state,
				remote,
				message,
			)
			if failure != nil {
				t.Fatalf("apply native SASL identity: %#v", failure)
			}
			if gotRemote.bind.authorizationID != test.want {
				t.Fatalf(
					"native authorization ID = %q, want %q",
					gotRemote.bind.authorizationID,
					test.want,
				)
			}
			if hasLDAPControl(gotMessage.Controls, proxyAuthorizationControlOID) {
				t.Fatalf("native identity retained ProxyAuthz control: %#v", gotMessage.Controls)
			}
			if !hasLDAPControl(gotMessage.Controls, manageDsaITControlOID) {
				t.Fatalf("native identity removed unrelated controls: %#v", gotMessage.Controls)
			}
		})
	}
}

func TestChainNativeSelfTransportIsolation(t *testing.T) {
	t.Parallel()

	server := &Server{}
	remote := nativeSASLChainRemote(chainIdentitySelf, "")
	remote.uri = "ldap://provider.example.test"
	remote.endpointKey = remote.uri
	message := ldapwire.Message{
		ID:      1,
		Request: ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
	}
	apply := func(boundDN string) chainRemoteConfiguration {
		got, _, failure := server.applyChainIdentity(
			context.Background(),
			&connectionState{boundDN: boundDN, runtime: &runtimeState{}},
			remote,
			message,
		)
		if failure != nil {
			t.Fatalf("apply native self identity for %q: %#v", boundDN, failure)
		}
		return got
	}

	alice := apply("uid=alice,dc=example,dc=com")
	bob := apply("uid=bob,dc=example,dc=com")
	if alice.bind.authorizationID == bob.bind.authorizationID {
		t.Fatalf("native self identities were not connection-specific: %q", alice.bind.authorizationID)
	}
	// OpenLDAP disables SELF+native because its admin connections are shared.
	// Here back-ldap opens operation-scoped transports, while back-meta includes
	// the dynamic authzID in its transport key.
	if metaTransportKey("target", alice) == metaTransportKey("target", bob) {
		t.Fatal("native self identities share a transport cache key")
	}
}

func TestOpenChainTransportDIGESTMD5UsesRemoteURI(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DIGEST-MD5 target: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	captured := make(chan chainDIGESTMD5Capture, 1)
	go func() {
		captured <- captureChainDIGESTMD5URI(listener)
	}()

	remote := nativeSASLChainRemote(chainIdentityOtherID, "u:asserted")
	remote.uri = "ldap://" + listener.Addr().String()
	remote.endpointKey = remote.uri
	remote.bind.saslMechanism = "DIGEST-MD5"
	remote.bind.authenticationID = "proxy"
	remote.bind.authorizationID = "u:asserted"
	remote.bind.realm = "example.com"
	remote.bind.credentials = []byte("secret")
	remote.bind.credentialsSet = true

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	transport, openErr := (&Server{}).openChainTransport(
		ctx,
		&connectionState{},
		remote,
		ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"},
	)
	if transport != nil {
		_ = transport.close()
	}
	if openErr == nil {
		t.Fatal("DIGEST-MD5 test target unexpectedly accepted the bind")
	}

	result := <-captured
	if result.err != nil {
		t.Fatalf("capture chained DIGEST-MD5 request: %v", result.err)
	}
	want := "ldap/" + strings.ToLower(listener.Addr().(*net.TCPAddr).IP.String())
	if result.digestURI != want {
		t.Fatalf("DIGEST-MD5 digest-uri = %q, want %q", result.digestURI, want)
	}
}

func TestMapMetaRemoteIdentityMassagesNativeAuthorizationDN(t *testing.T) {
	t.Parallel()

	local := mustChainNativeSASLDN(t, "dc=meta,dc=test")
	remoteSuffix := mustChainNativeSASLDN(t, "dc=provider,dc=test")
	mapping := &rwmRuntimeConfiguration{suffix: &rwmSuffixMapping{
		local:  local,
		remote: remoteSuffix,
	}}
	remote := nativeSASLChainRemote(chainIdentitySelf, "")
	remote.bind.bindDN = "cn=proxy,dc=meta,dc=test"
	remote.bind.authorizationID = "dn:uid=alice,ou=people,dc=meta,dc=test"
	message := ldapwire.Message{Controls: []ldapwire.Control{{
		OID:      proxyAuthorizationControlOID,
		Critical: true,
		Value:    []byte("dn:uid=bob,ou=people,dc=meta,dc=test"),
		HasValue: true,
	}}}

	gotRemote, gotMessage, failure := mapMetaRemoteIdentity(mapping, remote, message)
	if failure != nil {
		t.Fatalf("map back-meta remote identity: %#v", failure)
	}
	if gotRemote.bind.bindDN != "cn=proxy,dc=provider,dc=test" {
		t.Fatalf("mapped bind DN = %q", gotRemote.bind.bindDN)
	}
	if gotRemote.bind.authorizationID !=
		"dn:uid=alice,ou=people,dc=provider,dc=test" {
		t.Fatalf("mapped native authorization ID = %q", gotRemote.bind.authorizationID)
	}
	control := chainedProxyAuthorizationControl(gotMessage.Controls)
	if control == nil || string(control.Value) !=
		"dn:uid=bob,ou=people,dc=provider,dc=test" {
		t.Fatalf("mapped ProxyAuthz control = %#v", control)
	}
}

func TestMapMetaRemoteIdentityLeavesNonDNAuthorizationIDsUnchanged(t *testing.T) {
	t.Parallel()

	for _, authorizationID := range []string{"", "dn:", "u:alice"} {
		remote := nativeSASLChainRemote(chainIdentityOtherID, authorizationID)
		remote.bind.authorizationID = authorizationID
		got, _, failure := mapMetaRemoteIdentity(nil, remote, ldapwire.Message{})
		if failure != nil || got.bind.authorizationID != authorizationID {
			t.Fatalf(
				"map authorization ID %q = %q, %#v",
				authorizationID,
				got.bind.authorizationID,
				failure,
			)
		}
	}
}

func nativeSASLChainRemote(
	mode chainIdentityMode,
	assertedID string,
) chainRemoteConfiguration {
	remote := defaultChainRemoteConfiguration()
	remote.identity = chainIdentityAssertion{
		configured: true,
		mode:       mode,
		native:     true,
		assertedID: assertedID,
	}
	remote.bind.bindMethod = "sasl"
	remote.bind.saslMechanism = "PLAIN"
	remote.bind.authenticationID = "proxy"
	remote.bind.credentials = []byte("secret")
	remote.bind.credentialsSet = true
	return remote
}

type chainDIGESTMD5Capture struct {
	digestURI string
	err       error
}

func captureChainDIGESTMD5URI(listener net.Listener) chainDIGESTMD5Capture {
	connection, err := listener.Accept()
	if err != nil {
		return chainDIGESTMD5Capture{err: err}
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))

	initial, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return chainDIGESTMD5Capture{err: fmt.Errorf("read initial bind: %w", err)}
	}
	request, ok := initial.Request.(ldapwire.BindRequest)
	if !ok || !request.Authentication.IsSASL ||
		!strings.EqualFold(request.Authentication.SASLMechanism, "DIGEST-MD5") {
		return chainDIGESTMD5Capture{err: fmt.Errorf("initial request = %#v", initial.Request)}
	}
	challenge := []byte(
		`realm="example.com",nonce="chain-target",qop="auth",` +
			`charset=utf-8,algorithm=md5-sess`,
	)
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		initial.ID,
		ldapwire.Result{Code: ldapwire.ResultSASLBindInProgress},
		challenge,
		true,
		nil,
	)); err != nil {
		return chainDIGESTMD5Capture{err: fmt.Errorf("write challenge: %w", err)}
	}

	response, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return chainDIGESTMD5Capture{err: fmt.Errorf("read DIGEST-MD5 response: %w", err)}
	}
	request, ok = response.Request.(ldapwire.BindRequest)
	if !ok || !request.Authentication.IsSASL ||
		!request.Authentication.HasSASLCredentials {
		return chainDIGESTMD5Capture{err: fmt.Errorf("DIGEST-MD5 response = %#v", response.Request)}
	}
	directives, err := parseSASLDigestMD5Directives(request.Authentication.SASLCredentials)
	if err != nil {
		return chainDIGESTMD5Capture{err: fmt.Errorf("parse DIGEST-MD5 response: %w", err)}
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		response.ID,
		ldapwire.Result{Code: ldapwire.ResultInvalidCredentials},
		nil,
		false,
		nil,
	)); err != nil {
		return chainDIGESTMD5Capture{err: fmt.Errorf("write bind rejection: %w", err)}
	}
	return chainDIGESTMD5Capture{digestURI: directives["digest-uri"]}
}

func mustChainNativeSASLDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("parse DN %q: %v", value, err)
	}
	return dn
}
