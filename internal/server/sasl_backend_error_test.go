package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

const openLDAPSASLAuxiliaryLookupCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferenceSASLAuxiliaryLookupFailureMapping(t *testing.T) {
	_ = requireOpenLDAPLDAPBackendReferenceTools(t)
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("SASL auxiliary lookup reference requires a verified OpenLDAP build")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPSASLAuxiliaryLookupCommit {
		t.Fatalf("OpenLDAP reference commit = %q", got)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	path := filepath.Join(sourceRoot, "servers", "slapd", "sasl.c")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
	}
	source := string(contents)
	lookup := openLDAPSourceSection(
		t,
		source,
		"slap_auxprop_lookup(",
		"slap_auxprop_store(",
	)
	if !strings.Contains(
		lookup,
		"return rc != LDAP_SUCCESS ? SASL_FAIL : SASL_OK;",
	) {
		t.Fatal("pinned slap_auxprop_lookup no longer maps LDAP failures to SASL_FAIL")
	}
	mapper := openLDAPSourceSection(
		t,
		source,
		"slap_sasl_err2ldap( int saslerr )",
		"#ifdef SLAPD_SPASSWD",
	)
	failure := strings.Index(mapper, "case SASL_FAIL:")
	other := strings.Index(mapper, "rc = LDAP_OTHER;")
	if failure < 0 || other < 0 || other < failure {
		t.Fatal("pinned slap_sasl_err2ldap no longer maps SASL_FAIL to LDAP_OTHER")
	}
}

func openLDAPSourceSection(
	t *testing.T,
	source string,
	startAnchor string,
	endAnchor string,
) string {
	t.Helper()
	start := strings.Index(source, startAnchor)
	if start < 0 {
		t.Fatalf("pinned OpenLDAP source lacks %q", startAnchor)
	}
	end := strings.Index(source[start+len(startAnchor):], endAnchor)
	if end < 0 {
		t.Fatalf("pinned OpenLDAP source lacks %q after %q", endAnchor, startAnchor)
	}
	return source[start : start+len(startAnchor)+end]
}

func TestLDAPBackendSASLAuxiliaryLookupFailures(t *testing.T) {
	mechanisms := []struct {
		mechanism string
		configure func(*testing.T, storage.Store)
		exchange  func(*testing.T, net.Conn) (*ber.Packet, int64)
	}{
		{
			mechanism: "PLAIN",
			configure: func(t *testing.T, store storage.Store) {
				configureSASLBackendGlobal(t, store, ldapBackendTestSuffix)
			},
			exchange: exchangeSASLPlainLookupFailure,
		},
		{
			mechanism: "CRAM-MD5",
			configure: func(t *testing.T, store storage.Store) {
				configureSASLBackendGlobal(t, store, ldapBackendTestSuffix)
			},
			exchange: exchangeSASLCRAMMD5LookupFailure,
		},
		{
			mechanism: "DIGEST-MD5",
			configure: func(t *testing.T, store storage.Store) {
				configureSASLBackendDigestSCRAM(t, store, ldapBackendTestSuffix)
			},
			exchange: exchangeSASLDigestMD5LookupFailure,
		},
		{
			mechanism: "SCRAM-SHA-256",
			configure: func(t *testing.T, store storage.Store) {
				configureSASLBackendDigestSCRAM(t, store, ldapBackendTestSuffix)
			},
			exchange: exchangeSASLSCRAMLookupFailure,
		},
	}
	failures := []struct {
		name string
		mode saslCredentialProviderFailure
	}{
		{name: "transport closes during Search", mode: saslCredentialTransportClose},
		{name: "Search returns unavailable", mode: saslCredentialLDAPUnavailable},
	}

	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			for _, mechanism := range mechanisms {
				t.Run(mechanism.mechanism, func(t *testing.T) {
					provider := startSASLCredentialFailureProvider(
						t,
						failure.mode,
					)

					proxyStore := storage.NewMemory()
					t.Cleanup(func() { _ = proxyStore.Close() })
					seedLDAPBackendProxy(t, proxyStore, provider.address)
					mechanism.configure(t, proxyStore)
					configureLDAPBackendSASLCredentialBinds(t, proxyStore, true)
					proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
					defer stopProxy()

					connection, err := net.DialTimeout(
						"tcp",
						proxyAddress,
						2*time.Second,
					)
					if err != nil {
						t.Fatalf("dial proxy: %v", err)
					}
					defer connection.Close()
					if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatalf("set client deadline: %v", err)
					}

					response, nextMessageID := mechanism.exchange(t, connection)
					assertRawSASLBindResult(
						t,
						response,
						nextMessageID-1,
						ldapwire.ResultOther,
					)
					if diagnostic := rawLDAPDiagnostic(response); diagnostic != "" {
						t.Fatalf("lookup failure diagnostic = %q, want empty", diagnostic)
					}
					if provider.searches.Load() == 0 {
						t.Fatal("provider did not receive a credential Search")
					}

					response = sendRawLDAPOperation(
						t,
						connection,
						nextMessageID,
						rawExtendedRequest(whoAmIOID, nil, false),
					)
					assertRawLDAPOperationResult(
						t,
						response,
						nextMessageID,
						ldapwire.ApplicationExtendedResponse,
						ldapwire.ResultSuccess,
					)
					nextMessageID++

					response = sendRawLDAPOperation(
						t,
						connection,
						nextMessageID,
						rawSimpleBindRequest("", ""),
					)
					assertRawSASLBindResult(
						t,
						response,
						nextMessageID,
						ldapwire.ResultSuccess,
					)
					provider.assertNoErrors(t)
				})
			}
		})
	}
}

func exchangeSASLPlainLookupFailure(
	t *testing.T,
	connection net.Conn,
) (*ber.Packet, int64) {
	t.Helper()
	challenge := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSASLBindRequestWithoutCredentials("PLAIN"),
	)
	assertRawSASLBindResult(
		t,
		challenge,
		1,
		ldapwire.ResultSASLBindInProgress,
	)
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawSASLBindRequest(
			"PLAIN",
			[]byte("\x00alice\x00"+ldapBackendTestUserPassword),
		),
	)
	return response, 3
}

func exchangeSASLCRAMMD5LookupFailure(
	t *testing.T,
	connection net.Conn,
) (*ber.Packet, int64) {
	t.Helper()
	challenge := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSASLBindRequestWithoutCredentials("CRAM-MD5"),
	)
	assertRawSASLBindResult(
		t,
		challenge,
		1,
		ldapwire.ResultSASLBindInProgress,
	)
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawSASLBindRequest(
			"CRAM-MD5",
			[]byte("alice "+strings.Repeat("0", 32)),
		),
	)
	return response, 3
}

func exchangeSASLDigestMD5LookupFailure(
	t *testing.T,
	connection net.Conn,
) (*ber.Packet, int64) {
	t.Helper()
	challenge := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSASLBindRequestWithoutCredentials("DIGEST-MD5"),
	)
	assertRawSASLBindResult(
		t,
		challenge,
		1,
		ldapwire.ResultSASLBindInProgress,
	)
	directives, err := parseSASLDigestMD5Directives(
		rawSASLServerCredentials(t, challenge),
	)
	if err != nil {
		t.Fatalf("parse DIGEST-MD5 challenge: %v", err)
	}
	request := saslDigestMD5Response{
		username:   "alice",
		realm:      directives["realm"],
		nonce:      directives["nonce"],
		cnonce:     "transport-failure-test",
		nonceCount: 1,
		qop:        saslDigestMD5AuthenticationQOP,
		digestURI:  "ldap/ldap.example.test",
	}
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawSASLBindRequest(
			"DIGEST-MD5",
			formatSASLDigestMD5Response(
				request,
				strings.Repeat("0", 32),
			),
		),
	)
	return response, 3
}

func exchangeSASLSCRAMLookupFailure(
	t *testing.T,
	connection net.Conn,
) (*ber.Packet, int64) {
	t.Helper()
	challenge := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSASLBindRequestWithoutCredentials("SCRAM-SHA-256"),
	)
	assertRawSASLBindResult(
		t,
		challenge,
		1,
		ldapwire.ResultSASLBindInProgress,
	)
	client, err := scram.SHA256.NewClient(
		"alice",
		ldapBackendTestUserPassword,
		"",
	)
	if err != nil {
		t.Fatalf("create SCRAM client: %v", err)
	}
	initial, err := client.NewConversation().Step("")
	if err != nil {
		t.Fatalf("create SCRAM client-first message: %v", err)
	}
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawSASLBindRequest("SCRAM-SHA-256", []byte(initial)),
	)
	return response, 3
}

func rawSASLBindRequestWithoutCredentials(mechanism string) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(3),
		"version",
	))
	request.AppendChild(rawOctetString(nil))
	authentication := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		3,
		nil,
		"SASL authentication",
	)
	authentication.AppendChild(rawOctetString([]byte(mechanism)))
	request.AppendChild(authentication)
	return request
}

func assertRawSASLBindResult(
	t *testing.T,
	response *ber.Packet,
	messageID int64,
	want ldapwire.ResultCode,
) {
	t.Helper()
	assertRawLDAPOperationResult(
		t,
		response,
		messageID,
		ldapwire.ApplicationBindResponse,
		want,
	)
}

func assertRawLDAPOperationResult(
	t *testing.T,
	response *ber.Packet,
	messageID int64,
	applicationTag uint64,
	want ldapwire.ResultCode,
) {
	t.Helper()
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("LDAP response envelope = %#v", response)
	}
	gotMessageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAP response message ID: %v", err)
	}
	operation := response.Children[1]
	if gotMessageID != messageID ||
		operation.ClassType != ber.ClassApplication ||
		operation.TagType != ber.TypeConstructed ||
		uint64(operation.Tag) != applicationTag {
		t.Fatalf(
			"LDAP response = id %d class %d type %d tag %d; want id %d tag %d",
			gotMessageID,
			operation.ClassType,
			operation.TagType,
			operation.Tag,
			messageID,
			applicationTag,
		)
	}
	if got := rawLDAPResultCode(t, operation); got != int64(want) {
		t.Fatalf("LDAP result = %d, want %d", got, want)
	}
}

func rawSASLServerCredentials(t *testing.T, response *ber.Packet) []byte {
	t.Helper()
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("SASL response envelope = %#v", response)
	}
	for _, child := range response.Children[1].Children[3:] {
		if child.ClassType == ber.ClassContext &&
			child.TagType == ber.TypePrimitive &&
			child.Tag == 7 {
			return append([]byte(nil), child.Data.Bytes()...)
		}
	}
	t.Fatal("SASL response has no server credentials")
	return nil
}

type saslCredentialProviderFailure uint8

const (
	saslCredentialTransportClose saslCredentialProviderFailure = iota
	saslCredentialLDAPUnavailable
)

type saslCredentialFailureProvider struct {
	address       string
	listener      net.Listener
	failure       saslCredentialProviderFailure
	done          chan struct{}
	errors        chan error
	searches      atomic.Int64
	closeOnce     sync.Once
	handlers      sync.WaitGroup
	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
}

func startSASLCredentialFailureProvider(
	t *testing.T,
	failure saslCredentialProviderFailure,
) *saslCredentialFailureProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for credential drop provider: %v", err)
	}
	provider := &saslCredentialFailureProvider{
		address:     listener.Addr().String(),
		listener:    listener,
		failure:     failure,
		done:        make(chan struct{}),
		errors:      make(chan error, 8),
		connections: make(map[net.Conn]struct{}),
	}
	go provider.serve()
	t.Cleanup(provider.close)
	return provider
}

func (provider *saslCredentialFailureProvider) serve() {
	defer close(provider.done)
	for {
		connection, err := provider.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				provider.report(fmt.Errorf("accept credential connection: %w", err))
			}
			return
		}
		provider.connectionsMu.Lock()
		provider.connections[connection] = struct{}{}
		provider.connectionsMu.Unlock()
		provider.handlers.Add(1)
		go provider.handle(connection)
	}
}

func (provider *saslCredentialFailureProvider) handle(connection net.Conn) {
	defer provider.handlers.Done()
	defer func() {
		_ = connection.Close()
		provider.connectionsMu.Lock()
		delete(provider.connections, connection)
		provider.connectionsMu.Unlock()
	}()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		provider.report(fmt.Errorf("set credential connection deadline: %w", err))
		return
	}

	message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		provider.report(fmt.Errorf("read credential Bind: %w", err))
		return
	}
	if _, ok := message.Request.(ldapwire.BindRequest); !ok {
		provider.report(fmt.Errorf("credential first request = %T, want Bind", message.Request))
		return
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
	)); err != nil {
		provider.report(fmt.Errorf("write credential Bind response: %w", err))
		return
	}

	message, err = ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		provider.report(fmt.Errorf("read credential Search: %w", err))
		return
	}
	if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
		provider.report(fmt.Errorf("credential second request = %T, want Search", message.Request))
		return
	}
	provider.searches.Add(1)
	if provider.failure == saslCredentialLDAPUnavailable {
		if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnavailable,
				"credential provider unavailable",
			),
			nil,
		)); err != nil {
			provider.report(fmt.Errorf("write credential Search result: %w", err))
		}
	}
}

func (provider *saslCredentialFailureProvider) report(err error) {
	select {
	case provider.errors <- err:
	default:
	}
}

func (provider *saslCredentialFailureProvider) close() {
	provider.closeOnce.Do(func() {
		_ = provider.listener.Close()
		<-provider.done
		provider.connectionsMu.Lock()
		for connection := range provider.connections {
			_ = connection.Close()
		}
		provider.connectionsMu.Unlock()
		provider.handlers.Wait()
	})
}

func (provider *saslCredentialFailureProvider) assertNoErrors(t *testing.T) {
	t.Helper()
	provider.close()
	select {
	case err := <-provider.errors:
		t.Fatalf("credential drop provider: %v", err)
	default:
	}
}
