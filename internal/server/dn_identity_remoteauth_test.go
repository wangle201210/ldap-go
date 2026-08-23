package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityRemoteAuthExactOID       = "1.3.6.1.4.1.99999.951.1"
	dnIdentityRemoteAuthFoldOID        = "1.3.6.1.4.1.99999.951.2"
	dnIdentityRemoteAuthMappedExactOID = "1.3.6.1.4.1.99999.951.3"
	dnIdentityRemoteAuthMappedFoldOID  = "1.3.6.1.4.1.99999.951.4"
	dnIdentityRemoteAuthSuffix         = "dc=consumer,dc=test"
	dnIdentityRemoteAuthUpperDN        = "remoteAuthExactName=User+" +
		"remoteAuthFoldName=People," + dnIdentityRemoteAuthSuffix
	dnIdentityRemoteAuthLowerDN = "remoteAuthExactName=user+" +
		"remoteAuthFoldName=People," + dnIdentityRemoteAuthSuffix
)

func TestDNIdentityRemoteAuthOverlay(t *testing.T) {
	for _, backend := range dnIdentityRemoteAuthBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			successProvider := startDNIdentityRemoteAuthProvider(
				t,
				ldapwire.ResultSuccess,
			)
			failureProvider := startDNIdentityRemoteAuthProvider(
				t,
				ldapwire.ResultInvalidCredentials,
			)

			registry := dnIdentityRemoteAuthRegistry(t)
			database := dnIdentityRemoteAuthDatabase(
				t,
				registry,
				successProvider.uri(),
				failureProvider.uri(),
			)
			runtime := &runtimeState{
				schema:              registry,
				databases:           []runtimeDatabase{database},
				passwordHashSchemes: []string{auth.OpenLDAPDefaultHashScheme},
			}
			instance := &Server{config: Config{
				Store:  store,
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}}
			upperMapped := "remoteAuthMappedFoldAlias=\\20REMOTE\\20\\20IDENTITY\\20+" +
				dnIdentityRemoteAuthMappedExactOID + "=Target,DC=PROVIDER,DC=TEST"
			lowerMapped := dnIdentityRemoteAuthMappedFoldOID + "=Failure Identity+" +
				"remoteAuthMappedExactAlias=target,dc=provider,dc=test"
			seedDNIdentityRemoteAuthEntries(
				t,
				store,
				database,
				upperMapped,
				lowerMapped,
			)

			mismatched := mustDNIdentityRemoteAuthLegacyDN(
				t,
				"remoteAuthFoldAlias=PEOPLE+"+dnIdentityRemoteAuthExactOID+
					"=USER,DC=CONSUMER,DC=TEST",
			)
			handled, result, _ := instance.remoteAuthSimpleBind(
				t.Context(),
				runtime,
				database,
				mismatched,
				[]byte("must-not-be-forwarded"),
			)
			if handled || result.Code != 0 {
				t.Fatalf("caseExact-mismatched Bind = handled %t, result %d", handled, result.Code)
			}
			assertNoDNIdentityRemoteAuthRequest(t, successProvider)
			assertNoDNIdentityRemoteAuthRequest(t, failureProvider)

			lowerEquivalent := mustDNIdentityRemoteAuthLegacyDN(
				t,
				"remoteAuthFoldAlias=\\20PEOPLE\\20+"+
					dnIdentityRemoteAuthExactOID+
					"=user,DC=CONSUMER,DC=TEST",
			)
			failurePassword := []byte("failure-secret")
			handled, result, _ = instance.remoteAuthSimpleBind(
				t.Context(),
				runtime,
				database,
				lowerEquivalent,
				failurePassword,
			)
			if !handled || result.Code != ldapwire.ResultInvalidCredentials {
				t.Fatalf("failure provider Bind = handled %t, result %d", handled, result.Code)
			}
			failureRequest := waitDNIdentityRemoteAuthRequest(t, failureProvider)
			assertDNIdentityRemoteAuthWireRequest(
				t,
				registry,
				failureRequest,
				lowerMapped,
				failurePassword,
			)
			assertNoDNIdentityRemoteAuthRequest(t, successProvider)
			assertDNIdentityRemoteAuthPassword(t, store, database, lowerEquivalent, nil)

			upperEquivalent := mustDNIdentityRemoteAuthLegacyDN(
				t,
				"remoteAuthFoldAlias=\\20PEOPLE\\20\\20+"+
					dnIdentityRemoteAuthExactOID+
					"=User,DC=CONSUMER,DC=TEST",
			)
			successPassword := []byte("success-secret")
			handled, result, _ = instance.remoteAuthSimpleBind(
				t.Context(),
				runtime,
				database,
				upperEquivalent,
				successPassword,
			)
			if !handled || result.Code != ldapwire.ResultSuccess {
				t.Fatalf("success provider Bind = handled %t, result %d", handled, result.Code)
			}
			successRequest := waitDNIdentityRemoteAuthRequest(t, successProvider)
			assertDNIdentityRemoteAuthWireRequest(
				t,
				registry,
				successRequest,
				upperMapped,
				successPassword,
			)
			assertNoDNIdentityRemoteAuthRequest(t, failureProvider)
			assertDNIdentityRemoteAuthPassword(
				t,
				store,
				database,
				upperEquivalent,
				successPassword,
			)
			assertDNIdentityRemoteAuthPassword(t, store, database, lowerEquivalent, nil)
		})
	}
}

type dnIdentityRemoteAuthBackend struct {
	name string
	open func(*testing.T) storage.Store
}

func dnIdentityRemoteAuthBackends() []dnIdentityRemoteAuthBackend {
	return []dnIdentityRemoteAuthBackend{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}
}

func dnIdentityRemoteAuthRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + dnIdentityRemoteAuthExactOID +
			" NAME ( 'remoteAuthExactName' 'remoteAuthExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + dnIdentityRemoteAuthFoldOID +
			" NAME ( 'remoteAuthFoldName' 'remoteAuthFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + dnIdentityRemoteAuthMappedExactOID +
			" NAME ( 'remoteAuthMappedExactName' 'remoteAuthMappedExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + dnIdentityRemoteAuthMappedFoldOID +
			" NAME ( 'remoteAuthMappedFoldName' 'remoteAuthMappedFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityRemoteAuthDatabase(
	t *testing.T,
	registry *schema.Registry,
	successProvider,
	failureProvider string,
) runtimeDatabase {
	t.Helper()
	suffix, err := registry.NormalizeDN(dnIdentityRemoteAuthSuffix)
	if err != nil {
		t.Fatalf("NormalizeDN(suffix): %v", err)
	}
	return runtimeDatabase{
		name:         "{1}mdb",
		partition:    "dn-identity-remoteauth",
		suffixes:     []directory.DN{suffix},
		dnNormalizer: registry,
		remoteAuth: &remoteAuthRuntimeConfiguration{
			dnAttribute:     "seeAlso",
			domainAttribute: "description",
			mappings: map[string]string{
				"success": successProvider,
				"failure": failureProvider,
			},
			storeOnSuccess: true,
			connection: syncConsumerConfig{
				securityProperties: defaultSyncConsumerSASLSecurityProperties(),
			},
			pins: make(map[string]remoteAuthTLSPin),
		},
	}
}

func seedDNIdentityRemoteAuthEntries(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	upperMapped,
	lowerMapped string,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: dnIdentityRemoteAuthUpperDN,
			Attributes: []directory.Attribute{
				{Description: "remoteAuthExactAlias", Values: stringValues("User")},
				{Description: dnIdentityRemoteAuthFoldOID, Values: stringValues("People")},
				{Description: "seeAlso", Values: stringValues(upperMapped)},
				{Description: "description", Values: stringValues("SUCCESS:User")},
			},
		},
		{
			DN: dnIdentityRemoteAuthLowerDN,
			Attributes: []directory.Attribute{
				{Description: dnIdentityRemoteAuthExactOID, Values: stringValues("user")},
				{Description: "remoteAuthFoldAlias", Values: stringValues("People")},
				{Description: "seeAlso", Values: stringValues(lowerMapped)},
				{Description: "description", Values: stringValues("FAILURE:User")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed remoteauth entries: %v", err)
	}
}

func assertDNIdentityRemoteAuthPassword(
	t *testing.T,
	store storage.Store,
	database runtimeDatabase,
	dn directory.DN,
	want []byte,
) {
	t.Helper()
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(dn)
		if err != nil {
			return err
		}
		values := entry.Values("userPassword")
		if want == nil {
			if len(values) != 0 {
				return fmt.Errorf("unexpected stored password")
			}
			return nil
		}
		if len(values) != 1 || !auth.VerifyPassword(values[0], want) {
			return fmt.Errorf("stored password does not verify")
		}
		return nil
	}); err != nil {
		t.Fatalf("check remoteauth password: %v", err)
	}
}

func mustDNIdentityRemoteAuthLegacyDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func assertDNIdentityRemoteAuthWireRequest(
	t *testing.T,
	registry *schema.Registry,
	request ldapwire.BindRequest,
	mappedDN string,
	password []byte,
) {
	t.Helper()
	wantDN, err := registry.NormalizeDN(mappedDN)
	if err != nil {
		t.Fatalf("NormalizeDN(mapped DN): %v", err)
	}
	if request.Name != wantDN.String() {
		t.Fatalf("provider Bind DN = %q, want %q", request.Name, wantDN.String())
	}
	if request.Version != 3 || request.Authentication.IsSASL ||
		!bytes.Equal(request.Authentication.Simple, password) {
		t.Fatal("provider did not receive the expected LDAPv3 simple Bind")
	}
}

type dnIdentityRemoteAuthProvider struct {
	listener net.Listener
	result   ldapwire.ResultCode
	requests chan ldapwire.BindRequest
	errors   chan error
	wait     sync.WaitGroup
}

func startDNIdentityRemoteAuthProvider(
	t *testing.T,
	result ldapwire.ResultCode,
) *dnIdentityRemoteAuthProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen remoteauth provider: %v", err)
	}
	provider := &dnIdentityRemoteAuthProvider{
		listener: listener,
		result:   result,
		requests: make(chan ldapwire.BindRequest, 4),
		errors:   make(chan error, 4),
	}
	provider.wait.Add(1)
	go provider.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		provider.wait.Wait()
		select {
		case err := <-provider.errors:
			t.Errorf("remoteauth provider: %v", err)
		default:
		}
	})
	return provider
}

func (provider *dnIdentityRemoteAuthProvider) uri() string {
	return "ldap://" + provider.listener.Addr().String()
}

func (provider *dnIdentityRemoteAuthProvider) serve() {
	defer provider.wait.Done()
	for {
		connection, err := provider.listener.Accept()
		if err != nil {
			return
		}
		provider.wait.Add(1)
		go provider.handle(connection)
	}
}

func (provider *dnIdentityRemoteAuthProvider) handle(connection net.Conn) {
	defer provider.wait.Done()
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		provider.report(fmt.Errorf("read Bind: %w", err))
		return
	}
	request, ok := message.Request.(ldapwire.BindRequest)
	if !ok {
		provider.report(fmt.Errorf("request = %T, want Bind", message.Request))
		return
	}
	provider.requests <- request
	if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: provider.result},
		nil,
	)); err != nil {
		provider.report(fmt.Errorf("write Bind response: %w", err))
	}
}

func (provider *dnIdentityRemoteAuthProvider) report(err error) {
	select {
	case provider.errors <- err:
	default:
	}
}

func waitDNIdentityRemoteAuthRequest(
	t *testing.T,
	provider *dnIdentityRemoteAuthProvider,
) ldapwire.BindRequest {
	t.Helper()
	select {
	case request := <-provider.requests:
		return request
	case err := <-provider.errors:
		t.Fatalf("remoteauth provider: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("remoteauth provider did not receive Bind")
	}
	return ldapwire.BindRequest{}
}

func assertNoDNIdentityRemoteAuthRequest(
	t *testing.T,
	provider *dnIdentityRemoteAuthProvider,
) {
	t.Helper()
	select {
	case request := <-provider.requests:
		t.Fatalf("unexpected provider Bind for %q", request.Name)
	case err := <-provider.errors:
		t.Fatalf("remoteauth provider: %v", err)
	default:
	}
}
