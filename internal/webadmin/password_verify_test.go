package webadmin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestPasswordVerifyUsesTemporaryConnectionAndPreservesSession(t *testing.T) {
	t.Parallel()
	administrator := &fakeClient{}
	verifiedClient := &fakeClient{}
	invalidClient := &fakeClient{}
	var verifiedDN, verifiedPassword string
	verifiedClient.bindFunc = func(username, password string) error {
		verifiedDN, verifiedPassword = username, password
		return nil
	}
	invalidClient.bindFunc = func(username, password string) error {
		if username != "uid=alice,dc=example,dc=com" || password != "wrong-secret" {
			return errors.New("unexpected invalid-credential Bind arguments")
		}
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	}
	connector := &fakeConnector{clients: []Client{administrator, verifiedClient, invalidClient}}
	tlsConfig := &tls.Config{ServerName: "ldap.example", MinVersion: tls.VersionTLS13}
	application, _ := newTestApplication(t, connector, func(config *Config) {
		config.StartTLS = true
		config.TLSConfig = tlsConfig
		config.DialTimeout = 3 * time.Second
		config.OperationTimeout = 7 * time.Second
	})
	authenticated := loginTestSession(t, application, "dn")

	verified := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
		"user_identity": "uid=alice,dc=example,dc=com",
		"password":      "correct-secret",
	}, authenticated.cookie, authenticated.csrf)
	assertPasswordVerified(t, verified, true)
	if verifiedDN != "uid=alice,dc=example,dc=com" || verifiedPassword != "correct-secret" {
		t.Fatalf("temporary Bind credentials = (%q, %q)", verifiedDN, verifiedPassword)
	}

	rejected := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
		"user_identity": "uid=alice,dc=example,dc=com",
		"password":      "wrong-secret",
	}, authenticated.cookie, authenticated.csrf)
	assertPasswordVerified(t, rejected, false)

	if got := closeCount(verifiedClient); got != 1 {
		t.Fatalf("successful verification connection close count = %d, want 1", got)
	}
	if got := closeCount(invalidClient); got != 1 {
		t.Fatalf("invalid verification connection close count = %d, want 1", got)
	}
	if got := closeCount(administrator); got != 0 {
		t.Fatalf("administrator connection close count = %d, want 0", got)
	}
	administrator.mu.Lock()
	administratorDN := administrator.bindDN
	administrator.mu.Unlock()
	if administratorDN != "cn=admin,dc=example,dc=com" {
		t.Fatalf("administrator connection bind DN = %q", administratorDN)
	}
	assertSessionAvailable(t, application, authenticated)

	connector.mu.Lock()
	configs := append([]ConnectConfig(nil), connector.configs...)
	connector.mu.Unlock()
	if len(configs) != 3 {
		t.Fatalf("LDAP connect configs = %d, want login plus two verification connections", len(configs))
	}
	for index, config := range configs[1:] {
		if config.URL != "ldap://127.0.0.1:389" || !config.StartTLS ||
			config.DialTimeout != 3*time.Second || config.OperationTimeout != 7*time.Second ||
			config.TLSConfig == nil || config.TLSConfig.ServerName != "ldap.example" ||
			config.TLSConfig.MinVersion != tls.VersionTLS13 {
			t.Fatalf("verification Connect config %d = %#v", index+1, config)
		}
		if config.TLSConfig == application.config.TLSConfig || config.TLSConfig == configs[0].TLSConfig {
			t.Fatalf("verification Connect config %d reused a mutable TLS config", index+1)
		}
	}
	if configs[1].TLSConfig == configs[2].TLSConfig || configs[1].TLSConfig == tlsConfig {
		t.Fatal("temporary verification connections did not receive independent TLS config clones")
	}
}

func TestPasswordVerifyRejectsBeforeLDAPConnect(t *testing.T) {
	t.Parallel()

	t.Run("unauthenticated", func(t *testing.T) {
		connector := &fakeConnector{}
		application, _ := newTestApplication(t, connector, nil)
		response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, nil, "")
		if response.Code != http.StatusUnauthorized || connector.connectCount() != 0 {
			t.Fatalf("status = %d, connects = %d, body = %s", response.Code, connector.connectCount(), response.Body.String())
		}
	})

	t.Run("mutation security and validation", func(t *testing.T) {
		administrator := &fakeClient{}
		connector := &fakeConnector{clients: []Client{administrator}}
		application, _ := newTestApplication(t, connector, nil)
		authenticated := loginTestSession(t, application, "dn")
		body := map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}

		badCSRF := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", body,
			authenticated.cookie, "wrong")
		if badCSRF.Code != http.StatusForbidden {
			t.Fatalf("bad CSRF status = %d, body = %s", badCSRF.Code, badCSRF.Body.String())
		}

		badOrigin := performPasswordVerifyRequest(t, application, body, authenticated, "https://evil.example", context.Background())
		if badOrigin.Code != http.StatusForbidden {
			t.Fatalf("bad origin status = %d, body = %s", badOrigin.Code, badOrigin.Body.String())
		}

		invalidDN := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "not a DN", "password": "secret",
		}, authenticated.cookie, authenticated.csrf)
		if invalidDN.Code != http.StatusBadRequest {
			t.Fatalf("invalid DN status = %d, body = %s", invalidDN.Code, invalidDN.Body.String())
		}

		emptyPassword := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "",
		}, authenticated.cookie, authenticated.csrf)
		if emptyPassword.Code != http.StatusBadRequest {
			t.Fatalf("empty password status = %d, body = %s", emptyPassword.Code, emptyPassword.Body.String())
		}
		if connector.connectCount() != 1 {
			t.Fatalf("connect count = %d, want only administrator login", connector.connectCount())
		}
		assertSessionAvailable(t, application, authenticated)
	})

	t.Run("shared login rate limit", func(t *testing.T) {
		administrator := &fakeClient{}
		connector := &fakeConnector{clients: []Client{administrator}}
		application, _ := newTestApplication(t, connector, func(config *Config) {
			config.LoginRateLimit = 1
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" ||
			!strings.Contains(response.Body.String(), "login_rate_limited") {
			t.Fatalf("rate-limited status = %d, headers = %#v, body = %s", response.Code, response.Header(), response.Body.String())
		}
		if connector.connectCount() != 1 {
			t.Fatalf("connect count = %d, want only administrator login", connector.connectCount())
		}
		assertSessionAvailable(t, application, authenticated)
	})

	t.Run("LDAP operation admission", func(t *testing.T) {
		administrator := &fakeClient{}
		connector := &fakeConnector{clients: []Client{administrator}}
		application, _ := newTestApplication(t, connector, func(config *Config) {
			config.MaxConcurrentOperations = 1
		})
		authenticated := loginTestSession(t, application, "dn")
		application.operations <- struct{}{}
		response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, authenticated.cookie, authenticated.csrf)
		<-application.operations
		if response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), "operation_capacity_reached") {
			t.Fatalf("capacity status = %d, body = %s", response.Code, response.Body.String())
		}
		if connector.connectCount() != 1 {
			t.Fatalf("connect count = %d, want only administrator login", connector.connectCount())
		}
		if !webRequestUsesLDAP("/api/password-verify") {
			t.Fatal("password verification route is missing LDAP operation admission")
		}
	})
}

func TestPasswordVerifyRequiresLDAPAuthorizationForOtherIdentity(t *testing.T) {
	t.Parallel()
	administrator := &fakeClient{}
	var compared []string
	administrator.compareFunc = func(dn, attribute, value string) (bool, error) {
		if dn != "uid=alice,dc=example,dc=com" || value != "ldap-go-password-verification-authorization-probe" {
			t.Fatalf("authorization Compare = (%q, %q, %q)", dn, attribute, value)
		}
		compared = append(compared, attribute)
		return false, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
	}
	connector := &fakeConnector{clients: []Client{administrator}}
	application, _ := newTestApplication(t, connector, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
		"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
	}, authenticated.cookie, authenticated.csrf)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "password_verification_forbidden") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !reflect.DeepEqual(compared, []string{"userPassword", "authPassword"}) {
		t.Fatalf("authorization Compare attributes = %q", compared)
	}
	if connector.connectCount() != 1 {
		t.Fatalf("connect count = %d, want only administrator login", connector.connectCount())
	}
	assertSessionAvailable(t, application, authenticated)
}

func TestPasswordVerifyAllowsCurrentBoundIdentityWithoutPasswordAttributeCompare(t *testing.T) {
	t.Parallel()
	administrator := &fakeClient{compareFunc: func(string, string, string) (bool, error) {
		t.Fatal("self password verification performed an authorization Compare")
		return false, nil
	}}
	temporary := &fakeClient{}
	connector := &fakeConnector{clients: []Client{administrator, temporary}}
	application, _ := newTestApplication(t, connector, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
		"user_identity": "CN=ADMIN,DC=EXAMPLE,DC=COM", "password": "not-retained",
	}, authenticated.cookie, authenticated.csrf)
	assertPasswordVerified(t, response, true)
	if closeCount(temporary) != 1 || closeCount(administrator) != 0 {
		t.Fatalf("temporary close = %d, administrator close = %d", closeCount(temporary), closeCount(administrator))
	}
	assertSessionAvailable(t, application, authenticated)
}

func TestPasswordVerifyReturnsStructuredErrorsWithoutDestroyingSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		bindError  error
		status     int
		code       string
		resultCode *uint16
	}{
		{
			name: "LDAP result", bindError: ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied")),
			status: http.StatusForbidden, code: "ldap_error", resultCode: resultCodePointer(ldap.LDAPResultInsufficientAccessRights),
		},
		{name: "transport", bindError: errors.New("connection reset"), status: http.StatusBadGateway, code: "ldap_transport_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			administrator := &fakeClient{}
			temporary := &fakeClient{bindFunc: func(string, string) error { return test.bindError }}
			connector := &fakeConnector{clients: []Client{administrator, temporary}}
			application, _ := newTestApplication(t, connector, nil)
			authenticated := loginTestSession(t, application, "dn")

			response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
				"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
			}, authenticated.cookie, authenticated.csrf)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.status, response.Body.String())
			}
			var body apiErrorBody
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error.Code != test.code {
				t.Fatalf("error body = %#v, decode error = %v", body, err)
			}
			if test.resultCode != nil && (body.Error.LDAPResultCode == nil || *body.Error.LDAPResultCode != *test.resultCode) {
				t.Fatalf("LDAP result code = %v, want %d", body.Error.LDAPResultCode, *test.resultCode)
			}
			if closeCount(temporary) != 1 || closeCount(administrator) != 0 {
				t.Fatalf("temporary close = %d, administrator close = %d", closeCount(temporary), closeCount(administrator))
			}
			assertSessionAvailable(t, application, authenticated)
		})
	}

	t.Run("connect transport", func(t *testing.T) {
		administrator := &fakeClient{}
		temporary := &fakeClient{}
		connector := &stagedPasswordVerifyConnector{
			administrator: administrator,
			verify: func(context.Context, ConnectConfig) (Client, error) {
				return temporary, errors.New("dial failed after allocating a client")
			},
		}
		application, _ := newTestApplication(t, connector, nil)
		authenticated := loginTestSession(t, application, "dn")

		response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "ldap_unavailable") {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if closeCount(temporary) != 1 || closeCount(administrator) != 0 {
			t.Fatalf("temporary close = %d, administrator close = %d", closeCount(temporary), closeCount(administrator))
		}
		assertSessionAvailable(t, application, authenticated)
	})
}

func TestPasswordVerifyHonorsCancellationAndOperationTimeout(t *testing.T) {
	t.Parallel()
	t.Run("connection timeout", func(t *testing.T) {
		administrator := &fakeClient{}
		connector := &stagedPasswordVerifyConnector{
			administrator: administrator,
			verify: func(ctx context.Context, _ ConnectConfig) (Client, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		application, _ := newTestApplication(t, connector, func(config *Config) {
			config.DialTimeout = 20 * time.Millisecond
		})
		authenticated := loginTestSession(t, application, "dn")

		response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusGatewayTimeout ||
			!strings.Contains(response.Body.String(), "operation_deadline_exceeded") {
			t.Fatalf("connection timeout status = %d, body = %s", response.Code, response.Body.String())
		}
		if closeCount(administrator) != 0 {
			t.Fatalf("administrator close count = %d", closeCount(administrator))
		}
		assertSessionAvailable(t, application, authenticated)
	})

	t.Run("operation timeout closes temporary connection", func(t *testing.T) {
		administrator := &fakeClient{}
		temporary := newBlockingPasswordVerifyClient()
		connector := &fakeConnector{clients: []Client{administrator, temporary}}
		application, _ := newTestApplication(t, connector, func(config *Config) {
			config.OperationTimeout = 20 * time.Millisecond
		})
		authenticated := loginTestSession(t, application, "dn")

		response := performJSONRequest(t, application, http.MethodPost, "/api/password-verify", map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusGatewayTimeout ||
			!strings.Contains(response.Body.String(), "operation_deadline_exceeded") {
			t.Fatalf("timeout status = %d, body = %s", response.Code, response.Body.String())
		}
		if closeCount(&temporary.fakeClient) != 1 || closeCount(administrator) != 0 {
			t.Fatalf("temporary close = %d, administrator close = %d", closeCount(&temporary.fakeClient), closeCount(administrator))
		}
		assertSessionAvailable(t, application, authenticated)
	})

	t.Run("canceled request closes connected client without binding", func(t *testing.T) {
		administrator := &fakeClient{}
		temporary := &fakeClient{}
		connector := &fakeConnector{clients: []Client{administrator, temporary}}
		application, _ := newTestApplication(t, connector, nil)
		authenticated := loginTestSession(t, application, "dn")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		response := performPasswordVerifyRequest(t, application, map[string]string{
			"user_identity": "uid=alice,dc=example,dc=com", "password": "secret",
		}, authenticated, "https://admin.example", ctx)
		if response.Code != http.StatusRequestTimeout || !strings.Contains(response.Body.String(), "request_canceled") {
			t.Fatalf("canceled status = %d, body = %s", response.Code, response.Body.String())
		}
		if closeCount(temporary) != 1 || closeCount(administrator) != 0 {
			t.Fatalf("temporary close = %d, administrator close = %d", closeCount(temporary), closeCount(administrator))
		}
		temporary.mu.Lock()
		bindDN := temporary.bindDN
		temporary.mu.Unlock()
		if bindDN != "" {
			t.Fatalf("canceled verification reached Bind with DN %q", bindDN)
		}
		assertSessionAvailable(t, application, authenticated)
	})
}

type blockingPasswordVerifyClient struct {
	fakeClient
	closed    chan struct{}
	closeOnce sync.Once
}

type stagedPasswordVerifyConnector struct {
	mu            sync.Mutex
	administrator Client
	verify        func(context.Context, ConnectConfig) (Client, error)
	calls         int
}

func (connector *stagedPasswordVerifyConnector) Connect(ctx context.Context, config ConnectConfig) (Client, error) {
	connector.mu.Lock()
	connector.calls++
	call := connector.calls
	connector.mu.Unlock()
	if call == 1 {
		return connector.administrator, nil
	}
	return connector.verify(ctx, config)
}

func newBlockingPasswordVerifyClient() *blockingPasswordVerifyClient {
	return &blockingPasswordVerifyClient{closed: make(chan struct{})}
}

func (client *blockingPasswordVerifyClient) Bind(string, string) error {
	<-client.closed
	return errors.New("temporary LDAP connection closed")
}

func (client *blockingPasswordVerifyClient) Close() error {
	client.closeOnce.Do(func() { close(client.closed) })
	return client.fakeClient.Close()
}

func performPasswordVerifyRequest(
	t *testing.T,
	application *Application,
	body map[string]string,
	authenticated authenticatedSession,
	origin string,
	ctx context.Context,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(body); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://admin.example/api/password-verify", &encoded).WithContext(ctx)
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", authenticated.csrf)
	request.AddCookie(authenticated.cookie)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	return response
}

func assertPasswordVerified(t *testing.T, response *httptest.ResponseRecorder, want bool) {
	t.Helper()
	var body map[string]bool
	if err := json.Unmarshal(response.Body.Bytes(), &body); response.Code != http.StatusOK || err != nil || body["verified"] != want {
		t.Fatalf("password verification status = %d, body = %#v, decode error = %v", response.Code, body, err)
	}
}

func assertSessionAvailable(t *testing.T, application *Application, authenticated authenticatedSession) {
	t.Helper()
	response := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("administrator session status = %d, body = %s", response.Code, response.Body.String())
	}
}

func closeCount(client *fakeClient) int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.closeCount
}

func resultCodePointer(value uint16) *uint16 {
	return &value
}
