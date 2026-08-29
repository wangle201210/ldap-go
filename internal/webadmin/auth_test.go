package webadmin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestCloseContextForcesLDAPCloseBeforeWaitingForSessionLock(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	_ = loginTestSession(t, application, "dn")
	application.mu.Lock()
	var current *session
	for _, candidate := range application.sessions {
		current = candidate
		break
	}
	application.mu.Unlock()
	if current == nil {
		t.Fatal("login did not create a session")
	}
	current.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := application.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		current.mu.Unlock()
		t.Fatalf("CloseContext() = %v, want deadline", err)
	}
	client.mu.Lock()
	closeCount := client.closeCount
	client.mu.Unlock()
	if closeCount != 1 {
		current.mu.Unlock()
		t.Fatalf("LDAP close count before session unlock = %d, want 1", closeCount)
	}
	current.mu.Unlock()
	if err := application.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext(after unlock): %v", err)
	}
}

func TestNewValidatesTransportAndLimits(t *testing.T) {
	t.Parallel()
	tests := []Config{
		{},
		{LDAPURL: "https://ldap.example"},
		{LDAPURL: "ldaps://ldap.example", StartTLS: true},
		{LDAPURL: "ldap://user:password@ldap.example"},
		{LDAPURL: "ldap://ldap.example", MaxSessions: -1},
		{LDAPURL: "ldap://ldap.example", SessionIdleTimeout: time.Hour, SessionMaxLifetime: time.Minute},
		{LDAPURL: "ldap://ldap.example", ExternalURL: "https://admin.example/path"},
	}
	for _, config := range tests {
		if application, err := New(config); err == nil {
			_ = application.Close()
			t.Fatalf("New(%#v) unexpectedly succeeded", config)
		}
	}
}

func TestCanonicalExternalOriginRejectsRebindingAndSecuresProxyCookie(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, err := New(Config{
		LDAPURL: "ldap://127.0.0.1:389", ExternalURL: "https://admin.example",
		Connector: &fakeConnector{clients: []Client{client}}, Random: &sequenceReader{},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()

	rebound := httptest.NewRequest(http.MethodPost, "http://evil.example/api/login", bytes.NewBufferString(
		`{"bind_dn":"cn=admin","password":"secret"}`,
	))
	rebound.Header.Set("Content-Type", "application/json")
	rebound.Header.Set("Origin", "http://evil.example")
	reboundResponse := httptest.NewRecorder()
	application.Handler().ServeHTTP(reboundResponse, rebound)
	if reboundResponse.Code != http.StatusMisdirectedRequest {
		t.Fatalf("rebound status = %d, body=%s", reboundResponse.Code, reboundResponse.Body.String())
	}

	proxied := httptest.NewRequest(http.MethodPost, "http://admin.example/api/login", bytes.NewBufferString(
		`{"bind_dn":"cn=admin","password":"secret"}`,
	))
	proxied.Header.Set("Content-Type", "application/json")
	proxied.Header.Set("Origin", "https://admin.example")
	proxiedResponse := httptest.NewRecorder()
	application.Handler().ServeHTTP(proxiedResponse, proxied)
	if proxiedResponse.Code != http.StatusOK {
		t.Fatalf("proxied login status = %d, body=%s", proxiedResponse.Code, proxiedResponse.Body.String())
	}
	cookies := proxiedResponse.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("proxied session cookies = %#v, want Secure", cookies)
	}
}

func TestLoginCreatesSecureBoundSessionAndLogoutClosesIt(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.bindFunc = func(username, password string) error {
		if username != "cn=admin,dc=example,dc=com" || password != "not-retained" {
			t.Fatalf("Bind(%q, %q)", username, password)
		}
		return nil
	}
	connector := &fakeConnector{clients: []Client{client}}
	application, _ := newTestApplication(t, connector, func(config *Config) {
		config.StartTLS = true
		config.TLSConfig = &tls.Config{ServerName: "ldap.example"}
	})

	authenticated := loginTestSession(t, application, "dn")
	if !authenticated.cookie.HttpOnly || !authenticated.cookie.Secure ||
		authenticated.cookie.SameSite != http.SameSiteStrictMode || authenticated.cookie.Path != "/" {
		t.Fatalf("session cookie = %#v", authenticated.cookie)
	}
	if strings.Contains(authenticated.cookie.Value, "admin") || authenticated.cookie.Value == authenticated.csrf {
		t.Fatal("session and CSRF tokens are not independent opaque values")
	}
	if got := connector.configs[0]; !got.StartTLS || got.TLSConfig == nil || got.TLSConfig.ServerName != "ldap.example" {
		t.Fatalf("Connect config = %#v", got)
	}

	recorder := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("session status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Security-Policy") == "" || recorder.Header().Get("Strict-Transport-Security") == "" ||
		recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers = %#v", recorder.Header())
	}

	denied := performJSONRequest(t, application, http.MethodPost, "/api/logout", map[string]any{}, authenticated.cookie, "wrong")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("logout with bad CSRF status = %d", denied.Code)
	}
	if client.closeCount != 0 {
		t.Fatal("bad CSRF token closed the LDAP session")
	}
	logout := performJSONRequest(t, application, http.MethodPost, "/api/logout", map[string]any{}, authenticated.cookie, authenticated.csrf)
	if logout.Code != http.StatusOK || client.closeCount != 1 {
		t.Fatalf("logout status = %d, close count = %d", logout.Code, client.closeCount)
	}
	if cookies := logout.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Fatalf("logout cookie = %#v", cookies)
	}
}

func TestLoginRequiresSameOriginAndRateLimitsFailures(t *testing.T) {
	t.Parallel()
	connector := &fakeConnector{factory: func() Client {
		return &fakeClient{
			bindFunc: func(string, string) error {
				return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("invalid")}
			},
			addFunc: func(*ldap.AddRequest) error { return nil },
		}
	}}
	application, _ := newTestApplication(t, connector, func(config *Config) {
		config.LoginRateLimit = 2
	})

	request := httptest.NewRequest(http.MethodPost, "https://admin.example/api/login", bytes.NewBufferString(`{"dn":"cn=admin","password":"bad"}`))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || connector.connectCount() != 0 {
		t.Fatalf("missing origin status = %d, connects = %d", recorder.Code, connector.connectCount())
	}

	for attempt := 0; attempt < 2; attempt++ {
		failed := performJSONRequest(t, application, http.MethodPost, "/api/login", map[string]string{
			"dn": "cn=admin", "password": "bad",
		}, nil, "")
		if failed.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, body = %s", attempt, failed.Code, failed.Body.String())
		}
	}
	limited := performJSONRequest(t, application, http.MethodPost, "/api/login", map[string]string{
		"dn": "cn=admin", "password": "bad",
	}, nil, "")
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("limited status = %d, headers = %#v", limited.Code, limited.Header())
	}
	if connector.connectCount() != 2 {
		t.Fatalf("LDAP connect count = %d, want 2", connector.connectCount())
	}
}

func TestSessionExpiryAndApplicationCloseCloseConnections(t *testing.T) {
	t.Parallel()
	first := &fakeClient{}
	connector := &fakeConnector{clients: []Client{first}}
	application, clock := newTestApplication(t, connector, func(config *Config) {
		config.SessionIdleTimeout = time.Minute
		config.SessionMaxLifetime = 10 * time.Minute
	})
	authenticated := loginTestSession(t, application, "bind_dn")
	clock.Advance(time.Minute)
	expired := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if expired.Code != http.StatusUnauthorized || first.closeCount != 1 {
		t.Fatalf("expired status = %d, close count = %d", expired.Code, first.closeCount)
	}

	second := &fakeClient{}
	connector.mu.Lock()
	connector.clients = append(connector.clients, second)
	connector.mu.Unlock()
	secondSession := loginTestSession(t, application, "dn")
	if secondSession.cookie == nil {
		t.Fatal("second login returned no cookie")
	}
	if err := application.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if second.closeCount != 1 {
		t.Fatalf("Close close count = %d", second.closeCount)
	}
	if err := application.Close(); err != nil || second.closeCount != 1 {
		t.Fatalf("second Close() = %v, close count = %d", err, second.closeCount)
	}
}

func TestSessionSweeperClosesExpiredIdleConnectionWithoutAnotherRequest(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, clock := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.SessionIdleTimeout = 20 * time.Millisecond
		config.SessionMaxLifetime = time.Second
		config.SessionSweepInterval = 5 * time.Millisecond
	})
	_ = loginTestSession(t, application, "dn")
	clock.Advance(20 * time.Millisecond)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		closed := client.closeCount
		client.mu.Unlock()
		if closed == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("expired LDAP connection was not closed by the session sweeper")
}

func TestSessionCapacityRejectsBeforeLDAPConnect(t *testing.T) {
	t.Parallel()
	first := &fakeClient{}
	connector := &fakeConnector{clients: []Client{first}}
	application, _ := newTestApplication(t, connector, func(config *Config) { config.MaxSessions = 1 })
	_ = loginTestSession(t, application, "dn")

	recorder := performJSONRequest(t, application, http.MethodPost, "/api/login", map[string]string{
		"dn": "cn=other", "password": "secret",
	}, nil, "")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if connector.connectCount() != 1 {
		t.Fatalf("connect count = %d, want 1", connector.connectCount())
	}
}

func TestRequestBodyLimitAndStructuredLDAPError(t *testing.T) {
	t.Parallel()
	client := &fakeClient{addFunc: func(*ldap.AddRequest) error {
		return &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied")}
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.RequestBodyLimit = 128
	})
	authenticated := loginTestSession(t, application, "dn")

	tooLarge := performJSONRequest(t, application, http.MethodPost, "/api/entry", map[string]any{
		"dn": "uid=alice,dc=example,dc=com", "attributes": map[string][]string{"description": {strings.Repeat("x", 256)}},
	}, authenticated.cookie, authenticated.csrf)
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status = %d, body = %s", tooLarge.Code, tooLarge.Body.String())
	}

	application.config.RequestBodyLimit = defaultRequestBodyLimit
	denied := performJSONRequest(t, application, http.MethodPost, "/api/entry", map[string]any{
		"dn": "uid=alice,dc=example,dc=com", "attributes": map[string][]string{"objectClass": {"person"}},
	}, authenticated.cookie, authenticated.csrf)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("LDAP denial status = %d, body = %s", denied.Code, denied.Body.String())
	}
	var body apiErrorBody
	if err := json.Unmarshal(denied.Body.Bytes(), &body); err != nil || body.Error.LDAPResultCode == nil ||
		*body.Error.LDAPResultCode != ldap.LDAPResultInsufficientAccessRights {
		t.Fatalf("LDAP error body = %#v, decode error = %v", body, err)
	}
}
