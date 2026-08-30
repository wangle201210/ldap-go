package webadmin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *sequenceReader) Read(destination []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.next++
	for index := range destination {
		destination[index] = reader.next + byte(index)
	}
	return len(destination), nil
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type fakeConnector struct {
	mu      sync.Mutex
	clients []Client
	factory func() Client
	err     error
	configs []ConnectConfig
}

func (connector *fakeConnector) Connect(_ context.Context, config ConnectConfig) (Client, error) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	connector.configs = append(connector.configs, config)
	if connector.err != nil {
		return nil, connector.err
	}
	if connector.factory != nil {
		client := connector.factory()
		connector.clients = append(connector.clients, client)
		return client, nil
	}
	if len(connector.clients) == 0 {
		return nil, errors.New("no fake LDAP client")
	}
	client := connector.clients[0]
	connector.clients = connector.clients[1:]
	return client, nil
}

func (connector *fakeConnector) connectCount() int {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	return len(connector.configs)
}

type fakeClient struct {
	mu sync.Mutex

	bindFunc               func(string, string) error
	searchFunc             func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	compareFunc            func(string, string, string) (bool, error)
	addFunc                func(*ldap.AddRequest) error
	modifyFunc             func(*ldap.ModifyRequest) error
	delFunc                func(*ldap.DelRequest) error
	modifyDNFunc           func(*ldap.ModifyDNRequest) error
	passwordModifyFunc     func(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	passwordHashModifyFunc func(*ldap.PasswordModifyRequest, string) error

	bindDN               string
	searches             []*ldap.SearchRequest
	adds                 []*ldap.AddRequest
	modifies             []*ldap.ModifyRequest
	deletes              []*ldap.DelRequest
	renames              []*ldap.ModifyDNRequest
	passwordCalls        int
	passwordHashCalls    int
	passwordHashRequests []*ldap.PasswordModifyRequest
	passwordHashSchemes  []string
	closeCount           int
}

func (client *fakeClient) Bind(username, password string) error {
	client.mu.Lock()
	client.bindDN = username
	callback := client.bindFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(username, password)
	}
	return nil
}

func (client *fakeClient) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	client.mu.Lock()
	client.searches = append(client.searches, request)
	callback := client.searchFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request)
	}
	return &ldap.SearchResult{}, nil
}

func (client *fakeClient) Compare(dn, attribute, value string) (bool, error) {
	client.mu.Lock()
	callback := client.compareFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(dn, attribute, value)
	}
	return false, nil
}

func (client *fakeClient) Add(request *ldap.AddRequest) error {
	client.mu.Lock()
	client.adds = append(client.adds, request)
	callback := client.addFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request)
	}
	return nil
}

func (client *fakeClient) Modify(request *ldap.ModifyRequest) error {
	client.mu.Lock()
	client.modifies = append(client.modifies, request)
	callback := client.modifyFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request)
	}
	return nil
}

func (client *fakeClient) Del(request *ldap.DelRequest) error {
	client.mu.Lock()
	client.deletes = append(client.deletes, request)
	callback := client.delFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request)
	}
	return nil
}

func (client *fakeClient) ModifyDN(request *ldap.ModifyDNRequest) error {
	client.mu.Lock()
	client.renames = append(client.renames, request)
	callback := client.modifyDNFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request)
	}
	return nil
}

func (client *fakeClient) PasswordModify(request *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	client.mu.Lock()
	client.passwordCalls++
	callback := client.passwordModifyFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request)
	}
	return &ldap.PasswordModifyResult{}, nil
}

func (client *fakeClient) PasswordModifyWithHashScheme(
	request *ldap.PasswordModifyRequest,
	scheme string,
) error {
	client.mu.Lock()
	client.passwordHashCalls++
	client.passwordHashRequests = append(client.passwordHashRequests, request)
	client.passwordHashSchemes = append(client.passwordHashSchemes, scheme)
	callback := client.passwordHashModifyFunc
	client.mu.Unlock()
	if callback != nil {
		return callback(request, scheme)
	}
	return nil
}

func (client *fakeClient) Close() error {
	client.mu.Lock()
	client.closeCount++
	client.mu.Unlock()
	return nil
}

func newTestApplication(t *testing.T, connector Connector, configure func(*Config)) (*Application, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
	config := Config{
		LDAPURL:   "ldap://127.0.0.1:389",
		Connector: connector,
		Clock:     clock.Now,
		Random:    &sequenceReader{},
		Logger:    discardLogger{},
	}
	if configure != nil {
		configure(&config)
	}
	application, err := New(config)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })
	return application, clock
}

type authenticatedSession struct {
	cookie *http.Cookie
	csrf   string
}

func loginTestSession(t *testing.T, application *Application, field string) authenticatedSession {
	t.Helper()
	body := map[string]string{field: "cn=admin,dc=example,dc=com", "password": "not-retained"}
	recorder := performJSONRequest(t, application, http.MethodPost, "/api/login", body, nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	result := sessionResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d", len(cookies))
	}
	return authenticatedSession{cookie: cookies[0], csrf: result.CSRFToken}
}

func performJSONRequest(
	t *testing.T,
	application *Application,
	method string,
	path string,
	body any,
	cookie *http.Cookie,
	csrf string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	request := httptest.NewRequest(method, "https://admin.example"+path, &encoded)
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Origin", "https://admin.example")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	recorder := httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	return recorder
}
