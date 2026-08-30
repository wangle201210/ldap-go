package webadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const passwordSetHashTestDN = "uid=alice,ou=people,dc=example,dc=com"

type capturedPasswordHashModify struct {
	userIdentity string
	oldPassword  string
	newPassword  string
	hashScheme   string
}

func TestPasswordSetHashForwardsEveryAdvertisedSchemeToPasswordModify(t *testing.T) {
	client := ldapGoPasswordHashFakeClient()
	var captured capturedPasswordHashModify
	client.passwordHashModifyFunc = func(request *ldap.PasswordModifyRequest, scheme string) error {
		captured = capturePasswordHashModify(request, scheme)
		return nil
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	for index, scheme := range passwordHashSchemes {
		secret := "hash-selection-secret-" + string(rune('a'+index))
		oldSecret := "old-hash-selection-secret-" + string(rune('a'+index))
		captured = capturedPasswordHashModify{}
		response := performJSONRequest(t, application, http.MethodPost, "/api/password-set-hash", map[string]string{
			"user_identity": passwordSetHashTestDN,
			"old_password":  oldSecret,
			"new_password":  secret,
			"hash_scheme":   scheme,
		}, authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body = %s", scheme, response.Code, response.Body.String())
		}

		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s response: %v", scheme, err)
		}
		if len(body) != 2 || body["dn"] != passwordSetHashTestDN || body["hash_scheme"] != scheme {
			t.Fatalf("%s response = %#v", scheme, body)
		}
		if captured.userIdentity != passwordSetHashTestDN || captured.oldPassword != oldSecret ||
			captured.newPassword != secret || captured.hashScheme != scheme {
			t.Fatalf("%s Password Modify = %#v", scheme, captured)
		}
		if bytes := response.Body.Bytes(); strings.Contains(string(bytes), secret) ||
			strings.Contains(string(bytes), oldSecret) {
			t.Fatalf("%s response exposed password material: %s", scheme, response.Body.String())
		}

		client.mu.Lock()
		request := client.passwordHashRequests[len(client.passwordHashRequests)-1]
		client.mu.Unlock()
		if request.OldPassword != "" || request.NewPassword != "" {
			t.Fatalf("%s retained Password Modify secrets after completion", scheme)
		}
	}
}

func TestPasswordSetHashValidatesAuthenticationAndInput(t *testing.T) {
	client := ldapGoPasswordHashFakeClient()
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	valid := map[string]string{
		"user_identity": passwordSetHashTestDN,
		"new_password":  "validation-secret",
		"hash_scheme":   "{SSHA}",
	}

	tests := []struct {
		name   string
		method string
		body   map[string]string
		cookie *http.Cookie
		csrf   string
		origin string
		status int
		code   string
	}{
		{name: "method", method: http.MethodGet, cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
		{name: "authentication", method: http.MethodPost, body: valid, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusUnauthorized, code: "authentication_required"},
		{name: "origin", method: http.MethodPost, body: valid, cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://evil.example", status: http.StatusForbidden, code: "invalid_origin"},
		{name: "csrf missing", method: http.MethodPost, body: valid, cookie: authenticated.cookie, origin: "https://admin.example", status: http.StatusForbidden, code: "invalid_csrf_token"},
		{name: "csrf invalid", method: http.MethodPost, body: valid, cookie: authenticated.cookie, csrf: "wrong", origin: "https://admin.example", status: http.StatusForbidden, code: "invalid_csrf_token"},
		{name: "DN empty", method: http.MethodPost, body: passwordSetHashInput("", "validation-secret", "{SSHA}"), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusBadRequest, code: "invalid_dn"},
		{name: "DN malformed", method: http.MethodPost, body: passwordSetHashInput("not-a-dn", "validation-secret", "{SSHA}"), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusBadRequest, code: "invalid_dn"},
		{name: "password empty", method: http.MethodPost, body: passwordSetHashInput(passwordSetHashTestDN, "", "{SSHA}"), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "password too large", method: http.MethodPost, body: passwordSetHashInput(passwordSetHashTestDN, strings.Repeat("x", ldapwire.PasswordHashSelectionMaxPasswordBytes+1), "{SSHA}"), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "scheme empty", method: http.MethodPost, body: passwordSetHashInput(passwordSetHashTestDN, "validation-secret", ""), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "scheme unsupported", method: http.MethodPost, body: passwordSetHashInput(passwordSetHashTestDN, "validation-secret", "{CLEARTEXT}"), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", status: http.StatusBadRequest, code: "unsupported_hash_scheme"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performPasswordSetHashRequest(t, application, test.method, test.body, test.cookie, test.csrf, test.origin)
			assertPasswordSetHashError(t, response, test.status, test.code)
			if strings.Contains(response.Body.String(), "validation-secret") {
				t.Fatalf("response exposed plaintext: %s", response.Body.String())
			}
		})
	}

	client.mu.Lock()
	modifyCount := client.passwordHashCalls
	client.mu.Unlock()
	if modifyCount != 0 {
		t.Fatalf("invalid requests performed %d LDAP modifies", modifyCount)
	}
}

func TestPasswordSetHashPreservesLDAPPolicyFailure(t *testing.T) {
	client := ldapGoPasswordHashFakeClient()
	client.passwordHashModifyFunc = func(*ldap.PasswordModifyRequest, string) error {
		return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("ACL denied userPassword replace"))
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performJSONRequest(t, application, http.MethodPost, "/api/password-set-hash",
		passwordSetHashInput(passwordSetHashTestDN, "policy-secret", "{SSHA256}"),
		authenticated.cookie, authenticated.csrf)
	assertPasswordSetHashError(t, response, http.StatusForbidden, "ldap_error")
	if strings.Contains(response.Body.String(), "policy-secret") {
		t.Fatalf("response exposed plaintext: %s", response.Body.String())
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusOK {
		t.Fatalf("deterministic LDAP failure retired session: status = %d, body = %s", probe.Code, probe.Body.String())
	}
}

func TestPasswordSetHashRetiresUnknownWriteWithoutExposingSecrets(t *testing.T) {
	var captured capturedPasswordHashModify
	client := ldapGoPasswordHashFakeClient()
	client.passwordHashModifyFunc = func(request *ldap.PasswordModifyRequest, scheme string) error {
		captured = capturePasswordHashModify(request, scheme)
		return ldap.NewError(ldap.ErrorNetwork, errors.New("LDAP response was lost"))
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	secret := "unknown-result-secret"

	response := performJSONRequest(t, application, http.MethodPost, "/api/password-set-hash",
		passwordSetHashInput(passwordSetHashTestDN, secret, "{PBKDF2-SM3}"),
		authenticated.cookie, authenticated.csrf)
	assertPasswordSetHashError(t, response, http.StatusBadGateway, "ldap_result_unknown")
	if captured.newPassword != secret || captured.hashScheme != "{PBKDF2-SM3}" {
		t.Fatalf("Password Modify = %#v", captured)
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatalf("unknown-result response exposed password material: %s", response.Body.String())
	}

	client.mu.Lock()
	request := client.passwordHashRequests[len(client.passwordHashRequests)-1]
	client.mu.Unlock()
	if request.OldPassword != "" || request.NewPassword != "" {
		t.Fatal("unknown-result request retained password values")
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("unknown write session status = %d, body = %s", probe.Code, probe.Body.String())
	}
	waitForFakeClientClose(t, client)
}

func TestPasswordSetHashCanceledWriteCleansRequestAfterLDAPCallExits(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var ldapRequest *ldap.PasswordModifyRequest
	var captured capturedPasswordHashModify
	client := ldapGoPasswordHashFakeClient()
	client.passwordHashModifyFunc = func(request *ldap.PasswordModifyRequest, scheme string) error {
		ldapRequest = request
		captured = capturePasswordHashModify(request, scheme)
		close(entered)
		<-release
		return nil
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	secret := "canceled-write-secret"
	payload, err := json.Marshal(passwordSetHashInput(passwordSetHashTestDN, secret, "{SSM3}"))
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequestWithContext(ctx, http.MethodPost,
		"https://admin.example/api/password-set-hash", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://admin.example")
	request.Header.Set("X-CSRF-Token", authenticated.csrf)
	request.AddCookie(authenticated.cookie)
	responseChannel := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		application.Handler().ServeHTTP(response, request)
		responseChannel <- response
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("LDAP modify did not start")
	}
	cancel()
	var response *httptest.ResponseRecorder
	select {
	case response = <-responseChannel:
	case <-time.After(time.Second):
		t.Fatal("canceled password hash write did not return")
	}
	assertPasswordSetHashError(t, response, http.StatusRequestTimeout, "ldap_result_unknown")
	if captured.newPassword != secret || captured.hashScheme != "{SSM3}" {
		t.Fatalf("Password Modify = %#v", captured)
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatalf("canceled response exposed password material: %s", response.Body.String())
	}
	if ldapRequest == nil || ldapRequest.NewPassword != secret {
		t.Fatal("in-flight LDAP request was cleared before the LDAP call exited")
	}

	close(release)
	application.batchOperations.Wait()
	if ldapRequest.OldPassword != "" || ldapRequest.NewPassword != "" {
		t.Fatal("completed LDAP request retained password values")
	}
	waitForFakeClientClose(t, client)
}

func TestPasswordSetHashUsesLDAPOperationAdmission(t *testing.T) {
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxConcurrentOperations = 1
	})
	authenticated := loginTestSession(t, application, "dn")
	application.operations <- struct{}{}
	response := performJSONRequest(t, application, http.MethodPost, "/api/password-set-hash",
		passwordSetHashInput(passwordSetHashTestDN, "admission-secret", "{SSHA}"),
		authenticated.cookie, authenticated.csrf)
	<-application.operations
	assertPasswordSetHashError(t, response, http.StatusServiceUnavailable, "operation_capacity_reached")

	client.mu.Lock()
	modifyCount := client.passwordHashCalls
	client.mu.Unlock()
	if modifyCount != 0 {
		t.Fatalf("capacity-rejected request performed %d LDAP modifies", modifyCount)
	}
}

func TestPasswordSetHashRejectsAnUnverifiedTargetBeforeModify(t *testing.T) {
	client := passwordHashControlFakeClient(false)
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performJSONRequest(t, application, http.MethodPost, "/api/password-set-hash",
		passwordSetHashInput(passwordSetHashTestDN, "must-not-be-written", "{SSHA}"),
		authenticated.cookie, authenticated.csrf)
	assertPasswordSetHashError(t, response, http.StatusUnprocessableEntity, "password_hash_target_unsupported")

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.searches) != 1 || client.passwordHashCalls != 0 {
		t.Fatalf("target preflight searches=%d password modifies=%d, want 1 and 0", len(client.searches), client.passwordHashCalls)
	}
}

func capturePasswordHashModify(
	request *ldap.PasswordModifyRequest,
	scheme string,
) capturedPasswordHashModify {
	return capturedPasswordHashModify{
		userIdentity: request.UserIdentity,
		oldPassword:  request.OldPassword,
		newPassword:  request.NewPassword,
		hashScheme:   scheme,
	}
}

func passwordSetHashInput(dn, password, scheme string) map[string]string {
	return map[string]string{
		"user_identity": dn,
		"new_password":  password,
		"hash_scheme":   scheme,
	}
}

func ldapGoPasswordHashFakeClient() *fakeClient {
	return passwordHashControlFakeClient(true)
}

func passwordHashControlFakeClient(supported bool) *fakeClient {
	return &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.BaseDN != "" || request.Scope != ldap.ScopeBaseObject ||
			!reflect.DeepEqual(request.Attributes, []string{"supportedControl"}) {
			return nil, errors.New("unexpected password hash capability search")
		}
		values := []string{}
		if supported {
			values = append(values, ldapwire.PasswordHashSchemeControlOID)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("", map[string][]string{"supportedControl": values}),
		}}, nil
	}}
}

func performPasswordSetHashRequest(
	t *testing.T,
	application *Application,
	method string,
	body map[string]string,
	cookie *http.Cookie,
	csrf,
	origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://admin.example/api/password-set-hash", nil)
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		request = httptest.NewRequest(method, "https://admin.example/api/password-set-hash", strings.NewReader(string(encoded)))
		request.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	return response
}

func assertPasswordSetHashError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	var body apiErrorBody
	if response.Code != status || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Error.Code != code {
		t.Fatalf("status = %d, error = %#v, body = %s; want status %d code %q",
			response.Code, body.Error, response.Body.String(), status, code)
	}
}
