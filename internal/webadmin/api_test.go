package webadmin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestReadAPIsAndFrontendAliases(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.searchFunc = func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch request.BaseDN {
		case "":
			if len(request.Attributes) == 1 && request.Attributes[0] == "subschemaSubentry" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
					"subschemaSubentry": {"cn=Subschema"},
				})}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
				"namingContexts": {"dc=example,dc=com"},
			})}}, nil
		case "cn=Subschema":
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=Subschema", map[string][]string{
				"attributeTypes": {"( 2.5.4.3 NAME 'cn' )"},
				"objectClasses":  {"( 2.5.6.6 NAME 'person' )"},
			})}}, nil
		case "cn=Monitor":
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=Monitor", map[string][]string{
				"cn": {"Monitor"}, "monitorCounter": {"7"},
			})}}, nil
		default:
			paging := ldap.NewControlPaging(25)
			paging.SetCookie([]byte("next-page"))
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
					"cn": {"Alice"}, "uid": {"alice"},
				})},
				Controls: []ldap.Control{paging},
			}, nil
		}
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	searchPath := "/api/search?base=" + url.QueryEscape("dc=example,dc=com") +
		"&scope=sub&filter=" + url.QueryEscape("(uid=alice)") +
		"&attributes=cn,uid&size_limit=25&page_size=25"
	search := performJSONRequest(t, application, http.MethodGet, searchPath, nil, authenticated.cookie, "")
	if search.Code != http.StatusOK {
		t.Fatalf("GET search status = %d, body = %s", search.Code, search.Body.String())
	}
	var searchBody searchResponse
	if err := json.Unmarshal(search.Body.Bytes(), &searchBody); err != nil {
		t.Fatalf("decode search: %v", err)
	}
	if len(searchBody.Entries) != 1 || searchBody.PageCookie != base64.RawURLEncoding.EncodeToString([]byte("next-page")) {
		t.Fatalf("search response = %#v", searchBody)
	}
	client.mu.Lock()
	searchRequest := client.searches[0]
	client.mu.Unlock()
	if searchRequest.Scope != ldap.ScopeWholeSubtree || searchRequest.SizeLimit != 25 || !searchRequest.EnforceSizeLimit ||
		len(searchRequest.Controls) != 1 {
		t.Fatalf("LDAP search request = %#v", searchRequest)
	}

	entry := performJSONRequest(t, application, http.MethodGet,
		"/api/entry?dn="+url.QueryEscape("uid=alice,dc=example,dc=com"), nil, authenticated.cookie, "")
	if entry.Code != http.StatusOK {
		t.Fatalf("entry status = %d, body = %s", entry.Code, entry.Body.String())
	}
	root := performJSONRequest(t, application, http.MethodGet, "/api/root", nil, authenticated.cookie, "")
	if root.Code != http.StatusOK || !containsJSONText(root.Body.Bytes(), "dc=example,dc=com") {
		t.Fatalf("root status = %d, body = %s", root.Code, root.Body.String())
	}
	schema := performJSONRequest(t, application, http.MethodGet, "/api/schema", nil, authenticated.cookie, "")
	if schema.Code != http.StatusOK || !containsJSONText(schema.Body.Bytes(), "attributeTypes") {
		t.Fatalf("schema status = %d, body = %s", schema.Code, schema.Body.String())
	}
	monitor := performJSONRequest(t, application, http.MethodGet, "/api/monitor", nil, authenticated.cookie, "")
	if monitor.Code != http.StatusOK || !containsJSONText(monitor.Body.Bytes(), "monitorCounter") {
		t.Fatalf("monitor status = %d, body = %s", monitor.Code, monitor.Body.String())
	}
}

func TestWriteAPIsUseBoundSessionAndEnforceMutationSecurity(t *testing.T) {
	t.Parallel()
	var passwordIdentity string
	var passwordNew string
	client := &fakeClient{passwordModifyFunc: func(request *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
		passwordIdentity = request.UserIdentity
		passwordNew = request.NewPassword
		return &ldap.PasswordModifyResult{GeneratedPassword: "generated"}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	badOriginRequest := httptest.NewRequest(http.MethodPost, "https://admin.example/api/entry", strings.NewReader(
		`{"dn":"uid=alice,dc=example,dc=com","attributes":{"objectClass":["person"]}}`,
	))
	badOriginRequest.Header.Set("Content-Type", "application/json")
	badOriginRequest.Header.Set("Origin", "https://evil.example")
	badOriginRequest.Header.Set("X-CSRF-Token", authenticated.csrf)
	badOriginRequest.AddCookie(authenticated.cookie)
	badOrigin := httptest.NewRecorder()
	application.Handler().ServeHTTP(badOrigin, badOriginRequest)
	if badOrigin.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d", badOrigin.Code)
	}

	add := performJSONRequest(t, application, http.MethodPost, "/api/entry", map[string]any{
		"dn":         "uid=alice,dc=example,dc=com",
		"attributes": map[string][]string{"objectClass": {"person"}, "sn": {"Alice"}, "cn": {"Alice"}},
	}, authenticated.cookie, authenticated.csrf)
	if add.Code != http.StatusCreated {
		t.Fatalf("add status = %d, body = %s", add.Code, add.Body.String())
	}
	modify := performJSONRequest(t, application, http.MethodPatch, "/api/entry", map[string]any{
		"dn":      "uid=alice,dc=example,dc=com",
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"updated"}}},
	}, authenticated.cookie, authenticated.csrf)
	if modify.Code != http.StatusOK {
		t.Fatalf("modify status = %d, body = %s", modify.Code, modify.Body.String())
	}
	rename := performJSONRequest(t, application, http.MethodPost, "/api/rename", map[string]any{
		"dn": "uid=alice,dc=example,dc=com", "new_rdn": "uid=alice2", "delete_old_rdn": true,
	}, authenticated.cookie, authenticated.csrf)
	if rename.Code != http.StatusOK {
		t.Fatalf("rename status = %d, body = %s", rename.Code, rename.Body.String())
	}
	password := performJSONRequest(t, application, http.MethodPost, "/api/password", map[string]string{
		"user_identity": "uid=alice,dc=example,dc=com", "new_password": "new-secret",
	}, authenticated.cookie, authenticated.csrf)
	if password.Code != http.StatusOK || !containsJSONText(password.Body.Bytes(), `"generated_password":"generated"`) ||
		!containsJSONText(password.Body.Bytes(), base64.StdEncoding.EncodeToString([]byte("generated"))) {
		t.Fatalf("password status = %d, body = %s", password.Code, password.Body.String())
	}
	deleteResponse := performJSONRequest(t, application, http.MethodDelete,
		"/api/entry?dn="+url.QueryEscape("uid=alice2,dc=example,dc=com"), nil, authenticated.cookie, authenticated.csrf)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", deleteResponse.Code, deleteResponse.Body.String())
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.adds) != 1 || len(client.modifies) != 1 || len(client.renames) != 1 ||
		len(client.deletes) != 1 || client.passwordCalls != 1 || client.bindDN != "cn=admin,dc=example,dc=com" {
		t.Fatalf("bound client calls: add=%d modify=%d rename=%d delete=%d password=%d bind=%q",
			len(client.adds), len(client.modifies), len(client.renames), len(client.deletes), client.passwordCalls, client.bindDN)
	}
	if passwordIdentity != "uid=alice,dc=example,dc=com" || passwordNew != "new-secret" {
		t.Fatalf("password request identity = %q, new password = %q", passwordIdentity, passwordNew)
	}
}

func TestWriteAPIsRetireSessionWhenLDAPResultIsUnknown(t *testing.T) {
	t.Parallel()
	for _, test := range writeAPITestCases() {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{}
			test.failWith(client, ldap.NewError(ldap.ErrorNetwork, errors.New("LDAP response was lost")))
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")

			response := performJSONRequest(t, application, test.method, test.path, test.body,
				authenticated.cookie, authenticated.csrf)
			var body apiErrorBody
			if response.Code != http.StatusBadGateway || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
				body.Error.Code != "ldap_result_unknown" || body.Error.LDAPResultCode != nil {
				t.Fatalf("status = %d, error = %#v, body = %s", response.Code, body.Error, response.Body.String())
			}
			probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
			if probe.Code != http.StatusUnauthorized {
				t.Fatalf("retired session status = %d, body = %s", probe.Code, probe.Body.String())
			}
			waitForFakeClientClose(t, client)
		})
	}
}

func TestWriteAPIsPreserveSessionAfterDeterministicLDAPFailure(t *testing.T) {
	t.Parallel()
	for _, test := range writeAPITestCases() {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{}
			test.failWith(client, ldap.NewError(ldap.LDAPResultConstraintViolation, errors.New("policy rejected write")))
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")

			response := performJSONRequest(t, application, test.method, test.path, test.body,
				authenticated.cookie, authenticated.csrf)
			var body apiErrorBody
			if response.Code != http.StatusUnprocessableEntity || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
				body.Error.Code != "ldap_error" || body.Error.LDAPResultCode == nil ||
				*body.Error.LDAPResultCode != ldap.LDAPResultConstraintViolation {
				t.Fatalf("status = %d, error = %#v, body = %s", response.Code, body.Error, response.Body.String())
			}
			probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
			if probe.Code != http.StatusOK {
				t.Fatalf("preserved session status = %d, body = %s", probe.Code, probe.Body.String())
			}
			client.mu.Lock()
			closeCount := client.closeCount
			client.mu.Unlock()
			if closeCount != 0 {
				t.Fatalf("close count = %d", closeCount)
			}
		})
	}
}

func TestPasswordModifySupportsServerGeneratedPassword(t *testing.T) {
	t.Parallel()
	var identity string
	var oldPassword string
	var newPassword string
	client := &fakeClient{passwordModifyFunc: func(request *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
		identity = request.UserIdentity
		oldPassword = request.OldPassword
		newPassword = request.NewPassword
		return &ldap.PasswordModifyResult{GeneratedPassword: "server-secret"}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performJSONRequest(t, application, http.MethodPost, "/api/password-modify", map[string]string{
		"user_identity": "uid=alice,dc=example,dc=com",
	}, authenticated.cookie, authenticated.csrf)
	var body map[string]string
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		body["generated_password"] != "server-secret" ||
		body["generated_password_base64"] != base64.StdEncoding.EncodeToString([]byte("server-secret")) {
		t.Fatalf("status = %d, response = %#v, body = %s", response.Code, body, response.Body.String())
	}
	if identity != "uid=alice,dc=example,dc=com" || oldPassword != "" || newPassword != "" {
		t.Fatalf("password request identity = %q, old = %q, new = %q", identity, oldPassword, newPassword)
	}
}

func TestPasswordModifyInvalidOldPasswordDoesNotExpireWebSession(t *testing.T) {
	t.Parallel()
	client := &fakeClient{passwordModifyFunc: func(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
		return nil, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("old password is invalid"))
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performJSONRequest(t, application, http.MethodPost, "/api/password-modify", map[string]string{
		"user_identity": "uid=alice,dc=example,dc=com", "old_password": "wrong", "new_password": "new-secret",
	}, authenticated.cookie, authenticated.csrf)
	var body apiErrorBody
	if response.Code != http.StatusUnprocessableEntity || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		body.Error.Code != "invalid_old_password" || body.Error.LDAPResultCode == nil ||
		*body.Error.LDAPResultCode != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("status = %d, error = %#v, body = %s", response.Code, body.Error, response.Body.String())
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusOK {
		t.Fatalf("session status = %d, body = %s", probe.Code, probe.Body.String())
	}
}

func TestAddRejectsAttributeWithoutValues(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performJSONRequest(t, application, http.MethodPost, "/api/entry", map[string]any{
		"dn":         "uid=alice,dc=example,dc=com",
		"attributes": map[string][]string{"objectClass": {"person"}, "mail": {}},
	}, authenticated.cookie, authenticated.csrf)
	if response.Code != http.StatusBadRequest || !containsJSONText(response.Body.Bytes(), "requires at least one value") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 0 {
		t.Fatalf("LDAP add count = %d", addCount)
	}
}

func TestCanceledInFlightWriteReturnsUnknownAndRetiresSession(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		close(entered)
		<-release
		return nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	payload, err := json.Marshal(map[string]any{
		"dn":      "uid=alice,dc=example,dc=com",
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"updated"}}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodPatch, "https://admin.example/api/entry", strings.NewReader(string(payload)))
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
		t.Fatal("canceled write did not return")
	}
	var body apiErrorBody
	if response.Code != http.StatusRequestTimeout || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		body.Error.Code != "ldap_result_unknown" {
		t.Fatalf("status = %d, error = %#v, body = %s", response.Code, body.Error, response.Body.String())
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("retired session status = %d, body = %s", probe.Code, probe.Body.String())
	}
	waitForFakeClientClose(t, client)
}

func TestSearchValidationRejectsUnsafeBoundsBeforeLDAP(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxSearchSize = 10
		config.MaxFilterDepth = 3
	})
	authenticated := loginTestSession(t, application, "dn")
	tests := []string{
		"/api/search?base=not-a-dn&filter=%28objectClass%3D%2A%29",
		"/api/search?base=dc%3Dexample%2Cdc%3Dcom&filter=%28%26%28%26%28uid%3Da%29%29%29%29",
		"/api/search?base=dc%3Dexample%2Cdc%3Dcom&filter=%28uid%3Da%29&size_limit=11",
		"/api/search?base=dc%3Dexample%2Cdc%3Dcom&filter=%28uid%3Da%29&attribute=bad_attribute",
	}
	for _, path := range tests {
		response := performJSONRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body = %s", path, response.Code, response.Body.String())
		}
	}
	client.mu.Lock()
	searchCount := len(client.searches)
	client.mu.Unlock()
	if searchCount != 0 {
		t.Fatalf("invalid searches sent to LDAP = %d", searchCount)
	}
}

func TestSearchAndEntryRejectUnfollowedReferrals(t *testing.T) {
	t.Parallel()
	referral := "ldap://elsewhere.example/dc=example,dc=com"
	tests := []struct {
		name   string
		path   string
		result *ldap.SearchResult
	}{
		{
			name: "search with partial entries",
			path: "/api/search?base=dc%3Dexample%2Cdc%3Dcom&filter=%28objectClass%3D%2A%29",
			result: &ldap.SearchResult{
				Entries: []*ldap.Entry{ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
					"objectClass": {"person"},
				})},
				Referrals: []string{referral},
			},
		},
		{
			name:   "base entry with referral only",
			path:   "/api/entry?dn=uid%3Dalice%2Cdc%3Dexample%2Cdc%3Dcom",
			result: &ldap.SearchResult{Referrals: []string{referral}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return test.result, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")

			response := performJSONRequest(t, application, http.MethodGet, test.path, nil, authenticated.cookie, "")
			if response.Code != http.StatusBadGateway ||
				!strings.Contains(response.Body.String(), "ldap_referral_unfollowed") {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestBoundConnectionRejectsConcurrentSessionOperation(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		return &ldap.SearchResult{}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	request := func() *httptest.ResponseRecorder {
		return performJSONRequest(t, application, http.MethodGet,
			"/api/search?base=dc%3Dexample%2Cdc%3Dcom&filter=%28objectClass%3D%2A%29",
			nil, authenticated.cookie, "")
	}
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstResult <- request() }()
	<-entered
	second := request()
	if second.Code != http.StatusConflict || second.Header().Get("Retry-After") != "1" ||
		!strings.Contains(second.Body.String(), "session_busy") {
		t.Fatalf("second search status = %d, headers = %#v, body = %s", second.Code, second.Header(), second.Body.String())
	}
	if activeSlots := len(application.operations); activeSlots != 1 {
		t.Fatalf("active global operation slots = %d, want only the executing request", activeSlots)
	}
	close(release)
	if first := <-firstResult; first.Code != http.StatusOK {
		t.Fatalf("first search status = %d", first.Code)
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent LDAP calls = %d", maximum.Load())
	}
}

type writeAPITestCase struct {
	name     string
	method   string
	path     string
	body     any
	failWith func(*fakeClient, error)
}

func writeAPITestCases() []writeAPITestCase {
	return []writeAPITestCase{
		{
			name: "add", method: http.MethodPost, path: "/api/entry",
			body: map[string]any{
				"dn":         "uid=alice,dc=example,dc=com",
				"attributes": map[string][]string{"objectClass": {"person"}, "cn": {"Alice"}, "sn": {"Alice"}},
			},
			failWith: func(client *fakeClient, failure error) {
				client.addFunc = func(*ldap.AddRequest) error { return failure }
			},
		},
		{
			name: "modify", method: http.MethodPatch, path: "/api/entry",
			body: map[string]any{
				"dn":      "uid=alice,dc=example,dc=com",
				"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"updated"}}},
			},
			failWith: func(client *fakeClient, failure error) {
				client.modifyFunc = func(*ldap.ModifyRequest) error { return failure }
			},
		},
		{
			name: "delete", method: http.MethodDelete,
			path: "/api/entry?dn=" + url.QueryEscape("uid=alice,dc=example,dc=com"),
			failWith: func(client *fakeClient, failure error) {
				client.delFunc = func(*ldap.DelRequest) error { return failure }
			},
		},
		{
			name: "modify DN", method: http.MethodPost, path: "/api/rename",
			body: map[string]any{
				"dn": "uid=alice,dc=example,dc=com", "new_rdn": "uid=alice2", "delete_old_rdn": true,
			},
			failWith: func(client *fakeClient, failure error) {
				client.modifyDNFunc = func(*ldap.ModifyDNRequest) error { return failure }
			},
		},
		{
			name: "password modify", method: http.MethodPost, path: "/api/password-modify",
			body: map[string]string{
				"user_identity": "uid=alice,dc=example,dc=com", "new_password": "new-secret",
			},
			failWith: func(client *fakeClient, failure error) {
				client.passwordModifyFunc = func(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
					return nil, failure
				}
			},
		},
	}
}

func waitForFakeClientClose(t *testing.T, client *fakeClient) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		client.mu.Lock()
		closeCount := client.closeCount
		client.mu.Unlock()
		if closeCount == 1 {
			return
		}
		if closeCount > 1 || time.Now().After(deadline) {
			t.Fatalf("LDAP client close count = %d", closeCount)
		}
		time.Sleep(time.Millisecond)
	}
}

func containsJSONText(data []byte, value string) bool {
	return strings.Contains(string(data), value)
}
