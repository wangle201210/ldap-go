package webadmin

import (
	"encoding/base64"
	"encoding/json"
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
	client := &fakeClient{passwordModifyFunc: func(request *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
		if request.UserIdentity != "uid=alice,dc=example,dc=com" || request.NewPassword != "new-secret" {
			t.Fatalf("password request = %#v", request)
		}
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
	if password.Code != http.StatusOK || !containsJSONText(password.Body.Bytes(), base64.StdEncoding.EncodeToString([]byte("generated"))) {
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

func TestBoundConnectionIsSerializedPerSession(t *testing.T) {
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
	results := make(chan *httptest.ResponseRecorder, 2)
	go func() { results <- request() }()
	<-entered
	go func() { results <- request() }()
	select {
	case <-entered:
		t.Fatal("second search entered LDAP before the first completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if result := <-results; result.Code != http.StatusOK {
			t.Fatalf("search status = %d", result.Code)
		}
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent LDAP calls = %d", maximum.Load())
	}
}

func containsJSONText(data []byte, value string) bool {
	return strings.Contains(string(data), value)
}
