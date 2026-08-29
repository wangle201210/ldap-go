package webadmin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestLDAPSearchResponseAndOperationBudgets(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"uid=large,dc=example,dc=com",
			map[string][]string{"description": {strings.Repeat("x", 4096)}},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxLDAPResponseBytes = 1024
		config.MaxProcessResponseBytes = 2048
		config.MaxConcurrentOperations = 1
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performJSONRequest(
		t, application, http.MethodPost, "/api/search",
		map[string]any{
			"base_dn": "dc=example,dc=com", "scope": "sub",
			"filter": "(objectClass=*)", "size_limit": 1,
		},
		authenticated.cookie,
		authenticated.csrf,
	)
	if response.Code != http.StatusRequestEntityTooLarge ||
		!strings.Contains(response.Body.String(), "ldap_response_too_large") {
		t.Fatalf("large response status=%d body=%s", response.Code, response.Body.String())
	}
	if application.responseBytes.Load() != 0 || application.responseRejects.Load() != 1 {
		t.Fatalf("response bytes=%d rejected=%d", application.responseBytes.Load(), application.responseRejects.Load())
	}

	application.operations <- struct{}{}
	defer func() { <-application.operations }()
	blocked := httptest.NewRecorder()
	application.Handler().ServeHTTP(
		blocked,
		httptest.NewRequest(http.MethodPost, "http://admin.example/api/login", strings.NewReader(`{}`)),
	)
	if blocked.Code != http.StatusServiceUnavailable ||
		!strings.Contains(blocked.Body.String(), "operation_capacity_reached") {
		t.Fatalf("blocked status=%d body=%s", blocked.Code, blocked.Body.String())
	}
}
