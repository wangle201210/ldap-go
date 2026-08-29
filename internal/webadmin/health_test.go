package webadmin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestHealthAndMetricsEndpoints(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.BaseDN != "" || request.Scope != ldap.ScopeBaseObject {
			t.Fatalf("readiness Search = %#v", request)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{
			"supportedLDAPVersion": {"3"},
		})}}, nil
	}}
	application, err := New(Config{
		LDAPURL:   "ldap://127.0.0.1:389",
		Connector: &fakeConnector{clients: []Client{client}},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	for _, path := range []string{"/livez", "/readyz"} {
		request := httptest.NewRequest(http.MethodGet, "http://admin.example"+path, nil)
		response := httptest.NewRecorder()
		application.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%q", path, response.Code, response.Body.String())
		}
	}
	metrics := httptest.NewRecorder()
	application.Handler().ServeHTTP(
		metrics,
		httptest.NewRequest(http.MethodGet, "http://admin.example/metrics", nil),
	)
	if metrics.Code != http.StatusOK ||
		!strings.Contains(metrics.Body.String(), "ldap_go_web_admin_up 1") ||
		!strings.Contains(metrics.Body.String(), "ldap_go_web_admin_http_requests_total 3") {
		t.Fatalf("metrics status=%d body=%q", metrics.Code, metrics.Body.String())
	}
	if err := application.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	closed := httptest.NewRecorder()
	application.Handler().ServeHTTP(
		closed,
		httptest.NewRequest(http.MethodGet, "http://admin.example/livez", nil),
	)
	if closed.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed liveness status=%d", closed.Code)
	}
}

func TestReadinessRejectsLDAPResultErrorsAndEmptyRootDSE(t *testing.T) {
	t.Parallel()
	for _, client := range []*fakeClient{
		{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("unavailable")}
		}},
		{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		}},
	} {
		application, err := New(Config{
			LDAPURL: "ldap://127.0.0.1:389", Connector: &fakeConnector{clients: []Client{client}},
		})
		if err != nil {
			t.Fatalf("New(): %v", err)
		}
		response := httptest.NewRecorder()
		application.Handler().ServeHTTP(
			response,
			httptest.NewRequest(http.MethodGet, "http://admin.example/readyz", nil),
		)
		_ = application.Close()
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("readiness status=%d body=%q", response.Code, response.Body.String())
		}
	}
}
