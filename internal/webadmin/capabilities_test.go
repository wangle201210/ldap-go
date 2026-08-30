package webadmin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestCapabilitiesRouteReturnsEffectiveLimitsWithoutLDAP(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxSearchSize = 100
		config.MaxSearchSeconds = 9
		config.MaxAttributes = 21
		config.MaxImportChanges = 34
		config.MaxExportEntries = 55
		config.MaxExportBytes = 987654
		config.RequestBodyLimit = 456789
		config.MaxMonitorEntries = 13
	})
	authenticated := loginTestSession(t, application, "dn")

	response := performCapabilitiesRequest(application, http.MethodGet, authenticated.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d, body = %s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", contentType)
	}

	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	expected := map[string]any{
		"max_search_size":        float64(100),
		"max_search_seconds":     float64(9),
		"max_attributes":         float64(21),
		"max_import_changes":     float64(34),
		"max_export_entries":     float64(55),
		"max_export_bytes":       float64(987654),
		"request_body_limit":     float64(456789),
		"max_monitor_entries":    float64(13),
		"binary_max_values":      float64(maximumBinaryAttributeValues),
		"binary_max_value_bytes": float64(maximumBinaryValueBytes),
		"binary_max_total_bytes": float64(maximumBinaryTotalBytes),
		"page_size":              float64(100),
	}
	if !reflect.DeepEqual(body, expected) {
		t.Fatalf("capabilities = %#v, want %#v", body, expected)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.searches) != 0 || len(client.adds) != 0 || len(client.modifies) != 0 ||
		len(client.deletes) != 0 || len(client.renames) != 0 || client.passwordCalls != 0 {
		t.Fatalf("capabilities performed LDAP operations: searches=%d adds=%d modifies=%d deletes=%d renames=%d passwords=%d",
			len(client.searches), len(client.adds), len(client.modifies), len(client.deletes),
			len(client.renames), client.passwordCalls)
	}
}

func TestCapabilitiesRecommendedPageSizeUsesDefaultWithinSearchLimit(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{&fakeClient{}}}, func(config *Config) {
		config.MaxSearchSize = 500
	})
	authenticated := loginTestSession(t, application, "dn")

	response := performCapabilitiesRequest(application, http.MethodGet, authenticated.cookie)
	var body capabilitiesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if body.RecommendedPageSize != recommendedCapabilitiesPageSize ||
		body.RecommendedPageSize > body.MaxSearchSize {
		t.Fatalf("page_size = %d, max_search_size = %d", body.RecommendedPageSize, body.MaxSearchSize)
	}
}

func TestCapabilitiesRouteRequiresAuthentication(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{&fakeClient{}}}, nil)

	unauthenticated := performCapabilitiesRequest(application, http.MethodGet, nil)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, body = %s", unauthenticated.Code, unauthenticated.Body.String())
	}
	assertCapabilitiesAPIErrorCode(t, unauthenticated, "authentication_required")
	if unauthenticated.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", unauthenticated.Header().Get("Cache-Control"))
	}
}

func TestCapabilitiesRouteAllowsOnlyGET(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{&fakeClient{}}}, nil)

	authenticated := loginTestSession(t, application, "dn")
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		method := method
		t.Run(method, func(t *testing.T) {
			wrongMethod := performCapabilitiesRequest(application, method, authenticated.cookie)
			if wrongMethod.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, body = %s", wrongMethod.Code, wrongMethod.Body.String())
			}
			if allow := wrongMethod.Header().Get("Allow"); allow != http.MethodGet {
				t.Fatalf("Allow = %q, want %q", allow, http.MethodGet)
			}
			assertCapabilitiesAPIErrorCode(t, wrongMethod, "method_not_allowed")
		})
	}
}

func performCapabilitiesRequest(
	application *Application,
	method string,
	cookie *http.Cookie,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://admin.example/api/capabilities", nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	return response
}

func assertCapabilitiesAPIErrorCode(t *testing.T, response *httptest.ResponseRecorder, expected string) {
	t.Helper()
	var body apiErrorBody
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode API error: %v", err)
	}
	if body.Error.Code != expected {
		t.Fatalf("error code = %q, want %q", body.Error.Code, expected)
	}
}
