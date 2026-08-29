package webadmin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticApplicationAndUnknownAPI(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{}, nil)

	indexRequest := httptest.NewRequest(http.MethodGet, "https://admin.example/", nil)
	index := httptest.NewRecorder()
	application.Handler().ServeHTTP(index, indexRequest)
	if index.Code != http.StatusOK || !strings.Contains(index.Body.String(), "LDAP Operations") ||
		index.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("index status = %d, headers = %#v, body prefix = %.80q", index.Code, index.Header(), index.Body.String())
	}

	assetRequest := httptest.NewRequest(http.MethodGet, "https://admin.example/app.js", nil)
	asset := httptest.NewRecorder()
	application.Handler().ServeHTTP(asset, assetRequest)
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "/api/login") {
		t.Fatalf("asset status = %d, body prefix = %.80q", asset.Code, asset.Body.String())
	}

	unknownRequest := httptest.NewRequest(http.MethodGet, "https://admin.example/api/unknown", nil)
	unknown := httptest.NewRecorder()
	application.Handler().ServeHTTP(unknown, unknownRequest)
	if unknown.Code != http.StatusNotFound || unknown.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("unknown API status = %d, headers = %#v, body = %s", unknown.Code, unknown.Header(), unknown.Body.String())
	}
}
