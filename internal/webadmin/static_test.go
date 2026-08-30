package webadmin

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
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

func TestStaticApplicationChineseLocaleContract(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{}, nil)

	index := httptest.NewRecorder()
	application.Handler().ServeHTTP(index, httptest.NewRequest(http.MethodGet, "https://admin.example/", nil))
	if index.Code != http.StatusOK {
		t.Fatalf("index status = %d", index.Code)
	}
	indexBody := index.Body.String()
	for _, marker := range []string{
		`data-language="en"`,
		`data-language="zh-CN"`,
		`aria-label="Language"`,
		`value="(objectClass=*)"`,
		`placeholder="cn=admin,dc=example,dc=org"`,
		`id="filter-builder"`,
		`id="bulk-toolbar"`,
		`id="group-members"`,
		`id="menu-export-csv"`,
		`id="menu-export-json"`,
		`id="select-page"`,
		`id="column-relative-name"`,
		`id="column-open"`,
	} {
		if !strings.Contains(indexBody, marker) {
			t.Errorf("index does not contain %q", marker)
		}
	}

	asset := httptest.NewRecorder()
	application.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "https://admin.example/app.js", nil))
	if asset.Code != http.StatusOK {
		t.Fatalf("app.js status = %d", asset.Code)
	}
	assetBody := asset.Body.String()
	for _, marker := range []string{
		`const LANGUAGE_STORAGE_KEY = "ldap-go.webadmin.language"`,
		`navigator.language`,
		`window.localStorage.getItem(LANGUAGE_STORAGE_KEY)`,
		`window.localStorage.setItem(LANGUAGE_STORAGE_KEY, state.language)`,
		`document.documentElement.lang = state.language`,
		`Object.prototype.hasOwnProperty.call(messages, language)`,
		`bindings.set(property, { key, params, property })`,
		`[data-localized-validation="true"]`,
		`renderDynamic($("small", elements.monitorHealth)`,
		`function filterFromBuilder()`,
		`function runBulk(`,
		`function renderGroupMembers(`,
		`function openCloneDialog()`,
		`function exportData(format)`,
		`["#column-relative-name", "content.relativeName"]`,
		`["#column-open", "content.open"]`,
		"\"app.title\": \"LDAP \u8fd0\u7ef4\u7ba1\u7406\"",
		"\"search.filter\": \"LDAP \u8fc7\u6ee4\u5668\"",
		"\"import.content\": \"LDIF \u5185\u5bb9\"",
	} {
		if !strings.Contains(assetBody, marker) {
			t.Errorf("app.js does not contain %q", marker)
		}
	}
	if strings.Contains(assetBody, `.entry-table th:nth-child`) {
		t.Error("table header localization must not replace structural th contents")
	}
	if strings.Contains(assetBody, `setFormSubmitting(event.currentTarget`) {
		t.Error("async submit handlers must capture currentTarget before awaiting")
	}
	if count := strings.Count(assetBody, `const submittedForm = event.currentTarget`); count != 7 {
		t.Errorf("captured async submit forms = %d, want 7", count)
	}

	englishKeys := localeKeys(t, assetBody, "en", `"zh-CN"`)
	chineseKeys := localeKeys(t, assetBody, `"zh-CN"`, "};")
	if strings.Join(englishKeys, "\n") != strings.Join(chineseKeys, "\n") {
		t.Fatalf("locale keys differ:\nEnglish: %v\nChinese: %v", englishKeys, chineseKeys)
	}
}

func TestAdvancedAdministrationRoutesAreRegistered(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{}, nil)
	tests := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/bulk"},
		{method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom"},
		{method: http.MethodGet, path: "/api/data-export?format=json"},
		{method: http.MethodGet, path: "/api/binary?dn=uid%3Da%2Cdc%3Dexample&attribute=jpegPhoto"},
		{method: http.MethodPost, path: "/api/csv-import"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, "https://admin.example"+test.path, nil)
		application.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s %s status = %d, want %d; body = %s", test.method, test.path, response.Code, http.StatusUnauthorized, response.Body.String())
		}
	}
}

func localeKeys(t *testing.T, source, start, end string) []string {
	t.Helper()
	startMarker := start + ": {"
	startIndex := strings.Index(source, startMarker)
	if startIndex < 0 {
		t.Fatalf("locale start marker %q not found", startMarker)
	}
	section := source[startIndex+len(startMarker):]
	endIndex := strings.Index(section, end)
	if endIndex < 0 {
		t.Fatalf("locale end marker %q not found", end)
	}
	keyPattern := regexp.MustCompile(`(?m)^\s+"([^"]+)":`)
	matches := keyPattern.FindAllStringSubmatch(section[:endIndex], -1)
	keys := make([]string, 0, len(matches))
	for _, match := range matches {
		keys = append(keys, match[1])
	}
	sort.Strings(keys)
	return keys
}
