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

func TestStaticApplicationCapabilitiesContract(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{}, nil)

	asset := httptest.NewRecorder()
	application.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "https://admin.example/app.js", nil))
	if asset.Code != http.StatusOK {
		t.Fatalf("app.js status = %d", asset.Code)
	}
	source := asset.Body.String()
	for _, marker := range []string{
		`const { data: capabilities } = await api("/api/capabilities")`,
		`state.capabilities.max_search_size`,
		`state.capabilities.page_size`,
		`$("#search-size").max = String(searchMaximumSize())`,
		`$("#search-size").value = String(searchDefaultSize())`,
		`return Math.min(500, searchMaximumSize())`,
		`size_limit: Math.min(searchMaximumSize()`,
		`page_size: Math.min(searchMaximumSize()`,
	} {
		if !strings.Contains(source, marker) {
			t.Errorf("app.js does not contain capabilities contract %q", marker)
		}
	}

	capabilitiesFetch := strings.Index(source, `await api("/api/capabilities")`)
	rootDSEFetch := strings.Index(source, `await api("/api/root-dse")`)
	if capabilitiesFetch < 0 || rootDSEFetch < 0 || capabilitiesFetch > rootDSEFetch {
		t.Errorf("workspace must load capabilities before root DSE: capabilities=%d root-dse=%d", capabilitiesFetch, rootDSEFetch)
	}
}

func TestStaticApplicationPasswordVerificationContract(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{}, nil)

	index := httptest.NewRecorder()
	application.Handler().ServeHTTP(index, httptest.NewRequest(http.MethodGet, "https://admin.example/", nil))
	if index.Code != http.StatusOK {
		t.Fatalf("index status = %d", index.Code)
	}
	indexSource := index.Body.String()
	for _, marker := range []string{
		`id="current-password" type="password" autocomplete="current-password"`,
		`aria-describedby="password-verify-status"`,
		`id="verify-current-password" type="button"`,
		`id="password-verify-status" role="status" aria-live="polite" aria-atomic="true"`,
		`id="password-hash-scheme" aria-describedby="password-hash-warning"`,
		`<option value="policy" selected>Server policy (recommended)</option>`,
		`id="password-hash-warning" role="note" aria-live="polite" hidden`,
	} {
		if !strings.Contains(indexSource, marker) {
			t.Errorf("index does not contain password verification contract %q", marker)
		}
	}

	asset := httptest.NewRecorder()
	application.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "https://admin.example/app.js", nil))
	if asset.Code != http.StatusOK {
		t.Fatalf("app.js status = %d", asset.Code)
	}
	source := asset.Body.String()
	for _, marker := range []string{
		`"/api/password-verify"`,
		`const targetDN = state.passwordTargetDN`,
		`const generation = state.sessionGeneration`,
		`const sequence = ++state.passwordVerifySequence`,
		`body: { user_identity: targetDN, password }`,
		`generation === state.sessionGeneration`,
		`targetDN === state.passwordTargetDN`,
		`data && data.verified === true`,
		`if (oldPassword !== "") body.old_password = oldPassword`,
		`const PASSWORD_STORAGE_POLICY = "policy"`,
		`{ value: "{PBKDF2-SM3}", labelKey: "password.scheme.pbkdf2Sm3" }`,
		`{ value: "{ARGON2}", labelKey: "password.scheme.argon2" }`,
		`{ value: "{PBKDF2-SHA256}", labelKey: "password.scheme.pbkdf2Sha256" }`,
		`{ value: "{PBKDF2-SHA512}", labelKey: "password.scheme.pbkdf2Sha512" }`,
		`{ value: "{SSHA512}", labelKey: "password.scheme.ssha512" }`,
		`{ value: "{SSHA256}", labelKey: "password.scheme.ssha256" }`,
		`{ value: "{SSHA}", labelKey: "password.scheme.ssha" }`,
		`{ value: "{SSM3}", labelKey: "password.scheme.ssm3" }`,
		`state.capabilities && state.capabilities.password_hash_schemes`,
		`if (!Array.isArray(advertised)) return []`,
		`function renderPasswordHashSchemes(`,
		`function selectedPasswordStorageMethod()`,
		`await api("/api/password-set-hash"`,
		`const body = { user_identity: targetDN, new_password: password, hash_scheme: storageMethod }`,
		`["label[for='password-hash-scheme']", "password.storage"]`,
		`["#password-hash-warning", "password.hashWarning"]`,
		`password_hash_target_unsupported: "password.targetUnsupported"`,
		`"password.storage": "本次密码存储方式"`,
		`"password.policy": "服务器策略（推荐）"`,
		`"password.hashWarning": "所选算法仅用于本次 Password Modify，且需要密码管理员权限。填写当前密码时会由服务器原子校验，密码质量与密码历史仍会强制检查。"`,
		`passwordVerifyPending: false`,
		`["#verify-current-password", "password.verify", "attr:aria-label"]`,
		`["#verify-current-password", "password.verify", "attr:title"]`,
	} {
		if !strings.Contains(source, marker) {
			t.Errorf("app.js does not contain password verification contract %q", marker)
		}
	}
	if strings.Contains(source, `body: { user_identity: targetDN, old_password: oldPassword, new_password: password }`) {
		t.Error("administrator resets must not always send an empty old_password")
	}

	styles := httptest.NewRecorder()
	application.Handler().ServeHTTP(styles, httptest.NewRequest(http.MethodGet, "https://admin.example/styles.css", nil))
	if styles.Code != http.StatusOK {
		t.Fatalf("styles.css status = %d", styles.Code)
	}
	styleSource := styles.Body.String()
	for _, marker := range []string{
		`.password-verify-controls { display: grid; grid-template-columns: minmax(0, 1fr) auto;`,
		`.password-verification-status[data-state="verified"]`,
		`.password-verification-status[data-state="rejected"]`,
		`.password-storage-field, .password-storage-field select { min-width: 0; max-width: 100%; }`,
		`.password-hash-warning { scroll-margin-block: 8px; border-left: 3px solid var(--amber);`,
		`.password-modal-heading { min-width: 0; flex: 1; }`,
		`#password-target { margin: 8px 0 0; }`,
		`.password-verify-controls { grid-template-columns: minmax(0, 1fr); }`,
	} {
		if !strings.Contains(styleSource, marker) {
			t.Errorf("styles.css does not contain password verification contract %q", marker)
		}
	}
}

func TestStaticApplicationMutationSafetyContract(t *testing.T) {
	t.Parallel()
	application, _ := newTestApplication(t, &fakeConnector{}, nil)
	asset := httptest.NewRecorder()
	application.Handler().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "https://admin.example/app.js", nil))
	if asset.Code != http.StatusOK {
		t.Fatalf("app.js status = %d", asset.Code)
	}
	source := asset.Body.String()
	for _, marker := range []string{
		`csvRetryFingerprints: new Set()`,
		`ldifRetryFingerprints: new Set()`,
		`function canonicalLDIF(value)`,
		`async function batchFingerprint(kind, value)`,
		`function unsafeBatchOutcome(data, error = null)`,
		`state.csvRetryFingerprints.add(fingerprint)`,
		`state.ldifRetryFingerprints.add(fingerprint)`,
		`$$("button, input, select, textarea", form)`,
		`const generation = state.sessionGeneration`,
		`sequence !== fileSequence || generation !== state.sessionGeneration || state.selectedDN !== readTargetDN`,
		`node.toggle.classList.toggle("empty", !childCount && !node.nextCookie)`,
		`affectedDNs.filter(Boolean).forEach((dn) => requestedBranches.push(parentDN(dn) || dn))`,
		`await refreshAfterMutation([oldDN, newDN])`,
		`function currentEditorAttributeValues(name)`,
		`rule.type === "dITContentRules"`,
		`schemaDefinitionTokens(rule, "NOT")`,
		`async function runSearch(query = queryFromForm(), cookie = null, pageTransition = null)`,
		`handler: () => runSearch(query, cookie, pageTransition)`,
	} {
		if !strings.Contains(source, marker) {
			t.Errorf("app.js does not contain mutation safety contract %q", marker)
		}
	}
	if strings.Contains(source, "RetryBlocked") {
		t.Error("batch retry protection must not use an edit-cleared boolean lock")
	}
	if count := strings.Count(source, `openDialog(elements.importDialog)`); count != 1 {
		t.Errorf("LDIF dialog open calls = %d, want only the explicit menu/button path", count)
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
