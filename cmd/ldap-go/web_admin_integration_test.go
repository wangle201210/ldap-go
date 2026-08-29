package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/wangle201210/ldap-go/internal/webadmin"
)

func TestWebAdminRealLDAPLifecycleAndACLs(t *testing.T) {
	ldapURL := startLDAPClientToolServer(t, nil)
	application, err := webadmin.New(webadmin.Config{LDAPURL: ldapURL})
	if err != nil {
		t.Fatalf("webadmin.New(): %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })
	web := httptest.NewServer(application.Handler())
	t.Cleanup(web.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New(): %v", err)
	}
	client := &http.Client{Jar: jar}

	csrf := webAdminLogin(
		t,
		client,
		web.URL,
		clientToolRootDN,
		clientToolRootPassword,
	)
	root := webAdminJSONRequest(t, client, web.URL, http.MethodGet, "/api/root-dse", nil, "", http.StatusOK)
	attributes, _ := root["attributes"].(map[string]any)
	if attributes == nil || attributes["namingContexts"] == nil {
		t.Fatalf("Root DSE response = %#v", root)
	}

	search := webAdminJSONRequest(t, client, web.URL, http.MethodPost, "/api/search", map[string]any{
		"base_dn": clientToolPeopleDN, "scope": "sub", "filter": "(uid=alice)",
		"attributes": []string{"uid", "cn"}, "size_limit": 20,
	}, csrf, http.StatusOK)
	entries, _ := search["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("Search response = %#v", search)
	}

	const userDN = "uid=web-user," + clientToolPeopleDN
	webAdminJSONRequest(t, client, web.URL, http.MethodPost, "/api/entries", map[string]any{
		"dn": userDN,
		"attributes": map[string][]string{
			"objectClass":  {"inetOrgPerson"},
			"uid":          {"web-user"},
			"cn":           {"Web User"},
			"sn":           {"User"},
			"userPassword": {"web-secret"},
		},
	}, csrf, http.StatusCreated)
	webAdminJSONRequest(t, client, web.URL, http.MethodPatch, "/api/entries", map[string]any{
		"dn": userDN,
		"changes": []map[string]any{{
			"operation": "replace", "attribute": "description", "values": []string{"managed by web"},
		}},
	}, csrf, http.StatusOK)
	webAdminJSONRequest(t, client, web.URL, http.MethodPost, "/api/password-modify", map[string]any{
		"user_identity": userDN, "new_password": "updated-secret",
	}, csrf, http.StatusOK)

	// A second login replaces and closes the root-bound LDAP session. The new
	// session can read through ordinary ACLs but cannot mutate directory data.
	csrf = webAdminLogin(t, client, web.URL, userDN, "updated-secret")
	webAdminJSONRequest(t, client, web.URL, http.MethodPost, "/api/search", map[string]any{
		"base_dn": clientToolPeopleDN, "scope": "base", "filter": "(objectClass=*)",
		"attributes": []string{"ou"}, "size_limit": 1,
	}, csrf, http.StatusOK)
	denied := webAdminJSONRequest(t, client, web.URL, http.MethodPost, "/api/entries", map[string]any{
		"dn": "uid=forbidden," + clientToolPeopleDN,
		"attributes": map[string][]string{
			"objectClass": {"inetOrgPerson"}, "uid": {"forbidden"},
			"cn": {"Forbidden"}, "sn": {"User"},
		},
	}, csrf, http.StatusForbidden)
	failure, _ := denied["error"].(map[string]any)
	if failure == nil || failure["ldap_result_code"] == nil {
		t.Fatalf("ACL denial response = %#v", denied)
	}
}

func webAdminLogin(
	t *testing.T,
	client *http.Client,
	baseURL,
	dn,
	password string,
) string {
	t.Helper()
	response := webAdminJSONRequest(t, client, baseURL, http.MethodPost, "/api/login", map[string]string{
		"bind_dn": dn, "password": password,
	}, "", http.StatusOK)
	csrf, _ := response["csrf_token"].(string)
	if csrf == "" {
		t.Fatalf("login response has no CSRF token: %#v", response)
	}
	return csrf
}

func webAdminJSONRequest(
	t *testing.T,
	client *http.Client,
	baseURL,
	method,
	path string,
	body any,
	csrf string,
	wantStatus int,
) map[string]any {
	t.Helper()
	var content io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal(): %v", err)
		}
		content = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, baseURL+path, content)
	if err != nil {
		t.Fatalf("http.NewRequest(): %v", err)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", baseURL)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client.Do(%s %s): %v", method, path, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll(%s %s): %v", method, path, err)
	}
	var decoded map[string]any
	if len(data) != 0 {
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("decode %s %s response %q: %v", method, path, data, err)
		}
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("%s %s status=%d body=%s, want %d", method, path, response.StatusCode, data, wantStatus)
	}
	return decoded
}
