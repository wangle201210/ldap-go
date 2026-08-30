package webadmin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestCSVImportAddsInCSVOrderWithBOMCRLFEmptyLinesAndEscaping(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	rdnValue := " Smith, +# "

	response := performCSVImportRequest(t, application, map[string]any{
		"csv":               "\uFEFFuid,common_name,note,ignored\r\n\"" + rdnValue + "\",Alice,\"first\r\nline\",x\r\n\r\nbob,Bob,,y\r\n",
		"base_dn":           "ou=people,dc=example,dc=com",
		"rdn_attribute":     "uid",
		"object_classes":    []string{"top", "inetOrgPerson"},
		"mapping":           map[string]string{"note": "description", "common_name": "cn", "uid": "uid"},
		"continue_on_error": false,
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var result csvImportResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	wantFirstDN := "uid=" + ldap.EscapeDN(rdnValue) + ",ou=people,dc=example,dc=com"
	if result.Applied != 2 || result.Failed != 0 || len(result.Results) != 2 {
		t.Fatalf("result = %#v", result)
	}
	if result.Results[0].Row != 2 || result.Results[0].DN != wantFirstDN ||
		!result.Results[0].Success || result.Results[0].Status != "applied" ||
		result.Results[1].Row != 5 || result.Results[1].DN != "uid=bob,ou=people,dc=example,dc=com" ||
		!result.Results[1].Success || result.Results[1].Status != "applied" {
		t.Fatalf("results = %#v", result.Results)
	}

	client.mu.Lock()
	adds := append([]*ldap.AddRequest(nil), client.adds...)
	client.mu.Unlock()
	if len(adds) != 2 || adds[0].DN != wantFirstDN || adds[1].DN != result.Results[1].DN {
		t.Fatalf("add order = %#v", adds)
	}
	wantFirst := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "inetOrgPerson"}},
		{Type: "uid", Vals: []string{rdnValue}},
		{Type: "cn", Vals: []string{"Alice"}},
		{Type: "description", Vals: []string{"first\nline"}},
	}
	wantSecond := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "inetOrgPerson"}},
		{Type: "uid", Vals: []string{"bob"}},
		{Type: "cn", Vals: []string{"Bob"}},
	}
	if !reflect.DeepEqual(adds[0].Attributes, wantFirst) {
		t.Fatalf("first attributes = %#v, want %#v", adds[0].Attributes, wantFirst)
	}
	if !reflect.DeepEqual(adds[1].Attributes, wantSecond) {
		t.Fatalf("second attributes = %#v, want %#v", adds[1].Attributes, wantSecond)
	}
}

func TestCSVImportStopsAfterPartialFailureAndMarksRemainingRows(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.addFunc = func(request *ldap.AddRequest) error {
		if strings.HasPrefix(request.DN, "uid=second,") {
			return &ldap.Error{
				ResultCode: ldap.LDAPResultInsufficientAccessRights,
				MatchedDN:  "ou=people,dc=example,dc=com",
				Err:        errors.New("denied"),
			}
		}
		return nil
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performCSVImportRequest(t, application, validCSVImportBody("first\nsecond\nthird\n", false),
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var result csvImportResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Applied != 1 || result.Failed != 1 || len(result.Results) != 3 {
		t.Fatalf("result = %#v", result)
	}
	if !result.Results[0].Success || result.Results[0].Status != "applied" ||
		result.Results[1].Success || result.Results[1].Status != "failed" ||
		result.Results[1].Error == nil || result.Results[1].Error.LDAPResultCode == nil ||
		*result.Results[1].Error.LDAPResultCode != ldap.LDAPResultInsufficientAccessRights ||
		result.Results[1].Error.MatchedDN != "ou=people,dc=example,dc=com" ||
		result.Results[2].Success || result.Results[2].Status != "not_attempted" || result.Results[2].Error != nil {
		t.Fatalf("results = %#v", result.Results)
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 2 {
		t.Fatalf("Add calls = %d, want 2", addCount)
	}
}

func TestCSVImportStopsAfterUnknownTransportResult(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.addFunc = func(request *ldap.AddRequest) error {
		switch {
		case strings.HasPrefix(request.DN, "uid=first,"):
			return errors.New("connection reset with private details")
		case strings.HasPrefix(request.DN, "uid=second,"):
			return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("exists"))
		default:
			return nil
		}
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performCSVImportRequest(t, application, validCSVImportBody("first\nsecond\nthird\n", true),
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var result csvImportResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Applied != 0 || result.Failed != 0 || result.Unknown != 1 || len(result.Results) != 3 {
		t.Fatalf("result = %#v", result)
	}
	if result.Results[0].Status != "unknown" || result.Results[0].Error == nil || result.Results[0].Error.Code != "ldap_result_unknown" ||
		strings.Contains(result.Results[0].Error.Message, "private") ||
		result.Results[1].Status != "not_attempted" || result.Results[1].Error != nil ||
		result.Results[2].Status != "not_attempted" || result.Results[2].Error != nil {
		t.Fatalf("results = %#v", result.Results)
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 1 {
		t.Fatalf("Add calls = %d, want 1", addCount)
	}
}

func TestCSVImportRejectsInvalidDocumentsBeforeLDAP(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxImportChanges = 2
		config.MaxAttributes = 3
	})
	authenticated := loginTestSession(t, application, "dn")
	largeValue := strings.Repeat("x", maximumCSVImportValueBytes+1)

	tests := []struct {
		name string
		body map[string]any
	}{
		{name: "empty csv", body: csvImportBody("", "dc=example,dc=com", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "empty base DN", body: csvImportBody("uid\nalice\n", "", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "invalid base DN", body: csvImportBody("uid\nalice\n", "not a DN", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "invalid RDN attribute", body: csvImportBody("uid\nalice\n", "dc=example", "uid;lang-en", []string{"top"}, map[string]string{"uid": "uid;lang-en"})},
		{name: "empty object classes", body: csvImportBody("uid\nalice\n", "dc=example", "uid", nil, map[string]string{"uid": "uid"})},
		{name: "invalid object class", body: csvImportBody("uid\nalice\n", "dc=example", "uid", []string{"bad class"}, map[string]string{"uid": "uid"})},
		{name: "duplicate object class", body: csvImportBody("uid\nalice\n", "dc=example", "uid", []string{"top", "TOP"}, map[string]string{"uid": "uid"})},
		{name: "empty header", body: csvImportBody("uid, ,cn\na,b,c\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "duplicate header", body: csvImportBody("uid,uid\na,b\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "empty mapping", body: csvImportBody("uid\nalice\n", "dc=example", "uid", []string{"top"}, map[string]string{})},
		{name: "unknown mapped header", body: csvImportBody("uid\nalice\n", "dc=example", "uid", []string{"top"}, map[string]string{"missing": "uid"})},
		{name: "invalid mapped attribute", body: csvImportBody("uid\nalice\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "bad attribute"})},
		{name: "duplicate mapped attribute", body: csvImportBody("uid,login\nalice,a\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid", "login": "UID"})},
		{name: "mapped objectClass", body: csvImportBody("uid,class\nalice,top\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid", "class": "objectClass"})},
		{name: "RDN not mapped", body: csvImportBody("cn\nAlice\n", "dc=example", "uid", []string{"top"}, map[string]string{"cn": "cn"})},
		{name: "attribute limit", body: csvImportBody("uid,cn,sn\na,A,B\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid", "cn": "cn", "sn": "sn"})},
		{name: "no data rows", body: csvImportBody("uid\n\n\r\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "empty RDN value", body: csvImportBody("uid,cn\n,Alice\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid", "cn": "cn"})},
		{name: "inconsistent field count", body: csvImportBody("uid,cn\nalice\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid", "cn": "cn"})},
		{name: "malformed quote", body: csvImportBody("uid\n\"alice\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "too many rows", body: csvImportBody("uid\na\nb\nc\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
		{name: "value too large", body: csvImportBody("uid\n"+largeValue+"\n", "dc=example", "uid", []string{"top"}, map[string]string{"uid": "uid"})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performCSVImportRequest(t, application, test.body,
				authenticated.cookie, authenticated.csrf, "https://admin.example")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			assertAPIErrorCode(t, response, "invalid_csv_import")
		})
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 0 {
		t.Fatalf("invalid documents reached LDAP: Add calls = %d", addCount)
	}
}

func TestCSVImportStrictJSONDuplicateMappingAndUTF8(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	tests := []struct {
		name string
		body []byte
	}{
		{name: "unknown field", body: []byte(`{"csv":"uid\nalice\n","base_dn":"dc=example","rdn_attribute":"uid","object_classes":["top"],"mapping":{"uid":"uid"},"extra":true}`)},
		{name: "null csv", body: []byte(`{"csv":null,"base_dn":"dc=example","rdn_attribute":"uid","object_classes":["top"],"mapping":{"uid":"uid"}}`)},
		{name: "duplicate mapping member", body: []byte(`{"csv":"uid\nalice\n","base_dn":"dc=example","rdn_attribute":"uid","object_classes":["top"],"mapping":{"uid":"uid","uid":"cn"}}`)},
		{name: "non-string mapping value", body: []byte(`{"csv":"uid\nalice\n","base_dn":"dc=example","rdn_attribute":"uid","object_classes":["top"],"mapping":{"uid":1}}`)},
		{name: "null mapping value", body: []byte(`{"csv":"uid\nalice\n","base_dn":"dc=example","rdn_attribute":"uid","object_classes":["top"],"mapping":{"uid":null}}`)},
	}
	invalidUTF8 := []byte(`{"csv":"uid\n`)
	invalidUTF8 = append(invalidUTF8, 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`\n","base_dn":"dc=example","rdn_attribute":"uid","object_classes":["top"],"mapping":{"uid":"uid"}}`)...)
	tests = append(tests, struct {
		name string
		body []byte
	}{name: "invalid UTF-8", body: invalidUTF8})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performRawCSVImportRequest(application, http.MethodPost, test.body,
				authenticated.cookie, authenticated.csrf, "https://admin.example", "application/json")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			assertAPIErrorCode(t, response, "invalid_request")
		})
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 0 {
		t.Fatalf("invalid JSON reached LDAP: Add calls = %d", addCount)
	}
}

func TestCSVImportRequiresPOSTSessionOriginCSRFAndJSON(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	body, err := json.Marshal(validCSVImportBody("alice\n", false))
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	tests := []struct {
		name        string
		method      string
		cookie      *http.Cookie
		csrf        string
		origin      string
		contentType string
		status      int
		code        string
	}{
		{name: "wrong method", method: http.MethodGet, cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", contentType: "application/json", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
		{name: "no session", method: http.MethodPost, csrf: authenticated.csrf, origin: "https://admin.example", contentType: "application/json", status: http.StatusUnauthorized, code: "authentication_required"},
		{name: "bad origin", method: http.MethodPost, cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://evil.example", contentType: "application/json", status: http.StatusForbidden, code: "invalid_origin"},
		{name: "bad CSRF", method: http.MethodPost, cookie: authenticated.cookie, csrf: "wrong", origin: "https://admin.example", contentType: "application/json", status: http.StatusForbidden, code: "invalid_csrf_token"},
		{name: "wrong content type", method: http.MethodPost, cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://admin.example", contentType: "text/csv", status: http.StatusBadRequest, code: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performRawCSVImportRequest(application, test.method, body,
				test.cookie, test.csrf, test.origin, test.contentType)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.status, response.Body.String())
			}
			assertAPIErrorCode(t, response, test.code)
			if test.method == http.MethodGet && response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow = %q", response.Header().Get("Allow"))
			}
		})
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 0 {
		t.Fatalf("unauthorized requests reached LDAP: Add calls = %d", addCount)
	}
}

func TestCSVImportHonorsRequestBodyLimit(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.RequestBodyLimit = 128
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performCSVImportRequest(t, application, validCSVImportBody(strings.Repeat("a", 256)+"\n", false),
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	assertAPIErrorCode(t, response, "request_body_too_large")
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 0 {
		t.Fatalf("oversized body reached LDAP: Add calls = %d", addCount)
	}
}

func validCSVImportBody(rows string, continueOnError bool) map[string]any {
	return csvImportBody("uid\n"+rows, "ou=people,dc=example,dc=com", "uid",
		[]string{"top", "inetOrgPerson"}, map[string]string{"uid": "uid"}, continueOnError)
}

func csvImportBody(csvText, baseDN, rdnAttribute string, objectClasses []string, mapping map[string]string, continueOnError ...bool) map[string]any {
	body := map[string]any{
		"csv": csvText, "base_dn": baseDN, "rdn_attribute": rdnAttribute,
		"object_classes": objectClasses, "mapping": mapping,
	}
	if len(continueOnError) != 0 {
		body["continue_on_error"] = continueOnError[0]
	}
	return body
}

func performCSVImportRequest(
	t *testing.T,
	application *Application,
	body any,
	cookie *http.Cookie,
	csrf string,
	origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode CSV import request: %v", err)
	}
	return performRawCSVImportRequest(application, http.MethodPost, encoded, cookie, csrf, origin, "application/json")
}

func performRawCSVImportRequest(
	application *Application,
	method string,
	body []byte,
	cookie *http.Cookie,
	csrf string,
	origin string,
	contentType string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://admin.example/api/csv-import", bytes.NewReader(body))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Origin", origin)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	application.handleCSVImport(response, request)
	return response
}

func assertAPIErrorCode(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var result apiErrorBody
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode API error: %v; body = %s", err, response.Body.String())
	}
	if result.Error.Code != want {
		t.Fatalf("error code = %q, want %q; error = %s", result.Error.Code, want, fmt.Sprintf("%#v", result.Error))
	}
}
