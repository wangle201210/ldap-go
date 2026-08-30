package webadmin

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestBinaryAttributeGetUsesBoundBaseSearchAndReportsMetadata(t *testing.T) {
	t.Parallel()
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 24)...)
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.BaseDN != "uid=alice,dc=example,dc=com" || request.Scope != ldap.ScopeBaseObject ||
			request.Filter != "(objectClass=*)" || !request.EnforceSizeLimit || request.SizeLimit != 1 ||
			!reflect.DeepEqual(request.Attributes, []string{"jpegPhoto"}) {
			t.Fatalf("binary search request = %#v", request)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{{
			DN: request.BaseDN,
			Attributes: []*ldap.EntryAttribute{{
				Name: "jpegPhoto", ByteValues: [][]byte{png, {0x00, 0xff, 0x10}},
			}},
		}}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performBinaryRequest(t, application, http.MethodGet,
		binaryQuery("uid=alice,dc=example,dc=com", "jpegPhoto"), nil,
		authenticated.cookie, "", "https://admin.example")
	if response.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var output binaryAttributeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if !reflect.DeepEqual(output.ValuesBase64, []string{
		base64.StdEncoding.EncodeToString(png), base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10}),
	}) || !reflect.DeepEqual(output.SizesBytes, []int{len(png), 3}) ||
		output.MIMETypes[0] != "image/png" || output.MIMETypes[1] != "application/octet-stream" ||
		output.TotalBytes != len(png)+3 {
		t.Fatalf("GET response = %#v", output)
	}
	client.mu.Lock()
	searchCount := len(client.searches)
	client.mu.Unlock()
	if searchCount != 1 {
		t.Fatalf("search count = %d", searchCount)
	}
}

func TestBinaryAttributePutAndDeleteUseModifyOnBoundSession(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	dn := "uid=alice,dc=example,dc=com"

	put := performBinaryRequest(t, application, http.MethodPut, "/api/binary", map[string]any{
		"dn": dn, "attribute": "userCertificate;binary",
		"values_base64": []string{
			base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10}),
			base64.StdEncoding.EncodeToString([]byte("certificate")),
		},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", put.Code, put.Body.String())
	}

	remove := performBinaryRequest(t, application, http.MethodDelete,
		binaryQuery(dn, "userCertificate;binary"), nil,
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if remove.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, body = %s", remove.Code, remove.Body.String())
	}

	client.mu.Lock()
	requests := append([]*ldap.ModifyRequest(nil), client.modifies...)
	client.mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("modify count = %d", len(requests))
	}
	if requests[0].DN != dn || len(requests[0].Changes) != 1 ||
		requests[0].Changes[0].Operation != ldap.ReplaceAttribute ||
		requests[0].Changes[0].Modification.Type != "userCertificate;binary" ||
		!reflect.DeepEqual(requests[0].Changes[0].Modification.Vals,
			[]string{string([]byte{0x00, 0xff, 0x10}), "certificate"}) {
		t.Fatalf("PUT modify request = %#v", requests[0])
	}
	if requests[1].DN != dn || len(requests[1].Changes) != 1 ||
		requests[1].Changes[0].Operation != ldap.DeleteAttribute ||
		requests[1].Changes[0].Modification.Type != "userCertificate;binary" ||
		len(requests[1].Changes[0].Modification.Vals) != 0 {
		t.Fatalf("DELETE modify request = %#v", requests[1])
	}
}

func TestBinaryAttributeRejectsInvalidInputsBeforeLDAP(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	validDN := "uid=alice,dc=example,dc=com"
	validValue := base64.StdEncoding.EncodeToString([]byte("value"))

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		code   string
		status int
	}{
		{name: "missing query attribute", method: http.MethodGet, path: "/api/binary?dn=" + url.QueryEscape(validDN), code: "invalid_request", status: http.StatusBadRequest},
		{name: "duplicate query dn", method: http.MethodGet, path: binaryQuery(validDN, "jpegPhoto") + "&dn=dc%3Dother", code: "invalid_request", status: http.StatusBadRequest},
		{name: "unknown query", method: http.MethodGet, path: binaryQuery(validDN, "jpegPhoto") + "&scope=sub", code: "invalid_request", status: http.StatusBadRequest},
		{name: "invalid dn", method: http.MethodGet, path: binaryQuery("not-a-dn", "jpegPhoto"), code: "invalid_dn", status: http.StatusBadRequest},
		{name: "selector", method: http.MethodGet, path: binaryQuery(validDN, "*"), code: "invalid_attribute", status: http.StatusBadRequest},
		{name: "language option", method: http.MethodGet, path: binaryQuery(validDN, "jpegPhoto;lang-en"), code: "invalid_attribute", status: http.StatusBadRequest},
		{name: "duplicate binary option", method: http.MethodGet, path: binaryQuery(validDN, "jpegPhoto;binary;binary"), code: "invalid_attribute", status: http.StatusBadRequest},
		{name: "invalid base64", method: http.MethodPut, path: "/api/binary", body: binaryBody(validDN, "jpegPhoto", []string{"%%%"}), code: "invalid_binary_values", status: http.StatusBadRequest},
		{name: "base64 newline", method: http.MethodPut, path: "/api/binary", body: binaryBody(validDN, "jpegPhoto", []string{"dmFs\ndWU="}), code: "invalid_binary_values", status: http.StatusBadRequest},
		{name: "non canonical base64", method: http.MethodPut, path: "/api/binary", body: binaryBody(validDN, "jpegPhoto", []string{"dmFsdWU"}), code: "invalid_binary_values", status: http.StatusBadRequest},
		{name: "empty values", method: http.MethodPut, path: "/api/binary", body: binaryBody(validDN, "jpegPhoto", []string{}), code: "invalid_binary_values", status: http.StatusBadRequest},
		{name: "too many values", method: http.MethodPut, path: "/api/binary", body: binaryBody(validDN, "jpegPhoto", repeatString(validValue, maximumBinaryAttributeValues+1)), code: "binary_attribute_too_large", status: http.StatusRequestEntityTooLarge},
		{name: "mime input rejected", method: http.MethodPut, path: "/api/binary", body: map[string]any{"dn": validDN, "attribute": "jpegPhoto", "values_base64": []string{validValue}, "mime_type": "image/png"}, code: "invalid_request", status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			csrf := ""
			if test.method != http.MethodGet {
				csrf = authenticated.csrf
			}
			response := performBinaryRequest(t, application, test.method, test.path, test.body,
				authenticated.cookie, csrf, "https://admin.example")
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
	client.mu.Lock()
	searchCount, modifyCount := len(client.searches), len(client.modifies)
	client.mu.Unlock()
	if searchCount != 0 || modifyCount != 0 {
		t.Fatalf("invalid input reached LDAP: search=%d modify=%d", searchCount, modifyCount)
	}
}

func TestBinaryAttributeEnforcesDecodedAndLDAPResponseBudgets(t *testing.T) {
	t.Parallel()
	validDN := "uid=alice,dc=example,dc=com"

	t.Run("decoded value", func(t *testing.T) {
		client := &fakeClient{}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.RequestBodyLimit = int64(base64.StdEncoding.EncodedLen(maximumBinaryValueBytes+1) + 1024)
		})
		authenticated := loginTestSession(t, application, "dn")
		encoded := base64.StdEncoding.EncodeToString(make([]byte, maximumBinaryValueBytes+1))
		response := performBinaryRequest(t, application, http.MethodPut, "/api/binary",
			binaryBody(validDN, "jpegPhoto", []string{encoded}),
			authenticated.cookie, authenticated.csrf, "https://admin.example")
		if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "binary_attribute_too_large") {
			t.Fatalf("oversized PUT status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("decoded total", func(t *testing.T) {
		chunk := base64.StdEncoding.EncodeToString(make([]byte, maximumBinaryValueBytes))
		_, _, err := decodeBinaryValues(repeatString(chunk, maximumBinaryTotalBytes/maximumBinaryValueBytes+1))
		if err == nil || !strings.Contains(err.Error(), "total limit") {
			t.Fatalf("total budget error = %v", err)
		}
	})

	t.Run("GET value count", func(t *testing.T) {
		values := make([][]byte, maximumBinaryAttributeValues+1)
		client := binarySearchClient(validDN, "jpegPhoto", values)
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performBinaryRequest(t, application, http.MethodGet,
			binaryQuery(validDN, "jpegPhoto"), nil, authenticated.cookie, "", "https://admin.example")
		if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "binary_attribute_too_large") {
			t.Fatalf("value count status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("LDAP response", func(t *testing.T) {
		client := binarySearchClient(validDN, "jpegPhoto", [][]byte{make([]byte, 2048)})
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.MaxLDAPResponseBytes = 1024
			config.MaxProcessResponseBytes = 2048
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performBinaryRequest(t, application, http.MethodGet,
			binaryQuery(validDN, "jpegPhoto"), nil, authenticated.cookie, "", "https://admin.example")
		if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "ldap_response_too_large") {
			t.Fatalf("LDAP response status = %d, body = %s", response.Code, response.Body.String())
		}
		if application.responseBytes.Load() != 0 || application.responseRejects.Load() != 1 {
			t.Fatalf("response bytes = %d, rejects = %d", application.responseBytes.Load(), application.responseRejects.Load())
		}
	})

	t.Run("nil LDAP response", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, nil
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performBinaryRequest(t, application, http.MethodGet,
			binaryQuery(validDN, "jpegPhoto"), nil, authenticated.cookie, "", "https://admin.example")
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "invalid_ldap_response") {
			t.Fatalf("nil LDAP response status = %d, body = %s", response.Code, response.Body.String())
		}
		if application.responseBytes.Load() != 0 {
			t.Fatalf("retained response bytes = %d", application.responseBytes.Load())
		}
	})
}

func TestBinaryAttributeRequiresSessionMutationSecurityAndOperationCapacity(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxConcurrentOperations = 1
	})
	authenticated := loginTestSession(t, application, "dn")
	dn := "uid=alice,dc=example,dc=com"
	body := binaryBody(dn, "jpegPhoto", []string{"AA=="})

	unauthenticated := performBinaryRequest(t, application, http.MethodGet,
		binaryQuery(dn, "jpegPhoto"), nil, nil, "", "https://admin.example")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	badOrigin := performBinaryRequest(t, application, http.MethodPut, "/api/binary", body,
		authenticated.cookie, authenticated.csrf, "https://evil.example")
	if badOrigin.Code != http.StatusForbidden || !strings.Contains(badOrigin.Body.String(), "invalid_origin") {
		t.Fatalf("bad origin status = %d, body = %s", badOrigin.Code, badOrigin.Body.String())
	}
	badCSRF := performBinaryRequest(t, application, http.MethodPut, "/api/binary", body,
		authenticated.cookie, "wrong-token", "https://admin.example")
	if badCSRF.Code != http.StatusForbidden || !strings.Contains(badCSRF.Body.String(), "invalid_csrf_token") {
		t.Fatalf("bad CSRF status = %d, body = %s", badCSRF.Code, badCSRF.Body.String())
	}

	application.operations <- struct{}{}
	blocked := performBinaryRequest(t, application, http.MethodGet,
		binaryQuery(dn, "jpegPhoto"), nil, authenticated.cookie, "", "https://admin.example")
	<-application.operations
	if blocked.Code != http.StatusServiceUnavailable || !strings.Contains(blocked.Body.String(), "operation_capacity_reached") {
		t.Fatalf("operation capacity status = %d, body = %s", blocked.Code, blocked.Body.String())
	}

	client.mu.Lock()
	searchCount, modifyCount := len(client.searches), len(client.modifies)
	client.mu.Unlock()
	if searchCount != 0 || modifyCount != 0 {
		t.Fatalf("rejected request reached LDAP: search=%d modify=%d", searchCount, modifyCount)
	}
}

func TestBinaryAttributeMethodAndRequestBodyLimits(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.RequestBodyLimit = 128
	})
	authenticated := loginTestSession(t, application, "dn")

	wrongMethod := performBinaryRequest(t, application, http.MethodPost, "/api/binary", nil,
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "GET, PUT, DELETE" {
		t.Fatalf("wrong method status = %d, Allow = %q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}
	largeBody := binaryBody("uid=alice,dc=example,dc=com", "jpegPhoto", []string{
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 256)),
	})
	tooLarge := performBinaryRequest(t, application, http.MethodPut, "/api/binary", largeBody,
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if tooLarge.Code != http.StatusRequestEntityTooLarge || !strings.Contains(tooLarge.Body.String(), "request_body_too_large") {
		t.Fatalf("large body status = %d, body = %s", tooLarge.Code, tooLarge.Body.String())
	}
}

func performBinaryRequest(
	t *testing.T,
	application *Application,
	method string,
	path string,
	body any,
	cookie *http.Cookie,
	csrf string,
	origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatalf("encode binary request: %v", err)
		}
	}
	request := httptest.NewRequest(method, "https://admin.example"+path, &encoded)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Origin", origin)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	application.handleBinaryAttribute(response, request)
	return response
}

func binaryQuery(dn, attribute string) string {
	return "/api/binary?dn=" + url.QueryEscape(dn) + "&attribute=" + url.QueryEscape(attribute)
}

func binaryBody(dn, attribute string, values []string) map[string]any {
	return map[string]any{"dn": dn, "attribute": attribute, "values_base64": values}
}

func repeatString(value string, count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = value
	}
	return values
}

func binarySearchClient(dn, attribute string, values [][]byte) *fakeClient {
	return &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{{
			DN:         dn,
			Attributes: []*ldap.EntryAttribute{{Name: attribute, ByteValues: values}},
		}}}, nil
	}}
}
