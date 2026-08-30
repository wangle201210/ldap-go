package webadmin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestDataExportJSONUsesBoundSearchAndStableBinaryStructure(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.BaseDN != "dc=example,dc=com" || request.Filter != "(objectClass=person)" ||
			request.Scope != ldap.ScopeSingleLevel || request.SizeLimit != 4 || request.TimeLimit != 3 ||
			!request.EnforceSizeLimit || !reflect.DeepEqual(request.Attributes, []string{"cn", "description", "jpegPhoto"}) {
			t.Fatalf("export search = %#v", request)
		}
		binary := &ldap.EntryAttribute{
			Name: "jpegPhoto", Values: []string{"ignored"}, ByteValues: [][]byte{{0, 1, 2}},
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			{DN: "uid=bob,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
				ldap.NewEntryAttribute("cn", []string{"Bob"}),
			}},
			nil,
			{DN: "uid=alice,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
				ldap.NewEntryAttribute("description", []string{"zeta", "alpha"}),
				binary,
				ldap.NewEntryAttribute("cn", []string{"Alice"}),
			}},
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxExportEntries = 5
	})
	authenticated := loginTestSession(t, application, "dn")
	path := "/api/data-export?format=json&base=" + url.QueryEscape("dc=example,dc=com") +
		"&scope=one&filter=" + url.QueryEscape("(objectClass=person)") +
		"&attributes=cn,description,jpegPhoto&size_limit=4&time_limit_seconds=3"
	response := performDataExportRequest(application, http.MethodGet, path, authenticated.cookie)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json; charset=utf-8" ||
		response.Header().Get("Content-Disposition") != `attachment; filename="directory-export.json"` ||
		response.Header().Get("X-Directory-Entry-Count") != "2" ||
		response.Header().Get("Content-Length") != strconv.Itoa(response.Body.Len()) {
		t.Fatalf("headers = %#v", response.Header())
	}
	var document dataExportDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(document.Entries) != 2 || document.Entries[0].DN != "uid=alice,dc=example,dc=com" {
		t.Fatalf("entries = %#v", document.Entries)
	}
	alice := document.Entries[0]
	if !reflect.DeepEqual(alice.Attributes["description"], []string{"alpha", "zeta"}) ||
		!reflect.DeepEqual(alice.BinaryAttributes["jpegPhoto"], []string{"AAEC"}) {
		t.Fatalf("Alice export = %#v", alice)
	}
	client.mu.Lock()
	boundDN := client.bindDN
	searches := len(client.searches)
	client.mu.Unlock()
	if boundDN != "cn=admin,dc=example,dc=com" || searches != 1 {
		t.Fatalf("bound DN = %q, searches = %d", boundDN, searches)
	}
}

func TestDataExportCSVRFC4180ColumnsAndTypedMultivalues(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{{
			DN: "uid=alice,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				ldap.NewEntryAttribute("sn", []string{"Zulu", "Alpha"}),
				{Name: "jpegPhoto", ByteValues: [][]byte{{0xff, 0x00}}},
				ldap.NewEntryAttribute("description", []string{"line 1, quoted \"text\"\r\nline 2"}),
			},
		}}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performDataExportRequest(application, http.MethodGet,
		"/api/data-export?format=csv&base=dc%3Dexample%2Cdc%3Dcom", authenticated.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		response.Header().Get("Content-Disposition") != `attachment; filename="directory-export.csv"` {
		t.Fatalf("headers = %#v", response.Header())
	}
	if !strings.Contains(response.Body.String(), "\r\n") ||
		strings.Contains(strings.ReplaceAll(response.Body.String(), "\r\n", ""), "\n") {
		t.Fatalf("CSV does not use RFC 4180 CRLF records: %q", response.Body.String())
	}
	reader := csv.NewReader(strings.NewReader(response.Body.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v\n%s", err, response.Body.String())
	}
	wantHeader := []string{"dn", "description", "jpegPhoto", "sn"}
	if len(records) != 2 || !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("records = %#v", records)
	}
	var description, photo, surname dataExportCSVCell
	if err := json.Unmarshal([]byte(records[1][1]), &description); err != nil {
		t.Fatalf("description cell: %v", err)
	}
	if err := json.Unmarshal([]byte(records[1][2]), &photo); err != nil {
		t.Fatalf("photo cell: %v", err)
	}
	if err := json.Unmarshal([]byte(records[1][3]), &surname); err != nil {
		t.Fatalf("surname cell: %v", err)
	}
	if !reflect.DeepEqual(description.Text, []string{"line 1, quoted \"text\"\r\nline 2"}) ||
		!reflect.DeepEqual(photo.BinaryBase64, []string{"/wA="}) ||
		!reflect.DeepEqual(surname.Text, []string{"Alpha", "Zulu"}) {
		t.Fatalf("cells: description=%#v photo=%#v surname=%#v", description, photo, surname)
	}
}

func TestDataExportCSVPreservesRequestedColumnsAndCaseInsensitiveResults(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"uid=alice,dc=example,dc=com", map[string][]string{"CN": {"Alice"}, "mail": {"a@example.com"}, "description;lang-en": {"English"}},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performDataExportRequest(application, http.MethodGet,
		"/api/data-export?format=csv&base=dc%3Dexample%2Cdc%3Dcom&attribute=mail&attribute=name&attribute=uid&attribute=description",
		authenticated.cookie)
	reader := csv.NewReader(response.Body)
	records, err := reader.ReadAll()
	if response.Code != http.StatusOK || err != nil {
		t.Fatalf("status = %d, parse = %v, body = %s", response.Code, err, response.Body.String())
	}
	if !reflect.DeepEqual(records[0], []string{"dn", "mail", "name", "uid", "description", "CN", "description;lang-en"}) ||
		records[1][2] != "" || records[1][3] != "" || records[1][4] != "" || records[1][5] == "" || !strings.Contains(records[1][6], "English") {
		t.Fatalf("records = %#v", records)
	}
}

func TestDataExportRejectsMethodFormatAuthenticationAndInvalidSearch(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxExportEntries = 2
		config.MaxSearchSize = 10
	})
	authenticated := loginTestSession(t, application, "dn")
	tests := []struct {
		name   string
		method string
		path   string
		cookie *http.Cookie
		status int
		code   string
	}{
		{"method", http.MethodPost, "/api/data-export?format=json", authenticated.cookie, http.StatusMethodNotAllowed, "method_not_allowed"},
		{"missing format", http.MethodGet, "/api/data-export", authenticated.cookie, http.StatusBadRequest, "invalid_format"},
		{"invalid format", http.MethodGet, "/api/data-export?format=ldif", authenticated.cookie, http.StatusBadRequest, "invalid_format"},
		{"authentication", http.MethodGet, "/api/data-export?format=json", nil, http.StatusUnauthorized, "authentication_required"},
		{"DN", http.MethodGet, "/api/data-export?format=json&base=bad", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"filter", http.MethodGet, "/api/data-export?format=json&filter=%28bad", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"attribute", http.MethodGet, "/api/data-export?format=json&attribute=bad_attribute", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"size syntax", http.MethodGet, "/api/data-export?format=json&size_limit=zero", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"size bound", http.MethodGet, "/api/data-export?format=json&size_limit=3", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"time bound", http.MethodGet, "/api/data-export?format=json&time_limit_seconds=999", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"paging", http.MethodGet, "/api/data-export?format=json&page_size=1", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
		{"types only", http.MethodGet, "/api/data-export?format=json&types_only=true", authenticated.cookie, http.StatusBadRequest, "invalid_search"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performDataExportRequest(application, test.method, test.path, test.cookie)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
	client.mu.Lock()
	searches := len(client.searches)
	client.mu.Unlock()
	if searches != 0 {
		t.Fatalf("invalid requests performed %d LDAP searches", searches)
	}
}

func TestDataExportEntryAndEncodedByteLimits(t *testing.T) {
	t.Parallel()
	t.Run("entry limit", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if request.SizeLimit != 1 {
				t.Fatalf("default export size limit = %d", request.SizeLimit)
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry("uid=a,dc=example,dc=com", nil),
				ldap.NewEntry("uid=b,dc=example,dc=com", nil),
			}}, nil
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.MaxExportEntries = 1
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performDataExportRequest(application, http.MethodGet,
			"/api/data-export?format=json", authenticated.cookie)
		if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "export_entry_limit") {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if application.responseBytes.Load() != 0 {
			t.Fatalf("LDAP response budget was not released: %d", application.responseBytes.Load())
		}
	})

	t.Run("byte limit", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
				"uid=alice,dc=example,dc=com", map[string][]string{"description": {strings.Repeat("x", 512)}},
			)}}, nil
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.MaxExportBytes = 128
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performDataExportRequest(application, http.MethodGet,
			"/api/data-export?format=csv", authenticated.cookie)
		if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "export_byte_limit") ||
			response.Header().Get("Content-Disposition") != "" {
			t.Fatalf("status = %d, headers = %#v, body = %s", response.Code, response.Header(), response.Body.String())
		}
		if application.responseBytes.Load() != 0 {
			t.Fatalf("LDAP response budget was not released: %d", application.responseBytes.Load())
		}
	})
}

func TestDataExportPropagatesLDAPAndResponseBudgetErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		search    func(*ldap.SearchRequest) (*ldap.SearchResult, error)
		configure func(*Config)
		status    int
		code      string
	}{
		{
			name: "ACL denial",
			search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied")}
			},
			status: http.StatusForbidden, code: "ldap_error",
		},
		{
			name: "transport",
			search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, io.ErrUnexpectedEOF
			},
			status: http.StatusBadGateway, code: "ldap_transport_error",
		},
		{
			name: "nil result",
			search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, nil
			},
			status: http.StatusBadGateway, code: "ldap_transport_error",
		},
		{
			name: "LDAP response budget",
			search: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
					"uid=large,dc=example,dc=com", map[string][]string{"description": {strings.Repeat("x", 4096)}},
				)}}, nil
			},
			configure: func(config *Config) {
				config.MaxLDAPResponseBytes = 1024
				config.MaxProcessResponseBytes = 2048
			},
			status: http.StatusRequestEntityTooLarge, code: "ldap_response_too_large",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: test.search}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, test.configure)
			authenticated := loginTestSession(t, application, "dn")
			response := performDataExportRequest(application, http.MethodGet,
				"/api/data-export?format=json", authenticated.cookie)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if application.responseBytes.Load() != 0 {
				t.Fatalf("response bytes = %d", application.responseBytes.Load())
			}
		})
	}
}

func TestAdvancedReadHandlersRejectUnfollowedReferrals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		call func(*Application, *http.Cookie) *httptest.ResponseRecorder
	}{
		{name: "data export", call: func(application *Application, cookie *http.Cookie) *httptest.ResponseRecorder {
			return performDataExportRequest(application, http.MethodGet, "/api/data-export?format=json&base=dc%3Dexample", cookie)
		}},
		{name: "groups", call: func(application *Application, cookie *http.Cookie) *httptest.ResponseRecorder {
			return performGroupsRequest(t, application, http.MethodGet, "/api/groups?base_dn=dc%3Dexample", nil, cookie, "")
		}},
		{name: "binary", call: func(application *Application, cookie *http.Cookie) *httptest.ResponseRecorder {
			return performBinaryRequest(t, application, http.MethodGet, binaryQuery("uid=a,dc=example", "jpegPhoto"), nil, cookie, "", "https://admin.example")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Referrals: []string{"ldap://elsewhere.example/dc=example"}}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")
			response := test.call(application, authenticated.cookie)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "ldap_referral_unfollowed") {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestDataExportFormatHelpersAndWriterBoundaries(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"csv", " CSV ", "json", "JSON"} {
		if _, ok := parseDataExportFormat(value); !ok {
			t.Errorf("format %q rejected", value)
		}
	}
	for _, value := range []string{"", "ldif", "xml"} {
		if _, ok := parseDataExportFormat(value); ok {
			t.Errorf("format %q accepted", value)
		}
	}
	var destination strings.Builder
	writer := &limitedExportWriter{destination: &destination, maximum: 3}
	if count, err := writer.Write([]byte("abc")); err != nil || count != 3 {
		t.Fatalf("exact write = %d, %v", count, err)
	}
	if count, err := writer.Write([]byte("d")); count != 0 || !errors.Is(err, errDataExportTooLarge) {
		t.Fatalf("overflow write = %d, %v", count, err)
	}
	if destination.String() != "abc" || writer.written != 3 {
		t.Fatalf("destination = %q, written = %d", destination.String(), writer.written)
	}
}

func performDataExportRequest(
	application *Application,
	method string,
	path string,
	cookie *http.Cookie,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://admin.example"+path, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	application.handleDataExport(response, request)
	return response
}
