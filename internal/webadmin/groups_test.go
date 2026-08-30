package webadmin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestHandleGroupsListsSupportedGroupKinds(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.BaseDN != "ou=groups,dc=example,dc=com" || request.Scope != ldap.ScopeWholeSubtree ||
			request.Filter != groupObjectFilter || request.SizeLimit != 7 || !request.EnforceSizeLimit ||
			request.TimeLimit != 15 || strings.Join(request.Attributes, ",") != strings.Join(groupSearchAttributes, ",") {
			t.Fatalf("group search request = %#v", request)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("cn=staff,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"top", "groupOfNames"},
				"member":      {"uid=Alice,ou=people,dc=example,dc=com"},
			}),
			ldap.NewEntry("cn=owners,ou=groups,dc=example,dc=com", map[string][]string{
				"OBJECTCLASS":  {"groupOfUniqueNames"},
				"UNIQUEMEMBER": {"uid=bob,ou=people,dc=example,dc=com#'101'B"},
			}),
			ldap.NewEntry("cn=ops,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"alice", "Bob"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxSearchSize = 7
	})
	authenticated := loginTestSession(t, application, "dn")

	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn="+url.QueryEscape("ou=groups,dc=example,dc=com"),
		nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET groups status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode groups response: %v", err)
	}
	if len(body.Groups) != 3 || body.Groups[0].Type != "groupOfNames" ||
		len(body.Groups[0].Member) != 1 || body.Groups[0].Member[0] != "uid=Alice,ou=people,dc=example,dc=com" ||
		body.Groups[1].Type != "groupOfUniqueNames" || body.Groups[1].UniqueMember[0] != "uid=bob,ou=people,dc=example,dc=com#'101'B" ||
		body.Groups[2].Type != "posixGroup" || strings.Join(body.Groups[2].MemberUID, ",") != "alice,Bob" {
		t.Fatalf("groups response = %#v", body)
	}
}

func TestHandleGroupsExpandsNestedMembersWithCyclesAndDeduplication(t *testing.T) {
	t.Parallel()
	rootDN := "cn=Root,ou=groups,dc=example,dc=com"
	childDN := "cn=Child,ou=groups,dc=example,dc=com"
	sharedDN := "cn=Shared,ou=groups,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry(rootDN, map[string][]string{
				"objectClass": {"groupOfNames", "posixGroup"},
				"member": {
					childDN,
					sharedDN,
					"UID=Alice,ou=people,dc=example,dc=com",
					"uid=alice,ou=people,dc=example,dc=com",
				},
				"memberUid": {"LocalUser", "localuser", "LocalUser"},
			}),
			ldap.NewEntry(childDN, map[string][]string{
				"objectClass": {"groupOfUniqueNames"},
				"uniqueMember": {
					rootDN,
					sharedDN + "#'01'B",
					"uid=Bob,ou=people,dc=example,dc=com#'101'B",
					"uid=Bob,ou=people,dc=example,dc=com#'111'B",
				},
			}),
			ldap.NewEntry(sharedDN, map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"service"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	path := "/api/groups?base_dn=" + url.QueryEscape("ou=groups,dc=example,dc=com") +
		"&dn=" + url.QueryEscape(strings.ToLower(rootDN)) + "&nested=true"

	response := performGroupsRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("nested GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode nested response: %v", err)
	}
	if len(body.Groups) != 1 || body.Nested == nil {
		t.Fatalf("nested response = %#v", body)
	}
	nested := body.Nested
	if nested.RootDN != rootDN || strings.Join(nested.Groups, "|") != strings.Join([]string{rootDN, childDN, sharedDN}, "|") {
		t.Fatalf("nested groups = %#v", nested)
	}
	if len(nested.Member) != 1 || nested.Member[0] != "UID=Alice,ou=people,dc=example,dc=com" {
		t.Fatalf("nested member values = %#v", nested.Member)
	}
	if strings.Join(nested.UniqueMember, "|") != strings.Join([]string{
		"uid=Bob,ou=people,dc=example,dc=com#'101'B",
		"uid=Bob,ou=people,dc=example,dc=com#'111'B",
	}, "|") {
		t.Fatalf("nested uniqueMember values = %#v", nested.UniqueMember)
	}
	if strings.Join(nested.MemberUID, ",") != "service,LocalUser,localuser" {
		t.Fatalf("nested memberUid values = %#v", nested.MemberUID)
	}
	if len(nested.Cycles) != 1 || nested.Cycles[0] != rootDN {
		t.Fatalf("nested cycles = %#v", nested.Cycles)
	}
}

func TestHandleGroupsPatchUsesOneAtomicLDAPModify(t *testing.T) {
	t.Parallel()
	groupDN := "cn=staff,ou=groups,dc=example,dc=com"
	client := &fakeClient{
		searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if request.BaseDN != groupDN || request.Scope != ldap.ScopeBaseObject || request.SizeLimit != 1 ||
				request.Filter != groupObjectFilter || !request.EnforceSizeLimit {
				t.Fatalf("group lookup = %#v", request)
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(groupDN, map[string][]string{
				"objectClass": {"groupOfNames"},
			})}}, nil
		},
		modifyFunc: func(request *ldap.ModifyRequest) error {
			if request.DN != groupDN || len(request.Changes) != 3 {
				t.Fatalf("modify request = %#v", request)
			}
			assertLDAPChange(t, request.Changes[0], ldap.AddAttribute, "member", []string{"uid=alice,dc=example,dc=com"})
			assertLDAPChange(t, request.Changes[1], ldap.DeleteAttribute, "uniqueMember", []string{
				"uid=old,dc=example,dc=com#'1'B", "uid=old,dc=example,dc=com#'0'B",
			})
			assertLDAPChange(t, request.Changes[2], ldap.AddAttribute, "memberUid", []string{"local-user"})
			return nil
		},
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodPatch, "/api/groups", map[string]any{
		"dn": groupDN,
		"changes": []map[string]any{
			{"operation": "ADD", "attribute": "MEMBER", "values": []string{"uid=alice,dc=example,dc=com"}},
			{"operation": "remove", "attribute": "uniqueMember", "values": []string{
				"uid=old,dc=example,dc=com#'1'B", "uid=old,dc=example,dc=com#'0'B",
			}},
			{"operation": "add", "attribute": "memberUid", "values": []string{"local-user"}},
		},
	}, authenticated.cookie, authenticated.csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH groups status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupPatchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if body.DN != groupDN || !body.Atomic || len(body.Results) != 3 {
		t.Fatalf("patch response = %#v", body)
	}
	for _, result := range body.Results {
		if result.Status != "applied" {
			t.Fatalf("patch result = %#v", result)
		}
	}
	client.mu.Lock()
	modifyCount := len(client.modifies)
	client.mu.Unlock()
	if modifyCount != 1 {
		t.Fatalf("LDAP modify count = %d", modifyCount)
	}
}

func TestHandleGroupsSecurityAndValidationErrorsAvoidModify(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxAttributes = 2
	})
	authenticated := loginTestSession(t, application, "dn")

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		cookie *http.Cookie
		csrf   string
		origin string
		status int
	}{
		{name: "unauthenticated", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom", status: http.StatusUnauthorized},
		{name: "method", method: http.MethodPost, path: "/api/groups", cookie: authenticated.cookie, status: http.StatusMethodNotAllowed},
		{name: "unknown query", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&limit=1", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "duplicate query", method: http.MethodGet, path: "/api/groups?base_dn=a&base_dn=b", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "nested without dn", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&nested=true", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "dn outside base", method: http.MethodGet, path: "/api/groups?base_dn=ou%3Dgroups%2Cdc%3Dexample%2Cdc%3Dcom&dn=cn%3Dx%2Cou%3Dother%2Cdc%3Dexample%2Cdc%3Dcom", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "missing csrf", method: http.MethodPatch, path: "/api/groups", body: validGroupPatchBody(), cookie: authenticated.cookie, status: http.StatusForbidden},
		{name: "bad origin", method: http.MethodPatch, path: "/api/groups", body: validGroupPatchBody(), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://evil.example", status: http.StatusForbidden},
		{name: "unknown JSON", method: http.MethodPatch, path: "/api/groups", body: map[string]any{"dn": "cn=staff,dc=example,dc=com", "changes": []any{}, "extra": true}, cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "too many changes", method: http.MethodPatch, path: "/api/groups", body: map[string]any{"dn": "cn=staff,dc=example,dc=com", "changes": []map[string]any{{"operation": "add", "attribute": "memberUid", "values": []string{"a"}}, {"operation": "add", "attribute": "memberUid", "values": []string{"b"}}, {"operation": "add", "attribute": "memberUid", "values": []string{"c"}}}}, cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid operation", method: http.MethodPatch, path: "/api/groups", body: patchBody("replace", "memberUid", "alice"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid attribute", method: http.MethodPatch, path: "/api/groups", body: patchBody("add", "owner", "uid=alice,dc=example,dc=com"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid member DN", method: http.MethodPatch, path: "/api/groups", body: patchBody("add", "member", "not-a-dn"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid uid", method: http.MethodPatch, path: "/api/groups", body: patchBody("add", "memberUid", "bad\nuid"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{
			name: "duplicate value", method: http.MethodPatch, path: "/api/groups",
			body: map[string]any{
				"dn": "cn=staff,dc=example,dc=com",
				"changes": []map[string]any{{
					"operation": "add", "attribute": "member",
					"values": []string{"UID=Alice,dc=example,dc=com", "uid=alice,DC=example,dc=com"},
				}},
			},
			cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performGroupsRequestWithOrigin(t, application, test.method, test.path, test.body, test.cookie, test.csrf, test.origin)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
	client.mu.Lock()
	modifyCount := len(client.modifies)
	client.mu.Unlock()
	if modifyCount != 0 {
		t.Fatalf("invalid requests sent %d LDAP modifies", modifyCount)
	}
}

func TestHandleGroupsLDAPAndResourceErrors(t *testing.T) {
	t.Parallel()
	t.Run("search LDAP error", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied")}
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performGroupsRequest(t, application, http.MethodGet,
			"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom", nil, authenticated.cookie, "")
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("response budget", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
				"cn=large,dc=example,dc=com", map[string][]string{
					"objectClass": {"groupOfNames"}, "member": {"uid=" + strings.Repeat("x", 2048) + ",dc=example,dc=com"},
				},
			)}}, nil
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.MaxLDAPResponseBytes = 1024
			config.MaxProcessResponseBytes = 2048
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performGroupsRequest(t, application, http.MethodGet,
			"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom", nil, authenticated.cookie, "")
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("modify LDAP error is atomic failure", func(t *testing.T) {
		client := &fakeClient{
			searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
					"cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}},
				)}}, nil
			},
			modifyFunc: func(*ldap.ModifyRequest) error {
				return &ldap.Error{ResultCode: ldap.LDAPResultConstraintViolation, Err: errors.New("constraint")}
			},
		}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performGroupsRequest(t, application, http.MethodPatch, "/api/groups",
			validGroupPatchBody(), authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusUnprocessableEntity || strings.Contains(response.Body.String(), "applied") {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})
}

func TestHandleGroupsRejectsInvalidLDAPGroupResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		entries    []*ldap.Entry
		resultNil  bool
		selectedDN string
		limit      int
		status     int
		code       string
	}{
		{name: "nil result", resultNil: true, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "nil entry", entries: []*ldap.Entry{nil}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "invalid entry DN", entries: []*ldap.Entry{ldap.NewEntry("not-a-dn", map[string][]string{"objectClass": {"groupOfNames"}})}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "non-group entry", entries: []*ldap.Entry{ldap.NewEntry("cn=user,dc=example,dc=com", map[string][]string{"objectClass": {"person"}})}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "duplicate group DN", entries: []*ldap.Entry{
			ldap.NewEntry("cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
			ldap.NewEntry("CN=STAFF,DC=EXAMPLE,DC=COM", map[string][]string{"objectClass": {"groupOfNames"}}),
		}, limit: 3, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "result entry limit", entries: []*ldap.Entry{
			ldap.NewEntry("cn=one,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
			ldap.NewEntry("cn=two,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
		}, limit: 1, status: http.StatusRequestEntityTooLarge, code: "group_limit_exceeded"},
		{name: "selected group missing", entries: []*ldap.Entry{}, selectedDN: "cn=missing,dc=example,dc=com", status: http.StatusNotFound, code: "group_not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				if test.resultNil {
					return nil, nil
				}
				return &ldap.SearchResult{Entries: test.entries}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
				if test.limit != 0 {
					config.MaxSearchSize = test.limit
				}
			})
			authenticated := loginTestSession(t, application, "dn")
			path := "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom"
			if test.selectedDN != "" {
				path += "&dn=" + url.QueryEscape(test.selectedDN)
			}
			response := performGroupsRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandleGroupsPatchLookupAndRequestErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		path        string
		contentType string
		entries     []*ldap.Entry
		searchErr   error
		status      int
		code        string
	}{
		{name: "query rejected", path: "/api/groups?dn=cn%3Dstaff", status: http.StatusBadRequest, code: "invalid_groups_query"},
		{name: "content type required", contentType: "text/plain", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "group missing", entries: []*ldap.Entry{}, status: http.StatusNotFound, code: "group_not_found"},
		{name: "nil lookup result", status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "nil lookup entry", entries: []*ldap.Entry{nil}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "multiple lookup entries", entries: []*ldap.Entry{
			ldap.NewEntry("cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
			ldap.NewEntry("cn=other,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
		}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "lookup entry is not group", entries: []*ldap.Entry{ldap.NewEntry(
			"cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"person"}},
		)}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "lookup ACL error", searchErr: &ldap.Error{
			ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied"),
		}, status: http.StatusForbidden, code: "ldap_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				if test.searchErr != nil {
					return nil, test.searchErr
				}
				if test.entries == nil {
					return nil, nil
				}
				return &ldap.SearchResult{Entries: test.entries}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")
			path := test.path
			if path == "" {
				path = "/api/groups"
			}
			response := performGroupsRequestWithContentType(
				t, application, path, validGroupPatchBody(), authenticated, test.contentType,
			)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			client.mu.Lock()
			modifyCount := len(client.modifies)
			client.mu.Unlock()
			if modifyCount != 0 {
				t.Fatalf("invalid PATCH sent %d LDAP modifies", modifyCount)
			}
		})
	}
}

func TestNestedGroupLimitAndMalformedLDAPMembership(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []*ldap.Entry
		limit   int
		code    string
	}{
		{
			name: "member limit",
			entries: []*ldap.Entry{ldap.NewEntry("cn=root,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"},
				"member":      {"uid=a,dc=example,dc=com", "uid=b,dc=example,dc=com"},
			})},
			limit: 1, code: "nested_group_limit_exceeded",
		},
		{
			name: "invalid LDAP member",
			entries: []*ldap.Entry{ldap.NewEntry("cn=root,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {"not-a-dn"},
			})},
			limit: 2, code: "invalid_ldap_response",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: test.entries}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
				config.MaxSearchSize = test.limit
			})
			authenticated := loginTestSession(t, application, "dn")
			response := performGroupsRequest(t, application, http.MethodGet,
				"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&dn=cn%3Droot%2Cdc%3Dexample%2Cdc%3Dcom&nested=true",
				nil, authenticated.cookie, "")
			expectedStatus := http.StatusRequestEntityTooLarge
			if test.code == "invalid_ldap_response" {
				expectedStatus = http.StatusBadGateway
			}
			if response.Code != expectedStatus || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func validGroupPatchBody() map[string]any {
	return patchBody("add", "memberUid", "alice")
}

func patchBody(operation, attribute, value string) map[string]any {
	return map[string]any{
		"dn": "cn=staff,dc=example,dc=com",
		"changes": []map[string]any{{
			"operation": operation, "attribute": attribute, "values": []string{value},
		}},
	}
}

func assertLDAPChange(t *testing.T, change ldap.Change, operation uint, attribute string, values []string) {
	t.Helper()
	if change.Operation != operation || change.Modification.Type != attribute ||
		strings.Join(change.Modification.Vals, "\x00") != strings.Join(values, "\x00") {
		t.Fatalf("LDAP change = %#v, want operation=%d attribute=%q values=%q", change, operation, attribute, values)
	}
}

func performGroupsRequest(
	t *testing.T,
	application *Application,
	method, path string,
	body any,
	cookie *http.Cookie,
	csrf string,
) *httptest.ResponseRecorder {
	t.Helper()
	return performGroupsRequestWithOrigin(t, application, method, path, body, cookie, csrf, "https://admin.example")
}

func performGroupsRequestWithOrigin(
	t *testing.T,
	application *Application,
	method, path string,
	body any,
	cookie *http.Cookie,
	csrf, origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	if origin == "" {
		origin = "https://admin.example"
	}
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	request := httptest.NewRequest(method, "https://admin.example"+path, &encoded)
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:12345"
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
	application.handleGroups(response, request)
	return response
}

func performGroupsRequestWithContentType(
	t *testing.T,
	application *Application,
	path string,
	body any,
	authenticated authenticatedSession,
	contentType string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(body); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPatch, "https://admin.example"+path, &encoded)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Origin", "https://admin.example")
	request.Header.Set("X-CSRF-Token", authenticated.csrf)
	if contentType == "" {
		contentType = "application/json"
	}
	request.Header.Set("Content-Type", contentType)
	request.AddCookie(authenticated.cookie)
	response := httptest.NewRecorder()
	application.handleGroups(response, request)
	return response
}
