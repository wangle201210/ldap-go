package webadmin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestBoundedSubtreeLDIFExport(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.Scope != ldap.ScopeWholeSubtree || request.BaseDN != "dc=example,dc=com" ||
			request.SizeLimit != 3 || !request.EnforceSizeLimit {
			t.Fatalf("export search = %#v", request)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("dc=example,dc=com", map[string][]string{
				"objectClass": {"domain"}, "dc": {"example"},
			}),
			ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
				"objectClass": {"person"}, "cn": {"Alice"}, "sn": {"Alice"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxExportEntries = 2
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performJSONRequest(t, application, http.MethodGet,
		"/api/export?base_dn=dc%3Dexample%2Cdc%3Dcom&limit=2", nil, authenticated.cookie, "")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/ldif; charset=utf-8" ||
		response.Header().Get("X-LDIF-Entry-Count") != "2" {
		t.Fatalf("export status = %d, headers = %#v, body = %s", response.Code, response.Header(), response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "dn: dc=example,dc=com") ||
		!strings.Contains(response.Body.String(), "dn: uid=alice,dc=example,dc=com") {
		t.Fatalf("export LDIF = %s", response.Body.String())
	}
}

func TestLDIFExportHonorsRequestedScope(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.Scope != ldap.ScopeSingleLevel {
			t.Fatalf("export scope = %d, want one-level", request.Scope)
		}
		return &ldap.SearchResult{}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	request := httptest.NewRequest(
		http.MethodGet,
		"https://admin.example/api/export?base_dn=dc%3Dexample%2Cdc%3Dcom&scope=one",
		nil,
	)
	request.TLS = &tls.ConnectionState{}
	request.AddCookie(authenticated.cookie)
	response := httptest.NewRecorder()
	application.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestLDIFChangeImportIsValidatedThenAppliedOverSession(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	data := `dn: uid=alice,dc=example,dc=com
changetype: add
objectClass: person
cn: Alice
sn: Alice

dn: uid=alice,dc=example,dc=com
changetype: modify
replace: description
description: updated
-

dn: uid=alice,dc=example,dc=com
changetype: delete

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusOK {
		t.Fatalf("import status = %d, body = %s", response.Code, response.Body.String())
	}
	var result map[string]int
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result["applied"] != 3 {
		t.Fatalf("import response = %#v, error = %v", result, err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.adds) != 1 || len(client.modifies) != 1 || len(client.deletes) != 1 {
		t.Fatalf("import calls: adds=%d modifies=%d deletes=%d", len(client.adds), len(client.modifies), len(client.deletes))
	}
}

func TestLDIFImportReportsPartialApplyAndRejectsOverLimitBeforeApply(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.modifyFunc = func(*ldap.ModifyRequest) error {
		return &ldap.Error{ResultCode: ldap.LDAPResultConstraintViolation, Err: errors.New("constraint")}
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxImportChanges = 3
	})
	authenticated := loginTestSession(t, application, "dn")
	data := `dn: uid=alice,dc=example,dc=com
changetype: add
objectClass: person
cn: Alice
sn: Alice

dn: uid=alice,dc=example,dc=com
changetype: modify
replace: description
description: updated
-

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("partial import status = %d, body = %s", response.Code, response.Body.String())
	}
	var failure apiErrorBody
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || failure.Error.Applied == nil || *failure.Error.Applied != 1 {
		t.Fatalf("partial error = %#v, decode = %v", failure, err)
	}

	limitedClient := &fakeClient{}
	limitedApplication, _ := newTestApplication(t, &fakeConnector{clients: []Client{limitedClient}}, func(config *Config) {
		config.MaxImportChanges = 1
	})
	limitedSession := loginTestSession(t, limitedApplication, "dn")
	rejected := performLDIFRequest(limitedApplication, limitedSession, data)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("over-limit import status = %d, body = %s", rejected.Code, rejected.Body.String())
	}
	limitedClient.mu.Lock()
	addCount := len(limitedClient.adds)
	limitedClient.mu.Unlock()
	if addCount != 0 {
		t.Fatalf("over-limit import applied %d records", addCount)
	}
}

func TestLDIFImportHonorsRequestBodyLimit(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.RequestBodyLimit = 96
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performLDIFRequest(application, authenticated,
		"dn: uid=alice,dc=example,dc=com\nchangetype: add\ndescription: "+strings.Repeat("x", 200)+"\n\n")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large LDIF status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestWebLDIFImportRejectsExternalValuesBeforeParsing(t *testing.T) {
	t.Parallel()

	application, err := New(Config{LDAPURL: "ldap://127.0.0.1:389"})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()
	for _, test := range []struct {
		name string
		ldif string
		want string
	}{
		{
			name: "attribute URL",
			ldif: "dn: uid=alice,dc=example,dc=com\nobjectClass: person\ncn: Alice\nsn:< file:///etc/passwd\n",
			want: "URL values",
		},
		{
			name: "control URL",
			ldif: "dn: uid=alice,dc=example,dc=com\ncontrol: 1.2.3 true:< file:///etc/passwd\nchangetype: delete\n",
			want: "controls",
		},
		{
			name: "folded attribute URL",
			ldif: "dn: uid=alice,dc=example,dc=com\nchangetype: modify\nreplace: description\ndescription:\n < file:///etc/passwd\n-\n",
			want: "URL values",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := application.parseLDIFChanges([]byte(test.ldif))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseLDIFChanges() = %v, want %q", err, test.want)
			}
		})
	}
}

func performLDIFRequest(
	application *Application,
	authenticated authenticatedSession,
	data string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://admin.example/api/import", bytes.NewBufferString(data))
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Origin", "https://admin.example")
	request.Header.Set("Content-Type", "application/ldif")
	request.Header.Set("X-CSRF-Token", authenticated.csrf)
	request.AddCookie(authenticated.cookie)
	recorder := httptest.NewRecorder()
	application.Handler().ServeHTTP(recorder, request)
	return recorder
}
