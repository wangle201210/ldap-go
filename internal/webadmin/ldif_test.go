package webadmin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestLDIFExportRejectsUnfollowedReferrals(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{
			Entries: []*ldap.Entry{
				ldap.NewEntry("dc=example,dc=com", map[string][]string{"objectClass": {"domain"}}),
			},
			Referrals: []string{"ldap://elsewhere.example/dc=example,dc=com"},
		}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performJSONRequest(t, application, http.MethodGet,
		"/api/export?base_dn=dc%3Dexample%2Cdc%3Dcom", nil, authenticated.cookie, "")
	if response.Code != http.StatusBadGateway ||
		!strings.Contains(response.Body.String(), `"code":"ldap_referral_unfollowed"`) ||
		response.Header().Get("X-LDIF-Entry-Count") != "" ||
		strings.Contains(response.Body.String(), "dn: dc=example,dc=com") {
		t.Fatalf("export status = %d, headers = %#v, body = %s",
			response.Code, response.Header(), response.Body.String())
	}
}

func TestLDIFChangeImportIsValidatedThenAppliedOverSession(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	data := `version: 1
dn: uid=alice,dc=example,dc=com
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
changetype: modrdn
newrdn: uid=alicia
deleteoldrdn: 1
newsuperior: ou=archive,dc=example,dc=com

dn: uid=alicia,ou=archive,dc=example,dc=com
changetype: delete

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusOK {
		t.Fatalf("import status = %d, body = %s", response.Code, response.Body.String())
	}
	var result ldifImportResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Applied != 4 ||
		result.Failed != 0 || result.Unknown != 0 || result.Aborted || result.AbortReason != "" ||
		result.Error != nil || len(result.Results) != 4 {
		t.Fatalf("import response = %#v, error = %v", result, err)
	}
	for index, operation := range []string{"add", "modify", "moddn", "delete"} {
		item := result.Results[index]
		if item.Record != index+1 || item.Operation != operation || !item.Success || item.Status != "applied" || item.Error != nil {
			t.Fatalf("result[%d] = %#v", index, item)
		}
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"aborted":false`)) ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"abort_reason":""`)) {
		t.Fatalf("response omits explicit batch fields: %s", response.Body.String())
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.adds) != 1 || len(client.modifies) != 1 || len(client.renames) != 1 || len(client.deletes) != 1 {
		t.Fatalf("import calls: adds=%d modifies=%d renames=%d deletes=%d",
			len(client.adds), len(client.modifies), len(client.renames), len(client.deletes))
	}
	rename := client.renames[0]
	if rename.DN != "uid=alice,dc=example,dc=com" || rename.NewRDN != "uid=alicia" ||
		!rename.DeleteOldRDN || rename.NewSuperior != "ou=archive,dc=example,dc=com" {
		t.Fatalf("ModifyDN request = %#v", rename)
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

dn: uid=alice,dc=example,dc=com
changetype: delete

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("partial import status = %d, body = %s", response.Code, response.Body.String())
	}
	var result ldifImportResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Applied != 1 ||
		result.Failed != 1 || result.Unknown != 0 || !result.Aborted ||
		result.AbortReason != "LDAP operation failed at record 2; remaining LDIF records were not attempted" ||
		len(result.Results) != 3 ||
		result.Error == nil || result.Error.Applied == nil || *result.Error.Applied != 1 {
		t.Fatalf("partial result = %#v, decode = %v", result, err)
	}
	if result.Results[0].Status != "applied" || !result.Results[0].Success ||
		result.Results[1].Status != "failed" || result.Results[1].Error == nil ||
		result.Results[1].Error.LDAPResultCode == nil ||
		*result.Results[1].Error.LDAPResultCode != ldap.LDAPResultConstraintViolation ||
		result.Results[2].Status != "not_attempted" || result.Results[2].Error != nil {
		t.Fatalf("partial results = %#v", result.Results)
	}
	client.mu.Lock()
	deleteCount := len(client.deletes)
	client.mu.Unlock()
	if deleteCount != 0 {
		t.Fatalf("partial import issued %d delete calls", deleteCount)
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

func TestLDIFModifyDNValidationPrecedesAllWrites(t *testing.T) {
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
changetype: moddn
newrdn: uid=alicia
deleteoldrdn: maybe

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "deleteoldrdn must be 0 or 1") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	client.mu.Lock()
	addCount, renameCount := len(client.adds), len(client.renames)
	client.mu.Unlock()
	if addCount != 0 || renameCount != 0 {
		t.Fatalf("invalid ModifyDN reached LDAP: adds=%d renames=%d", addCount, renameCount)
	}
}

func TestLDIFModifyDNUsesCaseInsensitiveKeywordsAndDecodesValues(t *testing.T) {
	t.Parallel()
	application, err := New(Config{LDAPURL: "ldap://127.0.0.1:389"})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()
	records, err := application.parseLDIFChanges([]byte(`DN:: dWlkPWFsaWNlLGRjPWV4YW1wbGUsZGM9Y29t
CHANGETYPE: MoDrDn
NEWRDN:: dWlkPWFsaWNpYQ==
DELETEOLDRDN: 0
NEWSUPERIOR:: b3U9YXJjaGl2ZSxkYz1leGFtcGxlLGRj
 PWNvbQ==

`))
	if err != nil || len(records) != 1 || records[0].modifyDN == nil {
		t.Fatalf("parseLDIFChanges() = %#v, %v", records, err)
	}
	rename := records[0].modifyDN
	if rename.DN != "uid=alice,dc=example,dc=com" || rename.NewRDN != "uid=alicia" ||
		rename.DeleteOldRDN || rename.NewSuperior != "ou=archive,dc=example,dc=com" {
		t.Fatalf("ModifyDN request = %#v", rename)
	}

	modDNRecords, err := application.parseLDIFChanges([]byte(`Dn: uid=alice,dc=example,dc=com
ChangeType: MoDdN
NewRDN: uid=alicia
DeleteOldRDN: 1

`))
	if err != nil || len(modDNRecords) != 1 || modDNRecords[0].modifyDN == nil ||
		!modDNRecords[0].modifyDN.DeleteOldRDN || modDNRecords[0].modifyDN.NewSuperior != "" {
		t.Fatalf("mixed-case moddn parse = %#v, %v", modDNRecords, err)
	}
}

func TestLDIFModifyDNRejectsInvalidFieldFormsAndOrder(t *testing.T) {
	t.Parallel()
	application, err := New(Config{LDAPURL: "ldap://127.0.0.1:389"})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "base64 changetype",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype:: bW9kZG4=\nnewrdn: uid=alicia\ndeleteoldrdn: 1\n\n",
			want: "changetype must use plain string form",
		},
		{
			name: "URL changetype",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype:< file:///tmp/changetype\nnewrdn: uid=alicia\ndeleteoldrdn: 1\n\n",
			want: "URL values",
		},
		{
			name: "base64 deleteoldrdn",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: moddn\nnewrdn: uid=alicia\ndeleteoldrdn:: MQ==\n\n",
			want: "deleteoldrdn must use plain string form",
		},
		{
			name: "URL deleteoldrdn",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: moddn\nnewrdn: uid=alicia\ndeleteoldrdn:< file:///tmp/deleteoldrdn\n\n",
			want: "URL values",
		},
		{
			name: "out of order",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: moddn\nnewrdn: uid=alicia\nnewsuperior: ou=archive,dc=example,dc=com\ndeleteoldrdn: 1\n\n",
			want: `field "deleteoldrdn" must appear here`,
		},
		{
			name: "duplicate field",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: moddn\nnewrdn: uid=alicia\nnewrdn: uid=alicia2\ndeleteoldrdn: 1\n\n",
			want: `field "deleteoldrdn" must appear here`,
		},
		{
			name: "extra field",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: moddn\nnewrdn: uid=alicia\ndeleteoldrdn: 1\nnewsuperior: ou=archive,dc=example,dc=com\ndescription: unsupported\n\n",
			want: "unexpected ModifyDN field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := application.parseLDIFChanges([]byte(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseLDIFChanges() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLDIFStandardChangesUseCaseInsensitiveKeywords(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	data := `VERSION: 1
DN: uid=alice,dc=example,dc=com
CHANGETYPE: ADD
OBJECTCLASS: person
CN: Alice
SN: Alice

Dn: uid=alice,dc=example,dc=com
ChangeType: MoDiFy
REPLACE: Description
DESCRIPTION: Updated
-

dN: uid=alice,dc=example,dc=com
cHaNgEtYpE: DeLeTe

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusOK {
		t.Fatalf("import status = %d, body = %s", response.Code, response.Body.String())
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.adds) != 1 || len(client.modifies) != 1 || len(client.deletes) != 1 {
		t.Fatalf("calls: adds=%d modifies=%d deletes=%d",
			len(client.adds), len(client.modifies), len(client.deletes))
	}
	if client.adds[0].DN != "uid=alice,dc=example,dc=com" ||
		client.modifies[0].DN != "uid=alice,dc=example,dc=com" ||
		client.deletes[0].DN != "uid=alice,dc=example,dc=com" ||
		len(client.modifies[0].Changes) != 1 ||
		client.modifies[0].Changes[0].Modification.Type != "description" ||
		len(client.modifies[0].Changes[0].Modification.Vals) != 1 ||
		client.modifies[0].Changes[0].Modification.Vals[0] != "Updated" {
		t.Fatalf("requests: add=%#v modify=%#v delete=%#v",
			client.adds[0], client.modifies[0], client.deletes[0])
	}
}

func TestLDIFStandardRecordsRejectInvalidStructureAndEncoding(t *testing.T) {
	t.Parallel()
	application, err := New(Config{LDAPURL: "ldap://127.0.0.1:389"})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "delete extra attribute",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: delete\ncn: stray\n\n",
			want: `unexpected field "cn" after changetype delete`,
		},
		{
			name: "base64 changetype",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype:: YWRk\nobjectClass: person\ncn: Alice\nsn: Alice\n\n",
			want: "changetype must use plain string form",
		},
		{
			name: "add without attributes",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: add\n\n",
			want: "changetype add requires at least one attribute",
		},
		{
			name: "modify extra field",
			body: "dn: uid=alice,dc=example,dc=com\nchangetype: modify\nreplace: description\ndescription: updated\n-\ncn: stray\n\n",
			want: "invalid operation cn in modify record",
		},
		{
			name: "field before dn",
			body: "version: 1\ncn: stray\ndn: uid=alice,dc=example,dc=com\nchangetype: delete\n\n",
			want: `record must begin with dn, got "cn"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := application.parseLDIFChanges([]byte(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseLDIFChanges() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLDIFMalformedLaterRecordPreventsAllWrites(t *testing.T) {
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
changetype: delete
cn: stray

`
	response := performLDIFRequest(application, authenticated, data)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), `unexpected field \"cn\" after changetype delete`) {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.adds) != 0 || len(client.deletes) != 0 {
		t.Fatalf("malformed LDIF reached LDAP: adds=%d deletes=%d", len(client.adds), len(client.deletes))
	}
}

func TestLDIFParsingAppliesEarlyChangeAndStructureLimits(t *testing.T) {
	t.Parallel()
	application, err := New(Config{
		LDAPURL:          "ldap://127.0.0.1:389",
		MaxImportChanges: 2,
		MaxAttributes:    1,
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()

	var manyRecords strings.Builder
	for index := 0; index < 10_000; index++ {
		fmt.Fprintf(&manyRecords, "dn: uid=user%d,dc=example,dc=com\nchangetype: delete\n\n", index)
	}
	if _, err := application.parseLDIFChanges([]byte(manyRecords.String())); err == nil ||
		!strings.Contains(err.Error(), "limit of 2 changes") {
		t.Fatalf("change limit error = %v", err)
	}

	var excessiveLines strings.Builder
	excessiveLines.WriteString("dn: uid=alice,dc=example,dc=com\nchangetype: add\n")
	for index := 0; index < maximumValuesPerAttribute+32; index++ {
		excessiveLines.WriteString("description:\n")
	}
	excessiveLines.WriteByte('\n')
	if _, err := application.parseLDIFChanges([]byte(excessiveLines.String())); err == nil ||
		!strings.Contains(err.Error(), "structural limit") {
		t.Fatalf("structure limit error = %v", err)
	}

	comments := strings.Repeat("# comment-only record\n\n", 100) +
		"dn: uid=alice,dc=example,dc=com\nchangetype: delete\n\n"
	if records, err := application.parseLDIFChanges([]byte(comments)); err != nil || len(records) != 1 {
		t.Fatalf("comment records = %#v, error = %v", records, err)
	}
	if limit := maximumLDIFRecordLogicalLines(int(^uint(0)>>1), 100); limit != 100 {
		t.Fatalf("large configured attribute limit produced structural limit %d, want 100", limit)
	}
}

func TestLDIFImportStopsAfterUnknownNetworkResult(t *testing.T) {
	t.Parallel()
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		return ldap.NewError(ldap.ErrorNetwork, errors.New("response lost with private details"))
	}}
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
	var result ldifImportResponse
	if response.Code != http.StatusBadGateway || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Applied != 1 || result.Failed != 0 || result.Unknown != 1 || !result.Aborted ||
		result.AbortReason == "" || len(result.Results) != 3 || result.Error == nil ||
		result.Error.Code != "ldap_result_unknown" || result.Error.Applied == nil || *result.Error.Applied != 1 {
		t.Fatalf("status = %d, result = %#v, body = %s", response.Code, result, response.Body.String())
	}
	if result.Results[0].Status != "applied" || result.Results[1].Status != "unknown" ||
		result.Results[1].Error == nil || strings.Contains(result.Results[1].Error.Message, "private") ||
		result.Results[2].Status != "not_attempted" {
		t.Fatalf("results = %#v", result.Results)
	}
	client.mu.Lock()
	modifyCount, deleteCount := len(client.modifies), len(client.deletes)
	client.mu.Unlock()
	if modifyCount != 1 || deleteCount != 0 {
		t.Fatalf("LDAP calls after unknown: modifies=%d deletes=%d", modifyCount, deleteCount)
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("unknown-result session status = %d, body = %s", probe.Code, probe.Body.String())
	}
}

func TestLDIFImportDeadlineBeforeFirstWriteMarksAllNotAttempted(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = time.Nanosecond
	})
	authenticated := loginTestSession(t, application, "dn")
	data := `dn: uid=first,dc=example,dc=com
changetype: delete

dn: uid=second,dc=example,dc=com
changetype: delete

`
	response := performLDIFRequest(application, authenticated, data)
	var result ldifImportResponse
	if response.Code != http.StatusGatewayTimeout || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Applied != 0 || result.Failed != 0 || result.Unknown != 0 || !result.Aborted ||
		result.AbortReason != "batch operation deadline exceeded" || len(result.Results) != 2 ||
		result.Results[0].Status != "not_attempted" || result.Results[1].Status != "not_attempted" ||
		result.Error == nil || result.Error.Code != "import_deadline_exceeded" {
		t.Fatalf("status = %d, result = %#v, body = %s", response.Code, result, response.Body.String())
	}
	client.mu.Lock()
	deleteCount := len(client.deletes)
	client.mu.Unlock()
	if deleteCount != 0 {
		t.Fatalf("deadline import issued %d delete calls", deleteCount)
	}
}

func TestLDIFImportRequestCancellationMarksInFlightUnknown(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	client := &fakeClient{addFunc: func(*ldap.AddRequest) error {
		close(started)
		<-release
		return nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = time.Second
	})
	authenticated := loginTestSession(t, application, "dn")
	ctx, cancel := context.WithCancel(context.Background())
	responseChannel := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responseChannel <- performLDIFRequestWithContext(application, authenticated, twoAddLDIF(), ctx)
	}()
	<-started
	cancel()
	response := <-responseChannel
	close(release)

	var result ldifImportResponse
	if response.Code != http.StatusRequestTimeout || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Applied != 0 || result.Failed != 0 || result.Unknown != 1 || !result.Aborted ||
		result.AbortReason != "batch operation canceled" || len(result.Results) != 2 ||
		result.Results[0].Status != "unknown" || result.Results[1].Status != "not_attempted" ||
		result.Error == nil || result.Error.Code != "ldap_result_unknown" {
		t.Fatalf("status = %d, result = %#v, body = %s", response.Code, result, response.Body.String())
	}
}

func TestLDIFImportStopsCanceledRequestBeforeAndDuringRead(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	preCanceledContext, preCancel := context.WithCancel(context.Background())
	preCancel()
	preCanceledReader := &countingReader{reader: strings.NewReader(twoAddLDIF())}
	preCanceled := performLDIFReaderRequestWithContext(application, authenticated, preCanceledReader, preCanceledContext)
	if preCanceled.Code != http.StatusRequestTimeout || preCanceledReader.reads.Load() != 0 ||
		!strings.Contains(preCanceled.Body.String(), `"code":"import_canceled"`) {
		t.Fatalf("pre-canceled status=%d reads=%d body=%s",
			preCanceled.Code, preCanceledReader.reads.Load(), preCanceled.Body.String())
	}

	duringContext, duringCancel := context.WithCancel(context.Background())
	duringReader := &cancelOnFirstRead{reader: strings.NewReader(twoAddLDIF()), cancel: duringCancel}
	duringRead := performLDIFReaderRequestWithContext(application, authenticated, duringReader, duringContext)
	if duringRead.Code != http.StatusRequestTimeout || duringReader.reads.Load() != 1 ||
		!strings.Contains(duringRead.Body.String(), `"code":"import_canceled"`) {
		t.Fatalf("during-read status=%d reads=%d body=%s",
			duringRead.Code, duringReader.reads.Load(), duringRead.Body.String())
	}
	client.mu.Lock()
	addCount, modifyCount, deleteCount, renameCount := len(client.adds), len(client.modifies), len(client.deletes), len(client.renames)
	client.mu.Unlock()
	if addCount != 0 || modifyCount != 0 || deleteCount != 0 || renameCount != 0 {
		t.Fatalf("canceled import reached LDAP: adds=%d modifies=%d deletes=%d renames=%d",
			addCount, modifyCount, deleteCount, renameCount)
	}
}

func TestParseLDIFChangesChecksContextDuringParsing(t *testing.T) {
	t.Parallel()
	application, err := New(Config{LDAPURL: "ldap://127.0.0.1:389", MaxImportChanges: 100})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()

	ctx, cancel := context.WithCancel(context.Background())
	checkingContext := &cancelAfterChecksContext{Context: ctx, cancel: cancel}
	checkingContext.remaining.Store(8)
	_, err = application.parseLDIFChangesContext(checkingContext, []byte(strings.Repeat(twoAddLDIF(), 20)))
	if !errors.Is(err, context.Canceled) || checkingContext.checks.Load() < 8 {
		t.Fatalf("parseLDIFChangesContext() = %v after %d checks", err, checkingContext.checks.Load())
	}
}

func TestLDIFImportRecoversClientPanicAsUnknown(t *testing.T) {
	t.Parallel()
	client := &fakeClient{addFunc: func(*ldap.AddRequest) error { panic("client panic") }}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performLDIFRequest(application, authenticated, twoAddLDIF())
	var result ldifImportResponse
	if response.Code != http.StatusBadGateway || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Unknown != 1 || !result.Aborted || len(result.Results) != 2 ||
		result.Results[0].Status != "unknown" || result.Results[1].Status != "not_attempted" ||
		application.panics.Load() != 1 {
		t.Fatalf("status = %d, result = %#v, panics = %d, body = %s",
			response.Code, result, application.panics.Load(), response.Body.String())
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("panicked client session status = %d, body = %s", probe.Code, probe.Body.String())
	}
}

func TestLDIFImportDeadlineTracksInFlightWriteWithoutMultiplyingTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	client := &fakeClient{addFunc: func(*ldap.AddRequest) error {
		<-release
		return nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = 10 * time.Millisecond
	})
	authenticated := loginTestSession(t, application, "dn")
	started := time.Now()
	response := performLDIFRequest(application, authenticated, threeAddLDIF())
	elapsed := time.Since(started)

	var result ldifImportResponse
	if response.Code != http.StatusGatewayTimeout || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Unknown != 1 || !result.Aborted || len(result.Results) != 3 ||
		result.Results[0].Status != "unknown" || result.Results[1].Status != "not_attempted" ||
		result.Results[2].Status != "not_attempted" || elapsed > 500*time.Millisecond {
		t.Fatalf("status = %d, elapsed = %s, result = %#v, body = %s",
			response.Code, elapsed, result, response.Body.String())
	}
	client.mu.Lock()
	addCount := len(client.adds)
	client.mu.Unlock()
	if addCount != 1 {
		t.Fatalf("deadline import issued %d Add calls", addCount)
	}

	// Client write methods are not context-aware: the HTTP request can return,
	// but shutdown must still wait until the blocked client method exits.
	shortContext, shortCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer shortCancel()
	if err := application.CloseContext(shortContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext while LDIF write blocked = %v", err)
	}
	close(release)
	released = true
	longContext, longCancel := context.WithTimeout(context.Background(), time.Second)
	defer longCancel()
	if err := application.CloseContext(longContext); err != nil {
		t.Fatalf("CloseContext after LDIF write exit: %v", err)
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
	return performLDIFRequestWithContext(application, authenticated, data, context.Background())
}

func performLDIFRequestWithContext(
	application *Application,
	authenticated authenticatedSession,
	data string,
	ctx context.Context,
) *httptest.ResponseRecorder {
	return performLDIFReaderRequestWithContext(application, authenticated, bytes.NewBufferString(data), ctx)
}

func performLDIFReaderRequestWithContext(
	application *Application,
	authenticated authenticatedSession,
	reader io.Reader,
	ctx context.Context,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://admin.example/api/import", reader)
	request = request.WithContext(ctx)
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

type countingReader struct {
	reader io.Reader
	reads  atomic.Int32
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	reader.reads.Add(1)
	return reader.reader.Read(buffer)
}

type cancelOnFirstRead struct {
	reader io.Reader
	cancel context.CancelFunc
	reads  atomic.Int32
}

func (reader *cancelOnFirstRead) Read(buffer []byte) (int, error) {
	reader.reads.Add(1)
	count, err := reader.reader.Read(buffer)
	reader.cancel()
	return count, err
}

type cancelAfterChecksContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining atomic.Int32
	checks    atomic.Int32
}

func (ctx *cancelAfterChecksContext) Err() error {
	ctx.checks.Add(1)
	if ctx.remaining.Add(-1) == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func twoAddLDIF() string {
	return `dn: uid=first,dc=example,dc=com
changetype: add
objectClass: person
cn: First
sn: First

dn: uid=second,dc=example,dc=com
changetype: add
objectClass: person
cn: Second
sn: Second

`
}

func threeAddLDIF() string {
	return twoAddLDIF() + `dn: uid=third,dc=example,dc=com
changetype: add
objectClass: person
cn: Third
sn: Third

`
}
