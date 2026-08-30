package webadmin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestBulkModifyOrderAndPartialFailure(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.modifyFunc = func(request *ldap.ModifyRequest) error {
		if request.DN == "uid=second,dc=example,dc=com" {
			return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
		}
		return nil
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify",
		"dns": []string{
			"uid=first,dc=example,dc=com",
			"uid=second,dc=example,dc=com",
			"uid=third,dc=example,dc=com",
		},
		"changes": []map[string]any{
			{"operation": "add", "attribute": "description", "values": []string{"one"}},
			{"operation": "delete", "attribute": "seeAlso", "values": []string{}},
			{"operation": "replace", "attribute": "displayName", "values": []string{"Alice"}},
			{"operation": "increment", "attribute": "loginCount", "values": []string{"1"}},
		},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusOK {
		t.Fatalf("bulk modify status = %d, body = %s", response.Code, response.Body.String())
	}
	var result bulkResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode bulk response: %v", err)
	}
	if result.Applied != 1 || result.Failed != 1 || len(result.Results) != 3 {
		t.Fatalf("bulk response = %#v", result)
	}
	if !result.Results[0].Success || result.Results[0].Status != "applied" ||
		result.Results[1].Success || result.Results[1].Status != "failed" ||
		result.Results[1].Error == nil || result.Results[1].Error.LDAPResultCode == nil ||
		*result.Results[1].Error.LDAPResultCode != ldap.LDAPResultInsufficientAccessRights ||
		result.Results[2].Success || result.Results[2].Status != "not_attempted" {
		t.Fatalf("bulk results = %#v", result.Results)
	}

	client.mu.Lock()
	requests := append([]*ldap.ModifyRequest(nil), client.modifies...)
	client.mu.Unlock()
	if len(requests) != 2 || requests[0].DN != "uid=first,dc=example,dc=com" ||
		requests[1].DN != "uid=second,dc=example,dc=com" {
		t.Fatalf("modify order = %#v", requests)
	}
	wantOperations := []uint{ldap.AddAttribute, ldap.DeleteAttribute, ldap.ReplaceAttribute, ldap.IncrementAttribute}
	for _, request := range requests {
		operations := make([]uint, 0, len(request.Changes))
		for _, change := range request.Changes {
			operations = append(operations, change.Operation)
		}
		if !reflect.DeepEqual(operations, wantOperations) {
			t.Fatalf("modify operations = %v, want %v", operations, wantOperations)
		}
	}
}

func TestBulkContinueOnErrorAndDeleteDepthOrder(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	client.delFunc = func(request *ldap.DelRequest) error {
		if request.DN == "uid=blocked,ou=people,dc=example,dc=com" {
			return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("missing"))
		}
		return nil
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")

	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "delete",
		"dns": []string{
			"dc=example,dc=com",
			"uid=blocked,ou=people,dc=example,dc=com",
			"ou=groups,dc=example,dc=com",
			"cn=member,ou=groups,dc=example,dc=com",
			"CN=member,OU=groups,DC=example,DC=com",
			"ou=people,dc=example,dc=com",
		},
		"continue_on_error": true,
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusOK {
		t.Fatalf("bulk delete status = %d, body = %s", response.Code, response.Body.String())
	}
	var result bulkResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode bulk response: %v", err)
	}
	if result.Applied != 4 || result.Failed != 1 || len(result.Results) != 5 {
		t.Fatalf("bulk response = %#v", result)
	}

	client.mu.Lock()
	got := make([]string, 0, len(client.deletes))
	for _, request := range client.deletes {
		got = append(got, request.DN)
	}
	client.mu.Unlock()
	want := []string{
		"uid=blocked,ou=people,dc=example,dc=com",
		"cn=member,ou=groups,dc=example,dc=com",
		"ou=groups,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"dc=example,dc=com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("delete order = %v, want %v", got, want)
	}
	if result.Results[0].Error == nil || result.Results[0].Error.LDAPResultCode == nil ||
		*result.Results[0].Error.LDAPResultCode != ldap.LDAPResultNoSuchObject {
		t.Fatalf("first delete result = %#v", result.Results[0])
	}
}

func TestBulkValidationRejectsBeforeLDAP(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxImportChanges = 2
		config.MaxAttributes = 2
	})
	authenticated := loginTestSession(t, application, "dn")
	tests := []struct {
		name string
		body map[string]any
		code string
	}{
		{name: "empty dns", body: map[string]any{"action": "delete", "dns": []string{}}, code: "invalid_dns"},
		{name: "too many dns", body: map[string]any{
			"action": "delete", "dns": []string{"uid=1,dc=x", "uid=2,dc=x", "uid=3,dc=x"},
		}, code: "invalid_dns"},
		{name: "invalid later dn", body: map[string]any{
			"action": "delete", "dns": []string{"uid=valid,dc=example", "not a dn"},
		}, code: "invalid_dns"},
		{name: "missing changes", body: map[string]any{
			"action": "modify", "dns": []string{"uid=alice,dc=example"},
		}, code: "invalid_changes"},
		{name: "invalid operation", body: map[string]any{
			"action": "modify", "dns": []string{"uid=alice,dc=example"},
			"changes": []map[string]any{{"operation": "merge", "attribute": "cn", "values": []string{"Alice"}}},
		}, code: "invalid_changes"},
		{name: "invalid increment", body: map[string]any{
			"action": "modify", "dns": []string{"uid=alice,dc=example"},
			"changes": []map[string]any{{"operation": "increment", "attribute": "loginCount", "values": []string{"1", "2"}}},
		}, code: "invalid_changes"},
		{name: "changes on delete", body: map[string]any{
			"action": "delete", "dns": []string{"uid=alice,dc=example"},
			"changes": []map[string]any{{"operation": "delete", "attribute": "description"}},
		}, code: "invalid_changes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performBulkRequest(t, application, http.MethodPost, test.body,
				authenticated.cookie, authenticated.csrf, "https://admin.example")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var result apiErrorBody
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if result.Error.Code != test.code {
				t.Fatalf("error code = %q, want %q", result.Error.Code, test.code)
			}
		})
	}
	client.mu.Lock()
	modifyCount, deleteCount := len(client.modifies), len(client.deletes)
	client.mu.Unlock()
	if modifyCount != 0 || deleteCount != 0 {
		t.Fatalf("invalid batches reached LDAP: modify=%d delete=%d", modifyCount, deleteCount)
	}
}

func TestBulkRequiresPOSTSessionOriginAndCSRF(t *testing.T) {
	t.Parallel()
	client := &fakeClient{}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	body := map[string]any{"action": "delete", "dns": []string{"uid=alice,dc=example"}}

	wrongMethod := performBulkRequest(t, application, http.MethodGet, body,
		authenticated.cookie, authenticated.csrf, "https://admin.example")
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("wrong method status = %d, Allow = %q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}
	unauthenticated := performBulkRequest(t, application, http.MethodPost, body, nil, "", "https://admin.example")
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}
	badOrigin := performBulkRequest(t, application, http.MethodPost, body,
		authenticated.cookie, authenticated.csrf, "https://evil.example")
	if badOrigin.Code != http.StatusForbidden || !bytes.Contains(badOrigin.Body.Bytes(), []byte("invalid_origin")) {
		t.Fatalf("bad origin status = %d, body = %s", badOrigin.Code, badOrigin.Body.String())
	}
	badCSRF := performBulkRequest(t, application, http.MethodPost, body,
		authenticated.cookie, "wrong-token", "https://admin.example")
	if badCSRF.Code != http.StatusForbidden || !bytes.Contains(badCSRF.Body.Bytes(), []byte("invalid_csrf_token")) {
		t.Fatalf("bad CSRF status = %d, body = %s", badCSRF.Code, badCSRF.Body.String())
	}

	client.mu.Lock()
	deleteCount := len(client.deletes)
	client.mu.Unlock()
	if deleteCount != 0 {
		t.Fatalf("unauthorized requests reached LDAP: delete=%d", deleteCount)
	}
}

func TestBulkStopsAfterUnknownNetworkResult(t *testing.T) {
	t.Parallel()
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		return ldap.NewError(ldap.ErrorNetwork, errors.New("response lost"))
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify", "dns": []string{"uid=first,dc=example", "uid=second,dc=example"},
		"changes":           []map[string]any{{"operation": "increment", "attribute": "loginCount", "values": []string{"1"}}},
		"continue_on_error": true,
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	var result bulkResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if result.Applied != 0 || result.Failed != 0 || result.Unknown != 1 || len(result.Results) != 2 ||
		result.Results[0].Status != "unknown" || result.Results[0].Error == nil ||
		result.Results[0].Error.Code != "ldap_result_unknown" || result.Results[1].Status != "not_attempted" {
		t.Fatalf("result = %#v", result)
	}
	client.mu.Lock()
	modifyCount := len(client.modifies)
	client.mu.Unlock()
	if modifyCount != 1 {
		t.Fatalf("modify count = %d", modifyCount)
	}
}

func TestBulkDeadlineAndCaseFoldedDNDeduplication(t *testing.T) {
	t.Parallel()
	t.Run("deadline", func(t *testing.T) {
		client := &fakeClient{}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.OperationTimeout = time.Nanosecond
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performBulkRequest(t, application, http.MethodPost, map[string]any{
			"action": "delete", "dns": []string{"uid=first,dc=example", "uid=second,dc=example"},
		}, authenticated.cookie, authenticated.csrf, "https://admin.example")
		var result bulkResponse
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
			!result.Aborted || len(result.Results) != 2 || result.Results[0].Status != "not_attempted" {
			t.Fatalf("status = %d, result = %#v, body = %s", response.Code, result, response.Body.String())
		}
		client.mu.Lock()
		deleteCount := len(client.deletes)
		client.mu.Unlock()
		if deleteCount != 0 {
			t.Fatalf("delete count = %d", deleteCount)
		}
	})

	t.Run("case-folded ambiguity", func(t *testing.T) {
		client := &fakeClient{}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performBulkRequest(t, application, http.MethodPost, map[string]any{
			"action": "modify", "dns": []string{"cn=Alice,dc=example", "CN=alice,DC=EXAMPLE"},
			"changes": []map[string]any{{"operation": "increment", "attribute": "loginCount", "values": []string{"1"}}},
		}, authenticated.cookie, authenticated.csrf, "https://admin.example")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "differs") {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		client.mu.Lock()
		modifyCount := len(client.modifies)
		client.mu.Unlock()
		if modifyCount != 0 {
			t.Fatalf("modify count = %d", modifyCount)
		}
	})
}

func TestBulkDeadlineClosesInFlightSessionAndMarksUnknown(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		<-release
		return nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = 10 * time.Millisecond
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify", "dns": []string{"uid=first,dc=example", "uid=second,dc=example"},
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"value"}}},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	close(release)
	var result bulkResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		!result.Aborted || result.Unknown != 1 || len(result.Results) != 2 ||
		result.Results[0].Status != "unknown" || result.Results[1].Status != "not_attempted" {
		t.Fatalf("status = %d, result = %#v, body = %s", response.Code, result, response.Body.String())
	}
	client.mu.Lock()
	closeCount := client.closeCount
	client.mu.Unlock()
	waitStarted := time.Now()
	for closeCount == 0 && time.Since(waitStarted) < time.Second {
		time.Sleep(time.Millisecond)
		client.mu.Lock()
		closeCount = client.closeCount
		client.mu.Unlock()
	}
	if closeCount != 1 {
		t.Fatalf("close count = %d", closeCount)
	}
}

func TestBulkRecoversLDAPClientPanicAsUnknown(t *testing.T) {
	t.Parallel()
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error { panic("client panic") }}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify", "dns": []string{"uid=first,dc=example"},
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"value"}}},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	var result bulkResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Unknown != 1 || len(result.Results) != 1 || result.Results[0].Status != "unknown" ||
		application.panics.Load() != 1 {
		t.Fatalf("status = %d, result = %#v, panics = %d, body = %s", response.Code, result, application.panics.Load(), response.Body.String())
	}
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("panicked client session status = %d, body = %s", probe.Code, probe.Body.String())
	}
}

type blockingCloseClient struct {
	*fakeClient
	closeRelease <-chan struct{}
}

type panicCloseClient struct{ *fakeClient }

func (client *panicCloseClient) Close() error { panic("close panic") }

func TestBulkRecoversAsynchronousClientClosePanic(t *testing.T) {
	t.Parallel()
	operationRelease := make(chan struct{})
	client := &panicCloseClient{fakeClient: &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		<-operationRelease
		return nil
	}}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = 10 * time.Millisecond
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify", "dns": []string{"uid=first,dc=example"},
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"value"}}},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	close(operationRelease)
	waitStarted := time.Now()
	for application.panics.Load() == 0 && time.Since(waitStarted) < time.Second {
		time.Sleep(time.Millisecond)
	}
	if response.Code != http.StatusOK || application.panics.Load() != 1 {
		t.Fatalf("status = %d, panics = %d, body = %s", response.Code, application.panics.Load(), response.Body.String())
	}
}

func TestTimedOutOperationRetainsClosingSessionCapacityUntilItExits(t *testing.T) {
	t.Parallel()
	operationRelease := make(chan struct{})
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		<-operationRelease
		return nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = 10 * time.Millisecond
		config.MaxSessions = 1
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify", "dns": []string{"uid=first,dc=example"},
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"value"}}},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	if response.Code != http.StatusOK {
		close(operationRelease)
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	application.mu.Lock()
	closing := application.closingSessions
	application.mu.Unlock()
	if closing != 1 || application.hasLoginCapacity(httptest.NewRequest(http.MethodPost, "https://admin.example/api/login", nil)) {
		close(operationRelease)
		t.Fatalf("closing sessions = %d, login capacity should remain reserved", closing)
	}
	close(operationRelease)
	waitStarted := time.Now()
	for {
		application.mu.Lock()
		closing = application.closingSessions
		application.mu.Unlock()
		if closing == 0 || time.Since(waitStarted) >= time.Second {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if closing != 0 {
		t.Fatalf("closing sessions after operation exit = %d", closing)
	}
}

func TestApplicationCloseTracksAlreadyStartedBatchWrite(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		close(started)
		<-release
		return nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	responseChannel := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		responseChannel <- performBulkRequest(t, application, http.MethodPost, map[string]any{
			"action": "modify", "dns": []string{"uid=first,dc=example"},
			"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"value"}}},
		}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	}()
	<-started
	shortContext, shortCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer shortCancel()
	if err := application.CloseContext(shortContext); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("CloseContext while write blocked = %v", err)
	}
	close(release)
	if response := <-responseChannel; response.Code != http.StatusOK {
		t.Fatalf("bulk status = %d, body = %s", response.Code, response.Body.String())
	}
	longContext, longCancel := context.WithTimeout(context.Background(), time.Second)
	defer longCancel()
	if err := application.CloseContext(longContext); err != nil {
		t.Fatalf("CloseContext after write exit: %v", err)
	}
}

func (client *blockingCloseClient) Close() error {
	<-client.closeRelease
	return nil
}

func TestBulkDeadlineDoesNotWaitForBlockingClientClose(t *testing.T) {
	t.Parallel()
	operationRelease := make(chan struct{})
	closeRelease := make(chan struct{})
	client := &blockingCloseClient{fakeClient: &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
		<-operationRelease
		return nil
	}}, closeRelease: closeRelease}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.OperationTimeout = 10 * time.Millisecond
	})
	authenticated := loginTestSession(t, application, "dn")
	started := time.Now()
	response := performBulkRequest(t, application, http.MethodPost, map[string]any{
		"action": "modify", "dns": []string{"uid=first,dc=example"},
		"changes": []map[string]any{{"operation": "replace", "attribute": "description", "values": []string{"value"}}},
	}, authenticated.cookie, authenticated.csrf, "https://admin.example")
	elapsed := time.Since(started)
	close(operationRelease)
	close(closeRelease)
	if response.Code != http.StatusOK || elapsed > 500*time.Millisecond {
		t.Fatalf("status = %d, elapsed = %s, body = %s", response.Code, elapsed, response.Body.String())
	}
}

func performBulkRequest(
	t *testing.T,
	application *Application,
	method string,
	body any,
	cookie *http.Cookie,
	csrf string,
	origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatalf("encode bulk request: %v", err)
		}
	}
	request := httptest.NewRequest(method, "https://admin.example/api/bulk", &encoded)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	application.handleBulk(response, request)
	return response
}
