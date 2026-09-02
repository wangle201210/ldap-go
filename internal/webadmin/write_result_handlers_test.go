package webadmin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type specializedWriteTestCase struct {
	name      string
	configure func(*fakeClient)
	perform   func(*testing.T, *Application, authenticatedSession) *httptest.ResponseRecorder
}

func specializedWriteTestCases() []specializedWriteTestCase {
	const (
		groupDN = "cn=staff,dc=example,dc=com"
		userDN  = "uid=alice,dc=example,dc=com"
	)
	return []specializedWriteTestCase{
		{
			name: "group membership",
			configure: func(client *fakeClient) {
				client.searchFunc = func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
						groupDN, map[string][]string{"objectClass": {"groupOfNames"}},
					)}}, nil
				}
			},
			perform: func(t *testing.T, application *Application, authenticated authenticatedSession) *httptest.ResponseRecorder {
				return performGroupsRequest(t, application, http.MethodPatch, "/api/groups",
					validGroupPatchBody(), authenticated.cookie, authenticated.csrf)
			},
		},
		{
			name:      "binary replace",
			configure: func(*fakeClient) {},
			perform: func(t *testing.T, application *Application, authenticated authenticatedSession) *httptest.ResponseRecorder {
				return performBinaryRequest(t, application, http.MethodPut, "/api/binary",
					binaryBody(userDN, "jpegPhoto", []string{"AA=="}),
					authenticated.cookie, authenticated.csrf, "https://admin.example")
			},
		},
		{
			name:      "binary delete",
			configure: func(*fakeClient) {},
			perform: func(t *testing.T, application *Application, authenticated authenticatedSession) *httptest.ResponseRecorder {
				return performBinaryRequest(t, application, http.MethodDelete,
					binaryQuery(userDN, "jpegPhoto"), nil,
					authenticated.cookie, authenticated.csrf, "https://admin.example")
			},
		},
	}
}

func TestSpecializedWritesPreserveSessionAfterDeterministicLDAPFailure(t *testing.T) {
	t.Parallel()
	for _, operation := range specializedWriteTestCases() {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
				return ldap.NewError(ldap.LDAPResultConstraintViolation, errors.New("policy rejected write"))
			}}
			operation.configure(client)
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")

			response := operation.perform(t, application, authenticated)
			failure := decodeSpecializedWriteError(t, response)
			if response.Code != http.StatusUnprocessableEntity || failure.Code != "ldap_error" ||
				failure.LDAPResultCode == nil || *failure.LDAPResultCode != ldap.LDAPResultConstraintViolation {
				t.Fatalf("status = %d, error = %#v, body = %s", response.Code, failure, response.Body.String())
			}
			probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
			if probe.Code != http.StatusOK {
				t.Fatalf("preserved session status = %d, body = %s", probe.Code, probe.Body.String())
			}
			client.mu.Lock()
			closeCount := client.closeCount
			client.mu.Unlock()
			if closeCount != 0 {
				t.Fatalf("LDAP client close count = %d", closeCount)
			}
		})
	}
}

func TestSpecializedWritesRetireSessionAfterTransportFailure(t *testing.T) {
	t.Parallel()
	failures := []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "connection interrupted", err: ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))},
	}
	for _, operation := range specializedWriteTestCases() {
		operation := operation
		for _, test := range failures {
			test := test
			t.Run(operation.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error { return test.err }}
				operation.configure(client)
				application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
				authenticated := loginTestSession(t, application, "dn")

				response := operation.perform(t, application, authenticated)
				assertSpecializedWriteUnknown(t, response, http.StatusBadGateway)
				assertSpecializedWriteSessionRetired(t, application, authenticated, operation, client)
			})
		}
	}
}

func TestSpecializedWritesRetireSessionAfterStartedWriteTimeout(t *testing.T) {
	t.Parallel()
	for _, operation := range specializedWriteTestCases() {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			started := make(chan struct{})
			release := make(chan struct{})
			client := &fakeClient{modifyFunc: func(*ldap.ModifyRequest) error {
				close(started)
				<-release
				return nil
			}}
			operation.configure(client)
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
				config.OperationTimeout = 25 * time.Millisecond
			})
			authenticated := loginTestSession(t, application, "dn")

			response := operation.perform(t, application, authenticated)
			select {
			case <-started:
			default:
				close(release)
				t.Fatal("LDAP Modify did not start before the operation timeout")
			}
			close(release)
			assertSpecializedWriteUnknown(t, response, http.StatusGatewayTimeout)
			assertSpecializedWriteSessionRetired(t, application, authenticated, operation, client)
		})
	}
}

func decodeSpecializedWriteError(t *testing.T, response *httptest.ResponseRecorder) apiError {
	t.Helper()
	var body apiErrorBody
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v; body = %s", err, response.Body.String())
	}
	return body.Error
}

func assertSpecializedWriteUnknown(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	failure := decodeSpecializedWriteError(t, response)
	if response.Code != status || failure.Code != "ldap_result_unknown" || failure.LDAPResultCode != nil {
		t.Fatalf("status = %d, error = %#v, body = %s", response.Code, failure, response.Body.String())
	}
}

func assertSpecializedWriteSessionRetired(
	t *testing.T,
	application *Application,
	authenticated authenticatedSession,
	operation specializedWriteTestCase,
	client *fakeClient,
) {
	t.Helper()
	probe := performJSONRequest(t, application, http.MethodGet, "/api/session", nil, authenticated.cookie, "")
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("retired session status = %d, body = %s", probe.Code, probe.Body.String())
	}
	retry := operation.perform(t, application, authenticated)
	if retry.Code != http.StatusUnauthorized {
		t.Fatalf("direct retry status = %d, body = %s", retry.Code, retry.Body.String())
	}
	client.mu.Lock()
	modifyCount := len(client.modifies)
	client.mu.Unlock()
	if modifyCount != 1 {
		t.Fatalf("LDAP modify count after rejected retry = %d", modifyCount)
	}
	waitForFakeClientClose(t, client)
}
