package webadmin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRealLDAPBindAndRootDSEIntegration(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("domain")}},
				{Description: "dc", Values: [][]byte{[]byte("example")}},
			},
		}, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed LDAP directory: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := server.New(server.Config{
		Store: store, RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("secret"),
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	serveContext, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- instance.Serve(serveContext, listener) }()
	defer func() {
		cancelServe()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("LDAP server did not stop")
		}
	}()

	application, err := New(Config{
		LDAPURL: "ldap://" + listener.Addr().String(), Logger: discardLogger{},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer application.Close()
	authenticated := loginTestSessionWithCredentials(
		t, application, "cn=admin,dc=example,dc=com", "secret",
	)
	root := performJSONRequest(t, application, http.MethodGet, "/api/root-dse", nil, authenticated.cookie, "")
	if root.Code != http.StatusOK || !containsJSONText(root.Body.Bytes(), "supportedLDAPVersion") {
		t.Fatalf("Root DSE status = %d, body = %s", root.Code, root.Body.String())
	}
}

func loginTestSessionWithCredentials(
	t *testing.T,
	application *Application,
	dn,
	password string,
) authenticatedSession {
	t.Helper()
	recorder := performJSONRequest(t, application, http.MethodPost, "/api/login", map[string]string{
		"dn": dn, "password": password,
	}, nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("real login status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body sessionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d", len(cookies))
	}
	return authenticatedSession{cookie: cookies[0], csrf: body.CSRFToken}
}
