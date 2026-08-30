package webadmin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRealLDAPBindAndRootDSEIntegration(t *testing.T) {
	const userDN = "uid=alice,ou=people,dc=example,dc=com"
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
		if err := writer.Put(directory.Entry{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("organizationalUnit")}},
				{Description: "ou", Values: [][]byte{[]byte("people")}},
			},
		}, false); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{
			DN: userDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
				{Description: "uid", Values: [][]byte{[]byte("alice")}},
				{Description: "cn", Values: [][]byte{[]byte("Alice")}},
				{Description: "sn", Values: [][]byte{[]byte("Example")}},
				{Description: "userPassword", Values: [][]byte{[]byte("old-secret")}},
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

	const newPassword = "PBKDF2-SM3-integration-secret"
	changed := performJSONRequest(t, application, http.MethodPost, "/api/password-set-hash", map[string]string{
		"user_identity": userDN,
		"new_password":  newPassword,
		"hash_scheme":   auth.SMPBKDF2HashScheme,
	}, authenticated.cookie, authenticated.csrf)
	if changed.Code != http.StatusOK || strings.Contains(changed.Body.String(), newPassword) ||
		strings.Contains(changed.Body.String(), "100000$") {
		t.Fatalf("password hash status = %d, body = %s", changed.Code, changed.Body.String())
	}

	parsedUserDN, err := directory.ParseDN(userDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", userDN, err)
	}
	var stored []byte
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		entry, getErr := reader.Get(parsedUserDN)
		if getErr != nil {
			return getErr
		}
		values := entry.Values("userPassword")
		if len(values) == 1 {
			stored = append([]byte(nil), values[0]...)
		}
		return nil
	}); err != nil {
		t.Fatalf("read stored password: %v", err)
	}
	defer clear(stored)
	if !strings.HasPrefix(string(stored), auth.SMPBKDF2HashScheme) ||
		!auth.VerifyPassword(stored, []byte(newPassword)) {
		t.Fatal("stored userPassword does not contain the selected PBKDF2-SM3 hash")
	}

	user, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("dial user Bind: %v", err)
	}
	defer user.Close()
	if err := user.Bind(userDN, newPassword); err != nil {
		t.Fatalf("Bind with selected password hash: %v", err)
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
