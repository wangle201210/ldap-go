package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientBindAndSearch(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	if err := client.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous Bind(): %v", err)
	}

	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"namingContexts", "supportedLDAPVersion"},
		nil,
	))
	if err != nil {
		t.Fatalf("root DSE Search(): %v", err)
	}
	if len(root.Entries) != 1 ||
		root.Entries[0].GetAttributeValue("namingContexts") != "dc=example,dc=com" {
		t.Fatalf("root DSE entries = %#v", root.Entries)
	}

	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("user Bind(): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=inetOrgPerson)(cn=Alice*))",
		[]string{"uid", "cn", "jpegPhoto"},
		nil,
	))
	if err != nil {
		t.Fatalf("subtree Search(): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(result.Entries))
	}
	if got := result.Entries[0].GetAttributeValue("uid"); got != "alice" {
		t.Fatalf("uid = %q, want alice", got)
	}
	if got := result.Entries[0].GetRawAttributeValue("jpegPhoto"); len(got) != 3 ||
		got[0] != 0x00 || got[1] != 0xff || got[2] != 0x10 {
		t.Fatalf("jpegPhoto = %v", got)
	}

	passwordResult, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"userPassword"},
		nil,
	))
	if err != nil {
		t.Fatalf("password Search(): %v", err)
	}
	if len(passwordResult.Entries) != 1 ||
		len(passwordResult.Entries[0].GetRawAttributeValues("userPassword")) != 0 {
		t.Fatal("non-root search disclosed userPassword")
	}
}

func TestLDAPClientRejectsInvalidPassword(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	err = client.Bind("uid=alice,ou=people,dc=example,dc=com", "wrong")
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("Bind() error = %v, want invalid credentials", err)
	}
}

func seedDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("domain")}},
				{Description: "dc", Values: [][]byte{[]byte("example")}},
			},
		},
		{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("organizationalUnit")}},
				{Description: "ou", Values: [][]byte{[]byte("people")}},
			},
		},
		{
			DN: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
				{Description: "uid", Values: [][]byte{[]byte("alice")}},
				{Description: "cn", Values: [][]byte{[]byte("Alice Example")}},
				{Description: "sn", Values: [][]byte{[]byte("Example")}},
				{Description: "userPassword", Values: [][]byte{[]byte("secret")}},
				{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed directory: %v", err)
	}
}

func startServer(t *testing.T, store storage.Store, config Config) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	config.Store = store
	instance, err := New(config)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
	return fmt.Sprint(listener.Addr()), stop
}
