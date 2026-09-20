package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPVCProjectServerModule(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPClientToolDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("uid=alice," + clientToolPeopleDN)
		if err != nil {
			return err
		}
		user, err := writer.Get(dn)
		if err != nil {
			return err
		}
		user.ReplaceValues("userPassword", clientToolValues("alice-secret"))
		if err := writer.Put(user, true); err != nil {
			return err
		}
		for _, entry := range []directory.Entry{
			{DN: "cn=module{0},cn=config", Attributes: []directory.Attribute{
				{Description: "objectClass", Values: clientToolValues("olcModuleList")},
				{Description: "cn", Values: clientToolValues("module{0}")},
				{Description: "olcModuleLoad", Values: clientToolValues("vc.la", "authzid.la")},
			}},
			{DN: "olcDatabase={-1}frontend,cn=config", Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: clientToolValues("{-1}frontend")},
			}},
			{DN: "olcOverlay={0}authzid,olcDatabase={-1}frontend,cn=config", Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: clientToolValues("{0}authzid")},
			}},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	instance, err := server.New(server.Config{Store: store, RootDN: clientToolRootDN,
		RootPassword: []byte(clientToolRootPassword), AccessPolicy: clientToolAccessPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("VC server did not stop")
		}
	})
	dn := "uid=alice," + clientToolPeopleDN
	for _, test := range []struct {
		name, password, want string
		code                 int
	}{
		{"correct", "alice-secret", "authzid: dn:" + dn, 0},
		{"wrong", "wrong-secret", "Failed: Invalid credentials (49)", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, code := runLDAPClientCommand([]string{"ldapvc", "-x", "-H", "ldap://" + listener.Addr().String(),
				"-D", clientToolRootDN, "-w", clientToolRootPassword, "-a", dn, test.password}, "")
			if code != test.code || stderr != "" || !strings.Contains(stdout, test.want) {
				t.Fatalf("VC client/server: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	t.Run("explicit anonymous credentials", func(t *testing.T) {
		stdout, stderr, code := runLDAPClientCommand([]string{
			"ldapvc", "-x", "-H", "ldap://" + listener.Addr().String(),
			"-D", clientToolRootDN, "-w", clientToolRootPassword, "-v", "", "",
		}, "")
		if code != 0 || stderr != "" || !strings.Contains(stdout, "Result: Success (0)") {
			t.Fatalf("explicit anonymous VC: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("omitted credentials match native malformed request", func(t *testing.T) {
		stdout, stderr, code := runLDAPClientCommand([]string{
			"ldapvc", "-x", "-H", "ldap://" + listener.Addr().String(),
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
		}, "")
		if code == 0 || stderr != "" || !strings.Contains(stdout, "Protocol error (2)") {
			t.Fatalf("omitted VC credentials: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
}
